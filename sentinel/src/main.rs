mod config;
mod enricher;
mod event;
mod loader;
mod rules;
mod sinks;
mod triage;

use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use sentinel_common::SentinelEvent;
use tokio::sync::{mpsc, Mutex};

use crate::config::Config;
use crate::enricher::Enricher;
use crate::loader::{raise_memlock_limit, ProbeLoader};
use crate::rules::RuleEngine;
use crate::sinks::{build_sinks, MultiSink};
use crate::triage::ClaudeTriage;

#[derive(Debug, Parser)]
#[command(name = "sentinel", about = "eBPF Linux endpoint detection agent")]
struct Opt {
    /// Path to agent configuration YAML
    #[arg(short, long, default_value = "config/sentinel.yaml")]
    config: PathBuf,

    /// Stream all telemetry events (disable for alerts-only mode)
    #[arg(long, action = clap::ArgAction::SetTrue, default_value_t = true)]
    emit_events: bool,

    /// Disable Claude-powered alert triage even if configured
    #[arg(long)]
    no_triage: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let config = if opt.config.exists() {
        Config::load(&opt.config)?
    } else {
        log::warn!(
            "config {} not found, using defaults",
            opt.config.display()
        );
        Config::default()
    };

    raise_memlock_limit();

    let mut loader = ProbeLoader::load()?;
    loader.populate_monitored_paths(&config.monitored_paths)?;
    loader.seed_process_tree()?;

    let mut ring_buf = loader.ring_buf()?;
    let rules = Arc::new(RuleEngine::load_dir(PathBuf::from(&config.rules_dir).as_path())?);
    let sinks = Arc::new(MultiSink::new(build_sinks(&config.sinks)?));
    let triage = Arc::new(ClaudeTriage::new(config.triage.clone()));
    let host = config.host.clone();
    let enricher = Arc::new(Mutex::new(Enricher::new(host.clone())));
    let emit_events = opt.emit_events;
    let triage_enabled = triage.enabled() && !opt.no_triage;

    let (tx, mut rx) = mpsc::channel::<SentinelEvent>(4096);

    tokio::task::spawn_blocking(move || {
        loop {
            while let Some(item) = ring_buf.next() {
                let event = parse_ring_event(&item);
                if tx.blocking_send(event).is_err() {
                    return;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    });

    log::info!(
        "sentinel running on {} (triage={})",
        host,
        triage_enabled
    );

    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);

    loop {
        tokio::select! {
            maybe_event = rx.recv() => {
                match maybe_event {
                    Some(raw) => {
                        if let Err(e) = process_event(
                            raw,
                            emit_events,
                            triage_enabled,
                            &rules,
                            &sinks,
                            &triage,
                            &enricher,
                        ).await {
                            log::error!("event processing error: {e:#}");
                        }
                    }
                    None => break,
                }
            }
            _ = &mut ctrl_c => {
                log::info!("shutdown signal received");
                break;
            }
        }
    }

    Ok(())
}

async fn process_event(
    raw: SentinelEvent,
    emit_events: bool,
    triage_enabled: bool,
    rules: &RuleEngine,
    sinks: &MultiSink,
    triage: &ClaudeTriage,
    enricher: &Arc<Mutex<Enricher>>,
) -> anyhow::Result<()> {
    let event = {
        let mut guard = enricher.lock().await;
        guard.enrich(raw)
    };

    if emit_events {
        sinks.emit_event(&event).await?;
    }

    let mut alerts = rules.evaluate(&event);
    for alert in &mut alerts {
        if triage_enabled && rules.should_triage(&alert.rule_id) {
            match triage.triage(alert).await {
                Ok(outcome) => alert.triage = Some(outcome),
                Err(e) => log::warn!("triage failed for {}: {e:#}", alert.rule_id),
            }
        }
        sinks.emit_alert(alert).await?;
    }

    Ok(())
}

fn parse_ring_event(item: &[u8]) -> SentinelEvent {
    if item.len() >= core::mem::size_of::<SentinelEvent>() {
        unsafe { (item.as_ptr() as *const SentinelEvent).read_unaligned() }
    } else {
        SentinelEvent {
            kind: 0,
            pid: 0,
            ppid: 0,
            uid: 0,
            gid: 0,
            timestamp_ns: 0,
            comm: [0; 16],
            dst_addr: 0,
            dst_port: 0,
            flags: 0,
            path: [0; 128],
        }
    }
}
