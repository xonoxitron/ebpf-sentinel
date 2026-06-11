mod config;
mod enricher;
mod event;
mod k8s;
mod loader;
mod metrics;
mod pipeline;
mod rules;
mod sinks;
mod suppress;
mod triage;

use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use sentinel_common::SentinelEvent;
use tokio::sync::{mpsc, Mutex};

use crate::config::Config;
use crate::enricher::Enricher;
use crate::k8s::K8sMetadataCache;
use crate::loader::{raise_memlock_limit, ProbeLoader};
use crate::metrics::{serve_metrics, SentinelMetrics};
use crate::pipeline::parse_ring_event;
use crate::rules::RuleEngine;
use crate::sinks::{build_sinks, MultiSink};
use crate::suppress::AlertSuppressor;
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

    let mut config = if opt.config.exists() {
        Config::load(&opt.config)?
    } else {
        log::warn!("config {} not found, using defaults", opt.config.display());
        Config::default()
    };
    config.normalize();
    config.validate()?;

    raise_memlock_limit();

    let mut loader = ProbeLoader::load()?;
    loader.populate_monitored_paths(&config.monitored_paths)?;
    loader.seed_process_tree()?;

    let mut ring_buf = loader.ring_buf()?;
    let rules = Arc::new(RuleEngine::load_dir(
        PathBuf::from(&config.rules_dir).as_path(),
    )?);
    let sinks = Arc::new(MultiSink::new(build_sinks(&config.sinks)?));
    let triage = Arc::new(ClaudeTriage::new(config.triage.clone()));
    let host = config.host.clone();
    let k8s_cache = if config.k8s.enabled {
        let cache = Arc::new(K8sMetadataCache::new(config.k8s.clone()));
        let refresh = cache.clone();
        tokio::spawn(async move {
            refresh.refresh_loop().await;
        });
        Some(cache)
    } else {
        None
    };
    let mut enricher_builder = Enricher::new(host.clone());
    if let Some(cache) = k8s_cache {
        enricher_builder = enricher_builder.with_k8s(cache);
    }
    let enricher = Arc::new(Mutex::new(enricher_builder));
    let suppressor = Arc::new(AlertSuppressor::new(&config.suppression));
    let metrics = Arc::new(SentinelMetrics::new()?);
    let emit_events = opt.emit_events;
    let triage_enabled = triage.enabled() && !opt.no_triage;

    if config.metrics.enabled {
        let listen = config.metrics.listen.clone();
        let metrics_server = metrics.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_metrics(listen, metrics_server).await {
                log::error!("metrics server failed: {e:#}");
            }
        });
    }

    let (tx, mut rx) = mpsc::channel::<SentinelEvent>(4096);
    let metrics_ring = metrics.clone();

    tokio::task::spawn_blocking(move || loop {
        while let Some(item) = ring_buf.next() {
            match parse_ring_event(&item) {
                Some(event) => {
                    if tx.blocking_send(event).is_err() {
                        return;
                    }
                }
                None => {
                    metrics_ring.inc_ring_parse_error();
                    log::warn!(
                        "dropping ring buffer record with invalid size (got {}, expected {})",
                        item.len(),
                        core::mem::size_of::<SentinelEvent>()
                    );
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    });

    log::info!("sentinel running on {} (triage={})", host, triage_enabled);

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
                            &suppressor,
                            &metrics,
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

    sinks.flush().await?;
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
    suppressor: &AlertSuppressor,
    metrics: &SentinelMetrics,
) -> anyhow::Result<()> {
    let event = {
        let mut guard = enricher.lock().await;
        guard.enrich(raw)
    };

    metrics.inc_event(&event.kind, &event.host);

    if emit_events {
        sinks.emit_event(&event).await?;
    }

    let mut alerts = rules.evaluate(&event);
    for alert in &mut alerts {
        if !rules.should_alert(&alert.rule_id) {
            continue;
        }
        if !suppressor.allow(&alert.rule_id, alert.event.pid, alert.timestamp_ns) {
            metrics.inc_suppressed(&alert.rule_id);
            log::debug!(
                "suppressed alert {} for pid {}",
                alert.rule_id,
                alert.event.pid
            );
            continue;
        }
        if triage_enabled && rules.should_triage(&alert.rule_id) {
            match triage.triage(alert).await {
                Ok(outcome) => alert.triage = Some(outcome),
                Err(e) => log::warn!("triage failed for {}: {e:#}", alert.rule_id),
            }
        }
        metrics.inc_alert(&alert.rule_id, &alert.severity, &alert.event.host);
        sinks.emit_alert(alert).await?;
    }

    Ok(())
}
