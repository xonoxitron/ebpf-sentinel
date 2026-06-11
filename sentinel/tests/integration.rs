use std::path::PathBuf;

use sentinel::config::Config;
use sentinel::enricher::Enricher;
use sentinel::k8s::container_id_from_cgroup;
use sentinel::loader::{ensure_btf_available, raise_memlock_limit, ProbeLoader};
use sentinel::rules::RuleEngine;
use sentinel_common::{EventKind, SentinelEvent, MAX_COMM_LEN, MAX_PATH_LEN};

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

#[test]
fn loads_examples_custom_rule_lab() {
    let root = workspace_root();
    let config = Config {
        rules_dir: root.join("examples/rules").to_string_lossy().into_owned(),
        sigma_dir: Some(root.join("examples/sigma").to_string_lossy().into_owned()),
        ..Config::default()
    };
    let engine = RuleEngine::load_from_config(&config).expect("load example rules");
    assert!(
        engine.len() >= 2,
        "expected demo rule + sigma import, got {}",
        engine.len()
    );
}

#[test]
fn loads_native_and_sigma_rules() {
    let root = workspace_root();
    let config = Config {
        rules_dir: root.join("rules").to_string_lossy().into_owned(),
        sigma_dir: Some(root.join("sigma").to_string_lossy().into_owned()),
        ..Config::default()
    };
    let engine = RuleEngine::load_from_config(&config).expect("load rules");
    assert!(engine.len() >= 7, "expected native + sigma rules");
}

#[test]
fn end_to_end_rule_match_without_ebpf() {
    let root = workspace_root();
    let config = Config {
        rules_dir: root.join("rules").to_string_lossy().into_owned(),
        sigma_dir: Some(root.join("sigma").to_string_lossy().into_owned()),
        ..Config::default()
    };
    let engine = RuleEngine::load_from_config(&config).expect("load rules");
    let mut enricher = Enricher::new("integration-test");

    let mut parent_comm = [0u8; MAX_COMM_LEN];
    parent_comm[..2].copy_from_slice(b"nc");
    enricher.enrich(SentinelEvent {
        kind: EventKind::ProcessFork as u32,
        pid: 4242,
        ppid: 4241,
        uid: 1000,
        gid: 1000,
        timestamp_ns: 0,
        comm: parent_comm,
        addr_family: 0,
        _pad: [0],
        dst_port: 0,
        dst_addr: 0,
        dst_addr_v6: [0; 16],
        flags: 0,
        path: [0u8; MAX_PATH_LEN],
    });

    // Parent nc (4241) recorded via fork; exec carries stale comm but correct path.
    let mut comm = [0u8; MAX_COMM_LEN];
    comm[..2].copy_from_slice(b"nc");
    let mut path = [0u8; MAX_PATH_LEN];
    path[..9].copy_from_slice(b"/bin/bash");
    let raw = SentinelEvent {
        kind: EventKind::Exec as u32,
        pid: 4242,
        ppid: 4241,
        uid: 1000,
        gid: 1000,
        timestamp_ns: 1,
        comm,
        addr_family: 0,
        _pad: [0],
        dst_port: 0,
        dst_addr: 0,
        dst_addr_v6: [0; 16],
        flags: 0,
        path,
    };
    let event = enricher.enrich(raw);

    let alerts = engine.evaluate(&event);
    assert!(
        alerts
            .iter()
            .any(|a| a.rule_id.contains("T1059") || a.rule_id.contains("sigma")),
        "expected reverse-shell style alert, got: {:?}",
        alerts.iter().map(|a| &a.rule_id).collect::<Vec<_>>()
    );
}

#[test]
fn bundled_ipv6_rule_matches_numeric_family() {
    let root = workspace_root();
    let config = Config {
        rules_dir: root.join("rules").to_string_lossy().into_owned(),
        ..Config::default()
    };
    let engine = RuleEngine::load_from_config(&config).expect("load rules");
    let mut enricher = Enricher::new("integration-test");
    let raw = SentinelEvent {
        kind: EventKind::Connect as u32,
        pid: 1,
        ppid: 0,
        uid: 0,
        gid: 0,
        timestamp_ns: 1,
        comm: [0u8; MAX_COMM_LEN],
        addr_family: sentinel_common::AF_INET6,
        _pad: [0],
        dst_port: 443,
        dst_addr: 0,
        dst_addr_v6: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        flags: 0,
        path: [0u8; MAX_PATH_LEN],
    };
    let event = enricher.enrich(raw);
    let alerts = engine.evaluate(&event);
    assert!(
        alerts.iter().any(|a| a.rule_id == "NET-IPv6-001"),
        "expected NET-IPv6-001, got {:?}",
        alerts.iter().map(|a| &a.rule_id).collect::<Vec<_>>()
    );
}

#[test]
fn cgroup_fixture_parses_in_container_context() {
    let fixture = "0::/kubepods.slice/cri-containerd-deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef.scope\n";
    let id = container_id_from_cgroup(fixture).expect("parse");
    assert_eq!(id.len(), 64);
}

#[tokio::test]
async fn testcontainers_privileged_smoke() {
    use testcontainers::runners::AsyncRunner;
    use testcontainers::{GenericImage, ImageExt};

    if std::env::var("DOCKER_HOST").is_err()
        && !std::path::Path::new("/var/run/docker.sock").exists()
    {
        eprintln!("skipping testcontainers smoke: docker unavailable");
        return;
    }

    let image = GenericImage::new("alpine", "3.20").with_privileged(true);
    let container = image.start().await.expect("start privileged container");
    assert!(!container.id().is_empty());
}

#[test]
#[ignore = "requires root, BTF, and CAP_BPF"]
fn ebpf_probe_loader_attaches() {
    if !std::path::Path::new("/sys/kernel/btf/vmlinux").exists() {
        eprintln!("skipping ebpf_probe_loader_attaches: kernel BTF unavailable");
        return;
    }
    raise_memlock_limit();
    ensure_btf_available().expect("BTF");
    match ProbeLoader::load() {
        Ok(_loader) => {}
        Err(err) => {
            let msg = format!("{err:#}");
            if std::env::var_os("CI").is_some() {
                eprintln!("skipping ebpf_probe_loader_attaches on CI: {msg}");
                return;
            }
            panic!("load and attach eBPF programs: {msg}");
        }
    }
}
