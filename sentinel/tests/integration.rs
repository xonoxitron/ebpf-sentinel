use std::path::PathBuf;

use sentinel::config::Config;
use sentinel::enricher::Enricher;
use sentinel::k8s::container_id_from_cgroup;
use sentinel::loader::{ensure_btf_available, ProbeLoader};
use sentinel::rules::RuleEngine;
use sentinel_common::{EventKind, SentinelEvent, MAX_COMM_LEN, MAX_PATH_LEN};

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
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

    let mut comm = [0u8; MAX_COMM_LEN];
    comm[..4].copy_from_slice(b"bash");
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
        path: [0u8; MAX_PATH_LEN],
    };
    let mut event = enricher.enrich(raw);
    event.parent_comm = "nc".into();

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
    ensure_btf_available().expect("BTF");
    let _loader = ProbeLoader::load().expect("load and attach eBPF programs");
}
