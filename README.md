# ebpf-sentinel

**🛡️ eBPF-native Linux endpoint detection · 📜 detection-as-code · 🤖 Claude-powered alert triage**

[![CI](https://github.com/xonoxitron/ebpf-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/xonoxitron/ebpf-sentinel/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Rust](https://img.shields.io/badge/rust-nightly%20+%20stable-orange)
![eBPF](https://img.shields.io/badge/eBPF-Linux%205.8%2B-green)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-mapped-red)

> Production-oriented proof-of-concept for **kernel-level Linux endpoint security**: eBPF sensors, scalable telemetry pipelines, YAML detection-as-code, and **Claude-assisted SOAR triage** — designed for AI/ML infrastructure where observability must not compete with GPU workloads.

---

## Why this project exists

**ebpf-sentinel** is a hands-on implementation of a modern **Linux node sensor** — the kind of system used on detection platforms that protect large fleets of training and inference hosts. It demonstrates:

- **eBPF kernel instrumentation** (tracepoints, ring buffers, in-kernel maps) with minimal userspace overhead
- **Detection engineering** via version-controlled YAML rules mapped to **MITRE ATT&CK**
- **Security telemetry pipelines** (NDJSON, gRPC/protobuf) suitable for SIEM and internal platforms
- **AI-assisted detection & response** using the Anthropic Messages API for structured triage on ML-heavy endpoints

If you are evaluating candidates for **Linux kernel security**, **EDR**, **detection engineering**, or **AI × security** roles — this repository is meant to be clone-and-buildable evidence of end-to-end ownership.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                            Linux Kernel                                  │
│                                                                          │
│  syscalls/sys_enter_execve ──┐                                           │
│  syscalls/sys_enter_connect ─┼──► RingBuf (256 KiB, lock-free mmap)      │
│  syscalls/sys_enter_openat ──┤         │                                 │
│  sched/sched_process_fork  ──┤         │  PerCpuArray scratch (stack-safe)│
│  sched/sched_process_exec  ──┘         │                                 │
│  PROCESS_TREE · MONITORED_PATHS maps   │                                 │
└────────────────────────────────────────┼─────────────────────────────────┘
                                         │ zero-copy SentinelEvent
                                         ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                     sentinel daemon (Rust + Tokio)                       │
│                                                                          │
│  RingBuf consumer ──► Enricher (parent_comm, lineage) ──► RuleEngine     │
│                              │                              │            │
│                              ▼                              ▼            │
│                     Telemetry sinks                   Alert + MITRE       │
│                     (stdout / NDJSON / gRPC)              │              │
│                                                           ▼              │
│                                              ┌────────────────────────┐  │
│                                              │   Claude Triager       │  │
│                                              │  (ML-workload aware)   │  │
│                                              │  severity · reasoning  │  │
│                                              │  MITRE · remediation   │  │
│                                              │  false-positive score  │  │
│                                              └────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
```

### Design principles for ML workloads

| Concern | Approach |
|--------|----------|
| **CPU overhead** | Kernel events via tracepoints; single ring buffer; no per-event syscalls from probes |
| **Memory** | Fixed-size `#[repr(C)]` events; per-CPU scratch map avoids BPF stack exhaustion |
| **False positives on training nodes** | Claude triage prompt encodes ML context (PyTorch, checkpoints, telemetry) |
| **Fleet scale** | Stateless daemon; gRPC ingest for centralized pipelines; NDJSON for log aggregation |
| **Maintainability** | Rust userspace + Rust eBPF ([Aya](https://aya-rs.dev)); shared `sentinel-common` types |

---

## Feature matrix (job-relevant capabilities)

| Capability | Implementation |
|-----------|----------------|
| **eBPF / kernel sensors** | `sentinel-ebpf`: execve, connect, openat, fork/exec lineage, FIM |
| **Rust systems programming** | Workspace crates, `no_std` eBPF, async userspace daemon |
| **Detection-as-code** | YAML rules, regex pre-compiled at startup, MITRE metadata |
| **SIEM / log aggregation** | Structured JSON alerts; NDJSON sink |
| **Internal platform / API design** | gRPC + Protobuf (`SentinelIngest`); reference `grpc-ingest` server |
| **SOAR / automation** | Rule `actions: [alert, triage]` → Claude enrichment pipeline |
| **AI for security operations** | Anthropic API integration with structured triage JSON |
| **Process lineage** | In-kernel `PROCESS_TREE` map + userspace enricher |
| **File integrity monitoring** | Configurable path prefixes; write-capable open detection |
| **CI/CD** | GitHub Actions: build eBPF, unit tests, rustfmt |
| **Test-driven development** | Rule engine unit tests (prefix, regex, MITRE rules) |

---

## Quick start

### Prerequisites

```bash
# Toolchain (see rust-toolchain.toml)
rustup toolchain install nightly
rustup component add --toolchain nightly rust-src
cargo install bpf-linker

# System
# Linux ≥ 5.8 with BTF: /sys/kernel/btf/vmlinux
# clang / llvm, libelf
```

### Build

```bash
git clone https://github.com/xonoxitron/ebpf-sentinel.git
cd ebpf-sentinel
make build
# or: cargo build --release -p sentinel --bin sentinel --bin grpc-ingest
```

### Run (requires elevated privileges)

```bash
# CAP_BPF + CAP_PERFMON + CAP_SYS_ADMIN, or root
export ANTHROPIC_API_KEY="sk-ant-..."   # optional, for Claude triage

sudo -E ./target/release/sentinel --config config/sentinel.yaml
```

Enable triage in `config/sentinel.yaml`:

```yaml
triage:
  enabled: true
  api_key_env: ANTHROPIC_API_KEY
  model: claude-sonnet-4-20250514
  max_tokens: 1024
```

### Optional: gRPC ingest server (SOAR / platform sink)

```bash
./target/release/grpc-ingest
# listens on 0.0.0.0:50051 by default (override with SENTINEL_GRPC_ADDR)
```

---

## Example output

**Rule match (NDJSON / stdout):**

```json
{
  "rule_id": "T1059.004-001",
  "title": "Interactive Shell Spawned by Network Utility",
  "severity": "critical",
  "mitre": {
    "tactic": "Execution",
    "technique": "T1059.004"
  },
  "event": {
    "kind": "exec",
    "pid": 18341,
    "ppid": 18340,
    "comm": "bash",
    "parent_comm": "nc",
    "path": "/bin/bash",
    "lineage": ["nc", "systemd"]
  }
}
```

**Claude triage enrichment:**

```json
{
  "triage": {
    "severity": "critical",
    "summary": "Reverse shell pattern: bash spawned directly by netcat.",
    "reasoning": "Interactive shell with network utility parent is a high-fidelity execution chain. Unlikely to be legitimate ML training orchestration.",
    "mitre": ["T1059.004", "T1071.001"],
    "remediation": [
      "Isolate the node from the network.",
      "Kill PID 18341 and parent 18340; preserve memory if feasible.",
      "Audit UID 1000 credentials and recent outbound connections."
    ],
    "false_positive_likelihood": 0.03
  }
}
```

---

## Detection-as-code

Rules live in [`rules/`](rules/) — one YAML file per detection. Each rule supports:

- **Field matchers**: `eq`, `ne`, `prefix`, `suffix`, `contains`, `matches` (regex)
- **Boolean logic**: `all` / `any` condition groups
- **MITRE ATT&CK** metadata
- **Actions**: `alert`, `triage`

```yaml
id: T1059.004-001
title: Interactive Shell Spawned by Network Utility
severity: critical
mitre:
  tactic: Execution
  technique: T1059.004
conditions:
  all:
    - field: kind
      op: eq
      value: exec
    - field: comm
      op: matches
      value: "^(bash|sh|zsh|dash|fish)$"
    - field: parent_comm
      op: matches
      value: "^(nc|ncat|socat|python3?|perl|ruby|php|curl)$"
actions: [alert, triage]
```

### Event fields (enriched in userspace)

| Kind | Key fields |
|------|------------|
| `exec` | `comm`, `parent_comm`, `path`, `lineage`, `uid` |
| `connect` | `comm`, `dst_addr`, `dst_port` |
| `open` | `comm`, `path`, `flags` |
| `fileintegrity` | `comm`, `path`, `flags` |
| `processfork` | `comm`, `pid`, `ppid`, `uid` |

### Bundled detections

| ID | Name | Severity |
|----|------|----------|
| `T1059.004-001` | Interactive shell spawned by network utility | Critical |
| `T1574.006-001` | Binary executed from writable staging directory | High |
| `CUSTOM-ML-EXFIL-001` | Model artifact accessed by transfer utility | High |
| `T1003.008-001` | Access to credential store (`/etc/shadow`) | High |
| `FIM-001` | File integrity violation on monitored path | Critical |

---

## Project layout

```
ebpf-sentinel/
├── .github/workflows/ci.yml     # Build + test pipeline
├── config/sentinel.yaml         # Agent configuration
├── rules/                       # Detection-as-code (MITRE-mapped)
├── sentinel-common/             # Shared #[repr(C)] event types
├── sentinel-ebpf/               # Kernel probes (Aya, bpfel-unknown-none)
│   └── src/
│       ├── probes.rs            # execve · connect · openat · fork
│       └── helpers.rs           # emit · lineage · FIM matching
└── sentinel/                    # Userspace daemon
    ├── proto/sentinel.proto     # gRPC telemetry schema
    └── src/
        ├── loader.rs            # eBPF load · attach · map seeding
        ├── enricher.rs          # parent_comm · process lineage
        ├── rules/               # YAML engine · regex compile
        ├── triage.rs            # Claude SOAR integration
        └── sinks/               # stdout · NDJSON · gRPC
```

---

## Technology stack

| Layer | Technology |
|-------|------------|
| Kernel probes | Rust eBPF ([Aya](https://aya-rs.dev)), tracepoints, ring buffer |
| Userspace agent | Rust, Tokio, `aya`, `clap` |
| Rules | YAML, `serde`, `regex` (pre-compiled) |
| Triage | Anthropic Messages API, structured JSON |
| Telemetry | JSON, NDJSON, gRPC/Protobuf (Tonic) |
| Build | `aya-build`, `bpf-linker`, nightly `build-std` |

---

## Configuration reference

[`config/sentinel.yaml`](config/sentinel.yaml):

| Key | Description |
|-----|-------------|
| `rules_dir` | Path to YAML detection rules |
| `sigma_dir` | Optional Sigma rule import directory (`sigma-{id}` prefix) |
| `monitored_paths` | FIM path prefixes pushed to eBPF map |
| `sinks` | `stdout`, `ndjson`, or `grpc` outputs |
| `triage` | Claude model, token limit, API key env var |
| `host` | Hostname label on events/alerts |
| `metrics` | Prometheus scrape endpoint (`sentinel_events_total`, `sentinel_alerts_total`) |
| `suppression` | Per-rule alert rate limits |

### Sigma import

Sigma YAML rules under `sigma_dir` are translated into native rules. Supported mappings include `Image` → `comm`, `ParentImage` → `parent_comm`, `CommandLine` → `path`, and `logsource.category` → `kind`.

### Prometheus

When `metrics.enabled: true`, scrape `http://<host>:9090/metrics`:

```bash
curl -s localhost:9090/metrics | grep sentinel_
```

---

## Roadmap

- [x] CO-RE / BTF portability hardening for multi-kernel fleets
- [x] IPv6 connect telemetry (`sys_enter_connect` v6 parsing)
- [x] Alert suppression and per-rule rate limiting
- [x] Prometheus metrics (`sentinel_events_total`, `sentinel_alerts_total`)
- [x] Kubernetes pod metadata enrichment (CRI / container ID)
- [x] Sigma rule import
- [x] Integration tests with `testcontainers` + privileged CI runners

---

## Development

```bash
make test      # unit tests
make integration  # integration + sudo eBPF tests
make fmt       # rustfmt
make clippy    # lint (strict)
make ingest    # run gRPC reference server
```

---

## Security note

This agent loads eBPF programs into the kernel. Run only on systems you own. Review rules before enabling Claude triage in production — alerts may contain sensitive host telemetry.

---

## License

[MIT](LICENSE)

---

## Keywords

`eBPF` · `Linux kernel security` · `endpoint detection` · `EDR` · `detection engineering` · `detection-as-code` · `MITRE ATT&CK` · `Rust` · `Aya` · `tracepoints` · `ring buffer` · `SIEM` · `SOAR` · `Claude` · `Anthropic` · `security automation` · `ML infrastructure security` · `GPU training nodes` · `telemetry pipeline` · `gRPC` · `NDJSON` · `file integrity monitoring` · `process lineage` · `reverse shell detection`
