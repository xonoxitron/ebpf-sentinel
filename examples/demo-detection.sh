#!/usr/bin/env bash
# Hands-on detection demo — no root required for the rule-engine section.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "==> ebpf-sentinel detection demo"
echo ""

echo "── 1. Build (userspace + eBPF bytecode)"
make build
echo ""

echo "── 2. Rule engine (reverse shell + Sigma import)"
cargo test --release -p sentinel --lib \
  matches_reverse_shell_pattern \
  matches_numeric_eq \
  rules::sigma::tests::translates_minimal_sigma_rule \
  -- --nocapture
echo ""

echo "── 3. End-to-end pipeline (synthetic exec event, no kernel)"
cargo test --release -p sentinel --test integration end_to_end_rule_match_without_ebpf -- --nocapture
echo ""

echo "── 4. Live sensor (requires root + BTF at /sys/kernel/btf/vmlinux)"
echo "    Terminal A:"
echo "      sudo -E ./target/release/sentinel --config config/sentinel.yaml"
echo ""
echo "    Terminal B (safe trigger — writable staging exec):"
echo "      cp /bin/ls /tmp/sentinel-demo && /tmp/sentinel-demo --version"
echo "      rm -f /tmp/sentinel-demo"
echo ""
echo "    Expect alert T1574.006-001 in stderr / NDJSON (see README)."
echo ""
echo "── 5. gRPC pipeline (optional)"
echo "    ./examples/scripts/run-grpc-pipeline.sh"
echo ""
echo "── 6. More examples"
echo "    examples/README.md          — full catalog"
echo "    examples/scripts/live-sensor.sh config/sentinel.yaml"
echo "    examples/triggers/all-bundled.sh"
echo "    examples/config/fim-lab.yaml + examples/triggers/fim-lab.sh"
echo ""
echo "Done."
