#!/usr/bin/env bash
# Preflight checks before running the live eBPF sensor.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

fail=0

check() {
  if "$@"; then
    echo "  OK   $*"
  else
    echo "  FAIL $*"
    fail=1
  fi
}

echo "==> ebpf-sentinel preflight"
echo ""

echo "── Repository"
test -f Cargo.toml && echo "  OK   repo root ($ROOT)" || { echo "  FAIL not at repo root"; exit 1; }
test -d rules && echo "  OK   rules/" || { echo "  FAIL rules/ missing"; fail=1; }

echo ""
echo "── Build artifacts"
if test -x target/release/sentinel; then
  echo "  OK   target/release/sentinel"
else
  echo "  WARN sentinel binary missing — run: make build"
  fail=1
fi

echo ""
echo "── Kernel BTF"
if test -f /sys/kernel/btf/vmlinux; then
  echo "  OK   /sys/kernel/btf/vmlinux"
else
  echo "  FAIL BTF not available (Linux ≥ 5.8 + CONFIG_DEBUG_INFO_BTF)"
  fail=1
fi

echo ""
echo "── Privileges"
if test "$(id -u)" -eq 0; then
  echo "  OK   running as root"
elif command -v capsh >/dev/null 2>&1; then
  caps="$(capsh --print 2>/dev/null | tr '\n' ' ')"
  if grep -q cap_bpf <<<"$caps" && grep -q cap_perfmon <<<"$caps"; then
    echo "  OK   CAP_BPF + CAP_PERFMON present"
  else
    echo "  WARN need root or CAP_BPF,CAP_PERFMON,CAP_SYS_ADMIN"
    fail=1
  fi
else
  echo "  WARN not root — live sensor requires elevated privileges"
  fail=1
fi

echo ""
if test "$fail" -eq 0; then
  echo "Preflight passed."
  exit 0
fi
echo "Preflight failed — fix items above or use: make demo (no root)"
exit 1
