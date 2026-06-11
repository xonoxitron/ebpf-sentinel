#!/usr/bin/env bash
# Run sentinel with preflight checks.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CONFIG="${1:-config/sentinel.yaml}"
EXTRA_ARGS=("${@:2}")

cd "$ROOT"

if test "$(id -u)" -ne 0; then
  echo "Re-running with sudo..."
  exec sudo -E "$0" "$CONFIG" "${EXTRA_ARGS[@]}"
fi

./examples/scripts/preflight.sh
mkdir -p /tmp/sentinel
echo ""
echo "==> Starting sentinel ($CONFIG)"
exec ./target/release/sentinel --config "$CONFIG" "${EXTRA_ARGS[@]}"
