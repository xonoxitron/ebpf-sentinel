#!/usr/bin/env bash
# Run all safe bundled triggers (sensor must be running with config/sentinel.yaml).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

echo "==> Running bundled detection triggers"
echo ""

echo "── T1574.006-001 writable staging"
./examples/triggers/writable-staging.sh
echo ""

echo "── FIM lab (skip if not using fim-lab.yaml)"
./examples/triggers/fim-lab.sh || true
echo ""

echo "Done. Watch alerts:"
echo "  ./examples/scripts/watch-alerts.sh"
