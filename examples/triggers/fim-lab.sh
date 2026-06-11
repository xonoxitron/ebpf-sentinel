#!/usr/bin/env bash
# Safe FIM trigger for examples/config/fim-lab.yaml (monitors /tmp/sentinel-fim-lab).
set -euo pipefail

LAB_DIR="/tmp/sentinel-fim-lab"
TARGET="$LAB_DIR/sentinel-fim-test"

mkdir -p "$LAB_DIR"
echo "sentinel-fim-lab $(date -Is)" >"$TARGET"
echo "Wrote $TARGET (expect FIM-001 when sentinel uses fim-lab.yaml)."
