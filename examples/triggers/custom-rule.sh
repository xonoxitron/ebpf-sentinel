#!/usr/bin/env bash
# Trigger for DEMO-TMP-ECHO-001 (examples/config/custom-rule-lab.yaml).
set -euo pipefail

DEMO="/tmp/sentinel-echo-$$"
cp /bin/echo "$DEMO"
"$DEMO" "ebpf-sentinel lab"
rm -f "$DEMO"
echo "Triggered custom rule DEMO-TMP-ECHO-001."
