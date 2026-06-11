#!/usr/bin/env bash
# Tail NDJSON sink and print alerts (requires jq).
set -euo pipefail

PATH_NDJSON="${1:-/tmp/sentinel/events.ndjson}"

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required: sudo apt-get install -y jq"
  exit 1
fi

mkdir -p "$(dirname "$PATH_NDJSON")"
touch "$PATH_NDJSON"

echo "Watching alerts in $PATH_NDJSON (Ctrl-C to stop)"
tail -n 0 -F "$PATH_NDJSON" | jq -c 'select(.record_type == "alert") | .data | {rule_id, severity, title, event: {kind, comm, parent_comm, path, pid}}'
