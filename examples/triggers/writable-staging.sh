#!/usr/bin/env bash
# Safe trigger for bundled rule T1574.006-001 (exec from /tmp).
set -euo pipefail

DEMO="/tmp/sentinel-demo-$$"
cp /bin/ls "$DEMO"
"$DEMO" --version >/dev/null
rm -f "$DEMO"
echo "Triggered writable staging exec (T1574.006-001)."
echo "Check sentinel stderr or NDJSON for the alert."
