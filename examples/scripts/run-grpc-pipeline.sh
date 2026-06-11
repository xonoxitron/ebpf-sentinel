#!/usr/bin/env bash
# Start grpc-ingest and sentinel (gRPC sink) in one script.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

test -x target/release/grpc-ingest || { echo "run: make build"; exit 1; }
test -x target/release/sentinel || { echo "run: make build"; exit 1; }

cleanup() {
  kill "$INGEST_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

echo "==> Starting grpc-ingest on :50051"
./target/release/grpc-ingest &
INGEST_PID=$!
sleep 1

if test "$(id -u)" -ne 0; then
  echo "==> Starting sentinel (sudo) with config/sentinel-grpc.yaml"
  exec sudo -E ./target/release/sentinel --config config/sentinel-grpc.yaml
else
  exec ./target/release/sentinel --config config/sentinel-grpc.yaml
fi
