# Examples

## Quick demo (no root)

From the repository root:

```bash
chmod +x examples/demo-detection.sh
./examples/demo-detection.sh
```

This builds the project, runs rule-engine tests (reverse shell, IPv6 numeric match, Sigma import), and prints commands for live sensor trials.

## Live sensor

**Terminal A** — start the agent (repo root as working directory):

```bash
sudo -E ./target/release/sentinel --config config/sentinel.yaml
```

**Terminal B** — trigger a bundled detection safely:

```bash
# Writable staging execution (T1574.006-001)
cp /bin/ls /tmp/sentinel-demo && /tmp/sentinel-demo --version
rm -f /tmp/sentinel-demo
```

Alerts appear on **stderr** (stdout sink). NDJSON records append to `/tmp/sentinel/events.ndjson`.

## Alerts-only mode

```bash
sudo -E ./target/release/sentinel --config config/sentinel.yaml --no-emit-events
```

## gRPC ingest pipeline

```bash
# Terminal A
./target/release/grpc-ingest

# Terminal B
sudo -E ./target/release/sentinel --config config/sentinel-grpc.yaml
```

Or start only the ingest server via Compose (after `make build`):

```bash
docker compose -f examples/docker-compose.yml up
```

## Prometheus

With `metrics.enabled: true` in config:

```bash
curl -s localhost:9090/metrics | grep sentinel_
```

## Claude triage

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
# Enable triage.enabled: true in config/sentinel.yaml
sudo -E ./target/release/sentinel --config config/sentinel.yaml
```

Rules with `actions: [alert, triage]` receive structured triage JSON on alert export.
