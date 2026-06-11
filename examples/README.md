# Examples

Hands-on recipes for **ebpf-sentinel**. Run all commands from the **repository root**.

## Catalog

| Path | Description |
|------|-------------|
| [`demo-detection.sh`](demo-detection.sh) | No-root build + rule-engine demo (`make demo`) |
| [`config/`](config/) | Ready-to-use config variants |
| [`rules/`](rules/) | Custom detection rule lab |
| [`sigma/`](sigma/) | Sample Sigma import rules |
| [`triggers/`](triggers/) | Safe scripts that fire bundled/lab detections |
| [`scripts/`](scripts/) | Preflight, live sensor, alert watcher, gRPC pipeline |
| [`deploy/`](deploy/) | systemd unit + Kubernetes DaemonSet |
| [`prometheus/`](prometheus/) | Scrape config for metrics |
| [`docker-compose.yml`](docker-compose.yml) | Reference `grpc-ingest` service |

---

## 1. Quick demo (no root)

```bash
make demo
# or: ./examples/demo-detection.sh
```

Builds the project and runs rule-engine + synthetic pipeline tests.

---

## 2. Live sensor workflow

**Terminal A** — preflight + start agent:

```bash
make build
./examples/scripts/live-sensor.sh config/sentinel.yaml
```

**Terminal B** — watch alerts:

```bash
./examples/scripts/watch-alerts.sh
```

**Terminal C** — fire detections:

```bash
./examples/triggers/all-bundled.sh
# or individually:
./examples/triggers/writable-staging.sh   # T1574.006-001
```

Alerts appear on **stderr** (stdout sink). NDJSON: `/tmp/sentinel/events.ndjson`.

---

## 3. Config variants

| Config | Use case |
|--------|----------|
| [`config/alerts-only.yaml`](config/alerts-only.yaml) | `--no-emit-events` style lab (use with live-sensor) |
| [`config/fim-lab.yaml`](config/fim-lab.yaml) | FIM on safe `/tmp/sentinel-fim-lab` path |
| [`config/custom-rule-lab.yaml`](config/custom-rule-lab.yaml) | Isolated custom rule in `examples/rules/` |
| [`config/triage.yaml`](config/triage.yaml) | Claude triage enabled |
| [`config/k8s-node.yaml`](config/k8s-node.yaml) | CRI / pod metadata enrichment |
| [`config/sentinel-grpc.yaml`](../config/sentinel-grpc.yaml) | gRPC sink to `grpc-ingest` |

```bash
# FIM lab
./examples/scripts/live-sensor.sh examples/config/fim-lab.yaml
./examples/triggers/fim-lab.sh

# Custom rule lab
./examples/scripts/live-sensor.sh examples/config/custom-rule-lab.yaml
./examples/triggers/custom-rule.sh

# Alerts-only
./examples/scripts/live-sensor.sh examples/config/alerts-only.yaml --no-emit-events
```

---

## 4. Custom detection rule

See [`rules/README.md`](rules/README.md). Minimal rule: [`rules/demo-tmp-echo.yaml`](rules/demo-tmp-echo.yaml).

Sigma sample: [`sigma/demo_tmp_shell.yml`](sigma/demo_tmp_shell.yml) (loaded when `sigma_dir: examples/sigma`).

---

## 5. gRPC pipeline

```bash
./examples/scripts/run-grpc-pipeline.sh
```

Or manually:

```bash
./target/release/grpc-ingest          # Terminal A
sudo -E ./target/release/sentinel --config config/sentinel-grpc.yaml  # Terminal B
```

Compose (ingest only, after `make build`):

```bash
docker compose -f examples/docker-compose.yml up
```

---

## 6. Prometheus

With `metrics.enabled: true`:

```bash
curl -s localhost:9090/metrics | grep sentinel_
```

Optional local Prometheus:

```bash
prometheus --config.file=examples/prometheus/prometheus.yml
```

---

## 7. Claude triage

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
./examples/scripts/live-sensor.sh examples/config/triage.yaml
./examples/triggers/writable-staging.sh
```

Rules with `actions: [alert, triage]` include a `triage` object on alert export.

---

## 8. Deployment

- **systemd:** [`deploy/sentinel.service`](deploy/sentinel.service) — see [`deploy/README.md`](deploy/README.md)
- **Kubernetes:** [`deploy/daemonset.yaml`](deploy/daemonset.yaml) + [`config/k8s-node.yaml`](config/k8s-node.yaml)

---

## Makefile shortcuts

```bash
make demo        # rule-engine demo (no root)
make preflight   # BTF + binary checks
make triggers    # run writable-staging trigger
```
