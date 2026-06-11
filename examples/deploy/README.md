# Deployment examples

## systemd (bare metal / VM)

```bash
sudo mkdir -p /opt/ebpf-sentinel /etc/ebpf-sentinel
sudo cp -r . /opt/ebpf-sentinel/
sudo cp config/sentinel.yaml /etc/ebpf-sentinel/
sudo cp examples/deploy/sentinel.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ebpf-sentinel
sudo journalctl -u ebpf-sentinel -f
```

Optional environment file `/etc/ebpf-sentinel/env`:

```bash
ANTHROPIC_API_KEY=sk-ant-...
RUST_LOG=info
```

## Kubernetes

1. Build and push a container image containing `sentinel` (not included — use your registry).
2. Apply the reference manifest:

```bash
kubectl apply -f examples/deploy/daemonset.yaml
```

3. Customize the ConfigMap with your rules or mount rules from a volume.

See also [`docs/K8S.md`](../../docs/K8S.md) and [`examples/config/k8s-node.yaml`](../config/k8s-node.yaml).
