# Kubernetes deployment

ebpf-sentinel can enrich events with pod metadata by combining **cgroup container ID** parsing with **CRI RuntimeService** lookups.

## Requirements

- Linux node with containerd or CRI-O
- CRI socket mounted into the sentinel pod (default: `/run/containerd/containerd.sock`)
- `hostPID: true` recommended so `/proc/<pid>/cgroup` reflects node cgroups

## Configuration

```yaml
k8s:
  enabled: true
  cri_socket: /run/containerd/containerd.sock
  cache_ttl_secs: 30
```

CRI-O nodes typically use `/var/run/crio/crio.sock`.

## DaemonSet notes

```yaml
spec:
  hostPID: true
  containers:
    - name: sentinel
      securityContext:
        privileged: true
      volumeMounts:
        - name: cri-sock
          mountPath: /run/containerd/containerd.sock
  volumes:
    - name: cri-sock
      hostPath:
        path: /run/containerd/containerd.sock
        type: Socket
```

## Enriched fields

| Field | Source |
|-------|--------|
| `container_id` | `/proc/<pid>/cgroup` |
| `pod_name` | CRI `ListPodSandbox` |
| `pod_namespace` | CRI `ListPodSandbox` |
| `pod_image` | CRI `ListContainers` |

Rules can match on `pod_name`, `namespace`, `container_id`, and `pod_image`.
