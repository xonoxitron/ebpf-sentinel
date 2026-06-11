# Portability and BTF

ebpf-sentinel targets Linux fleets running **kernel ≥ 5.8** with **BTF** enabled (`/sys/kernel/btf/vmlinux`).

## Supported architectures

| Arch | Status |
|------|--------|
| `x86_64` | Supported |
| `aarch64` | Supported |

Other architectures will fail at eBPF compile time.

## How probes attach

| Probe | Mechanism |
|-------|-----------|
| `sys_enter_execve`, `sys_enter_connect`, `sys_enter_openat` | Classic tracepoints with per-arch argument offsets |
| `sched_process_fork` | BTF raw tracepoint (portable across kernels ≥ 5.5) |
| `sched_process_exec` | Classic tracepoint offsets |

Syscall offsets are defined in `sentinel-ebpf/src/tracepoint_offsets.rs`. Verify against your kernel:

```bash
sudo cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_connect/format
```

Connect events read `sockaddr` via `bpf_probe_read_user` (binary data, not string reads).

## BTF requirement

The userspace loader calls `ensure_btf_available()` before loading programs. If BTF is missing:

1. Enable `CONFIG_DEBUG_INFO_BTF=y` and rebuild the kernel, or
2. Install your distro's `kernel-debug` / BTF package (e.g. Fedora `kernel-debug`, Ubuntu HWE with BTF).

## Troubleshooting

| Symptom | Likely cause |
|---------|----------------|
| `kernel BTF not found` | BTF not enabled or path not mounted |
| `attach BTF tracepoint sched_process_fork` | Kernel < 5.5 or tracing disabled |
| Wrong connect IPs | Check sockaddr parsing; IPv4 and IPv6 (`AF_INET6`) are supported |
| Fork events missing | Confirm `sched_process_fork` in `/sys/kernel/tracing/events/sched/` |

## CO-RE limits

Full Rust CO-RE field relocations (`bpf_core_read`) are not emitted by the Rust BPF target today. Fleet hardening uses BTF validation, BTF tracepoints where available, and centralized arch offset tables—not C-shim CO-RE for `task_struct`.
