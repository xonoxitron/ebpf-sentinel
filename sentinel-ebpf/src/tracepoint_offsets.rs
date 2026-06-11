//! Architecture-specific tracepoint argument offsets.
//!
//! Syscall tracepoints use the legacy `TracePointContext::read_at` layout documented under
//! `/sys/kernel/debug/tracing/events/syscalls/*/format`. Sched `sched_process_exec` uses the
//! same layout; `sched_process_fork` is attached as a BTF raw tracepoint instead.

#[cfg(bpf_target_arch = "x86_64")]
mod arch {
    pub const SYS_ENTER_EXECVE_FILENAME: usize = 16;
    pub const SYS_ENTER_CONNECT_ADDR: usize = 24;
    pub const SYS_ENTER_OPENAT_FILENAME: usize = 24;
    pub const SYS_ENTER_OPENAT_FLAGS: usize = 32;
    pub const SCHED_PROCESS_EXEC_COMM: usize = 8;
    pub const SCHED_PROCESS_EXEC_PID: usize = 24;
}

#[cfg(bpf_target_arch = "aarch64")]
mod arch {
    pub const SYS_ENTER_EXECVE_FILENAME: usize = 16;
    pub const SYS_ENTER_CONNECT_ADDR: usize = 24;
    pub const SYS_ENTER_OPENAT_FILENAME: usize = 24;
    pub const SYS_ENTER_OPENAT_FLAGS: usize = 32;
    pub const SCHED_PROCESS_EXEC_COMM: usize = 8;
    pub const SCHED_PROCESS_EXEC_PID: usize = 24;
}

#[cfg(not(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64")))]
compile_error!("sentinel-ebpf supports only x86_64 and aarch64 BPF targets");

pub use arch::*;
