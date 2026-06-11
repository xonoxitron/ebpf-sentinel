use std::path::Path;

use anyhow::Context as _;
use aya::maps::{Array, HashMap, RingBuf};
use aya::programs::{BtfTracePoint, TracePoint};
use aya::{Btf, Ebpf};
use sentinel_common::{ProcessNode, MAX_PATH_LEN};

const BTF_VMLINUX: &str = "/sys/kernel/btf/vmlinux";

pub struct ProbeLoader {
    ebpf: Ebpf,
}

impl ProbeLoader {
    pub fn load() -> anyhow::Result<Self> {
        ensure_btf_available()?;
        log_kernel_info();

        let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/sentinel"
        )))?;

        if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
            log::warn!("eBPF logger init failed: {e}");
        }

        let btf = Btf::from_sys_fs().context("load BTF from /sys/kernel/btf/vmlinux")?;

        Self::attach_tracepoint(
            &mut ebpf,
            "sys_enter_execve",
            "syscalls",
            "sys_enter_execve",
        )?;
        Self::attach_tracepoint(
            &mut ebpf,
            "sys_enter_connect",
            "syscalls",
            "sys_enter_connect",
        )?;
        Self::attach_tracepoint(
            &mut ebpf,
            "sys_enter_openat",
            "syscalls",
            "sys_enter_openat",
        )?;
        Self::attach_btf_tracepoint(&mut ebpf, "sched_process_fork", "sched_process_fork", &btf)?;
        Self::attach_tracepoint(
            &mut ebpf,
            "sched_process_exec",
            "sched",
            "sched_process_exec",
        )?;

        Ok(Self { ebpf })
    }

    fn attach_tracepoint(
        ebpf: &mut Ebpf,
        program: &str,
        category: &str,
        name: &str,
    ) -> anyhow::Result<()> {
        let prog: &mut TracePoint = ebpf
            .program_mut(program)
            .with_context(|| format!("program {program} not found"))?
            .try_into()?;
        prog.load()?;
        prog.attach(category, name)
            .with_context(|| format!("attach {category}/{name}"))?;
        log::info!("attached tracepoint {category}/{name}");
        Ok(())
    }

    fn attach_btf_tracepoint(
        ebpf: &mut Ebpf,
        program: &str,
        tracepoint: &str,
        btf: &Btf,
    ) -> anyhow::Result<()> {
        let prog: &mut BtfTracePoint = ebpf
            .program_mut(program)
            .with_context(|| format!("program {program} not found"))?
            .try_into()?;
        prog.load(tracepoint, btf)
            .with_context(|| format!("load BTF tracepoint {tracepoint}"))?;
        prog.attach()
            .with_context(|| format!("attach BTF tracepoint {tracepoint}"))?;
        log::info!("attached BTF tracepoint {tracepoint}");
        Ok(())
    }

    pub fn ring_buf(&mut self) -> anyhow::Result<RingBuf<aya::maps::MapData>> {
        Ok(RingBuf::try_from(
            self.ebpf.take_map("EVENTS").context("EVENTS map")?,
        )?)
    }

    pub fn populate_monitored_paths(&mut self, paths: &[String]) -> anyhow::Result<()> {
        let mut map: Array<_, [u8; MAX_PATH_LEN]> = Array::try_from(
            self.ebpf
                .map_mut("MONITORED_PATHS")
                .context("MONITORED_PATHS map")?,
        )?;

        for (idx, path) in paths.iter().take(64).enumerate() {
            let mut key = [0u8; MAX_PATH_LEN];
            let bytes = path.as_bytes();
            let len = bytes.len().min(MAX_PATH_LEN - 1);
            key[..len].copy_from_slice(&bytes[..len]);
            map.set(idx as u32, key, 0)?;
            log::info!("monitoring path prefix: {path}");
        }
        Ok(())
    }

    pub fn seed_process_tree(&mut self) -> anyhow::Result<()> {
        // Best-effort: seed from /proc for existing processes
        let mut map: HashMap<_, u32, ProcessNode> = HashMap::try_from(
            self.ebpf
                .map_mut("PROCESS_TREE")
                .context("PROCESS_TREE map")?,
        )?;

        let proc = Path::new("/proc");
        for entry in std::fs::read_dir(proc).context("read /proc")? {
            let entry = entry?;
            let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
                continue;
            };
            let stat_path = proc.join(entry.file_name()).join("stat");
            let comm_path = proc.join(entry.file_name()).join("comm");
            let status_path = proc.join(entry.file_name()).join("status");

            let comm = std::fs::read_to_string(&comm_path)
                .unwrap_or_default()
                .trim()
                .as_bytes()
                .iter()
                .copied()
                .chain(std::iter::repeat(0))
                .take(16)
                .collect::<Vec<_>>();
            let mut comm_arr = [0u8; 16];
            comm_arr[..comm.len().min(16)].copy_from_slice(&comm[..comm.len().min(16)]);

            let ppid = parse_ppid(&stat_path).unwrap_or(0);
            let uid = parse_uid(&status_path).unwrap_or(0);

            let node = ProcessNode {
                ppid,
                uid,
                comm: comm_arr,
            };
            let _ = map.insert(pid, node, 0);
        }
        log::info!("seeded process tree from /proc");
        Ok(())
    }
}

/// Require kernel BTF before loading eBPF programs.
pub fn ensure_btf_available() -> anyhow::Result<()> {
    if !Path::new(BTF_VMLINUX).exists() {
        anyhow::bail!(
            "kernel BTF not found at {BTF_VMLINUX}. \
             Enable CONFIG_DEBUG_INFO_BTF (Linux ≥ 5.8) or install the kernel BTF package. \
             See docs/PORTABILITY.md."
        );
    }
    Ok(())
}

fn log_kernel_info() {
    let release = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".into());
    let arch = std::env::consts::ARCH;
    log::info!("kernel {release} ({arch}), BTF available at {BTF_VMLINUX}");
}

fn parse_ppid(stat_path: &Path) -> Option<u32> {
    let stat = std::fs::read_to_string(stat_path).ok()?;
    // pid (comm) state ppid ...
    let rparen = stat.rfind(')')?;
    let rest = stat[rparen + 2..].split_whitespace().collect::<Vec<_>>();
    rest.get(1)?.parse().ok()
}

fn parse_uid(status_path: &Path) -> Option<u32> {
    let status = std::fs::read_to_string(status_path).ok()?;
    for line in status.lines() {
        if let Some(val) = line.strip_prefix("Uid:") {
            return val.split_whitespace().next()?.parse().ok();
        }
    }
    None
}

pub fn raise_memlock_limit() {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        log::debug!("could not raise memlock rlimit: {ret}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn btf_path_constant() {
        assert!(BTF_VMLINUX.contains("vmlinux"));
    }
}
