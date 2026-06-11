use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use crate::event::EnrichedEvent;
use crate::k8s::K8sMetadataCache;
use sentinel_common::{EventKind, SentinelEvent, MAX_COMM_LEN, MAX_PATH_LEN};

const MAX_PROCESSES: usize = 32_768;

#[derive(Clone, Default)]
struct ProcessInfo {
    ppid: u32,
    comm: String,
}

pub struct Enricher {
    host: String,
    processes: HashMap<u32, ProcessInfo>,
    max_lineage: usize,
    k8s: Option<Arc<K8sMetadataCache>>,
}

impl Enricher {
    pub fn new(host: impl Into<String>) -> Self {
        let mut enricher = Self {
            host: host.into(),
            processes: HashMap::new(),
            max_lineage: 8,
            k8s: None,
        };
        if let Err(e) = enricher.seed_from_proc() {
            log::warn!("could not seed process tree from /proc: {e:#}");
        }
        enricher
    }

    /// Seed userspace lineage from running processes (mirrors BPF map seeding).
    pub fn seed_from_proc(&mut self) -> anyhow::Result<()> {
        let proc = Path::new("/proc");
        for entry in std::fs::read_dir(proc)? {
            let entry = entry?;
            let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
                continue;
            };
            let stat_path = proc.join(entry.file_name()).join("stat");
            let comm_path = proc.join(entry.file_name()).join("comm");
            let comm = std::fs::read_to_string(&comm_path)
                .unwrap_or_default()
                .trim()
                .to_string();
            let ppid = parse_ppid(&stat_path).unwrap_or(0);
            self.processes.insert(pid, ProcessInfo { ppid, comm });
        }
        log::info!(
            "enricher seeded {} processes from /proc",
            self.processes.len()
        );
        Ok(())
    }

    pub fn with_k8s(mut self, cache: Arc<K8sMetadataCache>) -> Self {
        self.k8s = Some(cache);
        self
    }

    pub fn enrich(&mut self, raw: SentinelEvent) -> EnrichedEvent {
        self.update_tree(&raw);

        let kind = EventKind::from_u32(raw.kind)
            .map(|k| format!("{:?}", k).to_lowercase())
            .unwrap_or_else(|| format!("unknown({})", raw.kind));

        let path = cstr_path(&raw.path);
        let mut comm = cstr_comm(&raw.comm);
        if kind == "exec" && !path.is_empty() {
            // sys_enter_execve fires before the task comm is updated; use the binary path.
            comm = path_basename(&path);
        }
        let parent_comm = if kind == "processfork" {
            // Fork events carry the parent comm in `comm`.
            comm.clone()
        } else {
            self.processes
                .get(&raw.ppid)
                .map(|p| p.comm.clone())
                .unwrap_or_default()
        };

        let addr_family = if raw.addr_family != 0 {
            Some(raw.addr_family)
        } else {
            None
        };

        let dst_addr = if raw.addr_family == sentinel_common::AF_INET6 {
            Some(std::net::Ipv6Addr::from(raw.dst_addr_v6).to_string())
        } else if raw.dst_addr != 0 {
            Some(std::net::Ipv4Addr::from(raw.dst_addr.to_be()).to_string())
        } else {
            None
        };

        let dst_port = if raw.dst_port != 0 {
            Some(raw.dst_port)
        } else {
            None
        };

        let timestamp = chrono::DateTime::from_timestamp(
            (raw.timestamp_ns / 1_000_000_000) as i64,
            (raw.timestamp_ns % 1_000_000_000) as u32,
        )
        .map(|ts| ts.to_rfc3339());

        let k8s = self
            .k8s
            .as_ref()
            .and_then(|cache| cache.lookup_by_pid(raw.pid));

        EnrichedEvent {
            kind,
            pid: raw.pid,
            ppid: raw.ppid,
            uid: raw.uid,
            gid: raw.gid,
            timestamp_ns: raw.timestamp_ns,
            timestamp,
            comm,
            parent_comm,
            path,
            addr_family,
            dst_addr,
            dst_port,
            flags: raw.flags,
            lineage: self.lineage(raw.ppid),
            host: self.host.clone(),
            container_id: k8s.as_ref().map(|m| m.container_id.clone()),
            pod_name: k8s
                .as_ref()
                .map(|m| m.pod_name.clone())
                .filter(|s| !s.is_empty()),
            pod_namespace: k8s
                .as_ref()
                .map(|m| m.pod_namespace.clone())
                .filter(|s| !s.is_empty()),
            pod_image: k8s
                .as_ref()
                .map(|m| m.pod_image.clone())
                .filter(|s| !s.is_empty()),
        }
    }

    fn update_tree(&mut self, raw: &SentinelEvent) {
        match EventKind::from_u32(raw.kind) {
            Some(EventKind::ProcessFork) => {
                let parent_comm = cstr_comm(&raw.comm);
                self.processes.insert(
                    raw.pid,
                    ProcessInfo {
                        ppid: raw.ppid,
                        comm: String::new(),
                    },
                );
                if let Some(parent) = self.processes.get_mut(&raw.ppid) {
                    if parent.comm.is_empty() {
                        parent.comm = parent_comm.clone();
                    }
                } else {
                    self.processes.insert(
                        raw.ppid,
                        ProcessInfo {
                            ppid: 0,
                            comm: parent_comm,
                        },
                    );
                }
            }
            Some(EventKind::Exec) => {
                let path = cstr_path(&raw.path);
                let comm = if path.is_empty() {
                    cstr_comm(&raw.comm)
                } else {
                    path_basename(&path)
                };
                self.processes.insert(
                    raw.pid,
                    ProcessInfo {
                        ppid: raw.ppid,
                        comm,
                    },
                );
            }
            _ => {
                if !self.processes.contains_key(&raw.pid) {
                    self.processes.insert(
                        raw.pid,
                        ProcessInfo {
                            ppid: raw.ppid,
                            comm: cstr_comm(&raw.comm),
                        },
                    );
                }
            }
        }
        if self.processes.len() > MAX_PROCESSES {
            self.processes.clear();
            log::warn!("process cache exceeded {MAX_PROCESSES} entries; cleared");
        }
    }

    fn lineage(&self, mut pid: u32) -> Vec<String> {
        let mut chain = Vec::new();
        while pid > 0 && chain.len() < self.max_lineage {
            if let Some(info) = self.processes.get(&pid) {
                if !info.comm.is_empty() {
                    chain.push(info.comm.clone());
                }
                pid = info.ppid;
            } else {
                break;
            }
        }
        chain
    }
}

fn cstr_comm(buf: &[u8; MAX_COMM_LEN]) -> String {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(MAX_COMM_LEN);
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

fn cstr_path(buf: &[u8; MAX_PATH_LEN]) -> String {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(MAX_PATH_LEN);
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

fn path_basename(path: &str) -> String {
    Path::new(path)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(path)
        .to_string()
}

fn parse_ppid(stat_path: &Path) -> Option<u32> {
    let stat = std::fs::read_to_string(stat_path).ok()?;
    let rparen = stat.rfind(')')?;
    let rest = stat[rparen + 2..].split_whitespace().collect::<Vec<_>>();
    rest.get(1)?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_common::{SentinelEvent, AF_INET6};

    #[test]
    fn enriches_ipv6_connect() {
        let mut enricher = Enricher::new("test-host");
        let mut v6 = [0u8; 16];
        v6[15] = 1; // ::1
        let raw = SentinelEvent {
            kind: EventKind::Connect as u32,
            pid: 1,
            ppid: 0,
            uid: 0,
            gid: 0,
            timestamp_ns: 0,
            comm: [0u8; MAX_COMM_LEN],
            addr_family: AF_INET6,
            _pad: [0],
            dst_port: 443,
            dst_addr: 0,
            dst_addr_v6: v6,
            flags: 0,
            path: [0u8; MAX_PATH_LEN],
        };
        let event = enricher.enrich(raw);
        assert_eq!(event.addr_family, Some(AF_INET6));
        assert_eq!(event.dst_addr.as_deref(), Some("::1"));
        assert_eq!(event.dst_port, Some(443));
    }

    #[test]
    fn exec_comm_derived_from_path() {
        let mut enricher = Enricher::new("test-host");
        enricher.processes.insert(
            4241,
            ProcessInfo {
                ppid: 1,
                comm: "nc".into(),
            },
        );

        let mut path = [0u8; MAX_PATH_LEN];
        let binary = b"/bin/bash";
        path[..binary.len()].copy_from_slice(binary);
        let mut comm = [0u8; MAX_COMM_LEN];
        comm[..2].copy_from_slice(b"nc");

        let raw = SentinelEvent {
            kind: EventKind::Exec as u32,
            pid: 4242,
            ppid: 4241,
            uid: 1000,
            gid: 1000,
            timestamp_ns: 1,
            comm,
            addr_family: 0,
            _pad: [0],
            dst_port: 0,
            dst_addr: 0,
            dst_addr_v6: [0; 16],
            flags: 0,
            path,
        };
        let event = enricher.enrich(raw);
        assert_eq!(event.comm, "bash");
        assert_eq!(event.parent_comm, "nc");
    }
}
