use std::collections::HashMap;

use crate::event::EnrichedEvent;
use sentinel_common::{EventKind, SentinelEvent, MAX_COMM_LEN, MAX_PATH_LEN};

#[derive(Clone, Default)]
struct ProcessInfo {
    ppid: u32,
    comm: String,
}

pub struct Enricher {
    host: String,
    processes: HashMap<u32, ProcessInfo>,
    max_lineage: usize,
}

impl Enricher {
    pub fn new(host: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            processes: HashMap::new(),
            max_lineage: 8,
        }
    }

    pub fn enrich(&mut self, raw: SentinelEvent) -> EnrichedEvent {
        self.update_tree(&raw);

        let kind = EventKind::from_u32(raw.kind)
            .map(|k| format!("{:?}", k).to_lowercase())
            .unwrap_or_else(|| format!("unknown({})", raw.kind));

        let comm = cstr_comm(&raw.comm);
        let path = cstr_path(&raw.path);
        let parent_comm = self
            .processes
            .get(&raw.ppid)
            .map(|p| p.comm.clone())
            .unwrap_or_default();

        let dst_addr = if raw.dst_addr != 0 {
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
            dst_addr,
            dst_port,
            flags: raw.flags,
            lineage: self.lineage(raw.ppid),
            host: self.host.clone(),
        }
    }

    fn update_tree(&mut self, raw: &SentinelEvent) {
        match EventKind::from_u32(raw.kind) {
            Some(EventKind::ProcessFork) => {
                self.processes.insert(
                    raw.pid,
                    ProcessInfo {
                        ppid: raw.ppid,
                        comm: cstr_comm(&raw.comm),
                    },
                );
            }
            Some(EventKind::Exec) => {
                self.processes.insert(
                    raw.pid,
                    ProcessInfo {
                        ppid: raw.ppid,
                        comm: cstr_comm(&raw.comm),
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
