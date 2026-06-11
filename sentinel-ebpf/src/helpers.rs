use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns,
    },
    programs::TracePointContext,
};
use sentinel_common::{EventKind, ProcessNode, SentinelEvent, MAX_COMM_LEN, MAX_PATH_LEN};

use crate::{EVENTS, MONITORED_PATHS, PROCESS_TREE, SCRATCH};

const MAX_MONITORED: u32 = 64;

pub fn current_pid() -> u32 {
    (bpf_get_current_pid_tgid() >> 32) as u32
}

pub fn lookup_ppid(pid: u32) -> u32 {
    unsafe {
        if let Some(node) = PROCESS_TREE.get(&pid) {
            return node.ppid;
        }
    }
    0
}

pub fn current_ppid() -> u32 {
    lookup_ppid(current_pid())
}

pub fn read_comm() -> [u8; MAX_COMM_LEN] {
    bpf_get_current_comm().unwrap_or([0u8; MAX_COMM_LEN])
}

pub fn read_uid_gid() -> (u32, u32) {
    let val = bpf_get_current_uid_gid();
    (val as u32, (val >> 32) as u32)
}

pub fn read_kernel_comm(ptr: *const u8, dest: &mut [u8; MAX_COMM_LEN]) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        let _ = aya_ebpf::helpers::bpf_probe_read_kernel_buf(ptr, dest);
    }
}

pub fn read_user_path(ptr: *const u8, dest: &mut [u8; MAX_PATH_LEN]) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        let _ = aya_ebpf::helpers::bpf_probe_read_user_str_bytes(ptr, dest);
    }
}

fn str_len(buf: &[u8]) -> usize {
    buf.iter().position(|&b| b == 0).unwrap_or(buf.len())
}

pub fn path_matches_monitored(path: &[u8; MAX_PATH_LEN]) -> bool {
    let path_len = str_len(path);

    for i in 0..MAX_MONITORED {
        if let Some(prefix) = MONITORED_PATHS.get(i) {
            let prefix_len = str_len(prefix);
            if prefix_len == 0 {
                continue;
            }
            if path_len >= prefix_len && path[..prefix_len] == prefix[..prefix_len] {
                return true;
            }
        }
    }
    false
}

pub fn emit_event(
    kind: EventKind,
    comm: [u8; MAX_COMM_LEN],
    path: [u8; MAX_PATH_LEN],
    flags: u32,
    dst_addr: u32,
    dst_port: u16,
) {
    emit_event_with_pid(
        kind,
        current_pid(),
        current_ppid(),
        comm,
        path,
        flags,
        0,
        dst_addr,
        dst_port,
        [0u8; 16],
    );
}

pub fn emit_event_with_pid(
    kind: EventKind,
    pid: u32,
    ppid: u32,
    comm: [u8; MAX_COMM_LEN],
    path: [u8; MAX_PATH_LEN],
    flags: u32,
    addr_family: u8,
    dst_addr: u32,
    dst_port: u16,
    dst_addr_v6: [u8; 16],
) {
    let Some(scratch) = SCRATCH.get_ptr_mut(0) else {
        return;
    };
    if scratch.is_null() {
        return;
    }

    let event = unsafe { &mut *scratch };
    *event = SentinelEvent {
        kind: kind as u32,
        pid,
        ppid,
        uid: 0,
        gid: 0,
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        comm,
        addr_family,
        _pad: [0],
        dst_port,
        dst_addr,
        dst_addr_v6,
        flags,
        path,
    };
    let (uid, gid) = read_uid_gid();
    event.uid = uid;
    event.gid = gid;
    let _ = EVENTS.output(event, 0);
}

pub fn upsert_process(pid: u32, ppid: u32, comm: [u8; MAX_COMM_LEN], uid: u32) {
    let node = ProcessNode { ppid, uid, comm };
    unsafe {
        let _ = PROCESS_TREE.insert(&pid, &node, 0);
    }
}

pub fn read_at<T>(ctx: &TracePointContext, offset: usize) -> Result<T, ()> {
    unsafe { ctx.read_at(offset).map_err(|_| ()) }
}
