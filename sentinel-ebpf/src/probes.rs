use aya_ebpf::{macros::tracepoint, programs::TracePointContext};
use sentinel_common::{EventKind, MAX_PATH_LEN};

use crate::helpers::{
    current_pid, emit_event, emit_event_with_pid, path_matches_monitored, read_at, read_comm,
    read_user_path, upsert_process,
};

#[tracepoint(category = "syscalls", name = "sys_enter_execve")]
pub fn sys_enter_execve(ctx: TracePointContext) -> u32 {
    let _ = try_execve(ctx);
    0
}

fn try_execve(ctx: TracePointContext) -> Result<(), ()> {
    let comm = read_comm();
    let pid = current_pid();
    let ppid = crate::helpers::current_ppid();
    let (uid, _) = crate::helpers::read_uid_gid();

    let filename_ptr: *const u8 = read_at(&ctx, 16)?;
    let mut path = [0u8; MAX_PATH_LEN];
    read_user_path(filename_ptr, &mut path);

    upsert_process(pid, ppid, comm, uid);
    emit_event(EventKind::Exec, comm, path, 0, 0, 0);
    Ok(())
}

#[tracepoint(category = "syscalls", name = "sys_enter_connect")]
pub fn sys_enter_connect(ctx: TracePointContext) -> u32 {
    let _ = try_connect(ctx);
    0
}

fn try_connect(ctx: TracePointContext) -> Result<(), ()> {
    let comm = read_comm();
    let addr_ptr: *const u8 = read_at(&ctx, 24)?;
    if addr_ptr.is_null() {
        return Ok(());
    }

    let sa_family = unsafe { core::ptr::read_unaligned(addr_ptr as *const u16) };
    let mut dst_port = 0u16;
    let mut dst_addr = 0u32;
    if sa_family == 2 {
        let port = unsafe { core::ptr::read_unaligned(addr_ptr.add(2) as *const u16) };
        dst_addr = unsafe { core::ptr::read_unaligned(addr_ptr.add(4) as *const u32) };
        dst_port = u16::from_be(port);
    }

    emit_event(
        EventKind::Connect,
        comm,
        [0u8; MAX_PATH_LEN],
        0,
        dst_addr,
        dst_port,
    );
    Ok(())
}

#[tracepoint(category = "syscalls", name = "sys_enter_openat")]
pub fn sys_enter_openat(ctx: TracePointContext) -> u32 {
    let _ = try_openat(ctx);
    0
}

fn try_openat(ctx: TracePointContext) -> Result<(), ()> {
    let comm = read_comm();
    let filename_ptr: *const u8 = read_at(&ctx, 24)?;
    let flags: i32 = read_at(&ctx, 32)?;
    let mut path = [0u8; MAX_PATH_LEN];
    read_user_path(filename_ptr, &mut path);

    emit_event(EventKind::Open, comm, path, flags as u32, 0, 0);

    const O_ACCMODE: i32 = 0o3;
    const O_WRONLY: i32 = 0o1;
    const O_RDWR: i32 = 0o2;
    let access = flags & O_ACCMODE;
    if (access == O_WRONLY || access == O_RDWR) && path_matches_monitored(&path) {
        emit_event(EventKind::FileIntegrity, comm, path, flags as u32, 0, 0);
    }
    Ok(())
}

#[tracepoint(category = "sched", name = "sched_process_fork")]
pub fn sched_process_fork(ctx: TracePointContext) -> u32 {
    let _ = try_fork(ctx);
    0
}

fn try_fork(ctx: TracePointContext) -> Result<(), ()> {
    let parent_comm: [u8; 16] = read_at(&ctx, 8)?;
    let parent_pid: u32 = read_at(&ctx, 24)?;
    let child_pid: u32 = read_at(&ctx, 28)?;

    let (uid, _) = crate::helpers::read_uid_gid();
    upsert_process(child_pid, parent_pid, parent_comm, uid);

    emit_event_with_pid(
        EventKind::ProcessFork,
        child_pid,
        parent_pid,
        parent_comm,
        [0u8; MAX_PATH_LEN],
        0,
        0,
        0,
    );
    Ok(())
}

#[tracepoint(category = "sched", name = "sched_process_exec")]
pub fn sched_process_exec(ctx: TracePointContext) -> u32 {
    let _ = try_exec(ctx);
    0
}

fn try_exec(ctx: TracePointContext) -> Result<(), ()> {
    let comm: [u8; 16] = read_at(&ctx, 8)?;
    let pid: u32 = read_at(&ctx, 24)?;
    let ppid = {
        let from_tree = crate::helpers::lookup_ppid(pid);
        if from_tree != 0 {
            from_tree
        } else {
            crate::helpers::current_ppid()
        }
    };
    let (uid, _) = crate::helpers::read_uid_gid();
    upsert_process(pid, ppid, comm, uid);
    Ok(())
}
