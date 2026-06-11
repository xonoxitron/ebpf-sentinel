use aya_ebpf::{
    helpers::bpf_probe_read_user,
    macros::{btf_tracepoint, tracepoint},
    programs::{BtfTracePointContext, TracePointContext},
};
use sentinel_common::{EventKind, MAX_COMM_LEN, MAX_PATH_LEN};

use crate::helpers::{
    current_pid, emit_event, emit_event_with_pid, path_matches_monitored, read_at, read_comm,
    read_kernel_comm, read_user_path, upsert_process,
};
use crate::tracepoint_offsets::{
    SCHED_PROCESS_EXEC_COMM, SCHED_PROCESS_EXEC_PID, SYS_ENTER_CONNECT_ADDR,
    SYS_ENTER_EXECVE_FILENAME, SYS_ENTER_OPENAT_FILENAME, SYS_ENTER_OPENAT_FLAGS,
};

const AF_INET: u16 = 2;

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

    let filename_ptr: *const u8 = read_at(&ctx, SYS_ENTER_EXECVE_FILENAME)?;
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
    let addr_ptr: *const u8 = read_at(&ctx, SYS_ENTER_CONNECT_ADDR)?;
    if addr_ptr.is_null() {
        return Ok(());
    }

    let sa_buf: [u8; 8] =
        unsafe { bpf_probe_read_user(addr_ptr as *const [u8; 8]) }.unwrap_or([0; 8]);
    let sa_family = u16::from_ne_bytes([sa_buf[0], sa_buf[1]]);

    let mut dst_port = 0u16;
    let mut dst_addr = 0u32;
    if sa_family == AF_INET {
        let port = u16::from_ne_bytes([sa_buf[2], sa_buf[3]]);
        dst_addr = u32::from_ne_bytes([sa_buf[4], sa_buf[5], sa_buf[6], sa_buf[7]]);
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
    let filename_ptr: *const u8 = read_at(&ctx, SYS_ENTER_OPENAT_FILENAME)?;
    let flags: i32 = read_at(&ctx, SYS_ENTER_OPENAT_FLAGS)?;
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

#[btf_tracepoint(function = "sched_process_fork")]
pub fn sched_process_fork(ctx: BtfTracePointContext) -> u32 {
    let _ = unsafe { try_fork(ctx) };
    0
}

unsafe fn try_fork(ctx: BtfTracePointContext) -> Result<(), ()> {
    let parent_comm_ptr = ctx.arg::<*const u8>(0);
    let parent_pid: i32 = ctx.arg(1);
    let child_pid: i32 = ctx.arg(3);

    let mut parent_comm = [0u8; MAX_COMM_LEN];
    read_kernel_comm(parent_comm_ptr, &mut parent_comm);

    let (uid, _) = crate::helpers::read_uid_gid();
    upsert_process(child_pid as u32, parent_pid as u32, parent_comm, uid);

    emit_event_with_pid(
        EventKind::ProcessFork,
        child_pid as u32,
        parent_pid as u32,
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
    let comm: [u8; 16] = read_at(&ctx, SCHED_PROCESS_EXEC_COMM)?;
    let pid: u32 = read_at(&ctx, SCHED_PROCESS_EXEC_PID)?;
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
