#![no_std]

pub const MAX_COMM_LEN: usize = 16;
pub const MAX_PATH_LEN: usize = 128;

/// Kernel → userspace event kinds.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventKind {
    Exec = 1,
    Connect = 2,
    Open = 3,
    FileIntegrity = 4,
    ProcessFork = 5,
}

impl EventKind {
    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            1 => Some(Self::Exec),
            2 => Some(Self::Connect),
            3 => Some(Self::Open),
            4 => Some(Self::FileIntegrity),
            5 => Some(Self::ProcessFork),
            _ => None,
        }
    }
}

/// Fixed-size process tree node stored in BPF maps.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ProcessNode {
    pub ppid: u32,
    pub uid: u32,
    pub comm: [u8; MAX_COMM_LEN],
}

/// Unified ring-buffer event emitted by all probes.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SentinelEvent {
    pub kind: u32,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub timestamp_ns: u64,
    pub comm: [u8; MAX_COMM_LEN],
    pub dst_addr: u32,
    pub dst_port: u16,
    pub flags: u32,
    pub path: [u8; MAX_PATH_LEN],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ProcessNode {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for SentinelEvent {}
