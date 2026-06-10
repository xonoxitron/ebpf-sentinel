#![no_std]
#![no_main]

mod helpers;
mod probes;

use aya_ebpf::{
    bindings::BPF_F_NO_PREALLOC,
    macros::map,
    maps::{Array, HashMap, PerCpuArray, RingBuf},
};

use sentinel_common::{ProcessNode, SentinelEvent, MAX_PATH_LEN};

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[map]
static SCRATCH: PerCpuArray<SentinelEvent> = PerCpuArray::with_max_entries(1, 0);

#[map]
static PROCESS_TREE: HashMap<u32, ProcessNode> = HashMap::with_max_entries(8192, BPF_F_NO_PREALLOC);

#[map]
static MONITORED_PATHS: Array<[u8; MAX_PATH_LEN]> = Array::with_max_entries(64, 0);

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
