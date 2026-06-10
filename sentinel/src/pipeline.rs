use sentinel_common::SentinelEvent;

/// Parse a ring-buffer record into a [`SentinelEvent`].
///
/// Returns `None` when the payload is missing or the size does not match exactly.
pub fn parse_ring_event(item: &[u8]) -> Option<SentinelEvent> {
    let expected = core::mem::size_of::<SentinelEvent>();
    if item.len() != expected {
        return None;
    }
    Some(unsafe { (item.as_ptr() as *const SentinelEvent).read_unaligned() })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_common::{EventKind, MAX_COMM_LEN, MAX_PATH_LEN};

    fn sample_raw() -> SentinelEvent {
        let mut path = [0u8; MAX_PATH_LEN];
        path[..4].copy_from_slice(b"/tmp");
        SentinelEvent {
            kind: EventKind::Exec as u32,
            pid: 42,
            ppid: 1,
            uid: 1000,
            gid: 1000,
            timestamp_ns: 99,
            comm: {
                let mut c = [0u8; MAX_COMM_LEN];
                c[..4].copy_from_slice(b"bash");
                c
            },
            dst_addr: 0,
            dst_port: 0,
            flags: 0,
            path,
        }
    }

    #[test]
    fn parses_exact_sized_event() {
        let raw = sample_raw();
        let bytes = unsafe {
            core::slice::from_raw_parts(
                (&raw as *const SentinelEvent).cast::<u8>(),
                core::mem::size_of::<SentinelEvent>(),
            )
        };
        let parsed = parse_ring_event(bytes).expect("parse");
        assert_eq!(parsed.pid, 42);
        assert_eq!(parsed.kind, EventKind::Exec as u32);
    }

    #[test]
    fn rejects_short_buffer() {
        assert!(parse_ring_event(&[0u8; 8]).is_none());
    }

    #[test]
    fn rejects_oversized_buffer() {
        let raw = sample_raw();
        let mut bytes = vec![0u8; core::mem::size_of::<SentinelEvent>() + 4];
        bytes[..core::mem::size_of::<SentinelEvent>()].copy_from_slice(unsafe {
            core::slice::from_raw_parts(
                (&raw as *const SentinelEvent).cast::<u8>(),
                core::mem::size_of::<SentinelEvent>(),
            )
        });
        assert!(parse_ring_event(&bytes).is_none());
    }
}
