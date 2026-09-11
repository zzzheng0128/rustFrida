//! Agent log metadata shared by the sender and host, without platform dependencies.

pub const FRAME_KIND_LOG_META: u8 = 0x88;
pub const LOG_META_LEN: usize = 16;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AgentLogMeta {
    pub pid: u32,
    pub tid: u32,
    /// CLOCK_MONOTONIC nanoseconds; zero means capture was unavailable.
    pub timestamp_ns: u64,
}

/// The existing five-byte frame header, followed by fixed-size log metadata.
/// Reject lengths that cannot be represented by the protocol's u32 payload size.
pub fn encode_header(meta: AgentLogMeta, message_len: usize) -> Option<[u8; 21]> {
    let payload_len = u32::try_from(message_len.checked_add(LOG_META_LEN)?).ok()?;
    let mut header = [0; 21];
    header[0] = FRAME_KIND_LOG_META;
    header[1..5].copy_from_slice(&payload_len.to_le_bytes());
    header[5..9].copy_from_slice(&meta.pid.to_le_bytes());
    header[9..13].copy_from_slice(&meta.tid.to_le_bytes());
    header[13..21].copy_from_slice(&meta.timestamp_ns.to_le_bytes());
    Some(header)
}

/// Decode metadata while leaving all original log bytes (including KT> text) intact.
pub fn decode_payload(payload: &[u8]) -> Option<(AgentLogMeta, &[u8])> {
    let meta = AgentLogMeta {
        pid: u32::from_le_bytes(payload.get(0..4)?.try_into().ok()?),
        tid: u32::from_le_bytes(payload.get(4..8)?.try_into().ok()?),
        timestamp_ns: u64::from_le_bytes(payload.get(8..16)?.try_into().ok()?),
    };
    Some((meta, payload.get(LOG_META_LEN..)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_has_existing_framing_and_little_endian_metadata() {
        let meta = AgentLogMeta {
            pid: 0x01020304,
            tid: 0x05060708,
            timestamp_ns: 0x090a0b0c0d0e0f10,
        };
        let header = encode_header(meta, 3).unwrap();
        assert_eq!(
            header,
            [0x88, 19, 0, 0, 0, 4, 3, 2, 1, 8, 7, 6, 5, 0x10, 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09,]
        );
    }

    #[test]
    fn roundtrip_preserves_kt_control_text_and_arbitrary_bytes() {
        let meta = AgentLogMeta {
            pid: 17,
            tid: 23,
            timestamp_ns: 1_234_567_890,
        };
        for message in [b"KT>sub svc".as_slice(), b"[agent] hook\nKT>regs x0", b"\0\xff\n", b""] {
            let header = encode_header(meta, message.len()).unwrap();
            let mut payload = header[5..].to_vec();
            payload.extend_from_slice(message);
            let (actual, body) = decode_payload(&payload).unwrap();
            assert_eq!(actual, meta);
            assert_eq!(body, message);
            assert_eq!(
                u32::from_le_bytes(header[1..5].try_into().unwrap()) as usize,
                payload.len()
            );
        }
    }

    #[test]
    fn every_truncated_metadata_header_is_rejected() {
        let bytes = [0; LOG_META_LEN];
        for len in 0..LOG_META_LEN {
            assert!(decode_payload(&bytes[..len]).is_none(), "length {len}");
        }
        assert_eq!(decode_payload(&bytes), Some((AgentLogMeta::default(), &b""[..])));
    }

    #[test]
    fn oversized_lengths_are_rejected_without_allocating_messages() {
        let meta = AgentLogMeta::default();
        let largest_message = u32::MAX as usize - LOG_META_LEN;
        let header = encode_header(meta, largest_message).unwrap();
        assert_eq!(&header[1..5], &u32::MAX.to_le_bytes());
        assert!(encode_header(meta, largest_message + 1).is_none());
        assert!(encode_header(meta, usize::MAX).is_none());
    }
}
