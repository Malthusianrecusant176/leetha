/// Wire protocol matching the Python side:
/// 4 bytes: packet length (u32 big-endian)
/// 8 bytes: timestamp nanoseconds (i64 big-endian)
/// 4 bytes: interface index (u32 big-endian)
/// N bytes: raw packet

pub const HEADER_SIZE: usize = 16;

pub fn serialize_frame(packet: &[u8], timestamp_ns: i64, iface_index: u32) -> Vec<u8> {
    let pkt_len = packet.len() as u32;
    let mut buf = Vec::with_capacity(HEADER_SIZE + packet.len());
    buf.extend_from_slice(&pkt_len.to_be_bytes());
    buf.extend_from_slice(&timestamp_ns.to_be_bytes());
    buf.extend_from_slice(&iface_index.to_be_bytes());
    buf.extend_from_slice(packet);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_frame_header_size() {
        let frame = serialize_frame(b"hello", 1000, 0);
        assert_eq!(frame.len(), HEADER_SIZE + 5);
    }

    #[test]
    fn test_serialize_frame_round_trip() {
        let pkt = vec![0xffu8; 60];
        let ts: i64 = 1_700_000_000_000_000_000;
        let frame = serialize_frame(&pkt, ts, 2);

        let pkt_len = u32::from_be_bytes(frame[0..4].try_into().unwrap());
        let ts_back = i64::from_be_bytes(frame[4..12].try_into().unwrap());
        let idx = u32::from_be_bytes(frame[12..16].try_into().unwrap());

        assert_eq!(pkt_len, 60);
        assert_eq!(ts_back, ts);
        assert_eq!(idx, 2);
        assert_eq!(&frame[16..], &pkt[..]);
    }
}
