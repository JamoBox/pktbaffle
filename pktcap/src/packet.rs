use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub use pktbaffle::codegen::LinkType;

/// An owned captured packet.
#[derive(Debug, Clone)]
pub struct Packet {
    /// Raw packet bytes (up to snaplen).
    pub data: Vec<u8>,
    /// Capture timestamp.
    pub timestamp: SystemTime,
    /// On-wire length before any snaplen truncation.
    pub orig_len: u32,
    /// Link-layer framing of the capture source.
    pub link_type: LinkType,
}

impl Packet {
    pub(crate) fn new(
        data: Vec<u8>,
        ts_sec: u64,
        ts_nsec: u32,
        orig_len: u32,
        link_type: LinkType,
    ) -> Self {
        let timestamp = UNIX_EPOCH + Duration::new(ts_sec, ts_nsec);
        Self {
            data,
            timestamp,
            orig_len,
            link_type,
        }
    }

    /// Returns true if the packet was truncated by snaplen.
    pub fn is_truncated(&self) -> bool {
        self.data.len() < self.orig_len as usize
    }
}
