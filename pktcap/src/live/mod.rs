#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "linux")]
pub use linux::{list_interfaces, query_link_type, LinuxLive as PlatformLive};
#[cfg(target_os = "macos")]
pub use macos::{list_interfaces, query_link_type, MacosLive as PlatformLive};
#[cfg(target_os = "windows")]
pub use windows::{list_interfaces, query_link_type, WindowsLive as PlatformLive};

use crate::error::Result;
use crate::packet::{LinkType, Packet};
#[cfg(unix)]
use crate::error::Error;

// ── Shared helpers ────────────────────────────────────────────────────────────

/// Map a libpcap / BPF DLT value to our LinkType.
/// Used by the macOS (BIOCGDLT) and Windows (pcap_datalink) backends.
#[cfg(any(target_os = "macos", target_os = "windows"))]
pub(super) fn dlt_to_link_type(dlt: u32) -> LinkType {
    match dlt {
        1 => LinkType::Ethernet,   // DLT_EN10MB
        101 => LinkType::RawIp,    // DLT_RAW
        113 => LinkType::LinuxSll, // DLT_LINUX_SLL
        _ => LinkType::Ethernet,
    }
}

/// Wrap `errno` as an `Error`. Used by the Linux and macOS backends.
#[cfg(unix)]
pub(super) fn io_err() -> Error {
    std::io::Error::last_os_error().into()
}

/// Platform-agnostic wrapper around the live capture backend.
pub struct Live(pub PlatformLive);

impl Live {
    pub fn open(
        iface: &str,
        filter: Option<&pktbaffle::bpf::Program>,
        snaplen: u32,
        promiscuous: bool,
    ) -> Result<Self> {
        PlatformLive::open(iface, filter, snaplen, promiscuous).map(Live)
    }

    pub fn next_packet(&mut self) -> Result<Packet> {
        self.0.next_packet()
    }

    pub fn link_type(&self) -> crate::packet::LinkType {
        self.0.link_type()
    }
}
