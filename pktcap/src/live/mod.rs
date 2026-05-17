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
use crate::packet::Packet;

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
