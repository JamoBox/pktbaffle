//! Windows live capture via Npcap.
//!
//! Npcap integration is not yet implemented. This stub compiles on Windows
//! but returns an error at runtime. See ADR 0003.

use crate::error::{Error, Result};
use crate::packet::{LinkType, Packet};

pub struct WindowsLive;

impl WindowsLive {
    pub fn open(
        _iface: &str,
        _filter: Option<&pktbaffle::bpf::Program>,
        _snaplen: u32,
        _promiscuous: bool,
    ) -> Result<Self> {
        Err(Error::Platform(
            "Windows live capture via Npcap is not yet implemented".into(),
        ))
    }

    pub fn link_type(&self) -> LinkType {
        LinkType::Ethernet
    }

    pub fn next_packet(&mut self) -> Result<Packet> {
        Err(Error::Platform("not implemented".into()))
    }
}

pub fn query_link_type(_iface: &str) -> Result<LinkType> {
    Ok(LinkType::Ethernet)
}

pub fn list_interfaces() -> Result<Vec<String>> {
    Err(Error::Platform(
        "interface enumeration on Windows is not yet implemented".into(),
    ))
}
