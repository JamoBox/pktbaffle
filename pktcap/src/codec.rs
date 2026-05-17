//! Conversions between pcap-file's DataLink and our LinkType.
//!
//! Centralised here so that file.rs (reading) and dump.rs (writing) share one
//! mapping. Add a new arm here whenever a new LinkType variant is added.

use pcap_file::DataLink;

use crate::packet::LinkType;

pub(crate) fn datalink_to_link_type(dl: DataLink) -> LinkType {
    match dl {
        DataLink::ETHERNET => LinkType::Ethernet,
        DataLink::RAW => LinkType::RawIp,
        DataLink::LINUX_SLL => LinkType::LinuxSll,
        _ => LinkType::Ethernet,
    }
}

pub(crate) fn link_type_to_datalink(lt: LinkType) -> DataLink {
    match lt {
        LinkType::Ethernet => DataLink::ETHERNET,
        LinkType::RawIp => DataLink::RAW,
        LinkType::LinuxSll => DataLink::LINUX_SLL,
    }
}
