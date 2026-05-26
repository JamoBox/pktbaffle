//! **pkttap** — cross-platform packet capture with pktbaffle filter expressions.
//!
//! # Quick start
//!
//! ```no_run
//! use pkttap::Capture;
//!
//! // Live capture
//! let mut cap = Capture::live("eth0")
//!     .promiscuous(true)
//!     .filter("tcp port 443")
//!     .open()?;
//!
//! while let Some(pkt) = cap.next()? {
//!     println!("{} bytes", pkt.data.len());
//! }
//!
//! // File capture
//! let mut cap = Capture::from_file("dump.pcap")
//!     .filter("udp port 53")
//!     .open()?;
//!
//! while let Some(pkt) = cap.next()? {
//!     println!("{} bytes at {:?}", pkt.data.len(), pkt.timestamp);
//! }
//! # Ok::<(), pkttap::Error>(())
//! ```

mod capture;
mod codec;
mod dump;
mod error;
mod file;
mod live;
mod packet;

pub use capture::{Capture, CaptureBuilder};
pub use dump::{Dump, DumpBuilder};
pub use error::{Error, Result};
pub use packet::{LinkType, Packet};

/// List available network interfaces by name.
pub fn interfaces() -> Result<Vec<String>> {
    live::list_interfaces()
}

/// Return the name of the default network interface for live capture.
///
/// This is the first non-loopback interface the OS makes available — the
/// same device `pcap_lookupdev` would return. Useful as a sensible default
/// in CLIs or UIs when the user has not specified an interface.
///
/// Returns `Err` if no usable interface is found, or if the platform capture
/// backend (e.g. Npcap on Windows) is not available.
pub fn default_interface() -> Result<String> {
    live::default_interface()
}

/// Write `packets` to a pcap or pcapng file in one call.
///
/// The format is chosen by file extension (`.pcap` or `.pcapng`).
/// This is a convenience wrapper around [`Dump`]; for streaming use,
/// open a `Dump` directly.
pub fn dump_packets(
    path: impl AsRef<std::path::Path>,
    packets: &[Packet],
    link_type: LinkType,
) -> Result<()> {
    let mut d = Dump::to_file(path).link_type(link_type).open()?;
    for pkt in packets {
        d.write_packet(pkt)?;
    }
    Ok(())
}
