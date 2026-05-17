//! **pktcap** — cross-platform packet capture with pktbaffle filter expressions.
//!
//! # Quick start
//!
//! ```no_run
//! use pktcap::Capture;
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
//! # Ok::<(), pktcap::Error>(())
//! ```

mod capture;
mod error;
mod file;
mod live;
mod packet;

pub use capture::{Capture, CaptureBuilder};
pub use error::{Error, Result};
pub use packet::{LinkType, Packet};

/// List available network interfaces by name.
pub fn interfaces() -> Result<Vec<String>> {
    live::list_interfaces()
}
