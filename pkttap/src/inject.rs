//! `Injector` — send raw link-layer frames onto a network interface ([#93]).
//!
//! [`Capture`](crate::Capture) is receive-only. `Injector` is its transmit
//! counterpart, the equivalent of libpcap's `pcap_inject()` /
//! `pcap_sendpacket()`: it writes complete frames — link-layer header
//! included — straight onto the wire, for traffic replay, fuzzing, and test
//! tooling.
//!
//! ```no_run
//! use pkttap::{Capture, Injector};
//!
//! # fn run() -> pkttap::Result<()> {
//! // Replay a capture file onto an interface.
//! let inj = Injector::on_interface("eth0")?;
//! let mut cap = Capture::from_file("traffic.pcap").open()?;
//! while let Some(pkt) = cap.next()? {
//!     inj.send(pkt.data())?;
//! }
//! # Ok(()) }
//! ```
//!
//! [#93]: https://github.com/JamoBox/pktbaffle/issues/93

use crate::error::{Error, Result};
use crate::live::PlatformInjector;
use crate::packet::LinkType;

/// A handle for transmitting raw frames on one network interface.
///
/// Frames passed to [`send`](Self::send) go out exactly as given: pkttap adds
/// no link-layer header, fills in no addresses, and computes no checksums.
/// Each frame must therefore already be in the interface's link-layer format,
/// which [`link_type`](Self::link_type) reports — a complete Ethernet frame
/// (destination MAC, source MAC, EtherType, payload) on an Ethernet interface.
/// The frame check sequence is not included; the NIC appends it.
///
/// An `Injector` only transmits. It never receives, so an idle one queues no
/// inbound traffic in the kernel. To see the frames it sends, open a
/// [`Capture`](crate::Capture) on the same interface.
///
/// `send` takes `&self`, and `Injector` is `Send + Sync`, so one injector can
/// be shared between threads (e.g. behind an `Arc`).
///
/// # Privileges
///
/// Injection needs the same elevated privileges as live capture: `CAP_NET_RAW`
/// (or root) on Linux, write access to `/dev/bpf*` on macOS, and Npcap on
/// Windows. Without them, [`on_interface`](Self::on_interface) returns
/// [`Error::PermissionDenied`] or a platform error.
///
/// # Platform implementation
///
/// | Platform | Mechanism |
/// |----------|-----------|
/// | Linux    | `send()` on an `AF_PACKET` / `SOCK_RAW` socket bound to the interface |
/// | macOS    | `write()` on a `/dev/bpf*` device, with `BIOCSHDRCMPLT` set so the kernel keeps the frame's source MAC |
/// | Windows  | `pcap_sendpacket()` via Npcap |
pub struct Injector {
    inner: PlatformInjector,
}

impl Injector {
    /// Open an injector on `iface`.
    ///
    /// Interface names follow the same rules as
    /// [`Capture::live`](crate::Capture::live): `eth0` / `lo` on Linux, `en0`
    /// on macOS, and an Npcap friendly name or `\Device\NPF_{GUID}` path on
    /// Windows.
    ///
    /// Returns an error if the interface does not exist or the process lacks
    /// the privileges to transmit on it.
    pub fn on_interface(iface: &str) -> Result<Self> {
        PlatformInjector::open(iface).map(|inner| Self { inner })
    }

    /// Transmit one frame, returning the number of bytes sent.
    ///
    /// `frame` must be a complete link-layer frame in the format given by
    /// [`link_type`](Self::link_type); it is sent unmodified. On success the
    /// whole frame has been handed to the interface, so the returned count
    /// equals `frame.len()`.
    ///
    /// Returns an error — without sending anything — if `frame` is empty, or
    /// if the OS rejects it: typically because it is shorter than the
    /// link-layer header or longer than the interface MTU plus that header,
    /// or because the interface is down.
    pub fn send(&self, frame: &[u8]) -> Result<usize> {
        if frame.is_empty() {
            return Err(Error::Platform("cannot inject an empty frame".into()));
        }
        self.inner.send(frame)
    }

    /// The link-layer format frames sent through this injector must use.
    pub fn link_type(&self) -> LinkType {
        self.inner.link_type()
    }
}

impl std::fmt::Debug for Injector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Injector")
            .field("link_type", &self.link_type())
            .finish_non_exhaustive()
    }
}
