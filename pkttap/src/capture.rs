//! `Capture` — unified live / file packet source with a builder API.

use std::path::{Path, PathBuf};
use std::time::Duration;

use pktbaffle::codegen::LinkType;
use pktbaffle::{compile, Target};

use crate::error::{Error, Result};
use crate::file::FileCapture;
use crate::live::{self, Live};
use crate::packet::PacketRef;
#[cfg(target_os = "linux")]
use crate::ring::RingConfig;
use crate::stats::CaptureStats;

// ── Filter specification ──────────────────────────────────────────────────────

pub(crate) enum FilterSpec {
    String(String),
    Program(pktbaffle::bpf::Program),
}

// ── Source ────────────────────────────────────────────────────────────────────

enum Source {
    Live(String),
    File(PathBuf),
}

// ── Builder ───────────────────────────────────────────────────────────────────

/// Builder for a [`Capture`].
pub struct CaptureBuilder {
    source: Source,
    filter: Option<FilterSpec>,
    snaplen: u32,
    promiscuous: bool,
    buffer_timeout: Duration,
    nonblocking: bool,
    #[cfg(target_os = "linux")]
    ring: Option<RingConfig>,
}

impl CaptureBuilder {
    fn new_live(iface: &str) -> Self {
        Self {
            source: Source::Live(iface.to_owned()),
            filter: None,
            snaplen: 65535,
            promiscuous: false,
            buffer_timeout: Duration::from_millis(100),
            nonblocking: false,
            #[cfg(target_os = "linux")]
            ring: None,
        }
    }

    fn new_file(path: PathBuf) -> Self {
        Self {
            source: Source::File(path),
            filter: None,
            snaplen: 65535,
            promiscuous: false,
            buffer_timeout: Duration::from_millis(100),
            nonblocking: false,
            #[cfg(target_os = "linux")]
            ring: None,
        }
    }

    /// Set a filter expression.
    ///
    /// Accepts a `&str`, an `Option<&str>`, or `None`. Passing `None` (or an
    /// `Option` that is `None`) is a no-op — all packets are captured, the
    /// same as not calling `.filter()` at all. This lets callers pass an
    /// optional filter from a variable without a separate `if let`:
    ///
    /// ```no_run
    /// use pkttap::Capture;
    ///
    /// let expr: Option<&str> = Some("tcp port 443");
    ///
    /// // Works for all three: &str, Option<&str>, or None
    /// # fn example(expr: Option<&str>) -> pkttap::Result<()> {
    /// let _cap = Capture::from_file("traffic.pcap").filter(expr).open()?;
    /// let _cap = Capture::from_file("traffic.pcap").filter("tcp port 80").open()?;
    /// let _cap = Capture::from_file("traffic.pcap").filter(None::<&str>).open()?;
    /// # Ok(()) }
    /// ```
    pub fn filter<'a>(mut self, expr: impl Into<Option<&'a str>>) -> Self {
        self.filter = expr.into().map(|s| FilterSpec::String(s.to_owned()));
        self
    }

    /// Attach a pre-compiled cBPF program.
    pub fn filter_program(mut self, program: pktbaffle::bpf::Program) -> Self {
        self.filter = Some(FilterSpec::Program(program));
        self
    }

    /// Maximum bytes captured per packet (default: 65535).
    pub fn snaplen(mut self, n: u32) -> Self {
        self.snaplen = n;
        self
    }

    /// Enable or disable promiscuous mode (default: off).
    pub fn promiscuous(mut self, on: bool) -> Self {
        self.promiscuous = on;
        self
    }

    /// Kernel buffer flush interval (default: 100 ms).
    /// Relevant for live capture; ignored for file reading.
    pub fn buffer_timeout(mut self, d: Duration) -> Self {
        self.buffer_timeout = d;
        self
    }

    /// Enable non-blocking mode for live capture.
    ///
    /// When enabled, [`Capture::next`] returns `Ok(None)` immediately if no
    /// packet is available, rather than blocking until one arrives. Use this
    /// when integrating with an event loop or polling multiple sources.
    ///
    /// On Linux and macOS this sets `O_NONBLOCK` on the capture socket/fd via
    /// `fcntl`. On Windows this option is not yet supported and
    /// [`CaptureBuilder::open`] will return an error.
    ///
    /// Ignored for file-based captures (they never block).
    ///
    /// Defaults to `false` (blocking).
    pub fn nonblocking(mut self, nb: bool) -> Self {
        self.nonblocking = nb;
        self
    }

    /// Capture through a `TPACKET_V3` mmap ring buffer instead of `recvmsg()`
    /// (Linux only).
    ///
    /// The kernel writes frames straight into memory shared with this process,
    /// so reading a packet costs neither a syscall nor a kernel→userspace copy
    /// — the two per-packet costs the default path pays. Everything else is
    /// unchanged: the same filter, snaplen, statistics and non-blocking
    /// behaviour, and [`Capture::next`] still yields a borrowed
    /// [`PacketRef`](crate::PacketRef), now pointing into the ring itself.
    ///
    /// Accepts a [`RingConfig`], an `Option<RingConfig>`, or `None` — passing
    /// `None` keeps the default `recvmsg()` path.
    ///
    /// ```no_run
    /// use pkttap::{Capture, RingConfig};
    ///
    /// # fn run() -> pkttap::Result<()> {
    /// let mut cap = Capture::live("eth0")
    ///     .filter("tcp port 443")
    ///     .ring(RingConfig::new())
    ///     .open()?;
    /// # Ok(()) }
    /// ```
    ///
    /// Ignored for file captures. [`open`](Self::open) returns an error if the
    /// kernel is older than 3.2 (no `TPACKET_V3`) or cannot allocate a ring of
    /// the requested geometry; fall back to the default path by retrying
    /// without this call.
    #[cfg(target_os = "linux")]
    pub fn ring(mut self, cfg: impl Into<Option<RingConfig>>) -> Self {
        self.ring = cfg.into();
        self
    }

    /// Open the capture source.
    pub fn open(self) -> Result<Capture> {
        match self.source {
            Source::Live(iface) => {
                // Query the interface's actual link type before compiling the filter
                // so that field offsets in the BPF program match the captured frames.
                let link_type = live::query_link_type(&iface)?;
                let prog = compile_filter(self.filter, link_type)?;
                #[cfg(target_os = "linux")]
                let live = match &self.ring {
                    Some(cfg) => {
                        Live::open_ring(&iface, prog.as_ref(), self.snaplen, self.promiscuous, cfg)?
                    }
                    None => Live::open(&iface, prog.as_ref(), self.snaplen, self.promiscuous)?,
                };
                #[cfg(not(target_os = "linux"))]
                let live = Live::open(&iface, prog.as_ref(), self.snaplen, self.promiscuous)?;
                if self.nonblocking {
                    live.set_nonblocking(true)?;
                }
                Ok(Capture {
                    inner: Inner::Live(live),
                })
            }
            Source::File(path) => {
                // Pass the raw filter spec to FileCapture so it can compile the
                // string expression after detecting the file's link type.
                let fc = FileCapture::open(&path, self.filter)?;
                Ok(Capture {
                    inner: Inner::File(Box::new(fc)),
                })
            }
        }
    }
}

// ── Capture ───────────────────────────────────────────────────────────────────

enum Inner {
    Live(Live),
    // Boxed because `FileCapture` carries large pcap-file reader + scratch-buffer
    // state; without the box every `Capture` — live ones included — would pay
    // that footprint inline.
    File(Box<FileCapture>),
}

/// A packet source: either a live network interface or a pcap/pcapng file.
///
/// Iterate with [`Capture::next`] or collect with a `while let` loop.
pub struct Capture {
    inner: Inner,
}

impl Capture {
    /// Begin building a live capture on `iface`.
    pub fn live(iface: &str) -> CaptureBuilder {
        CaptureBuilder::new_live(iface)
    }

    /// Wrap an already-open [`Live`] source, e.g. one member socket of a
    /// [`crate::FanoutGroup`].
    #[cfg(target_os = "linux")]
    pub(crate) fn from_live(live: Live) -> Self {
        Self {
            inner: Inner::Live(live),
        }
    }

    /// Begin building a file capture from a pcap or pcapng file.
    pub fn from_file(path: impl AsRef<Path>) -> CaptureBuilder {
        CaptureBuilder::new_file(path.as_ref().to_owned())
    }

    /// Return cumulative packet statistics from the kernel capture layer.
    ///
    /// For live captures this queries the platform's capture statistics
    /// (`PACKET_STATISTICS` on Linux, `BIOCGSTATS` on macOS, `pcap_stats`
    /// on Windows). File-based captures always return a zeroed
    /// [`CaptureStats`].
    ///
    /// # Example
    ///
    /// ```no_run
    /// use pkttap::Capture;
    ///
    /// # fn run() -> pkttap::Result<()> {
    /// let mut cap = Capture::live("eth0").open()?;
    /// // … read packets …
    /// let s = cap.stats()?;
    /// println!("received={} dropped={}", s.received, s.dropped);
    /// # Ok(()) }
    /// ```
    pub fn stats(&mut self) -> Result<CaptureStats> {
        match &mut self.inner {
            Inner::Live(l) => l.stats(),
            Inner::File(_) => Ok(CaptureStats::default()),
        }
    }

    /// Return the link type of the capture source.
    pub fn link_type(&self) -> LinkType {
        match &self.inner {
            Inner::Live(l) => l.link_type(),
            Inner::File(f) => f.link_type(),
        }
    }

    /// Return the next matching packet, blocking if necessary.
    ///
    /// Returns `Ok(None)` at end-of-file for file captures.
    /// In blocking mode (the default), live captures block until a packet arrives.
    /// In non-blocking mode (enabled via [`CaptureBuilder::nonblocking`]),
    /// returns `Ok(None)` immediately when no packet is available.
    ///
    /// The yielded [`PacketRef`] borrows from the capture's internal buffer and
    /// is only valid until the next call to `next`. Call
    /// [`PacketRef::to_owned`] to retain a packet across iterations.
    ///
    /// Returns `Result<Option<PacketRef<'_>>>` rather than implementing
    /// `Iterator` for two reasons: I/O errors propagate via `?` without
    /// panicking, and the borrowed item makes this a lending iterator, which
    /// `std::iter::Iterator` cannot express.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Result<Option<PacketRef<'_>>> {
        match &mut self.inner {
            Inner::Live(l) => l.next_packet(),
            Inner::File(f) => f.next_packet(),
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

pub(crate) fn compile_filter(
    spec: Option<FilterSpec>,
    link: LinkType,
) -> Result<Option<pktbaffle::bpf::Program>> {
    match spec {
        None => Ok(None),
        Some(FilterSpec::Program(p)) => Ok(Some(p)),
        Some(FilterSpec::String(s)) => {
            let prog = compile(&s, link, Target::Classic)?;
            match prog {
                pktbaffle::Program::Classic(p) => Ok(Some(p)),
                pktbaffle::Program::Extended(_) => Err(Error::Platform(
                    "unexpected eBPF program for live capture".into(),
                )),
            }
        }
    }
}
