//! `Capture` — unified live / file packet source with a builder API.

use std::path::{Path, PathBuf};
use std::time::Duration;

use pktbaffle::codegen::LinkType;
use pktbaffle::{compile, Target};

use crate::error::{Error, Result};
use crate::file::FileCapture;
use crate::live::{self, Live};
use crate::packet::Packet;

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
}

impl CaptureBuilder {
    fn new_live(iface: &str) -> Self {
        Self {
            source: Source::Live(iface.to_owned()),
            filter: None,
            snaplen: 65535,
            promiscuous: false,
            buffer_timeout: Duration::from_millis(100),
        }
    }

    fn new_file(path: PathBuf) -> Self {
        Self {
            source: Source::File(path),
            filter: None,
            snaplen: 65535,
            promiscuous: false,
            buffer_timeout: Duration::from_millis(100),
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

    /// Open the capture source.
    pub fn open(self) -> Result<Capture> {
        match self.source {
            Source::Live(iface) => {
                // Query the interface's actual link type before compiling the filter
                // so that field offsets in the BPF program match the captured frames.
                let link_type = live::query_link_type(&iface)?;
                let prog = compile_filter(self.filter, link_type)?;
                let live = Live::open(&iface, prog.as_ref(), self.snaplen, self.promiscuous)?;
                Ok(Capture {
                    inner: Inner::Live(live),
                })
            }
            Source::File(path) => {
                // Pass the raw filter spec to FileCapture so it can compile the
                // string expression after detecting the file's link type.
                let fc = FileCapture::open(&path, self.filter)?;
                Ok(Capture {
                    inner: Inner::File(fc),
                })
            }
        }
    }
}

// ── Capture ───────────────────────────────────────────────────────────────────

enum Inner {
    Live(Live),
    File(FileCapture),
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

    /// Begin building a file capture from a pcap or pcapng file.
    pub fn from_file(path: impl AsRef<Path>) -> CaptureBuilder {
        CaptureBuilder::new_file(path.as_ref().to_owned())
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
    /// Live captures block indefinitely until a packet arrives.
    ///
    /// Returns `Result<Option<Packet>>` rather than implementing `Iterator`
    /// so that I/O errors propagate via `?` without panicking.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Result<Option<Packet>> {
        match &mut self.inner {
            Inner::Live(l) => l.next_packet().map(Some),
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
