//! Multi-consumer capture via Linux `PACKET_FANOUT` ([#91]).
//!
//! `Capture` is single-threaded — reading requires `&mut self`, so packets
//! can only be distributed across worker threads by building a channel-based
//! fan-out layer on top. On Linux, `PACKET_FANOUT` lets several raw sockets
//! share a capture group and has the kernel split traffic between them
//! directly, with no userspace copy or channel hop.
//!
//! ```no_run
//! use pkttap::{FanoutGroup, FanoutMode};
//!
//! # fn run() -> pkttap::Result<()> {
//! let group = FanoutGroup::new("eth0", FanoutMode::CpuAffinity).promiscuous(true);
//! let mut captures = group.into_captures(4)?;
//!
//! let mut handles = Vec::new();
//! for mut cap in captures.drain(..) {
//!     handles.push(std::thread::spawn(move || {
//!         while let Ok(Some(pkt)) = cap.next() {
//!             // process pkt
//!             let _ = pkt.data().len();
//!         }
//!     }));
//! }
//! # Ok(()) }
//! ```
//!
//! [#91]: https://github.com/JamoBox/pktbaffle/issues/91

use crate::capture::{compile_filter, Capture, FilterSpec};
use crate::error::{Error, Result};
use crate::live::{query_link_type, Live, PlatformLive};
use crate::ring::RingConfig;

/// Packet distribution strategy for a [`FanoutGroup`].
///
/// Maps directly to the kernel's `PACKET_FANOUT_*` constants; see
/// `man 7 packet` for the exact semantics of each mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FanoutMode {
    /// Distribute by a hash of the packet's flow (source/dest address and
    /// port), so a given flow always lands on the same member socket.
    Hash,
    /// Round-robin across members, ignoring flow.
    LoadBalance,
    /// Send each packet to the member whose thread is pinned to the CPU that
    /// received it. Requires member sockets to be read from CPU-affine
    /// threads to see the expected balance.
    CpuAffinity,
    /// Round-robin, falling back to the next socket when the chosen one's
    /// receive buffer is full rather than dropping the packet.
    Rollover,
    /// Random distribution across members.
    Random,
    /// Distribute using the NIC's queue mapping (requires matching RSS
    /// configuration on the interface).
    QueueMapping,
}

impl FanoutMode {
    fn kernel_value(self) -> u16 {
        match self {
            FanoutMode::Hash => 0,
            FanoutMode::LoadBalance => 1,
            FanoutMode::CpuAffinity => 2,
            FanoutMode::Rollover => 3,
            FanoutMode::Random => 4,
            FanoutMode::QueueMapping => 5,
        }
    }
}

/// Builder for a group of [`Capture`]s that share kernel-side packet
/// distribution via `PACKET_FANOUT` (Linux only).
///
/// Each call to [`into_captures`](Self::into_captures) opens one raw socket
/// per member, all bound to the same interface and joined to the same
/// fanout group, so the kernel splits the interface's traffic between them
/// according to `mode`. Every member `Capture` can then be moved to its own
/// thread and read independently.
pub struct FanoutGroup {
    iface: String,
    filter: Option<FilterSpec>,
    snaplen: u32,
    promiscuous: bool,
    mode: FanoutMode,
    group_id: u16,
    ring: Option<RingConfig>,
}

impl FanoutGroup {
    /// Start building a fanout group on `iface` using distribution `mode`.
    ///
    /// The group id defaults to a value derived from the process id and
    /// current time; call [`group_id`](Self::group_id) to pin an explicit
    /// value if you need multiple independent groups on the same interface
    /// to never collide.
    pub fn new(iface: &str, mode: FanoutMode) -> Self {
        Self {
            iface: iface.to_owned(),
            filter: None,
            snaplen: 65535,
            promiscuous: false,
            mode,
            group_id: default_group_id(),
            ring: None,
        }
    }

    /// Use an explicit fanout group id instead of the generated default.
    ///
    /// All member sockets created by [`into_captures`](Self::into_captures)
    /// join this id. Two unrelated processes that pick the same id on the
    /// same interface end up sharing one fanout group, so pick a value
    /// unlikely to collide if that matters for your deployment.
    pub fn group_id(mut self, id: u16) -> Self {
        self.group_id = id;
        self
    }

    /// Set a filter expression applied to every member socket.
    pub fn filter<'a>(mut self, expr: impl Into<Option<&'a str>>) -> Self {
        self.filter = expr.into().map(|s| FilterSpec::String(s.to_owned()));
        self
    }

    /// Maximum bytes captured per packet on every member socket (default: 65535).
    pub fn snaplen(mut self, n: u32) -> Self {
        self.snaplen = n;
        self
    }

    /// Enable or disable promiscuous mode on every member socket (default: off).
    pub fn promiscuous(mut self, on: bool) -> Self {
        self.promiscuous = on;
        self
    }

    /// Give every member socket its own `TPACKET_V3` mmap ring instead of
    /// reading with `recvmsg()` — see [`CaptureBuilder::ring`].
    ///
    /// This is the pairing the two features were designed for: the kernel
    /// splits traffic across the group and writes each share straight into
    /// that member's ring, so a worker thread reads its packets with no
    /// syscall and no copy.
    ///
    /// Note that each member allocates a full ring, so the group's memory is
    /// `block_size × block_count × n`.
    ///
    /// ```no_run
    /// use pkttap::{FanoutGroup, FanoutMode, RingConfig};
    ///
    /// # fn run() -> pkttap::Result<()> {
    /// let captures = FanoutGroup::new("eth0", FanoutMode::CpuAffinity)
    ///     .ring(RingConfig::new())
    ///     .into_captures(4)?;
    /// # Ok(()) }
    /// ```
    ///
    /// [`CaptureBuilder::ring`]: crate::CaptureBuilder::ring
    pub fn ring(mut self, cfg: impl Into<Option<RingConfig>>) -> Self {
        self.ring = cfg.into();
        self
    }

    /// Open `n` member captures joined to the same fanout group.
    ///
    /// Every member receives a disjoint subset of the interface's traffic,
    /// split according to the group's [`FanoutMode`]. `n` must be at least 1.
    pub fn into_captures(self, n: usize) -> Result<Vec<Capture>> {
        if n == 0 {
            return Err(Error::Platform(
                "FanoutGroup::into_captures requires n >= 1".into(),
            ));
        }

        let link_type = query_link_type(&self.iface)?;
        let prog = compile_filter(self.filter, link_type)?;
        let mode = self.mode.kernel_value();

        let mut captures = Vec::with_capacity(n);
        for _ in 0..n {
            let live = PlatformLive::open_fanout(
                &self.iface,
                prog.as_ref(),
                self.snaplen,
                self.promiscuous,
                self.group_id,
                mode,
                self.ring.as_ref(),
            )?;
            captures.push(Capture::from_live(Live(live)));
        }
        Ok(captures)
    }
}

/// Derive a fanout group id from the process id and current time, so
/// concurrently running processes are unlikely to pick the same value.
fn default_group_id() -> u16 {
    use std::time::{SystemTime, UNIX_EPOCH};

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    (nanos as u16) ^ (std::process::id() as u16)
}
