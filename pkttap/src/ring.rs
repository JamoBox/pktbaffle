//! Configuration for the Linux `TPACKET_V3` mmap ring-buffer backend ([#90]).
//!
//! The default Linux capture path calls `recvmsg()` once per packet, which
//! copies the frame from the kernel's receive queue into a userspace buffer.
//! `TPACKET_V3` replaces that with a ring of memory shared between the kernel
//! and this process: the kernel writes frames straight into the mapping and
//! flips a status word when a block is ready, so reading a packet costs no
//! syscall and no kernel→userspace copy.
//!
//! Opt in by passing a [`RingConfig`] to [`CaptureBuilder::ring`]:
//!
//! ```no_run
//! use pkttap::{Capture, RingConfig};
//!
//! # fn run() -> pkttap::Result<()> {
//! let mut cap = Capture::live("eth0")
//!     .filter("tcp port 443")
//!     .ring(RingConfig::new())
//!     .open()?;
//!
//! while let Some(pkt) = cap.next()? {
//!     // `pkt` borrows directly from the mmap'd ring — no copy was made.
//!     let _ = pkt.data().len();
//! }
//! # Ok(()) }
//! ```
//!
//! [`CaptureBuilder::ring`]: crate::CaptureBuilder::ring
//! [#90]: https://github.com/JamoBox/pktbaffle/issues/90

use std::time::Duration;

/// Geometry of a `TPACKET_V3` capture ring (Linux only).
///
/// The ring is a contiguous mmap of `block_count` blocks of `block_size`
/// bytes. The kernel fills one block at a time with variable-length frames and
/// hands the whole block over when it is full or when `retire_timeout`
/// expires; [`Capture::next`](crate::Capture::next) then walks the frames in
/// place.
///
/// The defaults (256 KiB × 16 blocks = 4 MiB, retired after 100 ms) suit
/// general-purpose capture. Tune them when:
///
/// - **You are dropping packets** (`Capture::stats().dropped` climbing) — a
///   larger ring gives the kernel more room while your loop is busy. Raise
///   `block_count` first; it costs no extra latency.
/// - **You need lower delivery latency on quiet links** — lower
///   `retire_timeout`, which bounds how long a partly filled block waits
///   before it is handed over.
///
/// Sizes are adjusted upwards where the kernel requires it: `block_size` is
/// rounded up to a multiple of the page size and to at least one full frame
/// (snaplen plus per-frame header). Note the kernel sizes frames from the
/// on-wire packet, not from the snaplen, so a small snaplen does not shrink
/// the ring memory a packet occupies.
///
/// ```
/// use pkttap::RingConfig;
/// use std::time::Duration;
///
/// // 64 blocks of 1 MiB (64 MiB ring), handed over at most 5 ms late.
/// let cfg = RingConfig::new()
///     .block_size(1 << 20)
///     .block_count(64)
///     .retire_timeout(Duration::from_millis(5));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RingConfig {
    pub(crate) block_size: usize,
    pub(crate) block_count: usize,
    pub(crate) retire_timeout: Duration,
}

/// 256 KiB per block: large enough that a maximum-size frame always fits
/// without rounding, small enough that a block is retired promptly.
const DEFAULT_BLOCK_SIZE: usize = 256 * 1024;
/// 16 blocks — a 4 MiB ring, in the same range as libpcap's default buffer.
const DEFAULT_BLOCK_COUNT: usize = 16;
/// Matches the default of [`CaptureBuilder::buffer_timeout`], the equivalent
/// knob on the non-ring path.
///
/// [`CaptureBuilder::buffer_timeout`]: crate::CaptureBuilder::buffer_timeout
const DEFAULT_RETIRE_TIMEOUT: Duration = Duration::from_millis(100);

impl RingConfig {
    /// A ring with the default geometry: 16 blocks of 256 KiB (4 MiB total),
    /// each retired after at most 100 ms.
    pub fn new() -> Self {
        Self {
            block_size: DEFAULT_BLOCK_SIZE,
            block_count: DEFAULT_BLOCK_COUNT,
            retire_timeout: DEFAULT_RETIRE_TIMEOUT,
        }
    }

    /// Bytes per block (default: 256 KiB).
    ///
    /// Rounded up to a multiple of the system page size, and to at least one
    /// full frame. Very large blocks can fail to allocate: the kernel needs
    /// physically contiguous pages per block, so prefer more blocks over
    /// bigger ones when growing the ring.
    pub fn block_size(mut self, bytes: usize) -> Self {
        self.block_size = bytes;
        self
    }

    /// Number of blocks in the ring (default: 16).
    ///
    /// Total ring memory is `block_size × block_count`, locked in the kernel
    /// for the lifetime of the capture.
    pub fn block_count(mut self, n: usize) -> Self {
        self.block_count = n;
        self
    }

    /// How long the kernel may hold a partly filled block before handing it to
    /// userspace (default: 100 ms).
    ///
    /// This bounds delivery latency on quiet links: a packet arriving into an
    /// otherwise empty block is not visible until the block is full or this
    /// timeout expires. Sub-millisecond values are rounded up to 1 ms, the
    /// kernel's resolution for this option. Zero selects the kernel's own
    /// default, which it derives from the interface's link speed.
    pub fn retire_timeout(mut self, d: Duration) -> Self {
        self.retire_timeout = d;
        self
    }
}

impl Default for RingConfig {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_geometry_is_a_4mib_ring() {
        let cfg = RingConfig::default();
        assert_eq!(cfg.block_size * cfg.block_count, 4 * 1024 * 1024);
        assert_eq!(cfg.retire_timeout, Duration::from_millis(100));
    }

    #[test]
    fn builder_methods_override_defaults() {
        let cfg = RingConfig::new()
            .block_size(1 << 20)
            .block_count(64)
            .retire_timeout(Duration::from_millis(5));
        assert_eq!(cfg.block_size, 1 << 20);
        assert_eq!(cfg.block_count, 64);
        assert_eq!(cfg.retire_timeout, Duration::from_millis(5));
    }

    #[test]
    fn new_and_default_agree() {
        assert_eq!(RingConfig::new(), RingConfig::default());
    }
}
