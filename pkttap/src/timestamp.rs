//! Timestamp resolution strategy for live capture.

/// Controls which kernel timestamp source is used for live captures.
///
/// Hardware timestamps are stamped by the NIC before the kernel queues the
/// packet, giving sub-microsecond accuracy for latency-sensitive workloads
/// (PTP/IEEE 1588, HFT market data, network monitoring). Software timestamps
/// are assigned by the kernel receive stack and are accurate to ≈1 μs under
/// normal load.
///
/// # Platform support
///
/// | Mode       | Linux                  | macOS         | Windows        |
/// |------------|------------------------|---------------|----------------|
/// | `Software` | `SO_TIMESTAMPNS` (ns)  | BPF `bh_tstamp` (μs) | Npcap `PcapPkthdr.ts` (μs) |
/// | `Hardware` | `SO_TIMESTAMPING` (ns) | *falls back*  | *falls back*   |
///
/// On macOS and Windows the platform does not expose NIC hardware timestamps
/// through BPF or Npcap. Requesting `Hardware` on those platforms silently
/// falls back to the platform's default timestamp source.
///
/// On Linux, if the NIC driver does not support hardware timestamping (check
/// with `ethtool -T <iface>`), the kernel returns a zero hardware timestamp
/// and pkttap automatically falls back to the software timestamp from the
/// same `recvmsg()` call.
///
/// # Example
///
/// ```no_run
/// use pkttap::{Capture, TimestampMode};
///
/// let mut cap = Capture::live("eth0")
///     .timestamp_mode(TimestampMode::Hardware)
///     .open()?;
/// # Ok::<(), pkttap::Error>(())
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TimestampMode {
    /// Kernel-assigned software timestamp.
    ///
    /// On Linux this uses `SO_TIMESTAMPNS`, which gives nanosecond resolution
    /// and is stamped at the kernel receive queue — significantly more accurate
    /// than `SystemTime::now()` called after `recvfrom()` returns.
    #[default]
    Software,

    /// NIC hardware timestamp (Linux only; falls back to `Software` elsewhere
    /// or when the NIC driver does not support hardware timestamping).
    ///
    /// On Linux, `SO_TIMESTAMPING` is enabled with the flags:
    /// - `SOF_TIMESTAMPING_RX_HARDWARE` — request hardware Rx timestamp
    /// - `SOF_TIMESTAMPING_RAW_HARDWARE` — report the raw (unmodified) NIC value
    /// - `SOF_TIMESTAMPING_RX_SOFTWARE` — also request software timestamp
    /// - `SOF_TIMESTAMPING_SOFTWARE` — report the software timestamp
    ///
    /// The raw hardware timestamp from `scm_timestamping[2]` is used when
    /// non-zero; otherwise pkttap falls back to the software timestamp from
    /// `scm_timestamping[0]`.
    Hardware,
}
