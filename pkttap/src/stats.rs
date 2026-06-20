/// Cumulative packet statistics from the kernel capture layer.
///
/// Returned by [`crate::Capture::stats`] for live captures. All counters are
/// cumulative since the capture was opened. File-based captures always
/// return a zeroed struct.
///
/// # Platform notes
///
/// | Platform | `received`          | `dropped`               | `if_dropped`          |
/// |----------|---------------------|-------------------------|-----------------------|
/// | Linux    | `tp_packets`        | `tp_drops`              | 0 (not reported)      |
/// | macOS    | `bs_recv`           | `bs_drop`               | 0 (not reported)      |
/// | Windows  | `ps_recv`           | `ps_drop`               | `ps_ifdrop`           |
/// | File     | 0                   | 0                       | 0                     |
///
/// **Linux note:** The kernel's `PACKET_STATISTICS` counters are reset each
/// time they are read. The library accumulates them across calls so that
/// `received` and `dropped` are always totals from capture start, matching
/// the behaviour of the other platforms.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CaptureStats {
    /// Total packets delivered to userspace (after BPF filtering).
    pub received: u64,
    /// Packets dropped because the kernel socket buffer was full.
    pub dropped: u64,
    /// Packets dropped by the network interface driver before reaching the
    /// capture layer. Always 0 on Linux and macOS.
    pub if_dropped: u64,
}
