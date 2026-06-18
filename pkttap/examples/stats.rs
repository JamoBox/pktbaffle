//! stats — monitor live packet drop statistics while capturing.
//!
//! This example demonstrates [`Capture::stats`] — the mechanism for detecting
//! silent packet loss at line rate. It opens a live interface, captures
//! packets in a loop, and periodically prints the cumulative received and
//! dropped counts from the kernel's capture layer.
//!
//! ## Why this matters
//!
//! The kernel buffers packets between the NIC and your process.  When that
//! buffer is full (e.g. because your code is too slow to drain it, or because
//! traffic is bursting faster than your snaplen allows), the kernel silently
//! drops packets.  Without `stats()`, you have no idea you missed any.
//!
//! `Capture::stats()` queries the platform's capture counters:
//!
//! | Platform | Source                                             |
//! |----------|----------------------------------------------------|
//! | Linux    | `getsockopt(SOL_PACKET, PACKET_STATISTICS)`        |
//! | macOS    | `ioctl(BIOCGSTATS)`                                |
//! | Windows  | `pcap_stats()` via Npcap                           |
//! | File     | Always zero (no kernel buffer, no drops possible)  |
//!
//! ## Run it
//!
//! ```text
//! # Requires root / CAP_NET_RAW (or administrator on Windows)
//! cargo run --example stats -p pkttap -- eth0
//!
//! # With a filter (reduces CPU work, making drops less likely)
//! cargo run --example stats -p pkttap -- eth0 "tcp port 443"
//!
//! # Custom polling interval (default: every 500 packets)
//! cargo run --example stats -p pkttap -- eth0 --interval 1000
//! ```

use pkttap::{Capture, CaptureStats, Result};

const HELP: &str = "\
stats — live packet drop monitor

USAGE:
    stats <INTERFACE> [FILTER] [OPTIONS]
    stats -h | --help

ARGUMENTS:
    INTERFACE   Network interface to capture on (e.g. eth0, en0, Wi-Fi).
                Requires root / CAP_NET_RAW / administrator privileges.
    FILTER      Optional BPF filter expression (e.g. \"tcp port 443\").

OPTIONS:
    --interval <N>   Print stats every N packets (default: 500).
    -h, --help       Print this help message and exit.

OUTPUT:
    Prints a stats summary every <interval> packets:

        [500 pkts] received=500 dropped=0 if_dropped=0 (drop rate: 0.00%)

    A non-zero `dropped` count means the kernel was unable to deliver every
    packet to your process.  This indicates the capture buffer was full at
    some point — either increase the buffer or reduce the processing load.

EXAMPLES:
    stats eth0
    stats eth0 \"udp\" --interval 200
";

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 || args[1] == "-h" || args[1] == "--help" {
        print!("{HELP}");
        std::process::exit(if args.len() < 2 { 1 } else { 0 });
    }

    let iface = &args[1];
    let mut filter: Option<&str> = None;
    let mut interval: u64 = 500;

    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--interval" => {
                i += 1;
                interval = args.get(i).and_then(|s| s.parse().ok()).unwrap_or_else(|| {
                    eprintln!("error: --interval requires a positive integer");
                    std::process::exit(1);
                });
                if interval == 0 {
                    eprintln!("error: --interval must be >= 1");
                    std::process::exit(1);
                }
            }
            "--help" | "-h" => {
                print!("{HELP}");
                std::process::exit(0);
            }
            other if !other.starts_with('-') && filter.is_none() => {
                // Treat the first non-flag argument after the interface as the filter.
                filter = Some(other);
            }
            other => {
                eprintln!("error: unknown argument `{other}`");
                std::process::exit(1);
            }
        }
        i += 1;
    }

    // ── Open the live capture ─────────────────────────────────────────────────

    let mut cap = Capture::live(iface)
        .promiscuous(true)
        .filter(filter)
        .open()?;

    eprintln!(
        "capturing on {}  link-type: {:?}  filter: {}",
        iface,
        cap.link_type(),
        filter.unwrap_or("<none>"),
    );
    eprintln!("printing stats every {interval} packets  (Ctrl-C to stop)\n");

    // ── Packet loop with periodic stats ──────────────────────────────────────

    let mut total_packets: u64 = 0;
    let mut prev = CaptureStats::default();

    loop {
        // cap.next() blocks until a packet arrives.
        // On a live capture it never returns Ok(None) — that only happens at
        // end-of-file for file-based captures.
        let Some(pkt) = cap.next()? else { break };

        // Touch the first byte so the compiler cannot elide the read.
        let _ = pkt.data().first().copied();
        total_packets += 1;

        if total_packets % interval == 0 {
            // ── Query the kernel's capture counters ───────────────────────────
            //
            // stats() returns cumulative totals since the capture was opened:
            //   received   — packets delivered to your process
            //   dropped    — packets the kernel had to discard (buffer full)
            //   if_dropped — packets the NIC driver discarded before they
            //                reached the capture layer (not reported on Linux/macOS)
            //
            // On Linux, the kernel resets its internal counters each time they
            // are read; pkttap accumulates the deltas automatically so `received`
            // and `dropped` are always totals from capture start.
            let stats = cap.stats()?;

            // Compute per-interval delta so we can show the instantaneous rate.
            let delta_recv = stats.received.saturating_sub(prev.received);
            let delta_drop = stats.dropped.saturating_sub(prev.dropped);
            let drop_rate = if delta_recv + delta_drop > 0 {
                100.0 * delta_drop as f64 / (delta_recv + delta_drop) as f64
            } else {
                0.0
            };

            println!(
                "[{total_packets:>8} pkts]  received={:>8}  dropped={:>6}  if_dropped={:>6}  \
                 (interval drop rate: {drop_rate:.2}%)",
                stats.received, stats.dropped, stats.if_dropped,
            );

            // Warn loudly if we are dropping packets — the user should know.
            if delta_drop > 0 {
                eprintln!(
                    "  WARNING: dropped {delta_drop} packet(s) in the last {interval}-packet \
                     window.  Consider reducing filter complexity, increasing snaplen, \
                     or processing packets faster."
                );
            }

            prev = stats;
        }
    }

    // Print a final summary when the loop exits (Ctrl-C or file EOF).
    let stats = cap.stats()?;
    println!();
    println!("=== Final stats ===");
    println!("  total packets processed : {total_packets}");
    println!("  kernel received         : {}", stats.received);
    println!("  kernel dropped          : {}", stats.dropped);
    println!("  interface dropped       : {}", stats.if_dropped);

    if stats.received + stats.dropped > 0 {
        let overall_drop =
            100.0 * stats.dropped as f64 / (stats.received + stats.dropped) as f64;
        println!("  overall drop rate       : {overall_drop:.4}%");
    }

    Ok(())
}
