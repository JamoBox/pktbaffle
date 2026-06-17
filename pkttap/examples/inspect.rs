//! inspect — dump packets from a live interface or pcap/pcapng file.
//!
//! This example walks through the two core pkttap concepts:
//!
//! 1. **Capture** — a unified packet source that abstracts live interfaces
//!    and pcap/pcapng files behind the same builder + iterator API.
//! 2. **PacketRef** — a borrowed view of a single captured frame (raw bytes,
//!    timestamp, on-wire length, link type) that borrows from the capture's
//!    internal buffer and is valid only until the next `next()` call. Call
//!    `.to_owned()` for an owned `Packet` you can retain.
//!
//! Run it:
//!
//! ```text
//! # List interfaces (needs no privileges)
//! cargo run --example inspect -- -l
//!
//! # Live capture — requires root / administrator
//! cargo run --example inspect -- eth0
//! cargo run --example inspect -- eth0 "tcp port 443"
//!
//! # File capture — no privileges needed
//! cargo run --example inspect -- capture.pcap
//! cargo run --example inspect -- capture.pcap "udp port 53"
//! ```

use std::path::Path;

use pkttap::{Capture, Result};

const HELP: &str = "\
inspect — packet inspector

USAGE:
    inspect <INTERFACE|FILE> [FILTER]
    inspect -l | --list-interfaces
    inspect -h | --help

ARGUMENTS:
    INTERFACE   Live capture on a network interface (e.g. eth0, Wi-Fi).
                Requires root / administrator privileges.
    FILE        Read packets from a .pcap or .pcapng file.
    FILTER      Optional BPF filter expression (e.g. \"tcp port 443\").

OPTIONS:
    -l, --list-interfaces   Print available network interfaces and exit.
    -h, --help              Print this help message and exit.

OUTPUT:
    Each packet is shown as a one-line header:
        [<n>] <timestamp>  <link-type>  <origlen> bytes
    followed by a hex + ASCII dump of the captured bytes.

EXAMPLES:
    inspect eth0
    inspect eth0 \"tcp port 80\"
    inspect capture.pcap \"udp\"
    inspect -l
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

    // pkttap::interfaces() lists every network interface the OS reports.
    // On Linux these are the names you'd pass to `ip link`; on Windows,
    // Npcap device GUIDs prefixed with `\Device\NPF_`.
    if args[1] == "-l" || args[1] == "--list-interfaces" {
        for iface in pkttap::interfaces()? {
            println!("{iface}");
        }
        return Ok(());
    }

    let target = &args[1];

    // The second positional argument is the optional BPF filter expression.
    // `.map(String::as_str)` converts `Option<&String>` → `Option<&str>`.
    // Passing `None` (no filter) captures every packet — equivalent to not
    // calling `.filter()` at all.
    let filter: Option<&str> = args.get(2).map(String::as_str);

    // ── Build the Capture ─────────────────────────────────────────────────────
    //
    // Capture::live()      — opens a raw socket on a live network interface.
    //                        Requires root on Linux / administrator on Windows.
    //
    // Capture::from_file() — reads packets from a pcap or pcapng file.
    //                        Format is detected automatically from the file header.
    //
    // Both return the same CaptureBuilder, so the rest of the chain is identical.
    // Here we heuristically treat the target as a file if it already exists on disk;
    // otherwise we assume it's an interface name.
    let mut cap = if Path::new(target).exists() {
        // File capture — no privileges required.
        // .filter(filter) accepts &str, Option<&str>, or None without an if-let.
        Capture::from_file(target).filter(filter).open()?
    } else {
        // Live capture — promiscuous(true) makes the NIC deliver all frames,
        // not just those addressed to this host.
        Capture::live(target)
            .promiscuous(true)
            .filter(filter) // None → capture everything; Some("…") → kernel-filtered
            .open()?
    };

    // link_type() tells you the layer-2 framing of the source
    // (Ethernet, RawIp, LinuxSll, …).  This determines which byte offsets
    // pktbaffle used when compiling the filter expression.
    eprintln!("link type: {:?}", cap.link_type());

    // ── Packet loop ───────────────────────────────────────────────────────────
    //
    // cap.next() is deliberately not an Iterator implementation — it returns
    // Result<Option<PacketRef>> so that I/O errors propagate via `?` without
    // panicking, and because the borrowed PacketRef makes this a lending
    // iterator that std::iter::Iterator cannot express.  The pattern mirrors
    // what you'd write for a fallible stream:
    //
    //   Ok(Some(pkt))  — a packet arrived; process it (before the next iteration)
    //   Ok(None)       — end-of-file (file captures only; live captures block forever)
    //   Err(e)         — a real I/O or kernel error
    let mut count: u64 = 0;
    while let Some(pkt) = cap.next()? {
        count += 1;

        // timestamp() is a std::time::SystemTime measured from UNIX_EPOCH.
        // We split it into seconds + microseconds for a tcpdump-style display.
        let ts = pkt
            .timestamp()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();

        // orig_len() is the packet's length on the wire *before* any snaplen
        // truncation.  pkt.data().len() may be smaller if a snaplen was set.
        // is_truncated() returns true when data().len() < orig_len().
        let trunc = if pkt.is_truncated() {
            format!(" [truncated to {}]", pkt.data().len())
        } else {
            String::new()
        };

        println!(
            "\n[{count:>6}] {}.{:06}  {:?}  {} bytes{}",
            ts.as_secs(),
            ts.subsec_micros(),
            pkt.link_type(), // mirrors cap.link_type() for every packet
            pkt.orig_len(),  // on-wire length, not the (possibly truncated) captured length
            trunc,
        );

        // Print the captured bytes — may be shorter than orig_len if truncated.
        hexdump(pkt.data());
    }

    eprintln!("\n{count} packets captured");
    Ok(())
}

// ── Hex dump ──────────────────────────────────────────────────────────────────

/// Print `data` as a classic 16-bytes-per-row hex + ASCII dump.
///
/// Each row looks like:
/// ```text
/// 0000  45 00 00 3c 1c 46 40 00  40 06 a6 ec 7f 00 00 01  |E..<.F@.@.......|
/// ```
/// Non-printable bytes are shown as `.`.
fn hexdump(data: &[u8]) {
    for (row, chunk) in data.chunks(16).enumerate() {
        // Column 1: byte offset of the first byte in this row.
        print!("{:04x}  ", row * 16);

        // Column 2: hex bytes, split into two groups of 8 with a mid-gap.
        for (i, byte) in chunk.iter().enumerate() {
            if i == 8 {
                print!(" "); // visual separator between the two groups
            }
            print!("{byte:02x} ");
        }

        // Pad short final rows so the ASCII column stays aligned.
        let missing = 16 - chunk.len();
        let pad = missing * 3 + if chunk.len() <= 8 { 1 } else { 0 };
        print!("{:pad$} |", "", pad = pad);

        // Column 3: ASCII representation — printable chars as-is, rest as '.'.
        for &byte in chunk {
            let ch = if byte.is_ascii_graphic() || byte == b' ' {
                byte as char
            } else {
                '.'
            };
            print!("{ch}");
        }
        println!("|");
    }
}
