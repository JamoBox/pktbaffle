//! record — capture packets and save them to a pcap or pcapng file.
//!
//! This example demonstrates the **Dump** API — the write-side counterpart to
//! Capture — and also shows how to compile a filter expression once with
//! pktbaffle and reuse the resulting Program across multiple Captures.
//!
//! Run it:
//!
//! ```text
//! # Record 100 packets from eth0 into output.pcap
//! cargo run --example record -- eth0 output.pcap
//!
//! # Record only TCP traffic, stop after 50 packets
//! cargo run --example record -- eth0 output.pcap --filter "tcp" --count 50
//!
//! # Re-filter an existing file and save matches to a new file
//! cargo run --example record -- capture.pcap filtered.pcap --filter "udp port 53"
//!
//! # Write pcapng instead of pcap (format is chosen by extension)
//! cargo run --example record -- eth0 output.pcapng
//! ```
//!
//! Captured files can be opened with Wireshark, tcpdump, or read back with
//! `Capture::from_file`.

use std::path::Path;

use pkttap::{Capture, Dump, Result};

// ── CLI ───────────────────────────────────────────────────────────────────────

const HELP: &str = "\
record — capture packets to a file

USAGE:
    record <SOURCE> <OUTPUT> [OPTIONS]
    record -h | --help

ARGUMENTS:
    SOURCE   Interface name for live capture, or path to a pcap/pcapng file.
    OUTPUT   Destination file path.  Extension selects format:
               .pcap   — classic pcap
               .pcapng — pcapng (preferred; supports multiple interfaces)

OPTIONS:
    --filter <EXPR>   BPF filter expression (e.g. \"tcp port 443\").
    --count  <N>      Stop after capturing N packets (default: unlimited).
    -h, --help        Print this help message and exit.

EXAMPLES:
    record eth0 out.pcap
    record eth0 out.pcap --filter \"tcp\" --count 200
    record traffic.pcap filtered.pcapng --filter \"udp port 53\"
";

struct Args {
    source: String,
    output: String,
    filter: Option<String>,
    count: Option<u64>,
}

fn parse_args() -> Result<Args> {
    let raw: Vec<String> = std::env::args().skip(1).collect();

    if raw.is_empty() || raw.iter().any(|a| a == "-h" || a == "--help") {
        print!("{HELP}");
        std::process::exit(if raw.is_empty() { 1 } else { 0 });
    }

    if raw.len() < 2 {
        eprintln!("error: SOURCE and OUTPUT are both required");
        eprintln!("{HELP}");
        std::process::exit(1);
    }

    let source = raw[0].clone();
    let output = raw[1].clone();
    let mut filter: Option<String> = None;
    let mut count: Option<u64> = None;

    let mut i = 2;
    while i < raw.len() {
        match raw[i].as_str() {
            "--filter" => {
                i += 1;
                filter = Some(raw.get(i).cloned().unwrap_or_else(|| {
                    eprintln!("error: --filter requires a value");
                    std::process::exit(1);
                }));
            }
            "--count" => {
                i += 1;
                count = Some(raw.get(i).and_then(|s| s.parse().ok()).unwrap_or_else(|| {
                    eprintln!("error: --count requires an integer");
                    std::process::exit(1);
                }));
            }
            other => {
                eprintln!("error: unknown argument `{other}`");
                std::process::exit(1);
            }
        }
        i += 1;
    }

    Ok(Args {
        source,
        output,
        filter,
        count,
    })
}

// ── Main ──────────────────────────────────────────────────────────────────────

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args = parse_args()?;

    // ── Open the Capture ──────────────────────────────────────────────────────
    //
    // A Capture is either live (interface) or file-backed.  We detect which
    // by checking whether the source path exists on disk.
    //
    // .filter() accepts &str, Option<&str>, or None — no if-let needed.
    let filter_str: Option<&str> = args.filter.as_deref();

    let mut cap = if Path::new(&args.source).exists() {
        Capture::from_file(&args.source).filter(filter_str).open()?
    } else {
        Capture::live(&args.source)
            .promiscuous(true)
            .filter(filter_str)
            .open()?
    };

    let link_type = cap.link_type();
    eprintln!(
        "source: {}  link-type: {link_type:?}  filter: {}",
        args.source,
        args.filter.as_deref().unwrap_or("<none>"),
    );

    // ── Open the Dump ─────────────────────────────────────────────────────────
    //
    // Dump is the write-side counterpart to Capture.  It writes packets to a
    // pcap or pcapng file; the format is selected automatically by file extension.
    //
    // link_type() is required — it is written into the file header so that
    // readers know how to interpret the link-layer framing of each packet.
    //
    // Dump::to_file() returns a builder; .open() creates (or truncates) the file.
    let mut dump = Dump::to_file(&args.output).link_type(link_type).open()?;

    eprintln!("writing to: {}", args.output);

    // ── Packet loop ───────────────────────────────────────────────────────────
    //
    // cap.next() returns Result<Option<Packet>>:
    //   Ok(Some(pkt)) — packet available
    //   Ok(None)      — end of file (file captures only)
    //   Err(e)        — I/O or kernel error
    //
    // dump.write_packet() appends a single packet record to the file.
    // The Packet type is owned, so there are no lifetime constraints here;
    // packets can be stored, filtered, or modified before being written.
    let limit = args.count.unwrap_or(u64::MAX);
    let mut written: u64 = 0;

    while written < limit {
        let Some(pkt) = cap.next()? else {
            // Ok(None) — reached end of input file
            break;
        };

        // You can inspect, modify, or discard each Packet before writing it.
        // Here we just pass it straight through.
        dump.write_packet(&pkt)?;
        written += 1;

        if written % 100 == 0 {
            eprintln!("  … {written} packets written");
        }
    }

    // Flushing is optional — Drop flushes automatically — but doing it
    // explicitly lets you catch any final I/O error before the program exits.
    dump.flush()?;

    eprintln!("{written} packets written to {}", args.output);
    Ok(())
}
