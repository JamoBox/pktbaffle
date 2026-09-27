//! replay — send the packets from a pcap or pcapng file out of an interface.
//!
//! This example demonstrates the **Injector** API — the transmit counterpart
//! to Capture — by replaying a capture file onto the wire, tcpreplay-style.
//!
//! Run it (injection needs the same privileges as live capture):
//!
//! ```text
//! # Replay every packet in traffic.pcap out of eth0, as fast as possible
//! sudo cargo run --example replay -- traffic.pcap eth0
//!
//! # Replay only the DNS traffic, preserving the original packet spacing
//! sudo cargo run --example replay -- traffic.pcap eth0 --filter "udp port 53" --realtime
//!
//! # Replay onto loopback for a local test, stopping after 10 packets
//! sudo cargo run --example replay -- traffic.pcap lo --count 10
//! ```
//!
//! Frames are sent exactly as recorded, so the file's link type must match
//! the interface's (Ethernet captures onto Ethernet interfaces, and so on).

use std::time::{Duration, Instant, SystemTime};

use pkttap::{Capture, Error, Injector, Result};

// ── CLI ───────────────────────────────────────────────────────────────────────

const HELP: &str = "\
replay — send the packets in a capture file out of an interface

USAGE:
    replay <FILE> <INTERFACE> [OPTIONS]
    replay -h | --help

ARGUMENTS:
    FILE        pcap or pcapng file to replay.
    INTERFACE   Interface to transmit on (e.g. eth0, en0, lo).

OPTIONS:
    --filter <EXPR>   Only replay packets matching this BPF filter expression.
    --count  <N>      Stop after sending N packets (default: whole file).
    --realtime        Sleep between packets to reproduce the file's timing
                      (default: send as fast as possible).
    -h, --help        Print this help message and exit.

EXAMPLES:
    replay traffic.pcap eth0
    replay traffic.pcapng eth0 --filter \"tcp port 443\" --realtime
    replay traffic.pcap lo --count 10
";

struct Args {
    file: String,
    iface: String,
    filter: Option<String>,
    count: Option<u64>,
    realtime: bool,
}

fn parse_args() -> Args {
    let raw: Vec<String> = std::env::args().skip(1).collect();

    if raw.is_empty() || raw.iter().any(|a| a == "-h" || a == "--help") {
        print!("{HELP}");
        std::process::exit(if raw.is_empty() { 1 } else { 0 });
    }

    if raw.len() < 2 {
        eprintln!("error: FILE and INTERFACE are both required");
        eprintln!("{HELP}");
        std::process::exit(1);
    }

    let mut args = Args {
        file: raw[0].clone(),
        iface: raw[1].clone(),
        filter: None,
        count: None,
        realtime: false,
    };

    let mut i = 2;
    while i < raw.len() {
        match raw[i].as_str() {
            "--filter" => {
                i += 1;
                args.filter = Some(raw.get(i).cloned().unwrap_or_else(|| {
                    eprintln!("error: --filter requires a value");
                    std::process::exit(1);
                }));
            }
            "--count" => {
                i += 1;
                args.count = Some(raw.get(i).and_then(|s| s.parse().ok()).unwrap_or_else(|| {
                    eprintln!("error: --count requires an integer");
                    std::process::exit(1);
                }));
            }
            "--realtime" => args.realtime = true,
            other => {
                eprintln!("error: unknown argument `{other}`");
                std::process::exit(1);
            }
        }
        i += 1;
    }
    args
}

// ── Main ──────────────────────────────────────────────────────────────────────

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args = parse_args();

    // ── Open the source file ──────────────────────────────────────────────────
    //
    // The filter runs in pktbaffle's software VM, so only matching packets
    // are ever handed to the injector.
    let mut cap = Capture::from_file(&args.file)
        .filter(args.filter.as_deref())
        .open()?;

    // ── Open the Injector ─────────────────────────────────────────────────────
    //
    // Injector::on_interface() opens a transmit-only handle: it never receives,
    // so it costs nothing while idle.  send() transmits a frame unmodified —
    // no header is added and no address is rewritten — so the frames in the
    // file must already use the interface's link-layer format.
    let inj = Injector::on_interface(&args.iface)?;
    if cap.link_type() != inj.link_type() {
        return Err(Error::Platform(format!(
            "{} holds {:?} frames but {} expects {:?}",
            args.file,
            cap.link_type(),
            args.iface,
            inj.link_type()
        )));
    }

    eprintln!(
        "replaying {} onto {}  link-type: {:?}  filter: {}  timing: {}",
        args.file,
        args.iface,
        inj.link_type(),
        args.filter.as_deref().unwrap_or("<none>"),
        if args.realtime {
            "original"
        } else {
            "as fast as possible"
        },
    );

    // ── Packet loop ───────────────────────────────────────────────────────────
    let limit = args.count.unwrap_or(u64::MAX);
    let mut sent: u64 = 0;
    let mut skipped: u64 = 0;
    let mut bytes: u64 = 0;
    // (first packet's capture time, wall-clock time it was sent)
    let mut origin: Option<(SystemTime, Instant)> = None;
    let started = Instant::now();

    while sent < limit {
        let Some(pkt) = cap.next()? else {
            break; // end of file
        };

        // A frame cut short by the capture's snaplen is not the frame that was
        // on the wire; sending it would put a malformed packet on the network.
        if pkt.is_truncated() {
            skipped += 1;
            continue;
        }

        if args.realtime {
            match origin {
                None => origin = Some((pkt.timestamp(), Instant::now())),
                Some((first_ts, first_sent)) => {
                    // Out-of-order timestamps (common in merged captures) send
                    // immediately rather than failing.
                    let offset = pkt
                        .timestamp()
                        .duration_since(first_ts)
                        .unwrap_or(Duration::ZERO);
                    let due = first_sent + offset;
                    let now = Instant::now();
                    if due > now {
                        std::thread::sleep(due - now);
                    }
                }
            }
        }

        bytes += inj.send(pkt.data())? as u64;
        sent += 1;
    }

    let elapsed = started.elapsed().as_secs_f64();
    eprintln!("{sent} packets ({bytes} bytes) sent in {elapsed:.3}s");
    if skipped > 0 {
        eprintln!("{skipped} truncated packets skipped (captured with a short snaplen)");
    }
    Ok(())
}
