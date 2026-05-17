//! inspect — dump packets from a live interface or pcap/pcapng file.
//!
//! Each packet is printed as a one-line summary followed by a hex+ASCII dump.

use std::path::Path;

use pktcap::Capture;

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
    FILTER      Optional pktbaffle / BPF filter expression (e.g. \"tcp port 443\").

OPTIONS:
    -l, --list-interfaces   Print available network interfaces and exit.
    -h, --help              Print this help message and exit.

OUTPUT:
    Each packet is shown as a one-line header:
        [<n>] <timestamp>  <link-type>  <caplen>/<origlen> bytes
    followed by a hex + ASCII dump of the captured bytes.

EXAMPLES:
    inspect eth0
    inspect eth0 \"tcp port 80\"
    inspect capture.pcap \"udp\"
    inspect -l
";

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 || args[1] == "-h" || args[1] == "--help" {
        print!("{HELP}");
        std::process::exit(if args.len() < 2 { 1 } else { 0 });
    }

    if args[1] == "-l" || args[1] == "--list-interfaces" {
        match pktcap::interfaces() {
            Ok(interfaces) => {
                for iface in interfaces {
                    println!("{iface}");
                }
            }
            Err(e) => die(e),
        }
        return;
    }

    let target = &args[1];
    let filter = args.get(2).map(String::as_str);

    let mut cap = if Path::new(target).exists() {
        let mut b = Capture::from_file(target);
        if let Some(f) = filter {
            b = b.filter(f);
        }
        b.open().unwrap_or_else(|e| die(e))
    } else {
        let mut b = Capture::live(target).promiscuous(true);
        if let Some(f) = filter {
            b = b.filter(f);
        }
        b.open().unwrap_or_else(|e| die(e))
    };

    eprintln!("link type: {:?}", cap.link_type());

    let mut count: u64 = 0;
    loop {
        match cap.next() {
            Err(e) => {
                eprintln!("error: {e}");
                std::process::exit(1);
            }
            Ok(None) => break,
            Ok(Some(pkt)) => {
                count += 1;
                let ts = pkt
                    .timestamp
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default();
                let trunc = if pkt.is_truncated() {
                    format!(" [truncated to {}]", pkt.data.len())
                } else {
                    String::new()
                };
                println!(
                    "\n[{count:>6}] {}.{:06}  {:?}  {} bytes{}",
                    ts.as_secs(),
                    ts.subsec_micros(),
                    pkt.link_type,
                    pkt.orig_len,
                    trunc,
                );
                hexdump(&pkt.data);
            }
        }
    }

    eprintln!("\n{count} packets captured");
}

/// Print `data` as a classic 16-bytes-per-row hex + ASCII dump.
fn hexdump(data: &[u8]) {
    for (row, chunk) in data.chunks(16).enumerate() {
        // Offset
        print!("{:04x}  ", row * 16);

        // Hex columns (two groups of 8, separated by an extra space)
        for (i, byte) in chunk.iter().enumerate() {
            if i == 8 {
                print!(" ");
            }
            print!("{byte:02x} ");
        }

        // Pad short final row so the ASCII column aligns
        let missing = 16 - chunk.len();
        let pad = missing * 3 + if chunk.len() <= 8 { 1 } else { 0 };
        print!("{:pad$} ", "", pad = pad);

        // ASCII column: printable chars as-is, everything else as '.'
        print!("|");
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

fn die(e: pktcap::Error) -> ! {
    eprintln!("error: {e}");
    std::process::exit(1);
}
