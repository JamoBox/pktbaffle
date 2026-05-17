use std::path::Path;

use pktcap::Capture;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: dump <interface|file.pcap> [filter]");
        std::process::exit(1);
    }

    let target = &args[1];
    let filter = args.get(2).map(String::as_str);

    // If the argument names an existing file, read it; otherwise treat it as
    // a live interface.
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

    println!("link type: {:?}", cap.link_type());

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
                let ts = pkt.timestamp
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default();
                println!(
                    "[{count:>6}] {}.{:06}  {} bytes (orig {})",
                    ts.as_secs(),
                    ts.subsec_micros(),
                    pkt.data.len(),
                    pkt.orig_len,
                );
            }
        }
    }

    println!("{count} packets");
}

fn die(e: pktcap::Error) -> ! {
    eprintln!("error: {e}");
    std::process::exit(1);
}
