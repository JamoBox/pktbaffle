# Windows live capture uses Npcap (C dependency exception)

pktcap is otherwise pure Rust, but live capture on Windows requires a kernel driver for promiscuous access — there is no pure-Rust path. Npcap is the only viable option. The C dependency is scoped to Windows targets only (`#[cfg(target_os = "windows")]`); Linux and macOS remain pure Rust. pcap/pcapng file reading is pure Rust on all platforms.
