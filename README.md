# pktbaffle

A pure-Rust ecosystem for packet filtering and capture.

| Crate | Description |
|-------|-------------|
| [pktbaffle](pktbaffle/) | Compile libpcap-style filter expressions to cBPF / eBPF bytecode |
| [pkttap](pkttap/) | Cross-platform packet capture (live + pcap/pcapng file) |

---

## pktbaffle

Parses the same filter syntax used by `tcpdump` and Wireshark and produces classic BPF (cBPF) or extended BPF (eBPF) bytecode with zero C dependencies.

```toml
[dependencies]
pktbaffle = { path = "pktbaffle" }
```

```rust
use pktbaffle::{compile, codegen::LinkType, Target};

let prog = compile("tcp port 443", LinkType::Ethernet, Target::Classic)?;
```

See [pktbaffle/README.md](pktbaffle/README.md) for the full filter expression reference.

---

## pkttap

Wraps platform-specific live capture (Linux AF_PACKET, macOS /dev/bpf, Windows Npcap) and pcap/pcapng file I/O behind a unified API, using pktbaffle to compile filter expressions.

```toml
[dependencies]
pkttap = { path = "pkttap" }
```

```rust
use pkttap::Capture;

let mut cap = Capture::live("eth0")
    .promiscuous(true)
    .filter("tcp port 443")
    .open()?;

while let Some(pkt) = cap.next()? {
    println!("{} bytes", pkt.data.len());
}
```

See [pkttap/README.md](pkttap/README.md) for full documentation.

---

## License

MIT OR Apache-2.0
