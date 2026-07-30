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
pktbaffle = "0.2"
```

```rust
use pktbaffle::{compile, codegen::LinkType, Target};

let prog = compile("tcp port 443", LinkType::Ethernet, Target::Classic)?;
```

See [pktbaffle/README.md](pktbaffle/README.md) for the full filter expression reference.

---

## pkttap

Wraps platform-specific live capture (Linux AF_PACKET, macOS /dev/bpf, Windows Npcap) and pcap/pcapng file I/O behind a unified API, using pktbaffle to compile filter expressions. Packets are yielded as borrowed views with no per-packet allocation; on Linux, `.ring(RingConfig::new())` opts into a `TPACKET_V3` mmap ring that drops the per-packet syscall and kernel copy as well.

```toml
[dependencies]
pkttap = "0.3"
```

```rust
use pkttap::Capture;

let mut cap = Capture::live("eth0")
    .promiscuous(true)
    .filter("tcp port 443")
    .open()?;

while let Some(pkt) = cap.next()? {
    // pkt is a borrowed PacketRef; call pkt.to_owned() to keep it.
    println!("{} bytes", pkt.data().len());
}
```

See [pkttap/README.md](pkttap/README.md) for full documentation.

---

## License

Licensed under the [MIT license](LICENSE-MIT).
