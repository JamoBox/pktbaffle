# pkttap

Cross-platform packet capture with [pktbaffle](../) filter expressions. Capture live traffic from a network interface or read packets from a `.pcap` / `.pcapng` file — through the same API, on Linux, macOS, and Windows.

---

## Contents

- [Installation](#installation)
- [Platform support](#platform-support)
- [Quick start](#quick-start)
- [Live capture](#live-capture)
  - [Listing interfaces](#listing-interfaces)
  - [Basic capture](#basic-capture)
  - [Promiscuous mode](#promiscuous-mode)
  - [Applying a filter](#applying-a-filter)
  - [Snaplen](#snaplen)
  - [Pre-compiled filters](#pre-compiled-filters)
- [File capture](#file-capture)
  - [Reading a pcap file](#reading-a-pcap-file)
  - [Reading a pcapng file](#reading-a-pcapng-file)
  - [Filtering while reading](#filtering-while-reading)
  - [Link type detection](#link-type-detection)
- [Writing pcap files](#writing-pcap-files)
  - [Streaming writes](#streaming-writes)
  - [One-shot convenience function](#one-shot-convenience-function)
  - [pcapng output](#pcapng-output)
- [The Packet type](#the-packet-type)
- [Error handling](#error-handling)
- [Platform notes](#platform-notes)
  - [Linux](#linux)
  - [macOS](#macos)
  - [Windows](#windows)
- [The inspect example](#the-inspect-example)
- [Filter expression language](#filter-expression-language)

---

## Installation

```toml
[dependencies]
pkttap = "0.1"
```

**Runtime dependencies by platform:**

| Platform | Requirement |
|----------|-------------|
| Linux    | `CAP_NET_RAW` capability (or run as root) |
| macOS    | Read permission on `/dev/bpf*` (or run as root) |
| Windows  | [Npcap](https://npcap.com) installed |

---

## Platform support

| Feature | Linux | macOS | Windows |
|---------|-------|-------|---------|
| Live capture | ✓ AF_PACKET | ✓ /dev/bpf | ✓ Npcap |
| Kernel-level BPF filter | ✓ SO_ATTACH_FILTER | ✓ BIOCSETF | ✓ pcap_setfilter |
| Promiscuous mode | ✓ | ✓ | ✓ |
| Snaplen | ✓ | ✓ | ✓ |
| pcap file read | ✓ | ✓ | ✓ |
| pcapng file read | ✓ | ✓ | ✓ |
| pcap file write | ✓ | ✓ | ✓ |
| pcapng file write | ✓ | ✓ | ✓ |

---

## Quick start

```rust
use pkttap::{Capture, Dump, LinkType};

// ── Live capture ──────────────────────────────────────────────────────────────
let mut cap = Capture::live("eth0")
    .promiscuous(true)
    .filter("tcp port 443")
    .open()?;

while let Some(pkt) = cap.next()? {
    println!("{} bytes  orig={}", pkt.data.len(), pkt.orig_len);
}

// ── File capture ──────────────────────────────────────────────────────────────
let mut cap = Capture::from_file("traffic.pcap")
    .filter("udp port 53")
    .open()?;

while let Some(pkt) = cap.next()? {
    println!("{:?}  {} bytes", pkt.timestamp, pkt.data.len());
}

// ── Write packets to a new pcap file ─────────────────────────────────────────
let mut dump = Dump::to_file("output.pcap")
    .link_type(LinkType::Ethernet)
    .open()?;

dump.write_packet(&pkt)?;
```

---

## Live capture

### Listing interfaces

Before starting a capture you can enumerate the available interfaces:

```rust
let interfaces = pkttap::interfaces()?;
for name in &interfaces {
    println!("{name}");
}
```

On Windows, friendly names are returned (e.g., `"Wi-Fi"`, `"Ethernet"`). On Linux and macOS, system names are returned (e.g., `"eth0"`, `"en0"`).

From the command line:

```
$ cargo run --example inspect -- -l
eth0
lo
wlan0
```

### Basic capture

```rust
use pkttap::Capture;

let mut cap = Capture::live("eth0").open()?;

loop {
    match cap.next()? {
        Some(pkt) => println!("{} bytes", pkt.data.len()),
        None => break, // live captures never return None; this arm is unreachable
    }
}
```

`next()` blocks until a packet arrives. It returns `Ok(None)` only for file captures at end-of-file; a live capture blocks indefinitely.

### Promiscuous mode

By default the interface only delivers packets addressed to the host. Enable promiscuous mode to receive all traffic on the segment:

```rust
let mut cap = Capture::live("eth0")
    .promiscuous(true)
    .open()?;
```

> Promiscuous mode requires root or `CAP_NET_RAW` on Linux and macOS, and administrator privileges on Windows.

### Applying a filter

Filters are compiled with [pktbaffle](../) and applied in the kernel (or Npcap driver on Windows), so only matching packets ever reach your process. This is far more efficient than filtering in userspace.

`filter()` accepts a `&str`, an `Option<&str>`, or `None`. Passing `None` (or an `Option` containing `None`) is a no-op — equivalent to not calling `.filter()` at all. This lets you pass an optional filter from a variable without a conditional branch:

```rust
// Always filter — pass a &str directly
let mut cap = Capture::live("eth0").filter("tcp port 443").open()?;

// Conditionally filter — pass Option<&str> from e.g. a CLI argument
let expr: Option<&str> = args.get(2).map(String::as_str);
let mut cap = Capture::live("eth0").filter(expr).open()?;

// Explicitly no filter
let mut cap = Capture::live("eth0").filter(None::<&str>).open()?;
```

Further examples:

```rust
// HTTP or HTTPS, excluding internal traffic
let mut cap = Capture::live("eth0")
    .filter("(tcp port 80 or tcp port 443) and not src net 192.168.0.0/16")
    .open()?;

// DNS queries
let mut cap = Capture::live("eth0").filter("udp port 53").open()?;

// All ICMP
let mut cap = Capture::live("eth0").filter("icmp or icmp6").open()?;
```

If `filter()` is not called (or `None` is passed), all packets are captured.

See the [filter expression language](#filter-expression-language) section for the full syntax.

### Snaplen

The snapshot length limits how many bytes of each packet are captured. Bytes beyond the snaplen are truncated. The default is 65535 (capture the entire packet).

```rust
// Capture only the first 128 bytes of each packet (headers only for most traffic)
let mut cap = Capture::live("eth0")
    .snaplen(128)
    .open()?;

// Check whether a packet was truncated
if pkt.is_truncated() {
    println!("captured {} of {} bytes", pkt.data.len(), pkt.orig_len);
}
```

### Pre-compiled filters

If you already have a compiled `pktbaffle::bpf::Program`, attach it directly:

```rust
use pktbaffle::{compile, LinkType, Target};
use pkttap::Capture;

let prog = compile("tcp port 22", LinkType::Ethernet, Target::Classic)?;
let cbpf = match prog {
    pktbaffle::Program::Classic(p) => p,
    _ => unreachable!(),
};

let mut cap = Capture::live("eth0")
    .filter_program(cbpf)
    .open()?;
```

This is useful when you want to compile the filter once and reuse it across multiple captures, or when you build the `bpf::Program` by hand.

---

## File capture

pkttap reads both classic pcap (`.pcap`) and next-generation pcap (`.pcapng`) files. The format is detected automatically from the file's magic bytes, not the extension.

### Reading a pcap file

```rust
use pkttap::Capture;

let mut cap = Capture::from_file("traffic.pcap").open()?;

while let Some(pkt) = cap.next()? {
    let ts = pkt.timestamp
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    println!("[{}.{:06}] {} bytes", ts.as_secs(), ts.subsec_micros(), pkt.data.len());
}
```

`next()` returns `Ok(None)` at end-of-file. Use `?` to propagate I/O or parse errors.

### Reading a pcapng file

pcapng files are handled identically from the caller's perspective. Per-interface link types (from Interface Description Blocks) are tracked automatically, so each `Packet` carries the correct `link_type` even in multi-interface captures.

```rust
let mut cap = Capture::from_file("multi_interface.pcapng").open()?;

while let Some(pkt) = cap.next()? {
    println!("{:?}  {} bytes", pkt.link_type, pkt.data.len());
}
```

### Filtering while reading

Filters are applied in userspace via the pktbaffle software VM when reading files. Packets that do not match are skipped transparently.

```rust
let mut cap = Capture::from_file("traffic.pcap")
    .filter("tcp port 80")
    .open()?;

while let Some(pkt) = cap.next()? {
    // Only HTTP packets arrive here
}
```

```rust
// Count SYN packets in a capture
let mut cap = Capture::from_file("traffic.pcap")
    .filter("tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0")
    .open()?;

let mut syn_count = 0u64;
while cap.next()?.is_some() {
    syn_count += 1;
}
println!("{syn_count} SYN packets");
```

### Link type detection

The link type is read from the pcap file header (classic) or from Interface Description Blocks (pcapng). `Capture::link_type()` returns the type of the first interface:

```rust
let cap = Capture::from_file("traffic.pcap").open()?;
println!("link type: {:?}", cap.link_type()); // e.g. Ethernet
```

---

## Writing pcap files

The `Dump` type writes packets to a `.pcap` or `.pcapng` file. The format is selected automatically by file extension.

### Streaming writes

```rust
use pkttap::{Capture, Dump, LinkType};

let mut cap = Capture::live("eth0")
    .filter("tcp port 443")
    .promiscuous(true)
    .open()?;

// Write captured packets to a pcap file
let mut dump = Dump::to_file("tls.pcap")
    .link_type(cap.link_type())   // inherit from capture source
    .open()?;

let mut count = 0u32;
while count < 1000 {
    if let Some(pkt) = cap.next()? {
        dump.write_packet(&pkt)?;
        count += 1;
    }
}
// Dump flushes and closes automatically when dropped
```

`Dump` must be told the link type before `open()` is called — it uses this to write the correct header. Use `cap.link_type()` to inherit it from a live or file capture source.

`flush()` is a no-op (the underlying `File` has no Rust-level buffer), but it is available for uniform checkpoint-style code. The file is closed when `Dump` is dropped.

### One-shot convenience function

For writing a collected set of packets in one call:

```rust
use pkttap::{dump_packets, LinkType, Packet};

let packets: Vec<Packet> = collect_packets()?;
dump_packets("output.pcap", &packets, LinkType::Ethernet)?;
```

### pcapng output

Use a `.pcapng` extension to write next-generation format. pkttap writes an Interface Description Block followed by Enhanced Packet Blocks — fully compatible with Wireshark and `tcpdump`.

```rust
let mut dump = Dump::to_file("output.pcapng")
    .link_type(LinkType::Ethernet)
    .open()?;

for pkt in &packets {
    dump.write_packet(pkt)?;
}
```

**Choosing a format:**

| Format | Extension | Use when |
|--------|-----------|----------|
| pcap | `.pcap` | Maximum compatibility — works with every tool |
| pcapng | `.pcapng` | You need nanosecond timestamps, interface names, or multi-interface captures |

---

## The Packet type

Every packet returned by `Capture::next()` or passed to `Dump::write_packet()` is a `Packet`:

```rust
pub struct Packet {
    pub data: Vec<u8>,         // Captured bytes (up to snaplen)
    pub timestamp: SystemTime, // Capture timestamp
    pub orig_len: u32,         // On-wire length before any truncation
    pub link_type: LinkType,   // Link-layer framing of this packet
}
```

```rust
while let Some(pkt) = cap.next()? {
    // Raw bytes
    let raw: &[u8] = &pkt.data;

    // Timestamp as seconds + microseconds since epoch
    let ts = pkt.timestamp
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    println!("{}.{:06}", ts.as_secs(), ts.subsec_micros());

    // On-wire length (may be larger than data.len() if snaplen truncated)
    println!("captured {} of {} bytes on wire", pkt.data.len(), pkt.orig_len);

    // Was the packet truncated by snaplen?
    if pkt.is_truncated() {
        println!("packet was truncated");
    }

    // Link type (Ethernet, RawIp, or LinuxSll)
    println!("{:?}", pkt.link_type);
}
```

**`LinkType`** determines the framing of `pkt.data`:

| `LinkType` | `pkt.data` starts with |
|------------|------------------------|
| `Ethernet` | 14-byte Ethernet header (dst MAC, src MAC, EtherType) |
| `RawIp`    | IP header directly (no link-layer header) |
| `LinuxSll` | 16-byte Linux SLL header |

---

## Error handling

All fallible operations return `Result<T, pkttap::Error>`:

```rust
use pkttap::Error;

match Capture::live("eth0").open() {
    Ok(cap) => { /* use cap */ }

    Err(Error::PermissionDenied) => {
        eprintln!("run as root or grant CAP_NET_RAW");
    }

    Err(Error::Filter(e)) => {
        // Filter expression did not compile — e is a pktbaffle::Error
        eprintln!("bad filter: {e}");
    }

    Err(Error::Platform(msg)) => {
        // Platform-specific failure (e.g., interface not found, Npcap missing)
        eprintln!("platform error: {msg}");
    }

    Err(Error::Io(e)) => {
        eprintln!("I/O error: {e}");
    }

    Err(Error::Pcap(e)) => {
        // pcap-file parse error (file captures only)
        eprintln!("pcap parse error: {e}");
    }
}
```

**Error variants at a glance:**

| Variant | When it occurs |
|---------|----------------|
| `Error::PermissionDenied` | Insufficient privileges for live capture |
| `Error::Filter(pktbaffle::Error)` | Filter expression is invalid |
| `Error::Platform(String)` | Interface not found, Npcap not installed, etc. |
| `Error::Io(std::io::Error)` | File open/read/write failure |
| `Error::Pcap(pcap_file::PcapError)` | Malformed pcap or pcapng file |

The `Error` type implements `std::error::Error` and `Display`, so it works with `?`, `anyhow`, `thiserror`, and similar libraries.

---

## Platform notes

### Linux

pkttap uses `AF_PACKET` / `SOCK_RAW` sockets with `SO_ATTACH_FILTER` for kernel-level cBPF filtering. No C libraries are required.

**Privileges:** The process needs `CAP_NET_RAW`. Either run as root or grant the capability:

```
sudo setcap cap_net_raw=ep ./your_binary
```

**Interface names:** Use the names shown by `ip link` or `ifconfig` (e.g., `eth0`, `enp3s0`, `wlan0`, `lo`).

**Link type:** Determined automatically by reading `/sys/class/net/<iface>/type`. Ethernet NICs and the loopback interface both report `Ethernet` (the kernel prepends a synthetic Ethernet header on loopback for `AF_PACKET`).

```rust
// All interfaces (including loopback)
let mut cap = Capture::live("lo").filter("icmp").open()?;
```

### macOS

pkttap uses `/dev/bpf*` character devices with `BIOCSETF` for kernel-level cBPF filtering. No C libraries are required.

**Privileges:** `/dev/bpf*` is typically root-only. Either run as root or use Wireshark's `ChmodBPF` helper to grant access to a group.

**Interface names:** Use names shown by `ifconfig` (e.g., `en0`, `en1`, `lo0`).

**Link type:** Determined by `BIOCGDLT` after opening the device — the authoritative DLT from the kernel.

```rust
let mut cap = Capture::live("en0")
    .filter("tcp port 443")
    .promiscuous(true)
    .open()?;
```

### Windows

pkttap uses Npcap via dynamically-loaded `wpcap.dll`. The binary compiles and starts without Npcap present; `open()` and `interfaces()` return a clear error if Npcap is not installed.

**Prerequisites:** Install [Npcap](https://npcap.com) (free for personal use). Enable "WinPcap API-compatible mode" or use the Npcap SDK header path during installation.

**Privileges:** Live capture requires Administrator privileges or membership in the `NPF_Users` group (Npcap can be configured to allow non-admin access during install).

**Interface names:** pkttap exposes Npcap's friendly interface descriptions (e.g., `"Wi-Fi"`, `"Ethernet"`, `"Local Area Connection"`). You can also pass the raw `\Device\NPF_{GUID}` device path directly.

```rust
// Friendly name (preferred)
let mut cap = Capture::live("Wi-Fi").filter("tcp port 443").open()?;

// Raw device path (escape hatch)
let mut cap = Capture::live(r"\Device\NPF_{4B5B2D9C-...}").open()?;

// List available interfaces
for name in pkttap::interfaces()? {
    println!("{name}");
}
```

**DLL search order:** pkttap looks for `wpcap.dll` in:
1. `%SystemRoot%\System32\Npcap\` (Npcap's default install path)
2. `%SystemRoot%\System32\` (WinPcap legacy / manually placed)
3. Directories on `%PATH%`

---

## The inspect example

The `inspect` example reads from a live interface or a pcap/pcapng file and prints each packet as a hex + ASCII dump. It demonstrates all major pkttap features.

```
$ cargo run --example inspect -p pkttap -- --help

inspect — packet inspector

USAGE:
    inspect <INTERFACE|FILE> [FILTER]
    inspect -l | --list-interfaces
    inspect -h | --help
...
```

**Common uses:**

```bash
# Capture all traffic on eth0
cargo run --example inspect -p pkttap -- eth0

# Capture HTTPS traffic only
cargo run --example inspect -p pkttap -- eth0 "tcp port 443"

# Inspect a pcap file
cargo run --example inspect -p pkttap -- traffic.pcap

# Inspect a pcap file with a filter
cargo run --example inspect -p pkttap -- traffic.pcap "udp port 53"

# List available interfaces
cargo run --example inspect -p pkttap -- -l
```

**Sample output:**

```
link type: Ethernet

[     1] 1747123456.018432  Ethernet  74 bytes
0000   45 00 00 4a 1a 2b 40 00  40 06 c3 d4 c0 a8 01 0a  |E..J.+@.@.......|
0010   8b fb 45 00 c4 f2 01 bb  de ad be ef 00 00 00 00  |..E..............|
0020   a0 02 fa f0 12 34 00 00  02 04 05 b4 04 02 08 0a  |.....4..........|
0030   ...

[     2] 1747123456.019102  Ethernet  66 bytes
0000   45 00 00 28 1a 2c 40 00  40 06 c3 ed c0 a8 01 0a  |E..(.,@.@.......|
...

2 packets captured
```

Each packet shows:
- **Packet number** and **timestamp** (seconds.microseconds since epoch)
- **Link type** and **on-wire length** (with `[truncated to N]` if snaplen applies)
- **Hex dump:** 16 bytes per row — offset, two groups of 8 hex bytes, then a `|printable ASCII|` column

---

## Filter expression language

pkttap uses [pktbaffle](../) to compile filter expressions. The same libpcap / `tcpdump` syntax applies:

```
tcp port 443                       # HTTPS
udp port 53                        # DNS
icmp                               # all ICMP
host 192.168.1.1                   # to/from a specific host
src net 10.0.0.0/8                 # from an entire network
tcp and port 22                    # SSH
not port 22                        # everything except SSH
(port 80 or port 443) and tcp      # web traffic
vlan 100                           # VLAN 100
tcp[tcpflags] & tcp-syn != 0       # SYN packets (new connections)
len > 1200                         # large packets
ether host aa:bb:cc:dd:ee:ff       # specific MAC address
```

See the [pktbaffle README](../pktbaffle/README.md) for the complete filter expression reference, including raw byte access, named constants, VLAN/MPLS, and all supported primitives.
