# pktbaffle

A pure-Rust compiler for libpcap-style packet filter expressions. It parses the same filter syntax used by `tcpdump` and `pcap_compile(3)` and produces either classic BPF (cBPF) or extended BPF (eBPF) bytecode with no C runtime dependency.

> **Note:** This codebase was written with the assistance of AI coding tools (Claude and Gemini).

## Features

- Parses the full libpcap filter expression grammar — `host`, `net`, `port`, `portrange`, `proto`, `ether host`, `vlan`, `mpls`, `len`, raw byte-access (`tcp[13] & 0x02 != 0`), and more
- Implicit AND (juxtaposition), `and`/`or`/`not` with standard precedence
- Outputs **classic BPF** (for `SO_ATTACH_FILTER`, raw sockets, pcap) or **extended BPF** (for XDP, TC hooks)
- Three link types: `Ethernet`, `RawIp`, `LinuxSll`
- Zero dependencies in the library crate

## Quick start

```toml
[dependencies]
pktbaffle = "0.1"
```

```rust
use pktbaffle::{compile, LinkType, Target};

// Classic BPF — attach to a raw socket with SO_ATTACH_FILTER
let prog = compile("tcp port 443", LinkType::Ethernet, Target::Classic)?;
let bytes = prog.to_le_bytes(); // 8 bytes per instruction, little-endian

// eBPF — load into an XDP or TC program
let prog = compile("tcp port 443", LinkType::Ethernet, Target::Extended)?;
let bytes = prog.to_le_bytes();
```

### Inspect the AST without generating code

```rust
let expr = pktbaffle::parse("host 10.0.0.1 and tcp port 22")?;
println!("{expr:#?}");
```

## Filter syntax examples

| Expression | Matches |
|---|---|
| `host 192.168.1.1` | IPv4 src or dst |
| `src host 10.0.0.1` | IPv4 source only |
| `net 10.0.0.0/8` | IPv4 network |
| `tcp port 443` | TCP to/from port 443 |
| `udp portrange 1024-65535` | UDP ephemeral ports |
| `port 80 or port 443` | HTTP or HTTPS |
| `tcp and not port 22` | TCP excluding SSH |
| `ether host aa:bb:cc:dd:ee:ff` | Ethernet MAC |
| `vlan 100` | VLAN-tagged, ID 100 |
| `mpls` | Any MPLS-labeled packet |
| `ip multicast` | IPv4 multicast dst |
| `ip6 and tcp port 80` | IPv6 HTTP |
| `len <= 64` | Short packets |
| `tcp[13] & 0x02 != 0` | TCP SYN flag (raw byte access) |

## API

```rust
// Compile a filter to a Program (cBPF or eBPF)
pub fn compile(filter: &str, link: LinkType, target: Target) -> Result<Program>

// Parse without code generation
pub fn parse(filter: &str) -> Result<ast::Expr>

// Program methods
prog.len()            // instruction count
prog.to_le_bytes()    // raw bytes (8 bytes/instruction)
prog.as_classic()     // Option<&bpf::Program>
prog.as_extended()    // Option<&ebpf::Program>
```

### Link types

| `LinkType` | Description |
|---|---|
| `Ethernet` | IEEE 802.3 / Ethernet II (14-byte header) |
| `RawIp` | Raw IPv4 — no link-layer header |
| `LinuxSll` | Linux "cooked" capture (SLL, 16-byte header) |

## Try it

The `dump_filter` example prints the compiled bytecode:

```
cargo run --example dump_filter -- "tcp port 80"
cargo run --example dump_filter -- --ebpf "tcp port 80"
```

## Limitations

- No optimizer — redundant protocol checks across AND operands are not yet eliminated
- `ether multicast` is a stub
- `inbound` / `outbound` direction primitives cannot be expressed in BPF and return a `CodegenError`

## License

MIT OR Apache-2.0
