# pktbaffle

A pure-Rust compiler for libpcap-style packet filter expressions. Parse the same filter syntax used by `tcpdump` and Wireshark and produce classic BPF (cBPF) or extended BPF (eBPF) bytecode with zero C dependencies.

> **Note:** This codebase was written with the assistance of AI coding tools (Claude and Gemini).

---

## Contents

- [Installation](#installation)
- [Quick start](#quick-start)
- [Filter expression language](#filter-expression-language)
  - [IP hosts and networks](#ip-hosts-and-networks)
  - [Ports and port ranges](#ports-and-port-ranges)
  - [Protocols](#protocols)
  - [Direction qualifiers](#direction-qualifiers)
  - [Logical operators](#logical-operators)
  - [Ethernet and link layer](#ethernet-and-link-layer)
  - [VLAN and MPLS](#vlan-and-mpls)
  - [Broadcast and multicast](#broadcast-and-multicast)
  - [Packet length](#packet-length)
  - [Raw byte access](#raw-byte-access)
  - [Named constants](#named-constants)
  - [Combining expressions](#combining-expressions)
- [Compilation targets](#compilation-targets)
- [Working with the output](#working-with-the-output)
- [Software VM](#software-vm)
- [Parsing only](#parsing-only)
- [Error handling](#error-handling)
- [Link types](#link-types)
- [Limitations](#limitations)
- [pkttap](#pkttap)

---

## Installation

```toml
[dependencies]
pktbaffle = "0.2"
```

To enable the software BPF interpreter (for userspace packet matching without a kernel):

```toml
[dependencies]
pktbaffle = { version = "0.2", features = ["vm"] }
```

---

## Quick start

```rust
use pktbaffle::{compile, LinkType, Target};

// Classic BPF — attach to a raw socket with SO_ATTACH_FILTER
let prog = compile("tcp port 443", LinkType::Ethernet, Target::Classic)?;
println!("{} instructions", prog.len());
let bytes = prog.to_le_bytes(); // 8 bytes per instruction, little-endian

// eBPF — load into an XDP or TC hook
let prog = compile("tcp port 443", LinkType::Ethernet, Target::Extended)?;
let bytes = prog.to_le_bytes();
```

Print the disassembly of a filter:

```
$ cargo run --example dump_filter -- "tcp and port 80"
Filter: "tcp and port 80"  (13 instructions)  target=Classic
(000) ldh      [12]
(001) jeq      #0x800           jt 2     jf 12
(002) ldb      [23]
(003) jeq      #0x6             jt 4     jf 12
(004) ldh      [20]
(005) jset     #0x1fff          jt 12    jf 6
(006) ldxb     4*([14]&0xf)
(007) ldh      [x + 14]
(008) jeq      #0x50            jt 11    jf 9
...

$ cargo run --example dump_filter -- --ebpf "tcp port 80"
```

---

## Filter expression language

The filter language is identical to the one accepted by `tcpdump` and `pcap_compile(3)`. A filter is a boolean expression over packet fields; packets that evaluate to `true` are accepted, all others are dropped.

### IP hosts and networks

Match packets by source or destination IP address:

```
host 192.168.1.1          # src or dst IPv4 address
src host 10.0.0.1         # source address only
dst host 8.8.8.8          # destination address only
host 2001:db8::1          # IPv6 address
```

Match by network prefix (CIDR notation or explicit mask):

```
net 192.168.0.0/24        # any host in 192.168.0.0/24
net 10.0.0.0/8            # any host in 10.0.0.0/8
src net 172.16.0.0/12     # source in 172.16.0.0/12
net 10.0.0.0 mask 255.0.0.0   # explicit mask (equivalent to /8)
dst net 192.168.1.0/24    # destination network
```

### Ports and port ranges

```
port 80                   # src or dst port 80 (any IP protocol)
tcp port 443              # TCP src or dst port 443
udp port 53               # UDP src or dst port 53
src port 1234             # source port only
dst port 22               # destination port only
tcp dst port 22           # TCP, destination port 22

portrange 1024-65535      # src or dst in range (any IP protocol)
tcp portrange 1024-65535  # TCP only
udp portrange 5000-6000   # UDP only
src portrange 32768-60999 # source port range
```

### Protocols

Match by IP protocol or ethertype:

```
tcp                       # TCP (IPv4 or IPv6)
udp                       # UDP
icmp                      # ICMPv4
icmp6                     # ICMPv6
arp                       # ARP
rarp                      # RARP
igmp                      # IGMP
sctp                      # SCTP
ah                        # Authentication Header (IPsec, proto 51)
esp                       # Encapsulating Security Payload (IPsec, proto 50)
pim                       # Protocol Independent Multicast (proto 103)
vrrp                      # Virtual Router Redundancy Protocol (proto 112)

ip                        # Any IPv4 packet
ip6                       # Any IPv6 packet

proto 47                  # Raw IP protocol number (47 = GRE)
```

### Direction qualifiers

A direction qualifier (`src`, `dst`) can precede any address or port primitive:

```
src host 1.2.3.4          # source address
dst host 1.2.3.4          # destination address
src port 12345            # source port
dst port 80               # destination port
src net 10.0.0.0/8        # source network
dst net 172.16.0.0/12     # destination network
src and dst host 1.2.3.4  # both src AND dst match (same host)
src or dst port 80        # either src OR dst port (same as just "port 80")
```

When no direction qualifier is given, `src or dst` is implied — the primitive matches if either field satisfies the condition.

### Logical operators

Combine primitives with boolean operators:

```
tcp and port 80                          # TCP AND port 80
port 80 or port 443                      # HTTP or HTTPS
tcp and not port 22                      # TCP but not SSH
host 10.0.0.1 and tcp and port 443       # HTTPS to/from 10.0.0.1
(port 80 or port 443) and host 10.0.0.1  # parentheses for grouping
```

Both word and symbol forms are accepted:

| Word  | Symbol | Meaning |
|-------|--------|---------|
| `and` | `&&`   | Both sides must match |
| `or`  | `\|\|` | Either side must match |
| `not` | `!`    | Negation |

**Precedence** (highest to lowest): `not` > `and` > `or`.

Use parentheses to override precedence:

```
# Without parens: parsed as (port 22) or (port 80 and host 10.0.0.1)
port 22 or port 80 and host 10.0.0.1

# With parens: (port 22 or port 80) and host 10.0.0.1
(port 22 or port 80) and host 10.0.0.1
```

### Ethernet and link layer

Match by MAC address or EtherType (only meaningful with `LinkType::Ethernet`):

```
ether host aa:bb:cc:dd:ee:ff     # src or dst MAC
ether src aa:bb:cc:dd:ee:ff      # source MAC only
ether dst aa:bb:cc:dd:ee:ff      # destination MAC only
ether broadcast                  # ff:ff:ff:ff:ff:ff
ether proto 0x0800               # EtherType = IPv4
ether proto 0x0806               # EtherType = ARP
ether proto 0x86dd               # EtherType = IPv6
```

### VLAN and MPLS

```
vlan                      # any VLAN-tagged frame (EtherType 0x8100)
vlan 100                  # VLAN ID 100 specifically
mpls                      # any MPLS-labeled packet (EtherType 0x8847 or 0x8848)
mpls 1000                 # MPLS label 1000 specifically
pppoed                    # PPPoE Discovery (EtherType 0x8863)
pppoes                    # PPPoE Session (EtherType 0x8864)
```

To match traffic inside a VLAN, combine the VLAN primitive with another expression — the field offsets automatically shift past the VLAN header:

```
vlan 100 and tcp port 443
vlan and udp port 53
```

### Broadcast and multicast

```
ip broadcast              # IPv4 broadcast destination
ip multicast              # IPv4 multicast destination (224.0.0.0/4)
ip6 multicast             # IPv6 multicast destination (ff00::/8)
ether broadcast           # Ethernet broadcast (ff:ff:ff:ff:ff:ff)
```

### Packet length

Match on the captured (on-wire) length of the packet:

```
len < 64                  # shorter than 64 bytes
len <= 64                 # 64 bytes or fewer
len > 1500                # larger than standard Ethernet MTU
len == 40                 # exactly 40 bytes
len != 1500               # anything but 1500 bytes

less 64                   # synonym for len < 64
greater 1400              # synonym for len > 1400
```

### Raw byte access

Access arbitrary bytes within the packet with the `proto[offset:size]` syntax.

**Syntax:** `layer[offset:size] [& mask] op value`

- `layer` selects where to start counting: empty or `ip` for the network header, `tcp`/`udp`/`icmp` for the transport header.
- `offset` is the byte offset (integer) from the start of that layer.
- `size` is `1` (byte), `2` (16-bit halfword), or `4` (32-bit word).
- `& mask` is an optional bitwise AND applied before the comparison.
- `op` is one of `==`, `!=`, `<`, `<=`, `>`, `>=`, `&` (`& value != 0`).

```
ip[9] == 6                # IP protocol field == TCP (equivalent to "tcp")
ip[8] < 5                 # IP TTL < 5 (nearly-expired)
ip[6:2] & 0x1fff != 0    # IP fragment offset non-zero (fragmented)
tcp[13] == 0x02           # TCP flags byte == SYN only
tcp[13] & 0x12 != 0       # TCP SYN or ACK flag set
tcp[0:2] == 80            # TCP source port == 80 (16-bit halfword)
udp[4:2] > 20             # UDP payload length > 20 bytes
icmp[0] == 8              # ICMP type == Echo Request (ping)
```

Use named constants for clarity (see [Named constants](#named-constants)):

```
tcp[tcpflags] & tcp-syn != 0          # SYN flag
tcp[tcpflags] & tcp-rst != 0          # RST flag
tcp[tcpflags] & (tcp-syn|tcp-ack) == (tcp-syn|tcp-ack)  # SYN-ACK
icmp[icmptype] == icmp-echo           # ping request
icmp[icmptype] == icmp-unreach        # destination unreachable
```

### Named constants

Named constants expand to their numeric equivalents, making raw byte access more readable.

**TCP header offsets:**

| Name       | Value | Meaning |
|------------|-------|---------|
| `tcpflags` | 13    | TCP flags byte offset within the TCP header |

**TCP flag bits (for use with `tcp[tcpflags] &`):**

| Name       | Value  | Flag |
|------------|--------|------|
| `tcp-fin`  | `0x01` | FIN  |
| `tcp-syn`  | `0x02` | SYN  |
| `tcp-rst`  | `0x04` | RST  |
| `tcp-push` | `0x08` | PSH  |
| `tcp-ack`  | `0x10` | ACK  |
| `tcp-urg`  | `0x20` | URG  |
| `tcp-ece`  | `0x40` | ECE  |
| `tcp-cwr`  | `0x80` | CWR  |

**ICMP header offsets:**

| Name        | Value | Meaning |
|-------------|-------|---------|
| `icmptype`  | 0     | ICMP type field offset |
| `icmpcode`  | 1     | ICMP code field offset |
| `icmp6type` | 0     | ICMPv6 type field offset |
| `icmp6code` | 1     | ICMPv6 code field offset |

**ICMP type values (for use with `icmp[icmptype] ==`):**

| Name                  | Value | Meaning |
|-----------------------|-------|---------|
| `icmp-echoreply`      | 0     | Echo Reply (ping reply) |
| `icmp-unreach`        | 3     | Destination Unreachable |
| `icmp-sourcequench`   | 4     | Source Quench |
| `icmp-redirect`       | 5     | Redirect |
| `icmp-echo`           | 8     | Echo Request (ping) |
| `icmp-routeradvert`   | 9     | Router Advertisement |
| `icmp-routersolicit`  | 10    | Router Solicitation |
| `icmp-timxceed`       | 11    | Time Exceeded |
| `icmp-paramprob`      | 12    | Parameter Problem |
| `icmp-tstamp`         | 13    | Timestamp Request |
| `icmp-tstampreply`    | 14    | Timestamp Reply |
| `icmp-maskreq`        | 17    | Address Mask Request |
| `icmp-maskreply`      | 18    | Address Mask Reply |

### Combining expressions

Real-world filters combine multiple primitives:

```
# HTTPS from a specific subnet
tcp and port 443 and src net 10.0.0.0/8

# DNS or NTP (common monitoring target)
(udp port 53 or udp port 123)

# All TCP except SSH from any RFC 1918 address
tcp and not port 22 and (src net 10.0.0.0/8 or src net 172.16.0.0/12 or src net 192.168.0.0/16)

# TCP SYN-only (detect new connections)
tcp and tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn

# ICMP echo requests (ping) from outside
icmp and icmp[icmptype] == icmp-echo and not src net 192.168.0.0/16

# Large packets likely carrying bulk data
tcp and len > 1200

# ARP storms
arp and ether broadcast

# Any VLAN-100 traffic
vlan 100

# VLAN-100 web traffic
vlan 100 and tcp and (port 80 or port 443)

# IPsec tunnel traffic
esp or ah

# IPv6 TCP to web ports
ip6 and tcp and (dst port 80 or dst port 443)
```

---

## Compilation targets

### Classic BPF (`Target::Classic`)

Produces a `bpf::Program` — the original Berkeley Packet Filter format. This is the format required by:

- Linux `SO_ATTACH_FILTER` (raw sockets, `AF_PACKET`)
- macOS `/dev/bpf*` via `BIOCSETF`
- Windows Npcap via `pcap_setfilter`
- All `pcap_compile`-compatible APIs

```rust
use pktbaffle::{compile, LinkType, Target};

let prog = compile("tcp port 443", LinkType::Ethernet, Target::Classic)?;
let cbpf = prog.as_classic().unwrap();

// Print disassembly
println!("{cbpf}");

// Get raw bytes for kernel attachment
let bytes = cbpf.to_le_bytes(); // 8 bytes per instruction

// Count instructions
println!("{} instructions", cbpf.len());

// Iterate instructions
for insn in cbpf.instructions() {
    println!("code=0x{:04x} k=0x{:08x}", insn.code, insn.k);
}
```

### Extended BPF (`Target::Extended`)

Produces an `ebpf::Program` for modern Linux kernel attachment points (XDP, TC, cgroup filters). eBPF programs use 64-bit registers and have a richer instruction set.

```rust
let prog = compile("tcp port 443", LinkType::Ethernet, Target::Extended)?;
let ebpf = prog.as_extended().unwrap();

// Raw bytes for loading via bpf(2) syscall or libbpf
let bytes = ebpf.to_le_bytes(); // 8 bytes per instruction

for insn in ebpf.instructions() {
    println!(
        "code=0x{:02x} dst={} src={} off={} imm={}",
        insn.code, insn.dst(), insn.src(), insn.off, insn.imm
    );
}
```

**Choosing a target:**

| Use case | Target |
|----------|--------|
| Raw socket (`AF_PACKET`, `SOCK_RAW`) | `Classic` |
| `pcap` / Npcap / `/dev/bpf` | `Classic` |
| XDP (`BPF_PROG_TYPE_XDP`) | `Extended` |
| TC classifier (`BPF_PROG_TYPE_SCHED_CLS`) | `Extended` |
| Userspace software filter | `Classic` + `vm` feature |

---

## Working with the output

### Disassembly

Classic BPF programs implement `Display`, producing a `tcpdump`-style listing:

```rust
let prog = compile("tcp port 80", LinkType::Ethernet, Target::Classic)?;
print!("{}", prog.as_classic().unwrap());
```

Output:

```
(000) ldh  [12]
(001) jeq  #0x800           jt 2    jf 7
(002) ldb  [23]
(003) jeq  #0x6             jt 4    jf 7
(004) ldh  [20]
(005) jset #0x1fff          jt 7    jf 6
(006) ldx  4*([14]&0xf)
(007) ret  #0
(008) ldh  [x+0]
...
```

### Instruction count and emptiness

```rust
let prog = compile("port 22", LinkType::Ethernet, Target::Classic)?;
println!("{} instructions", prog.len());
assert!(!prog.is_empty());
```

### Serialising to bytes

Both classic and extended programs encode to 8 bytes per instruction in little-endian format — ready for direct use with kernel APIs:

```rust
let bytes = prog.to_le_bytes();
assert_eq!(bytes.len(), prog.len() * 8);
```

### Accessing the instruction slice directly

```rust
let prog = compile("tcp", LinkType::Ethernet, Target::Classic)?;
let insns: &[pktbaffle::Insn] = prog.as_classic().unwrap().instructions();
for (pc, insn) in insns.iter().enumerate() {
    println!("{pc:03}: code=0x{:04x} jt={} jf={} k=0x{:08x}",
             insn.code, insn.jt, insn.jf, insn.k);
}
```

### Building programs by hand

The `bpf::Insn` type provides constructors for every instruction class, so you can write programs directly when the filter language is insufficient:

```rust
use pktbaffle::bpf::{Insn, Program, BPF_ACCEPT, BPF_DROP};

// Accept all packets (trivial pass-through filter)
let insns = vec![Insn::ret_k(BPF_ACCEPT)];

// Check: is the first byte of the packet == 0x45 (IPv4, IHL=5)?
let insns = vec![
    Insn::ldb_abs(0),               // A = packet[0]
    Insn::jeq_k(0x45, 0, 1),       // if A == 0x45: jt 0, jf 1
    Insn::ret_k(BPF_ACCEPT),        // accept
    Insn::ret_k(BPF_DROP),         // drop
];
```

---

## Software VM

Enable the `vm` feature to run a classic BPF program against a byte slice in userspace, without attaching it to a kernel socket. Useful for filtering packets read from pcap files or received via any other mechanism.

```toml
[dependencies]
pktbaffle = { version = "0.2", features = ["vm"] }
```

```rust
use pktbaffle::{compile, LinkType, Target};

let prog = compile("tcp port 443", LinkType::Ethernet, Target::Classic)?;
let cbpf = prog.as_classic().unwrap();

// Any byte slice — e.g. a raw Ethernet frame
let raw_frame: &[u8] = &[ /* ... */ ];

if cbpf.matches(raw_frame) {
    println!("packet matches the filter");
}
```

`matches` returns `true` if the program would accept the packet, `false` if it would drop it or if the program faults (e.g. out-of-bounds access). It never panics.

---

## Parsing only

Call `pktbaffle::parse` to turn a filter string into an AST (`ast::Expr`) without generating any bytecode. Useful for validating expressions, linting, or building your own code generator:

```rust
let expr = pktbaffle::parse("host 10.0.0.1 and tcp port 22")?;
println!("{expr:#?}");
// Expr::And(
//   Expr::Primitive(Primitive::Host { addr: 10.0.0.1, dir: SrcOrDst }),
//   Expr::And(
//     Expr::Primitive(Primitive::Proto(Proto::Tcp)),
//     Expr::Primitive(Primitive::Port { port: 22, dir: SrcOrDst, proto: Some(Tcp) }),
//   ),
// )
```

---

## Error handling

All fallible operations return `Result<T, pktbaffle::Error>`:

```rust
use pktbaffle::Error;

match pktbaffle::compile("tcp port ???", LinkType::Ethernet, Target::Classic) {
    Ok(prog) => { /* use prog */ }
    Err(Error::LexError { offset, ch }) => {
        eprintln!("unexpected character {:?} at byte {offset}", ch);
    }
    Err(Error::ParseError { message }) => {
        eprintln!("parse error: {message}");
    }
    Err(Error::CodegenError { message }) => {
        // Triggered by constructs valid to parse but not representable
        // in BPF, such as "inbound" or "outbound".
        eprintln!("cannot compile: {message}");
    }
}
```

The `Error` type implements `std::error::Error` and `Display`, so it works with `?`, `anyhow`, `thiserror`, and any other error-handling library.

---

## Link types

The link type tells the compiler which layer-2 framing to expect. It determines the byte offsets used for IP, TCP, and other header fields.

| `LinkType`   | Framing | Layer-3 offset | When to use |
|--------------|---------|---------------|-------------|
| `Ethernet`   | Ethernet II (14-byte header) | 14 | `AF_PACKET` sockets, Ethernet NICs, most pcap files |
| `RawIp`      | No link-layer header | 0 | TUN interfaces, raw IP sockets, `DLT_RAW` captures |
| `LinuxSll`   | Linux cooked (16-byte SLL header) | 16 | `any` pseudo-interface (`tcpdump -i any`) |

```rust
// Ethernet NIC
compile("tcp port 80", LinkType::Ethernet, Target::Classic)?;

// TUN interface (no Ethernet header)
compile("tcp port 80", LinkType::RawIp, Target::Classic)?;

// "any" interface
compile("tcp port 80", LinkType::LinuxSll, Target::Classic)?;
```

If the wrong link type is used, field offsets will be wrong and the filter will produce incorrect results — it will compile without error but match the wrong packets. Always match the link type to your actual capture source.

---

## Limitations

- **No optimizer** — redundant protocol checks across `and` operands are not eliminated. The generated programs are correct but not minimal.
- **`inbound` / `outbound`** — these direction primitives cannot be expressed in BPF and produce a `CodegenError`.
- **`ether multicast`** — parsed but generates a stub that always accepts; use `ip multicast` or `ip6 multicast` instead.
- **IPv6 fields** — complex IPv6 extension-header traversal is not supported; basic `ip6 and tcp port N` works correctly.

---

## pkttap

[**pkttap**](../pkttap/) is a companion crate that wraps platform-specific live capture (Linux AF_PACKET, macOS /dev/bpf, Windows Npcap) and pcap/pcapng file I/O behind a unified API. It uses pktbaffle to compile filter expressions before attaching them to the kernel.

See [`pkttap/README.md`](../pkttap/README.md) for full documentation.

```toml
[dependencies]
pkttap = "0.3"
```

```rust
use pkttap::Capture;

let mut cap = Capture::live("eth0")
    .filter("tcp port 443")
    .promiscuous(true)
    .open()?;

while let Some(pkt) = cap.next()? {
    // pkt is a borrowed PacketRef; call pkt.to_owned() to keep it.
    println!("{} bytes", pkt.data().len());
}
```

---

## License

Licensed under the [MIT license](../LICENSE-MIT).
