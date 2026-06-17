# pktbaffle

A pure-Rust ecosystem for compiling libpcap-style packet filter expressions into BPF programs and capturing packets from live interfaces or pcap/pcapng files.

**pktbaffle** — BPF compiler and VM library.  
**pkttap** — cross-platform packet capture using pktbaffle filters.

## Language

**Filter**:
A libpcap-style expression string that specifies which packets to select (e.g. `"tcp port 443"`).
_Avoid_: query, rule, expression (too generic)

**Program**:
The compiled BPF artifact produced from a Filter — a sequence of cBPF or eBPF instructions ready to attach to a capture source or run in the VM.
_Avoid_: bytecode, instructions, filter (once compiled)

**Target**:
The BPF dialect a Program is compiled for: `Classic` (cBPF) or `Extended` (eBPF).
_Avoid_: mode, format, version

**LinkType**:
The link-layer framing of captured packets — `Ethernet`, `RawIp`, or `LinuxSll` — which determines byte offsets in the generated Program.
_Avoid_: datalink, layer, medium

**Capture**:
The unified source type in `pkttap` that yields packets from either a live interface or a pcap/pcapng file. A single enum type, not a trait.
_Avoid_: handle, session, reader, socket

**Dump**:
The write-side counterpart to Capture. Accepts packets and writes them to a pcap or pcapng file on disk. Supports both pcap and pcapng format, selected by file extension (`.pcap` → pcap, `.pcapng` → pcapng). Named after `tcpdump -w` and `pcap_dump()`.
_Avoid_: writer, recorder, sink, exporter

**PacketRef**:
A borrowed view of a single captured packet, valid only for the current iteration step. Carries raw bytes, timestamp, original length, and LinkType. Call `.to_owned()` to extend its lifetime.
_Avoid_: frame, buffer, packet (use PacketRef when referring to the borrowed iterator item specifically)

**Packet**:
The owned form of a captured packet produced by `PacketRef::to_owned()`.
_Avoid_: frame, buffer

**VM**:
The software cBPF interpreter in `pktbaffle` (behind the `vm` feature) that evaluates a Program against raw packet bytes in userspace. Used for file-based filtering where the kernel is not involved.
_Avoid_: interpreter, evaluator, engine

**Capture buffer**:
The reusable internal buffer each capture source fills and that PacketRefs borrow from for zero-copy delivery: the `recvfrom` buffer on Linux, the BPF read buffer on macOS, Npcap's `pcap_next_ex` buffer on Windows, and a per-`FileCapture` scratch buffer for pcap/pcapng files. A true zero-copy kernel ring (Linux TPACKET_V3) is future work; see ADR 0002.
_Avoid_: ring buffer (not yet a kernel ring), mmap buffer, socket buffer

**Snaplen**:
The maximum number of bytes captured per packet. Packets longer than snaplen are truncated; `PacketRef::orig_len()` reflects the on-wire length.
_Avoid_: capture length, truncation length

## Relationships

- A **Filter** string is compiled by `pktbaffle::compile()` into a **Program** for a given **Target** and **LinkType**
- A **Capture** is configured with a **Filter** string or a pre-compiled **Program** via its builder
- A **Dump** is configured with a **LinkType** (required) and a file path via its builder; format is determined by file extension
- A **Capture** yields **PacketRef**s; each **PacketRef** borrows from the source's **Capture buffer** and must be consumed before the next iteration step
- The **VM** evaluates a **Program** against **PacketRef** bytes when the **Capture** source is a file (not a live interface)
- **Snaplen** applies at the **Capture** level and affects all **PacketRef**s from that source

## Example dialogue

> **Dev:** "Should I pass a Filter or a Program to open a Capture?"
> **Domain expert:** "Either — the builder accepts both. Pass a Filter string if you don't need to reuse the compiled Program; pass a Program directly if you're opening multiple Captures with the same filter."

> **Dev:** "Can I store a PacketRef in a Vec for later?"
> **Domain expert:** "No — a PacketRef borrows from the source's Capture buffer. Call `.to_owned()` to get a Packet you can store."

## Flagged ambiguities

- "packet" is used loosely in conversation — in code, distinguish **PacketRef** (borrowed, iterator item) from **Packet** (owned).
- "filter" can mean either the Filter string or the compiled Program — in API design, use "filter" only for the string form and "program" for the compiled artifact.
