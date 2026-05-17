# ADR 0004 — Dump: write-side API for pcap/pcapng files

## Status
Accepted

## Context
`pktcap` can read packets from live interfaces and pcap/pcapng files via `Capture`, but had no way to write packets to disk. Users need to record captures for offline analysis.

## Decision
Add a `Dump` type as the write-side counterpart to `Capture`, with the following design:

**Format**: both pcap and pcapng, selected automatically by file extension (`.pcap` → pcap, `.pcapng` → pcapng). The `pcap-file` crate provides both writers.

**API**: builder + streaming. `Dump::to_file(path).link_type(lt).open()?` opens the file and writes the format header immediately. `dump.write_packet(&pkt)?` writes one packet at a time with no internal buffering. A convenience wrapper `pktcap::dump_packets(path, &packets, lt)` is provided for one-shot use.

**LinkType**: required explicitly on the builder — `.open()` errors if omitted. Both pcap and pcapng must record the link type before any packets (global header / IDB). Deferring to the first packet would delay header writes and complicate multi-threaded use.

**Overwrite only**: `Dump::to_file` always creates or truncates. Appending to pcap requires skipping the existing global header; appending to pcapng involves multi-SHB files that some readers handle poorly. File rotation by filename is the standard alternative.

**Flushing**: `Dump` exposes `flush() -> Result<()>` for explicit control. `Drop` performs a best-effort flush. Per-packet flushing is not forced — callers doing crash-safe recording call `flush()` at their own cadence.

## Alternatives considered
- **Append mode**: rejected — pcapng multi-SHB compatibility is poor; filename rotation is standard practice.
- **Infer LinkType from first packet**: rejected — delays header write, complicates concurrent use.
- **Plain batch function only**: rejected — forces full packet accumulation in memory, unusable for live captures.
- **Per-packet fsync**: rejected — destroys throughput; callers who need durability can call `flush()` themselves.
