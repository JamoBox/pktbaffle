# Changelog

All notable changes to **pkttap** are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **`Capture::stats()`** — returns a [`CaptureStats`] struct with cumulative
  packet receive and drop counts from the kernel capture layer ([#87]).
  Non-zero `dropped` means the kernel silently discarded packets because its
  buffer was full; without this there was no way to detect loss.

  ```rust
  let s = cap.stats()?;
  println!("received={} dropped={}", s.received, s.dropped);
  ```

  Platform implementations:
  - **Linux**: `getsockopt(SOL_PACKET, PACKET_STATISTICS)`. The kernel resets
    its counters on each read; pkttap accumulates them so `received` and
    `dropped` are always totals from capture start.
  - **macOS**: `ioctl(BIOCGSTATS)` on the BPF device fd. Counters are
    cumulative; no accumulation needed.
  - **Windows**: `pcap_stats()` dynamically loaded from `wpcap.dll`. Counters
    are cumulative. Added `pcap_stats` to the Npcap function table.
  - **File capture**: always returns a zeroed `CaptureStats`.

- **`CaptureStats`** — public struct with fields `received: u64`,
  `dropped: u64`, `if_dropped: u64`. Implements `Debug`, `Clone`, `Copy`,
  `Default`, and `PartialEq`.

- **`stats` example** (`examples/stats.rs`) — captures live traffic and
  prints cumulative stats every N packets (default: 500), with a per-interval
  drop rate and a warning when loss is detected. Run with:
  ```
  cargo run --example stats -p pkttap -- eth0
  ```

[#87]: https://github.com/JamoBox/pktbaffle/issues/87

## [0.3.0] - 2026-06-17

Zero-copy capture: `Capture` no longer allocates a `Vec<u8>` per packet.

### Changed (breaking)

- **`Capture::next()` now yields a borrowed `PacketRef<'_>`** instead of an owned
  `Packet` ([#85]). The bytes are borrowed directly from the capture source's
  internal buffer, so capturing a packet performs no heap allocation. `Capture`
  is now a lending iterator: a `PacketRef` is valid only until the next `next()`
  call and cannot be stored across iterations (the borrow checker enforces this).
- **`Packet` is now the owned form**, produced by `PacketRef::to_owned()`. Its
  fields are no longer `pub`; read them through `data()`, `timestamp()`,
  `orig_len()`, `link_type()`, and `is_truncated()`. Added `Packet::new()`,
  `Packet::as_ref()`, and `Packet::into_data()`.
- **`Dump::write_packet()` now takes a `PacketRef<'_>` by value** instead of
  `&Packet`. A `Capture` yields a `PacketRef`, so capture→dump pipelines pass it
  straight through; to write an owned `Packet`, call `pkt.as_ref()`.

### Migration

| Before (0.2)                       | After (0.3)                                     |
|------------------------------------|-------------------------------------------------|
| `pkt.data` / `pkt.orig_len`        | `pkt.data()` / `pkt.orig_len()`                 |
| `pkt.timestamp` / `pkt.link_type`  | `pkt.timestamp()` / `pkt.link_type()`           |
| store / return a captured `Packet` | `let owned = pkt.to_owned();`                   |
| `dump.write_packet(&pkt)`          | `dump.write_packet(pkt)` (owned: `.as_ref()`)   |

Callers that process-and-discard each packet (counting, filtering, forwarding)
need only the accessor-method changes and get the no-allocation benefit for free.

### Performance

- Removes the per-packet `Vec<u8>` allocation on all live backends (Linux
  `recvfrom`, macOS BPF, Windows Npcap) and on the file path (reused scratch
  buffer). At line rate this was the dominant allocator cost. See
  [ADR 0002](../pktbaffle/docs/adr/0002-zero-copy-ring-buffer.md). A Linux
  TPACKET_V3 mmap ring (to also drop the per-packet syscall) remains future work.

[#85]: https://github.com/JamoBox/pktbaffle/issues/85
