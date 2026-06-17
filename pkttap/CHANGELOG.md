# Changelog

All notable changes to **pkttap** are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
