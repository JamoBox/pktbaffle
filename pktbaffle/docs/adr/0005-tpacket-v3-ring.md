# ADR 0005 — Linux TPACKET_V3 ring buffer as an opt-in capture backend

## Status
Accepted (implemented in pkttap, issue #90). Completes the Linux half of ADR 0002.

## Context
The Linux backend reads one packet per `recvmsg()`. That costs a syscall and a
kernel→userspace copy for every packet, which dominates at small frame sizes:
at line rate with 64-byte frames it is hundreds of thousands of syscalls a
second. ADR 0002 removed the *per-packet allocation* on all platforms but left
the Linux syscall and copy in place, deferring `TPACKET_V3` to its own issue.

`TPACKET_V3` (Linux 3.2+) maps a ring of blocks shared between the kernel and
the process. The kernel writes frames into it directly and flips a per-block
status word; userspace reads the word, walks the frames in place, and writes the
word back when done. No syscall, no copy.

Measured on loopback, capturing 2 000 packets: 2 007 `recvmsg` calls on the
default path, zero receive syscalls through the ring.

## Decision

**Opt in, not automatic.** `Capture::live(iface).ring(RingConfig::new())` selects
the ring; without it the `recvmsg()` path is unchanged. A ring reserves several
megabytes of kernel memory per socket and imposes a delivery latency bound
(a partly filled block is only handed over when the retire timer fires), so it
is not a free upgrade for every caller. Making it explicit also keeps the
default path's behaviour bit-for-bit unchanged for existing users.

**Errors, no silent fallback.** If the kernel predates `TPACKET_V3` or cannot
allocate the ring, `open()` returns an error naming the reason, rather than
quietly degrading to `recvmsg()`. A caller who wants a fallback writes it
explicitly and knows which path they got; a silent one would hide a several-fold
throughput difference behind an identical-looking `Capture`.

**Geometry rounds up rather than rejecting.** `RingConfig` takes a block size
and count. Values the kernel would refuse — a block smaller than a page or than
a single frame — are rounded up, since the caller's intent ("blocks about this
big") is unambiguous. Only genuinely unusable input (zero blocks, a ring that
overflows the size fields) is an error.

**One knob for latency.** `RingConfig::retire_timeout` maps to
`tp_retire_blk_tov`, the kernel's bound on how long a partly filled block waits.
It defaults to 100 ms, the same default as `CaptureBuilder::buffer_timeout`,
which plays the same role for the non-ring path.

**Frame walking stays in safe Rust.** As in ADR 0002, the frame parser returns
`Copy` index metadata rather than a borrow, so the `PacketRef` slice is
constructed only at the single success-path return and never on a retry path.
`unsafe` is confined to the mapping itself: `mmap`/`munmap`, reading the kernel's
structs with `read_unaligned`, and the block status word, which is accessed as an
`AtomicU32` with acquire/release ordering because the kernel writes it
concurrently.

**Pairs with fanout.** `FanoutGroup::ring(cfg)` gives every member socket its own
ring, which is the combination the two features were designed for: the kernel
splits traffic across the group and each worker thread reads its share with no
syscall and no copy.

## Alternatives considered
- **Replace `recvmsg()` outright**: rejected — the ring costs multi-megabyte
  reservations per socket and bounds delivery latency by the retire timer, which
  is the wrong default for low-rate or latency-sensitive captures.
- **Runtime detection with automatic fallback**: rejected as the default for the
  reason above; an error message a caller can act on beats a silent downgrade.
  Callers who want it can retry without `.ring()`.
- **Cargo feature flag**: rejected — the code is Linux-gated already, and a
  feature flag cannot be turned on per-capture, which is the granularity that
  actually matters here.
- **`TPACKET_V2`**: rejected — fixed-size frames waste ring memory at large
  snaplens, and V3's variable-length frames plus block retire timer are strictly
  better for capture. V2's only advantage (no block-level latency) is what the
  retire timeout already controls.
- **`recvmmsg()` batching (#89)**: complementary but weaker — it amortises the
  syscall over a batch while still copying every packet. The ring removes both
  costs, which is why #89 notes it becomes largely redundant once this lands.
