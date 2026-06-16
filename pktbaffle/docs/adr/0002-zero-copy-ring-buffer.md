# Zero-copy borrowed PacketRef

Status: Accepted (implemented in pkttap 0.3.0). Supersedes the earlier deferred,
TPACKET_V3-first framing.

`pkttap` yields `PacketRef<'_>` borrowing from the capture source's internal
buffer rather than allocating a `Vec<u8>` per packet, eliminating the per-packet
heap allocation that dominates cost at line rate. The iterator item is
lifetime-bound to the current iteration step (a lending iterator), so callers
call `.to_owned()` to retain a packet. An owned-packet API would be simpler but
unsuitable for high-throughput capture.

As built, the borrowed buffer differs per backend:

- **Linux** reuses the existing `recvfrom` receive buffer (`self.buf`). A
  TPACKET_V3 mmap ring — which would additionally remove the per-packet
  `recvfrom` syscall — is deferred to its own issue; this ADR supersedes the
  original "TPACKET_V3 first" framing.
- **macOS** borrows the BPF batch read buffer, walking each `bpf_hdr` frame in
  place.
- **Windows** borrows the buffer `pcap_next_ex` returns, which Npcap guarantees
  is valid until the next capture call — exactly the lending lifetime, so no
  copy is needed. (The original assumption that a copy was unavoidable was wrong
  for this layer; only the kernel→Npcap copy, which every platform also has,
  remains.)
- **File** capture copies each packet once into a reusable scratch buffer.
  `pcap-file` already lends from its own reused buffer, but borrowing it through
  the userspace filter-skip loop runs into Rust's lending borrow-checker
  limitation; the scratch copy keeps the path allocation-free and in safe Rust.

To keep the lending iterator in **safe Rust** — no `unsafe` lifetime extension,
no `polonius-the-crab` — each backend's frame parser returns `Copy` index/
metadata rather than a borrow, and the `PacketRef` slice is constructed only at
the single success-path return. The borrow is therefore never created on a
`continue`/retry path, which sidesteps the borrow checker's "problem case #3".
