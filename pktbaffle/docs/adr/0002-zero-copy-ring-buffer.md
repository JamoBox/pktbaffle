# Zero-copy ring buffer and borrowed PacketRef

`pkttap` yields `PacketRef<'_>` borrowing from an internal ring buffer (TPACKET_V3 on Linux, Npcap ring on Windows, BPF read buffer on macOS) rather than allocating a `Vec<u8>` per packet. This makes the iterator item lifetime-bound to the current iteration step — callers must call `.to_owned()` to retain a packet. The trade-off is an awkward lifetime in exchange for eliminating per-packet heap allocation, which is the dominant cost at line rate. An owned-packet API would be simpler but unsuitable for high-throughput capture.
