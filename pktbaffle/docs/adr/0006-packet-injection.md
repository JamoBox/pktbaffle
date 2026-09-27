# ADR 0006 — Injector: packet injection API

## Status
Accepted

## Context
`pkttap` could receive frames (`Capture`) and write them to disk (`Dump`), but had no way to put a frame on the wire. Traffic replay, fuzzing, and test tooling (e.g. replaying a pcap onto loopback during integration tests) all need that. libpcap covers it with `pcap_inject()` / `pcap_sendpacket()` ([#93](https://github.com/JamoBox/pktbaffle/issues/93)).

## Decision
Add a standalone `Injector` type:

```rust
let inj = Injector::on_interface("eth0")?;
inj.send(&frame)?;          // -> Result<usize>
inj.link_type();            // framing `frame` must use
```

**Separate type, not a `Capture` method.** A capture-only user should not pay for a transmit path, and an injector should not pay for a receive path. Keeping them apart also leaves file captures, which cannot transmit, with no method that always fails. A combined capture-and-inject handle on one socket stays a possible later extension.

**No builder.** An injector has no options today: no filter, snaplen, promiscuity or timeouts. `Injector::on_interface(iface)` returns it directly. A builder can be added without breaking callers if options appear.

**Frames go out unmodified.** The caller supplies the complete link-layer frame. pkttap adds no encapsulation and rewrites no addresses, so `link_type()` tells the caller what framing to produce. On macOS this needs `BIOCSHDRCMPLT`; without it the kernel overwrites the Ethernet source MAC.

**Transmit-only handles.** An idle injector must not buffer inbound traffic:
- Linux: the `AF_PACKET` socket is created with protocol `0`, which the kernel delivers nothing to, and is bound to the interface only to fix the egress device.
- macOS / Windows: a BPF device or Npcap handle buffers everything the interface receives until it is read. The injector installs a one-instruction reject-all read filter (`ret #0`), which does not affect writes.

**`send(&self)` and `Send + Sync` on every platform.** One injector can be shared across threads behind an `Arc`. On Linux and macOS, concurrent `send()`/`write()` on one fd is safe. On Windows, `pcap_t` is not thread-safe and reports send errors through per-handle state (`pcap_geterr`), so sends go through a `Mutex`. If `Sync` differed by platform, code would compile on Linux and fail on Windows.

**Windows copies each frame before sending.** `pcap_sendpacket` takes a `const u_char *`, but Npcap passes the caller's memory to the driver, and Windows may write into it. On the loopback adapter, sending an IPv4 frame rewrites its IP identification and header checksum in place in the caller's buffer. Handing `send`'s `&[u8]` straight through would therefore mutate memory behind a shared reference, which is undefined behaviour. Each frame is copied into a reusable buffer owned by the injector, under the same mutex, so steady-state sends do not allocate.

**Errors.** An empty frame is rejected up front on every platform (`Error::Platform`), and nothing is sent. Every other rejection comes from the OS and is passed through: a frame shorter than the link header, one larger than the MTU, or a down interface. `Error::PermissionDenied` is returned when the process lacks the privilege to open the handle.

## Alternatives considered
- **`Capture::inject(&mut self, …)`**: rejected as the primary API. It ties transmit to a receive handle and to `&mut` access, and makes no sense for file captures.
- **`send(&mut self)`**: simpler on Windows (no mutex), but it prevents sharing one injector across threads. The mutex is uncontended in the single-threaded case.
- **Binding the Linux socket to `ETH_P_ALL`** (what libpcap does when injecting through a capture socket): rejected, because the socket would receive, and drop, every frame on the interface.
- **Passing the caller's buffer straight to `pcap_sendpacket`**: rejected as unsound; see above.
