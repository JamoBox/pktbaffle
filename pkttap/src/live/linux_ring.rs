//! Linux `TPACKET_V3` mmap ring-buffer capture backend ([#90]).
//!
//! The kernel writes captured frames straight into a memory region shared with
//! this process and flips a per-block status word when a block is ready, so
//! reading a packet costs neither a syscall nor a kernel→userspace copy. The
//! `recvmsg()` path in [`super::linux`] pays both per packet.
//!
//! Layout, as the kernel lays out the mapping:
//!
//! ```text
//! ring ─┬─ block 0 ─┬─ tpacket_block_desc (48 B: status, num_pkts, …)
//!       │           ├─ tpacket3_hdr + frame bytes   ─┐
//!       │           ├─ tpacket3_hdr + frame bytes    │ chained by
//!       │           └─ …                             ┘ tp_next_offset
//!       ├─ block 1 ─ …
//!       └─ block N-1
//! ```
//!
//! A block belongs to exactly one side at a time: the kernel sets
//! `TP_STATUS_USER` to hand it over, and we write `TP_STATUS_KERNEL` back when
//! every frame in it has been read. Blocks are consumed in order and the
//! ring wraps at the end.
//!
//! [#90]: https://github.com/JamoBox/pktbaffle/issues/90

use std::os::fd::RawFd;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use crate::error::{Error, Result};
use crate::packet::{LinkType, PacketRef};
use crate::ring::RingConfig;

// ── Kernel ABI ────────────────────────────────────────────────────────────────

/// `PACKET_RX_RING` — allocates the ring (`man 7 packet`).
const PACKET_RX_RING: libc::c_int = 5;
/// `TPACKET_V3`, the value written to `PACKET_VERSION`.
const TPACKET_V3: libc::c_int = 2;
/// `TP_STATUS_USER`: the kernel has finished with this block.
const TP_STATUS_USER: u32 = 1;
/// `TP_STATUS_KERNEL`: written back to hand the block to the kernel.
const TP_STATUS_KERNEL: u32 = 0;
/// Frame headers are aligned to `TPACKET_ALIGNMENT` (16) bytes.
const TPACKET_ALIGNMENT: usize = 16;

const fn tpacket_align(n: usize) -> usize {
    (n + TPACKET_ALIGNMENT - 1) & !(TPACKET_ALIGNMENT - 1)
}

/// `struct tpacket_req3` — the ring request passed to `PACKET_RX_RING`.
#[repr(C)]
struct TpacketReq3 {
    tp_block_size: libc::c_uint,
    tp_block_nr: libc::c_uint,
    tp_frame_size: libc::c_uint,
    tp_frame_nr: libc::c_uint,
    /// Milliseconds before a partly filled block is handed to userspace.
    tp_retire_blk_tov: libc::c_uint,
    tp_sizeof_priv: libc::c_uint,
    tp_feature_req_word: libc::c_uint,
}

/// `struct tpacket_bd_ts` — block timestamp, unused here but part of the ABI.
#[repr(C)]
#[derive(Clone, Copy)]
struct TpacketBdTs {
    ts_sec: u32,
    ts_frac: u32,
}

/// `struct tpacket_hdr_v1` — the per-block header the kernel maintains.
#[repr(C)]
#[derive(Clone, Copy)]
struct TpacketHdrV1 {
    block_status: u32,
    num_pkts: u32,
    offset_to_first_pkt: u32,
    blk_len: u32,
    seq_num: u64,
    ts_first_pkt: TpacketBdTs,
    ts_last_pkt: TpacketBdTs,
}

/// `struct tpacket_block_desc` — the 48-byte descriptor at the start of a block.
#[repr(C)]
#[derive(Clone, Copy)]
struct TpacketBlockDesc {
    version: u32,
    offset_to_priv: u32,
    hdr: TpacketHdrV1,
}

/// Byte offset of `block_status` within a block. The kernel updates it
/// concurrently, so it is always accessed as an atomic rather than read out of
/// a copied [`TpacketBlockDesc`].
const BLOCK_STATUS_OFFSET: usize = 8;

/// `struct tpacket3_hdr` — the per-frame header inside a block.
#[repr(C)]
#[derive(Clone, Copy)]
struct Tpacket3Hdr {
    /// Offset from this header to the next one; 0 on the last frame in a block.
    tp_next_offset: u32,
    tp_sec: u32,
    tp_nsec: u32,
    /// Bytes actually stored in the ring for this frame.
    tp_snaplen: u32,
    /// On-wire length before any truncation.
    tp_len: u32,
    tp_status: u32,
    /// Offset from this header to the link-layer header.
    tp_mac: u16,
    tp_net: u16,
    // `union tpacket_hdr_variant1` (rxhash / VLAN) plus tail padding. Never
    // read, but they are part of the struct's size, which TPACKET3_HDRLEN —
    // and therefore the kernel's minimum frame size — is derived from.
    hv1_rxhash: u32,
    hv1_vlan_tci: u32,
    hv1_vlan_tpid: u16,
    hv1_padding: u16,
    tp_padding: [u8; 8],
}

/// `TPACKET3_HDRLEN` — the kernel's minimum acceptable frame size: an aligned
/// frame header plus the `sockaddr_ll` it stores after it.
const fn tpacket3_hdrlen() -> usize {
    tpacket_align(std::mem::size_of::<Tpacket3Hdr>()) + std::mem::size_of::<libc::sockaddr_ll>()
}

// ── Ring geometry ─────────────────────────────────────────────────────────────

/// Validated ring dimensions, in the form the kernel wants them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Geometry {
    block_size: usize,
    block_count: usize,
    frame_size: usize,
    frame_count: usize,
    /// Bytes to map: `block_size × block_count`, checked for overflow.
    map_len: usize,
}

/// Smallest frame size we ask for, regardless of snaplen: the kernel only uses
/// `tp_frame_size` to derive `tp_frame_nr`, and a floor here keeps that count
/// in a sane range for small snaplens.
const MIN_FRAME_SIZE: usize = 2048;

/// Translate a [`RingConfig`] plus the capture snaplen into kernel-acceptable
/// ring dimensions.
///
/// The kernel requires: a page-aligned block size, a 16-byte-aligned frame size
/// of at least `TPACKET3_HDRLEN`, at least one frame per block, and a frame
/// count that exactly equals `frames_per_block × block_count` — a mismatch is
/// rejected with `EINVAL`. Undersized values are rounded up rather than
/// rejected; only genuinely unusable ones (zero blocks, or a ring too large to
/// address) are errors.
fn ring_geometry(cfg: &RingConfig, snaplen: usize, page_size: usize) -> Result<Geometry> {
    if cfg.block_count == 0 {
        return Err(Error::Platform(
            "ring block_count must be at least 1".into(),
        ));
    }
    if cfg.block_size == 0 {
        return Err(Error::Platform("ring block_size must be non-zero".into()));
    }

    // One frame must hold the captured bytes plus the frame header.
    let frame_size = tpacket_align(snaplen.saturating_add(tpacket3_hdrlen())).max(MIN_FRAME_SIZE);

    // Blocks are page-aligned and hold at least one whole frame.
    let block_size = round_up(cfg.block_size.max(frame_size), page_size);

    let frames_per_block = block_size / frame_size;
    let frame_count = frames_per_block
        .checked_mul(cfg.block_count)
        .ok_or_else(|| Error::Platform("ring frame count overflows".into()))?;

    // The kernel takes these as u32 and maps block_size × block_count bytes.
    let map_len = block_size
        .checked_mul(cfg.block_count)
        .ok_or_else(|| Error::Platform("ring size overflows".into()))?;
    if u32::try_from(block_size).is_err()
        || u32::try_from(cfg.block_count).is_err()
        || u32::try_from(frame_count).is_err()
    {
        return Err(Error::Platform(format!(
            "ring geometry too large: {} blocks of {block_size} bytes",
            cfg.block_count
        )));
    }

    Ok(Geometry {
        block_size,
        block_count: cfg.block_count,
        frame_size,
        frame_count,
        map_len,
    })
}

fn round_up(n: usize, multiple: usize) -> usize {
    debug_assert!(multiple > 0);
    n.div_ceil(multiple) * multiple
}

fn page_size() -> usize {
    // `_SC_PAGESIZE` is always available and positive on Linux; fall back to
    // the x86-64 default if the query somehow fails.
    let n = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if n > 0 {
        n as usize
    } else {
        4096
    }
}

// ── Frame walking (pure) ──────────────────────────────────────────────────────

/// Copy index metadata for one frame: where its bytes live plus the timestamp
/// and on-wire length. Returned instead of a borrow so the `PacketRef` slice is
/// constructed only at the single success-path return (see ADR 0002).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FrameMeta {
    /// Offset of the packet bytes, relative to the start of the block.
    offset: usize,
    /// Number of bytes available at `offset`, already clamped to snaplen.
    len: usize,
    ts_sec: u64,
    ts_nsec: u32,
    orig_len: u32,
}

/// Read the block descriptor at the start of `block`.
///
/// Returns `None` if the slice is too short to hold one, which can only happen
/// if the geometry and the mapping disagree.
fn parse_block_desc(block: &[u8]) -> Option<TpacketBlockDesc> {
    if block.len() < std::mem::size_of::<TpacketBlockDesc>() {
        return None;
    }
    // SAFETY: the length check above guarantees the read stays in bounds, and
    // `read_unaligned` makes no alignment assumption about the mapping.
    Some(unsafe { std::ptr::read_unaligned(block.as_ptr() as *const TpacketBlockDesc) })
}

/// Parse the frame header at `offset` within `block`.
///
/// Returns the frame's index metadata and the offset of the next frame, which
/// is `None` for the last frame in the block (`tp_next_offset == 0`). Yields
/// `None` when the header or its payload would run past the end of the block —
/// a malformed block, which the caller handles by releasing it.
///
/// Pure and side-effect-free so the walk can be exercised against a synthetic
/// block in unit tests.
fn parse_frame(block: &[u8], offset: usize, snaplen: usize) -> Option<(FrameMeta, Option<usize>)> {
    let hdr_size = std::mem::size_of::<Tpacket3Hdr>();
    if offset.checked_add(hdr_size)? > block.len() {
        return None;
    }
    // SAFETY: `offset + hdr_size` is within `block` per the check above;
    // `read_unaligned` makes no alignment assumption about the mapping.
    let hdr = unsafe { std::ptr::read_unaligned(block.as_ptr().add(offset) as *const Tpacket3Hdr) };

    let data_start = offset.checked_add(hdr.tp_mac as usize)?;
    let stored = hdr.tp_snaplen as usize;
    if data_start.checked_add(stored)? > block.len() {
        return None;
    }

    let next = match hdr.tp_next_offset {
        0 => None,
        n => Some(offset.checked_add(n as usize)?),
    };

    Some((
        FrameMeta {
            offset: data_start,
            // The kernel sizes frames from the on-wire packet, so apply the
            // requested snaplen here — matching the `recvmsg` path.
            len: stored.min(snaplen),
            ts_sec: hdr.tp_sec as u64,
            ts_nsec: hdr.tp_nsec,
            orig_len: hdr.tp_len,
        },
        next,
    ))
}

// ── Ring ──────────────────────────────────────────────────────────────────────

/// Position within the block we currently own.
#[derive(Debug, Clone, Copy)]
struct Walk {
    /// Offset of the next frame header, relative to the block.
    offset: usize,
    /// Frames left to read in this block.
    remaining: u32,
}

/// A mapped `TPACKET_V3` receive ring.
///
/// Owns the mapping: [`Drop`] unmaps it. The socket it was set up on is owned
/// by the enclosing [`LinuxLive`](super::linux::LinuxLive), which passes the
/// raw fd back in for `poll()`.
pub(super) struct Ring {
    /// Base of the mapping — `map_len` bytes, exclusively owned by this `Ring`.
    map: *mut u8,
    map_len: usize,
    geom: Geometry,
    /// Block the kernel will hand over next; blocks are consumed in order.
    cur_block: usize,
    /// Walk state for the block we own, `None` while it is with the kernel.
    walk: Option<Walk>,
    snaplen: usize,
    /// Set via `set_nonblocking`, which takes `&self` — hence the interior
    /// mutability. `O_NONBLOCK` has no effect on ring reads, so this flag is
    /// what decides whether an empty ring blocks in `poll()` or returns
    /// `Ok(None)`.
    nonblocking: AtomicBool,
}

// SAFETY: `map` points to a mapping this `Ring` exclusively owns and unmaps on
// drop; nothing in it is tied to the thread that created it. A `Capture` (which
// may hold a `Ring`) is moved between threads by design — one member socket of
// a `FanoutGroup` per worker thread.
unsafe impl Send for Ring {}

// SAFETY: every `&self` method is safe to call concurrently — the block status
// word is read and written atomically (the kernel writes it concurrently
// regardless), `set_nonblocking` goes through an atomic, and block bytes are
// only ever handed out as shared slices. Reading packets takes `&mut self`, so
// the walk state is never shared. This keeps `Capture` `Sync`, as it is on
// every other capture backend.
unsafe impl Sync for Ring {}

impl Ring {
    /// Configure `fd` for `TPACKET_V3`, allocate the ring, and map it.
    ///
    /// Call before `bind()`, so no packet is queued on the socket before the
    /// ring exists to receive it.
    pub(super) fn open(fd: RawFd, cfg: &RingConfig, snaplen: usize) -> Result<Self> {
        let version: libc::c_int = TPACKET_V3;
        let rc = unsafe {
            libc::setsockopt(
                fd,
                super::linux::SOL_PACKET,
                super::linux::PACKET_VERSION,
                &version as *const libc::c_int as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            let e = std::io::Error::last_os_error();
            return Err(Error::Platform(format!(
                "TPACKET_V3 ring capture is unavailable on this kernel (requires Linux 3.2+): {e}"
            )));
        }

        let geom = ring_geometry(cfg, snaplen, page_size())?;
        let req = TpacketReq3 {
            tp_block_size: geom.block_size as libc::c_uint,
            tp_block_nr: geom.block_count as libc::c_uint,
            tp_frame_size: geom.frame_size as libc::c_uint,
            tp_frame_nr: geom.frame_count as libc::c_uint,
            tp_retire_blk_tov: retire_tov_ms(cfg),
            tp_sizeof_priv: 0,
            tp_feature_req_word: 0,
        };
        let rc = unsafe {
            libc::setsockopt(
                fd,
                super::linux::SOL_PACKET,
                PACKET_RX_RING,
                &req as *const TpacketReq3 as *const libc::c_void,
                std::mem::size_of::<TpacketReq3>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            let e = std::io::Error::last_os_error();
            return Err(Error::Platform(format!(
                "failed to allocate a {}×{} byte TPACKET_V3 ring: {e}",
                geom.block_count, geom.block_size
            )));
        }

        let map = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                geom.map_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        if map == libc::MAP_FAILED {
            return Err(super::io_err());
        }

        Ok(Self {
            map: map as *mut u8,
            map_len: geom.map_len,
            geom,
            cur_block: 0,
            walk: None,
            snaplen,
            nonblocking: AtomicBool::new(false),
        })
    }

    /// Choose between blocking in `poll()` and returning `Ok(None)` when the
    /// ring is empty.
    pub(super) fn set_nonblocking(&self, nb: bool) {
        self.nonblocking.store(nb, Ordering::Relaxed);
    }

    /// Return the next frame in the ring, blocking in `poll()` until one
    /// arrives unless non-blocking mode is set.
    pub(super) fn next_packet(
        &mut self,
        fd: RawFd,
        link_type: LinkType,
    ) -> Result<Option<PacketRef<'_>>> {
        // `next_frame` returns Copy metadata rather than a borrow, so the
        // borrowed slice is created once, here, and never on a retry path —
        // which is what keeps this lending iterator in safe borrow-check
        // territory (ADR 0002).
        let Some(meta) = self.next_frame(fd)? else {
            return Ok(None);
        };
        // SAFETY: `meta.offset .. meta.offset + meta.len` was bounds-checked
        // against the current block by `parse_frame`, and the block lies within
        // the mapping. We hold the block (the kernel does not write to a block
        // marked TP_STATUS_USER until we release it), and the returned borrow
        // ends at the next `&mut self` call — which is the earliest point the
        // block can be released.
        let data = unsafe { std::slice::from_raw_parts(self.map.add(meta.offset), meta.len) };
        Ok(Some(PacketRef::new(
            data,
            meta.ts_sec,
            meta.ts_nsec,
            meta.orig_len,
            link_type,
        )))
    }

    /// Advance the ring to the next frame, returning its metadata with
    /// `offset` made absolute within the mapping.
    ///
    /// Releases exhausted or malformed blocks back to the kernel and waits for
    /// the next one; returns `Ok(None)` only in non-blocking mode with nothing
    /// ready.
    fn next_frame(&mut self, fd: RawFd) -> Result<Option<FrameMeta>> {
        loop {
            let Some(walk) = self.walk else {
                // No block in hand: take the next one if the kernel has
                // finished with it.
                if self.block_status(self.cur_block) & TP_STATUS_USER == 0 {
                    if self.nonblocking.load(Ordering::Relaxed) {
                        return Ok(None);
                    }
                    self.wait(fd)?;
                    continue;
                }
                let block = self.block(self.cur_block);
                let (offset, remaining) = match parse_block_desc(block) {
                    Some(desc) => (desc.hdr.offset_to_first_pkt as usize, desc.hdr.num_pkts),
                    // Unreadable descriptor: hand the block back rather than
                    // stalling the ring on it.
                    None => (0, 0),
                };
                self.walk = Some(Walk { offset, remaining });
                continue;
            };

            if walk.remaining == 0 {
                // Every frame read (or an empty block the kernel retired on
                // timeout): give it back and move to the next one.
                self.release_block();
                continue;
            }

            let block_start = self.cur_block * self.geom.block_size;
            let block = self.block(self.cur_block);
            let Some((meta, next)) = parse_frame(block, walk.offset, self.snaplen) else {
                // Malformed block — nothing more can be trusted in it.
                self.release_block();
                continue;
            };

            self.walk = match next {
                // `tp_next_offset == 0` marks the last frame regardless of what
                // `num_pkts` claimed, so stop the walk either way.
                Some(offset) if walk.remaining > 1 => Some(Walk {
                    offset,
                    remaining: walk.remaining - 1,
                }),
                _ => Some(Walk {
                    offset: 0,
                    remaining: 0,
                }),
            };

            return Ok(Some(FrameMeta {
                offset: block_start + meta.offset,
                ..meta
            }));
        }
    }

    /// Bytes of block `i`.
    fn block(&self, i: usize) -> &[u8] {
        // SAFETY: `i < block_count`, so the block lies wholly within the
        // mapping. The kernel only writes to blocks it owns; the caller either
        // holds this block (TP_STATUS_USER) or is reading only the descriptor
        // it just observed as handed over.
        unsafe {
            std::slice::from_raw_parts(self.map.add(i * self.geom.block_size), self.geom.block_size)
        }
    }

    /// Read block `i`'s status word, synchronising with the kernel's write.
    fn block_status(&self, i: usize) -> u32 {
        self.status_word(i).load(Ordering::Acquire)
    }

    /// Hand the current block back to the kernel and move to the next one.
    fn release_block(&mut self) {
        // Release ordering: every read of the block's frames happens-before the
        // kernel sees it as free and starts overwriting them.
        self.status_word(self.cur_block)
            .store(TP_STATUS_KERNEL, Ordering::Release);
        self.cur_block = (self.cur_block + 1) % self.geom.block_count;
        self.walk = None;
    }

    /// The `block_status` field of block `i`, as an atomic.
    ///
    /// The kernel writes this word while we hold the mapping, so it is only
    /// ever accessed through atomic loads and stores.
    fn status_word(&self, i: usize) -> &AtomicU32 {
        debug_assert!(i < self.geom.block_count);
        // SAFETY: blocks are page-aligned within the mapping, so the field is
        // 4-byte aligned and in bounds. `AtomicU32` has the same layout as
        // `u32`, and the reference never outlives the mapping.
        unsafe {
            &*(self.map.add(i * self.geom.block_size + BLOCK_STATUS_OFFSET) as *const AtomicU32)
        }
    }

    /// Block until the kernel signals that a block is ready.
    ///
    /// `EINTR` returns `Ok(())`; the caller re-checks the block status and
    /// waits again if needed.
    fn wait(&self, fd: RawFd) -> Result<()> {
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let rc = unsafe { libc::poll(&mut pfd, 1, -1) };
        if rc < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                return Ok(());
            }
            return Err(e.into());
        }
        Ok(())
    }
}

impl Drop for Ring {
    fn drop(&mut self) {
        // SAFETY: `map`/`map_len` are exactly what `mmap` returned (or, in
        // tests, an anonymous mapping of the same size), and this is the only
        // owner.
        unsafe { libc::munmap(self.map as *mut libc::c_void, self.map_len) };
    }
}

/// Convert the configured retire timeout to the kernel's milliseconds.
///
/// Zero is passed through — the kernel reads it as "pick a default from the
/// link speed" — but any non-zero duration rounds up to at least 1 ms so a
/// sub-millisecond request is not silently turned into that default.
fn retire_tov_ms(cfg: &RingConfig) -> libc::c_uint {
    let ms = cfg.retire_timeout.as_millis();
    if ms == 0 {
        if cfg.retire_timeout.is_zero() {
            return 0;
        }
        return 1;
    }
    ms.min(u32::MAX as u128) as libc::c_uint
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── ABI layout ────────────────────────────────────────────────────────────

    /// The kernel writes these structs into the mapping, so their sizes and
    /// field offsets are not ours to change.
    #[test]
    fn block_desc_layout_matches_kernel() {
        assert_eq!(std::mem::size_of::<TpacketBlockDesc>(), 48);
        let desc = TpacketBlockDesc {
            version: 0,
            offset_to_priv: 0,
            hdr: TpacketHdrV1 {
                block_status: 0,
                num_pkts: 0,
                offset_to_first_pkt: 0,
                blk_len: 0,
                seq_num: 0,
                ts_first_pkt: TpacketBdTs {
                    ts_sec: 0,
                    ts_frac: 0,
                },
                ts_last_pkt: TpacketBdTs {
                    ts_sec: 0,
                    ts_frac: 0,
                },
            },
        };
        let base = &desc as *const _ as usize;
        assert_eq!(
            &desc.hdr.block_status as *const _ as usize - base,
            BLOCK_STATUS_OFFSET,
        );
        assert_eq!(&desc.hdr.num_pkts as *const _ as usize - base, 12);
        assert_eq!(
            &desc.hdr.offset_to_first_pkt as *const _ as usize - base,
            16,
        );
    }

    #[test]
    fn frame_header_layout_matches_kernel() {
        assert_eq!(std::mem::size_of::<Tpacket3Hdr>(), 48);
        // TPACKET3_HDRLEN = TPACKET_ALIGN(sizeof(tpacket3_hdr)) + sizeof(sockaddr_ll)
        assert_eq!(tpacket3_hdrlen(), 48 + 20);
    }

    #[test]
    fn tpacket_req3_is_seven_u32s() {
        assert_eq!(std::mem::size_of::<TpacketReq3>(), 7 * 4);
    }

    // ── Geometry ──────────────────────────────────────────────────────────────

    #[test]
    fn default_geometry_satisfies_kernel_constraints() {
        let geom = ring_geometry(&RingConfig::new(), 65535, 4096).expect("geometry");
        assert_eq!(geom.block_size % 4096, 0, "block size must be page-aligned");
        assert_eq!(geom.frame_size % TPACKET_ALIGNMENT, 0);
        assert!(geom.frame_size >= tpacket3_hdrlen());
        // The kernel rejects a frame count that isn't exactly
        // frames_per_block × block_count.
        assert_eq!(
            geom.frame_count,
            (geom.block_size / geom.frame_size) * geom.block_count,
        );
        assert!(
            geom.block_size >= geom.frame_size,
            "a frame must fit a block"
        );
        assert_eq!(
            geom.map_len,
            geom.block_size * geom.block_count,
            "map_len must cover the whole ring"
        );
    }

    #[test]
    fn block_size_rounds_up_to_a_page_multiple() {
        let cfg = RingConfig::new().block_size(5000);
        let geom = ring_geometry(&cfg, 128, 4096).expect("geometry");
        assert_eq!(geom.block_size, 8192);
    }

    #[test]
    fn block_size_grows_to_fit_one_frame() {
        // A 4 KiB block cannot hold a 65535-byte frame; the block must grow.
        let cfg = RingConfig::new().block_size(4096);
        let geom = ring_geometry(&cfg, 65535, 4096).expect("geometry");
        assert!(geom.block_size >= geom.frame_size);
        assert_eq!(geom.block_size % 4096, 0);
        assert!(geom.frame_count >= geom.block_count);
    }

    #[test]
    fn small_snaplen_still_gets_a_usable_frame_size() {
        let geom = ring_geometry(&RingConfig::new(), 64, 4096).expect("geometry");
        assert_eq!(geom.frame_size, MIN_FRAME_SIZE);
    }

    #[test]
    fn zero_block_count_is_rejected() {
        let cfg = RingConfig::new().block_count(0);
        assert!(ring_geometry(&cfg, 1500, 4096).is_err());
    }

    #[test]
    fn zero_block_size_is_rejected() {
        let cfg = RingConfig::new().block_size(0);
        assert!(ring_geometry(&cfg, 1500, 4096).is_err());
    }

    #[test]
    fn oversized_ring_is_rejected_not_wrapped() {
        let cfg = RingConfig::new().block_size(1 << 30).block_count(1 << 24);
        assert!(ring_geometry(&cfg, 1500, 4096).is_err());
    }

    #[test]
    fn retire_timeout_rounds_up_to_one_millisecond() {
        use std::time::Duration;
        let sub_ms = RingConfig::new().retire_timeout(Duration::from_micros(200));
        assert_eq!(retire_tov_ms(&sub_ms), 1);
        // Zero means "kernel default", and must not be rounded away.
        let zero = RingConfig::new().retire_timeout(Duration::ZERO);
        assert_eq!(retire_tov_ms(&zero), 0);
        let ms = RingConfig::new().retire_timeout(Duration::from_millis(25));
        assert_eq!(retire_tov_ms(&ms), 25);
    }

    // ── Synthetic ring construction ───────────────────────────────────────────

    /// One frame to lay into a synthetic block.
    struct FrameSpec {
        ts_sec: u32,
        ts_nsec: u32,
        /// On-wire length, which may exceed `payload.len()`.
        orig_len: u32,
        payload: Vec<u8>,
    }

    fn frame(ts_sec: u32, orig_len: u32, payload: &[u8]) -> FrameSpec {
        FrameSpec {
            ts_sec,
            ts_nsec: 500,
            orig_len,
            payload: payload.to_vec(),
        }
    }

    /// Serialise a block exactly as the kernel lays one out: a 48-byte
    /// descriptor followed by `tpacket3_hdr` + payload pairs chained through
    /// `tp_next_offset`, with the last frame's `tp_next_offset` left at 0.
    fn build_block(block_size: usize, status: u32, frames: &[FrameSpec]) -> Vec<u8> {
        let hdr_size = std::mem::size_of::<Tpacket3Hdr>();
        let desc_size = std::mem::size_of::<TpacketBlockDesc>();
        let mut block = vec![0u8; block_size];

        let mut offsets = Vec::new();
        let mut pos = desc_size;
        for f in frames {
            offsets.push(pos);
            pos = tpacket_align(pos + hdr_size + f.payload.len());
        }

        for (i, f) in frames.iter().enumerate() {
            let at = offsets[i];
            let next = if i + 1 < frames.len() {
                (offsets[i + 1] - at) as u32
            } else {
                0
            };
            let hdr = Tpacket3Hdr {
                tp_next_offset: next,
                tp_sec: f.ts_sec,
                tp_nsec: f.ts_nsec,
                tp_snaplen: f.payload.len() as u32,
                tp_len: f.orig_len,
                tp_status: TP_STATUS_USER,
                tp_mac: hdr_size as u16,
                tp_net: hdr_size as u16,
                hv1_rxhash: 0,
                hv1_vlan_tci: 0,
                hv1_vlan_tpid: 0,
                hv1_padding: 0,
                tp_padding: [0; 8],
            };
            unsafe {
                std::ptr::copy_nonoverlapping(
                    &hdr as *const Tpacket3Hdr as *const u8,
                    block.as_mut_ptr().add(at),
                    hdr_size,
                );
            }
            block[at + hdr_size..at + hdr_size + f.payload.len()].copy_from_slice(&f.payload);
        }

        let desc = TpacketBlockDesc {
            version: TPACKET_V3 as u32,
            offset_to_priv: 0,
            hdr: TpacketHdrV1 {
                block_status: status,
                num_pkts: frames.len() as u32,
                offset_to_first_pkt: desc_size as u32,
                blk_len: pos as u32,
                seq_num: 1,
                ts_first_pkt: TpacketBdTs {
                    ts_sec: 0,
                    ts_frac: 0,
                },
                ts_last_pkt: TpacketBdTs {
                    ts_sec: 0,
                    ts_frac: 0,
                },
            },
        };
        unsafe {
            std::ptr::copy_nonoverlapping(
                &desc as *const TpacketBlockDesc as *const u8,
                block.as_mut_ptr(),
                desc_size,
            );
        }
        block
    }

    /// A `Ring` over an anonymous mapping holding `blocks`, in non-blocking
    /// mode so an empty ring returns `Ok(None)` instead of polling a socket.
    ///
    /// The mapping is a real `mmap`, so `Ring`'s `munmap` on drop is valid.
    fn fake_ring(block_size: usize, blocks: &[Vec<u8>], snaplen: usize) -> Ring {
        let map_len = block_size * blocks.len();
        let map = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                map_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(map, libc::MAP_FAILED, "test mmap failed");
        for (i, b) in blocks.iter().enumerate() {
            assert_eq!(b.len(), block_size);
            unsafe {
                std::ptr::copy_nonoverlapping(
                    b.as_ptr(),
                    (map as *mut u8).add(i * block_size),
                    block_size,
                );
            }
        }
        Ring {
            map: map as *mut u8,
            map_len,
            geom: Geometry {
                block_size,
                block_count: blocks.len(),
                frame_size: MIN_FRAME_SIZE,
                frame_count: blocks.len(),
                map_len,
            },
            cur_block: 0,
            walk: None,
            snaplen,
            nonblocking: AtomicBool::new(true),
        }
    }

    /// Drain every packet currently readable from the ring.
    fn drain(ring: &mut Ring) -> Vec<(Vec<u8>, u64, u32)> {
        let mut out = Vec::new();
        while let Some(pkt) = ring.next_packet(-1, LinkType::Ethernet).expect("next") {
            out.push((
                pkt.data().to_vec(),
                pkt.timestamp()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                pkt.orig_len(),
            ));
        }
        out
    }

    // ── Frame walking ─────────────────────────────────────────────────────────

    #[test]
    fn parses_a_single_frame() {
        let hdr_size = std::mem::size_of::<Tpacket3Hdr>();
        let desc_size = std::mem::size_of::<TpacketBlockDesc>();
        let block = build_block(
            4096,
            TP_STATUS_USER,
            &[frame(1234, 60, &[0xaa, 0xbb, 0xcc])],
        );

        let (meta, next) = parse_frame(&block, desc_size, 65535).expect("frame");
        assert_eq!(meta.offset, desc_size + hdr_size);
        assert_eq!(meta.len, 3);
        assert_eq!(
            &block[meta.offset..meta.offset + meta.len],
            &[0xaa, 0xbb, 0xcc]
        );
        assert_eq!(meta.ts_sec, 1234);
        assert_eq!(meta.ts_nsec, 500);
        assert_eq!(meta.orig_len, 60);
        // Only frame in the block, so no chain to follow.
        assert_eq!(next, None);
    }

    #[test]
    fn walks_the_frame_chain() {
        let desc_size = std::mem::size_of::<TpacketBlockDesc>();
        let block = build_block(
            4096,
            TP_STATUS_USER,
            &[frame(10, 3, &[1, 2, 3]), frame(20, 5, &[9, 8, 7, 6, 5])],
        );

        let (first, next) = parse_frame(&block, desc_size, 65535).expect("frame 1");
        assert_eq!(&block[first.offset..first.offset + first.len], &[1, 2, 3]);
        let (second, tail) = parse_frame(&block, next.expect("chained"), 65535).expect("frame 2");
        assert_eq!(
            &block[second.offset..second.offset + second.len],
            &[9, 8, 7, 6, 5],
        );
        assert_eq!(second.ts_sec, 20);
        assert_eq!(tail, None);
    }

    #[test]
    fn snaplen_clamps_the_captured_range() {
        let desc_size = std::mem::size_of::<TpacketBlockDesc>();
        let block = build_block(4096, TP_STATUS_USER, &[frame(0, 1500, &[0xff; 200])]);
        let (meta, _) = parse_frame(&block, desc_size, 64).expect("frame");
        assert_eq!(meta.len, 64, "captured bytes clamp to snaplen");
        assert_eq!(meta.orig_len, 1500, "on-wire length is unaffected");
    }

    #[test]
    fn frame_header_past_the_block_is_rejected() {
        let block = build_block(4096, TP_STATUS_USER, &[frame(0, 3, &[1, 2, 3])]);
        assert!(parse_frame(&block, 4090, 65535).is_none());
        assert!(parse_frame(&block, usize::MAX - 8, 65535).is_none());
    }

    #[test]
    fn payload_past_the_block_is_rejected() {
        let desc_size = std::mem::size_of::<TpacketBlockDesc>();
        let mut block = build_block(4096, TP_STATUS_USER, &[frame(0, 3, &[1, 2, 3])]);
        // Claim a snaplen that runs off the end of the block.
        let snaplen_at = desc_size + 12;
        block[snaplen_at..snaplen_at + 4].copy_from_slice(&u32::MAX.to_ne_bytes());
        assert!(parse_frame(&block, desc_size, 65535).is_none());
    }

    #[test]
    fn undersized_block_has_no_descriptor() {
        assert!(parse_block_desc(&[0u8; 16]).is_none());
        let block = build_block(4096, TP_STATUS_USER, &[]);
        let desc = parse_block_desc(&block).expect("descriptor");
        assert_eq!(desc.hdr.num_pkts, 0);
        assert_eq!(desc.hdr.block_status, TP_STATUS_USER);
    }

    // ── Ring state machine ────────────────────────────────────────────────────

    #[test]
    fn reads_every_frame_in_a_block_then_releases_it() {
        let block_size = 4096;
        let blocks = vec![build_block(
            block_size,
            TP_STATUS_USER,
            &[frame(1, 3, &[1, 2, 3]), frame(2, 4, &[4, 5, 6, 7])],
        )];
        let mut ring = fake_ring(block_size, &blocks, 65535);

        let got = drain(&mut ring);
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].0, vec![1, 2, 3]);
        assert_eq!(got[0].1, 1);
        assert_eq!(got[1].0, vec![4, 5, 6, 7]);
        assert_eq!(got[1].2, 4);
        // The exhausted block went back to the kernel.
        assert_eq!(ring.block_status(0), TP_STATUS_KERNEL);
    }

    #[test]
    fn walks_blocks_in_order_and_wraps() {
        let block_size = 4096;
        let blocks = vec![
            build_block(block_size, TP_STATUS_USER, &[frame(1, 1, &[0x11])]),
            build_block(block_size, TP_STATUS_USER, &[frame(2, 1, &[0x22])]),
            build_block(block_size, TP_STATUS_USER, &[frame(3, 1, &[0x33])]),
        ];
        let mut ring = fake_ring(block_size, &blocks, 65535);

        let got = drain(&mut ring);
        assert_eq!(
            got.iter().map(|(d, _, _)| d[0]).collect::<Vec<_>>(),
            vec![0x11, 0x22, 0x33],
        );
        // All three released, and the cursor wrapped back to the start.
        for i in 0..3 {
            assert_eq!(ring.block_status(i), TP_STATUS_KERNEL);
        }
        assert_eq!(ring.cur_block, 0);
    }

    #[test]
    fn empty_ring_returns_none_when_nonblocking() {
        let block_size = 4096;
        // TP_STATUS_KERNEL: the kernel still owns every block.
        let blocks = vec![build_block(block_size, TP_STATUS_KERNEL, &[])];
        let mut ring = fake_ring(block_size, &blocks, 65535);
        assert!(ring
            .next_packet(-1, LinkType::Ethernet)
            .expect("next")
            .is_none());
        // Still not released — it was never ours.
        assert_eq!(ring.block_status(0), TP_STATUS_KERNEL);
    }

    #[test]
    fn retired_empty_block_is_skipped_not_stalled_on() {
        let block_size = 4096;
        let blocks = vec![
            // A block the kernel retired on timeout with nothing in it.
            build_block(block_size, TP_STATUS_USER, &[]),
            build_block(block_size, TP_STATUS_USER, &[frame(7, 2, &[0xde, 0xad])]),
        ];
        let mut ring = fake_ring(block_size, &blocks, 65535);

        let got = drain(&mut ring);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].0, vec![0xde, 0xad]);
        assert_eq!(ring.block_status(0), TP_STATUS_KERNEL);
    }

    #[test]
    fn stops_at_the_end_of_the_chain_even_if_num_pkts_overcounts() {
        let block_size = 4096;
        let desc_size = std::mem::size_of::<TpacketBlockDesc>();
        // A block claiming more frames than it chains: the last frame's
        // tp_next_offset of 0 must end the walk, not send it into padding.
        let mut block = build_block(block_size, TP_STATUS_USER, &[frame(1, 2, &[0xaa, 0xbb])]);
        block[12..16].copy_from_slice(&9u32.to_ne_bytes()); // num_pkts = 9
        assert_eq!(parse_block_desc(&block).unwrap().hdr.num_pkts, 9);
        assert_eq!(
            parse_block_desc(&block).unwrap().hdr.offset_to_first_pkt as usize,
            desc_size,
        );

        let mut ring = fake_ring(block_size, &[block], 65535);
        let got = drain(&mut ring);
        assert_eq!(got.len(), 1, "walk stops at tp_next_offset == 0");
        assert_eq!(ring.block_status(0), TP_STATUS_KERNEL);
    }

    #[test]
    fn malformed_block_is_released_rather_than_looping() {
        let block_size = 4096;
        let mut block = build_block(block_size, TP_STATUS_USER, &[frame(1, 2, &[0xaa, 0xbb])]);
        // Point the first frame past the end of the block.
        block[16..20].copy_from_slice(&(block_size as u32 - 4).to_ne_bytes());
        let mut ring = fake_ring(block_size, &[block], 65535);

        assert!(ring
            .next_packet(-1, LinkType::Ethernet)
            .expect("next")
            .is_none());
        assert_eq!(ring.block_status(0), TP_STATUS_KERNEL);
    }

    #[test]
    fn nonblocking_flag_round_trips() {
        let block_size = 4096;
        let blocks = vec![build_block(block_size, TP_STATUS_KERNEL, &[])];
        let ring = fake_ring(block_size, &blocks, 65535);
        assert!(ring.nonblocking.load(Ordering::Relaxed));
        ring.set_nonblocking(false);
        assert!(!ring.nonblocking.load(Ordering::Relaxed));
        ring.set_nonblocking(true);
        assert!(ring.nonblocking.load(Ordering::Relaxed));
    }
}
