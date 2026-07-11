//! Regression test for issue #95: pcapng write_packet must not allocate per packet.
//!
//! A counting global allocator records every `alloc` call. We write a run of
//! packets through `Dump` in pcapng mode and assert the allocation count does
//! not scale with the number of packets — i.e. the per-packet `options` field
//! uses `Vec::new()` (zero-allocation) and the pcap-file write path introduces
//! no per-packet heap allocation.
//!
//! This lives in its own integration-test binary so the global allocator is not
//! shared with other test binaries (only one `#[global_allocator]` is allowed
//! per binary).

mod common;

use pkttap::{Dump, LinkType};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

struct CountingAlloc;

static ALLOCS: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        System.alloc(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }
}

#[global_allocator]
static GLOBAL: CountingAlloc = CountingAlloc;

/// Write `n` packets to a fresh pcapng file (after a warm-up write to settle
/// any one-time setup allocations), and return how many allocations occurred
/// during the measured write loop.
fn allocs_writing_pcapng(n: usize) -> usize {
    let frame = common::tcp_frame(80);
    let src_pkts = common::read_all(
        &common::temp_file(&common::pcap_bytes(1, &[frame.as_slice()])).into_temp_path(),
    );
    let pkt = &src_pkts[0];

    let out = tempfile::Builder::new()
        .suffix(".pcapng")
        .tempfile()
        .unwrap();
    let mut dump = Dump::to_file(out.path())
        .link_type(LinkType::Ethernet)
        .open()
        .unwrap();

    // Warm-up: the first write absorbs any one-time allocation (e.g. the
    // PcapNgWriter's internal interface list growing from 0 to 1 entry).
    dump.write_packet(pkt.as_ref()).unwrap();

    let before = ALLOCS.load(Ordering::Relaxed);
    for _ in 0..n {
        dump.write_packet(pkt.as_ref()).unwrap();
    }
    let after = ALLOCS.load(Ordering::Relaxed);
    after - before
}

#[test]
fn pcapng_dump_does_not_allocate_per_packet() {
    let short = allocs_writing_pcapng(100);
    let long = allocs_writing_pcapng(1000);

    // If write_packet allocated once per packet (e.g. via `vec![]` that
    // materialised a heap object), `long` would exceed `short` by ~900 (the
    // extra 900 packets). With `Vec::new()` the hot path is allocation-free, so
    // the delta should be near zero. A generous slack of 100 guards against
    // incidental allocations without masking a true per-packet regression.
    let delta = long.saturating_sub(short);
    assert!(
        delta < 100,
        "allocations scale with packet count \
         (short={short}, long={long}, delta={delta}); \
         per-packet allocation likely reintroduced in pcapng write_packet"
    );
}
