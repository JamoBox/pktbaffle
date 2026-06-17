//! Regression test for issue #85: file capture must not allocate per packet.
//!
//! A counting global allocator records every `alloc` call. We read a long run
//! of packets through `Capture` (without `to_owned`, the explicit allocation
//! opt-in) and assert that the allocation count does **not** scale with the
//! number of packets — i.e. the per-packet `.to_vec()` is gone and the scratch
//! buffer is reused.
//!
//! This lives in its own integration-test binary so the global allocator and
//! the alloc-count snapshots are not perturbed by other tests running in the
//! same process.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

mod common;

use pkttap::Capture;

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

/// Read `n` packets from `path`, touching each one's bytes so the read is not
/// optimized away, and return how many allocations occurred during the loop.
fn allocs_reading(path: &std::path::Path, n: usize) -> usize {
    let mut cap = Capture::from_file(path).open().unwrap();

    // Warm-up: the first packet grows the scratch buffer to its steady-state
    // size. Allocations here are one-time, not per-packet, so exclude them.
    let mut sink = 0u64;
    if let Some(pkt) = cap.next().unwrap() {
        sink = sink.wrapping_add(pkt.data().len() as u64);
    }

    let before = ALLOCS.load(Ordering::Relaxed);
    let mut read = 0usize;
    while read < n {
        match cap.next().unwrap() {
            Some(pkt) => {
                // Borrow only — no to_owned(), so no intentional allocation.
                sink = sink.wrapping_add(pkt.data()[0] as u64);
                read += 1;
            }
            None => break,
        }
    }
    let after = ALLOCS.load(Ordering::Relaxed);

    // Keep `sink` observable so the optimizer cannot elide the reads.
    assert!(sink != u64::MAX, "unreachable; keeps reads live");
    after - before
}

#[test]
fn file_capture_does_not_allocate_per_packet() {
    // A file with many identical packets; the reader cycles its buffer for each.
    let frame = common::tcp_frame(80);
    let refs: Vec<&[u8]> = std::iter::repeat(frame.as_slice()).take(2000).collect();
    let tmp = common::temp_file(&common::pcap_bytes(1, &refs));

    let short = allocs_reading(tmp.path(), 100);
    let long = allocs_reading(tmp.path(), 1000);

    // If capture allocated once per packet, `long` would exceed `short` by
    // ~900 (the extra packets). A reused scratch buffer keeps the delta flat.
    // Allow generous slack for incidental allocations (e.g. error paths), but
    // far below the ~900 a per-packet allocation would add.
    let delta = long.saturating_sub(short);
    assert!(
        delta < 100,
        "allocations scale with packet count (short={short}, long={long}, delta={delta}); \
         per-packet allocation likely reintroduced"
    );
}
