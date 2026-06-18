//! Tests for `Capture::stats()` and `CaptureStats` (issue #87).
//!
//! Live-capture statistics require a real network interface and elevated
//! privileges, so those paths are not tested in CI. We cover:
//!   - `CaptureStats` struct properties (Default, Clone, Copy, PartialEq, Debug)
//!   - File-based `Capture::stats()` always returns a zeroed struct

mod common;

use pkttap::{Capture, CaptureStats};

// ── CaptureStats struct ───────────────────────────────────────────────────────

#[test]
fn capture_stats_default_is_zero() {
    let s = CaptureStats::default();
    assert_eq!(s.received, 0);
    assert_eq!(s.dropped, 0);
    assert_eq!(s.if_dropped, 0);
}

#[test]
fn capture_stats_is_copy() {
    let s = CaptureStats {
        received: 100,
        dropped: 5,
        if_dropped: 1,
    };
    let copy = s; // would move if not Copy
    assert_eq!(copy.received, 100);
    assert_eq!(s.received, 100); // original still usable
}

#[test]
fn capture_stats_is_clone() {
    let s = CaptureStats {
        received: 42,
        dropped: 3,
        if_dropped: 0,
    };
    let cloned = s.clone();
    assert_eq!(cloned, s);
}

#[test]
fn capture_stats_equality() {
    let a = CaptureStats {
        received: 10,
        dropped: 1,
        if_dropped: 0,
    };
    let b = CaptureStats {
        received: 10,
        dropped: 1,
        if_dropped: 0,
    };
    let c = CaptureStats {
        received: 11,
        dropped: 1,
        if_dropped: 0,
    };
    assert_eq!(a, b);
    assert_ne!(a, c);
}

#[test]
fn capture_stats_debug_contains_fields() {
    let s = CaptureStats {
        received: 7,
        dropped: 2,
        if_dropped: 1,
    };
    let dbg = format!("{s:?}");
    assert!(dbg.contains("received"), "debug missing 'received': {dbg}");
    assert!(dbg.contains("dropped"), "debug missing 'dropped': {dbg}");
    assert!(
        dbg.contains("if_dropped"),
        "debug missing 'if_dropped': {dbg}"
    );
}

// ── File-based Capture::stats() ───────────────────────────────────────────────

#[test]
fn file_capture_stats_returns_zeros() {
    let pkt = common::tcp_frame(80);
    let tmp = common::temp_file(&common::pcap_bytes(1, &[&pkt]));
    let mut cap = Capture::from_file(tmp.path()).open().unwrap();

    let stats = cap.stats().unwrap();
    assert_eq!(
        stats,
        CaptureStats::default(),
        "file capture should return zeroed stats"
    );
}

#[test]
fn file_capture_stats_stable_across_reads() {
    let pkt = common::tcp_frame(80);
    let tmp = common::temp_file(&common::pcap_bytes(1, &[&pkt, &pkt, &pkt]));
    let mut cap = Capture::from_file(tmp.path()).open().unwrap();

    // Read some packets, then check stats — should stay zero for file captures
    while cap.next().unwrap().is_some() {}

    let stats = cap.stats().unwrap();
    assert_eq!(stats, CaptureStats::default());
}

#[test]
fn file_capture_stats_callable_multiple_times() {
    let tmp = common::temp_file(&common::pcap_bytes(1, &[&common::tcp_frame(80)]));
    let mut cap = Capture::from_file(tmp.path()).open().unwrap();

    let s1 = cap.stats().unwrap();
    let s2 = cap.stats().unwrap();
    assert_eq!(s1, s2);
}
