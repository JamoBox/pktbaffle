//! Tests for `CaptureBuilder::nonblocking` (issue #92).
//!
//! Live-capture tests require a real network interface and elevated privileges,
//! so they cannot run in CI. This file tests:
//!   - The builder method compiles and can be chained
//!   - Opening a live capture on a non-existent interface fails regardless of
//!     the nonblocking flag (exercises the builder/open path)
//!   - File captures are unaffected by the nonblocking flag

mod common;

use pkttap::Capture;

// ── Builder API surface ───────────────────────────────────────────────────────

/// Calling `.nonblocking(true)` on a live builder and then `.open()` on a
/// non-existent interface should fail with an error (not panic), proving the
/// code path is reachable and the flag is accepted.
#[test]
fn nonblocking_builder_on_missing_interface_returns_error() {
    let result = Capture::live("__pkttap_no_such_iface__")
        .nonblocking(true)
        .open();
    assert!(
        result.is_err(),
        "expected an error opening a non-existent interface"
    );
}

/// Disabling nonblocking (the default) on a non-existent interface also fails
/// cleanly — confirms the flag path doesn't introduce panics in either state.
#[test]
fn blocking_builder_on_missing_interface_returns_error() {
    let result = Capture::live("__pkttap_no_such_iface__")
        .nonblocking(false)
        .open();
    assert!(result.is_err());
}

// ── File captures ─────────────────────────────────────────────────────────────

/// Setting `.nonblocking(true)` on a file-based capture is silently ignored;
/// file captures should still open and read normally.
#[test]
fn nonblocking_flag_ignored_for_file_capture() {
    let pkt = common::tcp_frame(80);
    let tmp = common::temp_file(&common::pcap_bytes(1, &[&pkt]));

    // The nonblocking flag is only meaningful for live captures; file captures
    // should open and read without error.
    let mut cap = Capture::from_file(tmp.path())
        .nonblocking(true)
        .open()
        .expect("file capture should open successfully");

    let got = cap.next().unwrap().expect("should return the packet");
    assert_eq!(got.data(), pkt.as_slice());
    assert!(cap.next().unwrap().is_none());
}
