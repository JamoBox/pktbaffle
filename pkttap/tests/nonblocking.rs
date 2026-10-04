//! Tests for `CaptureBuilder::nonblocking` (issue #92).
//!
//! Live-capture tests require a real network interface and elevated privileges,
//! so they cannot run in CI. This file tests:
//!   - The builder method compiles and can be chained
//!   - Opening a live capture on a non-existent interface fails regardless of
//!     the nonblocking flag (exercises the builder/open path)
//!   - File captures are unaffected by the nonblocking flag
//!   - On Windows, an idle non-blocking capture on the Npcap loopback adapter
//!     returns `Ok(None)` (skipped when Npcap is not installed)

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

// ── Live non-blocking over the Npcap loopback adapter (Windows) ───────────────

/// A non-blocking capture on a quiet filter returns `Ok(None)` instead of
/// blocking. Skips when Npcap or its loopback adapter is unavailable.
#[cfg(windows)]
#[test]
fn nonblocking_windows_loopback_returns_none_when_idle() {
    use std::time::{Duration, Instant};

    let lo = pkttap::interfaces().ok().and_then(|names| {
        names
            .into_iter()
            .find(|n| n.to_lowercase().contains("loopback"))
    });
    let Some(lo) = lo else {
        eprintln!("skipping: no Npcap loopback adapter");
        return;
    };
    let mut cap = match Capture::live(&lo)
        .filter("udp port 9")
        .nonblocking(true)
        .open()
    {
        Ok(cap) => cap,
        Err(e) => {
            eprintln!("skipping: cannot capture on {lo} ({e})");
            return;
        }
    };

    // Background loopback traffic could still slip through, so drain until the
    // first `Ok(None)`. The blocking path never returns `None` — it loops on
    // 100 ms read timeouts — so reaching one within the deadline shows the
    // handle really is non-blocking.
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match cap.next().expect("next on a non-blocking capture") {
            None => break,
            Some(_) => assert!(
                Instant::now() < deadline,
                "non-blocking capture never reported an empty queue"
            ),
        }
    }
}
