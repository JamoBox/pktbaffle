//! Tests for the Linux `TPACKET_V3` ring-buffer backend (issue #90).
//!
//! Split in two halves:
//!
//!   - **API surface** — the builder, geometry validation and error paths,
//!     which need no privileges and run everywhere Linux does.
//!   - **Live capture** — a real ring over the loopback interface, which needs
//!     `CAP_NET_RAW`. Those tests skip themselves (with a printed note) when
//!     the capture cannot be opened, so an unprivileged CI run still exercises
//!     everything above.

#![cfg(target_os = "linux")]

use std::net::UdpSocket;
use std::time::{Duration, Instant, SystemTime};

use pkttap::{Capture, FanoutGroup, FanoutMode, RingConfig};

/// UDP port the live tests filter on; unusual enough not to collide with
/// whatever else is running on the machine.
const TEST_PORT: u16 = 45871;
const PAYLOAD: &[u8] = b"pkttap-tpacket-v3-ring-test";
/// How long a live test waits for its own packets before giving up.
const CAPTURE_TIMEOUT: Duration = Duration::from_secs(5);

// ── API surface (no privileges required) ──────────────────────────────────────

#[test]
fn ring_builder_methods_chain() {
    let cfg = RingConfig::new()
        .block_size(1 << 20)
        .block_count(8)
        .retire_timeout(Duration::from_millis(10));

    // Rejected because the interface does not exist — not because a builder
    // method panicked or the option was refused.
    let result = Capture::live("__pkttap_no_such_iface__")
        .filter("tcp port 443")
        .snaplen(1500)
        .promiscuous(true)
        .nonblocking(true)
        .ring(cfg)
        .open();
    assert!(result.is_err());
}

/// `ring()` takes the same `Into<Option<_>>` shapes as `filter()`, so an
/// optional config can be passed straight through from a caller's variable.
#[test]
fn ring_accepts_optional_config() {
    let maybe: Option<RingConfig> = Some(RingConfig::new());
    assert!(Capture::live("__pkttap_no_such_iface__")
        .ring(maybe)
        .open()
        .is_err());

    // `None` means "keep the default recvmsg path" rather than "no config".
    assert!(Capture::live("__pkttap_no_such_iface__")
        .ring(None::<RingConfig>)
        .open()
        .is_err());
}

/// A ring geometry the kernel would reject must be refused cleanly, whether or
/// not the process has capture privileges.
#[test]
fn invalid_geometry_returns_error_not_panic() {
    for cfg in [
        RingConfig::new().block_count(0),
        RingConfig::new().block_size(0),
        // Larger than the address space: must be an error, not a wrapped size.
        RingConfig::new().block_size(1 << 30).block_count(1 << 24),
    ] {
        assert!(Capture::live("lo").ring(cfg).open().is_err());
    }
}

/// Fanout members can each be given their own ring; the combination must fail
/// no worse than either feature alone on a missing interface.
#[test]
fn fanout_with_ring_returns_error_not_panic() {
    let result = FanoutGroup::new("__pkttap_no_such_iface__", FanoutMode::CpuAffinity)
        .ring(RingConfig::new())
        .into_captures(2);
    assert!(result.is_err());
}

/// A ring capture owns an mmap'd region behind a raw pointer, which would
/// otherwise strip `Capture`'s auto traits: it must stay `Send` (a
/// `FanoutGroup` hands one member per worker thread) and `Sync` (as it is on
/// every other capture backend).
#[test]
fn ring_capture_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Capture>();
    assert_send_sync::<RingConfig>();
}

// ── Live capture (requires CAP_NET_RAW) ───────────────────────────────────────

/// Open a ring capture on loopback, or `None` when this process cannot capture
/// (unprivileged CI, containers without `CAP_NET_RAW`, …).
fn open_ring_capture(snaplen: u32) -> Option<Capture> {
    let cfg = RingConfig::new()
        .block_size(1 << 16)
        .block_count(4)
        // Short timeout: a handful of test packets never fills a block, so
        // delivery is entirely down to the block retire timer.
        .retire_timeout(Duration::from_millis(5));

    match Capture::live("lo")
        .filter(format!("udp dst port {TEST_PORT}").as_str())
        .snaplen(snaplen)
        .nonblocking(true)
        .ring(cfg)
        .open()
    {
        Ok(cap) => Some(cap),
        Err(e) => {
            eprintln!("skipping live ring test: cannot capture on lo ({e})");
            None
        }
    }
}

/// Send test packets and read from `cap` until `want` of them come back or the
/// timeout expires. Returns the matching packets as (bytes, orig_len).
fn capture_own_packets(cap: &mut Capture, want: usize) -> Vec<(Vec<u8>, u32)> {
    let tx = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
    let dst = format!("127.0.0.1:{TEST_PORT}");
    let send = |n: usize| {
        for _ in 0..n {
            let _ = tx.send_to(PAYLOAD, &dst);
        }
    };

    send(want);
    let deadline = Instant::now() + CAPTURE_TIMEOUT;
    let mut got = Vec::new();
    let mut last_send = Instant::now();
    while got.len() < want && Instant::now() < deadline {
        match cap.next().expect("ring read failed") {
            Some(pkt) => got.push((pkt.data().to_vec(), pkt.orig_len())),
            None => {
                std::thread::sleep(Duration::from_millis(2));
                // Re-send periodically: the first batch can race a socket that
                // is bound but not yet passing traffic through the filter.
                if last_send.elapsed() > Duration::from_millis(500) {
                    send(want);
                    last_send = Instant::now();
                }
            }
        }
    }
    got
}

/// The end-to-end path: kernel writes frames into the mmap'd ring, `next()`
/// walks them in place, and the bytes come back intact.
#[test]
fn captures_loopback_traffic_through_the_ring() {
    let Some(mut cap) = open_ring_capture(65535) else {
        return;
    };

    let got = capture_own_packets(&mut cap, 4);
    assert!(
        !got.is_empty(),
        "no packets captured through the ring within {CAPTURE_TIMEOUT:?}"
    );

    for (data, orig_len) in &got {
        // Ethernet (14) + IPv4 (20) + UDP (8) on loopback, then our payload.
        assert!(
            data.ends_with(PAYLOAD),
            "captured frame does not end with the test payload: {data:02x?}"
        );
        assert_eq!(
            *orig_len as usize,
            data.len(),
            "untruncated capture should report the on-wire length"
        );
    }

    // Every frame read matched the payload above, which is the filter doing
    // its job in the kernel: nothing else on loopback reached the ring.
    assert_eq!(got.len(), 4, "should have read the four packets asked for");
}

/// Statistics come from the same `PACKET_STATISTICS` counters on a `TPACKET_V3`
/// socket, which answers with the longer `tpacket_stats_v3` struct.
#[test]
fn ring_capture_reports_stats() {
    let Some(mut cap) = open_ring_capture(65535) else {
        return;
    };

    let got = capture_own_packets(&mut cap, 2);
    assert!(!got.is_empty(), "no packets captured through the ring");

    let stats = cap.stats().expect("stats on a ring socket");
    assert!(
        stats.received >= got.len() as u64,
        "received={} should count at least the {} packets read",
        stats.received,
        got.len()
    );
}

/// Snaplen is applied to ring frames exactly as it is on the `recvmsg` path:
/// the packet is truncated, `orig_len` still reports the on-wire length.
#[test]
fn ring_capture_honours_snaplen() {
    let snaplen = 40u32;
    let Some(mut cap) = open_ring_capture(snaplen) else {
        return;
    };

    let got = capture_own_packets(&mut cap, 2);
    assert!(!got.is_empty(), "no packets captured through the ring");

    for (data, orig_len) in &got {
        assert_eq!(
            data.len(),
            snaplen as usize,
            "captured bytes clamp to snaplen"
        );
        assert!(
            *orig_len > snaplen,
            "on-wire length ({orig_len}) should exceed the snaplen"
        );
    }
}

/// Frames carry the kernel's own timestamp from the frame header, so it should
/// sit within a few seconds of now — not the epoch, and not the future.
#[test]
fn ring_frames_carry_kernel_timestamps() {
    let Some(mut cap) = open_ring_capture(65535) else {
        return;
    };

    let tx = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
    let dst = format!("127.0.0.1:{TEST_PORT}");
    let before = SystemTime::now();
    for _ in 0..4 {
        let _ = tx.send_to(PAYLOAD, &dst);
    }

    let deadline = Instant::now() + CAPTURE_TIMEOUT;
    let mut stamp = None;
    while stamp.is_none() && Instant::now() < deadline {
        match cap.next().expect("ring read failed") {
            Some(pkt) => stamp = Some(pkt.timestamp()),
            None => {
                std::thread::sleep(Duration::from_millis(2));
                let _ = tx.send_to(PAYLOAD, &dst);
            }
        }
    }
    let Some(stamp) = stamp else {
        panic!("no packets captured through the ring within {CAPTURE_TIMEOUT:?}");
    };

    // Allow a second of slack either side for clock granularity.
    assert!(
        stamp + Duration::from_secs(1) >= before,
        "timestamp {stamp:?} predates the send at {before:?}"
    );
    assert!(
        stamp <= SystemTime::now() + Duration::from_secs(1),
        "timestamp {stamp:?} is in the future"
    );
}

/// A non-blocking ring returns `Ok(None)` rather than blocking when no block
/// has been handed over yet.
#[test]
fn nonblocking_ring_returns_none_when_idle() {
    let Some(mut cap) = open_ring_capture(65535) else {
        return;
    };

    // Nothing has been sent to TEST_PORT, so the ring is empty and every read
    // must return immediately.
    let start = Instant::now();
    for _ in 0..100 {
        assert!(
            cap.next().expect("ring read failed").is_none(),
            "unexpected packet on an idle ring"
        );
    }
    assert!(
        start.elapsed() < Duration::from_secs(1),
        "non-blocking reads should return immediately"
    );
}

/// The default (blocking) mode parks in `poll()` until the kernel hands a
/// block over, rather than spinning or returning `Ok(None)`.
///
/// The read runs on its own thread so a regression that never delivers fails
/// the test on the timeout instead of hanging the suite.
#[test]
fn blocking_ring_waits_for_a_packet() {
    let Ok(mut cap) = Capture::live("lo")
        .filter(format!("udp dst port {TEST_PORT}").as_str())
        .ring(RingConfig::new().retire_timeout(Duration::from_millis(5)))
        .open()
    else {
        eprintln!("skipping live ring test: cannot capture on lo");
        return;
    };

    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        // Blocks in poll() until the kernel retires a block holding our packet.
        let data = cap
            .next()
            .expect("ring read failed")
            .map(|pkt| pkt.data().to_vec());
        let _ = done_tx.send(data);
    });

    // Keep offering packets until the reader wakes up.
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let sender_stop = stop.clone();
    let sender = std::thread::spawn(move || {
        let tx = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
        let dst = format!("127.0.0.1:{TEST_PORT}");
        while !sender_stop.load(std::sync::atomic::Ordering::Relaxed) {
            let _ = tx.send_to(PAYLOAD, &dst);
            std::thread::sleep(Duration::from_millis(20));
        }
    });

    let got = done_rx.recv_timeout(CAPTURE_TIMEOUT);
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    sender.join().expect("sender thread");

    let data = got
        .expect("blocking read did not return within the timeout")
        .expect("blocking read returned no packet");
    assert!(
        data.ends_with(PAYLOAD),
        "captured frame does not end with the test payload: {data:02x?}"
    );
    reader.join().expect("reader thread");
}

/// Reading more packets than the ring holds forces every block to be released
/// back to the kernel and reused — the wrap-around path, against a real kernel
/// rather than the synthetic blocks the unit tests walk.
#[test]
fn ring_wraps_around_under_sustained_traffic() {
    // Four small blocks, so a few hundred packets cycle the whole ring
    // several times over.
    let cfg = RingConfig::new()
        .block_size(1 << 14)
        .block_count(4)
        .retire_timeout(Duration::from_millis(1));
    let Ok(mut cap) = Capture::live("lo")
        .filter(format!("udp dst port {TEST_PORT}").as_str())
        .snaplen(128)
        .nonblocking(true)
        .ring(cfg)
        .open()
    else {
        eprintln!("skipping live ring test: cannot capture on lo");
        return;
    };

    let tx = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
    let dst = format!("127.0.0.1:{TEST_PORT}");

    // Interleave sending and reading so the kernel keeps handing blocks over
    // while we drain them.
    let deadline = Instant::now() + CAPTURE_TIMEOUT;
    let mut captured = 0usize;
    let mut sent = 0usize;
    while sent < 4000 && Instant::now() < deadline {
        for _ in 0..100 {
            let _ = tx.send_to(PAYLOAD, &dst);
            sent += 1;
        }
        while let Some(pkt) = cap.next().expect("ring read failed") {
            assert!(
                pkt.data().ends_with(PAYLOAD),
                "corrupt frame after {captured} packets: {:02x?}",
                pkt.data()
            );
            captured += 1;
        }
        std::thread::sleep(Duration::from_millis(1));
    }

    // A 16 KiB block holds on the order of a hundred of these frames, so
    // reading this many means every block was consumed, released and reused.
    // Kernel-side drops are legitimate under a flood, hence the loose bound.
    assert!(
        captured >= 1000,
        "captured only {captured} of {sent} packets; the ring should keep \
         cycling blocks rather than stalling after the first pass"
    );

    let stats = cap.stats().expect("stats on a ring socket");
    assert!(stats.received >= captured as u64);
}
