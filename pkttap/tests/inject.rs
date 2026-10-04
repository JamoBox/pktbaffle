//! Tests for `Injector` (issue #93).
//!
//! Split in two halves:
//!
//!   - **API surface** — error paths and auto traits, which need no
//!     privileges and run on every platform.
//!   - **Live injection** (Linux only) — frames sent onto the loopback
//!     interface and read back through a `Capture`, which needs
//!     `CAP_NET_RAW`. Those tests skip themselves (with a printed note) when
//!     the injector or capture cannot be opened, so an unprivileged CI run
//!     still exercises everything above. Loopback keeps the injected traffic
//!     inside the machine.

use pkttap::Injector;

// ── API surface (no privileges required) ──────────────────────────────────────

#[test]
fn missing_interface_returns_error_not_panic() {
    assert!(Injector::on_interface("__pkttap_no_such_iface__").is_err());
}

#[test]
fn empty_interface_name_returns_error_not_panic() {
    assert!(Injector::on_interface("").is_err());
}

/// `send` takes `&self`, so an injector is meant to be shared across threads
/// behind an `Arc` — which needs `Sync` on every platform, including Windows
/// where the underlying `pcap_t` is not thread-safe on its own.
#[test]
fn injector_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Injector>();
}

// ── Live injection over loopback (Linux, requires CAP_NET_RAW) ────────────────

#[cfg(target_os = "linux")]
mod live {
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use pkttap::{Capture, Error, Injector, LinkType};

    /// UDP port the injected frames are addressed to; distinct from the one the
    /// ring tests use so the two suites never see each other's traffic.
    const TEST_PORT: u16 = 45872;
    /// How long a test waits for its own frames before giving up.
    const CAPTURE_TIMEOUT: Duration = Duration::from_secs(5);

    /// Open an injector and a filtered, non-blocking capture on loopback, or
    /// `None` when this process lacks the privileges for either.
    fn open_pair() -> Option<(Injector, Capture)> {
        let inj = match Injector::on_interface("lo") {
            Ok(inj) => inj,
            Err(e) => {
                eprintln!("skipping live injection test: cannot inject on lo ({e})");
                return None;
            }
        };
        match Capture::live("lo")
            .filter(format!("udp dst port {TEST_PORT}").as_str())
            .nonblocking(true)
            .open()
        {
            Ok(cap) => Some((inj, cap)),
            Err(e) => {
                eprintln!("skipping live injection test: cannot capture on lo ({e})");
                None
            }
        }
    }

    /// A complete Ethernet + IPv4 + UDP frame from 127.0.0.1 to
    /// 127.0.0.1:`TEST_PORT` carrying `payload`, with a valid IPv4 header
    /// checksum (the UDP checksum is left at 0, which IPv4 permits).
    fn udp_frame(payload: &[u8]) -> Vec<u8> {
        let ip_len = (20 + 8 + payload.len()) as u16;
        let udp_len = (8 + payload.len()) as u16;

        // Loopback's link-layer header: all-zero MACs, EtherType IPv4.
        let mut f = vec![0u8; 12];
        f.extend_from_slice(&0x0800u16.to_be_bytes());

        let mut ip = [0u8; 20];
        ip[0] = 0x45; // version 4, IHL 5
        ip[2..4].copy_from_slice(&ip_len.to_be_bytes());
        ip[8] = 64; // TTL
        ip[9] = 17; // UDP
        ip[12..16].copy_from_slice(&[127, 0, 0, 1]);
        ip[16..20].copy_from_slice(&[127, 0, 0, 1]);
        let csum = ipv4_checksum(&ip);
        ip[10..12].copy_from_slice(&csum.to_be_bytes());
        f.extend_from_slice(&ip);

        f.extend_from_slice(&40000u16.to_be_bytes()); // source port
        f.extend_from_slice(&TEST_PORT.to_be_bytes());
        f.extend_from_slice(&udp_len.to_be_bytes());
        f.extend_from_slice(&0u16.to_be_bytes()); // checksum: none
        f.extend_from_slice(payload);
        f
    }

    fn ipv4_checksum(hdr: &[u8]) -> u16 {
        let mut sum: u32 = hdr
            .chunks(2)
            .map(|w| u32::from(u16::from_be_bytes([w[0], w[1]])))
            .sum();
        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    /// Read from `cap` until `want` frames ending in `marker` arrive or the
    /// timeout expires, calling `resend` periodically in case the first
    /// frames raced the capture socket coming up. Returns the matching frames.
    fn collect(
        cap: &mut Capture,
        marker: &[u8],
        want: usize,
        mut resend: impl FnMut(),
    ) -> Vec<Vec<u8>> {
        let deadline = Instant::now() + CAPTURE_TIMEOUT;
        let mut last_send = Instant::now();
        let mut got = Vec::new();
        while got.len() < want && Instant::now() < deadline {
            match cap.next().expect("capture read failed") {
                Some(pkt) if pkt.data().ends_with(marker) => got.push(pkt.data().to_vec()),
                Some(_) => {}
                None => {
                    std::thread::sleep(Duration::from_millis(2));
                    if last_send.elapsed() > Duration::from_millis(500) {
                        resend();
                        last_send = Instant::now();
                    }
                }
            }
        }
        got
    }

    #[test]
    fn loopback_reports_ethernet_link_type() {
        let Some((inj, _cap)) = open_pair() else {
            return;
        };
        // AF_PACKET gives loopback a synthetic 14-byte Ethernet header.
        assert_eq!(inj.link_type(), LinkType::Ethernet);
    }

    /// The end-to-end path: a frame handed to `send` goes out on the wire
    /// byte-for-byte, and a capture on the same interface sees it.
    #[test]
    fn injected_frame_is_captured_unmodified() {
        let Some((inj, mut cap)) = open_pair() else {
            return;
        };

        let frame = udp_frame(b"pkttap-inject-roundtrip");
        let sent = inj.send(&frame).expect("send");
        assert_eq!(sent, frame.len(), "send reports the whole frame");

        let got = collect(&mut cap, b"pkttap-inject-roundtrip", 1, || {
            inj.send(&frame).expect("resend");
        });
        let Some(captured) = got.first() else {
            panic!("injected frame not captured within {CAPTURE_TIMEOUT:?}");
        };
        // No encapsulation, no rewritten addresses: the capture sees exactly
        // the bytes that were injected.
        assert_eq!(captured, &frame);
    }

    #[test]
    fn empty_frame_is_rejected() {
        let Some((inj, _cap)) = open_pair() else {
            return;
        };
        assert!(matches!(inj.send(&[]), Err(Error::Platform(_))));
    }

    /// Frames the kernel cannot transmit — shorter than the link-layer header,
    /// or larger than the MTU allows — surface as errors, not panics or
    /// silent truncation.
    #[test]
    fn malformed_frames_are_rejected_by_the_kernel() {
        let Some((inj, _cap)) = open_pair() else {
            return;
        };
        assert!(
            inj.send(&[0u8; 5]).is_err(),
            "a frame shorter than the Ethernet header must be refused"
        );
        // Loopback's MTU is 65536, so this is too large for any interface.
        assert!(
            inj.send(&udp_frame(&vec![0u8; 70_000])).is_err(),
            "a frame larger than the MTU must be refused"
        );
    }

    /// One injector shared between threads: every thread's frames go out.
    #[test]
    fn shared_injector_sends_from_several_threads() {
        let Some((inj, mut cap)) = open_pair() else {
            return;
        };
        let inj = Arc::new(inj);
        const THREADS: usize = 4;
        const PER_THREAD: usize = 25;
        let marker = b"pkttap-inject-threads";
        let frame = Arc::new(udp_frame(marker));

        let send_all = |inj: &Arc<Injector>, frame: &Arc<Vec<u8>>| {
            let handles: Vec<_> = (0..THREADS)
                .map(|_| {
                    let inj = Arc::clone(inj);
                    let frame = Arc::clone(frame);
                    std::thread::spawn(move || {
                        for _ in 0..PER_THREAD {
                            inj.send(&frame).expect("send from worker thread");
                        }
                    })
                })
                .collect();
            for h in handles {
                h.join().expect("sender thread panicked");
            }
        };

        send_all(&inj, &frame);
        let got = collect(&mut cap, marker, THREADS * PER_THREAD, || {});
        // Loopback may hand the capture each frame twice (once outbound, once
        // inbound) and the kernel may drop some under load, so only require
        // a clear majority to have arrived.
        assert!(
            got.len() >= THREADS * PER_THREAD / 2,
            "captured only {} of {} injected frames",
            got.len(),
            THREADS * PER_THREAD
        );
    }
}

// ── Live injection over the Npcap loopback adapter (Windows) ──────────────────

#[cfg(windows)]
mod live_windows {
    use std::sync::mpsc;
    use std::time::Duration;

    use pkttap::{Capture, Injector};

    /// A DLT_NULL frame — the Npcap loopback adapter's link layer: a 4-byte
    /// host-order address family (AF_INET = 2), then an IPv4/UDP packet from
    /// 127.0.0.1 to 127.0.0.1:45872 carrying `payload`. The IP identification
    /// is 0 and the header checksum is valid for that.
    fn null_udp_frame(payload: &[u8]) -> Vec<u8> {
        let mut ip = [0u8; 20];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&((28 + payload.len()) as u16).to_be_bytes());
        ip[8] = 64;
        ip[9] = 17;
        ip[12..16].copy_from_slice(&[127, 0, 0, 1]);
        ip[16..20].copy_from_slice(&[127, 0, 0, 1]);
        let mut sum: u32 = ip
            .chunks(2)
            .map(|w| u32::from(u16::from_be_bytes([w[0], w[1]])))
            .sum();
        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        ip[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());

        let mut f = 2u32.to_le_bytes().to_vec();
        f.extend_from_slice(&ip);
        f.extend_from_slice(&40000u16.to_be_bytes());
        f.extend_from_slice(&45872u16.to_be_bytes());
        f.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        f.extend_from_slice(&[0, 0]);
        f.extend_from_slice(payload);
        f
    }

    /// Round-trip through the Npcap loopback adapter, and check `send` leaves
    /// the caller's buffer alone.
    ///
    /// The second check is the regression test for a soundness bug: Windows
    /// writes the IP identification and checksum of a loopback IPv4 frame into
    /// the buffer handed to `pcap_sendpacket`. Passed straight through, that
    /// would mutate memory behind `send`'s `&[u8]`.
    #[test]
    fn loopback_roundtrip_leaves_caller_buffer_untouched() {
        let lo = pkttap::interfaces().ok().and_then(|names| {
            names
                .into_iter()
                .find(|n| n.to_lowercase().contains("loopback"))
        });
        let Some(lo) = lo else {
            eprintln!("skipping live injection test: no Npcap loopback adapter");
            return;
        };
        let inj = match Injector::on_interface(&lo) {
            Ok(inj) => inj,
            Err(e) => {
                eprintln!("skipping live injection test: cannot inject on {lo} ({e})");
                return;
            }
        };

        let marker = b"pkttap-inject-windows-loopback";
        let frame = null_udp_frame(marker);

        // Read on a thread and wait on a channel with a timeout.
        let (tx, rx) = mpsc::channel();
        let cap_iface = lo.clone();
        std::thread::spawn(move || {
            let mut cap = match Capture::live(&cap_iface).open() {
                Ok(cap) => cap,
                Err(_) => return,
            };
            let _ = tx.send(None);
            while let Ok(pkt) = cap.next() {
                if let Some(pkt) = pkt.filter(|p| p.data().ends_with(marker)) {
                    let _ = tx.send(Some(pkt.data().to_vec()));
                    return;
                }
            }
        });
        if rx.recv_timeout(Duration::from_secs(5)).is_err() {
            eprintln!("skipping live injection test: cannot capture on {lo}");
            return;
        }

        let original = frame.clone();
        let mut captured = None;
        for _ in 0..10 {
            assert_eq!(inj.send(&frame).expect("send"), frame.len());
            assert_eq!(frame, original, "send must not modify the caller's frame");
            if let Ok(Some(got)) = rx.recv_timeout(Duration::from_millis(500)) {
                captured = Some(got);
                break;
            }
        }
        let captured = captured.expect("injected frame not captured on the loopback adapter");
        assert_eq!(captured, original);
    }
}
