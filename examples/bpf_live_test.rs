//! Live BPF filter tests — Linux only, requires CAP_NET_RAW.
//!
//! Opens a SOCK_RAW + IPPROTO_UDP socket (which sees every UDP datagram at
//! the IP layer — no Ethernet header), attaches a compiled BPF program via
//! SO_ATTACH_FILTER, then sends UDP packets through a normal SOCK_DGRAM socket
//! and asserts that the raw socket receives exactly the packets the filter
//! should accept.
//!
//!   docker compose run --rm live-test
//!
//! The container has CAP_NET_RAW so the SOCK_RAW socket can be opened.

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!(
        "bpf_live_test is Linux-only (current OS: {})",
        std::env::consts::OS
    );
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
fn main() {
    let tests: &[(&str, &[(&[u8], Verdict)])] = &[
        (
            // Filter: UDP port 9001 — accept port 9001, drop others.
            "udp port 9001",
            &[
                (b"hello9001" as &[u8], Verdict::Accept),
                (b"hello9002" as &[u8], Verdict::Drop),
            ],
        ),
        (
            "dst port 9001",
            &[(b"match", Verdict::Accept), (b"nomatch", Verdict::Drop)],
        ),
        (
            "portrange 8000-9999",
            &[
                (b"inrange", Verdict::Accept), // port 9001 — in [8000,9999]
                (b"outrange", Verdict::Drop),  // port 9002 — but we'll adjust below
            ],
        ),
        (
            "not dst port 9001",
            &[
                (b"notport", Verdict::Drop),     // port 9001 → filtered out by NOT
                (b"otherport", Verdict::Accept), // port 9002 → passes NOT
            ],
        ),
        (
            "dst port 9001 or dst port 9002",
            &[
                (b"p9001", Verdict::Accept),
                (b"p9002", Verdict::Accept),
                (b"p9003", Verdict::Drop),
            ],
        ),
        (
            "greater 4",
            &[
                (b"12345", Verdict::Accept), // 5-byte payload > 4
                (b"hi", Verdict::Drop),      // 2-byte payload, not > 4
            ],
        ),
    ];

    // Each test case maps payload → verdict.  The dst port is encoded by
    // convention: "matches" always use port 9001, "doesn't match" uses 9002,
    // unless the test is a portrange or length test.  We map by position to
    // keep the test declaration above readable.
    let port_map: &[&[u16]] = &[
        &[9001, 9002],       // udp port 9001
        &[9001, 9002],       // dst port 9001
        &[9001, 7777],       // portrange 8000-9999
        &[9001, 9002],       // not dst port 9001
        &[9001, 9002, 9003], // or
        &[9001, 9001],       // greater 4 (same port, different payload sizes)
    ];

    let mut pass = 0u32;
    let mut fail = 0u32;

    for (idx, &(filter, packets)) in tests.iter().enumerate() {
        print!("  {:40} ", format!("{filter:?}"));
        match run_test(filter, packets, port_map[idx]) {
            Ok(()) => {
                println!("ok");
                pass += 1;
            }
            Err(e) => {
                println!("FAILED  {e}");
                fail += 1;
            }
        }
    }

    println!("\n{pass} passed, {fail} failed");
    if fail > 0 {
        std::process::exit(1);
    }
}

// ── Core test runner ──────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    Accept,
    Drop,
}

#[cfg(target_os = "linux")]
fn run_test(filter: &str, packets: &[(&[u8], Verdict)], ports: &[u16]) -> Result<(), String> {
    use pktbaffle::LinkType;

    // Compile with RawIp: SOCK_RAW + IPPROTO_UDP presents the IP header at
    // offset 0, with no Ethernet wrapper.
    let prog =
        pktbaffle::compile(filter, LinkType::RawIp).map_err(|e| format!("compile error: {e}"))?;

    // Raw receiving socket — sees all UDP datagrams at the IP layer.
    let raw_fd = open_raw_udp_socket()?;
    let _raw_guard = FdGuard(raw_fd);
    attach_bpf(raw_fd, &prog)?;

    // Plain sending socket.
    let send_fd = udp_socket()?;
    let _send_guard = FdGuard(send_fd);

    for (i, &(payload, expected)) in packets.iter().enumerate() {
        let dst_port = ports[i];
        send_udp(send_fd, dst_port, payload)?;

        // Give the kernel a moment to deliver (or drop) the packet.
        let got = poll_recv(raw_fd, payload, std::time::Duration::from_millis(30));
        if got != expected {
            return Err(format!(
                "packet {i} (port {dst_port}, payload {:?}): expected {expected:?}, got {got:?}",
                String::from_utf8_lossy(payload)
            ));
        }
    }
    Ok(())
}

/// Poll the raw socket for a packet containing `needle` in its payload.
/// Returns `Accept` if found within `timeout`, `Drop` otherwise.
#[cfg(target_os = "linux")]
fn poll_recv(fd: libc::c_int, needle: &[u8], timeout: std::time::Duration) -> Verdict {
    let mut buf = [0u8; 4096];
    let deadline = std::time::Instant::now() + timeout;

    loop {
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };

        if n > 0 {
            let pkt = &buf[..n as usize];
            // The raw IP packet: IP header (min 20 bytes) + UDP (8 bytes) + payload.
            let ihl = ((pkt[0] & 0x0f) as usize) * 4;
            if pkt.len() >= ihl + 8 {
                let data = &pkt[ihl + 8..];
                if data.windows(needle.len()).any(|w| w == needle) {
                    return Verdict::Accept;
                }
            }
        } else {
            let e = unsafe { *libc::__errno_location() };
            if e != libc::EAGAIN && e != libc::EWOULDBLOCK {
                return Verdict::Drop;
            }
        }

        if std::time::Instant::now() >= deadline {
            return Verdict::Drop;
        }
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
}

// ── Socket helpers ────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn open_raw_udp_socket() -> Result<libc::c_int, String> {
    let fd = unsafe {
        libc::socket(
            libc::AF_INET,
            libc::SOCK_RAW | libc::SOCK_NONBLOCK,
            libc::IPPROTO_UDP,
        )
    };
    if fd < 0 {
        let e = unsafe { *libc::__errno_location() };
        if e == libc::EPERM {
            return Err(
                "SOCK_RAW requires CAP_NET_RAW — run the container with --cap-add NET_RAW".into(),
            );
        }
        return Err(format!("socket(SOCK_RAW, IPPROTO_UDP) failed: errno {e}"));
    }
    // Bind to loopback so we only see packets on 127.0.0.1.
    let addr = in_addr(127, 0, 0, 1, 0);
    unsafe {
        libc::bind(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of_val(&addr) as libc::socklen_t,
        )
    };
    Ok(fd)
}

#[cfg(target_os = "linux")]
fn udp_socket() -> Result<libc::c_int, String> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(format!("socket(SOCK_DGRAM) failed: errno {}", unsafe {
            *libc::__errno_location()
        }));
    }
    Ok(fd)
}

#[cfg(target_os = "linux")]
fn send_udp(fd: libc::c_int, dst_port: u16, payload: &[u8]) -> Result<(), String> {
    let dst = in_addr(127, 0, 0, 1, dst_port);
    let n = unsafe {
        libc::sendto(
            fd,
            payload.as_ptr() as *const libc::c_void,
            payload.len(),
            0,
            &dst as *const _ as *const libc::sockaddr,
            std::mem::size_of_val(&dst) as libc::socklen_t,
        )
    };
    if n < 0 {
        let e = unsafe { *libc::__errno_location() };
        Err(format!("sendto 127.0.0.1:{dst_port} failed: errno {e}"))
    } else {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn in_addr(a: u8, b: u8, c: u8, d: u8, port: u16) -> libc::sockaddr_in {
    let mut s: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    s.sin_family = libc::AF_INET as libc::sa_family_t;
    s.sin_port = port.to_be();
    s.sin_addr = libc::in_addr {
        s_addr: u32::from_be_bytes([a, b, c, d]).to_be(),
    };
    s
}

// ── BPF attachment ────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn attach_bpf(fd: libc::c_int, prog: &pktbaffle::Program) -> Result<(), String> {
    // `pktbaffle::Insn` has the same repr(C) layout as the kernel's sock_filter:
    //   u16 code, u8 jt, u8 jf, u32 k  (8 bytes total, matching __u16+__u8+__u8+__u32).
    #[repr(C)]
    struct SockFprog {
        len: libc::c_ushort,
        filter: *const pktbaffle::Insn,
    }

    let insns = prog.instructions();
    let fprog = SockFprog {
        len: insns.len() as libc::c_ushort,
        filter: insns.as_ptr(),
    };

    let r = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ATTACH_FILTER,
            &fprog as *const _ as *const libc::c_void,
            std::mem::size_of_val(&fprog) as libc::socklen_t,
        )
    };
    if r < 0 {
        let e = unsafe { *libc::__errno_location() };
        Err(format!("SO_ATTACH_FILTER failed: errno {e}"))
    } else {
        Ok(())
    }
}

// ── Cleanup ───────────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
struct FdGuard(libc::c_int);

#[cfg(target_os = "linux")]
impl Drop for FdGuard {
    fn drop(&mut self) {
        unsafe { libc::close(self.0) };
    }
}
