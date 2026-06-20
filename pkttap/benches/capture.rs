//! Criterion benchmarks for pkttap packet operations and file I/O.
//!
//! Run with:
//!   cargo bench -p pkttap
//!
//! HTML reports land in `target/criterion/`.
//!
//! # Benchmark families
//!
//! ## `packet` — pure-memory packet operations (no I/O)
//!
//! These benchmarks isolate pkttap's per-packet data structures from any I/O
//! or parsing overhead.
//!
//! | Benchmark          | Measures |
//! |--------------------|----------|
//! | `construction`     | `Packet::new` heap allocation for a 60-byte frame |
//! | `to_owned`         | `PacketRef::to_owned` — the explicit clone that saves a packet across iterations |
//! | `as_ref_fields`    | `Packet::as_ref` + reading all four fields — the zero-copy read path |
//!
//! ## `file_capture` — pcap parse + VM filter dispatch
//!
//! Reads a 1 000-packet synthetic pcap from a temp file.  The file is written
//! once in the benchmark setup and reused across all iterations, so the OS
//! page cache absorbs the disk I/O after the first read.  What remains is the
//! cost of pcap format parsing, scratch-buffer copies, and (for the filtered
//! variants) VM filter evaluation.
//!
//! Three variants isolate different layers:
//!
//! | Benchmark          | Filter       | Pcap content | Measures |
//! |--------------------|--------------|--------------|----------|
//! | `unfiltered`       | none         | TCP frames   | pcap parse + scratch-buffer copy |
//! | `filter_match_all` | `tcp` (pre-compiled) | TCP frames | above + VM accept path per packet |
//! | `filter_reject_all`| `tcp` (pre-compiled) | UDP frames | above + VM reject path (early exit) |
//!
//! The difference between `unfiltered` and `filter_match_all` isolates VM
//! accept cost.  The difference between the two filtered variants shows how
//! much the early-exit optimisation in the BPF program saves on mismatches.
//!
//! ## `dump_write` — pcap serialisation
//!
//! Writes 1 000 pre-built packets to a fresh temp file each iteration,
//! measuring pcap-file serialisation overhead.

use std::io::Write as _;
use std::time::SystemTime;

use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use pkttap::{Capture, Dump, LinkType, Packet};

// ── Synthetic frame builders ──────────────────────────────────────────────────

fn eth_ipv4_tcp() -> Vec<u8> {
    let mut f = vec![
        // Ethernet header (14 bytes)
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x08, 0x00,
        // IPv4 header (20 bytes): IHL=5, proto=6 (TCP), src=192.168.0.1, dst=10.0.0.1
        0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 0xc0, 0xa8, 0x00,
        0x01, 0x0a, 0x00, 0x00, 0x01, // TCP header (20 bytes): src=12345, dst=80, SYN
        0x30, 0x39, 0x00, 0x50, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0xff,
        0xff, 0x00, 0x00, 0x00, 0x00,
    ];
    f.resize(60, 0u8);
    f
}

fn eth_ipv4_udp() -> Vec<u8> {
    vec![
        // Ethernet header (14 bytes)
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x08, 0x00,
        // IPv4 header (20 bytes): IHL=5, proto=17 (UDP)
        0x45, 0x00, 0x00, 0x1c, 0x00, 0x02, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8, 0x00,
        0x01, 0x0a, 0x00, 0x00, 0x01, // UDP header (8 bytes): src=12345, dst=53
        0x30, 0x39, 0x00, 0x35, 0x00, 0x08, 0x00, 0x00,
    ]
}

// ── pcap byte builder ─────────────────────────────────────────────────────────

fn pcap_bytes(frame: &[u8], count: usize) -> Vec<u8> {
    let mut buf = Vec::with_capacity(24 + count * (16 + frame.len()));
    buf.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes()); // magic
    buf.extend_from_slice(&2u16.to_le_bytes());
    buf.extend_from_slice(&4u16.to_le_bytes());
    buf.extend_from_slice(&0i32.to_le_bytes()); // GMT offset
    buf.extend_from_slice(&0u32.to_le_bytes()); // accuracy
    buf.extend_from_slice(&65535u32.to_le_bytes());
    buf.extend_from_slice(&1u32.to_le_bytes()); // DLT_EN10MB
    for i in 0..count {
        buf.extend_from_slice(&(i as u32).to_le_bytes()); // ts_sec
        buf.extend_from_slice(&0u32.to_le_bytes()); // ts_usec
        buf.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        buf.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        buf.extend_from_slice(frame);
    }
    buf
}

const N: usize = 1_000;

// ── Packet operation benchmarks (no I/O) ─────────────────────────────────────

fn bench_packet(c: &mut Criterion) {
    let frame = eth_ipv4_tcp();
    let frame_len = frame.len() as u32;
    let owned = Packet::new(
        frame.clone(),
        SystemTime::UNIX_EPOCH,
        frame_len,
        LinkType::Ethernet,
    );

    let mut g = c.benchmark_group("packet");

    g.bench_function("construction", |b| {
        b.iter_batched(
            || frame.clone(),
            |data| {
                criterion::black_box(Packet::new(
                    data,
                    SystemTime::UNIX_EPOCH,
                    frame_len,
                    LinkType::Ethernet,
                ))
            },
            BatchSize::SmallInput,
        )
    });

    g.bench_function("to_owned", |b| {
        b.iter(|| criterion::black_box(owned.as_ref().to_owned()))
    });

    g.bench_function("as_ref_fields", |b| {
        b.iter(|| {
            let r = owned.as_ref();
            criterion::black_box((
                r.data().len(),
                r.orig_len(),
                r.link_type(),
                r.is_truncated(),
            ))
        })
    });

    g.finish();
}

// ── File capture benchmarks ───────────────────────────────────────────────────

fn bench_file_capture(c: &mut Criterion) {
    use pktbaffle::{compile, Target};

    let tcp_frame = eth_ipv4_tcp();
    let udp_frame = eth_ipv4_udp();

    // Compile the "tcp" filter once; use it as a pre-compiled program so that
    // compilation cost is excluded from the capture benchmarks.
    let tcp_prog = {
        let p = compile(
            "tcp",
            pktbaffle::codegen::LinkType::Ethernet,
            Target::Classic,
        )
        .unwrap();
        p.as_classic().unwrap().clone()
    };

    // Write pcap temp files once; reused across all iterations.
    let mut tcp_file = tempfile::Builder::new().suffix(".pcap").tempfile().unwrap();
    tcp_file.write_all(&pcap_bytes(&tcp_frame, N)).unwrap();
    let tcp_path = tcp_file.path().to_owned();

    let mut udp_file = tempfile::Builder::new().suffix(".pcap").tempfile().unwrap();
    udp_file.write_all(&pcap_bytes(&udp_frame, N)).unwrap();
    let udp_path = udp_file.path().to_owned();

    let mut g = c.benchmark_group("file_capture");
    g.throughput(Throughput::Elements(N as u64));

    // Baseline: pcap format parsing + scratch-buffer copy, no filter.
    g.bench_function("unfiltered", |b| {
        b.iter(|| {
            let mut cap = Capture::from_file(&tcp_path).open().unwrap();
            let mut n = 0u32;
            while let Some(pkt) = cap.next().unwrap() {
                n += criterion::black_box(pkt.data().len()) as u32;
            }
            n
        })
    });

    // VM accept path: every packet matches "tcp".
    g.bench_function("filter_match_all", |b| {
        b.iter(|| {
            let mut cap = Capture::from_file(&tcp_path)
                .filter_program(tcp_prog.clone())
                .open()
                .unwrap();
            let mut n = 0u32;
            while let Some(pkt) = cap.next().unwrap() {
                n += criterion::black_box(pkt.data().len()) as u32;
            }
            n
        })
    });

    // VM reject path: no packet matches — shows early-exit cost and that the
    // parsed packets are still copied into scratch before the VM sees them.
    g.bench_function("filter_reject_all", |b| {
        b.iter(|| {
            let mut cap = Capture::from_file(&udp_path)
                .filter_program(tcp_prog.clone())
                .open()
                .unwrap();
            let mut n = 0u32;
            // None of the UDP packets match "tcp"; count reaches 0.
            while let Some(pkt) = cap.next().unwrap() {
                n += criterion::black_box(pkt.data().len()) as u32;
            }
            n
        })
    });

    g.finish();
}

// ── Dump write benchmark ──────────────────────────────────────────────────────

fn bench_dump_write(c: &mut Criterion) {
    let frame = eth_ipv4_tcp();
    let frame_len = frame.len() as u32;

    let packets: Vec<Packet> = (0..N)
        .map(|i| {
            Packet::new(
                frame.clone(),
                SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(i as u64),
                frame_len,
                LinkType::Ethernet,
            )
        })
        .collect();

    let mut g = c.benchmark_group("dump_write");
    g.throughput(Throughput::Elements(N as u64));

    g.bench_function("throughput", |b| {
        b.iter(|| {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("bench.pcap");
            let mut dump = Dump::to_file(&path)
                .link_type(LinkType::Ethernet)
                .open()
                .unwrap();
            for pkt in &packets {
                dump.write_packet(pkt.as_ref()).unwrap();
            }
        })
    });

    g.finish();
}

criterion_group!(benches, bench_packet, bench_file_capture, bench_dump_write);
criterion_main!(benches);
