//! Criterion benchmark suite for pkttap capture throughput and latency.
//!
//! Run with:
//!     cargo bench -p pkttap
//!
//! HTML reports are written to `target/criterion/`.
//!
//! # What each benchmark measures
//!
//! - `file_capture_throughput`  — iterates all packets from a 1 000-packet
//!   synthetic pcap file; measures raw file-read + scratch-buffer copy rate.
//!
//! - `file_capture_with_filter` — same pcap file but with a "tcp" BPF filter
//!   applied in the pktbaffle software VM; measures filter-VM overhead on top
//!   of the base read rate.
//!
//! - `dump_write_throughput`    — writes 1 000 synthetic packets to a temp
//!   pcap file; measures write-path overhead (pcap-file serialisation + OS I/O).
//!
//! - `packet_construction`      — calls `Packet::new` once per iteration with
//!   a 60-byte frame; isolates per-packet `Vec` allocation cost.
//!
//! - `filter_compilation`       — compiles a representative filter expression
//!   via `pktbaffle::compile`; measures the front-end (parse + codegen) cost.

use std::io::Write as _;
use std::time::SystemTime;

use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use pkttap::{Capture, Dump, LinkType, Packet};

// ── Packet / pcap byte builders (duplicated from tests/common — benches cannot
// import integration-test modules) ────────────────────────────────────────────

fn eth_tcp_frame() -> Vec<u8> {
    // Minimal valid Ethernet/IPv4/TCP frame (54 bytes)
    let mut f = vec![
        // Ethernet header (14 bytes)
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // dst MAC
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // src MAC
        0x08, 0x00, // EtherType: IPv4
        // IPv4 header (20 bytes, IHL=5, protocol=TCP=6)
        0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 0xc0, 0xa8, 0x01,
        0x01, // src 192.168.1.1
        0x0a, 0x00, 0x00, 0x01, // dst 10.0.0.1
        // TCP header (20 bytes)
        0x30, 0x39, // src port 12345
        0x00, 0x50, // dst port 80
        0x00, 0x00, 0x00, 0x00, // seq
        0x00, 0x00, 0x00, 0x00, // ack
        0x50, 0x02, // data offset=5, SYN flag
        0xff, 0xff, // window
        0x00, 0x00, // checksum
        0x00, 0x00, // urgent
    ];
    // Pad to 60 bytes (minimum Ethernet frame size)
    f.resize(60, 0u8);
    f
}

/// Write a minimal, self-consistent pcap file into `buf`.
/// Builds N copies of `frame` as separate packet records.
fn write_pcap_bytes(buf: &mut Vec<u8>, frame: &[u8], count: usize) {
    // Global header
    buf.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes()); // magic
    buf.extend_from_slice(&2u16.to_le_bytes()); // major
    buf.extend_from_slice(&4u16.to_le_bytes()); // minor
    buf.extend_from_slice(&0i32.to_le_bytes()); // GMT offset
    buf.extend_from_slice(&0u32.to_le_bytes()); // accuracy
    buf.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
    buf.extend_from_slice(&1u32.to_le_bytes()); // DLT_EN10MB

    for i in 0..count {
        let ts_sec = i as u32;
        buf.extend_from_slice(&ts_sec.to_le_bytes()); // ts_sec
        buf.extend_from_slice(&0u32.to_le_bytes()); // ts_usec
        buf.extend_from_slice(&(frame.len() as u32).to_le_bytes()); // incl_len
        buf.extend_from_slice(&(frame.len() as u32).to_le_bytes()); // orig_len
        buf.extend_from_slice(frame);
    }
}

const BENCH_PACKET_COUNT: usize = 1_000;

// ── Benchmark 1: file capture throughput ─────────────────────────────────────

fn bench_file_capture_throughput(c: &mut Criterion) {
    let frame = eth_tcp_frame();
    let mut pcap_data = Vec::new();
    write_pcap_bytes(&mut pcap_data, &frame, BENCH_PACKET_COUNT);

    // Write to a named temp file once; re-read it on every iteration.
    let mut tmp = tempfile::Builder::new().suffix(".pcap").tempfile().unwrap();
    tmp.write_all(&pcap_data).unwrap();
    let path = tmp.path().to_owned();

    let mut group = c.benchmark_group("file_capture");
    group.throughput(Throughput::Elements(BENCH_PACKET_COUNT as u64));

    group.bench_function("throughput", |b| {
        b.iter(|| {
            let mut cap = Capture::from_file(&path).open().unwrap();
            let mut count = 0u64;
            while let Some(pkt) = cap.next().unwrap() {
                let _ = criterion::black_box(pkt.data().len());
                count += 1;
            }
            count
        })
    });

    group.finish();
}

// ── Benchmark 2: file capture with BPF filter ─────────────────────────────────

fn bench_file_capture_with_filter(c: &mut Criterion) {
    let frame = eth_tcp_frame();
    let mut pcap_data = Vec::new();
    write_pcap_bytes(&mut pcap_data, &frame, BENCH_PACKET_COUNT);

    let mut tmp = tempfile::Builder::new().suffix(".pcap").tempfile().unwrap();
    tmp.write_all(&pcap_data).unwrap();
    let path = tmp.path().to_owned();

    let mut group = c.benchmark_group("file_capture");
    group.throughput(Throughput::Elements(BENCH_PACKET_COUNT as u64));

    group.bench_function("with_filter_tcp", |b| {
        b.iter(|| {
            let mut cap = Capture::from_file(&path).filter("tcp").open().unwrap();
            let mut count = 0u64;
            while let Some(pkt) = cap.next().unwrap() {
                let _ = criterion::black_box(pkt.data().len());
                count += 1;
            }
            count
        })
    });

    group.finish();
}

// ── Benchmark 3: dump write throughput ───────────────────────────────────────

fn bench_dump_write_throughput(c: &mut Criterion) {
    let frame = eth_tcp_frame();
    let frame_len = frame.len();

    // Pre-build the packets once; the benchmark re-writes them each iteration.
    let packets: Vec<Packet> = (0..BENCH_PACKET_COUNT)
        .map(|i| {
            Packet::new(
                frame.clone(),
                SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(i as u64),
                frame_len as u32,
                LinkType::Ethernet,
            )
        })
        .collect();

    let mut group = c.benchmark_group("dump_write");
    group.throughput(Throughput::Elements(BENCH_PACKET_COUNT as u64));

    group.bench_function("throughput", |b| {
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

    group.finish();
}

// ── Benchmark 4: packet construction (allocation overhead) ───────────────────

fn bench_packet_construction(c: &mut Criterion) {
    let frame = eth_tcp_frame();
    let frame_len = frame.len() as u32;

    c.bench_function("packet_construction", |b| {
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
}

// ── Benchmark 5: filter compilation cost ─────────────────────────────────────

fn bench_filter_compilation(c: &mut Criterion) {
    use pktbaffle::{compile, Target};
    use pkttap::LinkType;

    // A representative, moderately-complex filter expression
    let expr = "tcp port 443 or (udp port 53 and src net 192.168.0.0/16)";

    c.bench_function("filter_compilation", |b| {
        b.iter(|| criterion::black_box(compile(expr, LinkType::Ethernet, Target::Classic).unwrap()))
    });
}

// ── Criterion entry point ─────────────────────────────────────────────────────

criterion_group!(
    benches,
    bench_file_capture_throughput,
    bench_file_capture_with_filter,
    bench_dump_write_throughput,
    bench_packet_construction,
    bench_filter_compilation,
);
criterion_main!(benches);
