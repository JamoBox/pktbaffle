//! Criterion benchmarks for the pktbaffle software BPF virtual machine.
//!
//! Run with:
//!   cargo bench -p pktbaffle --bench vm --features vm
//!
//! HTML reports land in `target/criterion/`.
//!
//! # What is measured
//!
//! The software VM (`vm::run`) is the hot path for any userspace filter —
//! including every packet read by pkttap from a file.  These benchmarks
//! are deliberately IO-free: the compiled program and synthetic packet bytes
//! live entirely in memory, so the numbers reflect pure CPU cost.
//!
//! Two families of benchmarks are provided:
//!
//! `filter` — single-packet pass/fail decisions.  Accept and reject paths are
//! benchmarked separately because the two can differ materially: the codegen
//! emits guards that short-circuit early on the reject path (ethertype check
//! before protocol check, etc.).
//!
//! `throughput` — runs the filter over a 1 000-packet mixed stream (50% TCP
//! match, 50% UDP non-match) and reports the result as packets/sec.  This
//! reflects realistic workloads where the CPU branch predictor sees a mix of
//! outcomes.
//!
//! # Filters and packets used
//!
//! | Scenario       | Filter                                                  | Packet                        | Expected |
//! |----------------|---------------------------------------------------------|-------------------------------|----------|
//! | simple/accept  | `tcp`                                                   | Ethernet/IPv4/TCP SYN (60 B)  | true     |
//! | simple/reject  | `tcp`                                                   | Ethernet/IPv4/UDP (42 B)      | false    |
//! | complex/accept | `tcp port 443 or (udp port 53 and src 192.168.0.0/16)` | TCP dst=443                   | true     |
//! | complex/reject | same                                                    | ARP frame                     | false    |

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use pktbaffle::codegen::LinkType;
use pktbaffle::{compile, Target};

// ── Synthetic packet builders ─────────────────────────────────────────────────

fn eth_ipv4_tcp(src_port: u16, dst_port: u16) -> Vec<u8> {
    let mut f = vec![
        // Ethernet header (14 bytes)
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff, // dst MAC
        0x00,
        0x11,
        0x22,
        0x33,
        0x44,
        0x55, // src MAC
        0x08,
        0x00, // EtherType IPv4
        // IPv4 header (20 bytes): IHL=5, proto=6 (TCP), src=192.168.0.1, dst=10.0.0.1
        0x45,
        0x00,
        0x00,
        0x28,
        0x00,
        0x01,
        0x00,
        0x00,
        0x40,
        0x06,
        0x00,
        0x00,
        0xc0,
        0xa8,
        0x00,
        0x01, // src 192.168.0.1
        0x0a,
        0x00,
        0x00,
        0x01, // dst 10.0.0.1
        // TCP header (20 bytes)
        (src_port >> 8) as u8,
        src_port as u8,
        (dst_port >> 8) as u8,
        dst_port as u8,
        0x00,
        0x00,
        0x00,
        0x01, // seq
        0x00,
        0x00,
        0x00,
        0x00, // ack
        0x50,
        0x02, // data offset=5, SYN
        0xff,
        0xff,
        0x00,
        0x00, // window, checksum
        0x00,
        0x00, // urgent
    ];
    f.resize(60, 0u8);
    f
}

fn eth_ipv4_udp(src_port: u16, dst_port: u16) -> Vec<u8> {
    vec![
        // Ethernet header (14 bytes)
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff, // dst MAC
        0x00,
        0x11,
        0x22,
        0x33,
        0x44,
        0x55, // src MAC
        0x08,
        0x00, // EtherType IPv4
        // IPv4 header (20 bytes): IHL=5, proto=17 (UDP), src=192.168.0.1, dst=10.0.0.1
        0x45,
        0x00,
        0x00,
        0x1c,
        0x00,
        0x02,
        0x00,
        0x00,
        0x40,
        0x11,
        0x00,
        0x00,
        0xc0,
        0xa8,
        0x00,
        0x01, // src 192.168.0.1
        0x0a,
        0x00,
        0x00,
        0x01, // dst 10.0.0.1
        // UDP header (8 bytes)
        (src_port >> 8) as u8,
        src_port as u8,
        (dst_port >> 8) as u8,
        dst_port as u8,
        0x00,
        0x08, // length
        0x00,
        0x00, // checksum
    ]
}

fn eth_arp() -> Vec<u8> {
    let mut f = vec![
        // Ethernet header (14 bytes)
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // dst MAC (broadcast)
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // src MAC
        0x08, 0x06, // EtherType ARP
    ];
    // Minimal ARP payload (28 bytes)
    f.extend_from_slice(&[0u8; 28]);
    f
}

// ── Compile helpers ───────────────────────────────────────────────────────────

fn cbpf(expr: &str) -> pktbaffle::bpf::Program {
    let prog = compile(expr, LinkType::Ethernet, Target::Classic).unwrap();
    prog.as_classic().unwrap().clone()
}

// ── Benchmarks ────────────────────────────────────────────────────────────────

fn bench_filter(c: &mut Criterion) {
    let tcp_prog = cbpf("tcp");
    let complex_prog = cbpf("tcp port 443 or (udp port 53 and src net 192.168.0.0/16)");

    let tcp_pkt = eth_ipv4_tcp(12345, 443);
    let udp_pkt = eth_ipv4_udp(12345, 53);
    let arp_pkt = eth_arp();

    let cases: &[(&str, &pktbaffle::bpf::Program, &[u8], bool)] = &[
        ("simple/accept", &tcp_prog, &tcp_pkt, true),
        ("simple/reject", &tcp_prog, &udp_pkt, false),
        ("complex/accept", &complex_prog, &tcp_pkt, true),
        ("complex/reject", &complex_prog, &arp_pkt, false),
    ];

    let mut g = c.benchmark_group("filter");
    for &(label, prog, pkt, expected) in cases {
        g.bench_with_input(
            BenchmarkId::from_parameter(label),
            &(prog, pkt),
            |b, &(prog, pkt)| {
                b.iter(|| {
                    let result = prog.matches(criterion::black_box(pkt));
                    assert_eq!(result, expected);
                    result
                })
            },
        );
    }
    g.finish();
}

fn bench_throughput(c: &mut Criterion) {
    const N: usize = 1_000;

    // 500 TCP (matching) + 500 UDP (non-matching) interleaved
    let packets: Vec<Vec<u8>> = (0..N)
        .map(|i| {
            if i % 2 == 0 {
                eth_ipv4_tcp(i as u16 + 1024, 80)
            } else {
                eth_ipv4_udp(i as u16 + 1024, 80)
            }
        })
        .collect();

    let prog = cbpf("tcp");

    let mut g = c.benchmark_group("throughput");
    g.throughput(Throughput::Elements(N as u64));
    g.bench_function("mixed_1000", |b| {
        b.iter(|| {
            let mut accepted = 0u32;
            for pkt in &packets {
                if prog.matches(criterion::black_box(pkt)) {
                    accepted += 1;
                }
            }
            criterion::black_box(accepted)
        })
    });
    g.finish();
}

criterion_group!(benches, bench_filter, bench_throughput);
criterion_main!(benches);
