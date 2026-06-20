//! Criterion benchmarks for the pktbaffle compilation pipeline.
//!
//! Run with:
//!   cargo bench -p pktbaffle --bench compiler
//!
//! HTML reports land in `target/criterion/`.
//!
//! # What is measured
//!
//! `parse` — lexing + AST construction only (no codegen).  Measures the front-end
//! cost in isolation; useful for tools that inspect or transform the AST before
//! choosing a target.
//!
//! `cbpf` — full classic-BPF pipeline: lex → parse → codegen → optimizer.
//! This is the cost paid at startup by any tool that calls `compile(...,
//! Target::Classic)`.  Three complexity levels show how codegen and optimizer
//! time scale with filter depth and the number of conjuncts/disjuncts.
//!
//! `ebpf` — same pipeline targeting eBPF (XDP/TC). No optimizer pass runs for
//! eBPF; the cost difference vs. cbpf reflects the additional bounds-check
//! instructions the eBPF backend emits and the absence of the peephole pass.
//!
//! # Filter expressions used
//!
//! | Label          | Expression                                                              | Why interesting |
//! |----------------|-------------------------------------------------------------------------|-----------------|
//! | simple         | `tcp`                                                                   | Minimal program; latency floor |
//! | medium         | `tcp port 80`                                                           | Requires X-register for transport offset |
//! | complex        | `tcp port 443 or (udp port 53 and src net 192.168.0.0/16)`             | OR + AND + net mask; exercises fact hoisting |
//! | boolean_chain  | `tcp and not port 22 and not port 23 and src host 192.168.1.100`       | Long AND chain; measures path-fact tracking benefit |

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use pktbaffle::codegen::LinkType;
use pktbaffle::{compile, parse, Target};

const SIMPLE: &str = "tcp";
const MEDIUM: &str = "tcp port 80";
const COMPLEX: &str = "tcp port 443 or (udp port 53 and src net 192.168.0.0/16)";
const BOOLEAN_CHAIN: &str = "tcp and not port 22 and not port 23 and src host 192.168.1.100";

fn bench_parse(c: &mut Criterion) {
    let mut g = c.benchmark_group("parse");
    for (label, expr) in [
        ("simple", SIMPLE),
        ("medium", MEDIUM),
        ("complex", COMPLEX),
        ("boolean_chain", BOOLEAN_CHAIN),
    ] {
        g.bench_with_input(BenchmarkId::from_parameter(label), &expr, |b, &expr| {
            b.iter(|| parse(criterion::black_box(expr)).unwrap())
        });
    }
    g.finish();
}

fn bench_cbpf(c: &mut Criterion) {
    let mut g = c.benchmark_group("cbpf");
    for (label, expr) in [
        ("simple", SIMPLE),
        ("medium", MEDIUM),
        ("complex", COMPLEX),
        ("boolean_chain", BOOLEAN_CHAIN),
    ] {
        g.bench_with_input(BenchmarkId::from_parameter(label), &expr, |b, &expr| {
            b.iter(|| {
                compile(
                    criterion::black_box(expr),
                    LinkType::Ethernet,
                    Target::Classic,
                )
                .unwrap()
            })
        });
    }
    g.finish();
}

fn bench_ebpf(c: &mut Criterion) {
    let mut g = c.benchmark_group("ebpf");
    for (label, expr) in [
        ("simple", SIMPLE),
        ("complex", COMPLEX),
        ("boolean_chain", BOOLEAN_CHAIN),
    ] {
        g.bench_with_input(BenchmarkId::from_parameter(label), &expr, |b, &expr| {
            b.iter(|| {
                compile(
                    criterion::black_box(expr),
                    LinkType::Ethernet,
                    Target::Extended,
                )
                .unwrap()
            })
        });
    }
    g.finish();
}

criterion_group!(benches, bench_parse, bench_cbpf, bench_ebpf);
criterion_main!(benches);
