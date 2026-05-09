//! eBPF codegen tests: verify instruction structure and bounds-check presence.
//!
//! These tests compile filters with `Target::Extended` and check that:
//! 1. Every program has a valid prologue and epilogue.
//! 2. Every packet read is preceded by a bounds-check `jgt_reg` instruction.
//! 3. Return values use XDP_PASS / XDP_DROP semantics.
//! 4. Logical combinators (AND, OR, NOT) produce non-empty programs.

use pktbaffle::ebpf::{
    Insn, BPF_ALU64, BPF_EXIT, BPF_JGT, BPF_JMP, BPF_K, BPF_LDX, BPF_MEM, BPF_MOV, BPF_W, BPF_X,
    R1, R2, R3, XDP_DROP, XDP_PASS,
};
use pktbaffle::{compile, LinkType, Target};

fn ebpf_eth(filter: &str) -> Vec<Insn> {
    compile(filter, LinkType::Ethernet, Target::Extended)
        .unwrap_or_else(|e| panic!("ebpf compile({filter:?}): {e}"))
        .as_extended()
        .expect("expected Extended program")
        .instructions()
        .to_vec()
}

fn ebpf_compile_err(filter: &str, link: LinkType) -> bool {
    compile(filter, link, Target::Extended).is_err()
}

// ── Prologue / epilogue structure ─────────────────────────────────────────────

// Every eBPF program must begin with two LDX_W instructions that load
// xdp_md->data and xdp_md->data_end from the context (R1).
#[test]
fn prologue_loads_data_and_data_end() {
    let prog = ebpf_eth("tcp");
    assert!(prog.len() >= 4, "program too short");

    let ldx_w_code = BPF_LDX | BPF_MEM | BPF_W;

    // insns[0]: r2 = *(u32 *)(r1 + 0)   — data
    assert_eq!(prog[0].code, ldx_w_code, "insns[0] must be LDX_W");
    assert_eq!(prog[0].dst(), R2);
    assert_eq!(prog[0].src(), R1);
    assert_eq!(prog[0].off, 0);

    // insns[1]: r3 = *(u32 *)(r1 + 4)   — data_end
    assert_eq!(prog[1].code, ldx_w_code, "insns[1] must be LDX_W");
    assert_eq!(prog[1].dst(), R3);
    assert_eq!(prog[1].src(), R1);
    assert_eq!(prog[1].off, 4);
}

// The last four instructions must be: mov r0=XDP_PASS, exit, mov r0=XDP_DROP, exit.
#[test]
fn epilogue_has_pass_and_drop_blocks() {
    let prog = ebpf_eth("tcp");
    let n = prog.len();
    assert!(n >= 4);

    let mov_k = BPF_ALU64 | BPF_MOV | BPF_K;
    let exit = BPF_JMP | BPF_EXIT;

    assert_eq!(prog[n - 4].code, mov_k, "n-4 must be MOV64_IMM (XDP_PASS)");
    assert_eq!(prog[n - 4].imm, XDP_PASS);
    assert_eq!(prog[n - 3].code, exit, "n-3 must be EXIT");
    assert_eq!(prog[n - 2].code, mov_k, "n-2 must be MOV64_IMM (XDP_DROP)");
    assert_eq!(prog[n - 2].imm, XDP_DROP);
    assert_eq!(prog[n - 1].code, exit, "n-1 must be EXIT");
}

// ── Bounds checks ──────────────────────────────────────────────────────────────

fn count_bounds_checks(prog: &[Insn]) -> usize {
    let jgt_reg = BPF_JMP | BPF_JGT | BPF_X;
    prog.iter()
        .filter(|i| i.code == jgt_reg && i.src() == R3)
        .count()
}

// Any filter that reads from the packet must emit at least one bounds check.
#[test]
fn tcp_has_bounds_checks() {
    let prog = ebpf_eth("tcp");
    assert!(
        count_bounds_checks(&prog) >= 1,
        "tcp program must have bounds checks"
    );
}

#[test]
fn host_has_bounds_checks() {
    let prog = ebpf_eth("host 192.168.1.1");
    assert!(count_bounds_checks(&prog) >= 1);
}

#[test]
fn port_has_bounds_checks() {
    let prog = ebpf_eth("tcp port 80");
    assert!(
        count_bounds_checks(&prog) >= 2,
        "port program needs ≥2 bounds checks"
    );
}

#[test]
fn ether_host_has_bounds_checks() {
    let prog = ebpf_eth("ether host aa:bb:cc:dd:ee:ff");
    assert!(count_bounds_checks(&prog) >= 2);
}

// Length comparison accesses no packet bytes; only computes data_end - data.
#[test]
fn len_filter_no_packet_bounds_check() {
    let prog = ebpf_eth("less 64");
    // No LDX-based bounds check needed (arithmetic only).
    assert_eq!(count_bounds_checks(&prog), 0);
}

// ── Primitives compile and produce non-trivial programs ───────────────────────

#[test]
fn proto_keywords_compile() {
    for filter in &["tcp", "udp", "icmp", "arp", "ip", "ip6"] {
        let prog = ebpf_eth(filter);
        assert!(prog.len() > 4, "{filter}: program too short");
    }
}

#[test]
fn port_filters_compile() {
    for filter in &[
        "port 80",
        "tcp port 443",
        "udp port 53",
        "portrange 1024-65535",
    ] {
        let prog = ebpf_eth(filter);
        assert!(prog.len() > 6, "{filter}: program too short");
    }
}

#[test]
fn host_filters_compile() {
    for filter in &["host 1.2.3.4", "src host 10.0.0.1", "dst host 10.0.0.2"] {
        let prog = ebpf_eth(filter);
        assert!(prog.len() > 4, "{filter}: program too short");
    }
}

#[test]
fn net_filter_compiles() {
    let prog = ebpf_eth("net 10.0.0.0/8");
    assert!(prog.len() > 4);
}

#[test]
fn vlan_filter_compiles() {
    let prog = ebpf_eth("vlan 100");
    assert!(prog.len() > 4);
    assert!(count_bounds_checks(&prog) >= 2);
}

#[test]
fn mpls_filter_compiles() {
    let prog = ebpf_eth("mpls");
    assert!(prog.len() > 4);
}

#[test]
fn len_comparisons_compile() {
    for filter in &[
        "less 64",
        "greater 1500",
        "len = 60",
        "len != 60",
        "len > 1000",
        "len >= 1000",
        "len < 64",
        "len <= 64",
    ] {
        let prog = ebpf_eth(filter);
        // Prologue (2) + comparison (≥1) + epilogue (4) = ≥7
        assert!(
            prog.len() >= 7,
            "{filter}: program too short (got {})",
            prog.len()
        );
    }
}

#[test]
fn byte_access_tcp_syn_compiles() {
    let prog = ebpf_eth("tcp[13] & 0x02 != 0");
    assert!(prog.len() > 6);
    assert!(count_bounds_checks(&prog) >= 1);
}

#[test]
fn ether_multicast_compiles() {
    let prog = ebpf_eth("ether multicast");
    assert!(prog.len() > 4);
    assert!(count_bounds_checks(&prog) >= 1);
}

#[test]
fn ip_broadcast_compiles() {
    let prog = ebpf_eth("ip broadcast");
    assert!(prog.len() > 4);
}

#[test]
fn ip_multicast_compiles() {
    let prog = ebpf_eth("ip multicast");
    assert!(prog.len() > 4);
}

#[test]
fn ip6_multicast_compiles() {
    let prog = ebpf_eth("ip6 multicast");
    assert!(prog.len() > 4);
}

// ── Logical combinators ────────────────────────────────────────────────────────

#[test]
fn and_combinator_compiles() {
    let prog = ebpf_eth("tcp and port 80");
    assert!(prog.len() > 6);
}

#[test]
fn or_combinator_compiles() {
    let prog = ebpf_eth("tcp or udp");
    assert!(prog.len() > 6);
}

#[test]
fn not_combinator_compiles() {
    let prog = ebpf_eth("not arp");
    assert!(prog.len() > 4);
}

#[test]
fn complex_expression_compiles() {
    let prog = ebpf_eth("(tcp or udp) and port 53");
    assert!(prog.len() > 8);
}

// ── Error cases ────────────────────────────────────────────────────────────────

#[test]
fn inbound_is_error() {
    assert!(ebpf_compile_err("inbound", LinkType::Ethernet));
}

#[test]
fn outbound_is_error() {
    assert!(ebpf_compile_err("outbound", LinkType::Ethernet));
}

#[test]
fn rawip_ether_host_is_error() {
    assert!(ebpf_compile_err(
        "ether host aa:bb:cc:dd:ee:ff",
        LinkType::RawIp
    ));
}

// ── RawIp and LinuxSll link types ─────────────────────────────────────────────

#[test]
fn rawip_host_compiles() {
    let prog = compile("host 192.168.1.1", LinkType::RawIp, Target::Extended)
        .unwrap()
        .as_extended()
        .unwrap()
        .instructions()
        .to_vec();
    assert!(prog.len() > 4);
    assert!(count_bounds_checks(&prog) >= 1);
}

#[test]
fn linuxsll_tcp_port_compiles() {
    let prog = compile("tcp port 443", LinkType::LinuxSll, Target::Extended)
        .unwrap()
        .as_extended()
        .unwrap()
        .instructions()
        .to_vec();
    assert!(prog.len() > 6);
}

// ── to_le_bytes encoding ──────────────────────────────────────────────────────

#[test]
fn to_le_bytes_length_matches_instruction_count() {
    let prog = compile("tcp port 80", LinkType::Ethernet, Target::Extended).unwrap();
    assert_eq!(prog.to_le_bytes().len(), prog.len() * 8);
}

// ── Target enum distinguishes programs ────────────────────────────────────────

#[test]
fn classic_program_has_no_extended() {
    let prog = compile("tcp", LinkType::Ethernet, Target::Classic).unwrap();
    assert!(prog.as_classic().is_some());
    assert!(prog.as_extended().is_none());
}

#[test]
fn extended_program_has_no_classic() {
    let prog = compile("tcp", LinkType::Ethernet, Target::Extended).unwrap();
    assert!(prog.as_extended().is_some());
    assert!(prog.as_classic().is_none());
}
