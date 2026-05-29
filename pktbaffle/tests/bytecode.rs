//! Bytecode-level tests: verify exact BPF instruction sequences.
//!
//! These tests pin the precise opcode, jump offsets, and immediate values
//! produced by the compiler. They exist alongside the compile-shape tests in
//! integration.rs, which only check that programs end with accept/drop.
//!
//! Opcode constants are computed from the BPF building blocks in bpf.rs.

use pktbaffle::bpf::Insn;
use pktbaffle::optimizer::dedup_loads;
use pktbaffle::{compile, LinkType, Target};

// ── derived opcode constants ─────────────────────────────────────────────────
// BPF_LD=0x00, BPF_LDX=0x01, BPF_ALU=0x04, BPF_JMP=0x05, BPF_RET=0x06
// BPF_W=0x00, BPF_H=0x08, BPF_B=0x10
// BPF_ABS=0x20, BPF_IND=0x40, BPF_LEN=0x80, BPF_MSH=0xa0
// BPF_AND=0x50, BPF_RSH=0x70
// BPF_JEQ=0x10, BPF_JGT=0x20, BPF_JGE=0x30, BPF_JSET=0x40, BPF_K=0x00

const LDH_ABS: u16 = 0x28; // BPF_LD | BPF_H | BPF_ABS
const LDB_ABS: u16 = 0x30; // BPF_LD | BPF_B | BPF_ABS
const LDW_ABS: u16 = 0x20; // BPF_LD | BPF_W | BPF_ABS
const LDH_IND: u16 = 0x48; // BPF_LD | BPF_H | BPF_IND
const LDB_IND: u16 = 0x50; // BPF_LD | BPF_B | BPF_IND
const LDX_MSH: u16 = 0xb1; // BPF_LDX | BPF_B | BPF_MSH
const LDX_IMM: u16 = 0x01; // BPF_LDX | BPF_W | BPF_IMM
const LD_LEN: u16 = 0x80; // BPF_LD | BPF_W | BPF_LEN
const AND_K: u16 = 0x54; // BPF_ALU | BPF_AND | BPF_K
const RSH_K: u16 = 0x74; // BPF_ALU | BPF_RSH | BPF_K
const JA: u16 = 0x05; // BPF_JMP | BPF_JA
const JEQ_K: u16 = 0x15; // BPF_JMP | BPF_JEQ | BPF_K
const JGT_K: u16 = 0x25; // BPF_JMP | BPF_JGT | BPF_K
const JGE_K: u16 = 0x35; // BPF_JMP | BPF_JGE | BPF_K
const JSET_K: u16 = 0x45; // BPF_JMP | BPF_JSET | BPF_K
const RET_K: u16 = 0x06; // BPF_RET | BPF_K

const ACCEPT: u32 = 0xffff_ffff;
const DROP: u32 = 0;

fn insn(code: u16, jt: u8, jf: u8, k: u32) -> Insn {
    Insn { code, jt, jf, k }
}

fn eth(filter: &str) -> Vec<Insn> {
    compile(filter, LinkType::Ethernet, Target::Classic)
        .unwrap_or_else(|e| panic!("compile({filter:?}): {e}"))
        .instructions()
        .to_vec()
}

// ── less / greater semantics ─────────────────────────────────────────────────

// `less 64` means len <= 64:  fail if len > 64  →  JGT_K with jt→DROP
#[test]
fn less_64_uses_jgt_jt_drop() {
    let prog = eth("less 64");
    assert_eq!(
        prog,
        vec![
            insn(LD_LEN, 0, 0, 0),
            insn(JGT_K, 1, 0, 64), // jt=1 → DROP at [3]
            insn(RET_K, 0, 0, ACCEPT),
            insn(RET_K, 0, 0, DROP),
        ]
    );
}

// `greater 1500` means len >= 1500: fail if len < 1500  →  JGE_K with jf→DROP
#[test]
fn greater_1500_uses_jge_jf_drop() {
    let prog = eth("greater 1500");
    assert_eq!(
        prog,
        vec![
            insn(LD_LEN, 0, 0, 0),
            insn(JGE_K, 0, 1, 1500), // jf=1 → DROP at [3]
            insn(RET_K, 0, 0, ACCEPT),
            insn(RET_K, 0, 0, DROP),
        ]
    );
}

// ── ether multicast ──────────────────────────────────────────────────────────

// Check bit 0 of destination MAC first byte (offset 0).
#[test]
fn ether_multicast_checks_bit0_of_dst_mac() {
    let prog = eth("ether multicast");
    assert_eq!(
        prog,
        vec![
            insn(LDB_ABS, 0, 0, 0),   // load byte at offset 0 (dst MAC[0])
            insn(JSET_K, 0, 1, 0x01), // jt=fall-through (accept), jf=1→DROP
            insn(RET_K, 0, 0, ACCEPT),
            insn(RET_K, 0, 0, DROP),
        ]
    );
}

// ── ip broadcast / multicast ─────────────────────────────────────────────────

// `ip broadcast` checks destination IP == 255.255.255.255.
#[test]
fn ip_broadcast_checks_destination_ip() {
    let prog = eth("ip broadcast");
    // [0] ldh[12]   — IPv4 guard
    // [1] jeq 0x800 jt=0 jf→DROP
    // [2] ldw[30]   — dst IP (14+16)
    // [3] jeq 0xffffffff jt=0 jf→DROP
    // [4] ACCEPT
    // [5] DROP
    assert_eq!(prog[0], insn(LDH_ABS, 0, 0, 12));
    assert_eq!(prog[1].code, JEQ_K);
    assert_eq!(prog[1].k, 0x0800);
    assert_eq!(prog[2], insn(LDW_ABS, 0, 0, 30));
    assert_eq!(prog[3].code, JEQ_K);
    assert_eq!(prog[3].k, 0xffff_ffff);
    assert_eq!(prog[4], insn(RET_K, 0, 0, ACCEPT));
    assert_eq!(prog[5], insn(RET_K, 0, 0, DROP));
    assert_eq!(prog.len(), 6);
}

// `ip multicast` must AND the dest IP with 0xf0000000 and compare to 0xe0000000.
#[test]
fn ip_multicast_masks_and_compares_224_block() {
    let prog = eth("ip multicast");
    // [0] ldh[12]
    // [1] jeq 0x800
    // [2] ldw[30]
    // [3] and 0xf0000000
    // [4] jeq 0xe0000000
    // [5] ACCEPT  [6] DROP
    assert_eq!(prog[2], insn(LDW_ABS, 0, 0, 30));
    assert_eq!(prog[3], insn(AND_K, 0, 0, 0xf000_0000));
    assert_eq!(prog[4].code, JEQ_K);
    assert_eq!(prog[4].k, 0xe000_0000);
    assert_eq!(prog.len(), 7);
}

// `ip6 multicast` checks first byte of IPv6 destination == 0xff.
#[test]
fn ip6_multicast_checks_first_dest_byte() {
    let prog = eth("ip6 multicast");
    // [0] ldh[12]
    // [1] jeq 0x86dd
    // [2] ldb[38]   — IPv6 dst at net_offset(14)+24=38
    // [3] jeq 0xff
    // [4] ACCEPT  [5] DROP
    assert_eq!(prog[0], insn(LDH_ABS, 0, 0, 12));
    assert_eq!(prog[1].code, JEQ_K);
    assert_eq!(prog[1].k, 0x86dd);
    assert_eq!(prog[2], insn(LDB_ABS, 0, 0, 38));
    assert_eq!(prog[3].code, JEQ_K);
    assert_eq!(prog[3].k, 0xff);
    assert_eq!(prog[4], insn(RET_K, 0, 0, ACCEPT));
    assert_eq!(prog[5], insn(RET_K, 0, 0, DROP));
    assert_eq!(prog.len(), 6);
}

// ── VLAN ─────────────────────────────────────────────────────────────────────

#[test]
fn vlan_any_checks_ethertype_8100() {
    let prog = eth("vlan");
    assert_eq!(
        prog,
        vec![
            insn(LDH_ABS, 0, 0, 12),
            insn(JEQ_K, 0, 1, 0x8100),
            insn(RET_K, 0, 0, ACCEPT),
            insn(RET_K, 0, 0, DROP),
        ]
    );
}

// `vlan 100` must mask TCI with 0x0fff before comparing the 12-bit VLAN ID.
#[test]
fn vlan_with_id_masks_tci() {
    let prog = eth("vlan 100");
    // [0] ldh[12], [1] jeq 0x8100 jf→[6=DROP]
    // [2] ldh[14], [3] and 0x0fff, [4] jeq 100 jf→[6=DROP]
    // [5] ACCEPT, [6] DROP
    assert_eq!(prog[0], insn(LDH_ABS, 0, 0, 12));
    assert_eq!(prog[1].code, JEQ_K);
    assert_eq!(prog[1].k, 0x8100);
    assert_eq!(prog[1].jf, 4); // skip [2,3,4,5] to DROP at [6]
    assert_eq!(prog[2], insn(LDH_ABS, 0, 0, 14));
    assert_eq!(prog[3], insn(AND_K, 0, 0, 0x0fff));
    assert_eq!(prog[4].code, JEQ_K);
    assert_eq!(prog[4].k, 100);
    assert_eq!(prog[5], insn(RET_K, 0, 0, ACCEPT));
    assert_eq!(prog[6], insn(RET_K, 0, 0, DROP));
    assert_eq!(prog.len(), 7);
}

// ── MPLS ─────────────────────────────────────────────────────────────────────

// `mpls` must accept both unicast (0x8847) AND multicast (0x8848) ethertypes.
#[test]
fn mpls_any_accepts_both_ethertypes() {
    let prog = eth("mpls");
    // [0] ldh[12]
    // [1] jeq 0x8847 jt→ACCEPT
    // [2] jeq 0x8848 jt=0 (fall-through to ACCEPT), jf→DROP
    // [3] ACCEPT, [4] DROP
    assert_eq!(prog[0], insn(LDH_ABS, 0, 0, 12));
    assert_eq!(prog[1].code, JEQ_K);
    assert_eq!(prog[1].k, 0x8847);
    assert_eq!(prog[1].jt, 1); // jt → ACCEPT at [3]
    assert_eq!(prog[2].code, JEQ_K);
    assert_eq!(prog[2].k, 0x8848);
    assert_eq!(prog[2].jt, 0); // jt → fall through to ACCEPT at [3]
    assert_eq!(prog[3], insn(RET_K, 0, 0, ACCEPT));
    assert_eq!(prog[4], insn(RET_K, 0, 0, DROP));
    assert_eq!(prog.len(), 5);
}

// `mpls 12345` checks the top-20-bit label via RSH 12.
#[test]
fn mpls_with_label_uses_rsh_12() {
    let prog = eth("mpls 12345");
    // [0] ldh[12], [1] jeq 0x8847, [2] jeq 0x8848
    // [3] ldw[14], [4] rsh 12, [5] jeq 12345
    // [6] ACCEPT, [7] DROP
    assert_eq!(prog[3], insn(LDW_ABS, 0, 0, 14));
    assert_eq!(prog[4], insn(RSH_K, 0, 0, 12));
    assert_eq!(prog[5].code, JEQ_K);
    assert_eq!(prog[5].k, 12345);
    assert_eq!(prog.len(), 8);
}

// ── port 80 bug fix ──────────────────────────────────────────────────────────

// Critical regression guard: `port 80` with no proto qualifier must not treat
// the TCP protocol-match shortcut as an ACCEPT jump. The TCP jeq's jt field
// must point to the fragment check (ldh ip[6:2]), NOT to ACCEPT.
//
// New layout with IPv4+IPv6 dual-path and fragmentation guard (20 instructions):
//  [0]  ldh[12]          — ethertype
//  [1]  jeq 0x86dd jt→[10] — branch to IPv6 path
//  [2]  jeq 0x0800 jf→DROP — IPv4 check
//  [3]  ldb[23]          — IPv4 protocol
//  [4]  jeq 6, jt=1      — TCP: skip [5] to [6]=frag check
//  [5]  jeq 17 jf→DROP   — UDP check
//  [6]  ldh[20]          — IP flags + fragment offset
//  [7]  jset 0x1fff jt→DROP — non-first fragment → drop
//  [8]  ldxb 4*([14]&0xf) — MSH: X = IHL*4
//  [9]  ja → [14]        — skip IPv6 section
//  [10] ldb[20]          — IPv6 next-header
//  [11] jeq 6, jt=1      — TCP: skip [12] to [13]=ldx
//  [12] jeq 17 jf→DROP   — UDP check
//  [13] ldx #40          — X = IPv6 header length (fixed)
//  [14] ldh[x+14]        — src port
//  [15] jeq 80 jt→ACCEPT
//  [16] ldh[x+16]        — dst port
//  [17] jeq 80 jf→DROP
//  [18] ACCEPT  [19] DROP
#[test]
fn port_no_proto_tcp_shortcut_resolves_to_frag_check_not_accept() {
    let prog = eth("port 80");
    assert_eq!(prog.len(), 20, "port 80 must compile to 20 instructions");

    // Ethertype section.
    assert_eq!(prog[0], insn(LDH_ABS, 0, 0, 12));
    assert_eq!(prog[1].code, JEQ_K);
    assert_eq!(prog[1].k, 0x86dd);
    assert_eq!(prog[2].code, JEQ_K);
    assert_eq!(prog[2].k, 0x0800);

    // IPv4 protocol check: TCP jeq (jt skips UDP check to land on frag check).
    assert_eq!(prog[3], insn(LDB_ABS, 0, 0, 23));
    assert_eq!(prog[4].code, JEQ_K);
    assert_eq!(prog[4].k, 6);
    assert_eq!(
        prog[4].jt, 1,
        "TCP shortcut must skip UDP check, not jump to ACCEPT"
    );
    assert_eq!(prog[5].code, JEQ_K);
    assert_eq!(prog[5].k, 17);

    // Fragmentation guard: ip[6:2] & 0x1fff != 0 → drop.
    assert_eq!(prog[6], insn(LDH_ABS, 0, 0, 20)); // net_offset(14)+6=20
    assert_eq!(prog[7].code, JSET_K);
    assert_eq!(prog[7].k, 0x1fff);

    // MSH and jump past IPv6 section.
    assert_eq!(prog[8], insn(LDX_MSH, 0, 0, 14));
    assert_eq!(prog[9].code, JA);

    // IPv6 path: next-header at net_offset(14)+6=20.
    assert_eq!(prog[10], insn(LDB_ABS, 0, 0, 20));
    assert_eq!(prog[11].code, JEQ_K);
    assert_eq!(prog[11].k, 6); // TCP
    assert_eq!(prog[11].jt, 1, "IPv6 TCP shortcut must skip UDP check");
    assert_eq!(prog[12].code, JEQ_K);
    assert_eq!(prog[12].k, 17); // UDP
    assert_eq!(prog[13], insn(LDX_IMM, 0, 0, 40)); // X = 40

    // Port check (same indirect loads work for both IPv4 and IPv6 via X).
    assert_eq!(prog[14], insn(LDH_IND, 0, 0, 14));
    assert_eq!(prog[15].code, JEQ_K);
    assert_eq!(prog[15].k, 80);
    assert_eq!(prog[16], insn(LDH_IND, 0, 0, 16));
    assert_eq!(prog[17].code, JEQ_K);
    assert_eq!(prog[17].k, 80);
    assert_eq!(prog[18], insn(RET_K, 0, 0, ACCEPT));
    assert_eq!(prog[19], insn(RET_K, 0, 0, DROP));
}

// Same guard for portrange: TCP shortcut must not escape to ACCEPT.
#[test]
fn portrange_no_proto_tcp_shortcut_resolves_correctly() {
    let prog = eth("portrange 1024-65535");
    // IPv4 TCP jeq is now at index 4 (after ethertype+ipv6-branch+ipv4-check+ldb-proto).
    assert_eq!(prog[4].code, JEQ_K);
    assert_eq!(prog[4].k, 6);
    assert_ne!(
        prog[4].jt, 0xff,
        "TCP shortcut must be resolved, not left as 0xff placeholder"
    );
    // TCP jt must not jump to ACCEPT (second-to-last instruction).
    let accept_idx = prog.len() - 2;
    let tcp_target = 4 + 1 + prog[4].jt as usize;
    assert_ne!(
        tcp_target, accept_idx,
        "TCP shortcut must not jump directly to ACCEPT"
    );
    // MSH must appear in the IPv4 path, before the port range check.
    let msh_pos = prog
        .iter()
        .position(|i| i.code == LDX_MSH)
        .expect("MSH missing from IPv4 path");
    assert!(
        msh_pos < prog.len() - 2,
        "MSH should appear before accept/drop"
    );
    // ldx_imm(40) must appear in the IPv6 path.
    assert!(
        prog.iter().any(|i| i.code == LDX_IMM && i.k == 40),
        "IPv6 path must load X=40"
    );
}

// ── proto-qualified port parsing (no duplicate prerequisite checks) ──────────

// `tcp port 80` must not duplicate the IPv4+TCP guard (parser fix), and must
// now emit both an IPv4 frag check and an IPv6 path (codegen fix):
//
//  [0]  ldh[12]              ethertype
//  [1]  jeq 0x86dd jt→[9]   branch to IPv6 path
//  [2]  jeq 0x0800 jf→DROP   IPv4 check
//  [3]  ldb[23]              IPv4 protocol
//  [4]  jeq 6 jf→DROP        TCP only
//  [5]  ldh[20]              ip[6:2] flags + fragment offset
//  [6]  jset 0x1fff jt→DROP  non-first fragment → drop
//  [7]  ldxb 4*([14]&0xf)    MSH: X = IHL*4
//  [8]  ja → [12]            skip IPv6 section
//  [9]  ldb[20]              IPv6 next-header
//  [10] jeq 6 jf→DROP        TCP only
//  [11] ldx #40              X = IPv6 header length (fixed)
//  [12] ldh[x+14]            src port
//  [13] jeq 80 jt→ACCEPT
//  [14] ldh[x+16]            dst port
//  [15] jeq 80 jf→DROP
//  [16] ACCEPT  [17] DROP
#[test]
fn tcp_port_emits_ethertype_check_exactly_once() {
    let prog = eth("tcp port 80");
    let eth_loads = prog
        .iter()
        .filter(|i| i.code == LDH_ABS && i.k == 12)
        .count();
    assert_eq!(
        eth_loads, 1,
        "ethertype check must appear exactly once in tcp port 80"
    );
    assert_eq!(
        prog.len(),
        18,
        "tcp port 80 must compile to 18 instructions"
    );
}

#[test]
fn tcp_port_80_exact_bytecode() {
    let prog = eth("tcp port 80");
    assert_eq!(prog.len(), 18);

    // Ethertype: load once, branch to IPv6 or check for IPv4.
    assert_eq!(prog[0], insn(LDH_ABS, 0, 0, 12));
    assert_eq!(prog[1].code, JEQ_K);
    assert_eq!(prog[1].k, 0x86dd); // IPv6 ethertype
    assert_eq!(prog[2].code, JEQ_K);
    assert_eq!(prog[2].k, 0x0800); // IPv4 ethertype

    // IPv4 path: protocol + frag guard + MSH + skip.
    assert_eq!(prog[3], insn(LDB_ABS, 0, 0, 23)); // net_offset(14)+9=23
    assert_eq!(prog[4].code, JEQ_K);
    assert_eq!(prog[4].k, 6); // TCP
    assert_eq!(prog[5], insn(LDH_ABS, 0, 0, 20)); // net_offset(14)+6=20
    assert_eq!(prog[6].code, JSET_K);
    assert_eq!(prog[6].k, 0x1fff); // fragment offset bits
    assert_eq!(prog[7], insn(LDX_MSH, 0, 0, 14));
    assert_eq!(prog[8].code, JA); // jump over IPv6 section

    // IPv6 path: next-header check + load fixed header length.
    assert_eq!(prog[9], insn(LDB_ABS, 0, 0, 20)); // net_offset(14)+6=20
    assert_eq!(prog[10].code, JEQ_K);
    assert_eq!(prog[10].k, 6); // TCP next-header
    assert_eq!(prog[11], insn(LDX_IMM, 0, 0, 40)); // X = 40 (IPv6 hdr len)

    // Port check (same indirect loads for both IPv4 via MSH and IPv6 via X=40).
    assert_eq!(prog[12], insn(LDH_IND, 0, 0, 14));
    assert_eq!(prog[13].code, JEQ_K);
    assert_eq!(prog[13].k, 80);
    assert_eq!(prog[14], insn(LDH_IND, 0, 0, 16));
    assert_eq!(prog[15].code, JEQ_K);
    assert_eq!(prog[15].k, 80);
    assert_eq!(prog[16], insn(RET_K, 0, 0, ACCEPT));
    assert_eq!(prog[17], insn(RET_K, 0, 0, DROP));
}

#[test]
fn udp_port_emits_ethertype_check_exactly_once() {
    let prog = eth("udp port 53");
    let eth_loads = prog
        .iter()
        .filter(|i| i.code == LDH_ABS && i.k == 12)
        .count();
    assert_eq!(
        eth_loads, 1,
        "ethertype check must appear exactly once in udp port 53"
    );
    assert_eq!(
        prog.len(),
        18,
        "udp port 53 must compile to 18 instructions"
    );
}

#[test]
fn sctp_port_emits_ethertype_check_exactly_once() {
    let prog = eth("sctp port 9000");
    let eth_loads = prog
        .iter()
        .filter(|i| i.code == LDH_ABS && i.k == 12)
        .count();
    assert_eq!(
        eth_loads, 1,
        "ethertype check must appear exactly once in sctp port 9000"
    );
}

// Directed forms: `src tcp port`, `dst udp port`.
// Prereqs are the same 12-instruction dual-path block; only the port check shrinks.
#[test]
fn src_tcp_port_emits_single_ethertype_check() {
    let prog = eth("src tcp port 80");
    let eth_loads = prog
        .iter()
        .filter(|i| i.code == LDH_ABS && i.k == 12)
        .count();
    assert_eq!(eth_loads, 1);
    // 12 prereq + 2 port (src only) + 2 terminals = 16
    assert_eq!(prog.len(), 16);
}

#[test]
fn dst_udp_port_emits_single_ethertype_check() {
    let prog = eth("dst udp port 53");
    let eth_loads = prog
        .iter()
        .filter(|i| i.code == LDH_ABS && i.k == 12)
        .count();
    assert_eq!(eth_loads, 1);
    assert_eq!(prog.len(), 16);
}

// Proto-qualified portrange forms.
#[test]
fn tcp_portrange_emits_ethertype_check_exactly_once() {
    let prog = eth("tcp portrange 1024-65535");
    let eth_loads = prog
        .iter()
        .filter(|i| i.code == LDH_ABS && i.k == 12)
        .count();
    assert_eq!(
        eth_loads, 1,
        "ethertype check must appear exactly once in tcp portrange"
    );
}

#[test]
fn src_tcp_portrange_is_valid() {
    // Before the fix, `src tcp portrange N-M` would fail to parse because
    // parse_after_dir only accepted `port`, not `portrange`, after a proto keyword.
    let prog = eth("src tcp portrange 1024-65535");
    assert_eq!(
        prog.last().unwrap(),
        &insn(RET_K, 0, 0, DROP),
        "program must end with DROP sentinel"
    );
}

// ── fragmentation and IPv6 structural guards ─────────────────────────────────

// `tcp port 80` must include a fragment-offset check in the IPv4 path.
// BPF: jset #0x1fff → drop (non-first fragment has non-zero fragment offset).
#[test]
fn tcp_port_ipv4_path_has_frag_guard() {
    let prog = eth("tcp port 80");
    // The IPv4 frag check is at index 6: jset 0x1fff jt→DROP
    assert_eq!(prog[6].code, JSET_K, "frag guard must be jset");
    assert_eq!(prog[6].k, 0x1fff, "frag guard must mask ip[6:2] & 0x1fff");
    // jt must be non-zero (resolves to DROP) — packet is fragmented → fail.
    assert_ne!(prog[6].jt, 0, "jset jt must jump to DROP on fragment");
}

// `tcp port 80` must include an IPv6 path that sets X = 40.
#[test]
fn tcp_port_ipv6_path_loads_fixed_header_length() {
    let prog = eth("tcp port 80");
    // IPv6 path: ldb next-header [9], jeq 6 [10], ldx #40 [11].
    assert_eq!(prog[11], insn(LDX_IMM, 0, 0, 40), "IPv6 path must set X=40");
    // IPv6 branch at [1] must jump to instruction 9.
    let ipv6_target = 1 + 1 + prog[1].jt as usize;
    assert_eq!(
        ipv6_target, 9,
        "jeq 0x86dd jt must branch to IPv6 path start"
    );
}

// `port 80` (no proto qualifier) must also have both frag guard and IPv6 path.
#[test]
fn port_no_proto_has_frag_guard_and_ipv6_path() {
    let prog = eth("port 80");
    assert!(
        prog.iter().any(|i| i.code == JSET_K && i.k == 0x1fff),
        "port 80 must include a fragment-offset guard"
    );
    assert!(
        prog.iter().any(|i| i.code == LDX_IMM && i.k == 40),
        "port 80 must include an IPv6 path that sets X=40"
    );
}

// The JA (unconditional jump) that bridges the IPv4 and IPv6 paths must
// correctly skip the entire IPv6 section and land on the port check.
#[test]
fn tcp_port_ipv4_ja_resolves_to_port_check() {
    let prog = eth("tcp port 80");
    // JA is at index 8; port check starts at index 12.
    assert_eq!(
        prog[8].code, JA,
        "IPv4 path must end with ja to skip IPv6 section"
    );
    let ja_target = 8 + 1 + prog[8].k as usize;
    assert_eq!(ja_target, 12, "JA must jump to port check start at [12]");
}

// ── equivalence: named synonyms produce identical programs ──────────────────

#[test]
fn ip_proto_6_identical_to_tcp() {
    assert_eq!(eth("ip proto 6"), eth("tcp"));
}

#[test]
fn ip6_proto_58_identical_to_icmp6() {
    assert_eq!(eth("ip6 proto 58"), eth("icmp6"));
}

#[test]
fn ip6_proto_6_identical_to_ip6_tcp() {
    // `ip6 proto 6` should match IPv6 TCP; must produce a valid program.
    let prog = eth("ip6 proto 6");
    assert_eq!(prog[0], insn(LDH_ABS, 0, 0, 12));
    assert_eq!(prog[1].k, 0x86dd); // IPv6 ethertype
    assert_eq!(prog[2].code, LDB_ABS);
    assert_eq!(prog[2].k, 20); // IPv6 next-header at net_offset(14)+6=20
    assert_eq!(prog[3].code, JEQ_K);
    assert_eq!(prog[3].k, 6); // next-header value == TCP (6)
}

#[test]
fn net_mask_syntax_identical_to_cidr() {
    assert_eq!(eth("net 10.0.0.0 mask 255.0.0.0"), eth("net 10.0.0.0/8"),);
}

#[test]
fn tcpflags_constant_identical_to_literal_offset() {
    assert_eq!(
        eth("tcp[tcpflags] & tcp-syn != 0"),
        eth("tcp[13] & 0x02 != 0"),
    );
}

// ── named ICMP constant identical to literal ─────────────────────────────────

#[test]
fn icmp_echo_constant_identical_to_literal() {
    assert_eq!(eth("icmp[icmptype] = icmp-echo"), eth("icmp[icmptype] = 8"),);
}

// ── len operator variants ────────────────────────────────────────────────────

#[test]
fn len_eq_60() {
    let prog = eth("len = 60");
    assert_eq!(prog[0], insn(LD_LEN, 0, 0, 0));
    assert_eq!(prog[1].code, JEQ_K);
    assert_eq!(prog[1].k, 60);
    assert_eq!(prog[1].jf, 1); // not-equal → DROP
}

#[test]
fn len_ne_60() {
    let prog = eth("len != 60");
    assert_eq!(prog[0], insn(LD_LEN, 0, 0, 0));
    assert_eq!(prog[1].code, JEQ_K);
    assert_eq!(prog[1].k, 60);
    assert_eq!(prog[1].jt, 1); // equal → DROP (NE inverts)
}

#[test]
fn len_gt_1000() {
    let prog = eth("len > 1000");
    assert_eq!(prog[0], insn(LD_LEN, 0, 0, 0));
    assert_eq!(prog[1].code, JGT_K);
    assert_eq!(prog[1].k, 1000);
    assert_eq!(prog[1].jf, 1); // not-gt → DROP
}

#[test]
fn len_lt_64() {
    let prog = eth("len < 64");
    // CmpOp::Lt uses JGE: A >= 64 → fail (A is not < 64)
    assert_eq!(prog[0], insn(LD_LEN, 0, 0, 0));
    assert_eq!(prog[1].code, JGE_K);
    assert_eq!(prog[1].k, 64);
    assert_eq!(prog[1].jt, 1); // ge → DROP
}

#[test]
fn len_ge_1000() {
    let prog = eth("len >= 1000");
    assert_eq!(prog[0], insn(LD_LEN, 0, 0, 0));
    assert_eq!(prog[1].code, JGE_K);
    assert_eq!(prog[1].k, 1000);
    assert_eq!(prog[1].jf, 1); // not-ge → DROP
}

#[test]
fn len_le_64() {
    let prog = eth("len <= 64");
    // CmpOp::Le uses JGT: A > 64 → fail
    assert_eq!(prog[0], insn(LD_LEN, 0, 0, 0));
    assert_eq!(prog[1].code, JGT_K);
    assert_eq!(prog[1].k, 64);
    assert_eq!(prog[1].jt, 1); // gt → DROP
}

// ── len and less/greater agree ────────────────────────────────────────────────

#[test]
fn less_n_equals_len_le_n() {
    assert_eq!(eth("less 64"), eth("len <= 64"));
}

#[test]
fn greater_n_equals_len_ge_n() {
    assert_eq!(eth("greater 1500"), eth("len >= 1500"));
}

// ── transport-layer byte access uses indirect load (issue #11) ────────────────

// `tcp[0] = 8` must emit ldb [x + 14] (BPF_LD|BPF_B|BPF_IND), not ldb [14].
// X holds the IP header length (loaded by MSH), so [x+14] resolves to the
// first byte of the TCP header — not the first byte of the IP header.
#[test]
fn tcp_byte_access_uses_ldb_ind() {
    let prog = eth("tcp[0] = 8");
    // [0] ldxb 4*([14]&0xf)  — MSH loads IP IHL into X
    // [1] ldb [x + 14]       — BPF_LD | BPF_B | BPF_IND  ← must NOT be LDB_ABS
    // [2] jeq 8, jf→DROP
    // [3] ACCEPT
    // [4] DROP
    assert_eq!(prog[0], insn(LDX_MSH, 0, 0, 14));
    assert_eq!(
        prog[1].code, LDB_IND,
        "tcp[0] must use indirect byte load (ldb [x+k]), got code 0x{:02x}",
        prog[1].code
    );
    assert_eq!(prog[1].k, 14, "indirect offset must be net_offset (14)");
    assert_eq!(prog[2].code, JEQ_K);
    assert_eq!(prog[2].k, 8);
    assert_eq!(prog[3], insn(RET_K, 0, 0, ACCEPT));
    assert_eq!(prog[4], insn(RET_K, 0, 0, DROP));
    assert_eq!(prog.len(), 5);
}

// ── peephole optimizer wiring ────────────────────────────────────────────────

// dedup_loads must remove a consecutive identical ldh (halfword) load.
// This fails before the mask fix because is_load() does not recognise LDH_ABS.
#[test]
fn dedup_removes_consecutive_ldh_abs() {
    let ldh = Insn::ldh_abs(12);
    // [0] ldh[12]  [1] ldh[12] (dup)  [2] jeq jf=1→[4]  [3] ACCEPT  [4] DROP
    let jeq = insn(JEQ_K, 0, 1, 0x0800);
    let mut insns = vec![
        ldh,
        ldh,
        jeq,
        insn(RET_K, 0, 0, ACCEPT),
        insn(RET_K, 0, 0, DROP),
    ];
    dedup_loads(&mut insns);
    // Second ldh removed; jump offsets must remain valid.
    assert_eq!(insns.len(), 4, "consecutive ldh[12] must be deduplicated");
    assert_eq!(insns[0], ldh);
    assert_eq!(insns[1], jeq);
    assert_eq!(insns[2], insn(RET_K, 0, 0, ACCEPT));
    assert_eq!(insns[3], insn(RET_K, 0, 0, DROP));
}

// dedup_loads must also remove consecutive identical ldb (byte) loads.
#[test]
fn dedup_removes_consecutive_ldb_abs() {
    let ldb = Insn::ldb_abs(23);
    let jeq = insn(JEQ_K, 0, 1, 6);
    let mut insns = vec![
        ldb,
        ldb,
        jeq,
        insn(RET_K, 0, 0, ACCEPT),
        insn(RET_K, 0, 0, DROP),
    ];
    dedup_loads(&mut insns);
    assert_eq!(insns.len(), 4, "consecutive ldb[23] must be deduplicated");
    assert_eq!(insns[0], ldb);
    assert_eq!(insns[1], jeq);
}

// After dedup_loads is wired into compile(), compiling tcp and port 80 must
// succeed and produce a valid program (regression guard — the optimizer must
// not corrupt jump offsets).
#[test]
fn tcp_and_port_80_compiles_and_has_correct_terminals() {
    let prog = eth("tcp and port 80");
    // Program must end with ACCEPT then DROP.
    let n = prog.len();
    assert!(n >= 2, "program must have at least two instructions");
    assert_eq!(prog[n - 2], insn(RET_K, 0, 0, ACCEPT));
    assert_eq!(prog[n - 1], insn(RET_K, 0, 0, DROP));
}
