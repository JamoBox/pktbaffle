//! Bytecode-level tests: verify exact BPF instruction sequences.
//!
//! These tests pin the precise opcode, jump offsets, and immediate values
//! produced by the compiler. They exist alongside the compile-shape tests in
//! integration.rs, which only check that programs end with accept/drop.
//!
//! Opcode constants are computed from the BPF building blocks in bpf.rs.

use pktbaffle::bpf::Insn;
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
const LD_LEN: u16 = 0x80; // BPF_LD | BPF_W | BPF_LEN
const AND_K: u16 = 0x54; // BPF_ALU | BPF_AND | BPF_K
const RSH_K: u16 = 0x74; // BPF_ALU | BPF_RSH | BPF_K
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
// the TCP protocol-match shortcut as an ACCEPT jump.  The TCP jeq's jt field
// must point to the MSH instruction (which loads the IP IHL), NOT to ACCEPT.
#[test]
fn port_no_proto_tcp_shortcut_resolves_to_msh_not_accept() {
    let prog = eth("port 80");
    // Expected layout:
    //  [0]  ldh[12]          — IPv4 guard
    //  [1]  jeq 0x0800       — jf→DROP
    //  [2]  ldb[23]          — IP proto (14+9)
    //  [3]  jeq 6, jt=1, jf=0  — TCP: jt skips [4] to [5]=MSH
    //  [4]  jeq 17           — UDP: jf→DROP
    //  [5]  ldxb 4*([14]&0xf) — MSH
    //  [6]  ldh[x+14]        — src port
    //  [7]  jeq 80, jt→ACCEPT
    //  [8]  ldh[x+16]        — dst port
    //  [9]  jeq 80, jf→DROP
    //  [10] ACCEPT
    //  [11] DROP
    assert_eq!(prog[2], insn(LDB_ABS, 0, 0, 23));
    assert_eq!(prog[3].code, JEQ_K);
    assert_eq!(prog[3].k, 6);
    // jt=1 means skip one instruction ([4]) to land at [5]=MSH, not ACCEPT.
    assert_eq!(prog[3].jt, 1, "TCP shortcut must jump to MSH, not ACCEPT");
    assert_eq!(prog[4].code, JEQ_K);
    assert_eq!(prog[4].k, 17);
    assert_eq!(prog[5], insn(LDX_MSH, 0, 0, 14));
    assert_eq!(prog[6], insn(LDH_IND, 0, 0, 14));
    assert_eq!(prog[7].code, JEQ_K);
    assert_eq!(prog[7].k, 80);
    assert_eq!(prog[8], insn(LDH_IND, 0, 0, 16));
    assert_eq!(prog[9].code, JEQ_K);
    assert_eq!(prog[9].k, 80);
    assert_eq!(prog[10], insn(RET_K, 0, 0, ACCEPT));
    assert_eq!(prog[11], insn(RET_K, 0, 0, DROP));
    assert_eq!(prog.len(), 12);
}

// Same bug must not exist in portrange.
#[test]
fn portrange_no_proto_tcp_shortcut_resolves_to_msh() {
    let prog = eth("portrange 1024-65535");
    // [3] is the TCP jeq; its jt must not be 0xff (unresolved to ACCEPT).
    assert_eq!(prog[3].code, JEQ_K);
    assert_eq!(prog[3].k, 6);
    assert_ne!(
        prog[3].jt, 0xff,
        "TCP shortcut must be resolved to MSH, not left as 0xff"
    );
    // MSH must appear before the port range check.
    let msh_pos = prog
        .iter()
        .position(|i| i.code == LDX_MSH)
        .expect("MSH missing");
    assert!(
        msh_pos < prog.len() - 2,
        "MSH should appear before accept/drop"
    );
    // TCP jt must resolve to the MSH instruction.
    let tcp_idx = 3usize;
    let target = tcp_idx + 1 + prog[tcp_idx].jt as usize;
    assert_eq!(prog[target].code, LDX_MSH, "TCP jt must land on MSH");
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
