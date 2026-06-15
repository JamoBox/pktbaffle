//! Integration tests: parse → codegen → verify instruction shape.

use pktbaffle::{compile, LinkType, Target};

fn eth_prog(filter: &str) -> pktbaffle::Program {
    compile(filter, LinkType::Ethernet, Target::Classic)
        .unwrap_or_else(|e| panic!("compile({filter:?}): {e}"))
}

// ── Sanity: programs are non-empty and terminate with ret ────────────────────

fn last_two_are_ret(prog: &pktbaffle::Program) {
    let insns = prog.instructions();
    let n = insns.len();
    assert!(
        n >= 2,
        "program must have at least 2 instructions (accept + drop)"
    );
    // ret opcode: BPF_RET (0x06) | BPF_K (0x00) = 0x0006
    let ret_k = 0x0006u16;
    assert_eq!(
        insns[n - 2].code,
        ret_k,
        "second-to-last must be ret ACCEPT"
    );
    assert_eq!(insns[n - 1].code, ret_k, "last must be ret DROP");
    assert_eq!(insns[n - 2].k, 0xffff_ffff, "ACCEPT value");
    assert_eq!(insns[n - 1].k, 0, "DROP value");
}

#[test]
fn host_ipv4() {
    let p = eth_prog("host 192.168.1.1");
    last_two_are_ret(&p);
    assert!(p.len() > 2);
}

#[test]
fn src_host() {
    let p = eth_prog("src host 10.0.0.1");
    last_two_are_ret(&p);
}

#[test]
fn dst_host() {
    let p = eth_prog("dst host 10.0.0.2");
    last_two_are_ret(&p);
}

#[test]
fn net_cidr() {
    let p = eth_prog("net 10.0.0.0/8");
    last_two_are_ret(&p);
}

#[test]
fn tcp_port() {
    let p = eth_prog("tcp port 443");
    last_two_are_ret(&p);
}

#[test]
fn udp_port() {
    let p = eth_prog("udp port 53");
    last_two_are_ret(&p);
}

#[test]
fn bare_port() {
    let p = eth_prog("port 80");
    last_two_are_ret(&p);
}

#[test]
fn portrange() {
    let p = eth_prog("portrange 1024-65535");
    last_two_are_ret(&p);
}

#[test]
fn proto_tcp() {
    let p = eth_prog("tcp");
    last_two_are_ret(&p);
}

#[test]
fn proto_icmp() {
    let p = eth_prog("icmp");
    last_two_are_ret(&p);
}

#[test]
fn proto_arp() {
    let p = eth_prog("arp");
    last_two_are_ret(&p);
}

#[test]
fn ether_host() {
    let p = eth_prog("ether host aa:bb:cc:dd:ee:ff");
    last_two_are_ret(&p);
}

#[test]
fn ether_broadcast() {
    let p = eth_prog("ether broadcast");
    last_two_are_ret(&p);
}

// `less n` means len <= n (libpcap semantics).
#[test]
fn less_than() {
    let p = eth_prog("less 64");
    last_two_are_ret(&p);
}

// `greater n` means len >= n (libpcap semantics).
#[test]
fn greater_than() {
    let p = eth_prog("greater 1500");
    last_two_are_ret(&p);
}

// ── Logical combinators ───────────────────────────────────────────────────────

#[test]
fn and_explicit() {
    let p = eth_prog("tcp and port 80");
    last_two_are_ret(&p);
}

#[test]
fn and_implicit() {
    let p = eth_prog("tcp port 80"); // juxtaposition
    last_two_are_ret(&p);
}

#[test]
fn or_simple() {
    let p = eth_prog("tcp or udp");
    last_two_are_ret(&p);
}

#[test]
fn not_simple() {
    let p = eth_prog("not arp");
    last_two_are_ret(&p);
}

#[test]
fn complex_and_or() {
    let p = eth_prog("(tcp or udp) and port 53");
    last_two_are_ret(&p);
}

#[test]
fn host_and_port() {
    let p = eth_prog("host 1.2.3.4 and tcp port 80");
    last_two_are_ret(&p);
}

#[test]
fn not_host() {
    let p = eth_prog("not host 1.2.3.4");
    last_two_are_ret(&p);
}

// ── ip protochain / ip6 protochain ────────────────────────────────────────────

#[test]
fn ip_protochain_numeric() {
    let p = eth_prog("ip protochain 6");
    last_two_are_ret(&p);
}

#[test]
fn ip6_protochain_numeric() {
    let p = eth_prog("ip6 protochain 58");
    last_two_are_ret(&p);
}

#[test]
fn ip_protochain_combined() {
    let p = eth_prog("ip protochain 6 and port 80");
    last_two_are_ret(&p);
}

#[test]
fn ip_protochain_does_not_break_ip_proto() {
    let p = eth_prog("ip proto 6");
    last_two_are_ret(&p);
}

#[test]
fn ip6_protochain_does_not_break_ip6_proto() {
    let p = eth_prog("ip6 proto 58");
    last_two_are_ret(&p);
}

// ── Byte access ───────────────────────────────────────────────────────────────

#[test]
fn byte_access_tcp_syn() {
    // Match TCP SYN packets: tcp[13] & 0x02 != 0
    let p = eth_prog("tcp[13] & 0x02 != 0");
    last_two_are_ret(&p);
}

#[test]
fn byte_access_ip_ttl() {
    let p = eth_prog("ip[8] = 64");
    last_two_are_ret(&p);
}

// tcp[0:2] range syntax without spaces (issue #10 — greedy colon lexing)
#[test]
fn byte_range_no_spaces_compiles() {
    // `tcp[0:2]` is identical in meaning to `tcp[0 : 2]`; both must compile.
    let p_compact = eth_prog("tcp[0:2] = 8");
    let p_spaced = eth_prog("tcp[0 : 2] = 8");
    last_two_are_ret(&p_compact);
    assert_eq!(
        p_compact.instructions(),
        p_spaced.instructions(),
        "compact and spaced range syntax must produce identical bytecode"
    );
}

#[test]
fn byte_range_various_no_spaces() {
    // A few representative range sizes to make sure the fix is general.
    eth_prog("ip[6:2] & 0x1fff != 0"); // IP fragment offset
    eth_prog("tcp[0:4] = 0"); // first 4 bytes of TCP header
}

// ── Named field constants ─────────────────────────────────────────────────────

#[test]
fn tcpflags_constant() {
    // tcpflags expands to 13 — equivalent to tcp[13] & tcp-syn != 0
    let p = eth_prog("tcp[tcpflags] & tcp-syn != 0");
    last_two_are_ret(&p);
}

#[test]
fn icmp_named_constants() {
    // icmptype = 0 (offset of ICMP type byte within ICMP header)
    let p = eth_prog("icmp[icmptype] = icmp-echo");
    last_two_are_ret(&p);
}

// ── net mask syntax ───────────────────────────────────────────────────────────

#[test]
fn net_mask_syntax() {
    let p = eth_prog("net 192.168.0.0 mask 255.255.0.0");
    last_two_are_ret(&p);
}

#[test]
fn net_mask_and_cidr_equivalent() {
    // Both should produce programs of the same length.
    let p_mask = eth_prog("net 10.0.0.0 mask 255.0.0.0");
    let p_cidr = eth_prog("net 10.0.0.0/8");
    assert_eq!(p_mask.len(), p_cidr.len());
}

// ── Additional IP protocol keywords ──────────────────────────────────────────

#[test]
fn proto_ah() {
    let p = eth_prog("ah");
    last_two_are_ret(&p);
}

#[test]
fn proto_esp() {
    let p = eth_prog("esp");
    last_two_are_ret(&p);
}

#[test]
fn proto_pim() {
    let p = eth_prog("pim");
    last_two_are_ret(&p);
}

#[test]
fn proto_igrp() {
    let p = eth_prog("igrp");
    last_two_are_ret(&p);
}

#[test]
fn proto_vrrp() {
    let p = eth_prog("vrrp");
    last_two_are_ret(&p);
}

// ── ip proto / ip6 proto ─────────────────────────────────────────────────────

#[test]
fn ip_proto_number() {
    // `ip proto 6` explicitly restricts to IPv4 with TCP protocol.
    let p = eth_prog("ip proto 6");
    last_two_are_ret(&p);
}

#[test]
fn ip6_proto_number() {
    // `ip6 proto 58` matches IPv6 ICMPv6 (next header 58).
    let p = eth_prog("ip6 proto 58");
    last_two_are_ret(&p);
}

#[test]
fn ip6_proto_tcp() {
    let p = eth_prog("ip6 proto 6");
    last_two_are_ret(&p);
}

// ── Broadcast and multicast ───────────────────────────────────────────────────

#[test]
fn ether_multicast() {
    // Proper bit-0 check on destination MAC first byte.
    let p = eth_prog("ether multicast");
    last_two_are_ret(&p);
}

#[test]
fn bare_broadcast() {
    let p = eth_prog("broadcast");
    last_two_are_ret(&p);
}

#[test]
fn bare_multicast() {
    let p = eth_prog("multicast");
    last_two_are_ret(&p);
}

#[test]
fn ip_broadcast() {
    let p = eth_prog("ip broadcast");
    last_two_are_ret(&p);
}

#[test]
fn ip_multicast() {
    let p = eth_prog("ip multicast");
    last_two_are_ret(&p);
}

#[test]
fn ip6_multicast() {
    let p = eth_prog("ip6 multicast");
    last_two_are_ret(&p);
}

// ── VLAN ─────────────────────────────────────────────────────────────────────

#[test]
fn vlan_any() {
    let p = eth_prog("vlan");
    last_two_are_ret(&p);
}

#[test]
fn vlan_with_id() {
    let p = eth_prog("vlan 100");
    last_two_are_ret(&p);
}

#[test]
fn vlan_and_tcp() {
    let p = eth_prog("vlan and tcp port 22");
    last_two_are_ret(&p);
}

// ── MPLS ─────────────────────────────────────────────────────────────────────

#[test]
fn mpls_any() {
    let p = eth_prog("mpls");
    last_two_are_ret(&p);
}

#[test]
fn mpls_with_label() {
    let p = eth_prog("mpls 12345");
    last_two_are_ret(&p);
}

// ── PPPoE ────────────────────────────────────────────────────────────────────

#[test]
fn pppoe_discovery() {
    let p = eth_prog("pppoed");
    last_two_are_ret(&p);
}

#[test]
fn pppoe_session() {
    let p = eth_prog("pppoes");
    last_two_are_ret(&p);
}

#[test]
fn pppoe_session_with_id() {
    let p = eth_prog("pppoes 100");
    last_two_are_ret(&p);
}

#[test]
fn pppoe_session_with_id_zero() {
    let p = eth_prog("pppoes 0");
    last_two_are_ret(&p);
}

// ── len keyword ───────────────────────────────────────────────────────────────

#[test]
fn len_eq() {
    let p = eth_prog("len = 60");
    last_two_are_ret(&p);
}

#[test]
fn len_ne() {
    let p = eth_prog("len != 60");
    last_two_are_ret(&p);
}

#[test]
fn len_gt() {
    let p = eth_prog("len > 1000");
    last_two_are_ret(&p);
}

#[test]
fn len_ge() {
    let p = eth_prog("len >= 1000");
    last_two_are_ret(&p);
}

#[test]
fn len_lt() {
    let p = eth_prog("len < 64");
    last_two_are_ret(&p);
}

#[test]
fn len_le() {
    let p = eth_prog("len <= 64");
    last_two_are_ret(&p);
}

// ── ether src/dst without host keyword ───────────────────────────────────────

#[test]
fn ether_src_mac_no_host() {
    // `ether src <mac>` — 'host' keyword optional
    let p = eth_prog("ether src aa:bb:cc:dd:ee:ff");
    last_two_are_ret(&p);
}

#[test]
fn ether_dst_mac_no_host() {
    let p = eth_prog("ether dst 11:22:33:44:55:66");
    last_two_are_ret(&p);
}

// ── sctp port ────────────────────────────────────────────────────────────────

#[test]
fn sctp_port() {
    let p = eth_prog("src sctp port 36412");
    last_two_are_ret(&p);
}

// ── inbound / outbound error ─────────────────────────────────────────────────

#[test]
fn inbound_is_codegen_error() {
    let r = compile("inbound", LinkType::Ethernet, Target::Classic);
    assert!(r.is_err());
}

#[test]
fn outbound_is_codegen_error() {
    let r = compile("outbound", LinkType::Ethernet, Target::Classic);
    assert!(r.is_err());
}

// ── Error cases ───────────────────────────────────────────────────────────────

#[test]
fn empty_filter_is_error() {
    // An empty string produces no tokens; parse should return an error.
    let result = compile("", LinkType::Ethernet, Target::Classic);
    assert!(result.is_err());
}

#[test]
fn unknown_keyword_is_error() {
    let result = compile(
        "frobnicator host 1.2.3.4",
        LinkType::Ethernet,
        Target::Classic,
    );
    // "frobnicator" is not a recognised keyword; should fail at parse.
    assert!(result.is_err());
}

// ── to_le_bytes encoding ──────────────────────────────────────────────────────

#[test]
fn bytes_length_matches_instruction_count() {
    let p = eth_prog("tcp port 80");
    assert_eq!(p.to_le_bytes().len(), p.len() * 8);
}

// ── RawIp link type ───────────────────────────────────────────────────────────

#[test]
fn rawip_host() {
    let p = compile("host 192.168.1.1", LinkType::RawIp, Target::Classic).unwrap();
    last_two_are_ret(&p);
}

#[test]
fn rawip_ether_host_is_error() {
    let r = compile(
        "ether host aa:bb:cc:dd:ee:ff",
        LinkType::RawIp,
        Target::Classic,
    );
    assert!(r.is_err());
}

#[test]
fn rawip_ether_multicast_is_error() {
    let r = compile("ether multicast", LinkType::RawIp, Target::Classic);
    assert!(r.is_err());
}

// ── LinuxSll link type ────────────────────────────────────────────────────────

#[test]
fn linuxsll_host() {
    let p = compile("host 10.0.0.1", LinkType::LinuxSll, Target::Classic).unwrap();
    last_two_are_ret(&p);
}

#[test]
fn linuxsll_tcp_port() {
    let p = compile("tcp port 443", LinkType::LinuxSll, Target::Classic).unwrap();
    last_two_are_ret(&p);
}

// ── Negative byte-access offsets must return an error, not panic (issue #26) ──

#[test]
fn negative_tcp_offset_returns_error() {
    let result = compile("tcp[-1] = 0", LinkType::Ethernet, Target::Classic);
    assert!(
        result.is_err(),
        "tcp[-1] = 0 must return an error, not succeed or panic"
    );
}

#[test]
fn negative_ip_offset_with_size_returns_error() {
    let result = compile("ip[-4:2] != 0", LinkType::Ethernet, Target::Classic);
    assert!(
        result.is_err(),
        "ip[-4:2] != 0 must return an error, not succeed or panic"
    );
}

#[test]
fn negative_ether_offset_returns_error() {
    let result = compile("ether[-2:1] = 0", LinkType::Ethernet, Target::Classic);
    assert!(
        result.is_err(),
        "ether[-2:1] = 0 must return an error, not succeed or panic"
    );
}

#[test]
fn zero_offset_byte_access_is_valid() {
    // Offset 0 is the minimum valid value and must compile successfully.
    let result = compile("tcp[0] = 0", LinkType::Ethernet, Target::Classic);
    assert!(
        result.is_ok(),
        "tcp[0] = 0 must compile: {:?}",
        result.err()
    );
}

#[test]
fn positive_offset_byte_access_unaffected() {
    // Existing positive-offset form must continue to work.
    let result = compile("ip[8] < 64", LinkType::Ethernet, Target::Classic);
    assert!(
        result.is_ok(),
        "ip[8] < 64 must compile: {:?}",
        result.err()
    );
}

// ── Arithmetic expressions in byte-access offset position (#32b) ──────────────

#[test]
fn offset_expr_addition() {
    // tcp[0+2]: offset computed as 0+2=2 at parse time
    let result = compile("tcp[0+2] = 0", LinkType::Ethernet, Target::Classic);
    assert!(
        result.is_ok(),
        "tcp[0+2] = 0 must compile: {:?}",
        result.err()
    );
    last_two_are_ret(&result.unwrap());
}

#[test]
fn offset_expr_subtraction() {
    // tcp[4-2]: offset computed as 4-2=2
    let result = compile("tcp[4-2] = 0", LinkType::Ethernet, Target::Classic);
    assert!(
        result.is_ok(),
        "tcp[4-2] = 0 must compile: {:?}",
        result.err()
    );
    last_two_are_ret(&result.unwrap());
}

#[test]
fn offset_expr_multiplication() {
    // tcp[1*4]: offset computed as 1*4=4
    let result = compile("tcp[1*4] = 0", LinkType::Ethernet, Target::Classic);
    assert!(
        result.is_ok(),
        "tcp[1*4] = 0 must compile: {:?}",
        result.err()
    );
    last_two_are_ret(&result.unwrap());
}

#[test]
fn offset_expr_division() {
    // tcp[8/2]: offset computed as 8/2=4
    let result = compile("tcp[8/2] = 0", LinkType::Ethernet, Target::Classic);
    assert!(
        result.is_ok(),
        "tcp[8/2] = 0 must compile: {:?}",
        result.err()
    );
    last_two_are_ret(&result.unwrap());
}

#[test]
fn offset_expr_shift_left() {
    // tcp[1<<2]: offset computed as 1<<2=4
    let result = compile("tcp[1<<2] = 0", LinkType::Ethernet, Target::Classic);
    assert!(
        result.is_ok(),
        "tcp[1<<2] = 0 must compile: {:?}",
        result.err()
    );
    last_two_are_ret(&result.unwrap());
}

#[test]
fn offset_expr_shift_right() {
    // tcp[16>>2]: offset computed as 16>>2=4
    let result = compile("tcp[16>>2] = 0", LinkType::Ethernet, Target::Classic);
    assert!(
        result.is_ok(),
        "tcp[16>>2] = 0 must compile: {:?}",
        result.err()
    );
    last_two_are_ret(&result.unwrap());
}

#[test]
fn offset_expr_bitwise_and() {
    // tcp[0xff&0x0f]: offset computed as 0xff&0x0f=15
    let result = compile("tcp[0xff&0x0f] = 0", LinkType::Ethernet, Target::Classic);
    assert!(
        result.is_ok(),
        "tcp[0xff&0x0f] = 0 must compile: {:?}",
        result.err()
    );
    last_two_are_ret(&result.unwrap());
}

#[test]
fn offset_expr_bitwise_or() {
    // tcp[0x01|0x04]: offset computed as 0x01|0x04=5
    let result = compile("tcp[0x01|0x04] = 0", LinkType::Ethernet, Target::Classic);
    assert!(
        result.is_ok(),
        "tcp[0x01|0x04] = 0 must compile: {:?}",
        result.err()
    );
    last_two_are_ret(&result.unwrap());
}

#[test]
fn offset_expr_bitwise_xor() {
    // tcp[0x0f^0x05]: offset computed as 0x0f^0x05=10
    let result = compile("tcp[0x0f^0x05] = 0", LinkType::Ethernet, Target::Classic);
    assert!(
        result.is_ok(),
        "tcp[0x0f^0x05] = 0 must compile: {:?}",
        result.err()
    );
    last_two_are_ret(&result.unwrap());
}

#[test]
fn offset_expr_with_explicit_size() {
    // tcp[0+2:2]: offset expr with explicit 2-byte size
    let result = compile("tcp[0+2:2] = 0", LinkType::Ethernet, Target::Classic);
    assert!(
        result.is_ok(),
        "tcp[0+2:2] = 0 must compile: {:?}",
        result.err()
    );
    last_two_are_ret(&result.unwrap());
}

#[test]
fn offset_expr_parentheses() {
    // tcp[(2+2)]: parenthesised offset expression evaluates to 4
    let result = compile("tcp[(2+2)] = 0", LinkType::Ethernet, Target::Classic);
    assert!(
        result.is_ok(),
        "tcp[(2+2)] = 0 must compile: {:?}",
        result.err()
    );
    last_two_are_ret(&result.unwrap());
}

#[test]
fn offset_expr_division_by_zero_is_error() {
    // Division by zero in the offset expression must be an error.
    let result = compile("tcp[4/0] = 0", LinkType::Ethernet, Target::Classic);
    assert!(result.is_err(), "tcp[4/0] = 0 must fail with a parse error");
}

#[test]
fn offset_expr_negative_result_is_error() {
    // Expressions that evaluate to a negative offset must be rejected.
    let result = compile("tcp[1-4] = 0", LinkType::Ethernet, Target::Classic);
    assert!(
        result.is_err(),
        "tcp[1-4] = 0 (offset -3) must fail with a parse error"
    );
}

#[test]
fn offset_expr_equivalence_to_plain_offset() {
    // tcp[0+4] and tcp[4] must produce identical bytecode.
    let expr = compile("tcp[0+4] = 0", LinkType::Ethernet, Target::Classic)
        .expect("tcp[0+4] must compile");
    let plain =
        compile("tcp[4] = 0", LinkType::Ethernet, Target::Classic).expect("tcp[4] must compile");
    assert_eq!(
        expr.instructions(),
        plain.instructions(),
        "tcp[0+4] and tcp[4] must produce identical bytecode"
    );
}

#[test]
fn offset_expr_operator_precedence() {
    // tcp[1+2*3] = tcp[7]: multiplication binds tighter than addition.
    let expr = compile("tcp[1+2*3] = 0", LinkType::Ethernet, Target::Classic)
        .expect("tcp[1+2*3] must compile");
    let plain =
        compile("tcp[7] = 0", LinkType::Ethernet, Target::Classic).expect("tcp[7] must compile");
    assert_eq!(
        expr.instructions(),
        plain.instructions(),
        "tcp[1+2*3] must equal tcp[7] (standard math precedence)"
    );
}

#[test]
fn offset_expr_rhs_byte_load() {
    // Offset expressions are also allowed on the RHS of expr-vs-expr comparisons.
    let result = compile("tcp[0+2] = tcp[1+1]", LinkType::Ethernet, Target::Classic);
    assert!(
        result.is_ok(),
        "tcp[0+2] = tcp[1+1] must compile: {:?}",
        result.err()
    );
    last_two_are_ret(&result.unwrap());
}

// ── Arithmetic and bitwise operators in byte-access expressions (#32) ─────────

#[test]
fn byte_access_subtract_constant() {
    // ip[8]-1 < 64: load TTL, subtract 1, compare less than 64
    let result = compile("ip[8]-1 < 64", LinkType::Ethernet, Target::Classic);
    assert!(
        result.is_ok(),
        "ip[8]-1 < 64 must compile: {:?}",
        result.err()
    );
    last_two_are_ret(&result.unwrap());
}

#[test]
fn byte_access_add_constant() {
    // ip[8]+1 > 64: load TTL, add 1, compare greater than 64
    let result = compile("ip[8]+1 > 64", LinkType::Ethernet, Target::Classic);
    assert!(
        result.is_ok(),
        "ip[8]+1 > 64 must compile: {:?}",
        result.err()
    );
    last_two_are_ret(&result.unwrap());
}

#[test]
fn byte_access_bitwise_or() {
    // tcp[13]|0x02 = 0x02: load TCP flags, OR with SYN bit, compare
    let result = compile("tcp[13]|0x02 = 0x02", LinkType::Ethernet, Target::Classic);
    assert!(
        result.is_ok(),
        "tcp[13]|0x02 = 0x02 must compile: {:?}",
        result.err()
    );
    last_two_are_ret(&result.unwrap());
}

#[test]
fn byte_access_bitwise_xor() {
    // tcp[0]^0xff = 0: load byte, XOR with 0xff, compare equal to 0
    let result = compile("tcp[0]^0xff = 0", LinkType::Ethernet, Target::Classic);
    assert!(
        result.is_ok(),
        "tcp[0]^0xff = 0 must compile: {:?}",
        result.err()
    );
    last_two_are_ret(&result.unwrap());
}

#[test]
fn byte_access_shift_left() {
    // tcp[0]<<2 = 8: load byte, shift left 2, compare equal to 8
    let result = compile("tcp[0]<<2 = 8", LinkType::Ethernet, Target::Classic);
    assert!(
        result.is_ok(),
        "tcp[0]<<2 = 8 must compile: {:?}",
        result.err()
    );
    last_two_are_ret(&result.unwrap());
}

#[test]
fn byte_access_shift_right() {
    // tcp[0]>>2 = 2: load byte, shift right 2, compare equal to 2
    let result = compile("tcp[0]>>2 = 2", LinkType::Ethernet, Target::Classic);
    assert!(
        result.is_ok(),
        "tcp[0]>>2 = 2 must compile: {:?}",
        result.err()
    );
    last_two_are_ret(&result.unwrap());
}

#[test]
fn byte_access_multiply_constant() {
    // ip[4:2]*2 < 100: load IP total length, multiply by 2, compare
    let result = compile("ip[4:2]*2 < 100", LinkType::Ethernet, Target::Classic);
    assert!(
        result.is_ok(),
        "ip[4:2]*2 < 100 must compile: {:?}",
        result.err()
    );
    last_two_are_ret(&result.unwrap());
}

#[test]
fn byte_access_divide_constant() {
    // ip[4:2]/2 < 50: load IP total length, divide by 2, compare
    let result = compile("ip[4:2]/2 < 50", LinkType::Ethernet, Target::Classic);
    assert!(
        result.is_ok(),
        "ip[4:2]/2 < 50 must compile: {:?}",
        result.err()
    );
    last_two_are_ret(&result.unwrap());
}

#[test]
fn byte_access_divide_by_zero_is_error() {
    // Division by zero constant must return a codegen error, not panic.
    let result = compile("ip[8]/0 < 64", LinkType::Ethernet, Target::Classic);
    assert!(result.is_err(), "ip[8]/0 should fail with a codegen error");
}

#[test]
fn byte_access_existing_mask_form_unchanged() {
    // The original & mask form must still work exactly as before.
    let original = compile("tcp[13] & 0x02 != 0", LinkType::Ethernet, Target::Classic)
        .expect("tcp[13] & 0x02 != 0 must compile");
    last_two_are_ret(&original);
}

#[test]
fn byte_access_chained_alu_ops() {
    // Multiple ALU ops chained: tcp[13]&0x17|0x02 = 0x02
    let result = compile(
        "tcp[13]&0x17|0x02 = 0x02",
        LinkType::Ethernet,
        Target::Classic,
    );
    assert!(
        result.is_ok(),
        "tcp[13]&0x17|0x02 = 0x02 must compile: {:?}",
        result.err()
    );
    last_two_are_ret(&result.unwrap());
}

// ── Codegen robustness: jump offset overflow must return Err, not panic ───────

#[test]
fn deeply_nested_not_returns_error_not_panic() {
    // A deeply-nested chain of NOT operators generates a BPF program whose
    // jump offsets exceed u8::MAX.  Before the fix this caused a panic via
    // debug_assert! in codegen::offset().  After the fix it must return a
    // CodegenError gracefully.
    //
    // Minimised fuzz crash input: "::!::!::!::!::!::!::!::"
    let result = compile(
        "::!::!::!::!::!::!::!::",
        LinkType::Ethernet,
        Target::Classic,
    );
    assert!(
        result.is_err(),
        "a filter that generates a jump offset > 255 must return Err, not panic"
    );
}

#[test]
fn deeply_nested_not_extended_does_not_panic() {
    // The eBPF target uses i16 jump offsets so the same input may not trigger
    // an overflow — either Ok or Err is acceptable; a panic is not.
    let result = compile(
        "::!::!::!::!::!::!::!::",
        LinkType::Ethernet,
        Target::Extended,
    );
    // Just verify it completes without panicking.
    let _ = result;
}

#[test]
fn very_complex_filter_does_not_panic() {
    // A long OR chain can also push jump offsets past 255.  Ensure it
    // returns Err rather than panicking on any link type and target.
    let long_or = (0u16..200)
        .map(|p| format!("port {p}"))
        .collect::<Vec<_>>()
        .join(" or ");
    for &link in &[LinkType::Ethernet, LinkType::RawIp, LinkType::LinuxSll] {
        let r = compile(&long_or, link, Target::Classic);
        // Either compiles fine or returns a CodegenError — must never panic.
        let _ = r;
    }
}

// ── Regression: deeply-nested parentheses must not stack-overflow ────────────
// The fuzzer (fuzz_compile) found that deeply nested `(` triggers unbounded
// recursion in the parser and causes a deadly signal (stack overflow).
// Fixed by enforcing a recursion depth limit in parse_expr.
// Ref: GH issue #81, nightly CI failure 2026-06-15.
#[test]
fn deeply_nested_parens_returns_error_not_stack_overflow() {
    use pktbaffle::{compile, Error, LinkType, Target};

    // 200 open parens — well past the parser's depth limit — must return
    // ParseError, not panic / SIGSEGV.
    let deeply_nested = format!("{}tcp{}", "(".repeat(200), ")".repeat(200));
    for &link in &[LinkType::Ethernet, LinkType::RawIp, LinkType::LinuxSll] {
        let r = compile(&deeply_nested, link, Target::Classic);
        assert!(
            matches!(r, Err(Error::ParseError { .. })),
            "expected ParseError for deeply nested input on {link:?}, got {r:?}"
        );
    }
}

#[test]
fn fuzz_crash_repro_deeply_nested_with_trailing_garbage() {
    use pktbaffle::{compile, LinkType, Target};

    // Exact bytes from the fuzz artifact that triggered the crash:
    // (((((((((((((((0::00 81.010 80.0 net 1 8010 80.0 net 1 80.0 net 1.01 tcp!(t((cp(
    let crash_input = "(((((((((((((((0::00 81.010 80.0 net 1 8010 80.0 net 1 80.0 net 1.01 tcp!(t((cp(";
    for &link in &[LinkType::Ethernet, LinkType::RawIp, LinkType::LinuxSll] {
        // Must not panic — either an Ok or an Err is acceptable.
        let _ = compile(crash_input, link, Target::Classic);
        let _ = compile(crash_input, link, Target::Extended);
    }
}
