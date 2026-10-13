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

// ── and/or precedence (#128) ──────────────────────────────────────────────────
// libpcap 1.10.3 (`%left OR AND`, pcap-filter(7)): `and`, `or` and juxtaposition
// have EQUAL precedence and associate left to right; only `not` binds tighter.

fn ast(filter: &str) -> pktbaffle::ast::Expr {
    pktbaffle::parse(filter).unwrap_or_else(|e| panic!("parse({filter:?}): {e}"))
}

#[test]
fn and_or_equal_precedence_left_assoc() {
    // `X or Y and Z` is `(X or Y) and Z` — the shape the old parser got wrong.
    for (flat, grouped) in [
        (
            "port 22 or port 80 and host 10.0.0.1",
            "(port 22 or port 80) and host 10.0.0.1",
        ),
        (
            "tcp or udp and host 10.0.0.1",
            "(tcp or udp) and host 10.0.0.1",
        ),
        // `X and Y or Z` is unchanged.
        ("tcp and udp or icmp", "(tcp and udp) or icmp"),
        (
            "host 1.1.1.1 and tcp or udp",
            "(host 1.1.1.1 and tcp) or udp",
        ),
        // Same-operator chains are left-associative.
        ("tcp or udp or icmp", "(tcp or udp) or icmp"),
        ("tcp and udp and icmp", "(tcp and udp) and icmp"),
        // Longer mixed chains fold strictly left to right.
        (
            "arp or tcp and udp or icmp",
            "((arp or tcp) and udp) or icmp",
        ),
        // Juxtaposition is AND at the same level.
        ("tcp or udp host 10.0.0.1", "(tcp or udp) and host 10.0.0.1"),
        ("tcp or udp icmp or arp", "((tcp or udp) and icmp) or arp"),
        // `not` still binds tighter than both.
        ("not tcp or udp and icmp", "((not tcp) or udp) and icmp"),
        ("tcp or not udp and icmp", "(tcp or (not udp)) and icmp"),
        // Inside parentheses the same rules apply, and `)` ends juxtaposition.
        (
            "(tcp or udp and icmp) arp",
            "((tcp or udp) and icmp) and arp",
        ),
    ] {
        assert_eq!(ast(flat), ast(grouped), "{flat:?} vs {grouped:?}");
    }
}

#[test]
fn or_then_and_is_not_the_old_tree_shape() {
    use pktbaffle::ast::Expr;
    let e = ast("port 22 or port 80 and host 10.0.0.1");
    assert!(
        matches!(&e, Expr::And(l, _) if matches!(**l, Expr::Or(..))),
        "expected And(Or(..), ..), got {e:?}"
    );
    assert_ne!(e, ast("port 22 or (port 80 and host 10.0.0.1)"));
}

#[test]
fn dangling_logical_operators_are_errors() {
    for f in ["tcp or", "tcp and", "or tcp", "and tcp", "tcp and or udp"] {
        assert!(pktbaffle::parse(f).is_err(), "{f:?} must be a parse error");
    }
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

    // 10_000 open parens — past the parser's limit — must return ParseError,
    // not panic / SIGSEGV. (This used 200 while the limit was 127; libpcap
    // 1.10.3 accepts 9995 and rejects 9996, per #199, and so does pktbaffle.)
    let deeply_nested = format!("{}tcp{}", "(".repeat(10_000), ")".repeat(10_000));
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
    let crash_input =
        "(((((((((((((((0::00 81.010 80.0 net 1 8010 80.0 net 1 80.0 net 1.01 tcp!(t((cp(";
    for &link in &[LinkType::Ethernet, LinkType::RawIp, LinkType::LinuxSll] {
        // Must not panic — either an Ok or an Err is acceptable.
        let _ = compile(crash_input, link, Target::Classic);
        let _ = compile(crash_input, link, Target::Extended);
    }
}

// ── Regression: byte-access offset arithmetic must not overflow (#134) ────────
// `X[(1<<63)/-1]` made the offset folder compute `i64::MIN / -1`, which panics
// ("attempt to divide with overflow") in debug and release.  `1<<63` itself was
// silently accepted as `ip[0]`.  libpcap 1.10.3 rejects both at compile time
// ("shift by more than 31 bits"); pktbaffle must return `Err(ParseError)`.

/// Run `f` on a thread with a `kib` KiB stack.  A panic inside `f` fails the
/// calling test with the panic reported, rather than unwinding through it.
fn on_small_stack<T: Send + 'static>(kib: usize, f: impl FnOnce() -> T + Send + 'static) -> T {
    std::thread::Builder::new()
        .stack_size(kib * 1024)
        .spawn(f)
        .expect("spawn thread")
        .join()
        .unwrap_or_else(|_| panic!("thread panicked (see message above)"))
}

const OFFSET_OVERFLOW_FILTERS: &[&str] = &[
    "ip[(1<<63)/-1] = 0",
    "tcp[(1<<63)/-1:2] = 0",
    "ether[(1<<63)/-1] = 0",
    "ip6[(1<<63)/-1] = 0",
    "ip[(1<<63)/(0-1)] = 0",
    "ip[(1<<62<<1)/-1] = 0",
    // `<<` that loses range without any division.
    "ip[1<<63] = 0",
    "ip[1<<62<<1] = 0",
    // RHS byte-load goes through the same folder.
    "ip[0] = ip[(1<<63)/-1]",
    // Out of i32 range and negative: `v as i32` used to truncate this to 0.
    "ip[0-(1<<40)] = 0",
    "ip[-(1<<40)] = 0",
];

#[test]
fn offset_expr_overflow_returns_parse_error_not_panic() {
    use pktbaffle::{parse, Error};

    on_small_stack(512, || {
        for filter in OFFSET_OVERFLOW_FILTERS {
            assert!(
                matches!(parse(filter), Err(Error::ParseError { .. })),
                "parse({filter:?}) must be a ParseError"
            );
            for &link in &[LinkType::Ethernet, LinkType::RawIp, LinkType::LinuxSll] {
                for &target in &[Target::Classic, Target::Extended] {
                    let r = compile(filter, link, target);
                    assert!(
                        matches!(r, Err(Error::ParseError { .. })),
                        "compile({filter:?}, {link:?}, {target:?}) must be a ParseError, got {r:?}"
                    );
                }
            }
        }
    });
}

#[test]
fn offset_expr_valid_forms_unchanged_by_overflow_checks() {
    // Checked arithmetic must not change results that are in range.
    for (expr, plain) in [
        ("ip[1<<3] = 0", "ip[8] = 0"),
        ("ip[8/2] = 0", "ip[4] = 0"),
        ("ip[-4/-2+2] = 0", "ip[4] = 0"),
        ("ip[(1<<30)/(1<<29)] = 0", "ip[2] = 0"),
        ("ip[-(1<<62)/-(1<<61)] = 0", "ip[2] = 0"),
    ] {
        assert_eq!(
            eth_prog(expr).instructions(),
            eth_prog(plain).instructions(),
            "{expr} must compile like {plain}"
        );
    }
}

// ── Regression: nested offset expressions must not stack-overflow (#135) ──────
// `parse_offset_atom` recursed once per `(` and once per unary `-` with no depth
// limit, so a few KB of `ip[(((...1...)))]` aborted the process (an uncatchable
// stack overflow).  libpcap 1.10.3 compiles moderate nesting and fails cleanly
// ("memory exhausted") on extreme nesting; pktbaffle must return
// `Err(ParseError)` and never abort.

/// Offset-expression bodies that nest `n` deep and evaluate to `1` for even `n`:
/// parens, bare unary minus, and minus-then-paren.
fn nested_offset_bodies(n: usize) -> [String; 3] {
    [
        format!("{}1{}", "(".repeat(n), ")".repeat(n)),
        format!("{}1", "-".repeat(n)),
        format!("{}1{}", "-(".repeat(n), ")".repeat(n)),
    ]
}

#[test]
fn deeply_nested_offset_expr_returns_error_not_stack_overflow() {
    use pktbaffle::{parse, Error};

    // 100_000 levels on a 256 KiB stack: must be a clean ParseError for the
    // primary offset and for the RHS `op ip[..]` load, on every link type and
    // both targets.
    on_small_stack(256, || {
        for body in nested_offset_bodies(100_000) {
            for filter in [
                format!("ip[{body}] = 0"),
                format!("tcp[{body}:2] = 0"),
                format!("ip[0] = ip[{body}]"),
            ] {
                assert!(
                    matches!(parse(&filter), Err(Error::ParseError { .. })),
                    "parse of a {}-byte nested offset must be a ParseError",
                    filter.len()
                );
                for &link in &[LinkType::Ethernet, LinkType::RawIp, LinkType::LinuxSll] {
                    for &target in &[Target::Classic, Target::Extended] {
                        let r = compile(&filter, link, target);
                        assert!(
                            matches!(r, Err(Error::ParseError { .. })),
                            "compile of a {}-byte nested offset ({link:?}, {target:?}) \
                             must be a ParseError, got {r:?}",
                            filter.len()
                        );
                    }
                }
            }
        }
    });
}

#[test]
fn moderately_nested_offset_expr_still_compiles() {
    // N = 20 is far below the depth limit and evaluates to offset 1.
    let plain = eth_prog("ip[1] = 0");
    for body in nested_offset_bodies(20) {
        let f = format!("ip[{body}] = 0");
        assert_eq!(
            eth_prog(&f).instructions(),
            plain.instructions(),
            "a 20-deep nested offset must compile like ip[1]"
        );
        assert!(pktbaffle::parse(&f).is_ok());
        assert!(compile(&f, LinkType::Ethernet, Target::Extended).is_ok());
    }

    // Sibling groups must give their depth back: 200 of them in a row is far
    // more levels than the limit allows if they leaked.
    let siblings = format!("ip[{}] = 0", vec!["(1)"; 200].join("+"));
    assert_eq!(
        eth_prog(&siblings).instructions(),
        eth_prog("ip[200] = 0").instructions()
    );
}

#[test]
fn nested_parens_around_nested_offset_expr_return_error() {
    use pktbaffle::Error;

    // Deep nesting of both parenthesised expressions and offset expressions
    // cannot add up to a stack overflow. (Until #199 the two shared one depth
    // budget; outer parens now cost no stack, so the offset keeps its own.)
    on_small_stack(256, || {
        for outer in [0, 50, 100, 126, 9995] {
            let filter = format!(
                "{}ip[{}1{}] = 0{}",
                "(".repeat(outer),
                "(".repeat(100_000),
                ")".repeat(100_000),
                ")".repeat(outer)
            );
            let r = compile(&filter, LinkType::Ethernet, Target::Classic);
            assert!(
                matches!(r, Err(Error::ParseError { .. })),
                "{outer} outer parens: expected ParseError, got {r:?}"
            );
        }
    });
}

// ── Regression: long and/or/not chains must not stack-overflow (#149) ────────
// `a or b or ...`, `a and b and ...` and `!!!...x` build an AST as deep as the
// chain is long, and dropping it, emitting cBPF or eBPF, or (for `!`) parsing
// it recursed once per term with no limit: a few hundred terms aborted a debug
// build on a 1 MiB stack (an uncatchable stack overflow). libpcap 1.10.3
// compiles a 15000-term `tcp or ...` and a 1000-term host list (per the issue;
// not re-run here). Every input below must now return `Ok` or `Err`.

/// `term op term op ...` with `n` terms.
fn chain(term: &str, op: &str, n: usize) -> String {
    vec![term; n].join(&format!(" {op} "))
}

/// The long-chain inputs: `or`, `and`, juxtaposition, `!` and `not` chains.
fn long_chains(n: usize) -> Vec<String> {
    vec![
        chain("tcp", "or", n),
        chain("tcp", "and", n),
        vec!["tcp"; n].join(" "),
        format!("{}tcp", "!".repeat(n)),
        format!("{}tcp", "not ".repeat(n)),
    ]
}

#[test]
fn long_chains_compile_on_small_stack() {
    on_small_stack(256, || {
        for filter in long_chains(5000) {
            for &link in &[LinkType::Ethernet, LinkType::RawIp, LinkType::LinuxSll] {
                for &target in &[Target::Classic, Target::Extended] {
                    // Ok or Err are both fine; returning at all is the test.
                    let _ = compile(&filter, link, target);
                }
            }
        }
    });
}

#[test]
fn million_term_chain_parses_and_drops_on_small_stack() {
    use pktbaffle::ast::Expr;

    on_small_stack(256, || {
        for op in ["or", "and"] {
            let expr = pktbaffle::parse(&chain("tcp", op, 1_000_000)).unwrap();
            // Left-deep: the left spine holds every operator.
            let (mut depth, mut e) = (0, &expr);
            while let Expr::Or(l, _) | Expr::And(l, _) = e {
                depth += 1;
                e = l;
            }
            assert_eq!(depth, 999_999, "{op} chain");
            drop(expr);
        }
        for neg in ["!", "not "] {
            let expr = pktbaffle::parse(&format!("{}tcp", neg.repeat(100_000))).unwrap();
            let (mut depth, mut e) = (0, &expr);
            while let Expr::Not(inner) = e {
                depth += 1;
                e = inner;
            }
            assert_eq!(depth, 100_000, "{neg:?} chain");
        }
    });
}

#[test]
fn deep_hand_built_trees_compile_on_small_stack() {
    use pktbaffle::ast::{Expr, Primitive, Proto};
    use pktbaffle::{codegen, ebpf_codegen};

    // The public codegen entry points take any `Expr`, including right-deep
    // and mixed shapes the parser only produces through parentheses.
    on_small_stack(256, || {
        let tcp = || Expr::Primitive(Primitive::Proto(Proto::Tcp));
        let mut right_or = tcp();
        let mut right_and = tcp();
        let mut mixed = tcp();
        for i in 0..5000 {
            right_or = Expr::Or(Box::new(tcp()), Box::new(right_or));
            right_and = Expr::And(Box::new(tcp()), Box::new(right_and));
            mixed = match i % 3 {
                0 => Expr::Not(Box::new(mixed)),
                1 => Expr::And(Box::new(mixed), Box::new(tcp())),
                _ => Expr::Or(Box::new(tcp()), Box::new(mixed)),
            };
        }
        for expr in [&right_or, &right_and, &mixed] {
            for &link in &[LinkType::Ethernet, LinkType::RawIp] {
                let _ = codegen::compile(expr, link);
                let _ = ebpf_codegen::compile(expr, link);
            }
        }
    });
}

// ── Regression: Expr Clone, PartialEq and Debug must not recurse per node (#229)
// The derived impls recursed once per tree level, so cloning, comparing or
// `{:?}`-printing a parsed 1,000-term chain aborted a 256 KiB stack.

/// Chain shapes: left-deep `or` / `and` (what the parser builds), a `!` chain
/// and a right-deep `or`. Built by hand rather than parsed so the deepest
/// leaf can differ without re-lexing a million terms.
const CHAIN_SHAPES: [&str; 4] = ["or", "and", "not", "right"];

/// An `n`-term chain of `shape` over `leaf`, with `tcp` as every other leaf.
fn deep_tree(shape: &str, n: usize, leaf: pktbaffle::ast::Expr) -> pktbaffle::ast::Expr {
    use pktbaffle::ast::{Expr, Primitive, Proto};

    let tcp = || Box::new(Expr::Primitive(Primitive::Proto(Proto::Tcp)));
    let mut e = leaf;
    for _ in 0..n {
        e = match shape {
            "or" => Expr::Or(Box::new(e), tcp()),
            "and" => Expr::And(Box::new(e), tcp()),
            "not" => Expr::Not(Box::new(e)),
            _ => Expr::Or(tcp(), Box::new(e)),
        };
    }
    e
}

#[test]
fn million_term_chains_clone_and_compare_on_small_stack() {
    use pktbaffle::ast::{Expr, Primitive, Proto};

    on_small_stack(256, || {
        let leaf = |p| Expr::Primitive(Primitive::Proto(p));
        for shape in CHAIN_SHAPES {
            let a = deep_tree(shape, 1_000_000, leaf(Proto::Tcp));
            let b = deep_tree(shape, 1_000_000, leaf(Proto::Udp));
            let copy = a.clone();
            assert!(copy == a, "{shape}: clone differs from original");
            // The chains differ only at the deepest leaf: the comparison
            // must walk all the way down to see it.
            assert!(a != b, "{shape}: chains differing at the bottom are equal");
            assert!(copy != b, "{shape}: clone equals a different chain");
        }
        // Parsed chains: the left spine holds every operator.
        for op in ["or", "and"] {
            let e = pktbaffle::parse(&chain("tcp", op, 1_000_000)).unwrap();
            let other = pktbaffle::parse(&chain("tcp", op, 999_999)).unwrap();
            let copy = e.clone();
            assert!(copy == e, "parsed {op} chain");
            assert!(copy != other, "parsed {op} chains of different length");
        }
    });
}

#[test]
fn expr_eq_distinguishes_variants_and_payloads() {
    use pktbaffle::parse;

    let p = |s: &str| parse(s).unwrap();
    assert!(p("tcp or udp") == p("tcp or udp"));
    assert!(p("tcp or udp") != p("tcp and udp"));
    assert!(p("tcp or udp") != p("udp or tcp"));
    assert!(p("not tcp") != p("tcp"));
    assert!(p("not tcp") == p("!tcp"));
    assert!(p("port 80") != p("port 81"));
    assert!(p("port 80") != p("src port 80"));
    assert!(p("tcp[13] & 2 != 0") != p("tcp[13] & 3 != 0"));
    assert!(p("tcp or udp or icmp") != p("tcp or (udp or icmp)"));
}

#[test]
fn million_term_chains_debug_format_on_small_stack() {
    use pktbaffle::ast::{Expr, Primitive, Proto};

    on_small_stack(256, || {
        let tcp = Expr::Primitive(Primitive::Proto(Proto::Tcp));
        for shape in CHAIN_SHAPES {
            let e = deep_tree(shape, 1_000_000, tcp.clone());
            for s in [format!("{e:?}"), format!("{e:#?}")] {
                // Elided: bounded output, not one entry per node.
                assert!(s.len() < 1 << 20, "{shape}: {} bytes of output", s.len());
                assert!(s.contains(".."), "{shape}: printed without elision");
            }
        }
        let parsed = pktbaffle::parse(&chain("tcp", "or", 1_000_000)).unwrap();
        assert!(format!("{parsed:?}").starts_with("Or(Or(Or("));
        // A `!` chain shows exactly the documented 128 levels, then `..`.
        let nots = deep_tree("not", 1_000_000, tcp);
        assert_eq!(
            format!("{nots:?}"),
            format!("{}..{}", "Not(".repeat(129), ")".repeat(129))
        );
    });
}

/// `ast::Expr` as `#[derive(Debug)]` would write it, to pin that the
/// hand-written `Debug` prints the same bytes. (Fields are only read by the
/// derived `Debug`, which dead-code analysis ignores.)
#[derive(Debug)]
#[allow(dead_code)]
enum DerivedExpr {
    And(Box<DerivedExpr>, Box<DerivedExpr>),
    Or(Box<DerivedExpr>, Box<DerivedExpr>),
    Not(Box<DerivedExpr>),
    Primitive(pktbaffle::ast::Primitive),
}

fn derived_mirror(e: &pktbaffle::ast::Expr) -> DerivedExpr {
    use pktbaffle::ast::Expr;

    match e {
        Expr::And(l, r) => {
            DerivedExpr::And(Box::new(derived_mirror(l)), Box::new(derived_mirror(r)))
        }
        Expr::Or(l, r) => DerivedExpr::Or(Box::new(derived_mirror(l)), Box::new(derived_mirror(r))),
        Expr::Not(x) => DerivedExpr::Not(Box::new(derived_mirror(x))),
        Expr::Primitive(p) => DerivedExpr::Primitive(p.clone()),
        _ => unreachable!("new Expr variant: extend DerivedExpr"),
    }
}

#[test]
fn expr_debug_matches_derived_output() {
    use pktbaffle::ast::{Expr, Primitive, Proto};

    let mut exprs: Vec<Expr> = [
        "tcp",
        "not tcp",
        "tcp and udp",
        "tcp or udp",
        "!(tcp and udp) or port 80",
        "src net 192.168.0.0/16 or ip6 host ::1 and not ether host 00:11:22:33:44:55",
        "src portrange 1000-2000 or vlan 5 or mpls or less 100 or inbound",
        "tcp[13] & 2 != 0 or ip[2:2] = 40 or tcp[0] = tcp[4]",
        "host 10.0.0.1 and (port 22 or port 80) and not (icmp or ip proto 47)",
    ]
    .iter()
    .map(|f| pktbaffle::parse(f).unwrap())
    .collect();
    // Deepest trees printed in full: 128 levels (and a long parsed chain).
    exprs.push(pktbaffle::parse(&chain("tcp", "or", 100)).unwrap());
    let leaf = || Expr::Primitive(Primitive::Proto(Proto::Tcp));
    let (mut nots, mut ands) = (leaf(), leaf());
    for _ in 0..128 {
        nots = Expr::Not(Box::new(nots));
        ands = Expr::And(Box::new(leaf()), Box::new(ands));
    }
    exprs.extend([nots, ands]);

    for e in &exprs {
        let want = derived_mirror(e);
        assert_eq!(format!("{e:?}"), format!("{want:?}"));
        assert_eq!(format!("{e:#?}"), format!("{want:#?}"));
        // Formatter flags reach the leaves exactly as they do when derived.
        assert_eq!(format!("{e:x?}"), format!("{want:x?}"));
        assert_eq!(format!("{e:#X?}"), format!("{want:#X?}"));
    }
}

#[test]
fn long_and_chain_compiles_like_one_term() {
    // Every later `tcp` is elided by the facts the first one proves.
    on_small_stack(1024, || {
        assert_eq!(
            eth_prog(&chain("tcp", "and", 5000)).instructions(),
            eth_prog("tcp").instructions()
        );
    });
}

/// `host 10.0.0.1 or host 10.0.0.2 ... or host 10.0.3.232` (1000 hosts).
fn thousand_host_list() -> String {
    (1u32..=1000)
        .map(|i| format!("host 10.0.{}.{}", i >> 8, i & 0xff))
        .collect::<Vec<_>>()
        .join(" or ")
}

#[test]
fn thousand_host_list_compiles_for_extended_on_1mib_stack() {
    // #149 acceptance: libpcap 1.10.3 compiles this list (1259 insns, per the
    // issue). 1 MiB is the Windows main-thread stack; this runs in debug too.
    on_small_stack(1024, || {
        let r = compile(&thousand_host_list(), LinkType::Ethernet, Target::Extended);
        assert!(
            r.is_ok(),
            "1000-host list must compile for eBPF: {:?}",
            r.err()
        );
    });
}

// ── Nested parentheses up to libpcap's limit (#199) ──────────────────────────
// The parser rejected 128 or more nested parentheses. libpcap 1.10.3 accepts
// 9995 around a primitive and fails with "memory exhausted" at 9996 (verified
// in the issue; not re-run here). pktbaffle now accepts the same 9995.

/// `n` nested parentheses around `body`.
fn parens(n: usize, body: &str) -> String {
    format!("{}{body}{}", "(".repeat(n), ")".repeat(n))
}

#[test]
fn nested_parens_up_to_9995_compile_on_small_stack() {
    on_small_stack(256, || {
        let tcp = pktbaffle::parse("tcp").unwrap();
        let tcp_classic = compile("tcp", LinkType::Ethernet, Target::Classic).unwrap();
        let tcp_ebpf = compile("tcp", LinkType::Ethernet, Target::Extended).unwrap();
        for n in [127, 128, 1000, 9995] {
            let f = parens(n, "tcp");
            // Parentheses add no AST nodes.
            assert_eq!(pktbaffle::parse(&f).unwrap(), tcp, "{n} parens");
            let c = compile(&f, LinkType::Ethernet, Target::Classic).unwrap();
            assert_eq!(c.instructions(), tcp_classic.instructions(), "{n} parens");
            let e = compile(&f, LinkType::Ethernet, Target::Extended).unwrap();
            assert_eq!(
                e.as_extended().unwrap().instructions(),
                tcp_ebpf.as_extended().unwrap().instructions(),
                "{n} parens"
            );
        }
    });
}

#[test]
fn nested_parens_past_9995_return_parse_error() {
    use pktbaffle::Error;

    on_small_stack(256, || {
        for n in [9996, 100_000] {
            let f = parens(n, "tcp");
            let r = pktbaffle::parse(&f);
            match &r {
                Err(Error::ParseError { message }) => {
                    assert!(message.contains("9995"), "{n} parens: {message}")
                }
                _ => panic!("{n} parens: expected ParseError, got {r:?}"),
            }
            for &target in &[Target::Classic, Target::Extended] {
                let r = compile(&f, LinkType::Ethernet, target);
                assert!(
                    matches!(r, Err(Error::ParseError { .. })),
                    "{n} parens, {target:?}: got {r:?}"
                );
            }
        }
    });
}

#[test]
fn deep_parens_mixed_with_operators_compile_on_small_stack() {
    use pktbaffle::ast::Expr;

    on_small_stack(256, || {
        // `!(!(...tcp...))`, `tcp and (tcp and (...))`, and the worst case for
        // the remaining recursion: 9995 parens around the deepest offset
        // expression accepted (31 nested `(` inside `[...]`).
        let not_nest = format!("{}tcp{}", "!(".repeat(9995), ")".repeat(9995));
        let and_nest = format!("{}tcp{}", "tcp and (".repeat(9995), ")".repeat(9995));
        let offset = parens(9995, &format!("ip[{}] = 0", parens(31, "1")));
        let expr = pktbaffle::parse(&and_nest).unwrap();
        // Right-deep: each level is `tcp and (...)`.
        let (mut depth, mut e) = (0, &expr);
        while let Expr::And(_, r) = e {
            depth += 1;
            e = r;
        }
        assert_eq!(depth, 9995);
        for f in [&not_nest, &and_nest, &offset] {
            for &target in &[Target::Classic, Target::Extended] {
                // eBPF runs out of jump range on the 9995-term `and` chain,
                // exactly as on the flat chain; parsing always succeeds.
                let r = compile(f, LinkType::Ethernet, target);
                assert!(
                    !matches!(r, Err(pktbaffle::Error::ParseError { .. })),
                    "{target:?}: {}...: {r:?}",
                    &f[..20]
                );
            }
        }
    });
}

// ── Regression: compile time is linear in chain length (#202) ────────────────
// Long left-deep `and` / `or` / `!` chains compiled in quadratic time: every OR
// recomputed its arms' guard sets, every AND rescanned its left spine for a
// leading `vlan` and copied the accumulated failure list, and jump threading
// chased each `ja` trampoline chain to its end. A 32000-term `tcp or ...`
// took 8.6 s (release). These tests compare sizes n and 4n instead of timing
// against a threshold: linear work grows ~4x, quadratic ~16x.

/// Fastest of three runs of `f`, in seconds.
fn fastest(f: impl Fn()) -> f64 {
    (0..3)
        .map(|_| {
            let t = std::time::Instant::now();
            f();
            t.elapsed().as_secs_f64()
        })
        .fold(f64::INFINITY, f64::min)
}

/// `f(4 * n)` must take less than 10x as long as `f(n)`, with 5 ms of slack
/// for timer noise.
fn assert_linear(name: &str, n: usize, f: impl Fn(usize)) {
    let small = fastest(|| f(n));
    let large = fastest(|| f(4 * n));
    assert!(
        large < 10.0 * small + 0.005,
        "{name}: {n} terms took {small:.4}s but {} took {large:.4}s",
        4 * n
    );
}

#[test]
fn compile_time_is_linear_in_chain_length() {
    let run = |target: Target, filter: String| {
        // Ok or "too complex" Err: only the time matters here.
        let _ = compile(&filter, LinkType::Ethernet, target);
    };
    for target in [Target::Classic, Target::Extended] {
        assert_linear(&format!("{target:?} or"), 8000, |n| {
            run(target, chain("tcp", "or", n))
        });
        assert_linear(&format!("{target:?} and"), 8000, |n| {
            run(target, chain("tcp", "and", n))
        });
        assert_linear(&format!("{target:?} !"), 64_000, |n| {
            run(target, format!("{}tcp", "!".repeat(n)))
        });
        // Right-deep, through parentheses (within the 9995 limit).
        assert_linear(&format!("{target:?} nested and"), 2000, |n| {
            run(
                target,
                format!("{}tcp{}", "tcp and (".repeat(n), ")".repeat(n)),
            )
        });
        assert_linear(&format!("{target:?} nested or"), 2000, |n| {
            run(
                target,
                format!("{}tcp{}", "tcp or (".repeat(n), ")".repeat(n)),
            )
        });
    }
}

#[test]
fn optimizer_time_is_linear_in_ja_chain_length() {
    use pktbaffle::bpf::Insn;

    // `n` chained `ja 0` trampolines in front of `ret #-1`: every one threads
    // to the `ret`. (#202: 64004 of these took about 1.5 s.)
    assert_linear("optimize ja chain", 16_000, |n| {
        let mut insns = vec![Insn::ja(0); n];
        insns.push(Insn::ret_k(0xffff_ffff));
        pktbaffle::optimizer::optimize(&mut insns);
        // The first `ja` now jumps straight to the `ret`; the rest are dead.
        assert_eq!(insns, [Insn::ja(0), Insn::ret_k(0xffff_ffff)]);
    });
}

#[test]
fn hundred_thousand_term_chains_compile_on_small_stack() {
    // #149 acceptance, practical only once compile time is linear: on a
    // 256 KiB stack a 100000-term `or` / `and` chain returns for both targets.
    on_small_stack(256, || {
        for op in ["or", "and"] {
            let f = chain("tcp", op, 100_000);
            for &target in &[Target::Classic, Target::Extended] {
                let _ = compile(&f, LinkType::Ethernet, target);
            }
        }
        // The `and` chain is still just `tcp` in cBPF.
        assert_eq!(
            eth_prog(&chain("tcp", "and", 100_000)).instructions(),
            eth_prog("tcp").instructions()
        );
    });
}

// ── Integer literals follow C syntax, as libpcap's scanner (#157) ─────────────
// libpcap 1.10.3 (scanner.l `stou`): `0x` hex, a leading `0` octal, otherwise
// decimal; `08` is an error. Expected trees hand-derived from that and issue #157.

#[test]
fn leading_zero_integers_are_octal_in_every_position() {
    for (octal, decimal) in [
        ("tcp port 010", "tcp port 8"),
        ("portrange 010-020", "portrange 8-16"),
        ("ip proto 017", "ip proto 15"),
        ("ether proto 0100", "ether proto 64"),
        ("vlan 010", "vlan 8"),
        ("mpls 010", "mpls 8"),
        ("less 010", "less 8"),
        ("len = 0100", "len = 64"),
        ("ip[010] = 1", "ip[8] = 1"),
        ("ip[8] = 010", "ip[8] = 8"),
        ("net 10.0.0.0/010", "net 10.0.0.0/8"),
        ("net 10.0.0.0/0x8", "net 10.0.0.0/8"),
        ("net 2001:db8::/040", "net 2001:db8::/32"),
        // Unchanged: 0 and 00 are 0, and decimal literals stay decimal.
        ("port 00", "port 0"),
        ("port 0", "port 0"),
        ("tcp port 80", "tcp port 0x50"),
    ] {
        assert_eq!(ast(octal), ast(decimal), "{octal:?} vs {decimal:?}");
    }
}

#[test]
fn octal_literals_differ_from_the_decimal_reading() {
    assert_ne!(ast("tcp port 010"), ast("tcp port 10"));
    assert_ne!(ast("net 10.0.0.0/010"), ast("net 10.0.0.0/10"));
}

#[test]
fn non_octal_digit_after_a_leading_zero_is_an_error() {
    for f in [
        "tcp port 08",
        "tcp port 09",
        "port 0800",
        "vlan 08",
        "less 08",
        "ip[08] = 1",
        "ether proto 0800",
        "net 10.0.0.0/08",
        "net 2001:db8::/09",
    ] {
        assert!(pktbaffle::parse(f).is_err(), "{f:?} must be rejected");
    }
}

#[test]
fn integer_over_32_bits_is_an_error_in_every_position() {
    // libpcap: "number ... overflows 32 bits".
    for f in [
        "greater 4294967296",
        "port 0x100000000",
        "ip[0] = 4294967296",
    ] {
        assert!(pktbaffle::parse(f).is_err(), "{f:?} must be rejected");
    }
    assert!(pktbaffle::parse("greater 4294967295").is_ok());
}

// ── Zero-padded octets in dotted IPv4 literals (#191) ─────────────────────────
// libpcap 1.10.3 parses each octet as plain decimal (`pcap_atoin`), so `010` in
// a dotted quad is 10, not octal. Expected trees hand-derived from issue #191.

#[test]
fn zero_padded_dotted_octets_are_decimal() {
    for (padded, plain) in [
        ("host 010.1.2.3", "host 10.1.2.3"),
        ("host 1.2.3.04", "host 1.2.3.4"),
        ("host 192.168.001.001", "host 192.168.1.1"),
        ("host 00.0.0.1", "host 0.0.0.1"),
        ("net 010.0.0.0/8", "net 10.0.0.0/8"),
        (
            "net 10.0.0.0 mask 255.255.255.000",
            "net 10.0.0.0 mask 255.255.255.0",
        ),
        ("net 10.0.0.0 mask 255.255.255.000", "net 10.0.0.0/24"),
        // The 1-3 octet forms already accepted padding; they keep doing so.
        ("net 010.1.2", "net 10.1.2"),
        ("host 10.01", "host 10.1"),
    ] {
        assert_eq!(ast(padded), ast(plain), "{padded:?} vs {plain:?}");
    }
}

#[test]
fn malformed_dotted_addresses_are_still_errors() {
    for f in [
        "host 10.256.0.1",
        "host 0x0a.0.0.1",
        "host 1.2.3.4.5",
        "host 1.2.3.",
        "net 10.0.0.0 mask 255.255.255.256",
    ] {
        assert!(pktbaffle::parse(f).is_err(), "{f:?} must be rejected");
    }
}

// ── `/` before a prefix length is an ordinary token (#194, #173) ──────────────
// libpcap 1.10.3 grammar: `HID '/' NUM`, `HID6 '/' NUM`, `HID NETMASK HID`; a bare
// number after an address is a syntax error. Expected trees hand-derived from
// that and issues #194 and #173.

#[test]
fn whitespace_and_hex_around_the_prefix_slash() {
    for (spaced, glued) in [
        ("net 10.0.0.0 / 8", "net 10.0.0.0/8"),
        ("net 10.0.0.0 /8", "net 10.0.0.0/8"),
        ("net 10.0.0.0/ 8", "net 10.0.0.0/8"),
        ("net 10.0.0.0/0x8", "net 10.0.0.0/8"),
        ("net 10.0.0.0/010", "net 10.0.0.0/8"),
        ("net 2001:db8:: /32", "net 2001:db8::/32"),
        ("net 2001:db8::/ 32", "net 2001:db8::/32"),
        ("net 2001:db8::/0x20", "net 2001:db8::/32"),
        (
            "src net fe80:: /10 and port 80",
            "src net fe80::/10 and port 80",
        ),
    ] {
        assert_eq!(ast(spaced), ast(glued), "{spaced:?} vs {glued:?}");
    }
}

#[test]
fn bare_number_after_a_network_is_a_syntax_error() {
    for f in [
        "net 10.0.0.0 8",
        "net 10 8",
        "net 2001:db8:: 32",
        "src net 192.168.1.0 24 and port 80",
        "net 10 mask 255.0.0.0",
        "net 10.0.0.0/",
        "net 10.0.0.0/abc",
        "net 2001:db8::/",
    ] {
        assert!(pktbaffle::parse(f).is_err(), "{f:?} must be rejected");
    }
}

#[test]
fn slash_prefix_regressions() {
    // Behaviour-preservation guards: a prefix still combines with `and`, and a
    // `/` in a byte-access expression is still division.
    assert!(pktbaffle::parse("net 10.0.0.0/8 and tcp").is_ok());
    assert!(pktbaffle::parse("ip[2] / 2 = 1").is_ok());
    assert!(pktbaffle::parse("net 10.0.0.0/33").is_err());
    assert!(pktbaffle::parse("net 2001:db8::/129").is_err());
}

#[test]
fn ipv6_net_starting_with_double_colon_takes_a_prefix() {
    for f in [
        "net ::/0",
        "net ::1/128",
        "net ::ffff:0:0/96",
        "net ::ffff:1.2.3.4/128",
        "ip6 net ::/32",
        "src net ::1/128",
        "dst net ::/0",
        "not net ::/0",
        "net ::/0 and tcp",
        "net ::1 /128",
        "net :: / 0",
    ] {
        assert!(pktbaffle::parse(f).is_ok(), "{f:?} must compile");
    }
    // The same network spelled with a leading digit is the same tree.
    for n in 0..=128 {
        assert_eq!(
            ast(&format!("net ::/{n}")),
            ast(&format!("net 0::/{n}")),
            "/{n}"
        );
    }
    assert!(pktbaffle::parse("net ::/129").is_err());
}

#[test]
fn host_ipv6_accepts_only_a_slash_128() {
    // libpcap: `host ::1/128` is a /128 net; any other length is "Mask syntax
    // for networks only".
    assert_eq!(ast("host ::1/128"), ast("host ::1"));
    assert_eq!(ast("src ::1/128"), ast("src host ::1"));
    for f in ["host ::1/64", "host ::1/129", "host 10.0.0.1/32"] {
        assert!(pktbaffle::parse(f).is_err(), "{f:?} must be rejected");
    }
}

// ── Diagnostics for malformed numbers and prefix lengths (#210) ───────────────
// Every input below is rejected by libpcap 1.10.3 too; only the diagnostic was
// wrong. Most of the fix landed with #157 (numbers), #191 (dotted octets) and
// #194 (the lexer no longer reads prefix lengths), so those tests are guards
// that fail on `main`; the offset of a missing prefix length is new here.

/// Rejected filters, with non-ASCII input, that cover every lexer error path.
const REJECTED: &[&str] = &[
    "net 10.0.0.0/",
    "net 10.0.0.0/abc",
    "net 10.0.0.0/99999999999999999999999",
    "host 2001:db8::1/",
    "ip6 net fe80::/\u{e9}",
    "host 10.0.0.256",
    "host 1.2.3.4.5",
    "port 12abc",
    "ip[0x]=1",
    "ip[0x1g]=1",
    "port 99999999999999999999",
    "greater 4294967296",
    "port 08",
    "tcp port ???",
    "\u{e9}",
    "host 10.0.0.1 \u{1f980}",
    "port 80 \u{e9}\u{e9}",
    ".1.2.3",
];

#[test]
fn lex_error_offset_and_char_agree() {
    for f in REJECTED {
        if let Err(pktbaffle::Error::LexError { offset, ch }) = pktbaffle::parse(f) {
            assert!(
                f.is_char_boundary(offset) && f[offset..].starts_with(ch),
                "{f:?}: LexError {{ offset: {offset}, ch: {ch:?} }} does not point at {ch:?}"
            );
        }
    }
    // The characters the lexer really does not know keep their exact position.
    assert_eq!(
        pktbaffle::parse("tcp port ???").unwrap_err(),
        pktbaffle::Error::LexError { offset: 9, ch: '?' }
    );
    assert_eq!(
        pktbaffle::parse("port 80 \u{e9}\u{e9}").unwrap_err(),
        pktbaffle::Error::LexError {
            offset: 8,
            ch: '\u{e9}'
        }
    );
}

#[test]
fn malformed_number_error_names_the_literal() {
    for (f, literal) in [
        ("port 99999999999999999999", "99999999999999999999"),
        ("host 10.0.0.256", "10.0.0.256"),
        ("ip[0x]=1", "0x"),
        ("port 12abc", "12abc"),
        ("port 08", "08"),
    ] {
        match pktbaffle::parse(f) {
            Err(pktbaffle::Error::ParseError { message }) => {
                assert!(
                    message.contains(&format!("'{literal}'")),
                    "{f:?}: {message}"
                )
            }
            other => panic!("{f:?}: expected a ParseError naming {literal:?}, got {other:?}"),
        }
    }
}

#[test]
fn over_32_bit_literals_are_one_kind_of_error() {
    // `greater 4294967296` used to fail in the parser and a larger literal in
    // the lexer, with two different error kinds.
    let kind = |f| std::mem::discriminant(&pktbaffle::parse(f).unwrap_err());
    assert_eq!(
        kind("greater 4294967296"),
        kind("greater 99999999999999999999")
    );
    assert_eq!(kind("greater 4294967296"), kind("greater 0x100000000"));
}

#[test]
fn missing_prefix_length_reports_the_slash_offset() {
    for (f, slash) in [
        ("net 10.0.0.0/", 12),
        ("net 10.0.0.0/abc", 12),
        ("net 10.0.0.0 / and tcp", 13),
        ("host 2001:db8::1/", 16),
        ("net 2001:db8::/", 14),
    ] {
        match pktbaffle::parse(f) {
            Err(pktbaffle::Error::ParseError { message }) => assert!(
                message.contains(&format!("at offset {slash}")) && f.as_bytes()[slash] == b'/',
                "{f:?}: {message}"
            ),
            other => panic!("{f:?}: expected a ParseError, got {other:?}"),
        }
    }
}

// ── A bare integer is an IPv4 host or net (#190) ──────────────────────────────
// libpcap 1.10.3 `gen_ncode`: `host N` is the exact 32-bit address N; `net N`
// shifts N (and an all-ones mask) left a byte at a time until the top byte is
// non-zero. Expected trees hand-derived from that and issue #190.

#[test]
fn host_takes_a_bare_integer_as_the_address() {
    for (bare, dotted) in [
        ("host 10", "host 0.0.0.10"),
        ("src host 10", "src host 0.0.0.10"),
        ("dst host 10", "dst host 0.0.0.10"),
        ("ip host 10", "ip host 0.0.0.10"),
        ("host 0x0a000001", "host 10.0.0.1"),
        ("host 167772161", "host 10.0.0.1"),
        ("host 4294967295", "host 255.255.255.255"),
        ("host 0", "host 0.0.0.0"),
        // After a direction, the type keyword is optional (like `src 1.2.3.4`).
        ("src 10", "src host 0.0.0.10"),
        ("dst 0x0a000001", "dst host 10.0.0.1"),
    ] {
        assert_eq!(ast(bare), ast(dotted), "{bare:?} vs {dotted:?}");
    }
}

#[test]
fn net_promotes_a_short_integer_to_a_prefix() {
    for (bare, cidr) in [
        ("net 10", "net 10.0.0.0/8"),
        ("net 255", "net 255.0.0.0/8"),
        ("net 256", "net 1.0.0.0/16"),
        ("net 300", "net 1.44.0.0/16"),
        ("net 65536", "net 1.0.0.0/24"),
        ("net 16777216", "net 1.0.0.0/32"),
        ("net 4294967295", "net 255.255.255.255/32"),
        ("src net 256", "src net 1.0.0.0/16"),
        ("dst net 65536", "dst net 1.0.0.0/24"),
        // `net 0` has no byte to shift: libpcap treats it as the exact address.
        ("net 0", "net 0.0.0.0/32"),
    ] {
        assert_eq!(ast(bare), ast(cidr), "{bare:?} vs {cidr:?}");
    }
}

#[test]
fn bare_integer_over_32_bits_is_still_rejected() {
    for f in [
        "host 4294967296",
        "net 4294967296",
        "src 4294967296",
        "host 0x100000000",
    ] {
        assert!(pktbaffle::parse(f).is_err(), "{f:?} must be rejected");
    }
}

// ── Dotted IPv4 host/net: the written octet count sets the mask (#158) ────────
// libpcap 1.10.3 `gen_ncode`: `v <<= 32 - vlen; mask <<= 32 - vlen` with vlen = 8
// per octet written, for both `host` and `net`: `10` is /8, `10.0` /16, `10.0.0`
// /24, `10.0.0.0` /32. Expected trees hand-derived from that and issue #158.

#[test]
fn net_mask_comes_from_the_octets_written() {
    for (short, cidr) in [
        ("net 10.0.0.0", "net 10.0.0.0/32"),
        ("net 192.168.1.0", "net 192.168.1.0/32"),
        ("net 192.168.1.77", "net 192.168.1.77/32"),
        ("net 10.0", "net 10.0.0.0/16"),
        ("net 10.0.0", "net 10.0.0.0/24"),
        ("net 10.1.0", "net 10.1.0.0/24"),
        ("net 10.1", "net 10.1.0.0/16"),
        ("src net 10.0", "src net 10.0.0.0/16"),
        ("dst net 10.0.0", "dst net 10.0.0.0/24"),
        // Unchanged: one octet, an explicit prefix, an explicit mask.
        ("net 10", "net 10.0.0.0/8"),
        ("net 192.168", "net 192.168.0.0/16"),
        ("net 10.0.1", "net 10.0.1.0/24"),
        ("net 10.1/24", "net 10.1.0.0/24"),
        ("net 10.0.0.0 mask 255.255.0.0", "net 10.0.0.0/16"),
    ] {
        assert_eq!(ast(short), ast(cidr), "{short:?} vs {cidr:?}");
    }
}

#[test]
fn host_with_fewer_than_four_octets_is_a_network() {
    for (host, net) in [
        ("host 10.1", "net 10.1.0.0/16"),
        ("host 10.1.2", "net 10.1.2.0/24"),
        ("src host 10.1", "src net 10.1.0.0/16"),
        ("dst host 10.1.2", "dst net 10.1.2.0/24"),
        ("src and dst host 10.1", "src and dst net 10.1.0.0/16"),
        ("src 10.1", "src net 10.1.0.0/16"),
        ("ip host 10.1", "ip net 10.1.0.0/16"),
        // Four octets stay an exact host.
        ("host 10.1.2.3", "net 10.1.2.3/32"),
    ] {
        // `host x.y.z.w` is a `Host`, not a /32 `Net`; compare the others only.
        if host == "host 10.1.2.3" {
            assert!(matches!(
                ast(host),
                pktbaffle::ast::Expr::Primitive(pktbaffle::ast::Primitive::Host { .. })
            ));
            continue;
        }
        assert_eq!(ast(host), ast(net), "{host:?} vs {net:?}");
    }
}

#[test]
fn short_dotted_address_without_a_qualifier_is_an_error() {
    // libpcap: a bare id is a syntax error. Reading `10.1` as the host
    // 10.1.0.0 (the old behaviour) was a silent wrong match.
    for f in ["10.1", "10.1.2", "tcp and 10.1", "10.1 and tcp"] {
        assert!(pktbaffle::parse(f).is_err(), "{f:?} must be rejected");
    }
}

// ── Digit-first IPv6 with an embedded IPv4 tail (#192) ────────────────────────
// libpcap 1.10.3 compiles these to the same program as the hex-group spelling
// (issue #192).

#[test]
fn digit_first_ipv6_embedded_ipv4_equals_hex_spelling() {
    for (dotted, hex) in [
        ("host 64:ff9b::192.0.2.1", "host 64:ff9b::c000:201"),
        ("host 2001:db8::1.2.3.4", "host 2001:db8::102:304"),
        ("host 1:2:3:4:5:6:1.2.3.4", "host 1:2:3:4:5:6:102:304"),
        ("host 1::1.2.3.4", "host 1::102:304"),
        ("src host 64:ff9b::192.0.2.1", "src host 64:ff9b::c000:201"),
        ("net 64:ff9b::192.0.2.1/128", "net 64:ff9b::c000:201/128"),
    ] {
        assert_eq!(ast(dotted), ast(hex), "{dotted:?} vs {hex:?}");
    }
    // Unaffected, and a malformed tail is still an error.
    assert!(pktbaffle::parse("net 64:ff9b::/96").is_ok());
    assert!(pktbaffle::parse("host 64:ff9b::c000:201").is_ok());
    for f in ["host 1::1.2.3", "host 1::1.2.3.4.5", "host 1::1.2.3.256"] {
        assert!(pktbaffle::parse(f).is_err(), "{f:?} must be rejected");
    }
}
