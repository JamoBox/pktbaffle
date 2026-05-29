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
    eth_prog("tcp[0:4] = 0");          // first 4 bytes of TCP header
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
