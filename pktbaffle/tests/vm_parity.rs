//! VM-based libpcap expression parity tests.
//!
//! Compiles filter expressions and runs the software BPF VM against
//! byte-accurate synthetic packets to verify match/no-match semantics,
//! ensuring feature parity with the libpcap expression language.

#![cfg(feature = "vm")]

mod common;

use common::packets::*;
use pktbaffle::{compile, LinkType, Target};

// ── Core helper ──────────────────────────────────────────────────────────────

fn run_filter(filter: &str, pkt: &[u8]) -> bool {
    let prog = compile(filter, LinkType::Ethernet, Target::Classic)
        .unwrap_or_else(|e| panic!("compile({filter:?}): {e}"));
    pktbaffle::vm::run(prog.instructions(), pkt)
}

// ── Host filters ─────────────────────────────────────────────────────────────

#[test]
fn host_matches_src_ip() {
    assert!(run_filter("host 192.168.1.1", &tcp(IP_A, IP_B, 1234, 80)));
}

#[test]
fn host_matches_dst_ip() {
    assert!(run_filter("host 192.168.1.1", &tcp(IP_B, IP_A, 1234, 80)));
}

#[test]
fn host_rejects_unrelated_ips() {
    assert!(!run_filter("host 192.168.1.1", &tcp(IP_B, IP_C, 1234, 80)));
}

#[test]
fn src_host_matches() {
    assert!(run_filter(
        "src host 192.168.1.1",
        &tcp(IP_A, IP_B, 1234, 80)
    ));
}

#[test]
fn src_host_rejects_when_only_dst_matches() {
    assert!(!run_filter(
        "src host 192.168.1.1",
        &tcp(IP_B, IP_A, 1234, 80)
    ));
}

#[test]
fn dst_host_matches() {
    assert!(run_filter(
        "dst host 192.168.1.1",
        &tcp(IP_B, IP_A, 1234, 80)
    ));
}

#[test]
fn dst_host_rejects_when_only_src_matches() {
    assert!(!run_filter(
        "dst host 192.168.1.1",
        &tcp(IP_A, IP_B, 1234, 80)
    ));
}

// ── Protocol filters ─────────────────────────────────────────────────────────

#[test]
fn proto_tcp_matches() {
    assert!(run_filter("tcp", &tcp(IP_A, IP_B, 1234, 80)));
}

#[test]
fn proto_tcp_rejects_udp() {
    assert!(!run_filter("tcp", &udp(IP_A, IP_B, 1234, 53)));
}

#[test]
fn proto_udp_matches() {
    assert!(run_filter("udp", &udp(IP_A, IP_B, 1234, 53)));
}

#[test]
fn proto_udp_rejects_tcp() {
    assert!(!run_filter("udp", &tcp(IP_A, IP_B, 1234, 80)));
}

#[test]
fn proto_icmp_matches() {
    assert!(run_filter("icmp", &eth_ipv4_icmp(IP_A, IP_B, 8, 0)));
}

#[test]
fn proto_icmp_rejects_tcp() {
    assert!(!run_filter("icmp", &tcp(IP_A, IP_B, 1234, 80)));
}

#[test]
fn proto_arp_matches() {
    assert!(run_filter("arp", &eth_arp(IP_A, IP_B)));
}

#[test]
fn proto_arp_rejects_tcp() {
    assert!(!run_filter("arp", &tcp(IP_A, IP_B, 1234, 80)));
}

#[test]
fn proto_ip_matches_ipv4() {
    assert!(run_filter("ip", &tcp(IP_A, IP_B, 1234, 80)));
}

#[test]
fn proto_ip_rejects_ipv6() {
    let src = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1u8];
    let dst = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2u8];
    assert!(!run_filter("ip", &eth_ipv6_tcp(src, dst, 1234, 80, 0x02)));
}

// ── IPv6 ─────────────────────────────────────────────────────────────────────

#[test]
fn ip6_matches() {
    let src = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1u8];
    let dst = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2u8];
    assert!(run_filter("ip6", &eth_ipv6_tcp(src, dst, 1234, 80, 0x02)));
}

#[test]
fn ip6_rejects_ipv4() {
    assert!(!run_filter("ip6", &tcp(IP_A, IP_B, 1234, 80)));
}

// ── Port filters ─────────────────────────────────────────────────────────────

#[test]
fn tcp_port_matches_src_port() {
    assert!(run_filter("tcp port 80", &tcp(IP_A, IP_B, 80, 4321)));
}

#[test]
fn tcp_port_matches_dst_port() {
    assert!(run_filter("tcp port 80", &tcp(IP_A, IP_B, 1234, 80)));
}

#[test]
fn tcp_port_rejects_wrong_port() {
    assert!(!run_filter("tcp port 80", &tcp(IP_A, IP_B, 1234, 443)));
}

#[test]
fn tcp_port_rejects_udp_with_matching_port() {
    assert!(!run_filter("tcp port 80", &udp(IP_A, IP_B, 1234, 80)));
}

#[test]
fn udp_port_matches() {
    assert!(run_filter("udp port 53", &udp(IP_A, IP_B, 1234, 53)));
}

#[test]
fn udp_port_rejects_tcp() {
    assert!(!run_filter("udp port 53", &tcp(IP_A, IP_B, 1234, 53)));
}

#[test]
fn udp_port_rejects_wrong_port() {
    assert!(!run_filter("udp port 53", &udp(IP_A, IP_B, 1234, 80)));
}

#[test]
fn bare_port_matches_tcp() {
    assert!(run_filter("port 80", &tcp(IP_A, IP_B, 1234, 80)));
}

#[test]
fn bare_port_matches_udp() {
    assert!(run_filter("port 80", &udp(IP_A, IP_B, 1234, 80)));
}

#[test]
fn bare_port_rejects_wrong_port() {
    assert!(!run_filter("port 80", &tcp(IP_A, IP_B, 1234, 443)));
}

#[test]
fn src_port_matches() {
    assert!(run_filter("tcp src port 1234", &tcp(IP_A, IP_B, 1234, 80)));
}

#[test]
fn src_port_rejects_when_only_dst_matches() {
    assert!(!run_filter(
        "tcp src port 1234",
        &tcp(IP_A, IP_B, 4321, 1234)
    ));
}

#[test]
fn dst_port_matches() {
    assert!(run_filter("tcp dst port 443", &tcp(IP_A, IP_B, 1234, 443)));
}

#[test]
fn dst_port_rejects_when_only_src_matches() {
    assert!(!run_filter("tcp dst port 443", &tcp(IP_A, IP_B, 443, 1234)));
}

// ── Port range ────────────────────────────────────────────────────────────────

#[test]
fn portrange_matches_src_in_range() {
    // Both src and dst in [1024, 65535]
    let pkt = eth_ipv4_tcp(MAC_B, MAC_A, IP_A, IP_B, 8080, 9090, 0x02, 0);
    assert!(run_filter("portrange 1024-65535", &pkt));
}

#[test]
fn portrange_rejects_when_both_ports_below_range() {
    // src=80, dst=443 — both below 1024
    let pkt = eth_ipv4_tcp(MAC_B, MAC_A, IP_A, IP_B, 80, 443, 0x02, 0);
    assert!(!run_filter("portrange 1024-65535", &pkt));
}

// ── Logical operators ─────────────────────────────────────────────────────────

#[test]
fn and_tcp_port_80() {
    let match_pkt = tcp(IP_A, IP_B, 1234, 80);
    let wrong_proto = udp(IP_A, IP_B, 1234, 80);
    let wrong_port = tcp(IP_A, IP_B, 1234, 443);
    assert!(run_filter("tcp and port 80", &match_pkt));
    assert!(!run_filter("tcp and port 80", &wrong_proto));
    assert!(!run_filter("tcp and port 80", &wrong_port));
}

#[test]
fn or_tcp_udp() {
    assert!(run_filter("tcp or udp", &tcp(IP_A, IP_B, 1234, 80)));
    assert!(run_filter("tcp or udp", &udp(IP_A, IP_B, 1234, 53)));
    assert!(!run_filter("tcp or udp", &eth_arp(IP_A, IP_B)));
}

#[test]
fn not_arp() {
    assert!(run_filter("not arp", &tcp(IP_A, IP_B, 1234, 80)));
    assert!(!run_filter("not arp", &eth_arp(IP_A, IP_B)));
}

#[test]
fn not_tcp() {
    assert!(!run_filter("not tcp", &tcp(IP_A, IP_B, 1234, 80)));
    assert!(run_filter("not tcp", &udp(IP_A, IP_B, 1234, 53)));
}

#[test]
fn host_and_port_combined() {
    let match_pkt = tcp(IP_A, IP_B, 1234, 80);
    let wrong_ip = tcp(IP_C, IP_B, 1234, 80);
    let wrong_port = tcp(IP_A, IP_B, 1234, 443);
    assert!(run_filter("host 192.168.1.1 and tcp port 80", &match_pkt));
    assert!(!run_filter("host 192.168.1.1 and tcp port 80", &wrong_ip));
    assert!(!run_filter("host 192.168.1.1 and tcp port 80", &wrong_port));
}

#[test]
fn paren_or_and_combined() {
    let tcp80 = tcp(IP_A, IP_B, 1234, 80);
    let tcp443 = tcp(IP_A, IP_B, 1234, 443);
    let udp53 = udp(IP_A, IP_B, 1234, 53);
    let tcp8080 = tcp(IP_A, IP_B, 1234, 8080);
    assert!(run_filter("(port 80 or port 443) and tcp", &tcp80));
    assert!(run_filter("(port 80 or port 443) and tcp", &tcp443));
    assert!(!run_filter("(port 80 or port 443) and tcp", &udp53)); // wrong protocol
    assert!(!run_filter("(port 80 or port 443) and tcp", &tcp8080)); // wrong port
}

/// Juxtaposition (no explicit keyword) is treated as AND.
#[test]
fn juxtaposition_acts_as_and() {
    let match_pkt = tcp(IP_A, IP_B, 1234, 80);
    let wrong = udp(IP_A, IP_B, 1234, 80);
    assert!(run_filter("tcp port 80", &match_pkt));
    assert!(!run_filter("tcp port 80", &wrong));
}

/// `and`/`or` have equal precedence and associate left to right (#128).
///
/// Expected verdicts are libpcap 1.10.3 `pcap_compile` + `pcap_offline_filter`
/// results recorded in issue #128, not derived from pktbaffle: libpcap parses
/// `X or Y and Z` as `(X or Y) and Z`. The two MATCH entries on the `tcp or udp`
/// filter are not in the issue; they follow from that same documented parse.
#[test]
fn or_then_and_has_equal_precedence_like_libpcap() {
    const NOMATCH: bool = false;
    const MATCH: bool = true;
    const OTHER: [u8; 4] = [9, 9, 9, 9];
    const TARGET: [u8; 4] = [10, 0, 0, 1];
    const DST: [u8; 4] = [8, 8, 8, 8];

    let cases: [(&str, Vec<u8>, bool); 6] = [
        // The issue's headline case: host guards BOTH port tests.
        (
            "port 22 or port 80 and host 10.0.0.1",
            tcp(OTHER, DST, 1234, 22),
            NOMATCH,
        ),
        (
            "port 22 or port 80 and host 10.0.0.1",
            tcp(TARGET, DST, 1234, 80),
            MATCH,
        ),
        (
            "port 22 or port 80 and host 10.0.0.1",
            tcp(OTHER, DST, 1234, 80),
            NOMATCH,
        ),
        (
            "tcp or udp and host 10.0.0.1",
            tcp(OTHER, DST, 1234, 80),
            NOMATCH,
        ),
        (
            "tcp or udp and host 10.0.0.1",
            tcp(TARGET, DST, 1234, 80),
            MATCH,
        ),
        (
            "tcp or udp and host 10.0.0.1",
            udp(TARGET, DST, 1234, 53),
            MATCH,
        ),
    ];

    // The tree shape is link-independent, but codegen is not: run each packet
    // on Ethernet, RawIp (Ethernet header stripped) and LinuxSll (cooked header).
    for (filter, eth_pkt, expected) in &cases {
        let mut sll = vec![0, 0, 0, 1, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0x08, 0x00];
        sll.extend_from_slice(&eth_pkt[14..]);
        for (link, pkt) in [
            (LinkType::Ethernet, &eth_pkt[..]),
            (LinkType::RawIp, &eth_pkt[14..]),
            (LinkType::LinuxSll, &sll[..]),
        ] {
            let prog = compile(filter, link, Target::Classic).unwrap();
            assert_eq!(
                pktbaffle::vm::run(prog.instructions(), pkt),
                *expected,
                "{filter:?} on {link:?}"
            );
        }
    }
}

// ── Packet length filters ─────────────────────────────────────────────────────
// Base TCP packet (no payload): 14 + 20 + 20 = 54 bytes.

#[test]
fn less_accepts_short_packet() {
    // 'less N' = len <= N (libpcap semantics)
    let pkt = tcp(IP_A, IP_B, 1234, 80); // 54 bytes
    assert!(run_filter("less 64", &pkt));
}

#[test]
fn less_rejects_long_packet() {
    let pkt = eth_ipv4_tcp(MAC_B, MAC_A, IP_A, IP_B, 1234, 80, 0x02, 50); // 104 bytes
    assert!(!run_filter("less 64", &pkt));
}

#[test]
fn greater_accepts_large_packet() {
    // 'greater N' = len >= N (libpcap semantics)
    let pkt = eth_ipv4_tcp(MAC_B, MAC_A, IP_A, IP_B, 1234, 80, 0x02, 100); // 154 bytes
    assert!(run_filter("greater 100", &pkt));
}

#[test]
fn greater_rejects_small_packet() {
    let pkt = tcp(IP_A, IP_B, 1234, 80); // 54 bytes
    assert!(!run_filter("greater 100", &pkt));
}

#[test]
fn len_eq_exact_match() {
    let pkt = tcp(IP_A, IP_B, 1234, 80); // 54 bytes
    assert!(run_filter("len = 54", &pkt));
    assert!(!run_filter("len = 55", &pkt));
}

#[test]
fn len_ne_matches() {
    let pkt = tcp(IP_A, IP_B, 1234, 80); // 54 bytes
    assert!(run_filter("len != 100", &pkt));
    assert!(!run_filter("len != 54", &pkt));
}

#[test]
fn len_lt_matches() {
    let pkt = tcp(IP_A, IP_B, 1234, 80); // 54 bytes
    assert!(run_filter("len < 100", &pkt));
    assert!(!run_filter("len < 54", &pkt));
}

#[test]
fn len_gt_matches() {
    let pkt = eth_ipv4_tcp(MAC_B, MAC_A, IP_A, IP_B, 1234, 80, 0x02, 100); // 154 bytes
    assert!(run_filter("len > 100", &pkt));
    assert!(!run_filter("len > 200", &pkt));
}

// ── TCP flags (raw byte access) ───────────────────────────────────────────────

#[test]
fn tcp_syn_flag() {
    let syn = eth_ipv4_tcp(MAC_B, MAC_A, IP_A, IP_B, 1234, 80, 0x02, 0); // SYN
    let ack = eth_ipv4_tcp(MAC_B, MAC_A, IP_A, IP_B, 1234, 80, 0x10, 0); // ACK
    assert!(run_filter("tcp[13] & 0x02 != 0", &syn));
    assert!(!run_filter("tcp[13] & 0x02 != 0", &ack));
}

#[test]
fn tcp_ack_flag() {
    let ack = eth_ipv4_tcp(MAC_B, MAC_A, IP_A, IP_B, 1234, 80, 0x10, 0); // ACK
    let syn = eth_ipv4_tcp(MAC_B, MAC_A, IP_A, IP_B, 1234, 80, 0x02, 0); // SYN
    assert!(run_filter("tcp[13] & 0x10 != 0", &ack));
    assert!(!run_filter("tcp[13] & 0x10 != 0", &syn));
}

#[test]
fn tcp_fin_flag() {
    let fin = eth_ipv4_tcp(MAC_B, MAC_A, IP_A, IP_B, 1234, 80, 0x01, 0); // FIN
    let syn = eth_ipv4_tcp(MAC_B, MAC_A, IP_A, IP_B, 1234, 80, 0x02, 0); // SYN
    assert!(run_filter("tcp[13] & 0x01 != 0", &fin));
    assert!(!run_filter("tcp[13] & 0x01 != 0", &syn));
}

#[test]
fn tcp_rst_flag() {
    let rst = eth_ipv4_tcp(MAC_B, MAC_A, IP_A, IP_B, 1234, 80, 0x04, 0); // RST
    let syn = eth_ipv4_tcp(MAC_B, MAC_A, IP_A, IP_B, 1234, 80, 0x02, 0); // SYN
    assert!(run_filter("tcp[13] & 0x04 != 0", &rst));
    assert!(!run_filter("tcp[13] & 0x04 != 0", &syn));
}

// ── Named flag constants ──────────────────────────────────────────────────────

#[test]
fn tcpflags_constant_syn() {
    let syn = eth_ipv4_tcp(MAC_B, MAC_A, IP_A, IP_B, 1234, 80, 0x02, 0);
    let ack = eth_ipv4_tcp(MAC_B, MAC_A, IP_A, IP_B, 1234, 80, 0x10, 0);
    assert!(run_filter("tcp[tcpflags] & tcp-syn != 0", &syn));
    assert!(!run_filter("tcp[tcpflags] & tcp-syn != 0", &ack));
}

#[test]
fn icmp_echo_named_constant() {
    let echo_req = eth_ipv4_icmp(IP_A, IP_B, 8, 0); // type=8 = echo request
    let echo_rep = eth_ipv4_icmp(IP_A, IP_B, 0, 0); // type=0 = echo reply
    assert!(run_filter("icmp[icmptype] = icmp-echo", &echo_req));
    assert!(!run_filter("icmp[icmptype] = icmp-echo", &echo_rep));
}

// ── IPv4 raw byte access ──────────────────────────────────────────────────────

#[test]
fn ip_ttl_byte_access() {
    // ip[8] = TTL in the IPv4 header; our packets use TTL=64.
    let pkt = tcp(IP_A, IP_B, 1234, 80);
    assert!(run_filter("ip[8] = 64", &pkt));
    assert!(!run_filter("ip[8] = 128", &pkt));
}

#[test]
fn ip_ttl_via_nested_offset_expressions() {
    // 20 levels of `(` / unary `-` around the offset 8 (#135) still match as
    // ip[8] does: well inside the nesting limit.
    let pkt = tcp(IP_A, IP_B, 1234, 80);
    let nested = [
        format!("{}8{}", "(".repeat(20), ")".repeat(20)),
        format!("{}8", "-".repeat(20)),
        format!("{}8{}", "-(".repeat(20), ")".repeat(20)),
    ];
    for offset in nested {
        assert!(run_filter(&format!("ip[{offset}] = 64"), &pkt), "{offset}");
        assert!(
            !run_filter(&format!("ip[{offset}] = 128"), &pkt),
            "{offset}"
        );
    }
}

#[test]
fn ip_ttl_via_folded_offset_expressions() {
    // Constant-folded offsets that stay in range are unchanged by the
    // overflow checks (#134): each of these is ip[8], the TTL (64).
    let pkt = tcp(IP_A, IP_B, 1234, 80);
    for offset in ["1<<3", "16/2", "-4/-2+6", "(1<<30)/(1<<27)"] {
        assert!(run_filter(&format!("ip[{offset}] = 64"), &pkt), "{offset}");
        assert!(
            !run_filter(&format!("ip[{offset}] = 128"), &pkt),
            "{offset}"
        );
    }
}

// ── Ethernet MAC address filters ──────────────────────────────────────────────
// eth_ipv4_tcp(dst_mac, src_mac, ...): bytes 0–5 = dst, bytes 6–11 = src.

#[test]
fn ether_host_matches_src_mac() {
    // src_mac = MAC_A = aa:bb:cc:dd:ee:ff
    let pkt = eth_ipv4_tcp(MAC_B, MAC_A, IP_A, IP_B, 1234, 80, 0x02, 0);
    assert!(run_filter("ether host aa:bb:cc:dd:ee:ff", &pkt));
}

#[test]
fn ether_host_matches_dst_mac() {
    // dst_mac = MAC_A = aa:bb:cc:dd:ee:ff
    let pkt = eth_ipv4_tcp(MAC_A, MAC_B, IP_A, IP_B, 1234, 80, 0x02, 0);
    assert!(run_filter("ether host aa:bb:cc:dd:ee:ff", &pkt));
}

#[test]
fn ether_host_rejects_unrelated_mac() {
    let pkt = eth_ipv4_tcp(MAC_B, MAC_B, IP_A, IP_B, 1234, 80, 0x02, 0);
    assert!(!run_filter("ether host aa:bb:cc:dd:ee:ff", &pkt));
}

#[test]
fn ether_src_matches() {
    let pkt = eth_ipv4_tcp(MAC_B, MAC_A, IP_A, IP_B, 1234, 80, 0x02, 0);
    assert!(run_filter("ether src aa:bb:cc:dd:ee:ff", &pkt));
}

#[test]
fn ether_src_rejects_when_only_dst() {
    let pkt = eth_ipv4_tcp(MAC_A, MAC_B, IP_A, IP_B, 1234, 80, 0x02, 0);
    assert!(!run_filter("ether src aa:bb:cc:dd:ee:ff", &pkt));
}

#[test]
fn ether_dst_matches() {
    let pkt = eth_ipv4_tcp(MAC_A, MAC_B, IP_A, IP_B, 1234, 80, 0x02, 0);
    assert!(run_filter("ether dst aa:bb:cc:dd:ee:ff", &pkt));
}

#[test]
fn ether_dst_rejects_when_only_src() {
    let pkt = eth_ipv4_tcp(MAC_B, MAC_A, IP_A, IP_B, 1234, 80, 0x02, 0);
    assert!(!run_filter("ether dst aa:bb:cc:dd:ee:ff", &pkt));
}

#[test]
fn ether_broadcast_matches() {
    let pkt = eth_ipv4_tcp(MAC_BCAST, MAC_A, IP_A, IP_B, 1234, 80, 0x02, 0);
    assert!(run_filter("ether broadcast", &pkt));
}

#[test]
fn ether_broadcast_rejects_unicast() {
    let pkt = eth_ipv4_tcp(MAC_B, MAC_A, IP_A, IP_B, 1234, 80, 0x02, 0);
    assert!(!run_filter("ether broadcast", &pkt));
}

#[test]
fn ether_multicast_matches() {
    // Multicast MACs have bit 0 of byte 0 set (e.g. 01:00:5e:xx:xx:xx).
    let pkt = eth_ipv4_tcp(MAC_MCAST, MAC_A, IP_A, IP_B, 1234, 80, 0x02, 0);
    assert!(run_filter("ether multicast", &pkt));
}

#[test]
fn ether_multicast_rejects_unicast() {
    // MAC_A has bit 0 of byte 0 clear (0xaa = 0b10101010), so it is a unicast
    // destination; `ether multicast` must not match it.
    let pkt = eth_ipv4_tcp(MAC_A, MAC_B, IP_A, IP_B, 1234, 80, 0x02, 0);
    assert!(!run_filter("ether multicast", &pkt));
}

// ── VLAN filters ──────────────────────────────────────────────────────────────

#[test]
fn vlan_any_matches_tagged() {
    let pkt = eth_vlan_ipv4_tcp(100, IP_A, IP_B, 1234, 80, 0x02);
    assert!(run_filter("vlan", &pkt));
}

#[test]
fn vlan_any_rejects_untagged() {
    assert!(!run_filter("vlan", &tcp(IP_A, IP_B, 1234, 80)));
}

#[test]
fn vlan_id_matches_correct_vlan() {
    let pkt = eth_vlan_ipv4_tcp(100, IP_A, IP_B, 1234, 80, 0x02);
    assert!(run_filter("vlan 100", &pkt));
}

#[test]
fn vlan_id_rejects_wrong_vlan() {
    let pkt = eth_vlan_ipv4_tcp(200, IP_A, IP_B, 1234, 80, 0x02);
    assert!(!run_filter("vlan 100", &pkt));
}

#[test]
fn vlan_and_tcp_port() {
    let vlan_tcp80 = eth_vlan_ipv4_tcp(10, IP_A, IP_B, 1234, 80, 0x02);
    let vlan_tcp443 = eth_vlan_ipv4_tcp(10, IP_A, IP_B, 1234, 443, 0x02);
    let plain_tcp80 = tcp(IP_A, IP_B, 1234, 80);
    assert!(run_filter("vlan and tcp port 80", &vlan_tcp80));
    assert!(!run_filter("vlan and tcp port 80", &vlan_tcp443));
    assert!(!run_filter("vlan and tcp port 80", &plain_tcp80));
}

// ── Network (CIDR) filters ────────────────────────────────────────────────────

#[test]
fn net_cidr_matches_src_in_subnet() {
    let pkt = tcp([192, 168, 1, 50], IP_B, 1234, 80);
    assert!(run_filter("net 192.168.1.0/24", &pkt));
}

#[test]
fn net_cidr_matches_dst_in_subnet() {
    let pkt = tcp(IP_B, [192, 168, 1, 100], 1234, 80);
    assert!(run_filter("net 192.168.1.0/24", &pkt));
}

#[test]
fn net_cidr_rejects_outside_subnet() {
    let pkt = tcp([192, 168, 2, 1], [10, 0, 0, 2], 1234, 80);
    assert!(!run_filter("net 192.168.1.0/24", &pkt));
}

#[test]
fn net_mask_syntax_matches() {
    let pkt = tcp([10, 0, 0, 5], IP_B, 1234, 80);
    assert!(run_filter("net 10.0.0.0 mask 255.0.0.0", &pkt));
}

#[test]
fn net_mask_syntax_rejects_outside() {
    // Both src (192.168.0.1) and dst (172.16.0.1) are outside 10.0.0.0/8.
    let pkt = tcp([192, 168, 0, 1], [172, 16, 0, 1], 1234, 80);
    assert!(!run_filter("net 10.0.0.0 mask 255.0.0.0", &pkt));
}

// ── ip broadcast ─────────────────────────────────────────────────────────────

#[test]
fn ip_broadcast_matches_limited_broadcast() {
    let pkt = tcp(IP_A, [255, 255, 255, 255], 1234, 80);
    assert!(run_filter("ip broadcast", &pkt));
}

#[test]
fn ip_broadcast_rejects_unicast_dst() {
    assert!(!run_filter("ip broadcast", &tcp(IP_A, IP_B, 1234, 80)));
}

// ── ip multicast ─────────────────────────────────────────────────────────────

#[test]
fn ip_multicast_matches_class_d() {
    // 224.0.0.0/4 = IPv4 multicast range
    let pkt = tcp(IP_A, [224, 0, 0, 1], 1234, 80);
    assert!(run_filter("ip multicast", &pkt));
}

#[test]
fn ip_multicast_rejects_unicast() {
    assert!(!run_filter("ip multicast", &tcp(IP_A, IP_B, 1234, 80)));
}

// ── IPv6 host filters ─────────────────────────────────────────────────────────

#[test]
fn ipv6_host_matches_src() {
    let pkt = eth_ipv6_tcp(IPV6_A, IPV6_B, 1234, 80, 0x02);
    assert!(run_filter("host 2001:db8::1", &pkt));
}

#[test]
fn ipv6_host_matches_dst() {
    let pkt = eth_ipv6_tcp(IPV6_B, IPV6_A, 1234, 80, 0x02);
    assert!(run_filter("host 2001:db8::1", &pkt));
}

#[test]
fn ipv6_host_rejects_unrelated() {
    let pkt = eth_ipv6_tcp(IPV6_B, IPV6_B, 1234, 80, 0x02);
    assert!(!run_filter("host 2001:db8::1", &pkt));
}

#[test]
fn ipv6_host_rejects_ipv4() {
    assert!(!run_filter("host 2001:db8::1", &tcp(IP_A, IP_B, 1234, 80)));
}

#[test]
fn ipv6_src_host_matches() {
    let pkt = eth_ipv6_tcp(IPV6_A, IPV6_B, 1234, 80, 0x02);
    assert!(run_filter("src host 2001:db8::1", &pkt));
}

#[test]
fn ipv6_src_host_rejects_when_only_dst() {
    let pkt = eth_ipv6_tcp(IPV6_B, IPV6_A, 1234, 80, 0x02);
    assert!(!run_filter("src host 2001:db8::1", &pkt));
}

#[test]
fn ipv6_dst_host_matches() {
    let pkt = eth_ipv6_tcp(IPV6_B, IPV6_A, 1234, 80, 0x02);
    assert!(run_filter("dst host 2001:db8::1", &pkt));
}

#[test]
fn ipv6_dst_host_rejects_when_only_src() {
    let pkt = eth_ipv6_tcp(IPV6_A, IPV6_B, 1234, 80, 0x02);
    assert!(!run_filter("dst host 2001:db8::1", &pkt));
}

// ── Directional net filters ───────────────────────────────────────────────────

#[test]
fn src_net_cidr_matches_src_in_subnet() {
    let pkt = tcp([192, 168, 1, 50], [10, 0, 0, 1], 1234, 80);
    assert!(run_filter("src net 192.168.1.0/24", &pkt));
}

#[test]
fn src_net_cidr_rejects_when_only_dst_in_subnet() {
    let pkt = tcp([10, 0, 0, 1], [192, 168, 1, 100], 1234, 80);
    assert!(!run_filter("src net 192.168.1.0/24", &pkt));
}

#[test]
fn dst_net_cidr_matches_dst_in_subnet() {
    let pkt = tcp([10, 0, 0, 1], [192, 168, 1, 100], 1234, 80);
    assert!(run_filter("dst net 192.168.1.0/24", &pkt));
}

#[test]
fn dst_net_cidr_rejects_when_only_src_in_subnet() {
    let pkt = tcp([192, 168, 1, 50], [10, 0, 0, 1], 1234, 80);
    assert!(!run_filter("dst net 192.168.1.0/24", &pkt));
}

// ── Directional portrange filters ─────────────────────────────────────────────

#[test]
fn src_portrange_matches_src_in_range() {
    let pkt = eth_ipv4_tcp(MAC_B, MAC_A, IP_A, IP_B, 8080, 80, 0x02, 0);
    assert!(run_filter("src portrange 1024-65535", &pkt));
}

#[test]
fn src_portrange_rejects_src_outside_range() {
    let pkt = eth_ipv4_tcp(MAC_B, MAC_A, IP_A, IP_B, 80, 8080, 0x02, 0);
    assert!(!run_filter("src portrange 1024-65535", &pkt));
}

#[test]
fn dst_portrange_matches_dst_in_range() {
    let pkt = eth_ipv4_tcp(MAC_B, MAC_A, IP_A, IP_B, 80, 8080, 0x02, 0);
    assert!(run_filter("dst portrange 1024-65535", &pkt));
}

#[test]
fn dst_portrange_rejects_dst_outside_range() {
    let pkt = eth_ipv4_tcp(MAC_B, MAC_A, IP_A, IP_B, 8080, 80, 0x02, 0);
    assert!(!run_filter("dst portrange 1024-65535", &pkt));
}

// ── Protocol-qualified portrange ──────────────────────────────────────────────

#[test]
fn tcp_portrange_matches_tcp() {
    let pkt = eth_ipv4_tcp(MAC_B, MAC_A, IP_A, IP_B, 8080, 9090, 0x02, 0);
    assert!(run_filter("tcp portrange 1024-65535", &pkt));
}

#[test]
fn tcp_portrange_rejects_udp() {
    let pkt = eth_ipv4_udp(MAC_B, MAC_A, IP_A, IP_B, 8080, 9090);
    assert!(!run_filter("tcp portrange 1024-65535", &pkt));
}

#[test]
fn tcp_portrange_rejects_ports_outside_range() {
    let pkt = eth_ipv4_tcp(MAC_B, MAC_A, IP_A, IP_B, 80, 443, 0x02, 0);
    assert!(!run_filter("tcp portrange 1024-65535", &pkt));
}

#[test]
fn udp_portrange_matches_udp() {
    let pkt = eth_ipv4_udp(MAC_B, MAC_A, IP_A, IP_B, 8080, 9090);
    assert!(run_filter("udp portrange 1024-65535", &pkt));
}

#[test]
fn udp_portrange_rejects_tcp() {
    let pkt = eth_ipv4_tcp(MAC_B, MAC_A, IP_A, IP_B, 8080, 9090, 0x02, 0);
    assert!(!run_filter("udp portrange 1024-65535", &pkt));
}

// ── IPv6 with transport port filters ─────────────────────────────────────────

#[test]
fn ip6_and_tcp_port_matches() {
    let pkt = eth_ipv6_tcp(IPV6_A, IPV6_B, 1234, 80, 0x02);
    assert!(run_filter("ip6 and tcp port 80", &pkt));
}

#[test]
fn ip6_and_tcp_port_rejects_wrong_port() {
    let pkt = eth_ipv6_tcp(IPV6_A, IPV6_B, 1234, 443, 0x02);
    assert!(!run_filter("ip6 and tcp port 80", &pkt));
}

#[test]
fn ip6_and_tcp_port_rejects_ipv4() {
    assert!(!run_filter(
        "ip6 and tcp port 80",
        &tcp(IP_A, IP_B, 1234, 80)
    ));
}

#[test]
fn ip6_and_udp_port_matches() {
    let pkt = eth_ipv6_udp(IPV6_A, IPV6_B, 1234, 53);
    assert!(run_filter("ip6 and udp port 53", &pkt));
}

#[test]
fn ip6_and_udp_port_rejects_ipv4() {
    assert!(!run_filter(
        "ip6 and udp port 53",
        &udp(IP_A, IP_B, 1234, 53)
    ));
}

// ── IPv6 multicast ────────────────────────────────────────────────────────────

#[test]
fn ip6_multicast_matches_ff02_group() {
    let pkt = eth_ipv6_tcp(IPV6_A, IPV6_MCAST, 1234, 80, 0x02);
    assert!(run_filter("ip6 multicast", &pkt));
}

#[test]
fn ip6_multicast_rejects_unicast_dst() {
    let pkt = eth_ipv6_tcp(IPV6_A, IPV6_B, 1234, 80, 0x02);
    assert!(!run_filter("ip6 multicast", &pkt));
}

#[test]
fn ip6_multicast_rejects_ipv4() {
    assert!(!run_filter(
        "ip6 multicast",
        &tcp(IP_A, [224, 0, 0, 1], 1234, 80)
    ));
}

// ── Bare broadcast / multicast ────────────────────────────────────────────────
// pktbaffle implements these as Ethernet-layer only checks:
//   broadcast  →  dst MAC == FF:FF:FF:FF:FF:FF
//   multicast  →  bit 0 of dst MAC byte 0 is set
//
// libpcap additionally ORs in ip broadcast / ip multicast / ip6 multicast.
// That gap is documented in tests/libpcap_compat.rs.
//
// Note: MAC_B = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66] — 0x11 & 0x01 = 1, so
// MAC_B is itself a multicast address.  Tests that want a unicast destination
// must use MAC_A = [0xaa, ...] (0xaa & 0x01 = 0).

#[test]
fn bare_broadcast_matches_ether_broadcast_dst() {
    let pkt = eth_ipv4_tcp(MAC_BCAST, MAC_A, IP_A, IP_B, 1234, 80, 0x02, 0);
    assert!(run_filter("broadcast", &pkt));
}

#[test]
fn bare_broadcast_rejects_unicast_dst_mac() {
    // MAC_A destination (0xaa:bb:... → not all-FF, not multicast).
    let pkt = eth_ipv4_tcp(MAC_A, MAC_B, IP_A, IP_B, 1234, 80, 0x02, 0);
    assert!(!run_filter("broadcast", &pkt));
}

#[test]
fn bare_multicast_matches_ether_multicast_dst() {
    // MAC_MCAST = 01:00:5e:... — bit 0 of byte 0 is set → multicast.
    let pkt = eth_ipv4_tcp(MAC_MCAST, MAC_A, IP_A, IP_B, 1234, 80, 0x02, 0);
    assert!(run_filter("multicast", &pkt));
}

#[test]
fn bare_multicast_rejects_unicast_dst_mac() {
    // MAC_A = aa:bb:cc:... — 0xaa & 0x01 = 0 → unicast destination.
    let pkt = eth_ipv4_tcp(MAC_A, MAC_B, IP_A, IP_B, 1234, 80, 0x02, 0);
    assert!(!run_filter("multicast", &pkt));
}

// ── ether proto ───────────────────────────────────────────────────────────────

#[test]
fn ether_proto_0x0800_matches_ipv4() {
    assert!(run_filter("ether proto 0x0800", &tcp(IP_A, IP_B, 1234, 80)));
}

#[test]
fn ether_proto_0x0800_rejects_arp() {
    assert!(!run_filter("ether proto 0x0800", &eth_arp(IP_A, IP_B)));
}

#[test]
fn ether_proto_ip_alias_matches_ipv4() {
    assert!(run_filter("ether proto ip", &tcp(IP_A, IP_B, 1234, 80)));
}

#[test]
fn ether_proto_ip_alias_rejects_arp() {
    assert!(!run_filter("ether proto ip", &eth_arp(IP_A, IP_B)));
}

#[test]
fn ether_proto_arp_matches_arp() {
    assert!(run_filter("ether proto arp", &eth_arp(IP_A, IP_B)));
}

#[test]
fn ether_proto_arp_rejects_ipv4() {
    assert!(!run_filter("ether proto arp", &tcp(IP_A, IP_B, 1234, 80)));
}

// ── Additional ICMP named constants ──────────────────────────────────────────

#[test]
fn icmp_echoreply_constant() {
    let reply = eth_ipv4_icmp(IP_B, IP_A, 0, 0); // type=0 = echo reply
    let request = eth_ipv4_icmp(IP_A, IP_B, 8, 0);
    assert!(run_filter("icmp[icmptype] = icmp-echoreply", &reply));
    assert!(!run_filter("icmp[icmptype] = icmp-echoreply", &request));
}

#[test]
fn icmp_unreach_constant() {
    let unreach = eth_ipv4_icmp(IP_B, IP_A, 3, 0); // type=3 = destination unreachable
    let echo = eth_ipv4_icmp(IP_A, IP_B, 8, 0);
    assert!(run_filter("icmp[icmptype] = icmp-unreach", &unreach));
    assert!(!run_filter("icmp[icmptype] = icmp-unreach", &echo));
}

#[test]
fn icmp_redirect_constant() {
    let redirect = eth_ipv4_icmp(IP_B, IP_A, 5, 0); // type=5 = redirect
    let echo = eth_ipv4_icmp(IP_A, IP_B, 8, 0);
    assert!(run_filter("icmp[icmptype] = icmp-redirect", &redirect));
    assert!(!run_filter("icmp[icmptype] = icmp-redirect", &echo));
}

// ── Long and/not chains (#149) ───────────────────────────────────────────────
// These used to abort with a stack overflow. Expected verdicts are
// hand-derived from libpcap semantics (`tcp and tcp ...` is `tcp`; an even
// number of `!` cancels out); libpcap was not run for these.

#[test]
fn long_and_chain_matches_like_tcp() {
    let f = vec!["tcp"; 5000].join(" and ");
    assert!(run_filter(&f, &tcp(IP_A, IP_B, 1234, 80)));
    assert!(!run_filter(&f, &udp(IP_A, IP_B, 1234, 53)));
}

#[test]
fn long_not_chain_matches_by_parity() {
    let tcp_pkt = tcp(IP_A, IP_B, 1234, 80);
    let udp_pkt = udp(IP_A, IP_B, 1234, 53);
    let even = format!("{}tcp", "!".repeat(5000));
    let odd = format!("{}tcp", "not ".repeat(5001));
    assert!(run_filter(&even, &tcp_pkt));
    assert!(!run_filter(&even, &udp_pkt));
    assert!(!run_filter(&odd, &tcp_pkt));
    assert!(run_filter(&odd, &udp_pkt));
}

// ── Deeply nested parentheses (#199) ────────────────────────────────────────
// libpcap 1.10.3 accepts up to 9995 nested parentheses (per the issue);
// parentheses do not change the meaning, so these match like `tcp` and
// `not tcp` (hand-derived).

#[test]
fn thousand_nested_parens_match_like_tcp() {
    let tcp_pkt = tcp(IP_A, IP_B, 1234, 80);
    let udp_pkt = udp(IP_A, IP_B, 1234, 53);
    let f = format!("{}tcp{}", "(".repeat(1000), ")".repeat(1000));
    assert!(run_filter(&f, &tcp_pkt));
    assert!(!run_filter(&f, &udp_pkt));
    let not_f = format!("not {f}");
    assert!(!run_filter(&not_f, &tcp_pkt));
    assert!(run_filter(&not_f, &udp_pkt));
}

// ── Very long chains, now compiled in linear time (#202) ────────────────────
// Hand-derived verdicts, as for #149 above: a 32000-term `tcp and ...` is
// `tcp`, and 256000 `!`s cancel out.

#[test]
fn very_long_and_and_not_chains_match_like_tcp() {
    let tcp_pkt = tcp(IP_A, IP_B, 1234, 80);
    let udp_pkt = udp(IP_A, IP_B, 1234, 53);
    for f in [
        vec!["tcp"; 32_000].join(" and "),
        format!("{}tcp", "!".repeat(256_000)),
    ] {
        assert!(run_filter(&f, &tcp_pkt));
        assert!(!run_filter(&f, &udp_pkt));
    }
}

// ── Integer literals: a leading 0 is octal (#157) ────────────────────────────
// libpcap 1.10.3 reads `010` as 8 (scanner.l `stou`). Verdicts hand-derived from
// that and issue #157 (no live libpcap was available).

#[test]
fn octal_port_matches_decimal_value_on_every_link() {
    let on_dport = |dport| tcp(IP_A, IP_B, 1234, dport);
    for (pkt, want) in [(on_dport(8), true), (on_dport(10), false)] {
        let mut sll = vec![0, 0, 0, 1, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0x08, 0x00];
        sll.extend_from_slice(&pkt[14..]);
        for (link, bytes) in [
            (LinkType::Ethernet, &pkt[..]),
            (LinkType::RawIp, &pkt[14..]),
            (LinkType::LinuxSll, &sll[..]),
        ] {
            let prog = compile("tcp port 010", link, Target::Classic).unwrap();
            assert_eq!(
                pktbaffle::vm::run(prog.instructions(), bytes),
                want,
                "{link:?}"
            );
        }
    }
}

#[test]
fn octal_byte_offset_loads_ip_ttl() {
    // ip[010] is ip[8] (the TTL), not ip[10] (checksum high byte).
    let mut ttl1 = tcp(IP_A, IP_B, 1234, 80);
    ttl1[14 + 8] = 1;
    let mut csum1 = tcp(IP_A, IP_B, 1234, 80);
    csum1[14 + 10] = 1;
    assert!(run_filter("ip[010] = 1", &ttl1));
    assert!(!run_filter("ip[010] = 1", &csum1));
}

#[test]
fn octal_ip_proto_ether_proto_vlan_and_len() {
    let mut proto15 = tcp(IP_A, IP_B, 1234, 80);
    proto15[14 + 9] = 15;
    assert!(run_filter("ip proto 017", &proto15));
    assert!(!run_filter("ip proto 017", &tcp(IP_A, IP_B, 1234, 80)));

    let mut etype40 = tcp(IP_A, IP_B, 1234, 80);
    etype40[12..14].copy_from_slice(&[0x00, 0x40]);
    assert!(run_filter("ether proto 0100", &etype40));
    assert!(!run_filter("ether proto 0100", &tcp(IP_A, IP_B, 1234, 80)));

    assert!(run_filter(
        "vlan 010",
        &eth_vlan_ipv4_tcp(8, IP_A, IP_B, 1234, 80, 2)
    ));
    assert!(!run_filter(
        "vlan 010",
        &eth_vlan_ipv4_tcp(10, IP_A, IP_B, 1234, 80, 2)
    ));

    // 54 bytes of headers: 10 payload bytes make 64 (= 0100), 46 make 100.
    let len64 = eth_ipv4_tcp(MAC_B, MAC_A, IP_A, IP_B, 1234, 80, 0x02, 10);
    let len100 = eth_ipv4_tcp(MAC_B, MAC_A, IP_A, IP_B, 1234, 80, 0x02, 46);
    assert!(run_filter("len = 0100", &len64));
    assert!(!run_filter("len = 0100", &len100));
}

#[test]
fn octal_cidr_prefix_is_a_slash_8() {
    // net 10.0.0.0/010 is /8: 10.64.0.1 and 10.128.0.1 match (a /10 would not
    // match 10.128.x.x); 11.0.0.1 does not.
    for (src, want) in [
        ([10, 64, 0, 1], true),
        ([10, 128, 0, 1], true),
        ([11, 0, 0, 1], false),
    ] {
        assert_eq!(
            run_filter("net 10.0.0.0/010", &tcp(src, IP_C, 1234, 80)),
            want,
            "{src:?}"
        );
    }
}

// ── Zero-padded octets in dotted IPv4 literals (#191) ────────────────────────
// `host 010.1.2.3` is 10.1.2.3 (decimal octets), as in libpcap 1.10.3.
// Verdicts hand-derived from issue #191 (no live libpcap was available).

#[test]
fn zero_padded_host_matches_decimal_address() {
    let src_10 = tcp([10, 1, 2, 3], IP_B, 1234, 80);
    let dst_10 = tcp(IP_B, [10, 1, 2, 3], 1234, 80);
    let src_8 = tcp([8, 1, 2, 3], IP_B, 1234, 80);
    for f in ["host 010.1.2.3", "host 10.001.002.003"] {
        assert!(run_filter(f, &src_10), "{f} src");
        assert!(run_filter(f, &dst_10), "{f} dst");
        assert!(!run_filter(f, &src_8), "{f} must not match 8.1.2.3");
    }
}

#[test]
fn zero_padded_netmask_is_a_slash_24() {
    let f = "net 192.168.1.0 mask 255.255.255.000";
    assert!(run_filter(f, &tcp([192, 168, 1, 77], IP_B, 1234, 80)));
    assert!(!run_filter(f, &tcp([192, 168, 2, 77], IP_B, 1234, 80)));
}

// ── IPv6 nets starting with `::` and spaced prefixes (#173, #194) ────────────
// Verdicts hand-derived from issues #173 and #194 (no live libpcap was
// available): `net ::ffff:0:0/96` matches IPv4-mapped addresses.

fn v6_mapped(a: u8, b: u8, c: u8, d: u8) -> [u8; 16] {
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, a, b, c, d]
}

const V6_LOOPBACK: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

#[test]
fn net_double_colon_zero_matches_any_ipv6_not_ipv4() {
    let v6 = eth_ipv6_tcp(IPV6_A, IPV6_B, 1234, 80, 0x02);
    assert!(run_filter("net ::/0", &v6));
    assert!(!run_filter("net ::/0", &tcp(IP_A, IP_B, 1234, 80)));
    assert!(!run_filter("not net ::/0", &v6));
}

#[test]
fn net_loopback_slash_128_matches_src_or_dst() {
    let to_lo = eth_ipv6_tcp(IPV6_A, V6_LOOPBACK, 1234, 80, 0x02);
    let from_lo = eth_ipv6_tcp(V6_LOOPBACK, IPV6_A, 1234, 80, 0x02);
    let other = eth_ipv6_tcp(IPV6_A, IPV6_B, 1234, 80, 0x02);
    for f in ["net ::1/128", "host ::1/128", "net ::1 / 128"] {
        assert!(run_filter(f, &to_lo), "{f} dst");
        assert!(run_filter(f, &from_lo), "{f} src");
        assert!(!run_filter(f, &other), "{f} other");
    }
    assert!(run_filter("src net ::1/128", &from_lo));
    assert!(!run_filter("src net ::1/128", &to_lo));
}

#[test]
fn net_ipv4_mapped_slash_96() {
    let mapped = eth_ipv6_tcp(IPV6_A, v6_mapped(1, 2, 3, 4), 1234, 80, 0x02);
    let plain = eth_ipv6_tcp(IPV6_A, IPV6_B, 1234, 80, 0x02);
    assert!(run_filter("net ::ffff:0:0/96", &mapped));
    assert!(!run_filter("net ::ffff:0:0/96", &plain));
}

#[test]
fn spaced_and_hex_ipv4_prefix_match_like_glued() {
    for f in ["net 10.0.0.0 / 8", "net 10.0.0.0/ 8", "net 10.0.0.0/0x8"] {
        assert!(run_filter(f, &tcp([10, 128, 0, 1], IP_C, 1234, 80)), "{f}");
        assert!(!run_filter(f, &tcp([11, 0, 0, 1], IP_C, 1234, 80)), "{f}");
    }
}

// ── A bare integer is an IPv4 host or net (#190) ─────────────────────────────
// Verdicts from the packets named in issue #190 (hand-derived from libpcap's
// `gen_ncode`; no live libpcap was available).

#[test]
fn host_bare_integer_is_the_exact_address() {
    let src_10 = tcp([0, 0, 0, 10], [9, 9, 9, 9], 1234, 80);
    let dst_10 = tcp([9, 9, 9, 9], [0, 0, 0, 10], 1234, 80);
    let dotted_10 = tcp([10, 0, 0, 0], [9, 9, 9, 9], 1234, 80);
    for f in ["host 10", "ip host 10", "host 0xa"] {
        assert!(run_filter(f, &src_10), "{f} src");
        assert!(run_filter(f, &dst_10), "{f} dst");
        assert!(!run_filter(f, &dotted_10), "{f} must not match 10.0.0.0");
    }
    assert!(run_filter("src host 10", &src_10));
    assert!(!run_filter("src host 10", &dst_10));
    assert!(run_filter("dst host 10", &dst_10));
    assert!(!run_filter("dst host 10", &src_10));
    assert!(run_filter(
        "host 0x0a000001",
        &tcp([10, 0, 0, 1], [9, 9, 9, 9], 1, 2)
    ));
}

#[test]
fn net_bare_integer_shifts_into_a_prefix() {
    // (filter, matching source, non-matching source)
    for (f, yes, no) in [
        ("net 256", [1, 0, 0, 5], [1, 1, 0, 5]),
        ("net 300", [1, 44, 5, 5], [1, 45, 5, 5]),
        ("net 65536", [1, 0, 0, 77], [1, 0, 1, 77]),
        ("net 16777216", [1, 0, 0, 0], [1, 0, 0, 1]),
        ("net 10", [10, 9, 9, 9], [11, 9, 9, 9]),
    ] {
        assert!(run_filter(f, &tcp(yes, [9, 9, 9, 9], 1234, 80)), "{f} yes");
        assert!(run_filter(f, &tcp([9, 9, 9, 9], yes, 1234, 80)), "{f} dst");
        assert!(!run_filter(f, &tcp(no, [9, 9, 9, 9], 1234, 80)), "{f} no");
    }
}

// ── Dotted IPv4 host/net: the written octet count sets the mask (#158) ───────
// Verdicts are the libpcap 1.10.3 results tabulated in issue #158 (packet
// `Ether()/IP(src=..., dst="192.0.2.1")/TCP()`), plus the matching cases that
// follow from the same masks.

fn src_pkt(src: [u8; 4]) -> Vec<u8> {
    tcp(src, [192, 0, 2, 1], 1234, 80)
}

#[test]
fn net_dotted_mask_follows_octet_count() {
    for (f, src, want) in [
        // All NOMATCH in libpcap (the old trailing-zero guess matched them).
        ("net 10.0.0.0", [10, 0, 0, 1], false),
        ("net 10.0.0.0", [10, 3, 4, 5], false),
        ("net 192.168.1.0", [192, 168, 1, 77], false),
        ("net 10.0", [10, 1, 1, 1], false),
        ("net 10.0.0", [10, 0, 1, 1], false),
        ("net 10.1.0", [10, 1, 1, 1], false),
        ("net 0", [0, 1, 2, 3], false),
        // What the same masks do match.
        ("net 10.0.0.0", [10, 0, 0, 0], true),
        ("net 192.168.1.0", [192, 168, 1, 0], true),
        ("net 10.0", [10, 0, 5, 5], true),
        ("net 10.0.0", [10, 0, 0, 9], true),
        ("net 10.1.0", [10, 1, 0, 200], true),
        ("net 0", [0, 0, 0, 0], true),
        // `net 10` stays /8.
        ("net 10", [10, 99, 1, 1], true),
        ("net 10", [11, 0, 0, 1], false),
    ] {
        assert_eq!(run_filter(f, &src_pkt(src)), want, "{f} on src {src:?}");
    }
}

#[test]
fn host_short_dotted_matches_the_network() {
    // MATCH in libpcap: `host 10.1` is 10.1.0.0/16, `host 10.1.2` is /24.
    for f in ["host 10.1", "ip host 10.1", "src host 10.1"] {
        assert!(run_filter(f, &src_pkt([10, 1, 2, 3])), "{f}");
    }
    assert!(run_filter("dst host 10.1", &tcp(IP_B, [10, 1, 9, 9], 1, 2)));
    assert!(!run_filter("src host 10.1", &src_pkt([10, 2, 2, 3])));
    assert!(run_filter("host 10.1.2", &src_pkt([10, 1, 2, 77])));
    assert!(!run_filter("host 10.1.2", &src_pkt([10, 1, 3, 77])));
    // Four octets are still the exact host.
    assert!(!run_filter("host 10.1.2.3", &src_pkt([10, 1, 2, 4])));
}

// ── Digit-first IPv6 with an embedded IPv4 tail (#192) ───────────────────────
// Issue #192: the NAT64 packet `Ether()/IPv6(dst="64:ff9b::c000:201")/TCP()`
// matches `host 64:ff9b::192.0.2.1`; dst `...c000:202` does not.

#[test]
fn nat64_dotted_host_matches_hex_address() {
    let nat64 = |tail: [u8; 4]| {
        let mut a = [0u8; 16];
        a[..4].copy_from_slice(&[0x00, 0x64, 0xff, 0x9b]);
        a[12..].copy_from_slice(&tail);
        a
    };
    let hit = eth_ipv6_tcp(IPV6_A, nat64([0xc0, 0x00, 0x02, 0x01]), 1234, 80, 0x02);
    let miss = eth_ipv6_tcp(IPV6_A, nat64([0xc0, 0x00, 0x02, 0x02]), 1234, 80, 0x02);
    assert!(run_filter("host 64:ff9b::192.0.2.1", &hit));
    assert!(run_filter("dst host 64:ff9b::192.0.2.1", &hit));
    assert!(!run_filter("src host 64:ff9b::192.0.2.1", &hit));
    assert!(!run_filter("host 64:ff9b::192.0.2.1", &miss));
}

// ── IPv6 `net <addr>` without a prefix is a /128 (#174) ──────────────────────
// Issue #174's packets: a has src 2001:db8::1, b has dst 2001:db8::1, c has src
// 2001:db8::2. `net 2001:db8::1` matches a and b, not c, exactly like `host` and
// `net .../128`.

#[test]
fn ipv6_net_without_prefix_matches_like_host() {
    let a = eth_ipv6_tcp(IPV6_A, V6_LOOPBACK, 1234, 80, 0x02);
    let b = eth_ipv6_udp(V6_LOOPBACK, IPV6_A, 1234, 53);
    let c = eth_ipv6_tcp(IPV6_B, V6_LOOPBACK, 1234, 80, 0x02);
    for f in ["net 2001:db8::1", "host 2001:db8::1", "net 2001:db8::1/128"] {
        assert!(run_filter(f, &a), "{f} a");
        assert!(run_filter(f, &b), "{f} b");
        assert!(!run_filter(f, &c), "{f} c");
    }
    assert!(run_filter("src net 2001:db8::1", &a));
    assert!(!run_filter("src net 2001:db8::1", &b));
    assert!(run_filter("dst net 2001:db8::1", &b));
    assert!(!run_filter("dst net 2001:db8::1", &a));
    assert!(!run_filter("net 2001:db8::1", &tcp(IP_A, IP_B, 1234, 80)));
}

// ── `net` with bits outside the prefix/mask is an error (#208) ────────────────
// The nets libpcap 1.10.3 still accepts (issue #208) match exactly their
// addresses; the rejected ones never reach the VM (see integration.rs).
// Verdicts hand-derived from the issue.

/// `head` zero-padded to 15 bytes, then `last`.
fn v6(head: &[u8], last: u8) -> [u8; 16] {
    let mut a = [0u8; 16];
    a[..head.len()].copy_from_slice(head);
    a[15] = last;
    a
}

#[test]
fn accepted_ipv4_nets_still_match() {
    let hit = |f: &str, ip: [u8; 4]| run_filter(f, &tcp(ip, IP_C, 1234, 80));
    // 10.1/24 is 10.1.0.0/24
    assert!(hit("net 10.1/24", [10, 1, 0, 200]));
    assert!(!hit("net 10.1/24", [10, 1, 1, 200]));
    // A non-contiguous mask keeps matching on the bits it names.
    assert!(hit("net 10.0.0.0 mask 255.0.255.0", [10, 99, 0, 7]));
    assert!(!hit("net 10.0.0.0 mask 255.0.255.0", [10, 99, 1, 7]));
    // /0 with a zero address is every IPv4 packet, and no IPv6 one.
    assert!(hit("net 0.0.0.0/0", IP_A));
    assert!(!run_filter(
        "net 0.0.0.0/0",
        &eth_ipv6_tcp(IPV6_A, IPV6_B, 1234, 80, 0x02)
    ));
}

#[test]
fn accepted_ipv6_nets_still_match() {
    let hit =
        |f: &str, src: [u8; 16]| run_filter(f, &eth_ipv6_tcp(src, IPV6_MCAST, 1234, 80, 0x02));
    assert!(hit(
        "net 2001:db8::/32",
        v6(&[0x20, 0x01, 0x0d, 0xb8, 0, 5], 7)
    ));
    assert!(!hit("net 2001:db8::/32", v6(&[0x20, 0x01, 0x0d, 0xb9], 1)));
    // fe80::/10 covers fe80:: through febf:: and not fec0::.
    assert!(hit("net fe80::/10", v6(&[0xfe, 0x80], 1)));
    assert!(hit("net fe80::/10", v6(&[0xfe, 0xbf], 1)));
    assert!(!hit("net fe80::/10", v6(&[0xfe, 0xc0], 1)));
    // A /128 is that one address.
    assert!(hit("net 2001:db8::/128", v6(&[0x20, 0x01, 0x0d, 0xb8], 0)));
    assert!(!hit("net 2001:db8::/128", v6(&[0x20, 0x01, 0x0d, 0xb8], 1)));
}

// ── IpNet::from_prefix above /32 clamps instead of wrapping (#187) ──────────
// Before the fix a release build returned mask 0x80000000 for /33, so the
// program tested only the top address bit: 1.1.1.1 -> 200.9.9.9 matched
// (src top bit clear).  Hand-derived: /33 is documented to clamp to /32, i.e.
// it matches exactly like `net 10.1.2.3/32`.  libpcap rejects the string form.

#[test]
fn from_prefix_above_32_matches_like_a_host_mask() {
    use pktbaffle::ast::{Dir, Expr, IpNet, Primitive};
    use pktbaffle::codegen;
    use std::net::Ipv4Addr;

    let host = tcp([10, 1, 2, 3], [1, 1, 1, 1], 1234, 80);
    let other = tcp([1, 1, 1, 1], [200, 9, 9, 9], 1234, 80);
    let neighbour = tcp([10, 1, 2, 4], [1, 1, 1, 1], 1234, 80);
    for len in [33u8, 64, 255] {
        let net = IpNet::from_prefix(Ipv4Addr::new(10, 1, 2, 3), len);
        let e = Expr::Primitive(Primitive::Net {
            net,
            dir: Dir::SrcOrDst,
        });
        let prog = codegen::compile(&e, LinkType::Ethernet).unwrap();
        assert!(pktbaffle::vm::run(prog.instructions(), &host), "/{len}");
        assert!(!pktbaffle::vm::run(prog.instructions(), &other), "/{len}");
        assert!(
            !pktbaffle::vm::run(prog.instructions(), &neighbour),
            "/{len}"
        );
    }
    assert!(run_filter("net 10.1.2.3/32", &host));
    assert!(!run_filter("net 10.1.2.3/32", &other));
    assert!(!run_filter("net 10.1.2.3/32", &neighbour));
}

// ── vm::run: JA with a huge `k` must fault, not wrap pc backwards (#188) ────
// `pc.wrapping_add(k as usize)` wrapped on 32-bit targets, so `ja 0xFFFFFFFF`
// jumped to itself and `vm::run` never returned (on 64-bit it walked off the
// end and returned false).  The verdicts below are the issue's observations
// on x86_64 (hang on i686): libpcap 1.10.3 `bpf_validate()` rejects `ja 5`
// and `ja 0xFFFFFFFE` on a 2-insn program; `ja 0xFFFFFFFF` is not a clean
// oracle (libpcap has its own u_int wrap quirk), so those are hand-derived.
// Only a 32-bit run can fail before the fix; the loop is bounded by a
// timeout so a regression fails instead of hanging the suite.

/// Run `vm::run` on a small-stack thread, failing (not hanging) after 10 s.
fn run_bounded(insns: Vec<pktbaffle::bpf::Insn>, pkt: &'static [u8]) -> bool {
    use std::sync::mpsc;
    use std::time::Duration;

    let (tx, rx) = mpsc::channel();
    std::thread::Builder::new()
        .stack_size(512 * 1024)
        .spawn(move || {
            let r = std::panic::catch_unwind(|| pktbaffle::vm::run(&insns, pkt));
            let _ = tx.send(r);
        })
        .expect("spawn thread");
    match rx.recv_timeout(Duration::from_secs(10)) {
        Ok(Ok(verdict)) => verdict,
        Ok(Err(_)) => panic!("vm::run panicked"),
        Err(_) => panic!("vm::run did not return within 10 s (hang)"),
    }
}

#[test]
fn ja_with_huge_k_is_a_fault_not_a_wrapped_jump() {
    use pktbaffle::bpf::{Insn, BPF_ACCEPT};

    // Self-loop on 32-bit before the fix.
    assert!(!run_bounded(
        vec![Insn::ja(u32::MAX), Insn::ret_k(BPF_ACCEPT)],
        b"x"
    ));
    // Backward loop to pc 0 on 32-bit before the fix.
    assert!(!run_bounded(
        vec![
            Insn::ld_imm(1),
            Insn::ja(0xFFFF_FFFE),
            Insn::ret_k(BPF_ACCEPT)
        ],
        b"x"
    ));
    // Nearby huge and merely out-of-range targets fault as well.
    for k in [0x8000_0000, 0xFFFF_FFFD, 5] {
        assert!(
            !run_bounded(vec![Insn::ja(k), Insn::ret_k(BPF_ACCEPT)], b"x"),
            "ja {k:#x}"
        );
    }
}

#[test]
fn ja_forward_within_program_still_works() {
    use pktbaffle::bpf::{Insn, BPF_ACCEPT};

    // [ja 1, ret 0, ret ACCEPT]: the control from the issue.
    assert!(run_bounded(
        vec![Insn::ja(1), Insn::ret_k(0), Insn::ret_k(BPF_ACCEPT)],
        b"x"
    ));
    // Jumping to exactly the last instruction is in range.
    assert!(run_bounded(
        vec![Insn::ja(0), Insn::ret_k(BPF_ACCEPT)],
        b"x"
    ));
}

// ── Malformed cBPF opcodes make the VM return false (#201) ──────────────────
// `vm::run` used to mask individual bit fields, so malformed opcodes ran as if
// they were valid ones (RET|X returned k, MISC 0xff ran as TXA, ...).  libpcap
// 1.10.3's `bpf_validate()` accepts them (it checks class and mode only), but
// `bpf_filter()` switches on the exact opcode and hits `abort()` for each
// code below (the issue ran `pcap_offline_filter`: SIGABRT), and the kernel's
// `bpf_check_classic()` rejects them with EINVAL; the documented pktbaffle
// contract is `false`.  The verdicts for the issue's seven programs are the
// issue's observations of the old behaviour inverted; the valid siblings are
// hand-derived.

fn raw(code: u16, k: u32) -> pktbaffle::bpf::Insn {
    pktbaffle::bpf::Insn {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn vm(insns: &[pktbaffle::bpf::Insn], pkt: &[u8]) -> bool {
    pktbaffle::vm::run(insns, pkt)
}

#[test]
fn malformed_opcodes_from_the_issue_return_false() {
    use pktbaffle::bpf::Insn;

    let jeq3 = Insn {
        code: 0x15,
        jt: 0,
        jf: 1,
        k: 3,
    };
    // RET|X (0x0e) is not an opcode; it used to return k.
    assert!(!vm(&[raw(0x0e, 1)], &[]));
    // MISC 0xff used to run as TXA: ldx #5 ; ld #0 ; <0xff> ; ret a.
    assert!(!vm(
        &[raw(0x01, 5), raw(0x00, 0), raw(0xff, 0), raw(0x16, 0)],
        &[]
    ));
    // LD|H|LEN (0x88) used to run as LD LEN: ld len ; jeq #3 ; ret 1 ; ret 0.
    assert!(!vm(
        &[raw(0x88, 0), jeq3, raw(0x06, 1), raw(0x06, 0)],
        &[1, 2, 3]
    ));
    // LD|B|IMM (0x10) used to run as LD IMM.
    assert!(!vm(&[raw(0x10, 7), raw(0x16, 0)], &[]));
    // ST with stray bits (0x62) used to store to M[0].
    assert!(!vm(
        &[
            raw(0x00, 9),
            raw(0x62, 0),
            raw(0x00, 0),
            raw(0x60, 0),
            raw(0x16, 0)
        ],
        &[]
    ));
    // ALU NEG|X (0x8c) used to negate.
    assert!(!vm(&[raw(0x00, 5), raw(0x8c, 0), raw(0x16, 0)], &[]));
    // LDX|H|IMM (0x09) used to load the immediate.
    assert!(!vm(&[raw(0x09, 3), raw(0x87, 0), raw(0x16, 0)], &[]));
}

#[test]
fn valid_siblings_of_the_malformed_opcodes_still_run() {
    use pktbaffle::bpf::Insn;

    let jeq3 = Insn {
        code: 0x15,
        jt: 0,
        jf: 1,
        k: 3,
    };
    assert!(vm(&[raw(0x06, 1)], &[])); // RET|K
    assert!(vm(
        &[raw(0x01, 5), raw(0x00, 0), raw(0x87, 0), raw(0x16, 0)],
        &[]
    )); // TXA
    assert!(vm(
        &[raw(0x80, 0), jeq3, raw(0x06, 1), raw(0x06, 0)],
        &[1, 2, 3]
    )); // LD|W|LEN
    assert!(vm(&[raw(0x00, 7), raw(0x16, 0)], &[])); // LD|W|IMM
    assert!(vm(
        &[
            raw(0x00, 9),
            raw(0x02, 0),
            raw(0x00, 0),
            raw(0x60, 0),
            raw(0x16, 0)
        ],
        &[]
    )); // ST, LD|W|MEM
    assert!(vm(&[raw(0x00, 5), raw(0x84, 0), raw(0x16, 0)], &[])); // ALU NEG|K
    assert!(vm(&[raw(0x01, 3), raw(0x87, 0), raw(0x16, 0)], &[])); // LDX|W|IMM
    assert!(!vm(&[raw(0x16, 0)], &[])); // RET|A with A = 0: the issue's baseline
}

/// The 47 opcodes `vm::run` implements, written out by hand from libpcap's
/// `bpf_filter()` switch (plus ALU XOR, which pktbaffle's codegen emits).
/// ALU MOD (0x94 / 0x9c, kernel-only) is not implemented by the VM, so it is
/// invalid here.
const VALID_OPCODES: &[u16] = &[
    // LD: W/H/B ABS, W/H/B IND, W LEN, W IMM, W MEM
    0x20, 0x28, 0x30, 0x40, 0x48, 0x50, 0x80, 0x00, 0x60,
    // LDX: W IMM, W LEN, W MEM, B MSH
    0x01, 0x81, 0x61, 0xb1, // ST, STX
    0x02, 0x03, // ALU K/X: add sub mul div or and lsh rsh; NEG (K only); XOR K/X
    0x04, 0x0c, 0x14, 0x1c, 0x24, 0x2c, 0x34, 0x3c, 0x44, 0x4c, 0x54, 0x5c, 0x64, 0x6c, 0x74, 0x7c,
    0x84, 0xa4, 0xac, // JMP: JA (K only), JEQ/JGT/JGE/JSET K/X
    0x05, 0x15, 0x1d, 0x25, 0x2d, 0x35, 0x3d, 0x45, 0x4d, // RET K/A, TAX, TXA
    0x06, 0x16, 0x07, 0x87,
];

#[test]
fn only_exact_cbpf_opcodes_execute_and_disassemble() {
    use pktbaffle::bpf::{Insn, BPF_ACCEPT};

    assert_eq!(VALID_OPCODES.len(), 47);
    let pkt = [0u8; 16];
    for code in 0..=u16::MAX {
        let insn = Insn {
            code,
            jt: 0,
            jf: 0,
            k: 1,
        };
        let shown = insn.to_string();
        if VALID_OPCODES.contains(&code) {
            assert!(!shown.contains(".word"), "{code:#06x} is valid: {shown}");
        } else {
            assert!(
                shown.contains(".word") && shown.contains("invalid"),
                "{code:#06x} must be marked invalid: {shown}"
            );
            // Were it executed, a non-jump opcode would fall through to the
            // accepting `ret`.
            assert!(!vm(&[insn, Insn::ret_k(BPF_ACCEPT)], &pkt), "{code:#06x}");
        }
    }
}

#[test]
fn compiled_programs_contain_only_valid_opcodes() {
    // Every opcode `compile()` emits (all link types, byte access, arithmetic,
    // vlan/mpls, protochain, ...) must stay inside the valid set.
    let filters = [
        "tcp",
        "udp or icmp",
        "ip6 and tcp port 80",
        "host 10.0.0.1 and not port 22",
        "net 10.0.0.0/8",
        "ether host aa:bb:cc:dd:ee:ff",
        "ether broadcast",
        "vlan 100 and tcp",
        "mpls 5",
        "pppoes 7",
        "len > 100 and len <= 1500",
        "tcp[13] & 2 != 0",
        "tcp[tcpflags] & tcp-syn != 0",
        "ip[2:2] + 20 > 40",
        "ip[0] & 0xf * 4 = 20",
        "ip[1] - 1 = ip[2]",
        "ip[0] ^ 1 = 4",
        "ip[0] << 1 = 4",
        "ip[0] >> 1 & 3 = 2",
        "ip[0] - 1 = 2",
        "ip[8] * 2 / 2 = 64",
        "icmp[icmptype] = icmp-echo",
        "ip6 protochain 6",
        "ip protochain 17",
        "portrange 1000-2000",
        "ip multicast or ip6 multicast",
        "arp or rarp",
        "greater 100 or less 50",
    ];
    for &link in &[LinkType::Ethernet, LinkType::RawIp, LinkType::LinuxSll] {
        for f in filters {
            let prog = match compile(f, link, Target::Classic) {
                Ok(p) => p,
                // Ethernet-only primitives are rejected on the other links.
                Err(_) if link != LinkType::Ethernet => continue,
                Err(e) => panic!("compile({f:?}): {e}"),
            };
            for insn in prog.instructions() {
                assert!(
                    VALID_OPCODES.contains(&insn.code),
                    "{f:?} on {link:?} emitted opcode {:#06x}",
                    insn.code
                );
            }
        }
    }
}

// ── Classic programs are capped at BPF_MAXINSNS (4096) insns (#203) ─────────
// A filter that compiles to exactly 4096 insns still runs correctly in the VM.
// Hand-derived: `ip[0]` of the test frames is 0x45, so `ip[0] + 1 * n` equals
// `0x45 + n` and (via the 8-bit `ldb`) never wraps.

#[test]
fn program_of_exactly_4096_insns_runs() {
    use pktbaffle::bpf::BPF_MAXINSNS;

    let overhead = compile("ip[0]+1 = 0", LinkType::Ethernet, Target::Classic)
        .unwrap()
        .len()
        - 1;
    let n = BPF_MAXINSNS - overhead;
    let f = format!("ip[0]{} = {}", "+1".repeat(n), 0x45 + n);
    let prog = compile(&f, LinkType::Ethernet, Target::Classic).unwrap();
    assert_eq!(prog.len(), BPF_MAXINSNS);
    let hit = tcp(IP_A, IP_B, 1234, 80);
    assert_eq!(hit[14], 0x45);
    assert!(pktbaffle::vm::run(prog.instructions(), &hit));
    let mut miss = hit.clone();
    miss[14] = 0x46;
    assert!(!pktbaffle::vm::run(prog.instructions(), &miss));
    assert!(!pktbaffle::vm::run(
        prog.instructions(),
        &udp(IP_A, IP_B, 1234, 53)[..14]
    ));
}
