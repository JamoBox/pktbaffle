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
