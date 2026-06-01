//! VM-based libpcap expression parity tests.
//!
//! Compiles filter expressions and runs the software BPF VM against
//! byte-accurate synthetic packets to verify match/no-match semantics,
//! ensuring feature parity with the libpcap expression language.

#![cfg(feature = "vm")]

use pktbaffle::{compile, LinkType, Target};

// ── Ethernet constants ────────────────────────────────────────────────────────

const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_ARP: u16 = 0x0806;
const ETHERTYPE_IPV6: u16 = 0x86DD;
const ETHERTYPE_VLAN: u16 = 0x8100;

const IPPROTO_ICMP: u8 = 1;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

// Fixed test MACs and IPs — arbitrary but distinct.
const MAC_A: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
const MAC_B: [u8; 6] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
const MAC_BCAST: [u8; 6] = [0xff; 6];
const MAC_MCAST: [u8; 6] = [0x01, 0x00, 0x5e, 0x00, 0x00, 0x01]; // IPv4 multicast MAC

const IP_A: [u8; 4] = [192, 168, 1, 1];
const IP_B: [u8; 4] = [10, 0, 0, 1];
const IP_C: [u8; 4] = [172, 16, 0, 1];

// ── Core helper ──────────────────────────────────────────────────────────────

fn run_filter(filter: &str, pkt: &[u8]) -> bool {
    let prog = compile(filter, LinkType::Ethernet, Target::Classic)
        .unwrap_or_else(|e| panic!("compile({filter:?}): {e}"));
    pktbaffle::vm::run(prog.instructions(), pkt)
}

// ── Packet builders ───────────────────────────────────────────────────────────

/// Ethernet/IPv4/TCP frame.
///
/// Layout: 14 (Eth) + 20 (IPv4, IHL=5) + 20 (TCP) + payload_len bytes.
fn eth_ipv4_tcp(
    dst_mac: [u8; 6],
    src_mac: [u8; 6],
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    tcp_flags: u8,
    payload_len: usize,
) -> Vec<u8> {
    let mut p = Vec::new();
    // Ethernet header
    p.extend_from_slice(&dst_mac);
    p.extend_from_slice(&src_mac);
    p.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
    // IPv4 header (no options, IHL=5)
    p.push(0x45); // version=4, IHL=5
    p.push(0x00); // DSCP/ECN
    let total_len = (20u16 + 20 + payload_len as u16).to_be_bytes();
    p.extend_from_slice(&total_len);
    p.extend_from_slice(&[0x00, 0x00]); // identification
    p.extend_from_slice(&[0x00, 0x00]); // flags + fragment offset
    p.push(64); // TTL
    p.push(IPPROTO_TCP);
    p.extend_from_slice(&[0x00, 0x00]); // header checksum (not validated by VM)
    p.extend_from_slice(&src_ip);
    p.extend_from_slice(&dst_ip);
    // TCP header
    p.extend_from_slice(&src_port.to_be_bytes());
    p.extend_from_slice(&dst_port.to_be_bytes());
    p.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // seq
    p.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // ack
    p.push(0x50); // data offset=5, reserved=0
    p.push(tcp_flags);
    p.extend_from_slice(&[0xff, 0xff]); // window
    p.extend_from_slice(&[0x00, 0x00]); // checksum
    p.extend_from_slice(&[0x00, 0x00]); // urgent pointer
    p.extend(std::iter::repeat(0u8).take(payload_len));
    p
}

/// Ethernet/IPv4/UDP frame.
fn eth_ipv4_udp(
    dst_mac: [u8; 6],
    src_mac: [u8; 6],
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&dst_mac);
    p.extend_from_slice(&src_mac);
    p.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
    p.push(0x45);
    p.push(0x00);
    p.extend_from_slice(&(20u16 + 8).to_be_bytes());
    p.extend_from_slice(&[0x00, 0x00]);
    p.extend_from_slice(&[0x00, 0x00]);
    p.push(64);
    p.push(IPPROTO_UDP);
    p.extend_from_slice(&[0x00, 0x00]);
    p.extend_from_slice(&src_ip);
    p.extend_from_slice(&dst_ip);
    p.extend_from_slice(&src_port.to_be_bytes());
    p.extend_from_slice(&dst_port.to_be_bytes());
    p.extend_from_slice(&8u16.to_be_bytes()); // UDP length
    p.extend_from_slice(&[0x00, 0x00]); // checksum
    p
}

/// Ethernet/IPv4/ICMP frame.
fn eth_ipv4_icmp(src_ip: [u8; 4], dst_ip: [u8; 4], icmp_type: u8, icmp_code: u8) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&MAC_B);
    p.extend_from_slice(&MAC_A);
    p.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
    p.push(0x45);
    p.push(0x00);
    p.extend_from_slice(&(20u16 + 8).to_be_bytes());
    p.extend_from_slice(&[0x00, 0x00]);
    p.extend_from_slice(&[0x00, 0x00]);
    p.push(64);
    p.push(IPPROTO_ICMP);
    p.extend_from_slice(&[0x00, 0x00]);
    p.extend_from_slice(&src_ip);
    p.extend_from_slice(&dst_ip);
    // ICMP header: type, code, checksum (2), rest-of-header (4)
    p.push(icmp_type);
    p.push(icmp_code);
    p.extend_from_slice(&[0x00, 0x00]);
    p.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    p
}

/// Ethernet/ARP frame.
fn eth_arp(src_ip: [u8; 4], dst_ip: [u8; 4]) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&MAC_B);
    p.extend_from_slice(&MAC_A);
    p.extend_from_slice(&ETHERTYPE_ARP.to_be_bytes());
    p.extend_from_slice(&[0x00, 0x01]); // HTYPE = Ethernet
    p.extend_from_slice(&[0x08, 0x00]); // PTYPE = IPv4
    p.push(6); // HLEN
    p.push(4); // PLEN
    p.extend_from_slice(&[0x00, 0x01]); // OPER = request
    p.extend_from_slice(&MAC_A); // SHA
    p.extend_from_slice(&src_ip); // SPA
    p.extend_from_slice(&MAC_B); // THA
    p.extend_from_slice(&dst_ip); // TPA
    p
}

/// VLAN-tagged Ethernet/IPv4/TCP frame (802.1Q).
fn eth_vlan_ipv4_tcp(
    vlan_id: u16,
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    tcp_flags: u8,
) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&MAC_B);
    p.extend_from_slice(&MAC_A);
    p.extend_from_slice(&ETHERTYPE_VLAN.to_be_bytes()); // outer ethertype
    p.extend_from_slice(&(vlan_id & 0x0FFF).to_be_bytes()); // TCI (PCP=0, DEI=0, VID)
    p.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes()); // inner ethertype
                                                        // IPv4 + TCP
    p.push(0x45);
    p.push(0x00);
    p.extend_from_slice(&(20u16 + 20).to_be_bytes());
    p.extend_from_slice(&[0x00, 0x00]);
    p.extend_from_slice(&[0x00, 0x00]);
    p.push(64);
    p.push(IPPROTO_TCP);
    p.extend_from_slice(&[0x00, 0x00]);
    p.extend_from_slice(&src_ip);
    p.extend_from_slice(&dst_ip);
    p.extend_from_slice(&src_port.to_be_bytes());
    p.extend_from_slice(&dst_port.to_be_bytes());
    p.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
    p.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    p.push(0x50);
    p.push(tcp_flags);
    p.extend_from_slice(&[0xff, 0xff]);
    p.extend_from_slice(&[0x00, 0x00]);
    p.extend_from_slice(&[0x00, 0x00]);
    p
}

/// Ethernet/IPv6/TCP frame (40-byte IPv6 header, no extension headers).
fn eth_ipv6_tcp(
    src_ip: [u8; 16],
    dst_ip: [u8; 16],
    src_port: u16,
    dst_port: u16,
    tcp_flags: u8,
) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&MAC_B);
    p.extend_from_slice(&MAC_A);
    p.extend_from_slice(&ETHERTYPE_IPV6.to_be_bytes());
    // IPv6 fixed header (40 bytes)
    p.push(0x60); // version=6, traffic class high nibble=0
    p.extend_from_slice(&[0x00, 0x00, 0x00]); // traffic class low + flow label
    p.extend_from_slice(&20u16.to_be_bytes()); // payload length = TCP header
    p.push(IPPROTO_TCP); // next header
    p.push(64); // hop limit
    p.extend_from_slice(&src_ip);
    p.extend_from_slice(&dst_ip);
    // TCP header
    p.extend_from_slice(&src_port.to_be_bytes());
    p.extend_from_slice(&dst_port.to_be_bytes());
    p.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
    p.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    p.push(0x50);
    p.push(tcp_flags);
    p.extend_from_slice(&[0xff, 0xff]);
    p.extend_from_slice(&[0x00, 0x00]);
    p.extend_from_slice(&[0x00, 0x00]);
    p
}

/// Convenience wrapper: Ethernet/IPv4/TCP with SYN flag set.
fn tcp(src_ip: [u8; 4], dst_ip: [u8; 4], src_port: u16, dst_port: u16) -> Vec<u8> {
    eth_ipv4_tcp(MAC_B, MAC_A, src_ip, dst_ip, src_port, dst_port, 0x02, 0)
}

/// Convenience wrapper: Ethernet/IPv4/UDP.
fn udp(src_ip: [u8; 4], dst_ip: [u8; 4], src_port: u16, dst_port: u16) -> Vec<u8> {
    eth_ipv4_udp(MAC_B, MAC_A, src_ip, dst_ip, src_port, dst_port)
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
