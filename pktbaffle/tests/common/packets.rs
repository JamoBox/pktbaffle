//! Byte-accurate synthetic packet builders shared by the parity test suites
//! (`vm_parity.rs`, `ebpf_exec.rs`).

// ── Ethernet constants ────────────────────────────────────────────────────────

pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_ARP: u16 = 0x0806;
pub const ETHERTYPE_IPV6: u16 = 0x86DD;
pub const ETHERTYPE_VLAN: u16 = 0x8100;

pub const IPPROTO_ICMP: u8 = 1;
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;

// Fixed test MACs and IPs — arbitrary but distinct.
pub const MAC_A: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
pub const MAC_B: [u8; 6] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
pub const MAC_BCAST: [u8; 6] = [0xff; 6];
pub const MAC_MCAST: [u8; 6] = [0x01, 0x00, 0x5e, 0x00, 0x00, 0x01]; // IPv4 multicast MAC

pub const IP_A: [u8; 4] = [192, 168, 1, 1];
pub const IP_B: [u8; 4] = [10, 0, 0, 1];
pub const IP_C: [u8; 4] = [172, 16, 0, 1];

// ── Packet builders ───────────────────────────────────────────────────────────

/// Ethernet/IPv4/TCP frame.
///
/// Layout: 14 (Eth) + 20 (IPv4, IHL=5) + 20 (TCP) + payload_len bytes.
pub fn eth_ipv4_tcp(
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
pub fn eth_ipv4_udp(
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
pub fn eth_ipv4_icmp(src_ip: [u8; 4], dst_ip: [u8; 4], icmp_type: u8, icmp_code: u8) -> Vec<u8> {
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
pub fn eth_arp(src_ip: [u8; 4], dst_ip: [u8; 4]) -> Vec<u8> {
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
pub fn eth_vlan_ipv4_tcp(
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
pub fn eth_ipv6_tcp(
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
pub fn tcp(src_ip: [u8; 4], dst_ip: [u8; 4], src_port: u16, dst_port: u16) -> Vec<u8> {
    eth_ipv4_tcp(MAC_B, MAC_A, src_ip, dst_ip, src_port, dst_port, 0x02, 0)
}

/// Convenience wrapper: Ethernet/IPv4/UDP.
pub fn udp(src_ip: [u8; 4], dst_ip: [u8; 4], src_port: u16, dst_port: u16) -> Vec<u8> {
    eth_ipv4_udp(MAC_B, MAC_A, src_ip, dst_ip, src_port, dst_port)
}

// Fixed IPv6 test addresses.
pub const IPV6_A: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
pub const IPV6_B: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
pub const IPV6_MCAST: [u8; 16] = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]; // ff02::1

/// Ethernet/IPv6/UDP frame (40-byte IPv6 header, no extension headers).
pub fn eth_ipv6_udp(src_ip: [u8; 16], dst_ip: [u8; 16], src_port: u16, dst_port: u16) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&MAC_B);
    p.extend_from_slice(&MAC_A);
    p.extend_from_slice(&ETHERTYPE_IPV6.to_be_bytes());
    p.push(0x60);
    p.extend_from_slice(&[0x00, 0x00, 0x00]);
    p.extend_from_slice(&8u16.to_be_bytes()); // payload length = UDP header
    p.push(IPPROTO_UDP);
    p.push(64);
    p.extend_from_slice(&src_ip);
    p.extend_from_slice(&dst_ip);
    p.extend_from_slice(&src_port.to_be_bytes());
    p.extend_from_slice(&dst_port.to_be_bytes());
    p.extend_from_slice(&8u16.to_be_bytes());
    p.extend_from_slice(&[0x00, 0x00]);
    p
}
