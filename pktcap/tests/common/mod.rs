use std::io::Write;

use pktcap::{Capture, Packet};

// ── Packet byte builders ──────────────────────────────────────────────────────

pub fn eth_frame(ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut f = vec![
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        (ethertype >> 8) as u8, ethertype as u8,
    ];
    f.extend_from_slice(payload);
    f
}

pub fn tcp_frame(dst_port: u16) -> Vec<u8> {
    let ip_tcp = vec![
        0x45, 0x00, 0x00, 0x28,
        0x00, 0x00, 0x00, 0x00,
        0x40, 0x06, 0x00, 0x00,
        0xc0, 0xa8, 0x01, 0x01,
        0x0a, 0x00, 0x00, 0x01,
        0x30, 0x39,
        (dst_port >> 8) as u8, dst_port as u8,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x50, 0x02, 0xff, 0xff,
        0x00, 0x00, 0x00, 0x00,
    ];
    eth_frame(0x0800, &ip_tcp)
}

pub fn udp_frame(dst_port: u16) -> Vec<u8> {
    let udp = vec![
        0x45, 0x00, 0x00, 0x1c,
        0x00, 0x00, 0x00, 0x00,
        0x40, 0x11, 0x00, 0x00,
        0xc0, 0xa8, 0x01, 0x01,
        0x0a, 0x00, 0x00, 0x01,
        0x30, 0x39,
        (dst_port >> 8) as u8, dst_port as u8,
        0x00, 0x08, 0x00, 0x00,
    ];
    eth_frame(0x0800, &udp)
}

// ── File format helpers ───────────────────────────────────────────────────────

pub fn pcap_bytes(link_type: u32, packets: &[&[u8]]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
    buf.extend_from_slice(&2u16.to_le_bytes());
    buf.extend_from_slice(&4u16.to_le_bytes());
    buf.extend_from_slice(&0i32.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&65535u32.to_le_bytes());
    buf.extend_from_slice(&link_type.to_le_bytes());
    for (i, data) in packets.iter().enumerate() {
        buf.extend_from_slice(&(i as u32).to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
        buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
        buf.extend_from_slice(data);
    }
    buf
}

pub fn pcapng_bytes(link_types: &[u16], packets: &[(u32, &[u8])]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&0x0A0D0D0Au32.to_le_bytes());
    buf.extend_from_slice(&28u32.to_le_bytes());
    buf.extend_from_slice(&0x1A2B3C4Du32.to_le_bytes());
    buf.extend_from_slice(&1u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0xFFFFFFFFFFFFFFFFu64.to_le_bytes());
    buf.extend_from_slice(&28u32.to_le_bytes());
    for &lt in link_types {
        buf.extend_from_slice(&1u32.to_le_bytes());
        buf.extend_from_slice(&20u32.to_le_bytes());
        buf.extend_from_slice(&lt.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&65535u32.to_le_bytes());
        buf.extend_from_slice(&20u32.to_le_bytes());
    }
    for &(iface_id, data) in packets {
        let cap_len = data.len() as u32;
        let padded = (cap_len + 3) & !3;
        let total_len = 32 + padded;
        buf.extend_from_slice(&6u32.to_le_bytes());
        buf.extend_from_slice(&total_len.to_le_bytes());
        buf.extend_from_slice(&iface_id.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&cap_len.to_le_bytes());
        buf.extend_from_slice(&cap_len.to_le_bytes());
        buf.extend_from_slice(data);
        buf.extend(std::iter::repeat(0u8).take((padded - cap_len) as usize));
        buf.extend_from_slice(&total_len.to_le_bytes());
    }
    buf
}

pub fn temp_file(bytes: &[u8]) -> tempfile::NamedTempFile {
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(bytes).unwrap();
    f
}

/// Read all packets from a file path into a Vec.
pub fn read_all(path: &std::path::Path) -> Vec<Packet> {
    let mut cap = Capture::from_file(path).open().unwrap();
    let mut out = Vec::new();
    while let Some(pkt) = cap.next().unwrap() {
        out.push(pkt);
    }
    out
}
