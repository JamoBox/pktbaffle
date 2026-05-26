mod common;

use pkttap::{Capture, LinkType};

#[test]
fn pcap_single_packet_roundtrip() {
    let pkt = common::tcp_frame(80);
    let tmp = common::temp_file(&common::pcap_bytes(1, &[&pkt]));
    let mut cap = Capture::from_file(tmp.path()).open().unwrap();

    let got = cap.next().unwrap().expect("expected a packet");
    assert_eq!(got.data, pkt);
}

#[test]
fn pcap_multiple_packets_all_returned() {
    let p1 = common::tcp_frame(80);
    let p2 = common::udp_frame(53);
    let tmp = common::temp_file(&common::pcap_bytes(1, &[&p1, &p2]));
    let mut cap = Capture::from_file(tmp.path()).open().unwrap();

    assert_eq!(cap.next().unwrap().unwrap().data, p1);
    assert_eq!(cap.next().unwrap().unwrap().data, p2);
}

#[test]
fn pcap_eof_returns_none() {
    let tmp = common::temp_file(&common::pcap_bytes(1, &[&common::tcp_frame(80)]));
    let mut cap = Capture::from_file(tmp.path()).open().unwrap();
    cap.next().unwrap().expect("first packet");
    assert!(cap.next().unwrap().is_none());
}

#[test]
fn pcap_reports_ethernet_link_type() {
    let tmp = common::temp_file(&common::pcap_bytes(1, &[&common::tcp_frame(80)]));
    let cap = Capture::from_file(tmp.path()).open().unwrap();
    assert_eq!(cap.link_type(), LinkType::Ethernet);
}

#[test]
fn pcap_reports_raw_link_type() {
    let raw_pkt = vec![
        0x45u8, 0x00, 0x00, 0x14, 0, 0, 0, 0, 64, 6, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8,
    ];
    let tmp = common::temp_file(&common::pcap_bytes(101, &[&raw_pkt]));
    let cap = Capture::from_file(tmp.path()).open().unwrap();
    assert_eq!(cap.link_type(), LinkType::RawIp);
}

#[test]
fn pcap_orig_len_preserved() {
    let pkt = common::tcp_frame(80);
    let orig = pkt.len() as u32;
    let tmp = common::temp_file(&common::pcap_bytes(1, &[&pkt]));
    let mut cap = Capture::from_file(tmp.path()).open().unwrap();

    let got = cap.next().unwrap().unwrap();
    assert_eq!(got.orig_len, orig);
    assert!(!got.is_truncated());
}

#[test]
fn pcapng_single_packet_roundtrip() {
    let pkt = common::tcp_frame(443);
    let tmp = common::temp_file(&common::pcapng_bytes(&[1], &[(0, &pkt)]));
    let mut cap = Capture::from_file(tmp.path()).open().unwrap();

    let got = cap.next().unwrap().expect("expected a packet");
    assert_eq!(got.data, pkt);
}

#[test]
fn pcapng_eof_returns_none() {
    let tmp = common::temp_file(&common::pcapng_bytes(&[1], &[(0, &common::tcp_frame(80))]));
    let mut cap = Capture::from_file(tmp.path()).open().unwrap();
    cap.next().unwrap().expect("first packet");
    assert!(cap.next().unwrap().is_none());
}

#[test]
fn pcapng_per_packet_link_type_from_idb() {
    let eth_pkt = common::tcp_frame(80);
    let raw_pkt = vec![
        0x45u8, 0x00, 0x00, 0x14, 0, 0, 0, 0, 64, 6, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8,
    ];
    let bytes = common::pcapng_bytes(&[1, 101], &[(0, &eth_pkt), (1, &raw_pkt)]);
    let tmp = common::temp_file(&bytes);
    let mut cap = Capture::from_file(tmp.path()).open().unwrap();

    let pkt0 = cap.next().unwrap().unwrap();
    assert_eq!(pkt0.link_type, LinkType::Ethernet);
    let pkt1 = cap.next().unwrap().unwrap();
    assert_eq!(pkt1.link_type, LinkType::RawIp);
}

#[test]
fn filter_expression_accepts_matching_packet() {
    let pkt = common::tcp_frame(80);
    let tmp = common::temp_file(&common::pcap_bytes(1, &[&pkt]));
    let mut cap = Capture::from_file(tmp.path())
        .filter("tcp port 80")
        .open()
        .unwrap();
    assert!(cap.next().unwrap().is_some());
    assert!(cap.next().unwrap().is_none());
}

#[test]
fn filter_expression_rejects_non_matching_packet() {
    let pkt = common::udp_frame(53);
    let tmp = common::temp_file(&common::pcap_bytes(1, &[&pkt]));
    let mut cap = Capture::from_file(tmp.path())
        .filter("tcp port 80")
        .open()
        .unwrap();
    assert!(cap.next().unwrap().is_none());
}

#[test]
fn filter_skips_non_matching_and_returns_next_match() {
    let tcp = common::tcp_frame(80);
    let udp = common::udp_frame(53);
    let tmp = common::temp_file(&common::pcap_bytes(1, &[&udp, &udp, &tcp, &udp]));
    let mut cap = Capture::from_file(tmp.path())
        .filter("tcp port 80")
        .open()
        .unwrap();

    let got = cap.next().unwrap().expect("should skip to TCP packet");
    assert_eq!(got.data, tcp);
    assert!(cap.next().unwrap().is_none());
}

#[test]
fn precompiled_filter_program_works() {
    use pktbaffle::{codegen::LinkType as BpfLinkType, compile, Target};

    let compiled = compile("tcp port 80", BpfLinkType::Ethernet, Target::Classic).unwrap();
    let prog = match compiled {
        pktbaffle::Program::Classic(p) => p,
        _ => unreachable!(),
    };
    let tcp = common::tcp_frame(80);
    let udp = common::udp_frame(53);
    let tmp = common::temp_file(&common::pcap_bytes(1, &[&udp, &tcp]));
    let mut cap = Capture::from_file(tmp.path())
        .filter_program(prog)
        .open()
        .unwrap();

    let got = cap
        .next()
        .unwrap()
        .expect("pre-compiled filter should accept TCP");
    assert_eq!(got.data, tcp);
    assert!(cap.next().unwrap().is_none());
}

// ── filter() accepts Option<&str> ────────────────────────────────────────────

#[test]
fn filter_none_captures_all_packets() {
    let tcp = common::tcp_frame(80);
    let udp = common::udp_frame(53);
    let tmp = common::temp_file(&common::pcap_bytes(1, &[&tcp, &udp]));

    // None is equivalent to no filter — both packets should arrive
    let mut cap = Capture::from_file(tmp.path()).filter(None::<&str>).open().unwrap();
    assert!(cap.next().unwrap().is_some());
    assert!(cap.next().unwrap().is_some());
    assert!(cap.next().unwrap().is_none());
}

#[test]
fn filter_option_some_filters_matching() {
    let tcp = common::tcp_frame(80);
    let udp = common::udp_frame(53);
    let tmp = common::temp_file(&common::pcap_bytes(1, &[&udp, &tcp]));

    // Option<&str> containing Some should filter exactly as a bare &str would
    let expr: Option<&str> = Some("tcp port 80");
    let mut cap = Capture::from_file(tmp.path()).filter(expr).open().unwrap();
    let got = cap.next().unwrap().expect("should return TCP packet");
    assert_eq!(got.data, tcp);
    assert!(cap.next().unwrap().is_none());
}

#[test]
fn filter_option_none_captures_all_packets() {
    let tcp = common::tcp_frame(80);
    let udp = common::udp_frame(53);
    let tmp = common::temp_file(&common::pcap_bytes(1, &[&tcp, &udp]));

    // Option<&str> containing None should pass all packets through
    let expr: Option<&str> = None;
    let mut cap = Capture::from_file(tmp.path()).filter(expr).open().unwrap();
    assert!(cap.next().unwrap().is_some());
    assert!(cap.next().unwrap().is_some());
    assert!(cap.next().unwrap().is_none());
}

#[test]
fn pcap_timestamp_increases_with_packets() {
    let tmp = common::temp_file(&common::pcap_bytes(
        1,
        &[&common::tcp_frame(80), &common::tcp_frame(443)],
    ));
    let mut cap = Capture::from_file(tmp.path()).open().unwrap();

    let t1 = cap.next().unwrap().unwrap().timestamp;
    let t2 = cap.next().unwrap().unwrap().timestamp;
    assert!(t2 > t1);
}
