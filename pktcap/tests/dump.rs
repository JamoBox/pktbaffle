mod common;

use pktcap::{Dump, LinkType};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn pcap_tmp() -> tempfile::NamedTempFile {
    tempfile::Builder::new().suffix(".pcap").tempfile().unwrap()
}

fn pcapng_tmp() -> tempfile::NamedTempFile {
    tempfile::Builder::new()
        .suffix(".pcapng")
        .tempfile()
        .unwrap()
}

// ── open() contract ───────────────────────────────────────────────────────────

#[test]
fn dump_open_errors_without_link_type() {
    // link_type() is required; open() without it must return Err
    let tmp = pcap_tmp();
    assert!(Dump::to_file(tmp.path()).open().is_err());
}

#[test]
fn dump_open_errors_on_unknown_extension() {
    let tmp = tempfile::Builder::new().suffix(".xyz").tempfile().unwrap();
    assert!(
        Dump::to_file(tmp.path())
            .link_type(LinkType::Ethernet)
            .open()
            .is_err(),
        "unknown extension should fail"
    );
}

// ── pcap roundtrips ───────────────────────────────────────────────────────────

#[test]
fn dump_pcap_single_packet_roundtrip() {
    let src = common::tcp_frame(80);
    let src_pkts =
        common::read_all(&common::temp_file(&common::pcap_bytes(1, &[&src])).into_temp_path());

    let out = pcap_tmp();
    let mut dump = Dump::to_file(out.path())
        .link_type(LinkType::Ethernet)
        .open()
        .unwrap();
    dump.write_packet(&src_pkts[0]).unwrap();
    drop(dump);

    let got = common::read_all(out.path());
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].data, src);
}

#[test]
fn dump_pcap_multiple_packets_in_order() {
    let frames: Vec<Vec<u8>> = vec![
        common::tcp_frame(80),
        common::udp_frame(53),
        common::tcp_frame(443),
    ];
    let refs: Vec<&[u8]> = frames.iter().map(|f| f.as_slice()).collect();
    let src_pkts =
        common::read_all(&common::temp_file(&common::pcap_bytes(1, &refs)).into_temp_path());

    let out = pcap_tmp();
    let mut dump = Dump::to_file(out.path())
        .link_type(LinkType::Ethernet)
        .open()
        .unwrap();
    for pkt in &src_pkts {
        dump.write_packet(pkt).unwrap();
    }
    drop(dump);

    let got = common::read_all(out.path());
    assert_eq!(got.len(), 3);
    for (g, f) in got.iter().zip(frames.iter()) {
        assert_eq!(&g.data, f);
    }
}

#[test]
fn dump_pcap_link_type_written_to_header() {
    let src = common::tcp_frame(80);
    let src_pkts =
        common::read_all(&common::temp_file(&common::pcap_bytes(1, &[&src])).into_temp_path());

    let out = pcap_tmp();
    let mut dump = Dump::to_file(out.path())
        .link_type(LinkType::Ethernet)
        .open()
        .unwrap();
    dump.write_packet(&src_pkts[0]).unwrap();
    drop(dump);

    let cap = pktcap::Capture::from_file(out.path()).open().unwrap();
    assert_eq!(cap.link_type(), LinkType::Ethernet);
}

#[test]
fn dump_pcap_orig_len_preserved() {
    let src = common::tcp_frame(80);
    let expected_orig = src.len() as u32;
    let src_pkts =
        common::read_all(&common::temp_file(&common::pcap_bytes(1, &[&src])).into_temp_path());

    let out = pcap_tmp();
    let mut dump = Dump::to_file(out.path())
        .link_type(LinkType::Ethernet)
        .open()
        .unwrap();
    dump.write_packet(&src_pkts[0]).unwrap();
    drop(dump);

    let got = common::read_all(out.path());
    assert_eq!(got[0].orig_len, expected_orig);
}

// ── pcapng roundtrips ─────────────────────────────────────────────────────────

#[test]
fn dump_pcapng_single_packet_roundtrip() {
    let src = common::tcp_frame(443);
    let src_pkts =
        common::read_all(&common::temp_file(&common::pcap_bytes(1, &[&src])).into_temp_path());

    let out = pcapng_tmp();
    let mut dump = Dump::to_file(out.path())
        .link_type(LinkType::Ethernet)
        .open()
        .unwrap();
    dump.write_packet(&src_pkts[0]).unwrap();
    drop(dump);

    let got = common::read_all(out.path());
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].data, src);
}

#[test]
fn dump_pcapng_link_type_written_to_idb() {
    let src = common::tcp_frame(80);
    let src_pkts =
        common::read_all(&common::temp_file(&common::pcap_bytes(1, &[&src])).into_temp_path());

    let out = pcapng_tmp();
    let mut dump = Dump::to_file(out.path())
        .link_type(LinkType::Ethernet)
        .open()
        .unwrap();
    dump.write_packet(&src_pkts[0]).unwrap();
    drop(dump);

    let got = common::read_all(out.path());
    assert_eq!(got[0].link_type, LinkType::Ethernet);
}

#[test]
fn dump_pcapng_multiple_packets_in_order() {
    let frames: Vec<Vec<u8>> = vec![common::tcp_frame(80), common::udp_frame(53)];
    let refs: Vec<&[u8]> = frames.iter().map(|f| f.as_slice()).collect();
    let src_pkts =
        common::read_all(&common::temp_file(&common::pcap_bytes(1, &refs)).into_temp_path());

    let out = pcapng_tmp();
    let mut dump = Dump::to_file(out.path())
        .link_type(LinkType::Ethernet)
        .open()
        .unwrap();
    for pkt in &src_pkts {
        dump.write_packet(pkt).unwrap();
    }
    drop(dump);

    let got = common::read_all(out.path());
    assert_eq!(got.len(), 2);
    for (g, f) in got.iter().zip(frames.iter()) {
        assert_eq!(&g.data, f);
    }
}

// ── flush / drop ──────────────────────────────────────────────────────────────

#[test]
fn dump_flush_succeeds() {
    let out = pcap_tmp();
    let mut dump = Dump::to_file(out.path())
        .link_type(LinkType::Ethernet)
        .open()
        .unwrap();
    assert!(dump.flush().is_ok());
}

// ── overwrite ─────────────────────────────────────────────────────────────────

#[test]
fn dump_overwrites_existing_file() {
    let src_a = common::tcp_frame(80);
    let src_b = common::tcp_frame(443);
    let src_pkts_a =
        common::read_all(&common::temp_file(&common::pcap_bytes(1, &[&src_a])).into_temp_path());
    let src_pkts_b =
        common::read_all(&common::temp_file(&common::pcap_bytes(1, &[&src_b])).into_temp_path());

    let out = pcap_tmp();

    // First dump: write packet A
    let mut dump = Dump::to_file(out.path())
        .link_type(LinkType::Ethernet)
        .open()
        .unwrap();
    dump.write_packet(&src_pkts_a[0]).unwrap();
    drop(dump);

    // Second dump to same path: overwrite with packet B only
    let mut dump = Dump::to_file(out.path())
        .link_type(LinkType::Ethernet)
        .open()
        .unwrap();
    dump.write_packet(&src_pkts_b[0]).unwrap();
    drop(dump);

    let got = common::read_all(out.path());
    assert_eq!(got.len(), 1, "file should contain only the second write");
    assert_eq!(got[0].data, src_b);
}

// ── convenience function ──────────────────────────────────────────────────────

#[test]
fn convenience_dump_packets_roundtrip() {
    let frames: Vec<Vec<u8>> = vec![common::tcp_frame(80), common::udp_frame(53)];
    let refs: Vec<&[u8]> = frames.iter().map(|f| f.as_slice()).collect();
    let src_pkts =
        common::read_all(&common::temp_file(&common::pcap_bytes(1, &refs)).into_temp_path());

    let out = pcap_tmp();
    pktcap::dump_packets(out.path(), &src_pkts, LinkType::Ethernet).unwrap();

    let got = common::read_all(out.path());
    assert_eq!(got.len(), 2);
    assert_eq!(got[0].data, frames[0]);
    assert_eq!(got[1].data, frames[1]);
}
