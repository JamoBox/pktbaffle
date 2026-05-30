//! Fuzz the software BPF VM interpreter against arbitrary packet bytes.
//!
//! The VM must never panic regardless of what byte sequence it receives as
//! a packet.  Any panic (including index-out-of-bounds) is a bug.

#![no_main]

use libfuzzer_sys::fuzz_target;
use pktbaffle::{compile, vm, LinkType, Target};

// A representative set of filter expressions that exercise different code paths
// in the VM: arithmetic, comparisons, BPF_MSH (IHL multiply), BPF_IND,
// bit-masking, and the two return paths.
static FILTERS: &[&str] = &[
    "tcp",
    "udp",
    "icmp",
    "arp",
    "ip",
    "ip6",
    "tcp port 80",
    "udp port 53",
    "host 192.168.1.1",
    "src host 10.0.0.1",
    "net 10.0.0.0/8",
    "port 443",
    "tcp and port 80",
    "tcp or udp",
    "not arp",
    "len < 64",
    "len > 1500",
    "vlan",
    "vlan 100",
    "tcp[13] & 0x02 != 0",
    "tcp[tcpflags] & tcp-syn != 0",
    "icmp[icmptype] = icmp-echo",
    "ip[8] = 64",
    "ether broadcast",
    "ether multicast",
    "ip broadcast",
    "ip multicast",
    "portrange 1024-65535",
    "mpls",
];

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // Use the first byte as an index to select the filter; the rest is the
    // packet payload fed to the VM.
    let filter = FILTERS[data[0] as usize % FILTERS.len()];
    let pkt = &data[1..];

    if let Ok(prog) = compile(filter, LinkType::Ethernet, Target::Classic) {
        // vm::run must never panic — it should return true/false.
        let _ = vm::run(prog.instructions(), pkt);
    }
});
