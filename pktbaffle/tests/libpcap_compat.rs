//! Libpcap filter expression compatibility manifest.
//!
//! # Parity strategy
//!
//! Parity with libpcap's `pcap_compile(3)` / `pcap-filter(7)` is maintained
//! across three dimensions:
//!
//! ## 1. Syntax parity
//! Every primitive class from the pcap-filter(7) man page has a corresponding
//! compile test here.  Tests are organised to mirror the man-page sections so
//! gaps are easy to spot.  A primitive that compiles without error is
//! considered syntactically supported.
//!
//! ## 2. Semantic parity
//! Compile-only tests cannot catch off-by-one offsets, wrong masks, or
//! misidentified protocol numbers.  All supported primitives must also appear
//! in `tests/vm_parity.rs`, where crafted byte-accurate packets are run
//! through the software BPF VM to verify match/no-match behaviour.
//!
//! ## 3. Optimization parity
//! The `optimization_budgets` module asserts upper bounds on instruction
//! counts for the most commonly used filter patterns.  These bounds are
//! intentionally loose (current count + 4) so they do not break on minor
//! refactors, but they will catch pathological regressions where a pattern
//! suddenly balloons.  Exact instruction-sequence pinning lives in
//! `tests/bytecode.rs`.
//!
//! # Known gaps vs libpcap
//!
//! The following libpcap features are **not** currently supported.  They must
//! return `Err` rather than silently misbehaving (see `mod unsupported`).
//!
//! | Feature | Behaviour | Notes |
//! |---------|-----------|-------|
//! | `gateway host` | `Err(CodegenError)` | Requires ARP/routing table at compile time |
//! | `inbound` / `outbound` | `Err(CodegenError)` | Requires kernel/interface context |
//! | IPv6 extension header traversal | Partial | `ip6 protochain` only walks one level |
//! | bare `broadcast` | Ethernet-only | Does not include `ip broadcast`; use `ether broadcast or ip broadcast` |
//! | bare `multicast` | Ethernet-only | Does not include `ip multicast` or `ip6 multicast`; use explicit OR |

use pktbaffle::{compile, LinkType, Target};

fn eth(filter: &str) -> pktbaffle::Program {
    compile(filter, LinkType::Ethernet, Target::Classic)
        .unwrap_or_else(|e| panic!("compile({filter:?}) failed: {e}"))
}

fn try_eth(filter: &str) -> Result<pktbaffle::Program, pktbaffle::Error> {
    compile(filter, LinkType::Ethernet, Target::Classic)
}

// ── Syntax parity: host primitives ───────────────────────────────────────────
// pcap-filter(7): host, src host, dst host, src or dst host, src and dst host

#[test]
fn host_ipv4() {
    eth("host 192.168.1.1");
}

#[test]
fn src_host_ipv4() {
    eth("src host 10.0.0.1");
}

#[test]
fn dst_host_ipv4() {
    eth("dst host 172.16.0.1");
}

#[test]
fn src_or_dst_host() {
    eth("src or dst host 1.2.3.4");
}

#[test]
fn src_and_dst_host() {
    eth("src and dst host 1.2.3.4");
}

#[test]
fn host_ipv6() {
    eth("host 2001:db8::1");
}

#[test]
fn src_host_ipv6() {
    eth("src host ::1");
}

#[test]
fn dst_host_ipv6() {
    eth("dst host 2001:db8::ff");
}

// ── Syntax parity: network primitives ────────────────────────────────────────
// pcap-filter(7): net, src net, dst net, net mask

#[test]
fn net_cidr() {
    eth("net 10.0.0.0/8");
}

#[test]
fn net_mask_syntax() {
    eth("net 10.0.0.0 mask 255.0.0.0");
}

#[test]
fn src_net() {
    eth("src net 192.168.0.0/16");
}

#[test]
fn dst_net() {
    eth("dst net 10.0.0.0/8");
}

#[test]
fn src_net_mask() {
    eth("src net 192.168.0.0 mask 255.255.0.0");
}

#[test]
fn dst_net_ipv6() {
    eth("dst net 2001:db8::/32");
}

// ── Syntax parity: port primitives ───────────────────────────────────────────
// pcap-filter(7): port, src port, dst port, proto port, proto src/dst port

#[test]
fn port() {
    eth("port 80");
}

#[test]
fn src_port() {
    eth("src port 1024");
}

#[test]
fn dst_port() {
    eth("dst port 443");
}

#[test]
fn tcp_port() {
    eth("tcp port 80");
}

#[test]
fn udp_port() {
    eth("udp port 53");
}

#[test]
fn sctp_port() {
    eth("sctp port 9000");
}

#[test]
fn tcp_src_port() {
    eth("tcp src port 1024");
}

#[test]
fn tcp_dst_port() {
    eth("tcp dst port 443");
}

#[test]
fn udp_src_port() {
    eth("udp src port 5353");
}

#[test]
fn udp_dst_port() {
    eth("udp dst port 123");
}

// ── Syntax parity: portrange primitives ──────────────────────────────────────
// pcap-filter(7): portrange, src portrange, dst portrange, proto portrange

#[test]
fn portrange() {
    eth("portrange 1024-65535");
}

#[test]
fn src_portrange() {
    eth("src portrange 1024-65535");
}

#[test]
fn dst_portrange() {
    eth("dst portrange 1024-65535");
}

#[test]
fn tcp_portrange() {
    eth("tcp portrange 1024-65535");
}

#[test]
fn udp_portrange() {
    eth("udp portrange 1024-65535");
}

#[test]
fn tcp_src_portrange() {
    eth("src tcp portrange 1024-65535");
}

#[test]
fn tcp_dst_portrange() {
    eth("dst tcp portrange 1024-65535");
}

// ── Syntax parity: protocol keywords ─────────────────────────────────────────
// pcap-filter(7): ip, ip6, arp, rarp, tcp, udp, icmp, icmp6, ah, esp,
//                 pim, igrp, vrrp, igmp, sctp

#[test]
fn proto_ip() {
    eth("ip");
}

#[test]
fn proto_ip6() {
    eth("ip6");
}

#[test]
fn proto_arp() {
    eth("arp");
}

#[test]
fn proto_rarp() {
    eth("rarp");
}

#[test]
fn proto_tcp() {
    eth("tcp");
}

#[test]
fn proto_udp() {
    eth("udp");
}

#[test]
fn proto_icmp() {
    eth("icmp");
}

#[test]
fn proto_icmp6() {
    eth("icmp6");
}

#[test]
fn proto_ah() {
    eth("ah");
}

#[test]
fn proto_esp() {
    eth("esp");
}

#[test]
fn proto_pim() {
    eth("pim");
}

#[test]
fn proto_igrp() {
    eth("igrp");
}

#[test]
fn proto_vrrp() {
    eth("vrrp");
}

#[test]
fn proto_sctp() {
    eth("sctp");
}

// ── Syntax parity: ip proto / ip6 proto / ip6 protochain ─────────────────────
// pcap-filter(7): ip proto p, ip6 proto p, ip protochain p, ip6 protochain p

#[test]
fn ip_proto_number() {
    eth("ip proto 6");
}

#[test]
fn ip6_proto_number() {
    eth("ip6 proto 58");
}

#[test]
fn ip_protochain() {
    eth("ip protochain 6");
}

#[test]
fn ip6_protochain() {
    eth("ip6 protochain 58");
}

// ── Syntax parity: Ethernet primitives ───────────────────────────────────────
// pcap-filter(7): ether host, ether src, ether dst, ether broadcast,
//                 ether multicast, ether proto

#[test]
fn ether_host() {
    eth("ether host aa:bb:cc:dd:ee:ff");
}

#[test]
fn ether_src() {
    eth("ether src 11:22:33:44:55:66");
}

#[test]
fn ether_dst() {
    eth("ether dst aa:bb:cc:dd:ee:ff");
}

#[test]
fn ether_broadcast() {
    eth("ether broadcast");
}

#[test]
fn ether_multicast() {
    eth("ether multicast");
}

#[test]
fn ether_proto_numeric() {
    eth("ether proto 0x0800");
}

#[test]
fn ether_proto_ip_alias() {
    eth("ether proto ip");
}

#[test]
fn ether_proto_arp_alias() {
    eth("ether proto arp");
}

#[test]
fn ether_proto_ipv6_alias() {
    eth("ether proto ip6");
}

// ── Syntax parity: broadcast / multicast ─────────────────────────────────────
//
// Semantic gap vs libpcap:
//
//   libpcap `broadcast` = ether broadcast OR ip broadcast
//   pktbaffle `broadcast` = ether broadcast only (all-FF dst MAC)
//
//   libpcap `multicast` = ether multicast OR ip multicast OR ip6 multicast
//   pktbaffle `multicast` = ether multicast only (bit 0 of dst MAC byte 0)
//
// The Ethernet-layer check is correct; the IP/IPv6 layer checks are missing.
// Workarounds: use `ether broadcast or ip broadcast` and
// `ether multicast or ip multicast or ip6 multicast` explicitly.

#[test]
fn bare_broadcast() {
    eth("broadcast");
}

#[test]
fn bare_multicast() {
    eth("multicast");
}

#[test]
fn ip_broadcast() {
    eth("ip broadcast");
}

#[test]
fn ip_multicast() {
    eth("ip multicast");
}

#[test]
fn ip6_multicast() {
    eth("ip6 multicast");
}

// ── Syntax parity: packet length ─────────────────────────────────────────────
// pcap-filter(7): less, greater, len

#[test]
fn less() {
    eth("less 64");
}

#[test]
fn greater() {
    eth("greater 1500");
}

#[test]
fn len_eq() {
    eth("len = 60");
}

#[test]
fn len_ne() {
    eth("len != 60");
}

#[test]
fn len_lt() {
    eth("len < 64");
}

#[test]
fn len_le() {
    eth("len <= 64");
}

#[test]
fn len_gt() {
    eth("len > 1000");
}

#[test]
fn len_ge() {
    eth("len >= 1000");
}

// ── Syntax parity: VLAN / MPLS / PPPoE ───────────────────────────────────────

#[test]
fn vlan_any() {
    eth("vlan");
}

#[test]
fn vlan_with_id() {
    eth("vlan 100");
}

#[test]
fn mpls_any() {
    eth("mpls");
}

#[test]
fn mpls_with_label() {
    eth("mpls 12345");
}

#[test]
fn pppoed() {
    eth("pppoed");
}

#[test]
fn pppoes() {
    eth("pppoes");
}

#[test]
fn pppoes_with_id() {
    eth("pppoes 100");
}

// ── Syntax parity: packet data / byte access ──────────────────────────────────
// pcap-filter(7): expr relop expr, where expr can use proto[offset:size],
//                 named field constants (tcpflags, icmptype, etc.)

#[test]
fn byte_access_tcp_flags() {
    eth("tcp[13] & 0x02 != 0");
}

#[test]
fn byte_access_tcp_flags_named() {
    eth("tcp[tcpflags] & tcp-syn != 0");
}

#[test]
fn byte_access_tcp_flags_ack_name() {
    eth("tcp[tcpflags] & tcp-ack != 0");
}

#[test]
fn byte_access_tcp_flags_fin_name() {
    eth("tcp[tcpflags] & tcp-fin != 0");
}

#[test]
fn byte_access_tcp_flags_rst_name() {
    eth("tcp[tcpflags] & tcp-rst != 0");
}

#[test]
fn byte_access_tcp_flags_push_name() {
    eth("tcp[tcpflags] & tcp-push != 0");
}

#[test]
fn byte_access_tcp_flags_urg_name() {
    eth("tcp[tcpflags] & tcp-urg != 0");
}

#[test]
fn byte_access_ip_ttl() {
    eth("ip[8] = 64");
}

#[test]
fn byte_access_ip_fragment_offset() {
    eth("ip[6:2] & 0x1fff != 0");
}

#[test]
fn byte_access_icmp_type() {
    eth("icmp[icmptype] = icmp-echo");
}

#[test]
fn byte_access_icmp_named_echoreply() {
    eth("icmp[icmptype] = icmp-echoreply");
}

#[test]
fn byte_access_icmp_named_unreach() {
    eth("icmp[icmptype] = icmp-unreach");
}

#[test]
fn byte_access_icmp_named_redirect() {
    eth("icmp[icmptype] = icmp-redirect");
}

#[test]
fn byte_access_with_size() {
    eth("tcp[0:2] = 80");
}

#[test]
fn byte_access_alu_expression() {
    eth("ip[8]-1 < 64");
}

// ── Syntax parity: logical operators ─────────────────────────────────────────

#[test]
fn logical_and_explicit() {
    eth("tcp and port 80");
}

#[test]
fn logical_and_implicit() {
    eth("tcp port 80");
}

#[test]
fn logical_or() {
    eth("tcp or udp");
}

#[test]
fn logical_not() {
    eth("not arp");
}

#[test]
fn logical_not_bang() {
    eth("!arp");
}

#[test]
fn logical_complex() {
    eth("(port 80 or port 443) and tcp and host 1.2.3.4");
}

// ── Syntax parity: link types ─────────────────────────────────────────────────

#[test]
fn rawip_host() {
    compile("host 10.0.0.1", LinkType::RawIp, Target::Classic).unwrap();
}

#[test]
fn rawip_tcp_port() {
    compile("tcp port 443", LinkType::RawIp, Target::Classic).unwrap();
}

#[test]
fn linuxsll_host() {
    compile("host 10.0.0.1", LinkType::LinuxSll, Target::Classic).unwrap();
}

#[test]
fn linuxsll_tcp_port() {
    compile("tcp port 443", LinkType::LinuxSll, Target::Classic).unwrap();
}

// ── Unsupported features: must return Err, never panic ───────────────────────

#[test]
fn gateway_returns_error() {
    assert!(
        try_eth("gateway foo").is_err(),
        "`gateway` must return an error (requires ARP table lookup)"
    );
}

#[test]
fn inbound_returns_error() {
    assert!(
        try_eth("inbound").is_err(),
        "`inbound` must return an error (requires kernel direction context)"
    );
}

#[test]
fn outbound_returns_error() {
    assert!(
        try_eth("outbound").is_err(),
        "`outbound` must return an error (requires kernel direction context)"
    );
}

// ── Optimization budgets ─────────────────────────────────────────────────────
//
// Upper bounds on instruction counts for common filter patterns.
// These are intentionally loose (headroom above current output) so that minor
// refactors don't break them, while still catching pathological regressions.
//
// Reference counts (Ethernet link type, Classic BPF target, as of 2026-06):
//   tcp             →  6 insns  (budget: 10)
//   udp             →  6 insns  (budget: 10)
//   host addr       →  8 insns  (budget: 14)
//   src host addr   →  6 insns  (budget: 10)
//   net addr/prefix → 10 insns  (budget: 16)
//   tcp port N      → 18 insns  (budget: 24)
//   port N          → 20 insns  (budget: 26)
//   tcp and port N  → 13 insns  (budget: 18)
//   ip multicast    →  7 insns  (budget: 12)
//   ether broadcast →  6 insns  (budget: 10)
//   vlan            →  4 insns  (budget:  8)
//   less N          →  4 insns  (budget:  8)
//   greater N       →  4 insns  (budget:  8)
//
// Note: pktbaffle emits dual IPv4+IPv6 paths for transport-layer filters,
// which is why counts are higher than single-protocol libpcap output on
// systems where libpcap omits the IPv6 path.

mod optimization_budgets {
    use pktbaffle::{compile, LinkType, Target};

    fn insn_count(filter: &str) -> usize {
        compile(filter, LinkType::Ethernet, Target::Classic)
            .unwrap_or_else(|e| panic!("compile({filter:?}): {e}"))
            .len()
    }

    #[test]
    fn tcp_budget() {
        assert!(
            insn_count("tcp") <= 10,
            "`tcp` must compile to ≤ 10 instructions (got {})",
            insn_count("tcp")
        );
    }

    #[test]
    fn udp_budget() {
        assert!(insn_count("udp") <= 10);
    }

    #[test]
    fn host_ipv4_budget() {
        assert!(insn_count("host 192.168.1.1") <= 14);
    }

    #[test]
    fn src_host_ipv4_budget() {
        assert!(insn_count("src host 192.168.1.1") <= 10);
    }

    #[test]
    fn net_ipv4_budget() {
        assert!(insn_count("net 192.168.0.0/16") <= 16);
    }

    #[test]
    fn tcp_port_budget() {
        assert!(insn_count("tcp port 80") <= 24);
    }

    #[test]
    fn port_budget() {
        assert!(insn_count("port 80") <= 26);
    }

    #[test]
    fn tcp_and_port_budget() {
        assert!(insn_count("tcp and port 80") <= 18);
    }

    #[test]
    fn ip_multicast_budget() {
        assert!(insn_count("ip multicast") <= 12);
    }

    #[test]
    fn ether_broadcast_budget() {
        assert!(insn_count("ether broadcast") <= 10);
    }

    #[test]
    fn vlan_budget() {
        assert!(insn_count("vlan") <= 8);
    }

    #[test]
    fn less_budget() {
        assert!(insn_count("less 64") <= 8);
    }

    #[test]
    fn greater_budget() {
        assert!(insn_count("greater 1500") <= 8);
    }

    // Combination patterns that exercise guard-hoisting and dedup.
    #[test]
    fn host_and_tcp_port_budget() {
        // Guard-hoisting should keep this well below 2× single-filter cost.
        assert!(insn_count("host 1.2.3.4 and tcp port 80") <= 28);
    }

    #[test]
    fn tcp_or_udp_budget() {
        assert!(insn_count("tcp or udp") <= 14);
    }
}
