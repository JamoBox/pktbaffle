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

#[test]
fn byte_access_offset_arithmetic_accepted() {
    // libpcap 1.10.3 accepts constant arithmetic inside `[...]`.
    eth("ip[1<<3] = 0");
    eth("ip[8/2] = 0");
    eth("ip[-4/-2+2] = 0");
}

#[test]
fn byte_access_offset_nested_parens_and_unary_minus_accepted() {
    // libpcap 1.10.3 compiles `ip[` + 3000 x "(" + "1" + 3000 x ")" + `] = 0`.
    // pktbaffle bounds offset nesting well below that (#135, see
    // `OFFSET_PAREN_COST` in the parser) and returns Err past the limit rather
    // than overflowing the stack; moderate nesting is accepted.
    eth("ip[((1))] = 0");
    eth(&format!("ip[{}1{}] = 0", "(".repeat(20), ")".repeat(20)));
    eth(&format!("ip[{}1] = 0", "-".repeat(20)));
    eth(&format!("ip[{}1{}] = 0", "-(".repeat(20), ")".repeat(20)));
}

#[test]
fn byte_access_offset_shift_overflow_rejected() {
    // libpcap 1.10.3 rejects both at pcap_compile() time with
    // "shift by more than 31 bits" (#134).  pktbaffle must return Err, not
    // panic or silently compile `ip[1<<63]` as `ip[0]`.
    assert!(try_eth("ip[1<<63] = 0").is_err());
    assert!(try_eth("ip[(1<<63)/-1] = 0").is_err());
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

/// Unparenthesised `or` followed by `and` is accepted by libpcap 1.10.3 (it
/// parses as `(a or b) and c`); the verdicts are checked in `vm_parity.rs`.
#[test]
fn logical_or_then_and_unparenthesised() {
    eth("port 22 or port 80 and host 10.0.0.1");
    eth("tcp or udp and host 10.0.0.1");
}

/// libpcap 1.10.3 accepts 9995 nested parentheses around `tcp` and rejects
/// 9996 ("memory exhausted"); results recorded in #199.
#[test]
fn nested_parens_accepted_up_to_libpcap_limit() {
    let parens = |n: usize| format!("{}tcp{}", "(".repeat(n), ")".repeat(n));
    eth(&parens(128));
    eth(&parens(1000));
    eth(&parens(9995));
    assert!(try_eth(&parens(9996)).is_err());
}

/// libpcap 1.10.3 compiles long flat chains (#149, #202 report a 15000-term
/// `tcp or ...`); that a 32000-term `tcp and ...` and a 256000-deep `!` chain
/// are accepted is hand-derived, not re-run here. pktbaffle compiles both in
/// linear time (#202).
#[test]
fn long_and_and_not_chains_accepted() {
    eth(&vec!["tcp"; 32_000].join(" and "));
    eth(&format!("{}tcp", "!".repeat(256_000)));
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

// ── Integer literals: C syntax (#157) ────────────────────────────────────────
// libpcap 1.10.3's scanner: `0x` hex, leading `0` octal, `08` rejected.
// Hand-derived from scanner.l and issue #157 (no live libpcap was available).

#[test]
fn leading_zero_integer_literals_accepted() {
    for f in [
        "tcp port 010",
        "port 00",
        "ip proto 017",
        "ether proto 0100",
        "vlan 010",
        "len = 0100",
        "ip[010] = 1",
        "net 10.0.0.0/010",
        "net 10.0.0.0/0x8",
    ] {
        eth(f);
    }
}

#[test]
fn non_octal_integer_literals_rejected() {
    for f in [
        "tcp port 08",
        "tcp port 09",
        "ether proto 0800",
        "vlan 08",
        "less 08",
        "ip[08] = 1",
        "net 10.0.0.0/08",
    ] {
        assert!(try_eth(f).is_err(), "{f:?} must be rejected");
    }
}

// ── Zero-padded octets in dotted IPv4 literals (#191) ────────────────────────
// libpcap 1.10.3 reads each octet as decimal. Hand-derived from issue #191.

#[test]
fn zero_padded_dotted_octets_accepted_on_both_targets() {
    for f in [
        "host 010.1.2.3",
        "host 1.2.3.04",
        "host 192.168.001.001",
        "host 00.0.0.1",
        "net 010.0.0.0/8",
        "net 10.0.0.0 mask 255.255.255.000",
    ] {
        eth(f);
        compile(f, LinkType::Ethernet, Target::Extended)
            .unwrap_or_else(|e| panic!("compile({f:?}, Extended) failed: {e}"));
    }
}

#[test]
fn bad_dotted_octets_rejected() {
    for f in ["host 10.256.0.1", "host 0x0a.0.0.1", "host 1.2.3.4.5"] {
        assert!(try_eth(f).is_err(), "{f:?} must be rejected");
    }
}

// ── `/` before a prefix length is an ordinary token (#194, #173) ─────────────
// libpcap 1.10.3 accepts these (verified against it in issues #194 and #173)
// and rejects a bare number after an address.

#[test]
fn net_prefix_spelling_accepted() {
    for f in [
        "net 10.0.0.0 / 8",
        "net 10.0.0.0/ 8",
        "net 10.0.0.0/0x8",
        "net 2001:db8:: /32",
        "net 2001:db8::/0x20",
        "net ::/0",
        "net ::1/128",
        "net ::ffff:0:0/96",
        "ip6 net ::/32",
        "src net ::1/128",
        "net ::/0 and tcp",
        "host ::1/128",
    ] {
        eth(f);
        compile(f, LinkType::Ethernet, Target::Extended)
            .unwrap_or_else(|e| panic!("compile({f:?}, Extended) failed: {e}"));
    }
}

#[test]
fn net_prefix_syntax_errors_rejected() {
    for f in [
        "net 10.0.0.0 8",
        "net 10 8",
        "net 2001:db8:: 32",
        "net 10 mask 255.0.0.0",
        "net ::/129",
    ] {
        assert!(try_eth(f).is_err(), "{f:?} must be rejected");
    }
}

// ── A bare integer is an IPv4 host or net (#190) ─────────────────────────────
// libpcap 1.10.3 accepts a plain integer wherever an IPv4 address is expected
// (issue #190); the 32-bit limit applies.

#[test]
fn bare_integer_host_and_net_accepted() {
    for f in [
        "host 10",
        "src host 10",
        "dst host 10",
        "ip host 10",
        "host 0x0a000001",
        "src 10",
        "net 256",
        "net 300",
        "net 65536",
        "net 16777216",
        "net 0",
    ] {
        eth(f);
        compile(f, LinkType::Ethernet, Target::Extended)
            .unwrap_or_else(|e| panic!("compile({f:?}, Extended) failed: {e}"));
    }
}

#[test]
fn bare_integer_over_32_bits_rejected() {
    for f in ["host 4294967296", "net 4294967296"] {
        assert!(try_eth(f).is_err(), "{f:?} must be rejected");
    }
}
