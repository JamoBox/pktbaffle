//! Tests for the guard-eliding codegen and post-resolution peephole passes.
//!
//! Two sections:
//! - Shape pins: compound filters must compile to the compact, libpcap-style
//!   layouts (no re-checked guards, no `ja` trampolines on hot paths).
//! - VM semantics (behind the `vm` feature): the optimizations must not
//!   change which packets match, including the corner cases they are most
//!   likely to break — guard elision across AND, guard hoisting in front of
//!   OR, and invalidation of the cached transport offset when X is
//!   clobbered between OR arms.

use pktbaffle::bpf::Insn;
use pktbaffle::{compile, LinkType, Target};

const LDH_ABS: u16 = 0x28;
const LDB_ABS: u16 = 0x30;
const LDH_IND: u16 = 0x48;
const LDX_MSH: u16 = 0xb1;
const JA: u16 = 0x05;
const JEQ_K: u16 = 0x15;
const JSET_K: u16 = 0x45;
const RET_K: u16 = 0x06;
const ACCEPT: u32 = 0xffff_ffff;
const DROP: u32 = 0;

fn insn(code: u16, jt: u8, jf: u8, k: u32) -> Insn {
    Insn { code, jt, jf, k }
}

fn eth(filter: &str) -> Vec<Insn> {
    compile(filter, LinkType::Ethernet, Target::Classic)
        .unwrap_or_else(|e| panic!("compile({filter:?}): {e}"))
        .instructions()
        .to_vec()
}

// ─────────────────────────────────────────────────────────────────────────────
// Shape pins
// ─────────────────────────────────────────────────────────────────────────────

/// `tcp and port 80` must be the canonical 13-instruction libpcap layout:
/// the port prologue reuses the ethertype and protocol checks already made
/// by `tcp` instead of re-emitting them with a dead IPv6 path.
#[test]
fn tcp_and_port_80_is_canonical_13_instructions() {
    let prog = eth("tcp and port 80");
    assert_eq!(
        prog,
        vec![
            insn(LDH_ABS, 0, 0, 12),    // ethertype
            insn(JEQ_K, 0, 10, 0x0800), // not IPv4 → DROP
            insn(LDB_ABS, 0, 0, 23),    // IPv4 protocol
            insn(JEQ_K, 0, 8, 6),       // not TCP → DROP
            insn(LDH_ABS, 0, 0, 20),    // flags + fragment offset
            insn(JSET_K, 6, 0, 0x1fff), // non-first fragment → DROP
            insn(LDX_MSH, 0, 0, 14),    // X = IHL*4
            insn(LDH_IND, 0, 0, 14),    // src port
            insn(JEQ_K, 2, 0, 80),      // match → ACCEPT
            insn(LDH_IND, 0, 0, 16),    // dst port
            insn(JEQ_K, 0, 1, 80),      // match → ACCEPT, else DROP
            insn(RET_K, 0, 0, ACCEPT),
            insn(RET_K, 0, 0, DROP),
        ]
    );
}

/// `tcp or udp` must share the hoisted ethertype guard and load the
/// protocol byte once; jump threading removes the OR trampoline.
#[test]
fn tcp_or_udp_is_canonical_7_instructions() {
    let prog = eth("tcp or udp");
    assert_eq!(
        prog,
        vec![
            insn(LDH_ABS, 0, 0, 12),
            insn(JEQ_K, 0, 4, 0x0800), // not IPv4 → DROP (required by both arms)
            insn(LDB_ABS, 0, 0, 23),
            insn(JEQ_K, 1, 0, 6),  // TCP → ACCEPT
            insn(JEQ_K, 0, 1, 17), // UDP → ACCEPT, else DROP
            insn(RET_K, 0, 0, ACCEPT),
            insn(RET_K, 0, 0, DROP),
        ]
    );
}

/// `not tcp` is `tcp` with accept and drop swapped — the NOT trampoline is
/// threaded away entirely.
#[test]
fn not_tcp_is_tcp_with_swapped_targets() {
    let prog = eth("not tcp");
    assert_eq!(
        prog,
        vec![
            insn(LDH_ABS, 0, 0, 12),
            insn(JEQ_K, 0, 2, 0x0800), // not IPv4 → ACCEPT
            insn(LDB_ABS, 0, 0, 23),
            insn(JEQ_K, 1, 0, 6), // TCP → DROP
            insn(RET_K, 0, 0, ACCEPT),
            insn(RET_K, 0, 0, DROP),
        ]
    );
}

/// A conjunct that only restates established facts adds no instructions.
#[test]
fn redundant_conjuncts_are_free() {
    assert_eq!(eth("ip and tcp"), eth("tcp"), "'ip and tcp' ≡ 'tcp'");
    assert_eq!(eth("tcp and tcp"), eth("tcp"), "'tcp and tcp' ≡ 'tcp'");
    assert_eq!(
        eth("ip6 and icmp6"),
        eth("icmp6"),
        "'ip6 and icmp6' ≡ 'icmp6'"
    );
    assert_eq!(
        eth("ip and host 1.2.3.4"),
        eth("host 1.2.3.4"),
        "'ip and host' ≡ 'host'"
    );
}

/// OR arms that all need the port prologue share a single hoisted copy:
/// exactly one MSH and one ethertype load in the whole program.
#[test]
fn or_of_ports_shares_one_prologue() {
    for filter in ["port 80 or port 443", "tcp port 80 or tcp port 443"] {
        let prog = eth(filter);
        let msh_count = prog.iter().filter(|i| i.code == LDX_MSH).count();
        assert_eq!(msh_count, 1, "{filter:?}: expected exactly one MSH");
        let eth_loads = prog
            .iter()
            .filter(|i| i.code == LDH_ABS && i.k == 12)
            .count();
        assert_eq!(
            eth_loads, 1,
            "{filter:?}: expected exactly one ethertype load"
        );
    }
}

/// `tcp and (port 80 or port 443)` runs every guard once and then only the
/// four port comparisons.
#[test]
fn tcp_and_port_or_port_is_17_instructions() {
    let prog = eth("tcp and (port 80 or port 443)");
    assert_eq!(prog.len(), 17);
    // One guard each: ethertype, protocol, fragment, MSH.
    assert_eq!(prog.iter().filter(|i| i.code == LDX_MSH).count(), 1);
    assert_eq!(prog.iter().filter(|i| i.code == JSET_K).count(), 1);
    assert_eq!(
        prog.iter()
            .filter(|i| i.code == LDH_ABS && i.k == 12)
            .count(),
        1
    );
    // Four port comparisons: src/dst × 80/443.
    assert_eq!(
        prog.iter().filter(|i| i.code == LDH_IND).count(),
        4,
        "expected four indirect port loads"
    );
}

/// Hot paths carry no `ja` trampolines after jump threading.
#[test]
fn no_ja_trampolines_in_simple_compounds() {
    for filter in [
        "tcp or udp",
        "not tcp",
        "tcp and port 80",
        "not (tcp and port 80)",
    ] {
        let prog = eth(filter);
        assert!(
            prog.iter().all(|i| i.code != JA),
            "{filter:?} should need no ja after threading: {prog:?}"
        );
    }
}

/// On RawIp, `ip` is vacuously true and compiles to a bare accept.
#[test]
fn rawip_ip_compiles_to_single_accept() {
    let prog = compile("ip", LinkType::RawIp, Target::Classic)
        .unwrap()
        .instructions()
        .to_vec();
    assert_eq!(prog, vec![insn(RET_K, 0, 0, ACCEPT)]);
}

/// The fragment guard and MSH stay present when the prologue is elided into
/// an AND chain — only the duplicated checks disappear.
#[test]
fn elided_prologue_keeps_fragment_guard_and_msh() {
    for filter in ["tcp and port 80", "tcp and portrange 1000-2000"] {
        let prog = eth(filter);
        assert!(
            prog.iter().any(|i| i.code == JSET_K && i.k == 0x1fff),
            "{filter:?} must keep the fragment guard"
        );
        assert!(
            prog.iter().any(|i| i.code == LDX_MSH),
            "{filter:?} must keep the MSH load"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VM semantics
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(feature = "vm")]
mod semantics {
    use super::*;

    fn matches(filter: &str, pkt: &[u8]) -> bool {
        matches_on(filter, LinkType::Ethernet, pkt)
    }

    fn matches_on(filter: &str, link: LinkType, pkt: &[u8]) -> bool {
        let prog = compile(filter, link, Target::Classic)
            .unwrap_or_else(|e| panic!("compile({filter:?}): {e}"));
        prog.as_classic().unwrap().matches(pkt)
    }

    // ── packet builders ──────────────────────────────────────────────────────

    /// Ethernet + IPv4 (with `opt_words` option words) + 8 bytes of L4 header
    /// carrying src/dst ports, then 4 payload bytes.
    fn v4(proto: u8, sport: u16, dport: u16, frag: u16, opt_words: u8) -> Vec<u8> {
        let mut p = vec![0u8; 12];
        p.extend_from_slice(&0x0800u16.to_be_bytes());
        let ihl = 5 + opt_words;
        p.push(0x40 | ihl); // version 4 + IHL
        p.push(0);
        let total = 20 + opt_words as u16 * 4 + 12;
        p.extend_from_slice(&total.to_be_bytes());
        p.extend_from_slice(&[0, 0]); // id
        p.extend_from_slice(&frag.to_be_bytes()); // flags + fragment offset
        p.push(64); // TTL
        p.push(proto);
        p.extend_from_slice(&[0, 0]); // checksum
        p.extend_from_slice(&[10, 0, 0, 1]); // src IP
        p.extend_from_slice(&[10, 0, 0, 2]); // dst IP
        p.resize(p.len() + opt_words as usize * 4, 0);
        p.extend_from_slice(&sport.to_be_bytes());
        p.extend_from_slice(&dport.to_be_bytes());
        p.extend_from_slice(&[0, 0, 0, 1]); // seq / rest of L4 header
        p.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        p
    }

    /// Ethernet + IPv6 + 8 bytes of L4 header carrying src/dst ports.
    fn v6(nh: u8, sport: u16, dport: u16) -> Vec<u8> {
        let mut p = vec![0u8; 12];
        p.extend_from_slice(&0x86ddu16.to_be_bytes());
        p.push(0x60); // version 6
        p.extend_from_slice(&[0, 0, 0]); // traffic class + flow label
        p.extend_from_slice(&12u16.to_be_bytes()); // payload length
        p.push(nh);
        p.push(64); // hop limit
        p.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        p.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        p.extend_from_slice(&sport.to_be_bytes());
        p.extend_from_slice(&dport.to_be_bytes());
        p.extend_from_slice(&[0, 0, 0, 1]);
        p.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        p
    }

    fn tcp4(sport: u16, dport: u16) -> Vec<u8> {
        v4(6, sport, dport, 0, 0)
    }
    fn udp4(sport: u16, dport: u16) -> Vec<u8> {
        v4(17, sport, dport, 0, 0)
    }
    fn tcp6(sport: u16, dport: u16) -> Vec<u8> {
        v6(6, sport, dport)
    }

    fn arp() -> Vec<u8> {
        let mut p = vec![0u8; 12];
        p.extend_from_slice(&0x0806u16.to_be_bytes());
        p.resize(p.len() + 28, 0);
        p
    }

    // ── guard elision across AND ─────────────────────────────────────────────

    #[test]
    fn tcp_and_port_80_semantics() {
        assert!(matches("tcp and port 80", &tcp4(80, 12345)));
        assert!(matches("tcp and port 80", &tcp4(12345, 80)));
        assert!(!matches("tcp and port 80", &tcp4(81, 12345)));
        assert!(!matches("tcp and port 80", &udp4(80, 12345)));
        // `tcp` pins IPv4, so IPv6 TCP:80 must not match even though a bare
        // `port 80` would accept it.
        assert!(!matches("tcp and port 80", &tcp6(80, 12345)));
        // Non-first fragment: the elided prologue must keep the frag guard.
        assert!(!matches("tcp and port 80", &v4(6, 80, 443, 0x0005, 0)));
        // IP options: MSH must still locate the transport header.
        assert!(matches("tcp and port 80", &v4(6, 80, 443, 0, 2)));
        assert!(!matches("tcp and port 80", &v4(6, 90, 443, 0, 2)));
    }

    #[test]
    fn chained_port_filters_reuse_one_prologue() {
        let f = "src port 80 and dst port 443";
        assert!(matches(f, &tcp4(80, 443)));
        assert!(matches(f, &udp4(80, 443)));
        assert!(!matches(f, &tcp4(443, 80)));
        assert!(!matches(f, &tcp4(80, 80)));
    }

    #[test]
    fn port_then_proto_qualified_port_narrows() {
        // The second primitive needs a narrower protocol set than the
        // established prologue provides and must re-check.
        let f = "port 80 and tcp port 80";
        assert!(matches(f, &tcp4(80, 1)));
        assert!(!matches(f, &udp4(80, 1)));
    }

    #[test]
    fn tcp_and_not_port_22_semantics() {
        assert!(matches("tcp and not port 22", &tcp4(80, 443)));
        assert!(!matches("tcp and not port 22", &tcp4(22, 443)));
        assert!(!matches("tcp and not port 22", &tcp4(443, 22)));
        assert!(!matches("tcp and not port 22", &udp4(80, 443)));
    }

    // ── guard hoisting in front of OR ────────────────────────────────────────

    #[test]
    fn or_of_ports_semantics() {
        let f = "port 80 or port 443";
        assert!(matches(f, &tcp4(80, 1)));
        assert!(matches(f, &tcp4(1, 443)));
        assert!(matches(f, &udp4(443, 1)));
        // The hoisted prologue must keep the IPv6 path alive.
        assert!(matches(f, &tcp6(1, 443)));
        assert!(!matches(f, &tcp4(1, 2)));
        assert!(!matches(f, &v4(1, 80, 443, 0, 0))); // ICMP has no ports
        assert!(!matches(f, &arp()));
    }

    #[test]
    fn or_of_protos_semantics() {
        let f = "tcp or udp";
        assert!(matches(f, &tcp4(1, 2)));
        assert!(matches(f, &udp4(1, 2)));
        assert!(!matches(f, &v4(1, 0, 0, 0, 0))); // ICMP
        assert!(!matches(f, &arp()));
        // `tcp`/`udp` are IPv4 checks in this dialect; the hoisted guard
        // must not change that.
        assert!(!matches(f, &tcp6(1, 2)));
    }

    #[test]
    fn or_of_proto_port_conjunctions_semantics() {
        let f = "(tcp and port 80) or (udp and port 53)";
        assert!(matches(f, &tcp4(80, 1)));
        assert!(matches(f, &udp4(1, 53)));
        assert!(!matches(f, &tcp4(53, 1)));
        assert!(!matches(f, &udp4(80, 1)));
        assert!(!matches(f, &tcp6(80, 1)));
    }

    #[test]
    fn or_of_hosts_semantics() {
        let f = "host 10.0.0.1 or host 10.0.0.2 or host 10.0.0.9";
        assert!(matches(f, &tcp4(1, 2))); // src 10.0.0.1, dst 10.0.0.2
        let mut other = tcp4(1, 2);
        other[26..30].copy_from_slice(&[10, 0, 0, 7]); // src
        other[30..34].copy_from_slice(&[10, 0, 0, 8]); // dst
        assert!(!matches(f, &other));
        other[30..34].copy_from_slice(&[10, 0, 0, 9]);
        assert!(matches(f, &other));
    }

    // ── X-clobber invalidation between OR arms ──────────────────────────────

    /// The left arm's transport byte-access clobbers X after the hoisted
    /// prologue; the right arm must re-establish the transport offset rather
    /// than trust the stale X. On IPv6 a stale X is observable: MSH applied
    /// to the IPv6 header yields a wrong offset.
    #[test]
    fn x_clobber_between_or_arms_is_reestablished() {
        let f = "(port 80 and tcp[0] = tcp[4]) or port 443";
        // IPv6 TCP src 80 → enters the left arm, whose byte access mangles
        // X (MSH applied to the IPv6 header); tcp[0] ≠ tcp[4] fails the arm;
        // the right arm must still match dst port 443 at the proper IPv6
        // transport offset. With a stale X the load lands far outside the
        // transport header.
        assert!(matches(f, &tcp6(80, 443)));
        // Same packet but dst 444: the right arm must fail.
        assert!(!matches(f, &tcp6(80, 444)));
        // IPv4: force tcp[0] (0x00, sport high byte) ≠ tcp[4] so the left
        // arm fails after clobbering X.
        let mut hit = tcp4(80, 443);
        hit[14 + 20 + 4] = 7;
        assert!(matches(f, &hit));
        let mut miss = tcp4(80, 444);
        miss[14 + 20 + 4] = 7;
        assert!(!matches(f, &miss));
        // When the byte equality holds, the left arm accepts on its own.
        assert!(matches(f, &tcp4(80, 444)));
    }

    // ── NOT around compounds ─────────────────────────────────────────────────

    #[test]
    fn not_of_conjunction_semantics() {
        let f = "not (tcp and port 80)";
        assert!(!matches(f, &tcp4(80, 1)));
        assert!(!matches(f, &tcp4(1, 80)));
        assert!(matches(f, &tcp4(1, 2)));
        assert!(matches(f, &udp4(80, 1)));
        assert!(matches(f, &arp()));
    }

    // ── contradictory chains keep their (never-matching) semantics ─────────

    #[test]
    fn vlan_then_ip_still_never_matches_plain_frames() {
        // This dialect does not shift offsets after `vlan`, so `vlan and ip`
        // cannot match: a plain IPv4 frame fails the vlan check and a tagged
        // frame fails the ip check. The optimizer must preserve that, not
        // "fix" it.
        let f = "vlan and ip and tcp port 80";
        assert!(!matches(f, &tcp4(80, 1)));
        let mut tagged = tcp4(80, 1);
        tagged[12..14].copy_from_slice(&0x8100u16.to_be_bytes());
        assert!(!matches(f, &tagged));
    }

    // ── other link types ─────────────────────────────────────────────────────

    #[test]
    fn rawip_elision_semantics() {
        let f = "tcp and port 80";
        // Strip the 14-byte Ethernet header for RawIp.
        assert!(matches_on(f, LinkType::RawIp, &tcp4(80, 1)[14..]));
        assert!(!matches_on(f, LinkType::RawIp, &udp4(80, 1)[14..]));
        assert!(!matches_on(f, LinkType::RawIp, &tcp4(81, 82)[14..]));
        assert!(matches_on("ip", LinkType::RawIp, &tcp4(1, 2)[14..]));
    }

    // ── compositional equivalence ────────────────────────────────────────────

    /// For every pair of primitives and every corpus packet, the compiled
    /// compound must agree with the boolean combination of the individually
    /// compiled primitives. This cross-checks guard elision and hoisting:
    /// each primitive compiled alone carries no inherited facts, so any
    /// unsound elision in the compound shows up as a mismatch.
    ///
    /// Packets are sized so no in-pool primitive performs an out-of-bounds
    /// load on them; an OOB aborts the whole program rather than just one
    /// arm, which would make the OR comparison invalid.
    #[test]
    fn compositional_semantics_against_primitive_pool() {
        let pool = [
            "tcp",
            "udp",
            "icmp",
            "ip",
            "ip6",
            "arp",
            "host 10.0.0.1",
            "src host 10.0.0.2",
            "host 2001:db8::1",
            "net 10.0.0.0/8",
            "net fc00::/7",
            "port 80",
            "src port 80",
            "dst port 443",
            "portrange 53-100",
            "tcp port 80",
            "udp port 53",
            "sctp port 9899",
            "ether host aa:bb:cc:dd:ee:ff",
            "ether multicast",
            "vlan",
            "vlan 100",
            "mpls",
            "pppoes",
            "ip multicast",
            "ip broadcast",
            "ip6 multicast",
            "icmp6",
            "proto 47",
            "ip6 proto 58",
            "len > 50",
            "tcp[13] & 0x02 != 0",
        ];

        let mut corpus: Vec<Vec<u8>> = vec![
            tcp4(80, 443),
            tcp4(443, 80),
            tcp4(22, 23),
            udp4(53, 1024),
            udp4(80, 53),
            v4(1, 0, 0, 0, 0),         // ICMP
            v4(47, 0, 0, 0, 0),        // GRE
            v4(6, 80, 443, 0x0005, 0), // non-first fragment
            v4(6, 80, 443, 0, 2),      // IP options
            tcp6(80, 443),
            tcp6(1, 2),
            v6(17, 53, 80),
            v6(58, 0, 0), // ICMPv6
            arp(),
        ];
        // Multicast / broadcast variants.
        let mut mcast = tcp4(1, 2);
        mcast[0] = 0x01;
        mcast[30..34].copy_from_slice(&[224, 0, 0, 1]);
        corpus.push(mcast);
        let mut bcast = udp4(67, 68);
        bcast[30..34].copy_from_slice(&[255, 255, 255, 255]);
        corpus.push(bcast);
        // Pad everything so no pool primitive loads out of bounds.
        for pkt in &mut corpus {
            while pkt.len() < 64 {
                pkt.push(0);
            }
        }

        let progs: Vec<_> = pool
            .iter()
            .map(|f| {
                compile(f, LinkType::Ethernet, Target::Classic)
                    .unwrap_or_else(|e| panic!("compile({f:?}): {e}"))
            })
            .collect();
        let truth: Vec<Vec<bool>> = progs
            .iter()
            .map(|p| {
                corpus
                    .iter()
                    .map(|pkt| p.as_classic().unwrap().matches(pkt))
                    .collect()
            })
            .collect();

        for (i, a) in pool.iter().enumerate() {
            for (j, b) in pool.iter().enumerate() {
                for (expr, expect) in [
                    (
                        format!("{a} and {b}"),
                        (0..corpus.len())
                            .map(|k| truth[i][k] && truth[j][k])
                            .collect::<Vec<_>>(),
                    ),
                    (
                        format!("{a} or {b}"),
                        (0..corpus.len())
                            .map(|k| truth[i][k] || truth[j][k])
                            .collect(),
                    ),
                    (
                        format!("{a} and not {b}"),
                        (0..corpus.len())
                            .map(|k| truth[i][k] && !truth[j][k])
                            .collect(),
                    ),
                    (
                        format!("not ({a} or {b})"),
                        (0..corpus.len())
                            .map(|k| !(truth[i][k] || truth[j][k]))
                            .collect(),
                    ),
                ] {
                    let prog = compile(&expr, LinkType::Ethernet, Target::Classic)
                        .unwrap_or_else(|e| panic!("compile({expr:?}): {e}"));
                    let prog = prog.as_classic().unwrap();
                    for (k, pkt) in corpus.iter().enumerate() {
                        assert_eq!(
                            prog.matches(pkt),
                            expect[k],
                            "{expr:?} disagrees with composed primitives on packet #{k}"
                        );
                    }
                }
            }
        }
    }

    /// Same property for a sample of three-way nestings, exercising facts
    /// across deeper AND/OR/NOT structure.
    #[test]
    fn compositional_semantics_three_way() {
        let triples = [
            ("ip", "tcp", "port 80"),
            ("tcp", "port 80", "port 443"),
            ("ip6", "icmp6", "len > 50"),
            ("vlan", "ip", "tcp port 80"),
            ("port 80", "tcp port 80", "udp"),
            ("host 10.0.0.1", "tcp", "dst port 443"),
            ("net 10.0.0.0/8", "udp port 53", "ip multicast"),
            ("tcp[13] & 0x02 != 0", "port 80", "icmp"),
        ];
        let corpus: Vec<Vec<u8>> = vec![
            tcp4(80, 443),
            tcp4(443, 80),
            udp4(53, 80),
            v4(1, 0, 0, 0, 0),
            tcp6(80, 443),
            v6(58, 0, 0),
            arp(),
        ]
        .into_iter()
        .map(|mut p| {
            while p.len() < 64 {
                p.push(0);
            }
            p
        })
        .collect();

        let run = |f: &str, pkt: &[u8]| -> bool {
            compile(f, LinkType::Ethernet, Target::Classic)
                .unwrap_or_else(|e| panic!("compile({f:?}): {e}"))
                .as_classic()
                .unwrap()
                .matches(pkt)
        };

        for (a, b, c) in triples {
            for pkt in &corpus {
                let (ta, tb, tc) = (run(a, pkt), run(b, pkt), run(c, pkt));
                for (expr, want) in [
                    (format!("{a} and {b} and {c}"), ta && tb && tc),
                    (format!("{a} and ({b} or {c})"), ta && (tb || tc)),
                    (format!("({a} and {b}) or {c}"), (ta && tb) || tc),
                    (format!("{a} or ({b} and {c})"), ta || (tb && tc)),
                    (format!("{a} and not ({b} or {c})"), ta && !(tb || tc)),
                    (format!("not ({a} and {b}) and {c}"), !(ta && tb) && tc),
                ] {
                    assert_eq!(
                        run(&expr, pkt),
                        want,
                        "{expr:?} disagrees with composed primitives"
                    );
                }
            }
        }
    }

    #[test]
    fn linux_sll_elision_semantics() {
        // SLL: 16-byte pseudo-header, protocol field at offset 14.
        let f = "tcp and port 80";
        let mut pkt = vec![0u8; 14];
        pkt.extend_from_slice(&0x0800u16.to_be_bytes());
        pkt.extend_from_slice(&tcp4(80, 1)[14..]);
        assert!(matches_on(f, LinkType::LinuxSll, &pkt));
        let mut bad = pkt.clone();
        bad[16 + 9] = 17; // proto → UDP
        assert!(!matches_on(f, LinkType::LinuxSll, &bad));
    }
}
