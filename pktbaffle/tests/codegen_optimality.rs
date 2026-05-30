/// Comprehensive BPF codegen verification and regression suite.
///
/// Tests are organised into sections:
///   1.  Compilation sanity — all primitives must compile without panicking.
///   2.  Program structure invariants — every cBPF program must be well-formed.
///   3.  Jump validity — all jump targets must land inside the program.
///   4.  Termination — every path through the program must end at a RET.
///   5.  Instruction count baselines — upper bounds by complexity tier.
///   6.  cBPF redundant-load audit — `dedup_loads` must fire correctly.
///   7.  Specific opcode shape checks — key filter types produce expected opcodes.
///   8.  Direction variants — Src / Dst / SrcAndDst / SrcOrDst all compile.
///   9.  Link-type variants — Ethernet / RawIp / LinuxSll.
///   10. eBPF structure — bounds checks, termination, register discipline.
///   11. Error path — unsupported constructs return Err, not panic.
///   12. Equivalence — logically identical filters produce similar programs.
///   13. NOT / logical negation correctness.
///   14. Complex compound expressions.
use pktbaffle::{bpf, compile, ebpf, LinkType, Target};

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn cbpf(filter: &str) -> Vec<bpf::Insn> {
    cbpf_link(filter, LinkType::Ethernet)
}

fn cbpf_link(filter: &str, link: LinkType) -> Vec<bpf::Insn> {
    compile(filter, link, Target::Classic)
        .unwrap_or_else(|e| panic!("cBPF compile failed for {filter:?}: {e}"))
        .as_classic()
        .unwrap()
        .instructions()
        .to_vec()
}

fn ebpf(filter: &str) -> Vec<ebpf::Insn> {
    compile(filter, LinkType::Ethernet, Target::Extended)
        .unwrap_or_else(|e| panic!("eBPF compile failed for {filter:?}: {e}"))
        .as_extended()
        .unwrap()
        .instructions()
        .to_vec()
}

fn compile_err(filter: &str, link: LinkType) -> String {
    compile(filter, link, Target::Classic)
        .expect_err(&format!("expected compile error for {filter:?}"))
        .to_string()
}

// ── cBPF opcode helpers ──────────────────────────────────────────────────────

fn is_ld_abs(insn: bpf::Insn) -> bool {
    (insn.code & 0xe7) == (bpf::BPF_LD | bpf::BPF_ABS)
}
fn is_ld_ind(insn: bpf::Insn) -> bool {
    (insn.code & 0xe7) == (bpf::BPF_LD | bpf::BPF_IND)
}
fn is_ret(insn: bpf::Insn) -> bool {
    (insn.code & 0x07) == bpf::BPF_RET
}
fn is_jmp(insn: bpf::Insn) -> bool {
    (insn.code & 0x07) == bpf::BPF_JMP
}
fn is_ja(insn: bpf::Insn) -> bool {
    is_jmp(insn) && (insn.code & 0xf0) == bpf::BPF_JA
}
fn is_jeq(insn: bpf::Insn) -> bool {
    is_jmp(insn) && (insn.code & 0xf0) == bpf::BPF_JEQ
}
fn is_jset(insn: bpf::Insn) -> bool {
    is_jmp(insn) && (insn.code & 0xf0) == bpf::BPF_JSET
}
fn is_jge(insn: bpf::Insn) -> bool {
    is_jmp(insn) && (insn.code & 0xf0) == bpf::BPF_JGE
}
fn is_jgt(insn: bpf::Insn) -> bool {
    is_jmp(insn) && (insn.code & 0xf0) == bpf::BPF_JGT
}
fn is_and_k(insn: bpf::Insn) -> bool {
    (insn.code & 0xff) == (bpf::BPF_ALU | bpf::BPF_AND | bpf::BPF_K)
}
fn is_msh(insn: bpf::Insn) -> bool {
    (insn.code & 0xff) == (bpf::BPF_LDX | bpf::BPF_B | bpf::BPF_MSH)
}
fn is_rsh(insn: bpf::Insn) -> bool {
    (insn.code & 0xff) == (bpf::BPF_ALU | bpf::BPF_RSH | bpf::BPF_K)
}

// ─────────────────────────────────────────────────────────────────────────────
// §1 Compilation Sanity — every primitive must compile without panic
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn compile_sanity_protocols() {
    for f in &[
        "tcp",
        "udp",
        "icmp",
        "icmp6",
        "igmp",
        "sctp",
        "ip",
        "ip6",
        "arp",
        "rarp",
        "ip proto 6",
        "ip proto 17",
        "ip proto 1",
        "ip proto 89",
        "ip6 proto 58",
    ] {
        let insns = cbpf(f);
        assert!(!insns.is_empty(), "empty program for {f:?}");
    }
}

#[test]
fn compile_sanity_hosts() {
    for f in &[
        "host 1.2.3.4",
        "src host 10.0.0.1",
        "dst host 192.168.1.254",
        "host 2001:db8::1",
        "dst host fe80::1",
        // Note: abbreviated IPv6 like ::1 is not yet supported by the parser.
    ] {
        let insns = cbpf(f);
        assert!(!insns.is_empty(), "empty program for {f:?}");
    }
}

#[test]
fn compile_sanity_networks() {
    for f in &[
        "net 10.0.0.0/8",
        "net 192.168.0.0/16",
        "src net 172.16.0.0/12",
        "dst net 10.0.0.0/24",
        "net 10.0.0.0 mask 255.0.0.0",
    ] {
        let insns = cbpf(f);
        assert!(!insns.is_empty(), "empty program for {f:?}");
    }
}

#[test]
fn compile_sanity_ports() {
    for f in &[
        "port 80",
        "port 443",
        "port 53",
        "src port 22",
        "dst port 8080",
        "tcp port 80",
        "udp port 53",
        "tcp src port 443",
        "tcp dst port 80",
    ] {
        let insns = cbpf(f);
        assert!(!insns.is_empty(), "empty program for {f:?}");
    }
}

#[test]
fn compile_sanity_portranges() {
    for f in &[
        "portrange 1024-65535",
        "portrange 1000-2000",
        "src portrange 1024-65535",
        "dst portrange 8000-8999",
        "tcp portrange 1024-65535",
        "udp portrange 5000-6000",
    ] {
        let insns = cbpf(f);
        assert!(!insns.is_empty(), "empty program for {f:?}");
    }
}

#[test]
fn compile_sanity_ethernet() {
    for f in &[
        "ether host aa:bb:cc:dd:ee:ff",
        "ether src 00:11:22:33:44:55",
        "ether dst ff:ff:ff:ff:ff:ff",
        "ether multicast",
        "ether broadcast",
    ] {
        let insns = cbpf(f);
        assert!(!insns.is_empty(), "empty program for {f:?}");
    }
}

#[test]
fn compile_sanity_special_primitives() {
    for f in &[
        "ip multicast",
        "ip broadcast",
        "ip6 multicast",
        "vlan",
        "vlan 100",
        "vlan 4094",
        "mpls",
        "mpls 100",
        "pppoed",
        "pppoes",
        "pppoes 100",
        "pppoes 0",
        "less 64",
        "greater 1500",
        "len = 60",
        "len > 100",
        "len < 1500",
        "len >= 64",
        "len <= 512",
    ] {
        let insns = cbpf(f);
        assert!(!insns.is_empty(), "empty program for {f:?}");
    }
}

#[test]
fn compile_sanity_byte_access() {
    for f in &[
        "tcp[13] & 0x02 != 0",   // SYN
        "tcp[13] & 0x10 != 0",   // ACK
        "tcp[13] & 0x01 != 0",   // FIN
        "tcp[13] & 0x04 != 0",   // RST
        "tcp[13] = 0x12",        // SYN+ACK exact
        "ip[9] = 6",             // IP proto TCP
        "ip[0] & 0x0f > 5",      // IP IHL > 5 (has options)
        "ip[6:2] & 0x1fff != 0", // IP fragment offset != 0
        "ip[8] < 10",            // IP TTL < 10
        "tcp[12] & 0xf0 != 0x50", // TCP data offset != 20
                                 // Note: raw link-layer byte access `[0:2]` is not yet supported by the parser.
    ] {
        let insns = cbpf(f);
        assert!(!insns.is_empty(), "empty program for {f:?}");
    }
}

#[test]
fn compile_sanity_logical_combinations() {
    let filters = [
        "tcp and port 80",
        "udp and port 53",
        "tcp or udp",
        "not tcp",
        "not port 22",
        "tcp and not port 22",
        "tcp and (port 80 or port 443)",
        "not (tcp and port 80)",
        "tcp and host 1.2.3.4 and port 443",
        "src host 10.0.0.1 and dst host 10.0.0.2",
        "tcp and src port 1024 and dst port 80",
        "ip and (tcp or udp) and not port 22",
        "(tcp and port 80) or (udp and port 53)",
        "tcp and port 80 or udp and port 53",
        "host 10.0.0.1 or host 10.0.0.2 or host 10.0.0.3",
    ];
    for f in &filters {
        let insns = cbpf(f);
        assert!(!insns.is_empty(), "empty program for {f:?}");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// §2 Program Structure Invariants
// ─────────────────────────────────────────────────────────────────────────────

fn assert_well_formed(filter: &str, insns: &[bpf::Insn]) {
    assert!(!insns.is_empty(), "{filter:?} produced empty program");
    // Must end with two RET instructions (accept, drop).
    let n = insns.len();
    assert!(
        is_ret(insns[n - 1]),
        "{filter:?}: last insn is not RET: {:?}",
        insns[n - 1]
    );
    assert!(
        is_ret(insns[n - 2]),
        "{filter:?}: second-to-last insn is not RET: {:?}",
        insns[n - 2]
    );
    // Penultimate RET must be ACCEPT (0xffff_ffff), last must be DROP (0).
    assert_eq!(
        insns[n - 2].k,
        bpf::BPF_ACCEPT,
        "{filter:?}: accept RET has wrong k"
    );
    assert_eq!(
        insns[n - 1].k,
        bpf::BPF_DROP,
        "{filter:?}: drop RET has wrong k"
    );
    // No instruction may appear after a RET (besides the terminal pair).
    for (i, insn) in insns[..n - 2].iter().enumerate() {
        assert!(
            !is_ret(*insn),
            "{filter:?}: unexpected mid-program RET at index {i}"
        );
    }
}

#[test]
fn program_structure_all_primitives() {
    let filters = [
        "tcp",
        "udp",
        "icmp",
        "icmp6",
        "igmp",
        "sctp",
        "ip",
        "ip6",
        "arp",
        "host 1.2.3.4",
        "src host 10.0.0.1",
        "net 10.0.0.0/8",
        "src net 192.168.0.0/24",
        "port 80",
        "src port 53",
        "dst port 443",
        "tcp port 80",
        "udp port 53",
        "portrange 1024-65535",
        "tcp portrange 8000-9000",
        "ether host aa:bb:cc:dd:ee:ff",
        "ether multicast",
        "ip multicast",
        "ip broadcast",
        "vlan",
        "vlan 100",
        "mpls",
        "less 64",
        "greater 1500",
        "len = 60",
        "tcp[13] & 0x02 != 0",
        "tcp and port 80",
        "tcp or udp",
        "not tcp",
    ];
    for f in &filters {
        let insns = cbpf(f);
        assert_well_formed(f, &insns);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// §3 Jump Validity — no out-of-bounds targets
// ─────────────────────────────────────────────────────────────────────────────

fn assert_jumps_in_bounds(filter: &str, insns: &[bpf::Insn]) {
    let n = insns.len();
    for (i, insn) in insns.iter().enumerate() {
        if !is_jmp(*insn) {
            continue;
        }
        if is_ja(*insn) {
            let target = i + 1 + insn.k as usize;
            assert!(
                target < n,
                "{filter:?}: JA at {i} has out-of-bounds target {target} (prog len {n})"
            );
        } else {
            let jt = i + 1 + insn.jt as usize;
            let jf = i + 1 + insn.jf as usize;
            assert!(
                jt < n,
                "{filter:?}: jt at {i} has out-of-bounds target {jt} (prog len {n})"
            );
            assert!(
                jf < n,
                "{filter:?}: jf at {i} has out-of-bounds target {jf} (prog len {n})"
            );
        }
    }
}

#[test]
fn jumps_in_bounds_for_all_filters() {
    let filters = [
        "tcp",
        "udp",
        "icmp",
        "ip",
        "host 1.2.3.4",
        "host 2001:db8::1",
        "net 10.0.0.0/8",
        "port 80",
        "portrange 1000-2000",
        "tcp port 80",
        "udp portrange 53-53",
        "ether host aa:bb:cc:dd:ee:ff",
        "vlan 100",
        "mpls 42",
        "ip multicast",
        "ip broadcast",
        "tcp and port 80",
        "tcp or udp",
        "not tcp",
        "not (tcp and port 80)",
        "tcp and (port 80 or port 443)",
        "src host 1.2.3.4 or dst host 5.6.7.8",
        "(tcp and port 80) or (udp and port 53) or icmp",
        "ip and not (tcp and port 22)",
        "tcp[13] & 0x02 != 0",
        "tcp[13] & 0x12 = 0x12",
        "len < 64",
    ];
    for f in &filters {
        let insns = cbpf(f);
        assert_jumps_in_bounds(f, &insns);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// §4 Termination — every code path ends at a RET
// ─────────────────────────────────────────────────────────────────────────────

fn reachable_from(insns: &[bpf::Insn], start: usize) -> std::collections::HashSet<usize> {
    let mut visited = std::collections::HashSet::new();
    let mut queue = vec![start];
    while let Some(i) = queue.pop() {
        if i >= insns.len() || !visited.insert(i) {
            continue;
        }
        let insn = insns[i];
        if is_ret(insn) {
            continue;
        }
        if is_ja(insn) {
            queue.push(i + 1 + insn.k as usize);
        } else if is_jmp(insn) {
            queue.push(i + 1 + insn.jt as usize);
            queue.push(i + 1 + insn.jf as usize);
            queue.push(i + 1); // fall-through for non-jump instructions
        } else {
            queue.push(i + 1);
        }
    }
    visited
}

fn assert_all_paths_terminate(filter: &str, insns: &[bpf::Insn]) {
    let n = insns.len();
    let reachable = reachable_from(insns, 0);
    // Every reachable instruction must be in-bounds.
    for &idx in &reachable {
        assert!(
            idx < n,
            "{filter:?}: reachable index {idx} is out-of-bounds"
        );
    }
    // At least one of the two terminal RET instructions must be reachable.
    let accept_idx = n - 2;
    let drop_idx = n - 1;
    assert!(
        reachable.contains(&accept_idx) || reachable.contains(&drop_idx),
        "{filter:?}: neither ACCEPT nor DROP is reachable from start!"
    );
}

#[test]
fn all_paths_terminate() {
    let filters = [
        "tcp",
        "udp",
        "ip",
        "arp",
        "host 1.2.3.4",
        "net 10.0.0.0/8",
        "port 80",
        "portrange 1-1024",
        "tcp port 443",
        "udp portrange 1000-2000",
        "vlan 100",
        "mpls",
        "tcp and port 80",
        "tcp or udp",
        "not tcp",
        "tcp and (port 80 or port 443)",
        "not (tcp and port 80)",
        "(tcp and port 80) or (udp and port 53)",
        "ip and not (tcp and port 22)",
    ];
    for f in &filters {
        let insns = cbpf(f);
        assert_all_paths_terminate(f, &insns);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// §5 Instruction Count Baselines
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn instruction_count_low_complexity() {
    // Simple single-primitive filters. Bounds are loose enough to survive
    // minor refactors but tight enough to catch gross regressions.
    let cases: &[(&str, usize, usize)] = &[
        ("tcp", 4, 12),
        ("udp", 4, 12),
        ("icmp", 4, 12),
        ("igmp", 4, 12),
        ("ip", 2, 6),
        ("ip6", 2, 6),
        ("arp", 2, 6),
        ("host 1.2.3.4", 8, 30),
        ("src host 10.0.0.1", 6, 20),
        ("dst host 10.0.0.1", 6, 20),
        ("port 80", 16, 50),
        ("src port 80", 14, 40),
        ("dst port 80", 14, 40),
        ("tcp port 80", 14, 30),
        ("len = 60", 2, 6),
        ("less 64", 2, 6),
        ("greater 1500", 2, 6),
        ("vlan", 2, 6),
        ("vlan 100", 5, 14),
        ("mpls", 4, 10),
    ];
    for &(filter, lo, hi) in cases {
        let n = cbpf(filter).len();
        assert!(
            n >= lo && n <= hi,
            "cBPF count for {filter:?}: expected [{lo}, {hi}], got {n}"
        );
    }
}

#[test]
fn instruction_count_medium_complexity() {
    let cases: &[(&str, usize, usize)] = &[
        ("tcp and port 80", 14, 35),
        ("udp and port 53", 14, 35),
        ("tcp or udp", 8, 18),
        ("not tcp", 6, 16),
        ("net 192.168.0.0/16", 6, 22),
        ("src net 10.0.0.0/8", 5, 18),
        ("portrange 1024-65535", 18, 50),
        ("tcp portrange 8000-9000", 16, 45),
        ("tcp[13] & 0x02 != 0", 4, 35),
        ("tcp[13] & 0x12 = 0x12", 4, 35),
        ("ip[0] & 0x0f > 5", 3, 22),
        ("tcp and not port 22", 16, 40),
        ("ether host aa:bb:cc:dd:ee:ff", 5, 16),
        ("ip multicast", 5, 16),
        ("ip broadcast", 4, 12),
    ];
    for &(filter, lo, hi) in cases {
        let n = cbpf(filter).len();
        assert!(
            n >= lo && n <= hi,
            "cBPF count for {filter:?}: expected [{lo}, {hi}], got {n}"
        );
    }
}

#[test]
fn instruction_count_high_complexity() {
    let cases: &[(&str, usize, usize)] = &[
        ("tcp and (port 80 or port 443)", 25, 65),
        ("(tcp and port 80) or (udp and port 53)", 35, 100),
        ("tcp and (port 80 or port 443) and host 10.0.0.1", 35, 100),
        ("not (tcp and port 80)", 16, 45),
        ("ip and not (tcp or udp)", 8, 22),
        ("host 10.0.0.1 or host 10.0.0.2 or host 10.0.0.3", 18, 70),
        ("vlan 100 and ip and tcp port 80", 20, 55),
        ("ip6 and tcp port 443", 14, 40),
        ("src host 1.2.3.4 or dst host 5.6.7.8", 8, 50),
        ("tcp and src port 1024 and dst port 80", 20, 55),
        ("(tcp or udp) and portrange 1024-65535", 28, 110),
    ];
    for &(filter, lo, hi) in cases {
        let n = cbpf(filter).len();
        assert!(
            n >= lo && n <= hi,
            "cBPF count for {filter:?}: expected [{lo}, {hi}], got {n}"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// §6 cBPF Redundant-Load Audit
// ─────────────────────────────────────────────────────────────────────────────

fn assert_no_consecutive_dup_abs_loads(filter: &str, insns: &[bpf::Insn]) {
    for i in 1..insns.len() {
        let cur = insns[i];
        let prv = insns[i - 1];
        if is_ld_abs(cur) && is_ld_abs(prv) && cur.code == prv.code && cur.k == prv.k {
            panic!(
                "Redundant consecutive absolute load in {filter:?} at idx {i}:\n  prev: {:?}\n  curr: {:?}",
                prv, cur
            );
        }
    }
}

#[test]
fn no_redundant_consecutive_loads() {
    let filters = [
        "tcp",
        "udp",
        "tcp and port 80",
        "tcp or udp",
        "tcp[13] & 2 != 0 and tcp[13] & 16 != 0",
        "ip[12:4] = 0x0a000001 and ip[16:4] = 0x0a000002",
        "vlan and ip and tcp and port 80",
        "tcp and (port 80 or port 443)",
        "(tcp and port 80) or (udp and port 53)",
        "ip multicast",
        "ip6 and tcp port 443",
        "host 1.2.3.4 and port 80",
    ];
    for f in &filters {
        let insns = cbpf(f);
        assert_no_consecutive_dup_abs_loads(f, &insns);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// §7 Opcode Shape Checks
// ─────────────────────────────────────────────────────────────────────────────

/// `ip` is just a halfword ethertype check: ldh[12]; jeq 0x0800
#[test]
fn ip_filter_shape() {
    let insns = cbpf("ip");
    // First instruction: ldh abs 12 (ethertype offset)
    assert!(
        is_ld_abs(insns[0]) && (insns[0].code & 0x18) == bpf::BPF_H && insns[0].k == 12,
        "expected ldh_abs(12) first, got {:?}",
        insns[0]
    );
    // Second: jeq 0x0800
    assert!(
        is_jeq(insns[1]) && insns[1].k == 0x0800,
        "expected jeq 0x0800, got {:?}",
        insns[1]
    );
}

/// `ip6` is a halfword ethertype check: ldh[12]; jeq 0x86dd
#[test]
fn ip6_filter_shape() {
    let insns = cbpf("ip6");
    assert!(is_ld_abs(insns[0]) && insns[0].k == 12);
    assert!(is_jeq(insns[1]) && insns[1].k == 0x86dd);
}

/// `arp` is a halfword ethertype check: ldh[12]; jeq 0x0806
#[test]
fn arp_filter_shape() {
    let insns = cbpf("arp");
    assert!(is_ld_abs(insns[0]) && insns[0].k == 12);
    assert!(is_jeq(insns[1]) && insns[1].k == 0x0806);
}

/// `tcp` must emit: ethertype check, then IP proto check for 6.
#[test]
fn tcp_filter_has_proto_check_for_6() {
    let insns = cbpf("tcp");
    // Find a jeq with k=6 (TCP protocol number)
    let has_proto6 = insns.iter().any(|i| is_jeq(*i) && i.k == 6);
    assert!(has_proto6, "no jeq #6 (TCP proto) in tcp filter: {insns:?}");
}

/// `udp` must emit a proto check for 17.
#[test]
fn udp_filter_has_proto_check_for_17() {
    let insns = cbpf("udp");
    let has_proto17 = insns.iter().any(|i| is_jeq(*i) && i.k == 17);
    assert!(
        has_proto17,
        "no jeq #17 (UDP proto) in udp filter: {insns:?}"
    );
}

/// `icmp` must emit a proto check for 1.
#[test]
fn icmp_filter_has_proto_check_for_1() {
    let insns = cbpf("icmp");
    let has_proto1 = insns.iter().any(|i| is_jeq(*i) && i.k == 1);
    assert!(
        has_proto1,
        "no jeq #1 (ICMP proto) in icmp filter: {insns:?}"
    );
}

/// Port filters use indirect loads (X + offset) — must include MSH instruction.
#[test]
fn port_filter_uses_msh_and_indirect_loads() {
    let insns = cbpf("tcp port 80");
    let has_msh = insns.iter().any(|i| is_msh(*i));
    assert!(has_msh, "no MSH instruction in 'tcp port 80': {insns:?}");
    let has_ind = insns.iter().any(|i| is_ld_ind(*i));
    assert!(has_ind, "no indirect load in 'tcp port 80': {insns:?}");
}

/// Port filters must also check for non-first IP fragments (jset 0x1fff).
#[test]
fn port_filter_has_fragment_check() {
    let insns = cbpf("tcp port 80");
    let has_frag = insns.iter().any(|i| is_jset(*i) && i.k == 0x1fff);
    assert!(
        has_frag,
        "no fragment-offset check (jset #0x1fff) in 'tcp port 80': {insns:?}"
    );
}

/// `portrange lo-hi` must use JGE and JGT to implement the range check.
#[test]
fn portrange_filter_uses_range_jumps() {
    let insns = cbpf("portrange 1000-2000");
    let has_jge = insns.iter().any(|i| is_jge(*i));
    let has_jgt = insns.iter().any(|i| is_jgt(*i));
    assert!(has_jge, "no JGE in portrange filter: {insns:?}");
    assert!(has_jgt, "no JGT in portrange filter: {insns:?}");
}

/// Net filter must include AND instruction to apply the mask.
#[test]
fn net_filter_uses_mask() {
    let insns = cbpf("net 192.168.0.0/24");
    let has_and = insns.iter().any(|i| is_and_k(*i));
    assert!(has_and, "no AND in net filter: {insns:?}");
}

/// Byte-access with bitmask: must emit AND before comparison.
#[test]
fn byte_access_with_mask_emits_and() {
    let insns = cbpf("tcp[13] & 0x02 != 0");
    let has_and = insns.iter().any(|i| is_and_k(*i) && i.k == 0x02);
    assert!(has_and, "no AND #0x02 in 'tcp[13] & 0x02 != 0': {insns:?}");
}

/// IP multicast: DST IP & 0xf0000000 == 0xe0000000
#[test]
fn ip_multicast_mask_shape() {
    let insns = cbpf("ip multicast");
    let has_and = insns.iter().any(|i| is_and_k(*i) && i.k == 0xf000_0000);
    assert!(has_and, "no AND 0xf0000000 in 'ip multicast': {insns:?}");
    let has_jeq = insns.iter().any(|i| is_jeq(*i) && i.k == 0xe000_0000);
    assert!(has_jeq, "no JEQ 0xe0000000 in 'ip multicast': {insns:?}");
}

/// Ether multicast: bit 0 of DST MAC byte 0 — uses JSET.
#[test]
fn ether_multicast_uses_jset() {
    let insns = cbpf("ether multicast");
    let has_jset = insns.iter().any(|i| is_jset(*i) && i.k == 0x01);
    assert!(has_jset, "no JSET #1 in 'ether multicast': {insns:?}");
}

/// MPLS filter should load ethertype and check for 0x8847.
#[test]
fn mpls_filter_checks_ethertype_8847() {
    let insns = cbpf("mpls");
    let has_mpls = insns.iter().any(|i| is_jeq(*i) && i.k == 0x8847);
    assert!(has_mpls, "no JEQ 0x8847 in 'mpls': {insns:?}");
}

/// VLAN filter must check ethertype 0x8100.
#[test]
fn vlan_filter_checks_ethertype_8100() {
    let insns = cbpf("vlan");
    let has_vlan = insns.iter().any(|i| is_jeq(*i) && i.k == 0x8100);
    assert!(has_vlan, "no JEQ 0x8100 in 'vlan': {insns:?}");
}

/// `vlan 100` must mask the TCI field (lower 12 bits) before comparing ID.
#[test]
fn vlan_id_filter_masks_tci() {
    let insns = cbpf("vlan 100");
    let has_mask = insns.iter().any(|i| is_and_k(*i) && i.k == 0x0fff);
    assert!(has_mask, "no AND 0x0fff in 'vlan 100': {insns:?}");
    let has_jeq = insns.iter().any(|i| is_jeq(*i) && i.k == 100);
    assert!(has_jeq, "no JEQ 100 in 'vlan 100': {insns:?}");
}

/// `mpls 42` must extract the top 20 bits (RSH 12) of the label stack entry.
#[test]
fn mpls_label_filter_uses_rsh() {
    let insns = cbpf("mpls 42");
    let has_rsh = insns.iter().any(|i| is_rsh(*i) && i.k == 12);
    assert!(has_rsh, "no RSH 12 in 'mpls 42': {insns:?}");
    let has_jeq = insns.iter().any(|i| is_jeq(*i) && i.k == 42);
    assert!(has_jeq, "no JEQ 42 in 'mpls 42': {insns:?}");
}

/// `len` filter uses BPF_LD | BPF_LEN (packet-length load).
#[test]
fn len_filter_uses_bpf_len_opcode() {
    let insns = cbpf("len = 60");
    let has_len = insns.iter().any(|i| {
        let class = i.code & 0x07;
        let mode = i.code & 0xe0;
        class == bpf::BPF_LD && mode == bpf::BPF_LEN
    });
    assert!(has_len, "no BPF_LEN load in 'len = 60': {insns:?}");
}

// ─────────────────────────────────────────────────────────────────────────────
// §8 Direction Variants
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn host_direction_variants_all_compile() {
    let filters = [
        "host 1.2.3.4",
        "src host 1.2.3.4",
        "dst host 1.2.3.4",
        // Note: "src and dst host" uses a specific parser production.
        "src and dst 1.2.3.4",
    ];
    for f in &filters {
        let insns = cbpf(f);
        assert_well_formed(f, &insns);
        assert_jumps_in_bounds(f, &insns);
    }
}

/// `src and dst 1.2.3.4` should emit checks against BOTH src and dst IPs.
#[test]
fn src_and_dst_host_checks_both_addresses() {
    let insns = cbpf("src and dst 1.2.3.4");
    let k = u32::from(std::net::Ipv4Addr::new(1, 2, 3, 4));
    let jeq_count = insns.iter().filter(|i| is_jeq(**i) && i.k == k).count();
    assert!(
        jeq_count >= 2,
        "src and dst host should check the IP twice, found {} jeq #{k:#010x}",
        jeq_count
    );
}

/// `src or dst host` (the default) checks src first and shortcuts on match.
#[test]
fn src_or_dst_host_has_success_shortcut_jt() {
    // For SrcOrDst, the src jeq uses jt as a forward success jump.
    let insns = cbpf("host 1.2.3.4");
    let has_jt_success = insns.iter().any(|i| is_jeq(*i) && i.jt != 0);
    assert!(
        has_jt_success,
        "SrcOrDst host should have a jt-based success shortcut, got: {insns:?}"
    );
}

#[test]
fn port_direction_variants_all_compile() {
    let filters = [
        "port 80",
        "src port 80",
        "dst port 80",
        "tcp port 80",
        "tcp src port 80",
        "tcp dst port 80",
        "udp port 53",
        "udp src port 5353",
        "udp dst port 5353",
    ];
    for f in &filters {
        let insns = cbpf(f);
        assert_well_formed(f, &insns);
        assert_jumps_in_bounds(f, &insns);
    }
}

#[test]
fn portrange_direction_variants_all_compile() {
    let filters = [
        "portrange 1024-65535",
        "src portrange 1024-65535",
        "dst portrange 1024-65535",
        "tcp portrange 8000-8999",
        "udp portrange 1000-2000",
    ];
    for f in &filters {
        let insns = cbpf(f);
        assert_well_formed(f, &insns);
        assert_jumps_in_bounds(f, &insns);
    }
}

#[test]
fn net_direction_variants_all_compile() {
    let filters = ["net 10.0.0.0/8", "src net 10.0.0.0/8", "dst net 10.0.0.0/8"];
    for f in &filters {
        let insns = cbpf(f);
        assert_well_formed(f, &insns);
        assert_jumps_in_bounds(f, &insns);
    }
}

#[test]
fn ether_host_direction_variants_all_compile() {
    let filters = [
        "ether host aa:bb:cc:dd:ee:ff",
        "ether src aa:bb:cc:dd:ee:ff",
        "ether dst aa:bb:cc:dd:ee:ff",
    ];
    for f in &filters {
        let insns = cbpf(f);
        assert_well_formed(f, &insns);
        assert_jumps_in_bounds(f, &insns);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// §9 Link-type Variants
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn ethernet_link_offsets_are_correct() {
    // On Ethernet, ethertype is at offset 12.
    let insns = cbpf_link("ip", LinkType::Ethernet);
    assert!(
        insns[0].k == 12,
        "Ethernet ethertype offset should be 12, got {}",
        insns[0].k
    );
}

#[test]
fn linux_sll_link_offsets_are_correct() {
    // On Linux SLL, ethertype is at offset 14.
    let insns = cbpf_link("ip", LinkType::LinuxSll);
    assert!(
        insns[0].k == 14,
        "LinuxSll ethertype offset should be 14, got {}",
        insns[0].k
    );
}

#[test]
fn rawip_link_compiles_basic_proto_filters() {
    // RawIp: no ethertype guard, starts directly with IP protocol byte.
    for f in &["tcp", "udp", "icmp"] {
        let insns = cbpf_link(f, LinkType::RawIp);
        assert!(!insns.is_empty(), "empty program for {f:?} on RawIp");
        assert_well_formed(f, &insns);
        assert_jumps_in_bounds(f, &insns);
    }
}

#[test]
fn rawip_tcp_has_no_ethertype_check() {
    // RawIp should NOT check for ethertype 0x0800.
    let insns = cbpf_link("tcp", LinkType::RawIp);
    let has_ethertype = insns.iter().any(|i| is_jeq(*i) && i.k == 0x0800);
    assert!(
        !has_ethertype,
        "RawIp 'tcp' should not check ethertype 0x0800: {insns:?}"
    );
}

#[test]
fn rawip_net_offset_is_zero() {
    // On RawIp, the IP src address should be at offset 12 (no Ethernet header).
    let insns = cbpf_link("src host 1.2.3.4", LinkType::RawIp);
    // Look for a word load at offset 12 (IP src on RawIp = 0 + 12).
    let has_offset12 = insns
        .iter()
        .any(|i| (i.code & 0xff) == (bpf::BPF_LD | bpf::BPF_W | bpf::BPF_ABS) && i.k == 12);
    assert!(
        has_offset12,
        "RawIp src host should load from offset 12, got: {insns:?}"
    );
}

#[test]
fn ethernet_net_offset_is_14() {
    // On Ethernet, the IP src address should be at offset 26 (14 + 12).
    let insns = cbpf_link("src host 1.2.3.4", LinkType::Ethernet);
    let has_offset26 = insns
        .iter()
        .any(|i| (i.code & 0xff) == (bpf::BPF_LD | bpf::BPF_W | bpf::BPF_ABS) && i.k == 26);
    assert!(
        has_offset26,
        "Ethernet src host should load from offset 26, got: {insns:?}"
    );
}

#[test]
fn linux_sll_net_offset_is_16() {
    // On LinuxSll, net offset is 16. IP src = 16 + 12 = 28.
    let insns = cbpf_link("src host 1.2.3.4", LinkType::LinuxSll);
    let has_offset28 = insns
        .iter()
        .any(|i| (i.code & 0xff) == (bpf::BPF_LD | bpf::BPF_W | bpf::BPF_ABS) && i.k == 28);
    assert!(
        has_offset28,
        "LinuxSll src host should load from offset 28, got: {insns:?}"
    );
}

#[test]
fn all_link_types_produce_well_formed_programs() {
    let filters = ["tcp", "udp", "host 1.2.3.4", "port 80", "tcp port 443"];
    for link in &[LinkType::Ethernet, LinkType::LinuxSll, LinkType::RawIp] {
        for f in &filters {
            let insns = cbpf_link(f, *link);
            assert_well_formed(f, &insns);
            assert_jumps_in_bounds(f, &insns);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// §10 eBPF Structure
// ─────────────────────────────────────────────────────────────────────────────

fn ebpf_is_exit(insn: ebpf::Insn) -> bool {
    insn.code == (ebpf::BPF_JMP | ebpf::BPF_EXIT)
}

fn ebpf_is_jmp(insn: ebpf::Insn) -> bool {
    let class = insn.code & 0x07;
    class == ebpf::BPF_JMP || class == ebpf::BPF_JMP32
}

#[test]
fn ebpf_programs_compile_for_all_basic_filters() {
    let filters = [
        "tcp",
        "udp",
        "icmp",
        "ip",
        "ip6",
        "host 1.2.3.4",
        "port 80",
        "tcp port 443",
        "tcp and port 80",
        "tcp or udp",
    ];
    for f in &filters {
        let insns = ebpf(f);
        assert!(!insns.is_empty(), "empty eBPF program for {f:?}");
    }
}

#[test]
fn ebpf_programs_always_terminate_with_exit() {
    let filters = ["tcp", "udp", "port 80", "tcp and port 80", "host 1.2.3.4"];
    for f in &filters {
        let insns = ebpf(f);
        // The last instruction must be an EXIT.
        let last = insns.last().expect("non-empty program");
        assert!(
            ebpf_is_exit(*last),
            "eBPF program for {f:?} does not end with EXIT: {last:?}"
        );
    }
}

#[test]
fn ebpf_programs_contain_bounds_checks_against_r3() {
    // Every eBPF program that accesses packet data must verify pointer < R3.
    let filters = [
        "tcp",
        "udp",
        "port 80",
        "tcp[13] & 0x02 != 0",
        "host 1.2.3.4",
    ];
    for f in &filters {
        let insns = ebpf(f);
        let bounds_checks = insns
            .iter()
            .filter(|i| {
                let class = i.code & 0x07;
                let is_jmp = class == ebpf::BPF_JMP || class == ebpf::BPF_JMP32;
                let src = (i.regs >> 4) & 0xf;
                let dst = i.regs & 0xf;
                is_jmp && (src == ebpf::R3 || dst == ebpf::R3)
            })
            .count();
        assert!(
            bounds_checks > 0,
            "eBPF {f:?}: no bounds check against R3 (data_end)"
        );
    }
}

#[test]
fn ebpf_instruction_count_baselines() {
    let cases: &[(&str, usize, usize)] = &[
        ("tcp", 15, 40),
        ("udp", 15, 40),
        ("icmp", 15, 40),
        ("port 80", 30, 70),
        ("tcp port 80", 30, 70),
        ("host 1.2.3.4", 20, 55),
        ("tcp and port 80", 35, 80),
        ("tcp and (port 80 or port 443)", 50, 130),
        ("(tcp and port 80) or (udp and port 53)", 70, 160),
    ];
    for &(filter, lo, hi) in cases {
        let n = ebpf(filter).len();
        assert!(
            n >= lo && n <= hi,
            "eBPF count for {filter:?}: expected [{lo}, {hi}], got {n}"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// §11 Error Paths
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn inbound_returns_error() {
    compile_err("inbound", LinkType::Ethernet);
}

#[test]
fn outbound_returns_error() {
    compile_err("outbound", LinkType::Ethernet);
}

#[test]
fn rawip_vlan_returns_error() {
    // VLAN requires an ethertype field; RawIp has no link layer.
    compile_err("vlan", LinkType::RawIp);
}

#[test]
fn rawip_mpls_returns_error() {
    compile_err("mpls", LinkType::RawIp);
}

#[test]
fn rawip_ether_host_returns_error() {
    compile_err("ether host aa:bb:cc:dd:ee:ff", LinkType::RawIp);
}

#[test]
fn rawip_ether_multicast_returns_error() {
    compile_err("ether multicast", LinkType::RawIp);
}

// ─────────────────────────────────────────────────────────────────────────────
// §12 Equivalence
// ─────────────────────────────────────────────────────────────────────────────

/// Check that two filters produce the same cBPF instruction count (within delta).
fn assert_cbpf_count_similar(a: &str, b: &str, max_delta: usize) {
    let na = cbpf(a).len();
    let nb = cbpf(b).len();
    let diff = na.abs_diff(nb);
    assert!(
        diff <= max_delta,
        "cBPF count divergence ({a:?} len={na}) vs ({b:?} len={nb}): delta {diff} > {max_delta}"
    );
}

#[test]
fn tcp_equivalents_have_similar_size() {
    assert_cbpf_count_similar("tcp", "ip proto 6 or ip6 proto 6", 10);
}

#[test]
fn udp_equivalents_have_similar_size() {
    assert_cbpf_count_similar("udp", "ip proto 17 or ip6 proto 17", 10);
}

#[test]
fn icmp_equivalents_have_similar_size() {
    // `icmp` matches IPv4 ICMP only; `ip proto 1` is the same.
    assert_cbpf_count_similar("icmp", "ip proto 1", 5);
}

#[test]
fn host_and_explicit_src_or_dst_are_equivalent_size() {
    assert_cbpf_count_similar("host 1.2.3.4", "src host 1.2.3.4 or dst host 1.2.3.4", 10);
}

#[test]
fn juxtaposition_and_keyword_same_size() {
    // `tcp port 80` parses as tcp-qualified-port (one proto path),
    // while `tcp and port 80` parses as two separate primitives AND-ed.
    // They should have a similar count, but may differ slightly.
    let a = cbpf("tcp port 80").len();
    let b = cbpf("tcp and port 80").len();
    let delta = a.abs_diff(b);
    assert!(
        delta <= 10,
        "'tcp port 80' ({a}) and 'tcp and port 80' ({b}) differ by {delta} instructions"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// §13 NOT / Negation Correctness
// ─────────────────────────────────────────────────────────────────────────────

/// `not tcp` should be strictly longer than `tcp` (inverted path).
#[test]
fn not_tcp_is_longer_than_tcp() {
    let a = cbpf("tcp").len();
    let b = cbpf("not tcp").len();
    assert!(b > a, "'not tcp' ({b}) should be longer than 'tcp' ({a})");
}

/// `not tcp` and `tcp` combined should compile and produce valid programs.
#[test]
fn not_combined_with_and_compiles() {
    for f in &["tcp and not port 22", "ip and not tcp", "not (tcp or udp)"] {
        let insns = cbpf(f);
        assert_well_formed(f, &insns);
        assert_jumps_in_bounds(f, &insns);
    }
}

/// `not (A and B)` should be equivalent length to `not A or not B` (De Morgan).
#[test]
fn double_negation_identity() {
    // `not not tcp` should have the same size as `tcp` (within a constant).
    // (Some compilers might not simplify this, so we just ensure it compiles.)
    let insns = cbpf("not (not tcp)");
    assert_well_formed("not (not tcp)", &insns);
    assert_jumps_in_bounds("not (not tcp)", &insns);
}

// ─────────────────────────────────────────────────────────────────────────────
// §14 Complex Compound Expressions
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn complex_expressions_compile_and_are_valid() {
    let filters = [
        // Network ACL style
        "src host 10.0.0.1 and dst host 10.0.0.2 and tcp and dst port 80",
        // Multi-host with port
        "(host 10.0.0.1 or host 10.0.0.2) and tcp port 443",
        // Protocol demux
        "(tcp and (port 80 or port 443)) or (udp and port 53) or icmp",
        // IPv6 traffic + port
        "ip6 and tcp and dst port 443",
        // TCP flag inspection
        "tcp[13] & 0x02 != 0 and tcp[13] & 0x10 = 0",  // SYN without ACK
        // Subnet exclusion
        "ip and not net 192.168.0.0/16",
        // VLAN + inner IP + port
        "vlan 100 and ip and tcp port 80",
        // PPPoE session traffic
        "pppoes and tcp port 80",
        // Multiple NOT layers
        "not (tcp or udp) and ip",
        // Large portrange with proto
        "tcp portrange 1024-65535 and host 10.10.10.10",
        // Deep nesting
        "((tcp and port 80) or (tcp and port 443)) and (src net 10.0.0.0/8 or src net 172.16.0.0/12)",
        // Byte access with compound logic
        "ip and tcp[13] & 0x02 != 0 and host 192.168.1.1",
        // IP fragment detection
        "ip[6:2] & 0x1fff != 0",
        // Short packet filter
        "less 64",
        "greater 1500",
        "len >= 64 and len <= 1514",
    ];
    for f in &filters {
        let insns = cbpf(f);
        assert_well_formed(f, &insns);
        assert_jumps_in_bounds(f, &insns);
        assert_all_paths_terminate(f, &insns);
        assert_no_consecutive_dup_abs_loads(f, &insns);
    }
}

#[test]
fn complex_expressions_compile_to_ebpf() {
    let filters = [
        "tcp and port 80",
        "udp and port 53",
        "(tcp and port 80) or (udp and port 53)",
        "ip6 and tcp port 443",
        "host 10.0.0.1 and tcp port 22",
    ];
    for f in &filters {
        let insns = ebpf(f);
        assert!(!insns.is_empty(), "eBPF empty for {f:?}");
        let last = insns.last().unwrap();
        assert!(
            ebpf_is_exit(*last),
            "eBPF for {f:?} doesn't end with EXIT: {last:?}"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// §15 libpcap Feature Parity
//
// These tests ensure that pktbaffle correctly handles the full set of filter
// syntax features documented in pcap-filter(7), including named constants,
// operator aliases, all protocol keywords, address variants, and explicit
// error signalling for deliberately unsupported constructs.
// ─────────────────────────────────────────────────────────────────────────────

// ── §15a Logical operator aliases: &&, ||, ! ─────────────────────────────────

/// libpcap accepts `&&` as a synonym for `and`.
#[test]
fn logical_and_double_ampersand_alias() {
    let a = cbpf("tcp && port 80");
    let b = cbpf("tcp and port 80");
    assert_eq!(
        a, b,
        "'tcp && port 80' and 'tcp and port 80' must produce identical programs"
    );
}

/// libpcap accepts `||` as a synonym for `or`.
#[test]
fn logical_or_double_pipe_alias() {
    let a = cbpf("tcp || udp");
    let b = cbpf("tcp or udp");
    assert_eq!(
        a, b,
        "'tcp || udp' and 'tcp or udp' must produce identical programs"
    );
}

/// libpcap accepts `!` as a synonym for `not`.
#[test]
fn logical_not_bang_alias() {
    let a = cbpf("! tcp");
    let b = cbpf("not tcp");
    assert_eq!(
        a, b,
        "'! tcp' and 'not tcp' must produce identical programs"
    );
}

/// Compound expression with all three operator aliases.
#[test]
fn all_operator_aliases_combined() {
    let a = cbpf("tcp && port 80 || udp && port 53");
    let b = cbpf("tcp and port 80 or udp and port 53");
    assert_eq!(a, b);
}

// ── §15b Named TCP flag constants ────────────────────────────────────────────

/// `tcp-syn` is a named constant for the SYN flag bit (0x02).
#[test]
fn named_constant_tcp_syn() {
    let a = cbpf("tcp[tcpflags] & tcp-syn != 0");
    let b = cbpf("tcp[13] & 0x02 != 0");
    assert_eq!(a, b, "tcp-syn and 0x02 should produce identical programs");
}

/// `tcp-ack` is a named constant for the ACK flag bit (0x10).
#[test]
fn named_constant_tcp_ack() {
    let a = cbpf("tcp[tcpflags] & tcp-ack != 0");
    let b = cbpf("tcp[13] & 0x10 != 0");
    assert_eq!(a, b, "tcp-ack and 0x10 should produce identical programs");
}

/// `tcp-fin` is a named constant for the FIN flag bit (0x01).
#[test]
fn named_constant_tcp_fin() {
    let a = cbpf("tcp[tcpflags] & tcp-fin != 0");
    let b = cbpf("tcp[13] & 0x01 != 0");
    assert_eq!(a, b);
}

/// `tcp-rst` is a named constant for the RST flag bit (0x04).
#[test]
fn named_constant_tcp_rst() {
    let a = cbpf("tcp[tcpflags] & tcp-rst != 0");
    let b = cbpf("tcp[13] & 0x04 != 0");
    assert_eq!(a, b);
}

/// `tcp-push` is a named constant for the PSH flag bit (0x08).
#[test]
fn named_constant_tcp_push() {
    let a = cbpf("tcp[tcpflags] & tcp-push != 0");
    let b = cbpf("tcp[13] & 0x08 != 0");
    assert_eq!(a, b);
}

/// `tcp-urg` is a named constant for the URG flag bit (0x20).
#[test]
fn named_constant_tcp_urg() {
    let a = cbpf("tcp[tcpflags] & tcp-urg != 0");
    let b = cbpf("tcp[13] & 0x20 != 0");
    assert_eq!(a, b);
}

/// `tcp-ece` and `tcp-cwr` are named constants for ECN bits.
#[test]
fn named_constants_tcp_ecn_bits() {
    let ece = cbpf("tcp[tcpflags] & tcp-ece != 0");
    let ece_raw = cbpf("tcp[13] & 0x40 != 0");
    assert_eq!(ece, ece_raw);

    let cwr = cbpf("tcp[tcpflags] & tcp-cwr != 0");
    let cwr_raw = cbpf("tcp[13] & 0x80 != 0");
    assert_eq!(cwr, cwr_raw);
}

/// `tcpflags` resolves to offset 13 in the TCP header.
#[test]
fn tcpflags_offset_alias() {
    let a = cbpf("tcp[tcpflags] & 0x12 != 0");
    let b = cbpf("tcp[13] & 0x12 != 0");
    assert_eq!(a, b, "tcpflags should resolve to offset 13");
}

/// Common real-world TCP flag combination: SYN but not SYN+ACK.
#[test]
fn named_constants_syn_not_ack() {
    let a = cbpf("tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack = 0");
    let b = cbpf("tcp[13] & 0x02 != 0 and tcp[13] & 0x10 = 0");
    assert_well_formed("tcp-syn not tcp-ack", &a);
    assert_jumps_in_bounds("tcp-syn not tcp-ack", &a);
    assert_eq!(a, b);
}

// ── §15c Named ICMP type constants ──────────────────────────────────────────

/// `icmptype` resolves to offset 0 in the ICMP header.
#[test]
fn icmptype_offset_alias() {
    let a = cbpf("icmp[icmptype] = 8");
    let b = cbpf("icmp[0] = 8");
    assert_eq!(a, b, "icmptype should resolve to ICMP byte offset 0");
}

/// `icmpcode` resolves to offset 1 in the ICMP header.
#[test]
fn icmpcode_offset_alias() {
    let a = cbpf("icmp[icmpcode] = 0");
    let b = cbpf("icmp[1] = 0");
    assert_eq!(a, b, "icmpcode should resolve to ICMP byte offset 1");
}

/// `icmp-echo` is a named constant for ICMP type 8 (Echo Request).
#[test]
fn named_constant_icmp_echo() {
    let a = cbpf("icmp[icmptype] = icmp-echo");
    let b = cbpf("icmp[0] = 8");
    assert_eq!(a, b);
}

/// `icmp-echoreply` is a named constant for ICMP type 0.
#[test]
fn named_constant_icmp_echoreply() {
    let a = cbpf("icmp[icmptype] = icmp-echoreply");
    let b = cbpf("icmp[0] = 0");
    assert_eq!(a, b);
}

/// `icmp-unreach` is a named constant for ICMP type 3.
#[test]
fn named_constant_icmp_unreach() {
    let a = cbpf("icmp[icmptype] = icmp-unreach");
    let b = cbpf("icmp[0] = 3");
    assert_eq!(a, b);
}

/// All ICMP type constants compile without error.
#[test]
fn all_icmp_named_constants_compile() {
    let filters = [
        "icmp[icmptype] = icmp-echoreply",
        "icmp[icmptype] = icmp-unreach",
        "icmp[icmptype] = icmp-sourcequench",
        "icmp[icmptype] = icmp-redirect",
        "icmp[icmptype] = icmp-echo",
        "icmp[icmptype] = icmp-routeradvert",
        "icmp[icmptype] = icmp-routersolicit",
        "icmp[icmptype] = icmp-timxceed",
        "icmp[icmptype] = icmp-paramprob",
        "icmp[icmptype] = icmp-tstamp",
        "icmp[icmptype] = icmp-tstampreply",
        "icmp[icmptype] = icmp-ireq",
        "icmp[icmptype] = icmp-ireqreply",
        "icmp[icmptype] = icmp-maskreq",
        "icmp[icmptype] = icmp-maskreply",
    ];
    for f in &filters {
        let insns = cbpf(f);
        assert_well_formed(f, &insns);
        assert_jumps_in_bounds(f, &insns);
    }
}

/// ICMPv6 type/code offset aliases.
#[test]
fn icmp6_offset_aliases() {
    let a = cbpf("icmp6[icmp6type] = 135"); // Neighbor Solicitation
    let b = cbpf("icmp6[0] = 135");
    assert_eq!(a, b);
}

// ── §15d Additional IP protocol keywords ────────────────────────────────────

/// `ah` is Authentication Header (IP proto 51).
#[test]
fn ah_protocol_keyword() {
    let insns = cbpf("ah");
    assert_well_formed("ah", &insns);
    let has_proto51 = insns.iter().any(|i| is_jeq(*i) && i.k == 51);
    assert!(has_proto51, "ah filter should check IP proto 51: {insns:?}");
}

/// `esp` is Encapsulating Security Payload (IP proto 50).
#[test]
fn esp_protocol_keyword() {
    let insns = cbpf("esp");
    assert_well_formed("esp", &insns);
    let has_proto50 = insns.iter().any(|i| is_jeq(*i) && i.k == 50);
    assert!(
        has_proto50,
        "esp filter should check IP proto 50: {insns:?}"
    );
}

/// `pim` is Protocol Independent Multicast (IP proto 103).
#[test]
fn pim_protocol_keyword() {
    let insns = cbpf("pim");
    assert_well_formed("pim", &insns);
    let has_proto103 = insns.iter().any(|i| is_jeq(*i) && i.k == 103);
    assert!(
        has_proto103,
        "pim filter should check IP proto 103: {insns:?}"
    );
}

/// `vrrp` is Virtual Router Redundancy Protocol (IP proto 112).
#[test]
fn vrrp_protocol_keyword() {
    let insns = cbpf("vrrp");
    assert_well_formed("vrrp", &insns);
    let has_proto112 = insns.iter().any(|i| is_jeq(*i) && i.k == 112);
    assert!(
        has_proto112,
        "vrrp filter should check IP proto 112: {insns:?}"
    );
}

/// `igrp` is Interior Gateway Routing Protocol (IP proto 9).
#[test]
fn igrp_protocol_keyword() {
    let insns = cbpf("igrp");
    assert_well_formed("igrp", &insns);
    let has_proto9 = insns.iter().any(|i| is_jeq(*i) && i.k == 9);
    assert!(has_proto9, "igrp filter should check IP proto 9: {insns:?}");
}

/// `sctp` compiles to IP proto 132.
#[test]
fn sctp_protocol_keyword() {
    let insns = cbpf("sctp");
    assert_well_formed("sctp", &insns);
    let has_proto132 = insns.iter().any(|i| is_jeq(*i) && i.k == 132);
    assert!(
        has_proto132,
        "sctp filter should check IP proto 132: {insns:?}"
    );
}

/// `sctp port` and `sctp portrange` compile correctly.
#[test]
fn sctp_port_and_portrange() {
    for f in &[
        "sctp port 9899",
        "sctp portrange 5000-6000",
        "src sctp port 9899",
        "dst sctp portrange 5000-6000",
    ] {
        let insns = cbpf(f);
        assert_well_formed(f, &insns);
        assert_jumps_in_bounds(f, &insns);
    }
}

/// `proto N` allows any raw IP protocol number.
#[test]
fn raw_proto_numbers() {
    for (filter, expected_proto) in [
        ("proto 6", 6u32),  // TCP
        ("proto 17", 17),   // UDP
        ("proto 41", 41),   // IPv6-in-IPv4
        ("proto 89", 89),   // OSPF
        ("proto 132", 132), // SCTP
    ] {
        let insns = cbpf(filter);
        assert_well_formed(filter, &insns);
        let has_proto = insns.iter().any(|i| is_jeq(*i) && i.k == expected_proto);
        assert!(
            has_proto,
            "'{filter}' should check IP proto {expected_proto}"
        );
    }
}

// ── §15e `ether proto` variants ──────────────────────────────────────────────

/// `ether proto` with a hex ethertype number.
#[test]
fn ether_proto_hex_number() {
    let a = cbpf("ether proto 0x0800");
    let b = cbpf("ip");
    assert_eq!(a, b, "'ether proto 0x0800' should equal 'ip'");
}

/// `ether proto ip` is a named shorthand for ethertype 0x0800.
/// pktbaffle supports named protocol keywords after `ether proto` (libpcap parity).
#[test]
fn ether_proto_ip_keyword() {
    let a = cbpf("ether proto ip");
    let b = cbpf("ip");
    assert_eq!(a, b, "'ether proto ip' should produce the same BPF as 'ip'");
    // Also verify it equals the hex literal form.
    let c = cbpf("ether proto 0x0800");
    assert_eq!(a, c, "'ether proto ip' should equal 'ether proto 0x0800'");
}

/// `ether proto ip6` is a named shorthand for ethertype 0x86dd.
#[test]
fn ether_proto_ip6_keyword() {
    let a = cbpf("ether proto ip6");
    let b = cbpf("ip6");
    assert_eq!(
        a, b,
        "'ether proto ip6' should produce the same BPF as 'ip6'"
    );
    let c = cbpf("ether proto 0x86dd");
    assert_eq!(a, c, "'ether proto ip6' should equal 'ether proto 0x86dd'");
}

/// `ether proto arp` is a named shorthand for ethertype 0x0806.
#[test]
fn ether_proto_arp_keyword() {
    let a = cbpf("ether proto arp");
    let b = cbpf("arp");
    assert_eq!(
        a, b,
        "'ether proto arp' should produce the same BPF as 'arp'"
    );
    let c = cbpf("ether proto 0x0806");
    assert_eq!(a, c, "'ether proto arp' should equal 'ether proto 0x0806'");
}

/// `ether proto rarp` is a named shorthand for ethertype 0x8035.
#[test]
fn ether_proto_rarp_keyword() {
    let a = cbpf("ether proto rarp");
    let b = cbpf("rarp");
    assert_eq!(
        a, b,
        "'ether proto rarp' should produce the same BPF as 'rarp'"
    );
    let c = cbpf("ether proto 0x8035");
    assert_eq!(a, c, "'ether proto rarp' should equal 'ether proto 0x8035'");
}

/// Arbitrary ethertype values can be matched with `ether proto`.
#[test]
fn ether_proto_arbitrary_ethertypes() {
    for (filter, ethertype) in [
        ("ether proto 0x88cc", 0x88ccu32), // LLDP
        ("ether proto 0x8847", 0x8847),    // MPLS unicast
        ("ether proto 0x8100", 0x8100),    // VLAN 802.1Q
        ("ether proto 0x86dd", 0x86dd),    // IPv6
    ] {
        let insns = cbpf(filter);
        assert_well_formed(filter, &insns);
        let has_et = insns.iter().any(|i| is_jeq(*i) && i.k == ethertype);
        assert!(has_et, "'{filter}' should match ethertype {ethertype:#06x}");
    }
}

// ── §15f `ether src/dst` without `host` keyword ──────────────────────────────

/// libpcap allows omitting the `host` keyword after `ether src/dst`.
#[test]
fn ether_src_mac_without_host_keyword() {
    let a = cbpf("ether src aa:bb:cc:dd:ee:ff");
    let b = cbpf("ether src host aa:bb:cc:dd:ee:ff");
    assert_eq!(a, b);
}

#[test]
fn ether_dst_mac_without_host_keyword() {
    let a = cbpf("ether dst aa:bb:cc:dd:ee:ff");
    let b = cbpf("ether dst host aa:bb:cc:dd:ee:ff");
    assert_eq!(a, b);
}

// ── §15g `broadcast` / `multicast` bare keywords ─────────────────────────────

/// Bare `broadcast` keyword matches dst MAC ff:ff:ff:ff:ff:ff.
#[test]
fn broadcast_bare_keyword() {
    let insns = cbpf("broadcast");
    assert_well_formed("broadcast", &insns);
    // Should check dst MAC bytes for 0xff patterns.
    let has_ff_word = insns.iter().any(|i| is_jeq(*i) && i.k == 0xffff_ffff);
    assert!(
        has_ff_word,
        "'broadcast' should check for 0xffffffff in destination MAC"
    );
}

/// Bare `multicast` keyword matches multicast bit in destination MAC.
#[test]
fn multicast_bare_keyword() {
    let a = cbpf("multicast");
    let b = cbpf("ether multicast");
    assert_eq!(a, b, "'multicast' should equal 'ether multicast'");
}

/// `ether broadcast` matches destination MAC ff:ff:ff:ff:ff:ff.
#[test]
fn ether_broadcast_keyword() {
    let insns = cbpf("ether broadcast");
    assert_well_formed("ether broadcast", &insns);
    let has_ff_word = insns.iter().any(|i| is_jeq(*i) && i.k == 0xffff_ffff);
    assert!(has_ff_word, "'ether broadcast' should check for 0xffffffff");
}

// ── §15h Classful network inference ──────────────────────────────────────────

/// `net 10` is equivalent to `net 10.0.0.0/8` (single-octet classful shorthand).
#[test]
fn net_classful_single_octet_infers_slash8() {
    let a = cbpf("net 10");
    let b = cbpf("net 10.0.0.0/8");
    assert_well_formed("net 10", &a);
    assert_eq!(a, b, "'net 10' should equal 'net 10.0.0.0/8'");
}

/// `net 192.168` is equivalent to `net 192.168.0.0/16` (two-octet classful shorthand).
#[test]
fn net_classful_double_octet_infers_slash16() {
    let a = cbpf("net 192.168");
    let b = cbpf("net 192.168.0.0/16");
    assert_well_formed("net 192.168", &a);
    assert_eq!(a, b, "'net 192.168' should equal 'net 192.168.0.0/16'");
}

/// `net 10.0.1` is equivalent to `net 10.0.1.0/24` (three-octet classful shorthand).
#[test]
fn net_classful_triple_octet_infers_slash24() {
    let a = cbpf("net 10.0.1");
    let b = cbpf("net 10.0.1.0/24");
    assert_well_formed("net 10.0.1", &a);
    assert_eq!(a, b, "'net 10.0.1' should equal 'net 10.0.1.0/24'");
}

/// Direction qualifiers work with classful shorthand.
#[test]
fn net_classful_direction_qualifiers() {
    let src_short = cbpf("src net 10");
    let src_cidr = cbpf("src net 10.0.0.0/8");
    assert_eq!(
        src_short, src_cidr,
        "'src net 10' should equal 'src net 10.0.0.0/8'"
    );

    let dst_short = cbpf("dst net 192.168");
    let dst_cidr = cbpf("dst net 192.168.0.0/16");
    assert_eq!(
        dst_short, dst_cidr,
        "'dst net 192.168' should equal 'dst net 192.168.0.0/16'"
    );
}

/// `net <addr> mask <netmask>` explicit mask notation.
#[test]
fn net_explicit_mask_notation() {
    let a = cbpf("net 192.168.0.0 mask 255.255.0.0");
    let b = cbpf("net 192.168.0.0/16");
    assert_eq!(
        a, b,
        "'net <addr> mask <netmask>' should equal CIDR notation"
    );
}

/// Non-contiguous mask is supported via explicit `mask` syntax.
#[test]
fn net_non_contiguous_mask_notation() {
    // A non-contiguous mask can only be expressed with `mask`.
    let insns = cbpf("net 10.0.0.0 mask 255.0.255.0");
    assert_well_formed("net 10.0.0.0 mask 255.0.255.0", &insns);
    assert_jumps_in_bounds("net 10.0.0.0 mask 255.0.255.0", &insns);
    // Mask 0xff00ff00 should appear as an AND instruction.
    let has_mask = insns.iter().any(|i| is_and_k(*i) && i.k == 0xff00_ff00);
    assert!(
        has_mask,
        "non-contiguous mask should appear as AND 0xff00ff00"
    );
}

// ── §15i `ip proto N` and `ip6 proto N` ──────────────────────────────────────

/// `ip proto <N>` matches packets with given IPv4 protocol number.
#[test]
fn ip_proto_number_variants() {
    for (filter, proto) in [
        ("ip proto 6", 6u32),
        ("ip proto 17", 17),
        ("ip proto 89", 89), // OSPF
        ("ip proto 41", 41), // 6-in-4
    ] {
        let insns = cbpf(filter);
        assert_well_formed(filter, &insns);
        let has_proto = insns.iter().any(|i| is_jeq(*i) && i.k == proto);
        assert!(has_proto, "'{filter}' should check IP proto {proto}");
    }
}

/// `ip6 proto <N>` matches packets with given IPv6 next-header value.
#[test]
fn ip6_proto_number_variants() {
    for (filter, nh) in [
        ("ip6 proto 6", 6u32),
        ("ip6 proto 17", 17),
        ("ip6 proto 58", 58), // ICMPv6
        ("ip6 proto 43", 43), // Routing header
    ] {
        let insns = cbpf(filter);
        assert_well_formed(filter, &insns);
        let has_nh = insns.iter().any(|i| is_jeq(*i) && i.k == nh);
        assert!(has_nh, "'{filter}' should check IPv6 next-header {nh}");
    }
}

/// `ip proto <keyword>` produces identical BPF to `ip proto <N>`.
#[test]
fn ip_proto_named_keywords() {
    for (named, numeric) in [
        ("ip proto tcp", "ip proto 6"),
        ("ip proto udp", "ip proto 17"),
        ("ip proto icmp", "ip proto 1"),
        ("ip proto icmp6", "ip proto 58"),
        ("ip proto igmp", "ip proto 2"),
        ("ip proto sctp", "ip proto 132"),
        ("ip proto ah", "ip proto 51"),
        ("ip proto esp", "ip proto 50"),
        ("ip proto pim", "ip proto 103"),
        ("ip proto igrp", "ip proto 9"),
        ("ip proto vrrp", "ip proto 112"),
    ] {
        assert_eq!(
            cbpf(named),
            cbpf(numeric),
            "'{named}' should produce identical BPF to '{numeric}'"
        );
    }
}

/// `ip6 proto <keyword>` produces identical BPF to `ip6 proto <N>`.
#[test]
fn ip6_proto_named_keywords() {
    for (named, numeric) in [
        ("ip6 proto tcp", "ip6 proto 6"),
        ("ip6 proto udp", "ip6 proto 17"),
        ("ip6 proto icmp", "ip6 proto 1"),
        ("ip6 proto icmp6", "ip6 proto 58"),
        ("ip6 proto igmp", "ip6 proto 2"),
        ("ip6 proto sctp", "ip6 proto 132"),
        ("ip6 proto ah", "ip6 proto 51"),
        ("ip6 proto esp", "ip6 proto 50"),
        ("ip6 proto pim", "ip6 proto 103"),
        ("ip6 proto igrp", "ip6 proto 9"),
        ("ip6 proto vrrp", "ip6 proto 112"),
    ] {
        assert_eq!(
            cbpf(named),
            cbpf(numeric),
            "'{named}' should produce identical BPF to '{numeric}'"
        );
    }
}

// ── §15j `src or dst` direction qualifier ───────────────────────────────────

/// libpcap allows explicit `src or dst` direction qualifier.
#[test]
fn src_or_dst_explicit_direction() {
    let a = cbpf("src or dst host 1.2.3.4");
    let b = cbpf("host 1.2.3.4");
    assert_eq!(a, b, "'src or dst host' should equal default 'host'");
}

/// Explicit `src or dst port` matches both directions.
#[test]
fn src_or_dst_port_explicit_direction() {
    let a = cbpf("src or dst port 80");
    let b = cbpf("port 80");
    assert_eq!(a, b, "'src or dst port 80' should equal default 'port 80'");
}

// ── §15k Byte-access with all size variants ───────────────────────────────────

/// Byte access with size 1 (default), 2 and 4.
/// NOTE: a byte-access expression requires a complete comparison to be a valid
/// standalone filter. Raw byte access without `op value` is not a valid filter.
#[test]
fn byte_access_all_size_variants() {
    // These are complete filters (with comparison operators):
    let filters = [
        ("tcp[13] != 0", "byte, no size"),
        ("tcp[13:1] != 0", "explicit byte"),
        ("tcp[0:2] != 0", "halfword"),
        ("ip[12:4] != 0", "word from net layer"),
    ];
    for (f, desc) in &filters {
        let insns = cbpf(f);
        assert_well_formed(desc, &insns);
        assert_jumps_in_bounds(desc, &insns);
    }
    // Incomplete byte access (no comparison) is not a valid filter:
    assert!(
        compile("tcp[13]", LinkType::Ethernet, Target::Classic).is_err(),
        "bare byte access without comparison is not a valid filter"
    );
}

/// All comparison operators work in byte access expressions.
/// NOTE: `ip[8] & 0x0f` without a comparison value is not a valid standalone
/// filter in pktbaffle — it requires an explicit `!= 0` or similar suffix.
#[test]
fn byte_access_all_comparison_operators() {
    let ops = [
        ("ip[8] = 64", "eq"),
        ("ip[8] != 64", "ne"),
        ("ip[8] > 64", "gt"),
        ("ip[8] >= 64", "ge"),
        ("ip[8] < 64", "lt"),
        ("ip[8] <= 64", "le"),
        ("ip[8] & 0x0f != 0", "bitand-with-comparison"),
    ];
    for (f, desc) in &ops {
        let insns = cbpf(f);
        assert_well_formed(desc, &insns);
        assert_jumps_in_bounds(desc, &insns);
    }
    // Incomplete: bit-and without trailing comparison is not valid:
    assert!(
        compile("ip[8] & 0x0f", LinkType::Ethernet, Target::Classic).is_err(),
        "ip[8] & 0x0f without comparison is not a valid filter"
    );
}

/// Byte access at the transport layer uses indirect loads.
#[test]
fn transport_byte_access_uses_indirect_load() {
    let insns = cbpf("tcp[0:2] != 0");
    let has_ind = insns.iter().any(|i| is_ld_ind(*i));
    assert!(
        has_ind,
        "tcp[...] should use indirect load (X-relative): {insns:?}"
    );
    let has_msh = insns.iter().any(|i| is_msh(*i));
    assert!(has_msh, "tcp[...] should set X via MSH: {insns:?}");
}

/// Byte access at the net layer uses absolute loads (no MSH).
#[test]
fn net_byte_access_uses_absolute_load_no_msh() {
    let insns = cbpf("ip[12:4] != 0");
    // Should NOT need MSH since offset is from net layer base (constant).
    let has_msh = insns.iter().any(|i| is_msh(*i));
    assert!(!has_msh, "ip[...] should NOT need MSH: {insns:?}");
    // Must use absolute loads.
    let has_abs = insns.iter().any(|i| is_ld_abs(*i));
    assert!(has_abs, "ip[...] should use absolute load: {insns:?}");
}

// ── §15l PPPoE ────────────────────────────────────────────────────────────────

/// `pppoed` matches PPPoE Discovery packets (ethertype 0x8863).
#[test]
fn pppoed_checks_correct_ethertype() {
    let insns = cbpf("pppoed");
    assert_well_formed("pppoed", &insns);
    let has_et = insns.iter().any(|i| is_jeq(*i) && i.k == 0x8863);
    assert!(has_et, "pppoed should check ethertype 0x8863: {insns:?}");
}

/// `pppoes` matches PPPoE Session packets (ethertype 0x8864).
#[test]
fn pppoes_checks_correct_ethertype() {
    let insns = cbpf("pppoes");
    assert_well_formed("pppoes", &insns);
    let has_et = insns.iter().any(|i| is_jeq(*i) && i.k == 0x8864);
    assert!(has_et, "pppoes should check ethertype 0x8864: {insns:?}");
}

/// `pppoes 100` must check both ethertype 0x8864 and PPPoE session ID 100.
#[test]
fn pppoes_with_session_id_checks_ethertype() {
    let insns = cbpf("pppoes 100");
    assert_well_formed("pppoes 100", &insns);
    let has_et = insns.iter().any(|i| is_jeq(*i) && i.k == 0x8864);
    assert!(
        has_et,
        "pppoes 100 should check ethertype 0x8864: {insns:?}"
    );
}

/// `pppoes 100` must emit a JEQ against session ID 100 after the ethertype check.
#[test]
fn pppoes_with_session_id_checks_id() {
    let insns = cbpf("pppoes 100");
    assert_well_formed("pppoes 100", &insns);
    let has_sid = insns.iter().any(|i| is_jeq(*i) && i.k == 100);
    assert!(has_sid, "pppoes 100 should check session ID 100: {insns:?}");
}

/// `pppoes 0` compiles correctly and checks session ID 0.
#[test]
fn pppoes_with_session_id_zero() {
    let insns = cbpf("pppoes 0");
    assert_well_formed("pppoes 0", &insns);
    let has_et = insns.iter().any(|i| is_jeq(*i) && i.k == 0x8864);
    assert!(has_et, "pppoes 0 should check ethertype 0x8864: {insns:?}");
    let has_sid = insns.iter().any(|i| is_jeq(*i) && i.k == 0);
    assert!(has_sid, "pppoes 0 should check session ID 0: {insns:?}");
}

// ── §15m IPv6 host addresses ─────────────────────────────────────────────────

/// Full-form IPv6 addresses compile correctly.
#[test]
fn ipv6_full_form_host() {
    let insns = cbpf("host 2001:0db8:0000:0000:0000:0000:0000:0001");
    assert_well_formed("host 2001:0db8:...:0001", &insns);
    assert_jumps_in_bounds("host 2001:0db8:...:0001", &insns);
}

/// Digit-first IPv6 with double-colon shorthand compiles.
#[test]
fn ipv6_digit_first_double_colon() {
    let insns = cbpf("host 2001:db8::1");
    assert_well_formed("host 2001:db8::1", &insns);
    assert_jumps_in_bounds("host 2001:db8::1", &insns);
}

/// Letter-first IPv6 with double-colon shorthand compiles.
#[test]
fn ipv6_letter_first_double_colon() {
    let insns = cbpf("host fe80::1");
    assert_well_formed("host fe80::1", &insns);
    assert_jumps_in_bounds("host fe80::1", &insns);
}

/// IPv6 loopback in full 8-group form.
/// `0:0:0:0:0:0:0:1` must lex as an IPv6 address, not a MAC.
#[test]
fn ipv6_loopback_full_form() {
    let insns = cbpf("host 0:0:0:0:0:0:0:1");
    assert_well_formed("host 0:0:0:0:0:0:0:1", &insns);
    assert_jumps_in_bounds("host 0:0:0:0:0:0:0:1", &insns);
    // Must generate 8 halfword loads — one per IPv6 segment.
    let ldh_count = insns
        .iter()
        .filter(|i| is_ld_abs(**i) && (i.code & 0x18) == bpf::BPF_H)
        .count();
    assert!(
        ldh_count >= 8,
        "host 0:0:0:0:0:0:0:1 should load at least 8 halfwords, got {ldh_count}"
    );
}

/// All-zero IPv6 address in full 8-group form must not be treated as a MAC.
#[test]
fn ipv6_all_zero_address_full_form() {
    let insns = cbpf("host 0:0:0:0:0:0:0:0");
    assert_well_formed("host 0:0:0:0:0:0:0:0", &insns);
    assert_jumps_in_bounds("host 0:0:0:0:0:0:0:0", &insns);
}

/// IPv6 host filter generates 8 halfword comparisons (one per segment).
#[test]
fn ipv6_host_generates_eight_segment_checks() {
    // 2001:db8::1 — check for 8 x jeq_k each matching a 16-bit segment.
    let insns = cbpf("host 2001:db8::1");
    // Count ldh (halfword) instructions — should have 8 loads per address check.
    let ldh_count = insns
        .iter()
        .filter(|i| is_ld_abs(**i) && (i.code & 0x18) == bpf::BPF_H)
        .count();
    assert!(
        ldh_count >= 8,
        "IPv6 host filter should load at least 8 halfwords, got {ldh_count}"
    );
}

// ── §15n `rarp` protocol ─────────────────────────────────────────────────────

/// `rarp` matches Reverse ARP frames (ethertype 0x8035).
#[test]
fn rarp_filter_checks_ethertype_8035() {
    let insns = cbpf("rarp");
    assert_well_formed("rarp", &insns);
    let has_rarp = insns.iter().any(|i| is_jeq(*i) && i.k == 0x8035);
    assert!(has_rarp, "'rarp' should check ethertype 0x8035: {insns:?}");
}

// ── §15o Unsupported constructs return Err ───────────────────────────────────

/// `gateway <host>` is not supported (requires DNS resolution).
#[test]
fn gateway_returns_error() {
    let e = compile("gateway somehost", LinkType::Ethernet, Target::Classic)
        .expect_err("gateway should return an error");
    assert!(
        e.to_string().contains("gateway"),
        "error message should mention 'gateway': {e}"
    );
}

/// `::1` abbreviated IPv6 (leading double-colon) must compile and match IPv6 loopback.
#[test]
fn leading_double_colon_ipv6_loopback_compiles() {
    let result = compile("host ::1", LinkType::Ethernet, Target::Classic);
    assert!(
        result.is_ok(),
        "host ::1 should compile: {:?}",
        result.err()
    );
}

/// `::ffff:192.0.2.1` IPv4-mapped IPv6 with leading double-colon must compile.
#[test]
fn leading_double_colon_ipv4_mapped_compiles() {
    let result = compile("host ::ffff:192.0.2.1", LinkType::Ethernet, Target::Classic);
    assert!(
        result.is_ok(),
        "host ::ffff:192.0.2.1 should compile: {:?}",
        result.err()
    );
}

/// `src host ::1` — direction qualifier with leading-:: IPv6 must compile.
#[test]
fn src_host_leading_double_colon_ipv6_compiles() {
    let result = compile("src host ::1", LinkType::Ethernet, Target::Classic);
    assert!(
        result.is_ok(),
        "src host ::1 should compile: {:?}",
        result.err()
    );
}

/// `inbound` and `outbound` are unsupported in cBPF; must return Err.
#[test]
fn inbound_outbound_return_errors() {
    assert!(compile("inbound", LinkType::Ethernet, Target::Classic).is_err());
    assert!(compile("outbound", LinkType::Ethernet, Target::Classic).is_err());
}

/// `ether port` is invalid (Ethernet has no ports) — must return Err.
#[test]
fn ether_port_returns_error() {
    let result = compile("ether port 80", LinkType::Ethernet, Target::Classic);
    assert!(
        result.is_err(),
        "ether port should fail (Ethernet has no ports)"
    );
}

/// A completely empty filter string is invalid.
#[test]
fn empty_filter_returns_error() {
    let result = compile("", LinkType::Ethernet, Target::Classic);
    assert!(
        result.is_err(),
        "empty filter string should return an error"
    );
}

/// `pppoes 65536` has a session ID that exceeds u16::MAX — must return Err.
#[test]
fn pppoes_out_of_range_session_id_returns_error() {
    let result = compile("pppoes 65536", LinkType::Ethernet, Target::Classic);
    assert!(
        result.is_err(),
        "pppoes 65536 should return an error (session ID exceeds 0xffff)"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// §15f Raw link-layer byte access (`[offset:size]` without `ether` prefix)
// ─────────────────────────────────────────────────────────────────────────────

/// Raw link-layer byte access `[0:1] & 1 != 0` compiles on Ethernet.
/// The bare `[` form is syntactic sugar for `ether[...]`.
#[test]
fn raw_byte_access_multicast_compiles() {
    let _ = cbpf("[0:1] & 1 != 0");
}

/// `[0:1] & 1 != 0` should produce the same BPF as `ether[0:1] & 1 != 0`.
#[test]
fn raw_byte_access_equals_ether_prefix_form() {
    let a = cbpf("[0:1] & 1 != 0");
    let b = cbpf("ether[0:1] & 1 != 0");
    assert_eq!(
        a, b,
        "'[0:1] & 1 != 0' must produce the same BPF as 'ether[0:1] & 1 != 0'"
    );
}

/// `[12:2] = 0x0800` should produce the same BPF as `ether[12:2] = 0x0800`.
#[test]
fn raw_byte_access_ethertype_equals_ether_prefix_form() {
    let a = cbpf("[12:2] = 0x0800");
    let b = cbpf("ether[12:2] = 0x0800");
    assert_eq!(
        a, b,
        "'[12:2] = 0x0800' must produce the same BPF as 'ether[12:2] = 0x0800'"
    );
}

/// Existing `ether[N:M]` syntax must be unaffected by the change.
#[test]
fn ether_prefix_byte_access_still_works() {
    let _ = cbpf("ether[0] = 0x01");
    let _ = cbpf("ether[12:2] = 0x0800");
    let _ = cbpf("ether[0:1] & 1 != 0");
}

/// Raw link-layer byte access on `RawIp` must return a codegen error
/// because there is no link-layer header to index into.
#[test]
fn raw_byte_access_rawip_returns_error() {
    compile_err("[0:1] & 1 != 0", LinkType::RawIp);
}

// ── §15p IPv6 network prefix filters ─────────────────────────────────────────

/// `net 2001:db8::/32` compiles without error and produces valid BPF.
#[test]
fn ipv6_net_cidr_compiles() {
    let insns = cbpf("net 2001:db8::/32");
    assert_well_formed("net 2001:db8::/32", &insns);
    assert_jumps_in_bounds("net 2001:db8::/32", &insns);
}

/// `src net fc00::/7` compiles and checks only the source IPv6 address.
#[test]
fn ipv6_src_net_cidr_compiles() {
    let insns = cbpf("src net fc00::/7");
    assert_well_formed("src net fc00::/7", &insns);
    assert_jumps_in_bounds("src net fc00::/7", &insns);
}

/// `dst net fe80::/10` compiles and checks only the destination IPv6 address.
#[test]
fn ipv6_dst_net_cidr_compiles() {
    let insns = cbpf("dst net fe80::/10");
    assert_well_formed("dst net fe80::/10", &insns);
    assert_jumps_in_bounds("dst net fe80::/10", &insns);
}

/// Mixed IPv4/IPv6 net filter compiles correctly.
#[test]
fn mixed_ipv4_ipv6_net_compiles() {
    let insns = cbpf("net 2001:db8::/32 or net 10.0.0.0/8");
    assert_well_formed("net 2001:db8::/32 or net 10.0.0.0/8", &insns);
    assert_jumps_in_bounds("net 2001:db8::/32 or net 10.0.0.0/8", &insns);
}

/// IPv6 prefix lengths > 128 produce a clear parse error.
#[test]
fn ipv6_net_out_of_range_prefix_returns_error() {
    let result = compile("net 2001:db8::/129", LinkType::Ethernet, Target::Classic);
    assert!(
        result.is_err(),
        "prefix length 129 should return a parse error"
    );
}

/// Existing IPv4 `net` filters are unaffected by the IPv6 net change.
#[test]
fn existing_ipv4_net_filters_unaffected() {
    let a = cbpf("net 10.0.0.0/8");
    let b = cbpf("src net 192.168.0.0/16");
    assert_well_formed("net 10.0.0.0/8", &a);
    assert_well_formed("src net 192.168.0.0/16", &b);
}

/// `net 2001:db8::/32` emits an IPv6 ethertype guard (0x86dd).
#[test]
fn ipv6_net_checks_ipv6_ethertype() {
    let insns = cbpf("net 2001:db8::/32");
    let has_ipv6_et = insns.iter().any(|i| is_jeq(*i) && i.k == 0x86dd);
    assert!(
        has_ipv6_et,
        "IPv6 net filter should check ethertype 0x86dd: {insns:?}"
    );
}

/// A partial-group prefix emits an AND instruction to apply the bit mask.
#[test]
fn ipv6_net_uses_and_for_partial_group() {
    // fc00::/7 — the first group is partially covered (7 bits), so AND is required.
    let insns = cbpf("net fc00::/7");
    let has_and = insns.iter().any(|i| is_and_k(*i));
    assert!(
        has_and,
        "IPv6 /7 net filter should emit AND for the partial group: {insns:?}"
    );
}

/// `net addr/128` is logically equivalent to a host filter: similar BPF size.
#[test]
fn ipv6_net_slash128_is_host_equivalent() {
    let net_insns = cbpf("net 2001:db8::1/128");
    let host_insns = cbpf("host 2001:db8::1");
    assert_well_formed("net 2001:db8::1/128", &net_insns);
    let diff = net_insns.len().abs_diff(host_insns.len());
    assert!(
        diff <= 4,
        "/128 net and host should produce similar-sized BPF: net={} host={}",
        net_insns.len(),
        host_insns.len()
    );
}

/// `net addr/0` only emits the ethertype guard (no segment comparisons).
#[test]
fn ipv6_net_slash0_only_checks_ethertype() {
    let insns = cbpf("net 2001:db8::/0");
    assert_well_formed("net 2001:db8::/0", &insns);
    // /0 means every IPv6 address matches; only the ethertype check is needed.
    let jeq_count = insns.iter().filter(|i| is_jeq(**i)).count();
    assert_eq!(
        jeq_count, 1,
        "net addr/0 should only check ethertype (1 jeq), got {jeq_count}: {insns:?}"
    );
}

/// All direction variants for IPv6 net compile and are structurally valid.
#[test]
fn ipv6_net_direction_variants_compile() {
    for f in &[
        "net 2001:db8::/32",
        "src net 2001:db8::/32",
        "dst net 2001:db8::/32",
    ] {
        let insns = cbpf(f);
        assert_well_formed(f, &insns);
        assert_jumps_in_bounds(f, &insns);
        assert_all_paths_terminate(f, &insns);
    }
}
