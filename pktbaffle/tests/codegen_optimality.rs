use pktbaffle::{compile, bpf, ebpf, LinkType, Target};

// ── Helpers ──────────────────────────────────────────────────────────────────

fn compile_cbpf(filter: &str) -> Vec<bpf::Insn> {
    compile(filter, LinkType::Ethernet, Target::Classic)
        .unwrap_or_else(|e| panic!("failed to compile {filter:?}: {e}"))
        .as_classic()
        .unwrap()
        .instructions()
        .to_vec()
}

fn compile_ebpf(filter: &str) -> Vec<ebpf::Insn> {
    compile(filter, LinkType::Ethernet, Target::Extended)
        .unwrap_or_else(|e| panic!("failed to compile {filter:?}: {e}"))
        .as_extended()
        .unwrap()
        .instructions()
        .to_vec()
}

// ── 1. Instruction Count Baselines ───────────────────────────────────────────

#[test]
fn test_instruction_count_baselines() {
    let variants = vec![
        // Low Complexity
        ("tcp", 20, 30),
        ("udp", 20, 30),
        ("icmp", 20, 30),
        ("host 1.2.3.4", 30, 45),
        ("port 80", 30, 50),
        
        // Medium Complexity
        ("tcp and port 80 or udp and port 53", 80, 130),
        ("net 192.168.0.0/24", 30, 50),
        ("tcp[13] & 2 != 0", 40, 50),
        
        // High Complexity
        ("tcp and (port 80 or port 443) and host 10.0.0.1", 80, 140),
        ("ip[2:2] & 0x1fff = 0", 40, 60), // bitwise mask and compare
        ("portrange 1000-2000", 40, 60),
        ("vlan 100 and ip6 and tcp port 80", 60, 90),
    ];

    for (filter, max_cbpf, max_ebpf) in variants {
        let cbpf_len = compile_cbpf(filter).len();
        assert!(
            cbpf_len <= max_cbpf,
            "cBPF instruction count regression for {filter:?}: expected <= {max_cbpf}, got {cbpf_len}"
        );

        let ebpf_len = compile_ebpf(filter).len();
        assert!(
            ebpf_len <= max_ebpf,
            "eBPF instruction count regression for {filter:?}: expected <= {max_ebpf}, got {ebpf_len}"
        );
    }
}

// ── 2. Redundancy Checks ─────────────────────────────────────────────────────

#[test]
fn test_cbpf_no_redundant_loads() {
    let filters = vec![
        "tcp and port 80",
        "tcp[13] & 2 != 0 and tcp[13] & 16 != 0",
        "ip[12:4] = 0x0a000001 and ip[16:4] = 0x0a000002",
        "vlan and ip and tcp and port 80",
    ];

    for filter in filters {
        let insns = compile_cbpf(filter);
        for i in 1..insns.len() {
            let curr = insns[i];
            let prev = insns[i - 1];

            // If it's a load absolute, it shouldn't identically match the previous load absolute
            if (curr.code & 0x07) == bpf::BPF_LD && (curr.code & 0xe0) == bpf::BPF_ABS {
                if curr.code == prev.code && curr.k == prev.k {
                    panic!(
                        "Redundant consecutive absolute load found in {filter:?}:\n  idx {i}: {curr:?}\n  prev : {prev:?}"
                    );
                }
            }
        }
    }
}

// ── 3. Equivalence Invariance ────────────────────────────────────────────────

#[test]
fn test_equivalence_invariance() {
    let pairs = vec![
        ("tcp", "ip proto 6 or ip6 proto 6"),
        ("udp", "ip proto 17 or ip6 proto 17"),
        ("icmp", "ip proto 1"),
        // "host 1.2.3.4" vs "src host 1.2.3.4 or dst host 1.2.3.4" (often parses to roughly similar logic tree)
        ("host 1.2.3.4", "src host 1.2.3.4 or dst host 1.2.3.4"),
    ];

    for (a, b) in pairs {
        let cbpf_a = compile_cbpf(a);
        let cbpf_b = compile_cbpf(b);

        // They don't have to be identical bytes, but should be roughly equivalent in length/complexity
        let diff = (cbpf_a.len() as isize - cbpf_b.len() as isize).abs();
        assert!(
            diff <= 10,
            "Equivalence divergence for {a:?} vs {b:?}: cBPF lengths {} and {}",
            cbpf_a.len(),
            cbpf_b.len()
        );

        let ebpf_a = compile_ebpf(a);
        let ebpf_b = compile_ebpf(b);

        let diff_e = (ebpf_a.len() as isize - ebpf_b.len() as isize).abs();
        assert!(
            diff_e <= 10,
            "Equivalence divergence for {a:?} vs {b:?}: eBPF lengths {} and {}",
            ebpf_a.len(),
            ebpf_b.len()
        );
    }
}

// ── 4. eBPF Bounds Check Safeties ────────────────────────────────────────────

#[test]
fn test_ebpf_bounds_checks_present() {
    // In eBPF, every packet data access must be preceded by a bounds check.
    // A bounds check typically looks like a comparison with R3 (data_end).
    let filters = vec![
        "tcp", // checks ethernet + ip + tcp bounds
        "tcp[13] & 2 != 0", // checks deeper into TCP
    ];

    for filter in filters {
        let insns = compile_ebpf(filter);
        
        // Count jumps that use R3 (data_end)
        let bounds_checks = insns.iter().filter(|i| {
            // Is it a jump instruction?
            let class = i.code & 0x07;
            let is_jmp = class == ebpf::BPF_JMP || class == ebpf::BPF_JMP32;
            
            // Does it compare against R3?
            // R3 is either src or dst in the regs byte: `(dst & 0xf) | ((src & 0xf) << 4)`
            let src = (i.regs >> 4) & 0xf;
            let dst = i.regs & 0xf;
            
            is_jmp && (src == ebpf::R3 || dst == ebpf::R3)
        }).count();

        assert!(
            bounds_checks > 0,
            "No bounds checks against R3 (data_end) found in eBPF for {filter:?}"
        );
    }
}
