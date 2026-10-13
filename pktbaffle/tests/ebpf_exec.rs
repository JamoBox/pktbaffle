//! Execution-based tests for the eBPF backend (issue #219).
//!
//! `tests/ebpf.rs` only checks instruction *shape*. This file actually runs the
//! programs `Target::Extended` produces, using the test-only interpreter in
//! `tests/common/ebpf_interp.rs`, and compares them with the cBPF VM.
//!
//! # Model
//!
//! * The program runs as an XDP program: R1 = pointer to `xdp_md`, whose
//!   `data` / `data_end` words (offsets 0 and 4) are 32-bit loads. R0 at `exit`
//!   is the verdict: `XDP_PASS` (2) = match, `XDP_DROP` (1) = no match.
//! * `LDX MEM` (B/H/W/DW) returns the bytes in the **selected host byte order**
//!   ([`Endian`]), zero-extended. `BPF_END` to-BE / to-LE (imm 16/32/64) swaps
//!   or truncates relative to that host. Both endiannesses are exercised.
//! * 64-bit ALU/JMP sign-extend imm32; 32-bit ALU/JMP32 use the low 32 bits and
//!   ALU32 results are zero-extended. Signed and unsigned conditional jumps are
//!   modelled, so sign-extension bugs (#132) are observable.
//! * A load outside `[data, data_end)`, an unknown opcode, an uninitialised
//!   register read, a bad jump or a bad return value is a [`Fault`], which is
//!   reported separately from "no match".
//!
//! # Limits
//!
//! This is a reference interpreter, **not the kernel verifier**. It does not
//! prove termination, track pointer types or ranges, check stack/helper/map
//! use, or enforce the kernel's per-program instruction limit; it only faults
//! on what an *execution* of the given packet actually does (so a missing bounds
//! check is caught only by a packet that is short enough to trip it). Memory is
//! just the ctx and the packet; `ST`/`STX`/`CALL`/`LD_IMM64` are unsupported.
//!
//! # Parity table
//!
//! [`FILTERS`] lists filters; each is compiled for both backends and run on
//! every packet of [`corpus`], on a little- and a big-endian host. The verdicts
//! must equal the cBPF VM's. To add a test, add one string to `FILTERS` (and a
//! packet to `corpus` if needed). Divergences that are caused by *other* open
//! issues are listed in [`KNOWN`] with the issue number; the test fails both
//! on an unlisted divergence and on a stale `KNOWN` entry that no longer
//! diverges, so the list cannot rot.

mod common;

use common::ebpf_interp::*;
use pktbaffle::ebpf::{
    Insn, BPF_ADD, BPF_ALU, BPF_ALU64, BPF_AND, BPF_B, BPF_DIV, BPF_DW, BPF_H, BPF_JEQ, BPF_JGE,
    BPF_JGT, BPF_JLE, BPF_JLT, BPF_JMP, BPF_JMP32, BPF_JNE, BPF_JSET, BPF_K, BPF_LDX, BPF_LSH,
    BPF_MEM, BPF_MOV, BPF_MUL, BPF_OR, BPF_RSH, BPF_SUB, BPF_W, BPF_X, BPF_XOR, R0, R1, R10, R2,
    R3, R4, R5, XDP_DROP, XDP_PASS,
};

use Endian::{Big, Little};

// ═════════════════════════════════════════════════════════════════════════════
// Interpreter self-tests: one hand-assembled program per instruction class.
// ═════════════════════════════════════════════════════════════════════════════

// ── Tiny assembler ───────────────────────────────────────────────────────────

fn ldx(size: u8, dst: u8, src: u8, off: i16) -> Insn {
    Insn::new(BPF_LDX | BPF_MEM | size, dst, src, off, 0)
}
fn alu64_k(op: u8, dst: u8, imm: i32) -> Insn {
    Insn::new(BPF_ALU64 | op, dst, 0, 0, imm)
}
fn alu32_k(op: u8, dst: u8, imm: i32) -> Insn {
    Insn::new(BPF_ALU | op, dst, 0, 0, imm)
}
fn alu64_x(op: u8, dst: u8, src: u8) -> Insn {
    Insn::new(BPF_ALU64 | op | BPF_X, dst, src, 0, 0)
}
fn end(to: u8, dst: u8, width: i32) -> Insn {
    Insn::new(BPF_ALU | BPF_END | to, dst, 0, 0, width)
}
fn jmp_k(class: u8, op: u8, dst: u8, imm: i32, off: i16) -> Insn {
    Insn::new(class | op, dst, 0, off, imm)
}

/// `r2 = data; r3 = data_end` — the codegen's own prologue.
fn prologue() -> Vec<Insn> {
    vec![ldx(BPF_W, R2, R1, 0), ldx(BPF_W, R3, R1, 4)]
}

/// Run `body` after the prologue and return R0.
fn r0_of(body: &[Insn], pkt: &[u8], host: Endian) -> Result<u64, Fault> {
    let mut prog = prologue();
    prog.extend_from_slice(body);
    prog.push(Insn::exit());
    exec(&prog, pkt, host)
}

const PKT8: [u8; 8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

// ── LDX MEM + the XDP ctx ────────────────────────────────────────────────────

#[test]
fn ldx_ctx_yields_packet_bounds() {
    // r0 = data_end - data == packet length, whatever the host byte order.
    let body = [Insn::mov64_reg(R0, R3), alu64_x(BPF_SUB, R0, R2)];
    for host in [Little, Big] {
        assert_eq!(r0_of(&body, &PKT8, host), Ok(8), "{host:?}");
        assert_eq!(r0_of(&body, &[0; 100], host), Ok(100), "{host:?}");
        assert_eq!(r0_of(&body, &[], host), Ok(0), "{host:?}");
    }
}

#[test]
fn ldx_sizes_follow_host_byte_order() {
    let load = |size, off, host| r0_of(&[ldx(size, R0, R2, off)], &PKT8, host);
    // (size, offset, little-endian value, big-endian value)
    let cases = [
        (BPF_B, 0, 0x01, 0x01),
        (BPF_B, 7, 0x08, 0x08),
        (BPF_H, 0, 0x0201, 0x0102),
        (BPF_H, 1, 0x0302, 0x0203),
        (BPF_W, 0, 0x0403_0201, 0x0102_0304),
        (BPF_W, 4, 0x0807_0605, 0x0506_0708),
        (BPF_DW, 0, 0x0807_0605_0403_0201, 0x0102_0304_0506_0708),
    ];
    for (size, off, le, be) in cases {
        assert_eq!(
            load(size, off, Little),
            Ok(le),
            "LE size={size:#x} off={off}"
        );
        assert_eq!(load(size, off, Big), Ok(be), "BE size={size:#x} off={off}");
    }
}

#[test]
fn ldx_outside_packet_faults() {
    let load = |size, off: i16| r0_of(&[ldx(size, R0, R2, off)], &PKT8, Little);
    assert!(load(BPF_W, 4).is_ok(), "last whole word is in range");
    assert!(matches!(
        load(BPF_W, 5),
        Err(Fault::OutOfBounds { size: 4, .. })
    ));
    assert!(matches!(load(BPF_B, 8), Err(Fault::OutOfBounds { .. })));
    assert!(matches!(load(BPF_B, -1), Err(Fault::OutOfBounds { .. })));
    // Through data_end rather than data.
    let past = [ldx(BPF_B, R0, R3, 0)];
    assert!(matches!(
        r0_of(&past, &PKT8, Big),
        Err(Fault::OutOfBounds { .. })
    ));
    assert!(r0_of(&[ldx(BPF_B, R0, R3, -1)], &PKT8, Big).is_ok());
}

#[test]
fn ldx_ctx_only_allows_aligned_word_loads() {
    let run = |load| exec(&[load, Insn::exit()], &PKT8, Little);
    assert!(matches!(
        run(ldx(BPF_H, R0, R1, 0)),
        Err(Fault::BadCtxAccess { size: 2, .. })
    ));
    assert!(matches!(
        run(ldx(BPF_W, R0, R1, 2)),
        Err(Fault::BadCtxAccess { .. })
    ));
    // One word past `data_end` is neither ctx nor packet.
    assert!(matches!(
        run(ldx(BPF_W, R0, R1, 8)),
        Err(Fault::OutOfBounds { .. })
    ));
}

// ── ALU / ALU64 ──────────────────────────────────────────────────────────────

#[test]
fn alu32_wraps_and_zero_extends() {
    for host in [Little, Big] {
        // 64-bit -1, then a 32-bit op: upper half must be cleared.
        let neg1 = alu64_k(BPF_MOV, R0, -1);
        assert_eq!(r0_of(&[neg1], &PKT8, host), Ok(u64::MAX));
        assert_eq!(r0_of(&[neg1, alu32_k(BPF_ADD, R0, 1)], &PKT8, host), Ok(0));
        assert_eq!(
            r0_of(&[neg1, alu32_k(BPF_AND, R0, 0xff)], &PKT8, host),
            Ok(0xff)
        );
        // 32-bit subtraction wraps at 32 bits, not 64.
        assert_eq!(
            r0_of(
                &[alu32_k(BPF_MOV, R0, 0), alu32_k(BPF_SUB, R0, 1)],
                &PKT8,
                host
            ),
            Ok(0xffff_ffff)
        );
        // mov32 of a "negative" imm is zero-extended, mov64 is sign-extended.
        assert_eq!(
            r0_of(&[alu32_k(BPF_MOV, R0, i32::MIN)], &PKT8, host),
            Ok(0x8000_0000)
        );
        assert_eq!(
            r0_of(&[alu64_k(BPF_MOV, R0, i32::MIN)], &PKT8, host),
            Ok(0xffff_ffff_8000_0000)
        );
    }
}

#[test]
fn alu_ops_match_rust_semantics() {
    // Seed r0 with D via an 8-byte little-endian load, apply `op r0, imm`.
    const D: u64 = 0xf000_0000_8765_4321;
    let seed = [ldx(BPF_DW, R0, R2, 0)];
    let pkt = D.to_le_bytes();
    let run = |class_op: Insn| {
        let mut body = seed.to_vec();
        body.push(class_op);
        r0_of(&body, &pkt, Little)
    };
    let (d32, imm) = (D as u32, 4i32);
    let s = imm as u64;
    let cases: [(u8, u64, u32); 9] = [
        (BPF_ADD, D.wrapping_add(s), d32.wrapping_add(imm as u32)),
        (BPF_SUB, D.wrapping_sub(s), d32.wrapping_sub(imm as u32)),
        (BPF_MUL, D.wrapping_mul(s), d32.wrapping_mul(imm as u32)),
        (BPF_DIV, D / s, d32 / imm as u32),
        (BPF_OR, D | s, d32 | imm as u32),
        (BPF_AND, D & s, d32 & imm as u32),
        (BPF_XOR, D ^ s, d32 ^ imm as u32),
        (BPF_LSH, D << 4, d32 << 4),
        (BPF_RSH, D >> 4, d32 >> 4),
    ];
    for (op, want64, want32) in cases {
        assert_eq!(run(alu64_k(op, R0, imm)), Ok(want64), "alu64 op={op:#x}");
        assert_eq!(
            run(alu32_k(op, R0, imm)),
            Ok(want32 as u64),
            "alu32 op={op:#x}"
        );
    }
    assert_eq!(run(alu64_k(BPF_MOD, R0, 7)), Ok(D % 7));
    assert_eq!(run(alu32_k(BPF_MOD, R0, 7)), Ok((d32 % 7) as u64));
    assert_eq!(run(alu64_k(BPF_NEG, R0, 0)), Ok(D.wrapping_neg()));
    assert_eq!(run(alu64_k(BPF_ARSH, R0, 4)), Ok(((D as i64) >> 4) as u64));
    assert_eq!(
        run(alu32_k(BPF_ARSH, R0, 4)),
        Ok(((d32 as i32) >> 4) as u32 as u64)
    );
    // Register source.
    let reg_src = [
        ldx(BPF_DW, R4, R2, 0),
        alu64_k(BPF_MOV, R0, 1),
        alu64_x(BPF_ADD, R0, R4),
    ];
    assert_eq!(r0_of(&reg_src, &pkt, Little), Ok(D.wrapping_add(1)));
}

#[test]
fn alu_faults() {
    let div0 = [alu64_k(BPF_MOV, R0, 1), alu64_k(BPF_DIV, R0, 0)];
    assert!(matches!(
        r0_of(&div0, &PKT8, Little),
        Err(Fault::DivByZero { .. })
    ));
    let shift = [alu64_k(BPF_MOV, R0, 1), alu32_k(BPF_LSH, R0, 32)];
    assert!(matches!(
        r0_of(&shift, &PKT8, Little),
        Err(Fault::BadShift { .. })
    ));
    let shift64 = [alu64_k(BPF_MOV, R0, 1), alu64_k(BPF_LSH, R0, 63)];
    assert_eq!(r0_of(&shift64, &PKT8, Little), Ok(1 << 63));
    // r0 = r4 where r4 was never written.
    let uninit = [Insn::mov64_reg(R0, R4)];
    assert_eq!(
        r0_of(&uninit, &PKT8, Little),
        Err(Fault::UninitRegister { pc: 2, reg: 4 })
    );
    let r10 = [alu64_k(BPF_MOV, R10, 0)];
    assert!(matches!(
        r0_of(&r10, &PKT8, Little),
        Err(Fault::WriteToR10 { .. })
    ));
}

// ── BPF_END ──────────────────────────────────────────────────────────────────

#[test]
fn end_swaps_relative_to_host_and_zero_extends() {
    // Seed r0 = V on either host (pick the packet bytes so the DW load yields V).
    const V: u64 = 0xdead_beef_1234_5678;
    let run = |to, width, host| {
        let pkt = match host {
            Little => V.to_le_bytes(),
            Big => V.to_be_bytes(),
        };
        r0_of(&[ldx(BPF_DW, R0, R2, 0), end(to, R0, width)], &pkt, host)
    };
    // to-BE: swap on a little-endian host, truncate only on big-endian.
    assert_eq!(run(BPF_TO_BE, 16, Little), Ok(0x7856));
    assert_eq!(run(BPF_TO_BE, 16, Big), Ok(0x5678));
    assert_eq!(run(BPF_TO_BE, 32, Little), Ok(0x7856_3412));
    assert_eq!(run(BPF_TO_BE, 32, Big), Ok(0x1234_5678));
    assert_eq!(run(BPF_TO_BE, 64, Little), Ok(V.swap_bytes()));
    assert_eq!(run(BPF_TO_BE, 64, Big), Ok(V));
    // to-LE: the mirror image.
    assert_eq!(run(BPF_TO_LE, 16, Big), Ok(0x7856));
    assert_eq!(run(BPF_TO_LE, 16, Little), Ok(0x5678));
    assert_eq!(run(BPF_TO_LE, 32, Big), Ok(0x7856_3412));
    assert_eq!(run(BPF_TO_LE, 32, Little), Ok(0x1234_5678));
    assert_eq!(run(BPF_TO_LE, 64, Big), Ok(V.swap_bytes()));
    assert_eq!(run(BPF_TO_LE, 64, Little), Ok(V));
}

#[test]
fn end_makes_loads_network_order_on_either_host() {
    // The property the eBPF codegen relies on: ldx + to-BE == the packet's
    // big-endian value, independent of the host.
    for host in [Little, Big] {
        let h = [ldx(BPF_H, R0, R2, 0), end(BPF_TO_BE, R0, 16)];
        assert_eq!(r0_of(&h, &PKT8, host), Ok(0x0102), "{host:?}");
        let w = [ldx(BPF_W, R0, R2, 2), end(BPF_TO_BE, R0, 32)];
        assert_eq!(r0_of(&w, &PKT8, host), Ok(0x0304_0506), "{host:?}");
    }
}

#[test]
fn end_rejects_bad_width_and_alu64_form() {
    let bad = [alu64_k(BPF_MOV, R0, 1), end(BPF_TO_BE, R0, 8)];
    assert!(matches!(
        r0_of(&bad, &PKT8, Little),
        Err(Fault::BadEndWidth { imm: 8, .. })
    ));
    // ALU64|END (bswap) is a newer kernel opcode the codegen never emits.
    let alu64_end = Insn::new(BPF_ALU64 | BPF_END | BPF_TO_LE, R0, 0, 0, 16);
    assert!(matches!(
        r0_of(&[alu64_k(BPF_MOV, R0, 1), alu64_end], &PKT8, Little),
        Err(Fault::UnknownOpcode { .. })
    ));
}

// ── JMP / JMP32 ──────────────────────────────────────────────────────────────

/// Whether `class|op r, imm` is taken when r holds `a` (loaded as 8 raw bytes).
fn taken(class: u8, op: u8, a: u64, imm: i32) -> bool {
    let body = [
        ldx(BPF_DW, R4, R2, 0),
        alu64_k(BPF_MOV, R0, 0),
        jmp_k(class, op, R4, imm, 1), // taken: skip the `ja`
        Insn::ja(1),                  // not taken: skip the `mov r0, 1`
        alu64_k(BPF_MOV, R0, 1),
    ];
    r0_of(&body, &a.to_le_bytes(), Little).unwrap() == 1
}

#[test]
fn jmp64_compares_against_sign_extended_imm32() {
    // r4 = 0x8000_0000. The imm32 0x8000_0000 sign-extends to
    // 0xffff_ffff_8000_0000 for a 64-bit compare, so they are NOT equal (#132).
    assert!(!taken(BPF_JMP, BPF_JEQ, 0x8000_0000, i32::MIN));
    assert!(taken(BPF_JMP, BPF_JNE, 0x8000_0000, i32::MIN));
    assert!(taken(BPF_JMP, BPF_JEQ, 0xffff_ffff_8000_0000, i32::MIN));
    assert!(taken(BPF_JMP, BPF_JEQ, u64::MAX, -1));
    assert!(!taken(BPF_JMP, BPF_JEQ, 0xffff_ffff, -1));
    // Unsigned ordering: sign-extended imm is a huge unsigned value.
    assert!(taken(BPF_JMP, BPF_JLT, 5, -1));
    assert!(taken(BPF_JMP, BPF_JGT, u64::MAX, 1));
    assert!(taken(BPF_JMP, BPF_JGE, 7, 7));
    assert!(taken(BPF_JMP, BPF_JLE, 7, 7));
    assert!(!taken(BPF_JMP, BPF_JGT, 7, 7));
    assert!(taken(BPF_JMP, BPF_JSET, 0b101, 0b100));
    assert!(!taken(BPF_JMP, BPF_JSET, 0b101, 0b010));
}

#[test]
fn jmp32_compares_low_32_bits_only() {
    assert!(taken(BPF_JMP32, BPF_JEQ, 0x8000_0000, i32::MIN));
    assert!(taken(BPF_JMP32, BPF_JEQ, 0xffff_ffff, -1));
    // Upper half ignored.
    assert!(taken(BPF_JMP32, BPF_JEQ, 0xabcd_0000_0000_0005, 5));
    assert!(taken(BPF_JMP32, BPF_JGT, 0x8000_0000, 1));
    assert!(
        !taken(BPF_JMP32, BPF_JSGT, 0x8000_0000, 1),
        "signed: negative"
    );
    assert!(taken(BPF_JMP32, BPF_JSLT, 0x8000_0000, 1));
}

#[test]
fn jmp64_signed_compares() {
    assert!(!taken(BPF_JMP, BPF_JSGT, u64::MAX, 1), "-1 > 1 is false");
    assert!(taken(BPF_JMP, BPF_JSLT, u64::MAX, 1));
    assert!(taken(BPF_JMP, BPF_JSGE, 5, 5));
    assert!(taken(BPF_JMP, BPF_JSLE, u64::MAX, -1));
}

#[test]
fn jmp_register_form_and_ja() {
    // r5 = data + 14; `jgt r5, r3` is the codegen's bounds check.
    let check = |len: usize| {
        let body = [
            Insn::mov64_reg(R5, R2),
            alu64_k(BPF_ADD, R5, 14),
            alu64_k(BPF_MOV, R0, 0),
            Insn::jgt_reg(R5, R3, 1),
            alu64_k(BPF_MOV, R0, 1),
        ];
        r0_of(&body, &vec![0; len], Little).unwrap()
    };
    assert_eq!(check(14), 1, "exactly 14 bytes: in bounds");
    assert_eq!(check(13), 0, "13 bytes: out of bounds");
    // A jump target outside the program is a fault.
    assert_eq!(
        exec(&[Insn::ja(5), Insn::exit()], &PKT8, Little),
        Err(Fault::JumpOutOfRange { pc: 0 })
    );
    assert_eq!(
        exec(&[Insn::ja(-2), Insn::exit()], &PKT8, Little),
        Err(Fault::JumpOutOfRange { pc: 0 })
    );
}

// ── EXIT and run_ebpf verdicts ───────────────────────────────────────────────

fn ret(r0: i32) -> Vec<Insn> {
    vec![Insn::mov64_imm(R0, r0), Insn::exit()]
}

#[test]
fn exit_returns_r0_as_verdict() {
    for host in [Little, Big] {
        assert_eq!(run_ebpf(&ret(XDP_PASS), &[], host), Ok(Verdict::Match));
        assert_eq!(run_ebpf(&ret(XDP_DROP), &[], host), Ok(Verdict::NoMatch));
        assert_eq!(run_ebpf(&ret(7), &[], host), Err(Fault::BadReturn(7)));
    }
    assert_eq!(exec(&ret(123), &[], Little), Ok(123));
}

#[test]
fn faults_are_not_nomatch() {
    // Unknown opcode.
    let junk = [Insn::new(0xff, 0, 0, 0, 0), Insn::exit()];
    assert!(matches!(
        run_ebpf(&junk, &PKT8, Little),
        Err(Fault::UnknownOpcode { pc: 0, code: 0xff })
    ));
    // Unsupported classes: ST, STX, legacy LD (incl. ld_imm64), CALL.
    for code in [0x62, 0x63, 0x18, 0x28, 0x85] {
        let p = [Insn::new(code, 0, 0, 0, 0), Insn::exit()];
        assert!(
            matches!(exec(&p, &PKT8, Little), Err(Fault::UnknownOpcode { .. })),
            "opcode {code:#x}"
        );
    }
    // Out-of-range register number.
    let bad = [Insn::new(BPF_ALU64 | BPF_MOV | BPF_K, 11, 0, 0, 0)];
    assert!(matches!(
        exec(&bad, &PKT8, Little),
        Err(Fault::BadRegister { .. })
    ));
    // Running off the end, `exit` before R0 is written, and an endless loop.
    assert_eq!(
        exec(&[Insn::mov64_imm(R0, 1)], &PKT8, Little),
        Err(Fault::PcOutOfRange { pc: 1 })
    );
    assert_eq!(
        exec(&[Insn::exit()], &PKT8, Little),
        Err(Fault::UninitRegister { pc: 0, reg: 0 })
    );
    assert_eq!(exec(&[Insn::ja(-1)], &PKT8, Little), Err(Fault::StepLimit));
}

// ═════════════════════════════════════════════════════════════════════════════
// cBPF-parity table
// ═════════════════════════════════════════════════════════════════════════════

#[cfg(feature = "vm")]
mod parity {
    use super::common::packets::*;
    use super::*;
    use pktbaffle::{compile, LinkType, Target};

    /// The table: one string per filter. Each is run against every packet in
    /// [`corpus`] on both hosts and must agree with the cBPF VM, apart from
    /// the divergences recorded in [`KNOWN`].
    const FILTERS: &[&str] = &[
        // ── protocols
        "tcp",
        "udp",
        "icmp",
        "arp",
        "ip",
        "ip6",
        "icmp6",
        "ip proto 6",
        "ip proto 021", // octal 17 (#157)
        "ip proto 17",
        "ip6 proto 17",
        "ether proto 0x0800",
        "ether proto 0x86dd",
        // ── IPv4 hosts and networks
        "host 10.0.0.1",
        "host 0x0a000001", // bare integer address (#190)
        "host 192.168.1.1",
        "src host 192.168.1.1",
        "dst host 10.0.0.1",
        "src or dst host 10.0.0.1",
        "src and dst host 192.168.1.1",
        "net 10.0.0.0/8",
        "net 0xa0000", // bare integer shifted into 10.0.0.0/8 (#190)
        "net 10.0",    // octets written set the mask: /16 (#158)
        "host 10.0.0", // short host is the /24 net (#158)
        "src net 192.168.0.0/16",
        "dst net 10.0.0.0/8",
        "net 192.168.1.0 mask 255.255.255.0",
        "ip broadcast",
        "ip multicast",
        // ── IPv6 hosts and networks
        "host 2001:db8::1",
        "dst host 2001:db8::2",
        "net 2001:db8::/32",
        "ip6 multicast",
        // ── ports
        "port 80",
        "tcp port 80",
        "udp port 53",
        "src port 1234",
        "dst port 80",
        "portrange 1000-2000",
        "tcp portrange 80-90",
        "src portrange 1000-2000",
        "ip6 and tcp port 80",
        // ── Ethernet
        "ether host aa:bb:cc:dd:ee:ff",
        "ether src aa:bb:cc:dd:ee:ff",
        "ether dst 11:22:33:44:55:66",
        "ether broadcast",
        "ether multicast",
        // ── VLAN / MPLS / PPPoE
        "vlan",
        "vlan 100",
        "vlan 200",
        "vlan 0144", // octal 100 (#157)
        "vlan 100 and ip",
        "vlan and tcp port 80",
        "mpls",
        "mpls 100",
        "mpls 200",
        "pppoes",
        "pppoes 7",
        "pppoed",
        // ── length
        "less 100",
        "greater 100",
        "len = 60",
        "len > 1000",
        // ── raw byte access
        "ip[0] = 0x45",
        "ip[8] > 32",
        "ip[2:2] = 40",
        "ip[2:2] > 40",
        "ip[12:4] = 0x0a000001",
        "ip[12:4] = 0xc0a80101",
        "ether[12:2] = 0x0800",
        "ether[12:2] = 0x86dd",
        "ether[0:4] = 0x11223344",
        "ether[6:4] = 0xaabbccdd",
        "ether[6:2] & 0xff00 = 0xaa00",
        "tcp[13] & 2 != 0",
        "tcp[0:2] = 1234",
        "tcp[2:2] >= 80",
        "tcp[4:4] = 1",
        "udp[2:2] = 53",
        "icmp[0] = 8",
        "tcp[0:2] > tcp[2:2]",
        // ── combinators
        "tcp and port 80",
        "tcp or udp",
        "not arp",
        "not tcp",
        "(tcp or udp) and port 53",
        "host 10.0.0.1 and not port 80",
        "ip and tcp[13] & 2 != 0",
        "ether host aa:bb:cc:dd:ee:ff and ip",
    ];

    // ── Packet corpus ───────────────────────────────────────────────────────

    /// Ethernet / MPLS (label, bottom-of-stack, TTL 64) / IPv4 header.
    fn eth_mpls(label: u32) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(&MAC_B);
        p.extend_from_slice(&MAC_A);
        p.extend_from_slice(&0x8847u16.to_be_bytes());
        p.extend_from_slice(&((label << 12) | (1 << 8) | 64).to_be_bytes());
        p.extend_from_slice(&tcp(IP_A, IP_B, 1234, 80)[14..34]);
        p
    }

    /// Ethernet / PPPoE session (or discovery) header / padding.
    fn eth_pppoe(ethertype: u16, session: u16) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(&MAC_B);
        p.extend_from_slice(&MAC_A);
        p.extend_from_slice(&ethertype.to_be_bytes());
        p.extend_from_slice(&[0x11, 0x00]); // ver/type, code
        p.extend_from_slice(&session.to_be_bytes());
        p.extend_from_slice(&[0x00, 0x08, 0x00, 0x21]); // length, PPP protocol
        p.extend_from_slice(&[0u8; 8]);
        p
    }

    /// IPv4/TCP with a 4-byte IP option (IHL = 6): L4 starts at offset 38.
    fn tcp_with_ip_options(sport: u16, dport: u16) -> Vec<u8> {
        let mut p = tcp(IP_A, IP_B, sport, dport);
        p[14] = 0x46;
        for _ in 0..4 {
            p.insert(34, 0x01); // NOP options
        }
        p
    }

    /// IPv6 with next-header 58 (ICMPv6).
    fn ipv6_icmp6() -> Vec<u8> {
        let mut p = eth_ipv6_udp(IPV6_A, IPV6_B, 0, 0);
        p[20] = 58;
        p
    }

    /// A TCP packet whose IPv4 header says "fragment offset 16": L4 is absent.
    fn ipv4_non_first_fragment() -> Vec<u8> {
        let mut p = tcp(IP_A, IP_B, 1234, 80);
        p[20] = 0x00;
        p[21] = 0x10;
        p
    }

    /// Named packets every filter is run against. Names are used by [`KNOWN`].
    fn corpus() -> Vec<(&'static str, Vec<u8>)> {
        let full = tcp(IP_A, IP_B, 1234, 80);
        vec![
            ("tcp_a_b_1234_80", full.clone()),
            ("tcp_b_a_80_1234", tcp(IP_B, IP_A, 80, 1234)),
            ("tcp_c_a_5555_443", tcp(IP_C, IP_A, 5555, 443)),
            ("tcp_a_a_1000_2000", tcp(IP_A, IP_A, 1000, 2000)),
            ("tcp_ip_options", tcp_with_ip_options(1234, 80)),
            (
                "tcp_mac_swapped",
                eth_ipv4_tcp(MAC_A, MAC_B, IP_A, IP_B, 1234, 80, 0x02, 0),
            ),
            (
                "tcp_60_bytes",
                eth_ipv4_tcp(MAC_B, MAC_A, IP_A, IP_B, 1234, 80, 0x02, 6),
            ),
            (
                "tcp_1200_bytes",
                eth_ipv4_tcp(MAC_B, MAC_A, IP_A, IP_B, 1234, 80, 0x02, 1146),
            ),
            ("udp_a_b_4000_53", udp(IP_A, IP_B, 4000, 53)),
            ("udp_b_c_1500_2000", udp(IP_B, IP_C, 1500, 2000)),
            ("icmp_echo", eth_ipv4_icmp(IP_A, IP_B, 8, 0)),
            ("arp", eth_arp(IP_A, IP_B)),
            (
                "vlan100_tcp80",
                eth_vlan_ipv4_tcp(100, IP_A, IP_B, 1234, 80, 2),
            ),
            (
                "vlan200_tcp443",
                eth_vlan_ipv4_tcp(200, IP_C, IP_A, 5555, 443, 2),
            ),
            ("ipv6_tcp_80", eth_ipv6_tcp(IPV6_A, IPV6_B, 1234, 80, 0x02)),
            ("ipv6_udp_53", eth_ipv6_udp(IPV6_B, IPV6_A, 53, 4000)),
            (
                "ipv6_mcast_udp",
                eth_ipv6_udp(IPV6_A, IPV6_MCAST, 1234, 5353),
            ),
            ("ipv6_icmp6", ipv6_icmp6()),
            (
                "ipv4_bcast_tcp",
                eth_ipv4_tcp(MAC_BCAST, MAC_A, IP_A, [255; 4], 1234, 80, 0x02, 0),
            ),
            (
                "ipv4_mcast_tcp",
                eth_ipv4_tcp(MAC_MCAST, MAC_A, IP_A, [224, 0, 0, 1], 1234, 80, 0x02, 100),
            ),
            ("mpls_100", eth_mpls(100)),
            ("pppoes_7", eth_pppoe(0x8864, 7)),
            ("pppoed", eth_pppoe(0x8863, 0)),
            ("ipv4_frag_tcp", ipv4_non_first_fragment()),
            ("runt_10", full[..10].to_vec()),
            ("eth_only_14", full[..14].to_vec()),
            ("ip_truncated_30", full[..30].to_vec()),
            ("tcp_truncated_36", full[..36].to_vec()),
        ]
    }

    // ── Known divergences ───────────────────────────────────────────────────

    const ANY: &str = "*";

    /// Mutations per corpus packet in the differential fuzz.
    const FUZZ_ROUNDS: usize = 200;

    /// A divergence between eBPF and cBPF that belongs to another open issue.
    struct Known {
        filter: &'static str,
        packet: &'static str,
        /// `None`: both hosts.
        host: Option<Endian>,
        issue: &'static str,
    }

    const fn known(filter: &'static str, packet: &'static str, issue: &'static str) -> Known {
        Known {
            filter,
            packet,
            host: None,
            issue,
        }
    }

    /// Every divergence below is *expected* until its issue is fixed; the
    /// parity tests fail if an entry stops diverging, so fix the issue and
    /// delete the row. Where the cBPF oracle (not eBPF) is the buggy side the
    /// issue is noted as such.
    const KNOWN: &[Known] = &[
        // ── #130: the cBPF *oracle* is wrong. tcp/udp/sctp/proto match IPv4
        // only, while eBPF (correctly, like libpcap) is dual-stack.
        known("tcp", "ipv6_tcp_80", "#130"),
        known("udp", ANY, "#130"),
        known("tcp or udp", ANY, "#130"),
        known("tcp and port 80", "ipv6_tcp_80", "#130"),
        known("not tcp", "ipv6_tcp_80", "#130"),
        known("(tcp or udp) and port 53", "ipv6_udp_53", "#130"),
        // ── #132: 64-bit JMP against a sign-extended imm32 breaks every
        // constant with bit 31 set (192.x.x.x, 255.255.255.255, aa:bb:cc:dd, ...).
        known("host 192.168.1.1", ANY, "#132"),
        known("src and dst host 192.168.1.1", ANY, "#132"),
        known("src host 192.168.1.1", ANY, "#132"),
        known("net 192.168.1.0 mask 255.255.255.0", ANY, "#132"),
        known("src net 192.168.0.0/16", ANY, "#132"),
        known("ip broadcast", ANY, "#132"),
        known("ip multicast", ANY, "#132"),
        known("ether broadcast", ANY, "#132"),
        known("ether host aa:bb:cc:dd:ee:ff", ANY, "#132"),
        known("ether src aa:bb:cc:dd:ee:ff", ANY, "#132"),
        known("ether host aa:bb:cc:dd:ee:ff and ip", ANY, "#132"),
        known("ip[12:4] = 0xc0a80101", ANY, "#132"),
        known("ether[6:4] = 0xaabbccdd", ANY, "#132"),
        // ── #133: no offset shift after `vlan`.
        known("vlan 100 and ip", "vlan100_tcp80", "#133"),
        known("vlan and tcp port 80", "vlan100_tcp80", "#133"),
        // ── #147: the cBPF *oracle* ignores the label of unicast MPLS.
        known("mpls 200", "mpls_100", "#147"),
        // ── #148: no IPv4 non-first-fragment guard on port/portrange.
        known("port 80", "ipv4_frag_tcp", "#148"),
        known("tcp port 80", "ipv4_frag_tcp", "#148"),
        known("dst port 80", "ipv4_frag_tcp", "#148"),
        known("src port 1234", "ipv4_frag_tcp", "#148"),
        known("portrange 1000-2000", "ipv4_frag_tcp", "#148"),
        known("tcp portrange 80-90", "ipv4_frag_tcp", "#148"),
        known("src portrange 1000-2000", "ipv4_frag_tcp", "#148"),
        known("tcp and port 80", "ipv4_frag_tcp", "#148"),
        known("host 10.0.0.1 and not port 80", "ipv4_frag_tcp", "#148"),
        // ── #156: a failed bounds check is an ordinary "false", so `not` /
        // `or` accept truncated packets (cBPF aborts the whole program).
        known("not arp", "runt_10", "#156"),
        known("not tcp", "runt_10", "#156"),
        known("not tcp", "eth_only_14", "#156"),
        known("host 10.0.0.1 and not port 80", "tcp_truncated_36", "#156"),
        // ── unfiled: port/portrange demand 4 transport bytes up front, but
        // cBPF/libpcap load only the port they test. With 2 of the 4 port
        // bytes present, `src port N` matches in cBPF and drops in eBPF.
        known("src port 1234", "tcp_truncated_36", "unfiled"),
        known("portrange 1000-2000", "tcp_truncated_36", "unfiled"),
        known("src portrange 1000-2000", "tcp_truncated_36", "unfiled"),
        // ── #172: expr-vs-expr byte access is a compile error in eBPF.
        known("tcp[0:2] > tcp[2:2]", ANY, "#172"),
    ];

    // ── Machinery ───────────────────────────────────────────────────────────

    struct Divergence {
        filter: &'static str,
        packet: &'static str,
        host: Endian,
        cbpf: bool,
        ebpf: String,
    }

    fn covers(k: &Known, d: &Divergence) -> bool {
        (k.filter == ANY || k.filter == d.filter)
            && (k.packet == ANY || k.packet == d.packet)
            && k.host.is_none_or(|h| h == d.host)
    }

    fn divergences(host: Endian) -> Vec<Divergence> {
        let corpus = corpus();
        let mut out = Vec::new();
        for &filter in FILTERS {
            let cbpf = compile(filter, LinkType::Ethernet, Target::Classic)
                .unwrap_or_else(|e| panic!("cBPF oracle cannot compile {filter:?}: {e}"));
            let ebpf = compile(filter, LinkType::Ethernet, Target::Extended);
            for (name, pkt) in &corpus {
                let want = pktbaffle::vm::run(cbpf.instructions(), pkt);
                let got: Result<bool, String> = match &ebpf {
                    Ok(p) => run_ebpf(p.as_extended().unwrap().instructions(), pkt, host)
                        .map(|v| v == Verdict::Match)
                        .map_err(|f| format!("{f:?}")),
                    Err(e) => Err(format!("compile error: {e}")),
                };
                if got != Ok(want) {
                    out.push(Divergence {
                        filter,
                        packet: name,
                        host,
                        cbpf: want,
                        ebpf: format!("{got:?}"),
                    });
                }
            }
        }
        out
    }

    fn assert_parity(host: Endian) {
        let unexpected: Vec<String> = divergences(host)
            .iter()
            .filter(|d| !KNOWN.iter().any(|k| covers(k, d)))
            .map(|d| {
                format!(
                    "  {:?} on {:?}: cBPF={} eBPF={}",
                    d.filter, d.packet, d.cbpf, d.ebpf
                )
            })
            .collect();
        assert!(
            unexpected.is_empty(),
            "{host:?} host: eBPF disagrees with cBPF ({}). Fix the backend or, if \
             another open issue causes it, add a KNOWN entry:\n{}",
            unexpected.len(),
            unexpected.join("\n"),
        );
    }

    #[test]
    fn ebpf_matches_cbpf_on_little_endian_host() {
        assert_parity(Little);
    }

    #[test]
    fn ebpf_matches_cbpf_on_big_endian_host() {
        assert_parity(Big);
    }

    /// Every KNOWN entry must still diverge on some host. (Not per host: a bug
    /// can be masked on one host by another, e.g. both sides wrongly say "no".)
    #[test]
    fn known_divergences_are_not_stale() {
        let all: Vec<Divergence> = divergences(Little)
            .into_iter()
            .chain(divergences(Big))
            .collect();
        let stale: Vec<String> = KNOWN
            .iter()
            .filter(|k| !all.iter().any(|d| covers(k, d)))
            .map(|k| format!("  {} ({:?} on {:?})", k.issue, k.filter, k.packet))
            .collect();
        assert!(
            stale.is_empty(),
            "these KNOWN entries no longer diverge - delete them:\n{}",
            stale.join("\n"),
        );
    }

    /// Guards against a vacuous table: under the oracle every filter must
    /// accept at least one corpus packet and reject at least one.
    #[test]
    fn corpus_exercises_every_filter() {
        let corpus = corpus();
        let mut vacuous = Vec::new();
        for &filter in FILTERS {
            let cbpf = compile(filter, LinkType::Ethernet, Target::Classic).unwrap();
            let hits = corpus
                .iter()
                .filter(|(_, p)| pktbaffle::vm::run(cbpf.instructions(), p))
                .count();
            if hits == 0 || hits == corpus.len() {
                vacuous.push(format!(
                    "{filter:?} accepts {hits}/{} packets",
                    corpus.len()
                ));
            }
        }
        assert!(
            vacuous.is_empty(),
            "add corpus packets for:\n{}",
            vacuous.join("\n")
        );
    }

    /// Deterministic xorshift64* (this crate has no `rand` dependency).
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
        }

        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }
    }

    /// IPv4 over Ethernet with a non-zero fragment offset.
    fn is_ipv4_fragment(pkt: &[u8]) -> bool {
        pkt.len() >= 22 && pkt[12..14] == [0x08, 0x00] && (pkt[20] & 0x1f != 0 || pkt[21] != 0)
    }

    /// Differential fuzz: mutate corpus packets (random bytes, sometimes
    /// truncated) and require eBPF == cBPF on both hosts. Filters with a KNOWN
    /// entry sit out, since KNOWN is keyed by corpus packet; the two other
    /// known divergences a mutation can reach are skipped below.
    #[test]
    fn mutated_packets_agree_with_cbpf() {
        let progs: Vec<_> = FILTERS
            .iter()
            .filter(|f| !KNOWN.iter().any(|k| k.filter == **f))
            .map(|&f| {
                let c = compile(f, LinkType::Ethernet, Target::Classic).unwrap();
                let e = compile(f, LinkType::Ethernet, Target::Extended).unwrap();
                (f, c, e)
            })
            .collect();
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        let mut bad: std::collections::BTreeMap<&str, (usize, String)> = Default::default();
        for (name, base) in corpus() {
            for _ in 0..FUZZ_ROUNDS {
                let mut pkt = base.clone();
                for _ in 0..1 + rng.below(3) {
                    let i = rng.below(pkt.len());
                    pkt[i] = match rng.below(4) {
                        0 => 0x00,
                        1 => 0xff,
                        _ => rng.next() as u8,
                    };
                }
                if rng.below(10) == 0 {
                    pkt.truncate(rng.below(pkt.len() + 1));
                }
                for (f, c, e) in &progs {
                    if (f.contains("port") && is_ipv4_fragment(&pkt)) // #148
                        || f.starts_with("mpls ")
                    // #147: cBPF ignores the label
                    {
                        continue;
                    }
                    let want = pktbaffle::vm::run(c.instructions(), &pkt);
                    let want_v = if want {
                        Verdict::Match
                    } else {
                        Verdict::NoMatch
                    };
                    for host in [Little, Big] {
                        let got = run_ebpf(e.as_extended().unwrap().instructions(), &pkt, host);
                        if got != Ok(want_v) {
                            let slot = bad.entry(f).or_insert_with(|| {
                                (
                                    0,
                                    format!(
                                        "{host:?} cBPF={want} eBPF={got:?} on {name}: {pkt:02x?}"
                                    ),
                                )
                            });
                            slot.0 += 1;
                        }
                    }
                }
            }
        }
        let report: Vec<String> = bad
            .iter()
            .map(|(f, (n, first))| format!("  {f:?} x{n}, first: {first}"))
            .collect();
        assert!(
            report.is_empty(),
            "eBPF disagrees with cBPF on mutated packets:\n{}",
            report.join("\n")
        );
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Explicit verdicts (independent of the cBPF oracle)
// ═════════════════════════════════════════════════════════════════════════════

mod explicit {
    use super::common::packets::*;
    use super::*;
    use pktbaffle::{compile, LinkType, Target};

    fn verdict(filter: &str, pkt: &[u8], host: Endian) -> Result<Verdict, Fault> {
        let prog = compile(filter, LinkType::Ethernet, Target::Extended)
            .unwrap_or_else(|e| panic!("ebpf compile({filter:?}): {e}"));
        run_ebpf(prog.as_extended().unwrap().instructions(), pkt, host)
    }

    // #129 acceptance: `tcp` on Ether()/IP()/TCP() matches on either host.
    #[test]
    fn tcp_matches_ether_ip_tcp_on_little_endian_host() {
        let pkt = tcp(IP_A, IP_B, 1234, 80);
        assert_eq!(verdict("tcp", &pkt, Little), Ok(Verdict::Match));
    }

    #[test]
    fn tcp_matches_ether_ip_tcp_on_big_endian_host() {
        let pkt = tcp(IP_A, IP_B, 1234, 80);
        assert_eq!(verdict("tcp", &pkt, Big), Ok(Verdict::Match));
    }

    fn named(name: &str) -> Vec<u8> {
        match name {
            "tcp80" => tcp(IP_A, IP_B, 1234, 80),
            "tcp_other" => tcp(IP_C, IP_A, 5555, 443),
            "tcp_other_macs" => eth_ipv4_tcp([2; 6], [4; 6], IP_A, IP_B, 1234, 80, 0x02, 0),
            "udp53" => udp(IP_A, IP_B, 4000, 53),
            "icmp" => eth_ipv4_icmp(IP_A, IP_B, 8, 0),
            "arp" => eth_arp(IP_A, IP_B),
            "ip6tcp" => eth_ipv6_tcp(IPV6_A, IPV6_B, 1234, 80, 0x02),
            "vlan100" => eth_vlan_ipv4_tcp(100, IP_A, IP_B, 1234, 80, 0x02),
            "vlan200" => eth_vlan_ipv4_tcp(200, IP_A, IP_B, 1234, 80, 0x02),
            _ => panic!("unknown packet {name:?}"),
        }
    }

    /// `(filter, packets that match, packets that do not)`.
    ///
    /// Verdicts are hand-derived from libpcap 1.10.3 semantics (the issue's
    /// cross-check covers tcp, ip, arp, icmp, `tcp dst port 80`,
    /// `ether proto 0x0800`, `ip[2:2] = 40` and `ether[12:2] = 0x0800`); they
    /// do not depend on the cBPF oracle. Packets a filter would match only
    /// because of another open issue (e.g. `host` on ARP, #140) are left out
    /// of both lists, as are constants with bit 31 set (#132).
    #[allow(clippy::type_complexity)]
    const MATRIX: &[(&str, &[&str], &[&str])] = &[
        (
            "tcp",
            &["tcp80", "tcp_other", "ip6tcp"],
            &["udp53", "icmp", "arp", "vlan100"],
        ),
        (
            "udp",
            &["udp53"],
            &["tcp80", "icmp", "arp", "ip6tcp", "vlan100"],
        ),
        (
            "ip",
            &["tcp80", "udp53", "icmp"],
            &["arp", "ip6tcp", "vlan100"],
        ),
        ("ip6", &["ip6tcp"], &["tcp80", "udp53", "arp"]),
        ("arp", &["arp"], &["tcp80", "icmp", "ip6tcp"]),
        ("icmp", &["icmp"], &["tcp80", "udp53", "arp", "ip6tcp"]),
        (
            "port 80",
            &["tcp80", "ip6tcp"],
            &["udp53", "tcp_other", "icmp", "arp"],
        ),
        (
            "tcp dst port 80",
            &["tcp80", "ip6tcp"],
            &["tcp_other", "udp53"],
        ),
        (
            "src port 1234",
            &["tcp80", "ip6tcp"],
            &["tcp_other", "udp53"],
        ),
        (
            "portrange 50-100",
            &["tcp80", "udp53", "ip6tcp"],
            &["tcp_other"],
        ),
        ("host 10.0.0.1", &["tcp80", "udp53", "icmp"], &["tcp_other"]),
        ("dst host 10.0.0.1", &["tcp80", "icmp"], &["tcp_other"]),
        (
            "net 10.0.0.0/8",
            &["tcp80", "udp53", "icmp"],
            &["tcp_other"],
        ),
        ("host 2001:db8::1", &["ip6tcp"], &["tcp80"]),
        (
            "ether host 11:22:33:44:55:66",
            &["tcp80", "udp53", "arp"],
            &["tcp_other_macs"],
        ),
        ("vlan", &["vlan100", "vlan200"], &["tcp80", "arp"]),
        ("vlan 100", &["vlan100"], &["vlan200", "tcp80"]),
        (
            "ether proto 0x0800",
            &["tcp80", "udp53", "icmp"],
            &["arp", "ip6tcp", "vlan100"],
        ),
        ("ip[2:2] = 40", &["tcp80", "tcp_other"], &["udp53", "icmp"]),
        // Ordered compares are why the fix byte-swaps the loaded value rather
        // than swapping the constant.
        ("ip[2:2] > 30", &["tcp80", "tcp_other"], &["udp53", "icmp"]),
        ("ip[2:2] < 30", &["udp53", "icmp"], &["tcp80", "tcp_other"]),
        (
            "ip[16:4] = 0x0a000001",
            &["tcp80", "udp53", "icmp"],
            &["tcp_other"],
        ),
        (
            "ether[12:2] = 0x0800",
            &["tcp80", "udp53", "icmp"],
            &["arp", "ip6tcp", "vlan100"],
        ),
        ("tcp[0:2] = 1234", &["tcp80"], &["tcp_other"]),
        ("ip6 and tcp port 80", &["ip6tcp"], &["tcp80", "udp53"]),
    ];

    #[test]
    fn explicit_verdicts_agree_on_both_hosts() {
        let mut bad = Vec::new();
        for host in [Little, Big] {
            for &(filter, yes, no) in MATRIX {
                for (names, want) in [(yes, Verdict::Match), (no, Verdict::NoMatch)] {
                    for name in names {
                        let got = verdict(filter, &named(name), host);
                        if got != Ok(want) {
                            bad.push(format!(
                                "  {host:?} {filter:?} on {name}: want {want:?}, got {got:?}"
                            ));
                        }
                    }
                }
            }
        }
        assert!(
            bad.is_empty(),
            "{} wrong verdicts:\n{}",
            bad.len(),
            bad.join("\n")
        );
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Long host list (#149)
// ═════════════════════════════════════════════════════════════════════════════

/// #149 acceptance: a 1000-host `host 10.0.0.1 or ... or host 10.0.3.232` list
/// compiles for eBPF on a 1 MiB stack (debug builds included) and matches only
/// listed hosts. libpcap 1.10.3 compiles the same shape of list (per the
/// issue); these verdicts are hand-derived, not taken from libpcap.
#[test]
fn thousand_host_list_matches_listed_hosts_only() {
    use common::packets::{tcp, IP_C};
    use pktbaffle::{compile, LinkType, Target};

    std::thread::Builder::new()
        .stack_size(1 << 20)
        .spawn(|| {
            let filter = (1u32..=1000)
                .map(|i| format!("host 10.0.{}.{}", i >> 8, i & 0xff))
                .collect::<Vec<_>>()
                .join(" or ");
            let prog = compile(&filter, LinkType::Ethernet, Target::Extended)
                .unwrap_or_else(|e| panic!("1000-host list must compile: {e}"));
            let insns = prog.as_extended().unwrap().instructions();
            for host in [Little, Big] {
                for (dst, want) in [
                    ([10, 0, 0, 1], Verdict::Match),   // first term
                    ([10, 0, 3, 232], Verdict::Match), // last term
                    ([10, 0, 3, 233], Verdict::NoMatch),
                    ([10, 0, 4, 1], Verdict::NoMatch),
                ] {
                    let got = run_ebpf(insns, &tcp(IP_C, dst, 1234, 80), host);
                    assert_eq!(got, Ok(want), "{host:?} dst {dst:?}");
                }
            }
        })
        .unwrap()
        .join()
        .expect("thread panicked (see message above)");
}
