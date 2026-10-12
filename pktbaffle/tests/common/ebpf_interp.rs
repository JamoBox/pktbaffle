//! Test-only reference interpreter for the eBPF programs `Target::Extended`
//! produces (issue #219). See the model/limits description at the top of
//! `tests/ebpf_exec.rs`.
//!
//! Opcode values that the crate does not define yet (`BPF_END` and friends) are
//! hard-coded here from the kernel's `linux/bpf.h` on purpose: the interpreter
//! is an independent decoder, so a wrong constant in the crate is caught
//! instead of being mirrored.

use pktbaffle::ebpf::{
    Insn, BPF_ADD, BPF_ALU, BPF_ALU64, BPF_AND, BPF_B, BPF_DIV, BPF_DW, BPF_EXIT, BPF_H, BPF_JA,
    BPF_JEQ, BPF_JGE, BPF_JGT, BPF_JLE, BPF_JLT, BPF_JMP, BPF_JMP32, BPF_JNE, BPF_JSET, BPF_LDX,
    BPF_LSH, BPF_MEM, BPF_MOV, BPF_MUL, BPF_OR, BPF_RSH, BPF_SUB, BPF_W, BPF_X, BPF_XOR, R1, R10,
    XDP_DROP, XDP_PASS,
};

// ── Opcodes the crate does not export ────────────────────────────────────────
pub const BPF_NEG: u8 = 0x80;
pub const BPF_MOD: u8 = 0x90;
pub const BPF_ARSH: u8 = 0xc0;
/// Byte-swap operation (ALU class only); bit 3 selects the direction.
pub const BPF_END: u8 = 0xd0;
pub const BPF_TO_LE: u8 = 0x00;
pub const BPF_TO_BE: u8 = 0x08;
pub const BPF_JSGT: u8 = 0x60;
pub const BPF_JSGE: u8 = 0x70;
pub const BPF_JSLT: u8 = 0xc0;
pub const BPF_JSLE: u8 = 0xd0;

const ALU_OPS: [u8; 14] = [
    BPF_ADD, BPF_SUB, BPF_MUL, BPF_DIV, BPF_OR, BPF_AND, BPF_LSH, BPF_RSH, BPF_NEG, BPF_MOD,
    BPF_XOR, BPF_MOV, BPF_ARSH, BPF_END,
];
const COND_OPS: [u8; 11] = [
    BPF_JEQ, BPF_JNE, BPF_JGT, BPF_JGE, BPF_JLT, BPF_JLE, BPF_JSET, BPF_JSGT, BPF_JSGE, BPF_JSLT,
    BPF_JSLE,
];

// ── Memory map ───────────────────────────────────────────────────────────────

/// Address of the `xdp_md` context (R1 on entry).
pub const CTX_BASE: u64 = 0x2000_0000;
/// Address of the first packet byte. Deliberately non-zero and not 4-aligned so
/// that code which confuses offsets with addresses cannot pass by accident.
pub const PKT_BASE: u64 = 0x1000_0002;
/// Upper bound on executed instructions (guards against backward-jump loops).
/// Programs are forward-only, so this only has to exceed the longest program
/// under test (the #200 tests run ~200K-instruction ones).
const STEP_LIMIT: usize = 1 << 20;

/// Byte order of the simulated host; it decides what `LDX MEM` returns and what
/// `BPF_END` does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Endian {
    Little,
    Big,
}

impl Endian {
    fn read(self, bytes: &[u8]) -> u64 {
        match self {
            Endian::Little => bytes.iter().rev().fold(0, |v, &b| (v << 8) | b as u64),
            Endian::Big => bytes.iter().fold(0, |v, &b| (v << 8) | b as u64),
        }
    }
}

/// XDP verdict an accepted program run can end with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// `XDP_PASS`: the filter matched.
    Match,
    /// `XDP_DROP`: the filter did not match.
    NoMatch,
}

/// A run that did not end in a clean `XDP_PASS` / `XDP_DROP`. Never conflated
/// with [`Verdict::NoMatch`]: a faulting program is a codegen bug, not a drop.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Fault {
    UnknownOpcode {
        pc: usize,
        code: u8,
    },
    BadRegister {
        pc: usize,
    },
    /// Write to the read-only frame pointer R10.
    WriteToR10 {
        pc: usize,
    },
    /// Read of a register that no earlier instruction wrote.
    UninitRegister {
        pc: usize,
        reg: u8,
    },
    /// Load outside `[data, data_end)` (and not a valid ctx access).
    OutOfBounds {
        pc: usize,
        addr: u64,
        size: usize,
    },
    /// Context access other than an aligned 4-byte load of `data`/`data_end`.
    BadCtxAccess {
        pc: usize,
        addr: u64,
        size: usize,
    },
    JumpOutOfRange {
        pc: usize,
    },
    /// Execution ran off the end of the program.
    PcOutOfRange {
        pc: usize,
    },
    DivByZero {
        pc: usize,
    },
    BadShift {
        pc: usize,
    },
    BadEndWidth {
        pc: usize,
        imm: i32,
    },
    /// `exit` with R0 neither `XDP_PASS` nor `XDP_DROP`.
    BadReturn(u64),
    StepLimit,
}

/// Run `prog` on `pkt` as an XDP program and return its verdict.
pub fn run_ebpf(prog: &[Insn], pkt: &[u8], host: Endian) -> Result<Verdict, Fault> {
    match exec(prog, pkt, host)? {
        r0 if r0 == XDP_PASS as u64 => Ok(Verdict::Match),
        r0 if r0 == XDP_DROP as u64 => Ok(Verdict::NoMatch),
        r0 => Err(Fault::BadReturn(r0)),
    }
}

struct Regs {
    v: [u64; 11],
    init: [bool; 11],
}

impl Regs {
    fn rd(&self, r: usize, pc: usize) -> Result<u64, Fault> {
        if self.init[r] {
            Ok(self.v[r])
        } else {
            Err(Fault::UninitRegister { pc, reg: r as u8 })
        }
    }

    fn wr(&mut self, r: usize, val: u64, pc: usize) -> Result<(), Fault> {
        if r == R10 as usize {
            return Err(Fault::WriteToR10 { pc });
        }
        self.v[r] = val;
        self.init[r] = true;
        Ok(())
    }
}

/// Run `prog` and return the raw value of R0 at `exit`.
pub fn exec(prog: &[Insn], pkt: &[u8], host: Endian) -> Result<u64, Fault> {
    let mut regs = Regs {
        v: [0; 11],
        init: [false; 11],
    };
    regs.v[R1 as usize] = CTX_BASE;
    regs.init[R1 as usize] = true;
    regs.init[R10 as usize] = true;

    // xdp_md { u32 data; u32 data_end; }, stored in host byte order.
    let data = PKT_BASE as u32;
    let data_end = (PKT_BASE + pkt.len() as u64) as u32;
    let mut ctx = [0u8; 8];
    match host {
        Endian::Little => {
            ctx[..4].copy_from_slice(&data.to_le_bytes());
            ctx[4..].copy_from_slice(&data_end.to_le_bytes());
        }
        Endian::Big => {
            ctx[..4].copy_from_slice(&data.to_be_bytes());
            ctx[4..].copy_from_slice(&data_end.to_be_bytes());
        }
    }

    let mut pc = 0usize;
    for _ in 0..STEP_LIMIT {
        let insn = *prog.get(pc).ok_or(Fault::PcOutOfRange { pc })?;
        let at = pc;
        pc += 1;
        let (dst, src) = (insn.dst() as usize, insn.src() as usize);
        if dst > 10 || src > 10 {
            return Err(Fault::BadRegister { pc: at });
        }
        let unknown = Fault::UnknownOpcode {
            pc: at,
            code: insn.code,
        };

        match insn.code & 0x07 {
            BPF_LDX => {
                if insn.code & 0xe0 != BPF_MEM {
                    return Err(unknown);
                }
                let size = match insn.code & 0x18 {
                    BPF_B => 1,
                    BPF_H => 2,
                    BPF_W => 4,
                    BPF_DW => 8,
                    _ => return Err(unknown),
                };
                let addr = regs.rd(src, at)?.wrapping_add(insn.off as i64 as u64);
                let bytes = load(&ctx, pkt, addr, size, at)?;
                regs.wr(dst, host.read(bytes), at)?;
            }

            class @ (BPF_ALU | BPF_ALU64) => {
                let is64 = class == BPF_ALU64;
                let op = insn.code & 0xf0;
                if !ALU_OPS.contains(&op) {
                    return Err(unknown);
                }

                if op == BPF_END {
                    if is64 {
                        return Err(unknown);
                    }
                    let v = regs.rd(dst, at)?;
                    let swap = matches!(
                        (insn.code & 0x08, host),
                        (BPF_TO_BE, Endian::Little) | (BPF_TO_LE, Endian::Big)
                    );
                    let out = match insn.imm {
                        16 if swap => (v as u16).swap_bytes() as u64,
                        16 => v as u16 as u64,
                        32 if swap => (v as u32).swap_bytes() as u64,
                        32 => v as u32 as u64,
                        64 if swap => v.swap_bytes(),
                        64 => v,
                        imm => return Err(Fault::BadEndWidth { pc: at, imm }),
                    };
                    regs.wr(dst, out, at)?;
                    continue;
                }

                let s = if insn.code & BPF_X != 0 {
                    regs.rd(src, at)?
                } else if is64 {
                    insn.imm as i64 as u64 // imm32 sign-extended
                } else {
                    insn.imm as u32 as u64
                };
                let d = if op == BPF_MOV { 0 } else { regs.rd(dst, at)? };
                let width = if is64 { 64 } else { 32 };
                let mask = if is64 { u64::MAX } else { u32::MAX as u64 };
                let (d, s) = (d & mask, s & mask);
                let shift = |s: u64| {
                    if s < width {
                        Ok(s as u32)
                    } else {
                        Err(Fault::BadShift { pc: at })
                    }
                };
                let r = match op {
                    BPF_ADD => d.wrapping_add(s),
                    BPF_SUB => d.wrapping_sub(s),
                    BPF_MUL => d.wrapping_mul(s),
                    BPF_DIV | BPF_MOD if s == 0 => return Err(Fault::DivByZero { pc: at }),
                    BPF_DIV => d / s,
                    BPF_MOD => d % s,
                    BPF_OR => d | s,
                    BPF_AND => d & s,
                    BPF_XOR => d ^ s,
                    BPF_LSH => d << shift(s)?,
                    BPF_RSH => d >> shift(s)?,
                    BPF_ARSH if is64 => ((d as i64) >> shift(s)?) as u64,
                    BPF_ARSH => ((d as u32 as i32) >> shift(s)?) as u32 as u64,
                    BPF_NEG => d.wrapping_neg(),
                    BPF_MOV => s,
                    _ => return Err(unknown),
                };
                regs.wr(dst, r & mask, at)?; // 32-bit results are zero-extended
            }

            class @ (BPF_JMP | BPF_JMP32) => {
                let is32 = class == BPF_JMP32;
                let op = insn.code & 0xf0;
                if !(COND_OPS.contains(&op) || (!is32 && matches!(op, BPF_JA | BPF_EXIT))) {
                    return Err(unknown); // incl. CALL
                }
                if !is32 && op == BPF_EXIT {
                    return regs.rd(0, at);
                }
                let target = |pc: &mut usize| -> Result<(), Fault> {
                    let t = at as i64 + 1 + insn.off as i64;
                    if t < 0 || t as usize >= prog.len() {
                        return Err(Fault::JumpOutOfRange { pc: at });
                    }
                    *pc = t as usize;
                    Ok(())
                };
                if !is32 && op == BPF_JA {
                    target(&mut pc)?;
                    continue;
                }

                let a = regs.rd(dst, at)?;
                let b = if insn.code & BPF_X != 0 {
                    regs.rd(src, at)?
                } else {
                    insn.imm as i64 as u64 // imm32 sign-extended (64-bit compare!)
                };
                // JMP32 compares only the low 32 bits of both operands.
                let (a, b, sa, sb) = if is32 {
                    (
                        a as u32 as u64,
                        b as u32 as u64,
                        a as u32 as i32 as i64,
                        b as u32 as i32 as i64,
                    )
                } else {
                    (a, b, a as i64, b as i64)
                };
                let taken = match op {
                    BPF_JEQ => a == b,
                    BPF_JNE => a != b,
                    BPF_JGT => a > b,
                    BPF_JGE => a >= b,
                    BPF_JLT => a < b,
                    BPF_JLE => a <= b,
                    BPF_JSET => a & b != 0,
                    BPF_JSGT => sa > sb,
                    BPF_JSGE => sa >= sb,
                    BPF_JSLT => sa < sb,
                    _ => sa <= sb, // BPF_JSLE; `COND_OPS` rules out the rest
                };
                if taken {
                    target(&mut pc)?;
                }
            }

            _ => return Err(unknown),
        }
    }
    Err(Fault::StepLimit)
}

/// Resolve a `size`-byte load at `addr` against the ctx and packet regions.
fn load<'a>(
    ctx: &'a [u8; 8],
    pkt: &'a [u8],
    addr: u64,
    size: usize,
    pc: usize,
) -> Result<&'a [u8], Fault> {
    if (CTX_BASE..CTX_BASE + 8).contains(&addr) {
        let off = (addr - CTX_BASE) as usize;
        // The kernel only allows aligned 4-byte reads of `data` / `data_end`.
        if size != 4 || off & 3 != 0 {
            return Err(Fault::BadCtxAccess { pc, addr, size });
        }
        return Ok(&ctx[off..off + 4]);
    }
    if let Some(off) = addr.checked_sub(PKT_BASE) {
        if let Some(bytes) = (off as usize).checked_add(size).and_then(|end| {
            if end <= pkt.len() {
                Some(&pkt[off as usize..end])
            } else {
                None
            }
        }) {
            return Ok(bytes);
        }
    }
    Err(Fault::OutOfBounds { pc, addr, size })
}
