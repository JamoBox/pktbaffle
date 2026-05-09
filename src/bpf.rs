//! Classic BPF (cBPF) instruction encoding.
//!
//! Each instruction is a 64-bit struct: opcode (16), jump-true (8),
//! jump-false (8), constant (32).  This matches the kernel `struct bpf_insn`
//! / `struct sock_filter` layout.

// ── Instruction classes ──────────────────────────────────────────────────────
pub const BPF_LD: u16 = 0x00;
pub const BPF_LDX: u16 = 0x01;
pub const BPF_ST: u16 = 0x02;
pub const BPF_STX: u16 = 0x03;
pub const BPF_ALU: u16 = 0x04;
pub const BPF_JMP: u16 = 0x05;
pub const BPF_RET: u16 = 0x06;
pub const BPF_MISC: u16 = 0x07;

// ── Size modifiers (LD/LDX) ──────────────────────────────────────────────────
pub const BPF_W: u16 = 0x00; // 32-bit word
pub const BPF_H: u16 = 0x08; // 16-bit half-word
pub const BPF_B: u16 = 0x10; // 8-bit byte

// ── Mode modifiers (LD/LDX) ─────────────────────────────────────────────────
pub const BPF_IMM: u16 = 0x00;
pub const BPF_ABS: u16 = 0x20;
pub const BPF_IND: u16 = 0x40;
pub const BPF_MEM: u16 = 0x60;
pub const BPF_LEN: u16 = 0x80;
pub const BPF_MSH: u16 = 0xa0; // (4*(P[k:1] & 0xf)) → X, used for IP IHL

// ── ALU operations ───────────────────────────────────────────────────────────
pub const BPF_ADD: u16 = 0x00;
pub const BPF_SUB: u16 = 0x10;
pub const BPF_MUL: u16 = 0x20;
pub const BPF_DIV: u16 = 0x30;
pub const BPF_OR: u16 = 0x40;
pub const BPF_AND: u16 = 0x50;
pub const BPF_LSH: u16 = 0x60;
pub const BPF_RSH: u16 = 0x70;
pub const BPF_NEG: u16 = 0x80;
pub const BPF_XOR: u16 = 0xa0;

// ── Jump operations ──────────────────────────────────────────────────────────
pub const BPF_JA: u16 = 0x00;
pub const BPF_JEQ: u16 = 0x10;
pub const BPF_JGT: u16 = 0x20;
pub const BPF_JGE: u16 = 0x30;
pub const BPF_JSET: u16 = 0x40;

// ── Source operand ───────────────────────────────────────────────────────────
pub const BPF_K: u16 = 0x00; // use constant k
pub const BPF_X: u16 = 0x08; // use register X

// ── Return value source ──────────────────────────────────────────────────────
pub const BPF_A: u16 = 0x10; // use accumulator

// ── MISC operations ──────────────────────────────────────────────────────────
pub const BPF_TAX: u16 = 0x00; // A → X
pub const BPF_TXA: u16 = 0x80; // X → A

// ── Pseudo-constant: return "accept this packet" ────────────────────────────
/// A return value meaning "accept the full packet".
pub const BPF_ACCEPT: u32 = 0xffff_ffff;
/// A return value meaning "drop the packet".
pub const BPF_DROP: u32 = 0;

/// A single classic BPF instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct Insn {
    /// Opcode word (class | size | mode or op | src).
    pub code: u16,
    /// Jump offset if comparison is true.
    pub jt: u8,
    /// Jump offset if comparison is false.
    pub jf: u8,
    /// Immediate constant / memory slot / packet offset.
    pub k: u32,
}

impl Insn {
    /// Load a 32-bit word from the packet at absolute offset `k`.
    #[inline]
    pub fn ldw_abs(k: u32) -> Self {
        Self {
            code: BPF_LD | BPF_W | BPF_ABS,
            jt: 0,
            jf: 0,
            k,
        }
    }

    /// Load a 16-bit half-word from the packet at absolute offset `k`.
    #[inline]
    pub fn ldh_abs(k: u32) -> Self {
        Self {
            code: BPF_LD | BPF_H | BPF_ABS,
            jt: 0,
            jf: 0,
            k,
        }
    }

    /// Load a byte from the packet at absolute offset `k`.
    #[inline]
    pub fn ldb_abs(k: u32) -> Self {
        Self {
            code: BPF_LD | BPF_B | BPF_ABS,
            jt: 0,
            jf: 0,
            k,
        }
    }

    /// Load a 32-bit word from the packet at (X + `k`).
    #[inline]
    pub fn ldw_ind(k: u32) -> Self {
        Self {
            code: BPF_LD | BPF_W | BPF_IND,
            jt: 0,
            jf: 0,
            k,
        }
    }

    /// Load a 16-bit half-word from the packet at (X + `k`).
    #[inline]
    pub fn ldh_ind(k: u32) -> Self {
        Self {
            code: BPF_LD | BPF_H | BPF_IND,
            jt: 0,
            jf: 0,
            k,
        }
    }

    /// BPF_MSH: load 4*(P[k:1] & 0xf) into X (computes IPv4 IHL).
    #[inline]
    pub fn ldx_msh(k: u32) -> Self {
        Self {
            code: BPF_LDX | BPF_B | BPF_MSH,
            jt: 0,
            jf: 0,
            k,
        }
    }

    /// Load immediate into A.
    #[inline]
    pub fn ld_imm(k: u32) -> Self {
        Self {
            code: BPF_LD | BPF_IMM,
            jt: 0,
            jf: 0,
            k,
        }
    }

    /// AND accumulator with constant `k`.
    #[inline]
    pub fn and_k(k: u32) -> Self {
        Self {
            code: BPF_ALU | BPF_AND | BPF_K,
            jt: 0,
            jf: 0,
            k,
        }
    }

    /// OR accumulator with constant `k`.
    #[inline]
    pub fn or_k(k: u32) -> Self {
        Self {
            code: BPF_ALU | BPF_OR | BPF_K,
            jt: 0,
            jf: 0,
            k,
        }
    }

    /// RSH accumulator by `k` bits.
    #[inline]
    pub fn rsh_k(k: u32) -> Self {
        Self {
            code: BPF_ALU | BPF_RSH | BPF_K,
            jt: 0,
            jf: 0,
            k,
        }
    }

    /// Jump: `A == k` → jt, else jf.
    #[inline]
    pub fn jeq_k(k: u32, jt: u8, jf: u8) -> Self {
        Self {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            jt,
            jf,
            k,
        }
    }

    /// Jump: `A > k` → jt, else jf.
    #[inline]
    pub fn jgt_k(k: u32, jt: u8, jf: u8) -> Self {
        Self {
            code: BPF_JMP | BPF_JGT | BPF_K,
            jt,
            jf,
            k,
        }
    }

    /// Jump: `A >= k` → jt, else jf.
    #[inline]
    pub fn jge_k(k: u32, jt: u8, jf: u8) -> Self {
        Self {
            code: BPF_JMP | BPF_JGE | BPF_K,
            jt,
            jf,
            k,
        }
    }

    /// Jump: `A & k != 0` → jt, else jf.
    #[inline]
    pub fn jset_k(k: u32, jt: u8, jf: u8) -> Self {
        Self {
            code: BPF_JMP | BPF_JSET | BPF_K,
            jt,
            jf,
            k,
        }
    }

    /// Unconditional jump forward by `offset` instructions.
    #[inline]
    pub fn ja(offset: u32) -> Self {
        Self {
            code: BPF_JMP | BPF_JA,
            jt: 0,
            jf: 0,
            k: offset,
        }
    }

    /// Return with immediate value `k`.
    #[inline]
    pub fn ret_k(k: u32) -> Self {
        Self {
            code: BPF_RET | BPF_K,
            jt: 0,
            jf: 0,
            k,
        }
    }

    /// Encode as 8 raw bytes (little-endian, matching Linux sock_filter).
    pub fn to_le_bytes(self) -> [u8; 8] {
        let mut b = [0u8; 8];
        b[0..2].copy_from_slice(&self.code.to_le_bytes());
        b[2] = self.jt;
        b[3] = self.jf;
        b[4..8].copy_from_slice(&self.k.to_le_bytes());
        b
    }
}

impl std::fmt::Display for Insn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt_insn(f, self, None)
    }
}

/// Format a single instruction, optionally with its program counter so that
/// conditional-jump targets can be printed as absolute instruction indices
/// (matching libpcap's `bpf_dump` output).
fn fmt_insn(f: &mut std::fmt::Formatter<'_>, insn: &Insn, pc: Option<usize>) -> std::fmt::Result {
    let code = insn.code;
    let k = insn.k;
    let class = code & 0x07;
    let size = code & 0x18;
    let mode = code & 0xe0;

    match class {
        BPF_LD => {
            let mnem = match size {
                BPF_W => "ld",
                BPF_H => "ldh",
                BPF_B => "ldb",
                _ => "ld?",
            };
            match mode {
                BPF_ABS => write!(f, "{:<8} [{}]", mnem, k),
                BPF_IND => write!(f, "{:<8} [x + {}]", mnem, k),
                BPF_MEM => write!(f, "{:<8} M[{}]", mnem, k),
                BPF_LEN => write!(f, "{:<8} #pktlen", mnem),
                BPF_IMM => write!(f, "{:<8} #0x{:x}", mnem, k),
                _ => write!(f, "{:<8} ?mode=0x{:x}", mnem, mode),
            }
        }
        BPF_LDX => match (size, mode) {
            (BPF_B, BPF_MSH) => write!(f, "{:<8} 4*([{}]&0xf)", "ldxb", k),
            (_, BPF_IMM) => write!(f, "{:<8} #0x{:x}", "ldx", k),
            (_, BPF_MEM) => write!(f, "{:<8} M[{}]", "ldx", k),
            (_, BPF_LEN) => write!(f, "{:<8} #pktlen", "ldx"),
            _ => write!(f, "{:<8} ?mode=0x{:x}", "ldx", mode),
        },
        BPF_ST => write!(f, "{:<8} M[{}]", "st", k),
        BPF_STX => write!(f, "{:<8} M[{}]", "stx", k),
        BPF_ALU => {
            let op = code & 0xf0;
            let src = code & 0x08;
            if op == BPF_NEG {
                return write!(f, "neg");
            }
            let mnem = match op {
                BPF_ADD => "add",
                BPF_SUB => "sub",
                BPF_MUL => "mul",
                BPF_DIV => "div",
                BPF_OR => "or",
                BPF_AND => "and",
                BPF_LSH => "lsh",
                BPF_RSH => "rsh",
                BPF_XOR => "xor",
                _ => "alu?",
            };
            if src == BPF_X {
                write!(f, "{:<8} x", mnem)
            } else {
                write!(f, "{:<8} #0x{:x}", mnem, k)
            }
        }
        BPF_JMP => {
            let op = code & 0xf0;
            let src = code & 0x08;
            if op == BPF_JA {
                return write!(f, "{:<8} {}", "ja", k);
            }
            let mnem = match op {
                BPF_JEQ => "jeq",
                BPF_JGT => "jgt",
                BPF_JGE => "jge",
                BPF_JSET => "jset",
                _ => "jmp?",
            };
            let operand = if src == BPF_X {
                "x".to_string()
            } else {
                format!("#0x{:x}", k)
            };
            let abs_jt = pc.map_or(insn.jt as usize, |i| i + 1 + insn.jt as usize);
            let abs_jf = pc.map_or(insn.jf as usize, |i| i + 1 + insn.jf as usize);
            write!(
                f,
                "{:<8} {:<16} jt {:<5} jf {}",
                mnem, operand, abs_jt, abs_jf
            )
        }
        BPF_RET => {
            if code & 0x10 != 0 {
                write!(f, "{:<8} a", "ret")
            } else {
                write!(f, "{:<8} #0x{:x}", "ret", k)
            }
        }
        BPF_MISC => match code & 0xf8 {
            0x80 => write!(f, "txa"), // BPF_TXA
            _ => write!(f, "tax"),    // BPF_TAX (0x00) and fallthrough
        },
        _ => unreachable!("class is low 3 bits of code, always 0–7"),
    }
}

/// A compiled, ready-to-use BPF program.
#[derive(Debug, Clone)]
pub struct Program {
    insns: Vec<Insn>,
}

impl Program {
    pub(crate) fn new(insns: Vec<Insn>) -> Self {
        Self { insns }
    }

    /// The instruction slice.
    pub fn instructions(&self) -> &[Insn] {
        &self.insns
    }

    /// Encode the entire program as raw bytes (8 bytes per instruction,
    /// little-endian), suitable for writing to `/dev/bpf` or a raw socket.
    pub fn to_le_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.insns.len() * 8);
        for insn in &self.insns {
            out.extend_from_slice(&insn.to_le_bytes());
        }
        out
    }

    /// Number of instructions.
    pub fn len(&self) -> usize {
        self.insns.len()
    }

    pub fn is_empty(&self) -> bool {
        self.insns.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_ldh_abs() {
        assert_eq!(Insn::ldh_abs(12).to_string(), "ldh      [12]");
    }

    #[test]
    fn display_ldb_abs() {
        assert_eq!(Insn::ldb_abs(23).to_string(), "ldb      [23]");
    }

    #[test]
    fn display_ldw_abs() {
        assert_eq!(
            Insn {
                code: BPF_LD | BPF_W | BPF_ABS,
                jt: 0,
                jf: 0,
                k: 0
            }
            .to_string(),
            "ld       [0]"
        );
    }

    #[test]
    fn display_ldx_msh() {
        assert_eq!(Insn::ldx_msh(14).to_string(), "ldxb     4*([14]&0xf)");
    }

    #[test]
    fn display_and_k() {
        assert_eq!(Insn::and_k(0xff).to_string(), "and      #0xff");
    }

    #[test]
    fn display_neg() {
        let insn = Insn {
            code: BPF_ALU | BPF_NEG,
            jt: 0,
            jf: 0,
            k: 0,
        };
        assert_eq!(insn.to_string(), "neg");
    }

    #[test]
    fn display_ja() {
        assert_eq!(Insn::ja(3).to_string(), "ja       3");
    }

    #[test]
    fn display_jeq_k_standalone() {
        // Standalone (no pc): jt/jf printed as stored raw offsets.
        let insn = Insn::jeq_k(0x800, 1, 14);
        assert_eq!(insn.to_string(), "jeq      #0x800           jt 1     jf 14");
    }

    #[test]
    fn display_ret_accept() {
        assert_eq!(Insn::ret_k(BPF_ACCEPT).to_string(), "ret      #0xffffffff");
    }

    #[test]
    fn display_ret_drop() {
        assert_eq!(Insn::ret_k(BPF_DROP).to_string(), "ret      #0x0");
    }

    #[test]
    fn display_tax_txa() {
        let tax = Insn {
            code: BPF_MISC | BPF_TAX,
            jt: 0,
            jf: 0,
            k: 0,
        };
        let txa = Insn {
            code: BPF_MISC | BPF_TXA,
            jt: 0,
            jf: 0,
            k: 0,
        };
        assert_eq!(tax.to_string(), "tax");
        assert_eq!(txa.to_string(), "txa");
    }

    #[test]
    fn display_program_absolute_jump_targets() {
        // jeq at instruction index 1, jt=1 → abs 3, jf=13 → abs 15
        let prog = Program::new(vec![Insn::ldh_abs(12), Insn::jeq_k(0x800, 1, 13)]);
        let s = prog.to_string();
        assert!(s.contains("(000) ldh      [12]"), "got: {s}");
        assert!(s.contains("jt 3"), "got: {s}");
        assert!(s.contains("jf 15"), "got: {s}");
    }
}

impl std::fmt::Display for Program {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (i, insn) in self.insns.iter().enumerate() {
            write!(f, "({:03}) ", i)?;
            fmt_insn(f, insn, Some(i))?;
            writeln!(f)?;
        }
        Ok(())
    }
}
