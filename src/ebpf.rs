//! Extended BPF (eBPF) instruction encoding.
//!
//! Each instruction is 64 bits: opcode (8), regs (8), offset (16), imm (32).
//! Registers are encoded as `(dst & 0xf) | ((src & 0xf) << 4)` in the `regs` byte.

// ── Instruction classes (low 3 bits of opcode) ──────────────────────────────
pub const BPF_LD: u8 = 0x00;
pub const BPF_LDX: u8 = 0x01;
pub const BPF_ST: u8 = 0x02;
pub const BPF_STX: u8 = 0x03;
pub const BPF_ALU: u8 = 0x04; // 32-bit arithmetic
pub const BPF_JMP: u8 = 0x05;
pub const BPF_JMP32: u8 = 0x06;
pub const BPF_ALU64: u8 = 0x07; // 64-bit arithmetic

// ── Size modifiers (bits 4:3, memory class) ──────────────────────────────────
pub const BPF_W: u8 = 0x00; // 32-bit
pub const BPF_H: u8 = 0x08; // 16-bit
pub const BPF_B: u8 = 0x10; // 8-bit
pub const BPF_DW: u8 = 0x18; // 64-bit

// ── Mode modifier (bits 7:5, memory class) ───────────────────────────────────
pub const BPF_MEM: u8 = 0x60;

// ── Source operand (bit 3, ALU/JMP) ─────────────────────────────────────────
pub const BPF_K: u8 = 0x00; // use imm
pub const BPF_X: u8 = 0x08; // use src_reg

// ── 32-bit ALU operations (high nibble of opcode) ────────────────────────────
pub const BPF_ADD: u8 = 0x00;
pub const BPF_SUB: u8 = 0x10;
pub const BPF_MUL: u8 = 0x20;
pub const BPF_AND: u8 = 0x50;
pub const BPF_LSH: u8 = 0x60;
pub const BPF_RSH: u8 = 0x70;
pub const BPF_MOV: u8 = 0xb0;

// ── Jump operations (high nibble of opcode) ──────────────────────────────────
pub const BPF_JA: u8 = 0x00;
pub const BPF_JEQ: u8 = 0x10;
pub const BPF_JGT: u8 = 0x20;
pub const BPF_JGE: u8 = 0x30;
pub const BPF_JSET: u8 = 0x40;
pub const BPF_JNE: u8 = 0x50;
pub const BPF_JLT: u8 = 0xa0;
pub const BPF_JLE: u8 = 0xb0;
pub const BPF_EXIT: u8 = 0x90;

// ── Registers ────────────────────────────────────────────────────────────────

/// Return value register. Set to [`XDP_PASS`] or [`XDP_DROP`] before `exit`.
pub const R0: u8 = 0;
/// First function argument; holds the XDP context pointer (`xdp_md *`).
pub const R1: u8 = 1;
/// Packet data start — loaded from `xdp_md->data` in the prologue.
pub const R2: u8 = 2;
/// Packet data end — loaded from `xdp_md->data_end` in the prologue.
pub const R3: u8 = 3;
/// Primary scratch register: loaded packet values and computed results.
pub const R4: u8 = 4;
/// Address scratch register: bounds-check end pointer and computed base addresses.
pub const R5: u8 = 5;
/// Transport scratch register: transport header pointer used for port checks.
pub const R6: u8 = 6;
/// Frame pointer (read-only stack base).
pub const R10: u8 = 10;

// ── XDP return codes ─────────────────────────────────────────────────────────

/// XDP return code: drop the packet and recycle the buffer.
pub const XDP_DROP: i32 = 1;
/// XDP return code: pass the packet up the networking stack.
pub const XDP_PASS: i32 = 2;

/// A single eBPF instruction (8 bytes, little-endian on the wire).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct Insn {
    pub code: u8,
    /// Packed registers: `(dst & 0xf) | ((src & 0xf) << 4)`.
    pub regs: u8,
    pub off: i16,
    pub imm: i32,
}

impl Insn {
    /// Construct an eBPF instruction from its raw fields.
    ///
    /// `dst` and `src` are register numbers (0–10); they are packed into the
    /// `regs` byte automatically as `(dst & 0xf) | ((src & 0xf) << 4)`.
    #[inline]
    pub fn new(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> Self {
        Self {
            code,
            regs: (dst & 0xf) | ((src & 0xf) << 4),
            off,
            imm,
        }
    }

    /// Destination register number (low nibble of `regs`).
    #[inline]
    pub fn dst(&self) -> u8 {
        self.regs & 0xf
    }

    /// Source register number (high nibble of `regs`).
    #[inline]
    pub fn src(&self) -> u8 {
        (self.regs >> 4) & 0xf
    }

    // ── 64-bit ALU ───────────────────────────────────────────────────────────

    /// `dst = src` (64-bit register copy).
    pub fn mov64_reg(dst: u8, src: u8) -> Self {
        Self::new(BPF_ALU64 | BPF_MOV | BPF_X, dst, src, 0, 0)
    }

    /// `dst = imm` (64-bit, sign-extended).
    pub fn mov64_imm(dst: u8, imm: i32) -> Self {
        Self::new(BPF_ALU64 | BPF_MOV | BPF_K, dst, 0, 0, imm)
    }

    /// `dst += src` (64-bit).
    pub fn add64_reg(dst: u8, src: u8) -> Self {
        Self::new(BPF_ALU64 | BPF_ADD | BPF_X, dst, src, 0, 0)
    }

    /// `dst += imm` (64-bit, sign-extended immediate).
    pub fn add64_imm(dst: u8, imm: i32) -> Self {
        Self::new(BPF_ALU64 | BPF_ADD | BPF_K, dst, 0, 0, imm)
    }

    // ── 32-bit ALU ───────────────────────────────────────────────────────────

    /// `dst &= imm` (32-bit).
    pub fn and32_imm(dst: u8, imm: i32) -> Self {
        Self::new(BPF_ALU | BPF_AND | BPF_K, dst, 0, 0, imm)
    }

    /// `dst >>= imm` (32-bit logical right shift).
    pub fn rsh32_imm(dst: u8, imm: i32) -> Self {
        Self::new(BPF_ALU | BPF_RSH | BPF_K, dst, 0, 0, imm)
    }

    /// `dst <<= imm` (32-bit logical left shift).
    pub fn lsh32_imm(dst: u8, imm: i32) -> Self {
        Self::new(BPF_ALU | BPF_LSH | BPF_K, dst, 0, 0, imm)
    }

    // ── Memory loads (LDX MEM) ───────────────────────────────────────────────

    /// `dst = *(u8 *)(src + off)`.
    pub fn ldx_b(dst: u8, src: u8, off: i16) -> Self {
        Self::new(BPF_LDX | BPF_MEM | BPF_B, dst, src, off, 0)
    }

    /// `dst = *(u16 *)(src + off)` (big-endian network byte order in packet).
    pub fn ldx_h(dst: u8, src: u8, off: i16) -> Self {
        Self::new(BPF_LDX | BPF_MEM | BPF_H, dst, src, off, 0)
    }

    /// `dst = *(u32 *)(src + off)`.
    pub fn ldx_w(dst: u8, src: u8, off: i16) -> Self {
        Self::new(BPF_LDX | BPF_MEM | BPF_W, dst, src, off, 0)
    }

    // ── Jumps ────────────────────────────────────────────────────────────────

    /// Unconditional jump: `PC += off + 1`.
    pub fn ja(off: i16) -> Self {
        Self::new(BPF_JMP | BPF_JA, 0, 0, off, 0)
    }

    /// `if dst == imm: PC += off + 1`.
    pub fn jeq_imm(dst: u8, imm: i32, off: i16) -> Self {
        Self::new(BPF_JMP | BPF_JEQ | BPF_K, dst, 0, off, imm)
    }

    /// `if dst != imm: PC += off + 1`.
    pub fn jne_imm(dst: u8, imm: i32, off: i16) -> Self {
        Self::new(BPF_JMP | BPF_JNE | BPF_K, dst, 0, off, imm)
    }

    /// `if dst > imm: PC += off + 1` (unsigned).
    pub fn jgt_imm(dst: u8, imm: i32, off: i16) -> Self {
        Self::new(BPF_JMP | BPF_JGT | BPF_K, dst, 0, off, imm)
    }

    /// `if dst >= imm: PC += off + 1` (unsigned).
    pub fn jge_imm(dst: u8, imm: i32, off: i16) -> Self {
        Self::new(BPF_JMP | BPF_JGE | BPF_K, dst, 0, off, imm)
    }

    /// `if dst < imm: PC += off + 1` (unsigned).
    pub fn jlt_imm(dst: u8, imm: i32, off: i16) -> Self {
        Self::new(BPF_JMP | BPF_JLT | BPF_K, dst, 0, off, imm)
    }

    /// `if dst <= imm: PC += off + 1` (unsigned).
    pub fn jle_imm(dst: u8, imm: i32, off: i16) -> Self {
        Self::new(BPF_JMP | BPF_JLE | BPF_K, dst, 0, off, imm)
    }

    /// `if dst & imm != 0: PC += off + 1`.
    pub fn jset_imm(dst: u8, imm: i32, off: i16) -> Self {
        Self::new(BPF_JMP | BPF_JSET | BPF_K, dst, 0, off, imm)
    }

    /// `if dst > src: PC += off + 1` (unsigned, register comparison).
    pub fn jgt_reg(dst: u8, src: u8, off: i16) -> Self {
        Self::new(BPF_JMP | BPF_JGT | BPF_X, dst, src, off, 0)
    }

    /// Program exit (returns R0 to the kernel).
    pub fn exit() -> Self {
        Self::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0)
    }

    /// Encode as 8 raw bytes (little-endian, matching Linux bpf_insn layout).
    pub fn to_le_bytes(self) -> [u8; 8] {
        let mut b = [0u8; 8];
        b[0] = self.code;
        b[1] = self.regs;
        b[2..4].copy_from_slice(&self.off.to_le_bytes());
        b[4..8].copy_from_slice(&self.imm.to_le_bytes());
        b
    }
}

/// A compiled eBPF program (sequence of instructions).
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

    /// Number of instructions in the program.
    pub fn len(&self) -> usize {
        self.insns.len()
    }

    /// Returns `true` if the program contains no instructions.
    pub fn is_empty(&self) -> bool {
        self.insns.is_empty()
    }

    /// Encode as raw bytes (8 bytes per instruction, little-endian).
    pub fn to_le_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.insns.len() * 8);
        for insn in &self.insns {
            out.extend_from_slice(&insn.to_le_bytes());
        }
        out
    }
}
