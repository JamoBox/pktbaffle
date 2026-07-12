//! Software cBPF interpreter.
//!
//! Evaluates a classic BPF program against a packet byte slice.
//! Out-of-bounds packet loads cause the program to return false (drop).

use crate::bpf::{
    Insn, BPF_ABS, BPF_ADD, BPF_ALU, BPF_AND, BPF_B, BPF_DIV, BPF_H, BPF_IMM, BPF_IND, BPF_JA,
    BPF_JEQ, BPF_JGE, BPF_JGT, BPF_JMP, BPF_JSET, BPF_LD, BPF_LDX, BPF_LEN, BPF_LSH, BPF_MEM,
    BPF_MISC, BPF_MSH, BPF_MUL, BPF_NEG, BPF_OR, BPF_RET, BPF_RSH, BPF_ST, BPF_STX, BPF_SUB, BPF_W,
    BPF_X, BPF_XOR,
};

const SCRATCH: usize = 16;

/// Returns `true` if `insns` accepts `pkt`, `false` if it drops or errors.
pub fn run(insns: &[Insn], pkt: &[u8]) -> bool {
    inner(insns, pkt).unwrap_or(false)
}

fn inner(insns: &[Insn], pkt: &[u8]) -> Option<bool> {
    let pkt_len = pkt.len() as u32;
    let mut a: u32 = 0;
    let mut x: u32 = 0;
    let mut scratch = [0u32; SCRATCH];
    let mut pc = 0usize;

    loop {
        let insn = *insns.get(pc)?;
        pc += 1;

        match insn.code & 0x07 {
            BPF_LD => {
                let mode = insn.code & 0xe0;
                a = match mode {
                    BPF_ABS => sized_load(pkt, insn.k, insn.code & 0x18)?,
                    BPF_IND => sized_load(pkt, x.wrapping_add(insn.k), insn.code & 0x18)?,
                    BPF_LEN => pkt_len,
                    BPF_IMM => insn.k,
                    BPF_MEM => *scratch.get(insn.k as usize)?,
                    _ => return None,
                };
            }
            BPF_LDX => {
                let size = insn.code & 0x18;
                let mode = insn.code & 0xe0;
                x = if size == BPF_B && mode == BPF_MSH {
                    4 * (*pkt.get(insn.k as usize)? as u32 & 0xf)
                } else {
                    match mode {
                        BPF_IMM => insn.k,
                        BPF_MEM => *scratch.get(insn.k as usize)?,
                        BPF_LEN => pkt_len,
                        _ => return None,
                    }
                };
            }
            BPF_ST => *scratch.get_mut(insn.k as usize)? = a,
            BPF_STX => *scratch.get_mut(insn.k as usize)? = x,
            BPF_ALU => {
                let v = if uses_x(insn) { x } else { insn.k };
                a = match insn.code & 0xf0 {
                    BPF_ADD => a.wrapping_add(v),
                    BPF_SUB => a.wrapping_sub(v),
                    BPF_MUL => a.wrapping_mul(v),
                    BPF_DIV => {
                        if v == 0 {
                            return None;
                        }
                        a / v
                    }
                    BPF_OR => a | v,
                    BPF_AND => a & v,
                    BPF_LSH => a << (v & 31),
                    BPF_RSH => a >> (v & 31),
                    BPF_NEG => a.wrapping_neg(),
                    BPF_XOR => a ^ v,
                    _ => return None,
                };
            }
            BPF_JMP => {
                let op = insn.code & 0xf0;
                if op == BPF_JA {
                    pc = pc.wrapping_add(insn.k as usize);
                    continue;
                }
                let v = if uses_x(insn) { x } else { insn.k };
                let taken = match op {
                    BPF_JEQ => a == v,
                    BPF_JGT => a > v,
                    BPF_JGE => a >= v,
                    BPF_JSET => (a & v) != 0,
                    _ => return None,
                };
                pc += if taken {
                    insn.jt as usize
                } else {
                    insn.jf as usize
                };
            }
            BPF_RET => {
                let retval = if insn.code & 0x10 != 0 { a } else { insn.k };
                return Some(retval != 0);
            }
            BPF_MISC => {
                if insn.code & 0x80 != 0 {
                    a = x; // TXA
                } else {
                    x = a; // TAX
                }
            }
            _ => return None,
        }
    }
}

/// Returns `true` if an ALU/JMP instruction's second operand is the `X`
/// register rather than the immediate `k`.
#[inline]
fn uses_x(insn: Insn) -> bool {
    insn.code & 0x08 == BPF_X
}

#[inline]
fn sized_load(pkt: &[u8], off: u32, size: u16) -> Option<u32> {
    let off = off as usize;
    match size {
        BPF_W => {
            let b = pkt.get(off..off.checked_add(4)?)?;
            Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
        }
        BPF_H => {
            let b = pkt.get(off..off.checked_add(2)?)?;
            Some(u16::from_be_bytes([b[0], b[1]]) as u32)
        }
        BPF_B => Some(*pkt.get(off)? as u32),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bpf::{Insn, BPF_ACCEPT};

    #[test]
    fn accept_all() {
        assert!(run(&[Insn::ret_k(BPF_ACCEPT)], b"hello"));
    }

    #[test]
    fn drop_all() {
        assert!(!run(&[Insn::ret_k(0)], b"hello"));
    }

    #[test]
    fn ethertype_check() {
        let insns = vec![
            Insn::ldh_abs(12),
            Insn::jeq_k(0x0800, 0, 1),
            Insn::ret_k(BPF_ACCEPT),
            Insn::ret_k(0),
        ];
        let mut pkt = vec![0u8; 14];
        pkt[12] = 0x08;
        pkt[13] = 0x00;
        assert!(run(&insns, &pkt));
        pkt[13] = 0x06;
        assert!(!run(&insns, &pkt));
    }

    #[test]
    fn out_of_bounds_drops() {
        let insns = vec![Insn::ldh_abs(1000), Insn::ret_k(BPF_ACCEPT)];
        assert!(!run(&insns, b"short"));
    }

    #[test]
    fn proto_check() {
        let insns = vec![
            Insn::ldb_abs(23),
            Insn::jeq_k(6, 0, 1),
            Insn::ret_k(BPF_ACCEPT),
            Insn::ret_k(0),
        ];
        let mut pkt = vec![0u8; 34];
        pkt[14] = 0x45;
        pkt[23] = 6;
        assert!(run(&insns, &pkt));
        pkt[23] = 17;
        assert!(!run(&insns, &pkt));
    }

    #[test]
    fn scratch_memory() {
        use crate::bpf::{BPF_MEM, BPF_ST};
        let insns = vec![
            Insn::ld_imm(42),
            Insn {
                code: BPF_ST,
                jt: 0,
                jf: 0,
                k: 0,
            },
            Insn::ld_imm(0),
            Insn {
                code: BPF_LD | BPF_MEM,
                jt: 0,
                jf: 0,
                k: 0,
            },
            Insn::jeq_k(42, 0, 1),
            Insn::ret_k(BPF_ACCEPT),
            Insn::ret_k(0),
        ];
        assert!(run(&insns, b"x"));
    }

    #[test]
    fn out_of_range_scratch_load_drops() {
        use crate::bpf::BPF_MEM;
        // M[16] is out of range (SCRATCH == 16 valid slots: 0..=15).
        let insns = vec![
            Insn {
                code: BPF_LD | BPF_MEM,
                jt: 0,
                jf: 0,
                k: SCRATCH as u32,
            },
            Insn::ret_k(BPF_ACCEPT),
        ];
        assert!(!run(&insns, b"x"));
    }

    #[test]
    fn out_of_range_scratch_store_drops() {
        use crate::bpf::BPF_ST;
        let insns = vec![
            Insn::ld_imm(1),
            Insn {
                code: BPF_ST,
                jt: 0,
                jf: 0,
                k: SCRATCH as u32,
            },
            Insn::ret_k(BPF_ACCEPT),
        ];
        assert!(!run(&insns, b"x"));
    }
}
