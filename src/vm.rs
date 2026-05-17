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

        let class = insn.code & 0x07;

        if class == BPF_LD {
            let size = insn.code & 0x18;
            let mode = insn.code & 0xe0;
            if mode == BPF_ABS {
                a = sized_load(pkt, insn.k, size)?;
            } else if mode == BPF_IND {
                a = sized_load(pkt, x.wrapping_add(insn.k), size)?;
            } else if mode == BPF_LEN {
                a = pkt_len;
            } else if mode == BPF_IMM {
                a = insn.k;
            } else if mode == BPF_MEM {
                a = scratch.get(insn.k as usize).copied().unwrap_or(0);
            } else {
                return None;
            }
        } else if class == BPF_LDX {
            let size = insn.code & 0x18;
            let mode = insn.code & 0xe0;
            if size == BPF_B && mode == BPF_MSH {
                x = 4 * (*pkt.get(insn.k as usize)? as u32 & 0xf);
            } else if mode == BPF_IMM {
                x = insn.k;
            } else if mode == BPF_MEM {
                x = scratch.get(insn.k as usize).copied().unwrap_or(0);
            } else if mode == BPF_LEN {
                x = pkt_len;
            } else {
                return None;
            }
        } else if class == BPF_ST {
            if let Some(slot) = scratch.get_mut(insn.k as usize) {
                *slot = a;
            }
        } else if class == BPF_STX {
            if let Some(slot) = scratch.get_mut(insn.k as usize) {
                *slot = x;
            }
        } else if class == BPF_ALU {
            let op = insn.code & 0xf0;
            let v = if insn.code & 0x08 == BPF_X { x } else { insn.k };
            if op == BPF_ADD {
                a = a.wrapping_add(v);
            } else if op == BPF_SUB {
                a = a.wrapping_sub(v);
            } else if op == BPF_MUL {
                a = a.wrapping_mul(v);
            } else if op == BPF_DIV {
                if v == 0 {
                    return None;
                }
                a /= v;
            } else if op == BPF_OR {
                a |= v;
            } else if op == BPF_AND {
                a &= v;
            } else if op == BPF_LSH {
                a <<= v & 31;
            } else if op == BPF_RSH {
                a >>= v & 31;
            } else if op == BPF_NEG {
                a = a.wrapping_neg();
            } else if op == BPF_XOR {
                a ^= v;
            } else {
                return None;
            }
        } else if class == BPF_JMP {
            let op = insn.code & 0xf0;
            if op == BPF_JA {
                pc = pc.wrapping_add(insn.k as usize);
                continue;
            }
            let v = if insn.code & 0x08 == BPF_X { x } else { insn.k };
            let taken = if op == BPF_JEQ {
                a == v
            } else if op == BPF_JGT {
                a > v
            } else if op == BPF_JGE {
                a >= v
            } else if op == BPF_JSET {
                (a & v) != 0
            } else {
                return None;
            };
            pc += if taken {
                insn.jt as usize
            } else {
                insn.jf as usize
            };
        } else if class == BPF_RET {
            let retval = if insn.code & 0x10 != 0 { a } else { insn.k };
            return Some(retval != 0);
        } else if class == BPF_MISC {
            if insn.code & 0x80 != 0 {
                a = x; // TXA
            } else {
                x = a; // TAX
            }
        } else {
            return None;
        }
    }
}

#[inline]
fn sized_load(pkt: &[u8], off: u32, size: u16) -> Option<u32> {
    let off = off as usize;
    if size == BPF_W {
        let b = pkt.get(off..off + 4)?;
        Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    } else if size == BPF_H {
        let b = pkt.get(off..off + 2)?;
        Some(u16::from_be_bytes([b[0], b[1]]) as u32)
    } else if size == BPF_B {
        Some(*pkt.get(off)? as u32)
    } else {
        None
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
}
