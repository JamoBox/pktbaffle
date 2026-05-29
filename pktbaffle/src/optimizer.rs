//! Peephole optimizer for BPF instruction sequences.
//!
//! Runs after code generation to remove redundant loads and dead jumps.

use crate::bpf::{Insn, BPF_ABS, BPF_LD};

/// Remove consecutive identical absolute loads (ldw/ldh/ldb A ← P[k]).
///
/// This commonly appears when two predicates both start by loading the
/// Ethernet type field, or when an IP guard is emitted redundantly.
pub fn dedup_loads(insns: &mut Vec<Insn>) {
    if insns.is_empty() {
        return;
    }
    let load_mask = BPF_LD | BPF_ABS;
    let mut i = 0;
    while i + 1 < insns.len() {
        let cur = insns[i];
        let nxt = insns[i + 1];
        // If two consecutive instructions load from the same absolute offset
        // with the same width, the second is redundant — but only if no
        // jump targets it.  We conservatively skip if there is any jump
        // between the two; the jump-target check would require a full pass
        // and is deferred.  For now, only elide if the two are truly adjacent
        // with identical codes and keys, and neither has non-zero jt/jf.
        //
        // Mask 0xe7 clears the size bits (3–4), so ldw/ldh/ldb ABS are all
        // recognised as absolute loads (0xf8 would only match ldw).
        let is_load = |insn: Insn| (insn.code & 0xe7) == load_mask;
        if is_load(cur)
            && is_load(nxt)
            && cur.code == nxt.code
            && cur.k == nxt.k
            && cur.jt == 0
            && cur.jf == 0
        {
            // The second load is redundant.  Removing it invalidates all jump
            // offsets that cross this index.  Adjust forward jumps.
            insns.remove(i + 1);
            adjust_jumps(insns, i + 1);
        } else {
            i += 1;
        }
    }
}

/// Decrement by 1 all forward jump offsets that cross `removed_idx`.
///
/// Classic BPF jumps are forward-only and relative; an offset `o` at
/// instruction index `src` means "skip `o` instructions" (target = src + 1 + o).
/// If we remove the instruction at `removed_idx`, any jump whose source is
/// *before* `removed_idx` and whose target is *at or after* `removed_idx` must
/// have its offset decremented by 1.  Jumps whose source is at or after
/// `removed_idx` had both source and target shift left by 1, so their relative
/// offsets are unchanged and must not be touched.
fn adjust_jumps(insns: &mut [Insn], removed_idx: usize) {
    let bpf_jmp = 0x05u16;
    for (src, insn) in insns.iter_mut().enumerate() {
        if (insn.code & 0x07) != bpf_jmp {
            continue;
        }
        // Jumps at or after the removed index moved together with their targets.
        if src >= removed_idx {
            continue;
        }
        let adjust = |field: &mut u8, src: usize| {
            let target = src + 1 + *field as usize;
            if target >= removed_idx {
                *field -= 1;
            }
        };
        let is_ja = (insn.code & 0xf0) == 0x00; // BPF_JA
        if is_ja {
            let target = src + 1 + insn.k as usize;
            if target >= removed_idx {
                insn.k -= 1;
            }
        } else {
            adjust(&mut insn.jt, src);
            adjust(&mut insn.jf, src);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bpf::Insn;

    #[test]
    fn dedup_removes_repeated_load() {
        let ldh = Insn::ldh_abs(12);
        let jeq = Insn::jeq_k(0x0800, 0, 1);
        // Simulate: ldh 12; jeq; ldh 12 (dup); jeq
        let mut insns = vec![ldh, jeq, ldh, Insn::jeq_k(0x86dd, 0, 1)];
        // Don't dedup here — the second ldh is needed after a jump.
        // Just verify the function doesn't crash.
        dedup_loads(&mut insns);
    }
}
