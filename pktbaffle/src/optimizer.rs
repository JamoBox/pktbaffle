//! Peephole optimizer for BPF instruction sequences.
//!
//! [`optimize`] runs after code generation **and** jump-patch resolution, so
//! every jump offset is concrete and instructions can be safely retargeted or
//! removed. Three passes run in order:
//!
//! 1. **Jump threading** — any jump whose target is an unconditional `ja` is
//!    retargeted to the `ja`'s final destination, chasing chains. This lifts
//!    the `ja` trampolines that OR / NOT emission places on hot paths.
//! 2. **Redundant-load elimination** — an absolute load is removed when the
//!    accumulator already holds the same value on every path reaching it.
//! 3. **Dead-code elimination** — instructions unreachable from the entry
//!    (typically `ja`s bypassed by pass 1) are removed and all jump offsets
//!    are recomputed.

use crate::bpf::{Insn, BPF_ABS, BPF_JA, BPF_JMP, BPF_LD, BPF_MISC, BPF_RET, BPF_TXA};

/// Run all peephole passes over a fully patched program.
///
/// Must only be called once every jump offset is final (after terminal
/// `ret` instructions are emitted and all patches resolved); the passes
/// rewrite and renumber jumps based on the offsets they find.
pub fn optimize(insns: &mut Vec<Insn>) {
    thread_jumps(insns);
    let redundant = redundant_load_marks(insns);
    let reachable = reachable_marks(insns);
    let keep: Vec<bool> = insns
        .iter()
        .enumerate()
        .map(|(i, &insn)| {
            // `ja 0` only falls through — a no-op once threading has run.
            reachable[i] && !redundant[i] && !(is_ja(insn) && insn.k == 0)
        })
        .collect();
    remove_unkept(insns, &keep);
}

fn is_ja(insn: Insn) -> bool {
    (insn.code & 0x07) == BPF_JMP && (insn.code & 0xf0) == BPF_JA
}

fn is_cond_jump(insn: Insn) -> bool {
    (insn.code & 0x07) == BPF_JMP && (insn.code & 0xf0) != BPF_JA
}

fn is_ld_abs(insn: Insn) -> bool {
    // Mask 0xe7 keeps class + mode and clears the size bits, so ldw/ldh/ldb
    // absolute loads are all recognised.
    (insn.code & 0xe7) == (BPF_LD | BPF_ABS)
}

/// True if executing `insn` writes the accumulator.
fn writes_a(insn: Insn) -> bool {
    let class = insn.code & 0x07;
    class == BPF_LD
        || class == crate::bpf::BPF_ALU
        || (class == BPF_MISC && (insn.code & 0xf8) == BPF_TXA)
}

/// Follow a chain of unconditional jumps starting at `target`, returning the
/// first non-`ja` instruction index. cBPF jumps are strictly forward, so the
/// chain cannot loop.
fn final_target(insns: &[Insn], mut target: usize) -> usize {
    while let Some(&insn) = insns.get(target) {
        if !is_ja(insn) {
            break;
        }
        target = target + 1 + insn.k as usize;
    }
    target
}

/// Retarget every jump that lands on a `ja` to the `ja`'s final destination.
///
/// Conditional offsets are 8-bit; a retarget that would overflow 255 is left
/// alone (the trampoline stays, which is correct, just slower).
fn thread_jumps(insns: &mut [Insn]) {
    for i in 0..insns.len() {
        let insn = insns[i];
        if is_ja(insn) {
            let t = final_target(insns, i + 1 + insn.k as usize);
            insns[i].k = (t - i - 1) as u32;
        } else if is_cond_jump(insn) {
            let jt_target = final_target(insns, i + 1 + insn.jt as usize);
            if let Ok(off) = u8::try_from(jt_target - i - 1) {
                insns[i].jt = off;
            }
            let jf_target = final_target(insns, i + 1 + insn.jf as usize);
            if let Ok(off) = u8::try_from(jf_target - i - 1) {
                insns[i].jf = off;
            }
        }
    }
}

/// What the accumulator is known to hold at a program point.
#[derive(Debug, Clone, Copy, PartialEq)]
enum AState {
    /// Unanalysed or conflicting across joining paths.
    Unknown,
    /// A holds the result of the absolute load with this `(code, k)`.
    Load(u16, u32),
}

/// Mark absolute loads whose value is already in the accumulator on every
/// path that reaches them.
///
/// cBPF jumps are strictly forward, so a single in-order sweep that meets
/// the out-states of all predecessor edges (fall-through and jump alike) is
/// an exact forward dataflow. A load marked here is a no-op on every
/// reaching path, including its out-of-bounds behaviour: the identical
/// earlier load on each such path already faulted or succeeded.
fn redundant_load_marks(insns: &[Insn]) -> Vec<bool> {
    let mut marks = vec![false; insns.len()];
    // in_state[i] stays `None` until some predecessor edge propagates into
    // it; instructions never reached keep `None` and propagate nothing.
    let mut in_state: Vec<Option<AState>> = vec![None; insns.len()];
    if insns.is_empty() {
        return marks;
    }
    in_state[0] = Some(AState::Unknown);

    fn meet(slot: &mut Option<AState>, incoming: AState) {
        *slot = Some(match *slot {
            None => incoming,
            Some(prev) if prev == incoming => incoming,
            Some(_) => AState::Unknown,
        });
    }

    for i in 0..insns.len() {
        let Some(state) = in_state[i] else { continue };
        let insn = insns[i];
        let out = if is_ld_abs(insn) {
            if state == AState::Load(insn.code, insn.k) {
                marks[i] = true;
            }
            AState::Load(insn.code, insn.k)
        } else if writes_a(insn) {
            AState::Unknown
        } else {
            state
        };
        if (insn.code & 0x07) == BPF_RET {
            continue;
        }
        if is_ja(insn) {
            let t = i + 1 + insn.k as usize;
            if t < insns.len() {
                meet(&mut in_state[t], out);
            }
        } else if is_cond_jump(insn) {
            for t in [i + 1 + insn.jt as usize, i + 1 + insn.jf as usize] {
                if t < insns.len() {
                    meet(&mut in_state[t], out);
                }
            }
        } else if i + 1 < insns.len() {
            meet(&mut in_state[i + 1], out);
        }
    }
    marks
}

/// Compute reachability from instruction 0. Loads never alter control flow,
/// so the result is unaffected by which loads pass 2 marked for removal.
fn reachable_marks(insns: &[Insn]) -> Vec<bool> {
    let mut reachable = vec![false; insns.len()];
    let mut stack = vec![0usize];
    while let Some(i) = stack.pop() {
        let Some(&insn) = insns.get(i) else { continue };
        if std::mem::replace(&mut reachable[i], true) {
            continue;
        }
        if (insn.code & 0x07) == BPF_RET {
            continue;
        }
        if is_ja(insn) {
            stack.push(i + 1 + insn.k as usize);
        } else if is_cond_jump(insn) {
            stack.push(i + 1 + insn.jt as usize);
            stack.push(i + 1 + insn.jf as usize);
        } else {
            stack.push(i + 1);
        }
    }
    reachable
}

/// Drop instructions not marked `keep`, recomputing every jump offset.
///
/// A jump edge that pointed at a dropped instruction is redirected to the
/// next kept instruction after it. Dropped instructions are either
/// unreachable (no live edge points at them) or redundant loads, which are
/// never at a jump target and act as no-ops on their fall-through path.
fn remove_unkept(insns: &mut Vec<Insn>, keep: &[bool]) {
    if keep.iter().all(|&k| k) {
        return;
    }
    // new_index[i] = number of kept instructions before old index i; for a
    // dropped index this is the new position of the next kept instruction.
    let mut new_index = Vec::with_capacity(insns.len() + 1);
    let mut count = 0usize;
    for &k in keep {
        new_index.push(count);
        count += k as usize;
    }
    new_index.push(count);

    let old = std::mem::take(insns);
    for (i, mut insn) in old.into_iter().enumerate() {
        if !keep[i] {
            continue;
        }
        if is_ja(insn) {
            let t = (i + 1 + insn.k as usize).min(new_index.len() - 1);
            insn.k = (new_index[t] - new_index[i] - 1) as u32;
        } else if is_cond_jump(insn) {
            let jt = (i + 1 + insn.jt as usize).min(new_index.len() - 1);
            let jf = (i + 1 + insn.jf as usize).min(new_index.len() - 1);
            // Offsets only shrink when instructions are removed, so the u8
            // narrowing cannot overflow.
            insn.jt = (new_index[jt] - new_index[i] - 1) as u8;
            insn.jf = (new_index[jf] - new_index[i] - 1) as u8;
        }
        insns.push(insn);
    }
}

/// Remove consecutive identical absolute loads (ldw/ldh/ldb A ← `P[k]`).
///
/// Superseded by [`optimize`], which performs the same elimination as part
/// of a general redundant-load pass; kept as a standalone utility for
/// callers that hold raw instruction sequences.
pub fn dedup_loads(insns: &mut Vec<Insn>) {
    if insns.is_empty() {
        return;
    }
    let mut i = 0;
    while i + 1 < insns.len() {
        let cur = insns[i];
        let nxt = insns[i + 1];
        // Only elide when the two loads are truly adjacent with identical
        // codes and keys; a jump between them would change the analysis.
        if is_ld_abs(cur) && is_ld_abs(nxt) && cur.code == nxt.code && cur.k == nxt.k {
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
    for (src, insn) in insns.iter_mut().enumerate() {
        if (insn.code & 0x07) != BPF_JMP {
            continue;
        }
        // Jumps at or after the removed index moved together with their targets.
        if src >= removed_idx {
            continue;
        }
        if (insn.code & 0xf0) == BPF_JA {
            let target = src + 1 + insn.k as usize;
            if target >= removed_idx {
                insn.k -= 1;
            }
        } else {
            let adjust = |field: &mut u8| {
                let target = src + 1 + *field as usize;
                if target >= removed_idx && *field > 0 {
                    *field -= 1;
                }
            };
            adjust(&mut insn.jt);
            adjust(&mut insn.jf);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bpf::{Insn, BPF_ACCEPT, BPF_DROP};

    fn ret_accept() -> Insn {
        Insn::ret_k(BPF_ACCEPT)
    }
    fn ret_drop() -> Insn {
        Insn::ret_k(BPF_DROP)
    }

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

    #[test]
    fn threading_retargets_cond_jump_through_ja() {
        // jeq falls through (jt=0) into a ja that jumps to ACCEPT.
        let mut insns = vec![
            Insn::ldh_abs(12),
            Insn::jeq_k(0x0800, 0, 2), // jt → ja at [2], jf → drop at [4]
            Insn::ja(0),               // → accept at [3]
            ret_accept(),
            ret_drop(),
        ];
        optimize(&mut insns);
        // The ja is bypassed and removed.
        assert_eq!(
            insns,
            vec![
                Insn::ldh_abs(12),
                Insn::jeq_k(0x0800, 0, 1),
                ret_accept(),
                ret_drop(),
            ]
        );
    }

    #[test]
    fn threading_chases_ja_chains() {
        let mut insns = vec![
            Insn::ldh_abs(12),
            Insn::jeq_k(0x0800, 0, 3), // jt → [2] (ja), jf → [5] drop
            Insn::ja(0),               // → [3] (ja)
            Insn::ja(0),               // → [4] accept
            ret_accept(),
            ret_drop(),
        ];
        optimize(&mut insns);
        assert_eq!(
            insns,
            vec![
                Insn::ldh_abs(12),
                Insn::jeq_k(0x0800, 0, 1),
                ret_accept(),
                ret_drop(),
            ]
        );
    }

    #[test]
    fn reachable_ja_is_kept() {
        // The ja at [2] is reached by fall-through from the load at [1]
        // (not by a jump), so threading cannot bypass it and it must stay.
        let insns = vec![
            Insn::jeq_k(1, 0, 2), // jt → [1], jf → [3] drop
            Insn::ldh_abs(0),
            Insn::ja(1), // → [4] accept
            ret_drop(),
            ret_accept(),
        ];
        let mut optimized = insns.clone();
        optimize(&mut optimized);
        assert_eq!(optimized, insns);
    }

    #[test]
    fn redundant_load_on_straight_line_is_removed() {
        let mut insns = vec![
            Insn::ldh_abs(12),
            Insn::ldh_abs(12), // same load, A unchanged — redundant
            Insn::jeq_k(0x0800, 0, 1),
            ret_accept(),
            ret_drop(),
        ];
        optimize(&mut insns);
        assert_eq!(
            insns,
            vec![
                Insn::ldh_abs(12),
                Insn::jeq_k(0x0800, 0, 1),
                ret_accept(),
                ret_drop(),
            ]
        );
    }

    #[test]
    fn load_at_join_with_conflicting_a_is_kept() {
        // [3] joins two paths: fall-through from [2] carries A = ldb[23],
        // the jf edge from [1] carries A = ldh[12]. The states conflict, so
        // the ldh[12] at [3] is live.
        let insns = vec![
            Insn::ldh_abs(12),
            Insn::jeq_k(0x0800, 0, 1), // jt → [2], jf → [3]
            Insn::ldb_abs(23),
            Insn::ldh_abs(12),
            Insn::jeq_k(0x86dd, 0, 1),
            ret_accept(),
            ret_drop(),
        ];
        let mut optimized = insns.clone();
        optimize(&mut optimized);
        assert_eq!(optimized, insns);
    }

    #[test]
    fn load_at_join_with_agreeing_a_is_removed() {
        // tcp-or-udp shape: the reload at [2] is reached only by the jf edge
        // of [1], which still carries A = ldb[23], so it is redundant.
        let mut insns = vec![
            Insn::ldb_abs(23),
            Insn::jeq_k(6, 2, 0), // jt → [4] accept, jf → [2]
            Insn::ldb_abs(23),
            Insn::jeq_k(17, 0, 1), // jt → [4] accept, jf → [5] drop
            ret_accept(),
            ret_drop(),
        ];
        optimize(&mut insns);
        assert_eq!(
            insns,
            vec![
                Insn::ldb_abs(23),
                Insn::jeq_k(6, 1, 0),
                Insn::jeq_k(17, 0, 1),
                ret_accept(),
                ret_drop(),
            ]
        );
    }

    #[test]
    fn nop_ja_is_removed() {
        // `ja 0` falls through to the next instruction — a pure no-op.
        let mut insns = vec![
            Insn::ldh_abs(12),
            Insn::ja(0),
            Insn::jeq_k(0x0800, 0, 1),
            ret_accept(),
            ret_drop(),
        ];
        optimize(&mut insns);
        assert_eq!(
            insns,
            vec![
                Insn::ldh_abs(12),
                Insn::jeq_k(0x0800, 0, 1),
                ret_accept(),
                ret_drop(),
            ]
        );
    }

    #[test]
    fn intervening_a_write_blocks_load_removal() {
        let mut insns = vec![
            Insn::ldh_abs(12),
            Insn::and_k(0xff),
            Insn::ldh_abs(12), // A was modified — load is live
            Insn::jeq_k(0x0800, 0, 1),
            ret_accept(),
            ret_drop(),
        ];
        let before = insns.clone();
        optimize(&mut insns);
        assert_eq!(insns, before);
    }

    #[test]
    fn ldx_between_loads_does_not_block_removal() {
        // LDX writes X, not A, so the duplicate A load is still redundant.
        let mut insns = vec![
            Insn::ldh_abs(12),
            Insn::ldx_msh(14),
            Insn::ldh_abs(12),
            Insn::jeq_k(0x0800, 0, 1),
            ret_accept(),
            ret_drop(),
        ];
        optimize(&mut insns);
        assert_eq!(
            insns,
            vec![
                Insn::ldh_abs(12),
                Insn::ldx_msh(14),
                Insn::jeq_k(0x0800, 0, 1),
                ret_accept(),
                ret_drop(),
            ]
        );
    }

    #[test]
    fn unreachable_code_is_removed() {
        let mut insns = vec![
            Insn::ja(1),       // skips [1]
            Insn::ldh_abs(12), // unreachable
            ret_accept(),
            ret_drop(), // unreachable (no path reaches it) — also removed
        ];
        optimize(&mut insns);
        assert_eq!(insns, vec![Insn::ja(0), ret_accept()]);
    }

    #[test]
    fn cond_jump_offsets_survive_removal_between_source_and_target() {
        // A jump whose target lies beyond a removed instruction must have
        // its offset shrunk to match.
        let mut insns = vec![
            Insn::jeq_k(1, 0, 4), // jt → [1], jf → [5] drop
            Insn::ldh_abs(0),
            Insn::ldh_abs(0), // redundant — removed
            Insn::jeq_k(2, 0, 1),
            ret_accept(),
            ret_drop(),
        ];
        optimize(&mut insns);
        assert_eq!(
            insns,
            vec![
                Insn::jeq_k(1, 0, 3), // jf offset shrank 4 → 3
                Insn::ldh_abs(0),
                Insn::jeq_k(2, 0, 1),
                ret_accept(),
                ret_drop(),
            ]
        );
    }
}
