//! Range-extension thunks.
//!
//! An arm64 bl/b reaches +-128 MiB; a __TEXT section larger than that
//! needs islands of trampolines so any branch can reach its target.
//! The layout follows mold's design (mold-rust's thunks.rs): thunks
//! are placed after each batch of code, and a batch never grows so
//! large that its own thunk would fall out of reach - the layout
//! cursor and the scan cursor stay within one branch reach (minus
//! margin) of each other, so placing a thunk can never invalidate an
//! earlier layout decision.

use crate::arch::{Arch, RelocClass};
use crate::context::Context;
use crate::output_chunks;
use crate::symbol::Origin;
use crate::util::align_to;

/// Lays out the subsections of one big executable output section with
/// range-extension thunks interleaved, following mold's design: a
/// thunk is placed after each batch of code, and a batch never grows
/// so large that its thunk would be out of reach of the batch's own
/// branches - the layout cursor and the scan cursor stay within one
/// branch reach (minus margin) of each other, so placing a thunk can
/// never invalidate an earlier decision. Each relocation that might be
/// out of range records its thunk entry; relocation application then
/// uses the entry only when the direct branch really cannot reach.
pub fn create_range_extension_thunks<E: Arch>(
    ctx: &mut Context<E>,
    isecs: &[usize],
) -> Vec<output_chunks::Thunk> {
    const BATCH: u64 = 10 * 1024 * 1024;
    const MAX_THUNK: u64 = 1024 * 1024;
    let budget = E::BRANCH_RANGE / 2 - MAX_THUNK - BATCH;

    // An upper bound on the section's final size: every subsection
    // with worst-case alignment padding, plus a full thunk per batch.
    // A forward branch's target can't land beyond this, so if the
    // bound is within forward reach of a batch, that batch needs no
    // entries for still-unplaced targets - which is what keeps a
    // merely-large section (bigger than the trigger, far smaller than
    // the branch range) from drowning in reserved-but-unused thunk
    // entries.
    let total_estimate: u64 = isecs
        .iter()
        .map(|&id| ctx.isecs[id].size + 16)
        .sum::<u64>();
    let total_estimate = total_estimate + (total_estimate / BATCH + 1) * MAX_THUNK;

    let mut thunks: Vec<output_chunks::Thunk> = Vec::new();
    let mut off: u64 = 0;
    let mut i = 0;

    // Distinguish placed subsections from ones still ahead.
    for &id in isecs {
        ctx.isecs[id].output_offset = u32::MAX;
    }

    while i < isecs.len() {
        let batch_start_off = off;
        let batch_start = i;

        // A single subsection larger than the budget can't have a thunk
        // after it within reach; its thunk goes in front instead, where
        // at least branches from its first reach's worth of code can
        // use it.
        let first_size = ctx.isecs[isecs[i]].size;
        if first_size > budget {
            let monster = isecs[i];
            // Scan the monster's relocations against a thunk placed here.
            let thunk_off = align_to(off, 16);
            let fwd_ok = total_estimate - off <= E::BRANCH_RANGE / 2 - MAX_THUNK;
            let n =
                scan_relocs_into_thunk::<E>(ctx, &[monster], thunk_off, fwd_ok, &mut thunks);
            off = thunk_off + n * E::THUNK_SIZE;
            let isec = &mut ctx.isecs[monster];
            off = align_to(off, 1 << isec.p2align);
            isec.output_offset = off as u32;
            off += isec.size;
            i += 1;
            continue;
        }

        // Place a batch: bounded by BATCH bytes, and by the thunk after
        // it staying within reach of the batch start.
        while i < isecs.len() {
            let isec = &ctx.isecs[isecs[i]];
            let aligned = align_to(off, 1 << isec.p2align);
            if i != batch_start
                && (aligned + isec.size - batch_start_off > budget
                    || aligned - batch_start_off >= BATCH)
            {
                break;
            }
            let isec = &mut ctx.isecs[isecs[i]];
            isec.output_offset = aligned as u32;
            off = aligned + isec.size;
            i += 1;
        }

        let thunk_off = align_to(off, 16);
        let batch: Vec<usize> = isecs[batch_start..i].to_vec();
        let fwd_ok = total_estimate - batch_start_off <= E::BRANCH_RANGE / 2 - MAX_THUNK;
        let n = scan_relocs_into_thunk::<E>(ctx, &batch, thunk_off, fwd_ok, &mut thunks);
        if n > 0 {
            off = thunk_off + n * E::THUNK_SIZE;
        }
    }
    thunks
}

/// Scans `batch`'s branch relocations and, if any target may be out of
/// reach, appends a thunk at `thunk_off` with one entry per such
/// target. Returns the number of entries.
fn scan_relocs_into_thunk<E: Arch>(
    ctx: &mut Context<E>,
    batch: &[usize],
    thunk_off: u64,
    forward_reachable: bool,
    thunks: &mut Vec<output_chunks::Thunk>,
) -> u64 {
    // Scan the batch's branch relocations in parallel to find the ones
    // whose target may be out of reach - mold-rust scans each batch's
    // members with par_iter here too, and the reachability test is a
    // pure read of state layout has already fixed. Each subsection
    // emits, in relocation order, the (object, arena index, target)
    // triples of its out-of-reach branches; the serial pass below then
    // assigns thunk entries in exactly the batch-then-reloc order the
    // old serial scan used, so the thunk is byte-identical.
    use rayon::prelude::*;
    let ctx_ref: &Context<E> = ctx;
    let per_isec: Vec<Vec<(usize, usize, crate::symbol::SymbolId)>> = batch
        .par_iter()
        .map(|&isec_id| {
            let mut out = Vec::new();
            let obj = ctx_ref.isecs[isec_id].obj as usize;
            if obj == usize::MAX {
                return out;
            }
            let osec = ctx_ref.isecs[isec_id].osec;
            let ro = ctx_ref.isecs[isec_id].rel_offset as usize;
            let nr = ctx_ref.isecs[isec_id].nrels as usize;
            for r in 0..nr {
                let rel = ctx_ref.objs[obj].relocs[ro + r];
                if E::classify_reloc(rel.r_type) != RelocClass::Branch {
                    continue;
                }
                let Some(sym_id) = ctx_ref.reloc_target_sym(obj, &rel) else {
                    continue;
                };

                let sym = &ctx_ref.symtab[sym_id];
                if let (Origin::Obj(_), Some(target)) = (sym.origin(), sym.isec()) {
                    let t = &ctx_ref.isecs[ctx_ref.resolve_isec(target as usize)];
                    // A target in another output section has no offset
                    // in this section's space; reserve an entry.
                    if t.osec != osec {
                        // conservative: fall through to the entry below
                    } else if t.output_offset != u32::MAX {
                        let target_off = t.output_offset as u64 + sym.value;
                        if thunk_off.saturating_sub(target_off)
                            < E::BRANCH_RANGE / 2 - 1024 * 1024
                        {
                            continue;
                        }
                    } else if forward_reachable {
                        // Still unplaced, but the whole section fits
                        // within forward reach of this batch.
                        continue;
                    }
                }
                out.push((obj, ro + r, sym_id));
            }
            out
        })
        .collect();

    let mut entry_of: std::collections::HashMap<crate::symbol::SymbolId, u64> =
        std::collections::HashMap::new();
    let mut nsyms = 0u64;
    for isec_out in &per_isec {
        for &(obj, ridx, sym_id) in isec_out {
            let entry = *entry_of.entry(sym_id).or_insert_with(|| {
                let e = thunk_off + nsyms * E::THUNK_SIZE;
                nsyms += 1;
                e
            });
            ctx.objs[obj].relocs[ridx].thunk_off = entry as u32;
        }
    }

    if nsyms > 0 {
        let mut syms: Vec<(u64, crate::symbol::SymbolId)> =
            entry_of.into_iter().map(|(s, e)| (e, s)).collect();
        syms.sort_unstable();
        thunks.push(output_chunks::Thunk {
            offset: thunk_off,
            syms: syms.into_iter().map(|(_, s)| s).collect(),
        });
    }
    nsyms
}

