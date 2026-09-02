//! Identical code folding.
//!
//! ld64 deduplicates identical functions by default (disabled with
//! -no_deduplicate); mold's ICF does the same for ELF. Two subsections
//! can share one copy when their bytes, relocations and unwind
//! behavior are all identical, *and* folding cannot be observed:
//! C++ explicitly permits identical instantiations to coalesce (that's
//! what weak definitions are), so folding is restricted to
//! subsections defined only by weak symbols.
//!
//! The algorithm follows mold: every candidate gets a hash of its
//! literal content, and a few refinement rounds rehash each candidate
//! with the previous-round hashes of its relocation targets, so the
//! hash comes to describe the whole reachable shape. Groups with equal
//! final hashes are then verified structurally and folded onto their
//! first member.

use std::collections::HashMap;
use std::hash::{Hash, Hasher};

use crate::arch::Arch;
use crate::context::Context;
use crate::input_sections::RelocTarget;
use crate::macho::*;
use crate::symbol::Origin;

/// A stable identifier for what a relocation edge points at.
#[derive(Hash, PartialEq, Eq, Clone, Copy)]
enum Edge {
    /// A candidate subsection, compared by its evolving hash.
    Candidate(usize),
    /// Anything else, compared by identity.
    Isec(usize, u64),
    Sym(usize),
}

pub fn icf_sections<E: Arch>(ctx: &mut Context<E>) {
    use rayon::prelude::*;

    // Candidates: live, executable, and defined exclusively by weak
    // symbols, so no one may rely on their addresses being distinct.
    let mut weak_only = vec![None::<bool>; ctx.isecs.len()];
    let mut has_syms = vec![false; ctx.isecs.len()];
    for obj in &ctx.objs {
        for (nlist, &sym_id) in obj.nlists.iter().zip(&obj.syms) {
            if nlist.is_stab() || nlist.n_type() != N_SECT {
                continue;
            }
            let sym = &ctx.symtab[sym_id];
            // Compiler-generated temporary labels don't make an atom's
            // address observable.
            if !nlist.is_extern() && (sym.name.starts_with('l') || sym.name.starts_with('L')) {
                continue;
            }
            let Some(isec) = sym.isec else {
                continue;
            };
            has_syms[isec] = true;
            let weak = nlist.n_desc & N_WEAK_DEF != 0;
            weak_only[isec] = Some(weak_only[isec].unwrap_or(true) && weak);
        }
    }

    let is_candidate = |ctx: &Context<E>, id: usize| -> bool {
        let isec = &ctx.isecs[id];
        isec.is_alive
            && isec.replacement.is_none()
            && isec.hdr.segname() == "__TEXT"
            && isec.hdr.flags & S_ATTR_PURE_INSTRUCTIONS != 0
            && isec.hdr.flags & (S_ATTR_NO_DEAD_STRIP | S_ATTR_LIVE_SUPPORT) == 0
            && weak_only[id] == Some(true)
    };

    let __t = std::time::Instant::now();
    let candidates: Vec<usize> = (0..ctx.isecs.len())
        .filter(|&i| is_candidate(ctx, i))
        .collect();
    if candidates.len() < 2 {
        return;
    }
    let mut cand_index = vec![usize::MAX; ctx.isecs.len()];
    for (i, &id) in candidates.iter().enumerate() {
        cand_index[id] = i;
    }

    // Unwind records per candidate, since unwinding is part of a
    // function's identity.
    let mut unwind_of: HashMap<usize, Vec<usize>> = HashMap::new();
    for (i, rec) in ctx.unwind_records.iter().enumerate() {
        unwind_of.entry(rec.isec).or_default().push(i);
    }

    let edge_of = |ctx: &Context<E>, obj: usize, target: RelocTarget, addend: i64| -> (Edge, i64) {
        match target {
            RelocTarget::Sym(idx) => {
                let sym_id = ctx.objs[obj].syms[idx];
                let sym = &ctx.symtab[sym_id];
                if let (Origin::Obj(_), Some(isec)) = (sym.origin, sym.isec) {
                    let isec = ctx.resolve_isec(isec);
                    if cand_index[isec] != usize::MAX {
                        return (Edge::Candidate(cand_index[isec]), addend + sym.value as i64);
                    }
                    return (Edge::Isec(isec, sym.value), addend);
                }
                (Edge::Sym(sym_id), addend)
            }
            RelocTarget::Section(isec) => {
                let isec = ctx.resolve_isec(isec);
                if cand_index[isec] != usize::MAX {
                    return (Edge::Candidate(cand_index[isec]), addend);
                }
                (Edge::Isec(isec, 0), addend)
            }
        }
    };

    // Initial hashes: everything except which candidate an edge points
    // at.
    let base_hash = |ctx: &Context<E>, id: usize, prev: Option<&Vec<u64>>| -> u64 {
        let isec = &ctx.isecs[id];
        // xxh3, as elsewhere: the refinement rounds hash every
        // candidate's bytes and relocations log2(n) times, and SipHash
        // was half of ICF's runtime.
        let mut h = xxhash_rust::xxh3::Xxh3::new();
        isec.hdr.flags.hash(&mut h);
        isec.size.hash(&mut h);
        isec.data.hash(&mut h);
        for rel in &isec.relocs {
            (rel.offset, rel.r_type, rel.size, rel.is_pcrel, rel.is_subtracted).hash(&mut h);
            let (edge, addend) = edge_of(ctx, isec.obj, rel.target, rel.addend);
            addend.hash(&mut h);
            match (edge, prev) {
                (Edge::Candidate(c), Some(prev)) => prev[c].hash(&mut h),
                (Edge::Candidate(_), None) => 0u8.hash(&mut h),
                (e, _) => e.hash(&mut h),
            }
        }
        if let Some(recs) = unwind_of.get(&id) {
            for &r in recs {
                let rec = &ctx.unwind_records[r];
                (rec.input_offset, rec.code_len, rec.encoding, rec.personality, rec.fde)
                    .hash(&mut h);
                if let Some((lsda, off)) = rec.lsda {
                    (ctx.resolve_isec(lsda), off).hash(&mut h);
                }
            }
        }
        h.finish()
    };

    // Refinement rounds propagate hashes along edges; log2(n) rounds
    // reach across any chain of distinct shapes.
    if std::env::var_os("MOLD_TIMING").is_some() {
        eprintln!("      icf-prep {:?} candidates {}", __t.elapsed(), candidates.len());
    }
    let __t = std::time::Instant::now();
    let rounds = (usize::BITS - candidates.len().leading_zeros()) as usize + 1;

    // Content is hashed exactly once; the refinement rounds mix only
    // fixed-size digests - each candidate's base digest plus its
    // candidate-edge targets' previous-round digests - so a round
    // costs microseconds instead of rehashing every candidate's bytes
    // and relocations, which is how mold keeps log2(n) rounds cheap.
    let base: Vec<u64> = candidates
        .par_iter()
        .map(|&id| base_hash(ctx, id, None))
        .collect();
    let cand_edges: Vec<Vec<u32>> = candidates
        .par_iter()
        .map(|&id| {
            let isec = &ctx.isecs[id];
            isec.relocs
                .iter()
                .filter_map(|rel| {
                    match edge_of(ctx, isec.obj, rel.target, rel.addend).0 {
                        Edge::Candidate(c) => Some(c as u32),
                        _ => None,
                    }
                })
                .collect()
        })
        .collect();

    let mut hashes = base.clone();
    for _ in 0..rounds {
        hashes = (0..candidates.len())
            .into_par_iter()
            .map(|i| {
                use std::hash::Hasher;
                let mut h = xxhash_rust::xxh3::Xxh3::new();
                h.write_u64(base[i]);
                for &c in &cand_edges[i] {
                    h.write_u64(hashes[c as usize]);
                }
                h.finish()
            })
            .collect();
    }

    // Group by final hash and fold each group onto its first member,
    // after verifying literal equality to rule out collisions.
    if std::env::var_os("MOLD_TIMING").is_some() {
        eprintln!("      icf-rounds {:?}", __t.elapsed());
    }
    let __t = std::time::Instant::now();
    let mut groups: HashMap<u64, Vec<usize>> = HashMap::new();
    for (i, &id) in candidates.iter().enumerate() {
        groups.entry(hashes[i]).or_default().push(id);
    }

    let equal = |ctx: &Context<E>, a: usize, b: usize| -> bool {
        let (x, y) = (&ctx.isecs[a], &ctx.isecs[b]);
        if x.data != y.data || x.hdr.flags != y.hdr.flags || x.relocs.len() != y.relocs.len() {
            return false;
        }
        x.relocs.iter().zip(&y.relocs).all(|(r, s)| {
            r.offset == s.offset
                && r.r_type == s.r_type
                && r.size == s.size
                && r.is_pcrel == s.is_pcrel
                && edge_of(ctx, x.obj, r.target, r.addend)
                    == edge_of(ctx, y.obj, s.target, s.addend)
        })
    };

    // Folding makes more edges coincide (references to the folded
    // copies now resolve to one leader), so repeat until stable.
    if std::env::var_os("MOLD_TIMING").is_some() {
        eprintln!("      icf-group {:?}", __t.elapsed());
    }
    let __t = std::time::Instant::now();
    loop {
        let mut folded = 0usize;
        for group in groups.values() {
            if group.len() < 2 {
                continue;
            }
            let mut leader = None;
            for &id in group {
                if ctx.isecs[id].replacement.is_some() {
                    continue;
                }
                match leader {
                    None => leader = Some(id),
                    Some(lead) => {
                        if equal(ctx, lead, id) {
                            ctx.isecs[id].replacement = Some(lead);
                            folded += 1;
                        }
                    }
                }
            }
        }
        if folded == 0 {
            break;
        }
    }
    if std::env::var_os("MOLD_TIMING").is_some() {
        eprintln!("      icf-fold {:?}", __t.elapsed());
    }
}
