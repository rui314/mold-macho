//! Dead-stripping (-dead_strip): mold's gc-sections for Mach-O.
//!
//! Subsections not reachable from the roots - the entry point,
//! exported symbols (for a dylib), initializers and everything the
//! format pins (no-dead-strip sections and symbols) - are removed.
//! Reachability follows relocations and unwind-info edges, so a live
//! function keeps its LSDA and personality. This is passes.rs's
//! liveness walk's section-level counterpart, and mirrors
//! gc_sections.rs in mold-rust (dead-strip.cc in sold).

use crate::arch::Arch;
use crate::context::Context;
use crate::input_sections::RelocTarget;
use crate::macho::*;
use crate::symbol::Origin;

/// Removes subsections that are not reachable from the roots: the entry
/// point, exported symbols (for a dylib), and everything the format
/// requires to stay (initializers, no-dead-strip sections and symbols).
/// Reachability follows relocations and unwind-info edges.
pub fn dead_strip<E: Arch>(ctx: &mut Context<E>) {
    let mut live = vec![false; ctx.isecs.len()];
    // For -why_live: who first marked each subsection (usize::MAX for
    // roots), giving a spanning tree of the liveness walk.
    let mut pred = vec![usize::MAX; ctx.isecs.len()];
    let mut stack: Vec<usize> = Vec::new();
    let redirects: Vec<usize> = {
        use rayon::prelude::*;
        (0..ctx.isecs.len())
            .into_par_iter()
            .map(|i| ctx.resolve_isec(i))
            .collect()
    };
    let redirects = &redirects;
    let mark =
        move |live: &mut Vec<bool>, pred: &mut Vec<usize>, stack: &mut Vec<usize>, id: usize, from: usize| {
            let id = redirects[id];
            if !live[id] {
                live[id] = true;
                pred[id] = from;
                stack.push(id);
            }
        };

    // Section-level roots, found on all cores; marking stays serial
    // (it is a handful of sections). Sections of dead archive members
    // are not part of the link at all and must not be resurrected.
    let root_ids: Vec<usize> = {
        use rayon::prelude::*;
        ctx.isecs
            .par_iter()
            .enumerate()
            .filter_map(|(id, isec)| {
                if !isec.is_alive {
                    return None;
                }
                let keep_type = matches!(
                    isec.hdr.section_type(),
                    S_MOD_INIT_FUNC_POINTERS | S_INIT_FUNC_OFFSETS | S_THREAD_LOCAL_VARIABLES
                );
                let keep_attr =
                    isec.hdr.flags & (S_ATTR_NO_DEAD_STRIP | S_ATTR_LIVE_SUPPORT) != 0;
                if keep_type || keep_attr || isec.hdr.sectname() == "__objc_imageinfo" {
                    Some(id)
                } else {
                    None
                }
            })
            .collect()
    };
    for id in root_ids {
        mark(&mut live, &mut pred, &mut stack, id, usize::MAX);
    }

    // Initializers converted to __init_offsets are roots; their source
    // sections are gone.
    for &(isec, _) in &ctx.init_funcs {
        mark(&mut live, &mut pred, &mut stack, isec, usize::MAX);
    }

    // Symbol-level roots, found on all cores like the section roots.
    let sym_roots: Vec<usize> = {
        use rayon::prelude::*;
        ctx.symtab
            .syms
            .par_iter()
            .filter_map(|sym| {
                let is_root = sym.no_dead_strip()
                    || (ctx.args.output_type != MH_EXECUTE
                        && sym.is_extern()
                        && !sym.is_private_extern()
                        && sym.is_defined());
                if is_root { sym.isec().map(|i| i as usize) } else { None }
            })
            .collect()
    };
    for isec in sym_roots {
        mark(&mut live, &mut pred, &mut stack, isec, usize::MAX);
    }
    if ctx.args.output_type == MH_EXECUTE {
        if let Some(id) = ctx.symtab.get(&ctx.args.entry) {
            if let Some(isec) = ctx.symtab[id].isec().map(|i| i as usize) {
                mark(&mut live, &mut pred, &mut stack, isec, usize::MAX);
            }
        }
    }

    // Propagate liveness. mold's gc-sections walks the graph in
    // parallel rounds: the frontier's out-edges are computed on all
    // cores, and an atomic visited bit decides which targets extend
    // the next frontier. The set of live sections is
    // order-independent, so the result is deterministic; only the
    // spanning tree (who marked whom) is not, so -why_live keeps the
    // serial walk to report stable chains.
    let edges_of = |id: usize, out: &mut Vec<usize>| {
        for rel in ctx.isec_relocs(id) {
            match rel.target() {
                RelocTarget::Sym(idx) => {
                    let sym = &ctx.symtab[ctx.objs[ctx.isecs[id].obj as usize].syms[idx as usize]];
                    if let Some(isec) = sym.isec().map(|i| i as usize) {
                        out.push(isec);
                    }
                }
                RelocTarget::Section(isec) => out.push(isec as usize),
            }
        }
        // A live function keeps its LSDA and personality alive, via
        // the subsection's compact-unwind record range.
        let isec = &ctx.isecs[id];
        let recs = isec.unwind_offset as usize..(isec.unwind_offset + isec.nunwind) as usize;
        for rec in &ctx.unwind_records[recs] {
            if let Some((lsda, _)) = rec.lsda() {
                out.push(lsda);
            }
            let mut personality = rec.personality();
            if let Some(fde) = rec.fde() {
                if let Some((lsda, _)) = ctx.fdes[fde].lsda {
                    out.push(lsda as usize);
                }
                personality = personality.or(ctx.cies[ctx.fdes[fde].cie as usize].personality);
            }
            if let Some(p) = personality {
                if let Some(isec) = ctx.symtab[p].isec().map(|i| i as usize) {
                    out.push(isec);
                }
            }
        }
    };

    if ctx.args.why_live.is_empty() {
        use rayon::prelude::*;
        use std::sync::atomic::{AtomicBool, Ordering};
        let visited: Vec<AtomicBool> =
            live.iter().map(|&l| AtomicBool::new(l)).collect();

        // mold's gc-sections marks with a work-stealing task pool, not
        // synchronous frontier rounds: each visit follows edges up to
        // three levels inline and banks the rest in small batches that
        // spawn as tasks (rayon tasks are heavier than TBB feeder
        // items, so batches of 16 amortize them). Unoptimized debug
        // code has deep call chains, which starve round-based marking;
        // dynamic tasks keep every core fed regardless of graph depth.
        const GC_BATCH: usize = 16;
        struct Gc<'a, E: Arch> {
            ctx: &'a Context<E>,
            visited: &'a [AtomicBool],
            redirects: &'a [usize],
        }
        fn visit_section<'s, E: Arch>(
            gc: &'s Gc<'s, E>,
            id: usize,
            depth: usize,
            scope: &rayon::Scope<'s>,
            next: &mut Vec<usize>,
        ) {
            let mut targets = Vec::new();
            for rel in gc.ctx.isec_relocs(id) {
                match rel.target() {
                    RelocTarget::Sym(idx) => {
                        let sym =
                            &gc.ctx.symtab[gc.ctx.objs[gc.ctx.isecs[id].obj as usize].syms[idx as usize]];
                        if let Some(isec) = sym.isec().map(|i| i as usize) {
                            targets.push(isec);
                        }
                    }
                    RelocTarget::Section(isec) => targets.push(isec as usize),
                }
            }
            let isec = &gc.ctx.isecs[id];
            let recs =
                isec.unwind_offset as usize..(isec.unwind_offset + isec.nunwind) as usize;
            for rec in &gc.ctx.unwind_records[recs] {
                if let Some((lsda, _)) = rec.lsda() {
                    targets.push(lsda);
                }
                let mut personality = rec.personality();
                if let Some(fde) = rec.fde() {
                    if let Some((lsda, _)) = gc.ctx.fdes[fde].lsda {
                        targets.push(lsda as usize);
                    }
                    personality =
                        personality.or(gc.ctx.cies[gc.ctx.fdes[fde].cie as usize].personality);
                }
                if let Some(p) = personality {
                    if let Some(isec) = gc.ctx.symtab[p].isec().map(|i| i as usize) {
                        targets.push(isec);
                    }
                }
            }
            for t in targets {
                let t = gc.redirects[t];
                if !gc.visited[t].swap(true, Ordering::Relaxed) {
                    if depth < 3 {
                        visit_section(gc, t, depth + 1, scope, next);
                    } else {
                        next.push(t);
                    }
                }
            }
        }
        fn visit_batch<'s, E: Arch>(
            gc: &'s Gc<'s, E>,
            batch: Vec<usize>,
            scope: &rayon::Scope<'s>,
        ) {
            let mut next = Vec::with_capacity(GC_BATCH);
            for id in batch {
                visit_section(gc, id, 0, scope, &mut next);
                if next.len() >= GC_BATCH {
                    let found =
                        std::mem::replace(&mut next, Vec::with_capacity(GC_BATCH));
                    scope.spawn(move |scope| visit_batch(gc, found, scope));
                }
            }
            if !next.is_empty() {
                scope.spawn(move |scope| visit_batch(gc, next, scope));
            }
        }
        let gc = Gc {
            ctx,
            visited: &visited,
            redirects,
        };
        let gc = &gc;
        let roots = std::mem::take(&mut stack);
        rayon::scope(|scope| {
            roots
                .par_chunks(GC_BATCH)
                .for_each(|batch| visit_batch(gc, batch.to_vec(), scope));
        });
        for (l, v) in live.iter_mut().zip(&visited) {
            *l = v.load(Ordering::Relaxed);
        }
    } else {
        while let Some(id) = stack.pop() {
            let mut out = Vec::new();
            edges_of(id, &mut out);
            for t in out {
                mark(&mut live, &mut pred, &mut stack, t, id);
            }
        }
    }

    print_why_live(ctx, &pred, &live);

    for (id, isec) in ctx.isecs.iter_mut().enumerate() {
        isec.is_alive = live[id] && isec.is_alive;
    }

    // Drop unwind records and FDEs of dead functions, remapping the
    // record-to-FDE links.
    let mut fde_map = vec![usize::MAX; ctx.fdes.len()];
    let mut kept_fdes = Vec::new();
    let fdes = std::mem::take(&mut ctx.fdes);
    for (i, fde) in fdes.into_iter().enumerate() {
        if live[fde.isec as usize] {
            fde_map[i] = kept_fdes.len();
            kept_fdes.push(fde);
        }
    }
    ctx.fdes = kept_fdes;
    let isecs = &ctx.isecs;
    let map = &fde_map;
    ctx.unwind_records.retain_mut(|rec| {
        if !isecs[rec.isec as usize].is_alive {
            return false;
        }
        if rec.fde_idx != crate::input_files::UNWIND_NONE {
            // usize::MAX (a dropped FDE) narrows to UNWIND_NONE.
            rec.fde_idx = map[rec.fde_idx as usize] as u32;
        }
        true
    });

    // The compaction moved the surviving records; refresh the ranges.
    crate::passes::refresh_unwind_ranges(ctx);
}


/// -why_live prints, for each symbol matching a -why_live pattern
/// ("*" wildcards), the chain of references that kept it alive: the
/// liveness walk's spanning tree read backwards, one "symbol from
/// file" line per hop, ending at a dead-strip root. Only meaningful
/// under -dead_strip, like ld64's option of the same name.
fn print_why_live<E: Arch>(ctx: &Context<E>, pred: &[usize], live: &[bool]) {
    if ctx.args.why_live.is_empty() {
        return;
    }

    let matches = crate::util::glob_match;

    // A displayable symbol for each live subsection: prefer an extern
    // symbol defined at it, else any named local.
    let mut name_of: std::collections::HashMap<usize, &str> = std::collections::HashMap::new();
    for sym in &ctx.symtab.syms {
        if !matches!(sym.origin(), Origin::Obj(_)) || sym.name().is_empty() {
            continue;
        }
        let Some(isec) = sym.isec().map(|i| i as usize) else { continue };
        let isec = ctx.resolve_isec(isec);
        match name_of.entry(isec) {
            std::collections::hash_map::Entry::Vacant(e) => {
                e.insert(sym.name());
            }
            std::collections::hash_map::Entry::Occupied(mut e) => {
                if sym.is_extern() && sym.value == 0 {
                    e.insert(sym.name());
                }
            }
        }
    }
    let describe = |isec: usize| -> String {
        let sec = &ctx.isecs[isec];
        let name = name_of
            .get(&isec)
            .copied()
            .map(String::from)
            .unwrap_or_else(|| format!("{},{}", sec.hdr.segname(), sec.hdr.sectname()));
        if sec.obj == u32::MAX {
            return name;
        }
        format!("{} from {}", name, crate::passes::file_display(&ctx.objs[sec.obj as usize]))
    };

    for sym in &ctx.symtab.syms {
        if !matches!(sym.origin(), Origin::Obj(_))
            || !ctx.args.why_live.iter().any(|p| matches(p, sym.name()))
        {
            continue;
        }
        let Some(isec) = sym.isec().map(|i| i as usize) else { continue };
        let mut isec = ctx.resolve_isec(isec);
        if !live[isec] {
            continue;
        }
        println!("{} from {}", sym.name(), crate::passes::file_display(&ctx.objs[ctx.isecs[isec].obj as usize]));
        let mut indent = 1;
        while pred[isec] != usize::MAX {
            isec = pred[isec];
            println!("{:indent$}{}", "", describe(isec), indent = indent * 2);
            indent += 1;
        }
    }
}

