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
    let redirects: Vec<usize> = (0..ctx.isecs.len()).map(|i| ctx.resolve_isec(i)).collect();
    let mark =
        move |live: &mut Vec<bool>, pred: &mut Vec<usize>, stack: &mut Vec<usize>, id: usize, from: usize| {
            let id = redirects[id];
            if !live[id] {
                live[id] = true;
                pred[id] = from;
                stack.push(id);
            }
        };

    // Section-level roots. Sections of dead archive members are not
    // part of the link at all and must not be resurrected here.
    for (id, isec) in ctx.isecs.iter().enumerate() {
        if !isec.is_alive {
            continue;
        }
        let keep_type = matches!(
            isec.hdr.section_type(),
            S_MOD_INIT_FUNC_POINTERS | S_INIT_FUNC_OFFSETS | S_THREAD_LOCAL_VARIABLES
        );
        let keep_attr =
            isec.hdr.flags & (S_ATTR_NO_DEAD_STRIP | S_ATTR_LIVE_SUPPORT) != 0;
        if keep_type || keep_attr || isec.hdr.sectname() == "__objc_imageinfo" {
            mark(&mut live, &mut pred, &mut stack, id, usize::MAX);
        }
    }

    // Initializers converted to __init_offsets are roots; their source
    // sections are gone.
    for &(isec, _) in &ctx.init_funcs {
        mark(&mut live, &mut pred, &mut stack, isec, usize::MAX);
    }

    // Symbol-level roots
    for sym in &ctx.symtab.syms {
        let is_root = sym.no_dead_strip
            || (ctx.args.output_type != MH_EXECUTE
                && sym.is_extern
                && !sym.is_private_extern
                && sym.is_defined());
        if is_root {
            if let Some(isec) = sym.isec {
                mark(&mut live, &mut pred, &mut stack, isec, usize::MAX);
            }
        }
    }
    if ctx.args.output_type == MH_EXECUTE {
        if let Some(id) = ctx.symtab.get(&ctx.args.entry) {
            if let Some(isec) = ctx.symtab[id].isec {
                mark(&mut live, &mut pred, &mut stack, isec, usize::MAX);
            }
        }
    }

    // Unwind records for a live function keep its LSDA and personality
    // alive; index them by function subsection.
    let mut unwind_by_isec: std::collections::HashMap<usize, Vec<usize>> =
        std::collections::HashMap::new();
    for (i, rec) in ctx.unwind_records.iter().enumerate() {
        unwind_by_isec.entry(rec.isec).or_default().push(i);
    }

    while let Some(id) = stack.pop() {
        for rel in &ctx.isecs[id].relocs {
            match rel.target {
                RelocTarget::Sym(idx) => {
                    let sym = &ctx.symtab[ctx.objs[ctx.isecs[id].obj].syms[idx]];
                    if let Some(isec) = sym.isec {
                        mark(&mut live, &mut pred, &mut stack, isec, id);
                    }
                }
                RelocTarget::Section(isec) => mark(&mut live, &mut pred, &mut stack, isec, id),
            }
        }

        for &rec_idx in unwind_by_isec.get(&id).map(Vec::as_slice).unwrap_or(&[]) {
            let rec = &ctx.unwind_records[rec_idx];
            if let Some((lsda, _)) = rec.lsda {
                mark(&mut live, &mut pred, &mut stack, lsda, id);
            }
            let mut personality = rec.personality;
            if let Some(fde) = rec.fde {
                if let Some((lsda, _)) = ctx.fdes[fde].lsda {
                    mark(&mut live, &mut pred, &mut stack, lsda, id);
                }
                personality = personality.or(ctx.cies[ctx.fdes[fde].cie].personality);
            }
            if let Some(p) = personality {
                if let Some(isec) = ctx.symtab[p].isec {
                    mark(&mut live, &mut pred, &mut stack, isec, id);
                }
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
        if live[fde.isec] {
            fde_map[i] = kept_fdes.len();
            kept_fdes.push(fde);
        }
    }
    ctx.fdes = kept_fdes;
    let isecs = &ctx.isecs;
    let map = &fde_map;
    ctx.unwind_records.retain_mut(|rec| {
        if !isecs[rec.isec].is_alive {
            return false;
        }
        if let Some(fde) = &mut rec.fde {
            *fde = map[*fde];
        }
        true
    });
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
        if !matches!(sym.origin, Origin::Obj(_)) || sym.name.is_empty() {
            continue;
        }
        let Some(isec) = sym.isec else { continue };
        let isec = ctx.resolve_isec(isec);
        match name_of.entry(isec) {
            std::collections::hash_map::Entry::Vacant(e) => {
                e.insert(sym.name);
            }
            std::collections::hash_map::Entry::Occupied(mut e) => {
                if sym.is_extern && sym.value == 0 {
                    e.insert(sym.name);
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
        if sec.obj == usize::MAX {
            return name;
        }
        format!("{} from {}", name, crate::passes::file_display(&ctx.objs[sec.obj]))
    };

    for sym in &ctx.symtab.syms {
        if !matches!(sym.origin, Origin::Obj(_))
            || !ctx.args.why_live.iter().any(|p| matches(p, sym.name))
        {
            continue;
        }
        let Some(isec) = sym.isec else { continue };
        let mut isec = ctx.resolve_isec(isec);
        if !live[isec] {
            continue;
        }
        println!("{} from {}", sym.name, crate::passes::file_display(&ctx.objs[ctx.isecs[isec].obj]));
        let mut indent = 1;
        while pred[isec] != usize::MAX {
            isec = pred[isec];
            println!("{:indent$}{}", "", describe(isec), indent = indent * 2);
            indent += 1;
        }
    }
}

