//! The linker passes, in the order the driver runs them.

use std::path::{Path, PathBuf};

use crate::arch::Arch;
use crate::cmdline::InputArg;
use crate::context::Context;
use crate::error;
use crate::fatal;
use crate::filetype::{get_file_type, FileType};
use crate::input_files;
use crate::input_sections::{InputSection, RelocTarget};
use crate::macho::*;
use crate::mapped_file::MappedFile;
use crate::output_chunks::{
    self, Chunk, ChunkKind, OutputSegment, code_signature_size, mach_header_size,
    section_ordinals,
};
use crate::arch::RelocClass;
use crate::symbol::Origin;
use crate::util::{align_to, write_uleb};

/// Returns the directories to search for `-l` libraries, in order. A
/// library path that exists under a syslibroot is looked up there; the
/// default search path is the syslibroot's /usr/lib.
fn library_search_dirs<E: Arch>(ctx: &Context<E>) -> Vec<PathBuf> {
    let mut dirs = Vec::new();

    for dir in &ctx.args.library_paths {
        let mut found = false;
        for root in &ctx.args.syslibroot {
            let path = Path::new(root).join(dir.trim_start_matches('/'));
            if path.is_dir() {
                dirs.push(path);
                found = true;
            }
        }
        if !found {
            dirs.push(PathBuf::from(dir));
        }
    }

    if ctx.args.syslibroot.is_empty() {
        dirs.push(PathBuf::from("/usr/lib"));
    } else {
        for root in &ctx.args.syslibroot {
            dirs.push(Path::new(root).join("usr/lib"));
        }
    }
    dirs
}

/// Returns the directories to search for `-framework`, in order,
/// mirroring the library search rules.
fn framework_search_dirs<E: Arch>(ctx: &Context<E>) -> Vec<PathBuf> {
    let mut dirs = Vec::new();

    for dir in &ctx.args.framework_paths {
        let mut found = false;
        for root in &ctx.args.syslibroot {
            let path = Path::new(root).join(dir.trim_start_matches('/'));
            if path.is_dir() {
                dirs.push(path);
                found = true;
            }
        }
        if !found {
            dirs.push(PathBuf::from(dir));
        }
    }

    if ctx.args.syslibroot.is_empty() {
        dirs.push(PathBuf::from("/System/Library/Frameworks"));
        dirs.push(PathBuf::from("/Library/Frameworks"));
    } else {
        for root in &ctx.args.syslibroot {
            dirs.push(Path::new(root).join("System/Library/Frameworks"));
            dirs.push(Path::new(root).join("Library/Frameworks"));
        }
    }
    dirs
}

fn find_framework<E: Arch>(ctx: &Context<E>, name: &str) -> Option<PathBuf> {
    for dir in framework_search_dirs(ctx) {
        let fw = dir.join(format!("{name}.framework"));
        for file in [format!("{name}.tbd"), name.to_string()] {
            let path = fw.join(file);
            if path.is_file() {
                return Some(path);
            }
        }
    }
    None
}

fn find_library<E: Arch>(ctx: &Context<E>, name: &str) -> Option<PathBuf> {
    for dir in library_search_dirs(ctx) {
        for ext in ["tbd", "dylib", "a"] {
            let path = dir.join(format!("lib{name}.{ext}"));
            if path.is_file() {
                return Some(path);
            }
        }
    }
    None
}

/// A parsed-input request: a file to stage as an object, with its
/// liveness and input-order priority.
struct PendingObject {
    mf: &'static MappedFile,
    alive: bool,
    priority: u32,
}

/// Classifies one input file. Dylib stubs and binaries are registered
/// immediately (they are cheap and order-sensitive); objects and
/// archive members are queued for parallel staging; bitcode is
/// registered immediately since libLTO calls are kept on one thread.
fn collect_file<E: Arch>(
    ctx: &mut Context<E>,
    mf: &'static MappedFile,
    force_load: bool,
    weak: bool,
    out: &mut Vec<PendingObject>,
) {
    // A library may be named both on the command line and by auto-link
    // options; load each file once.
    if !ctx.visited_files.insert(mf.name.clone()) {
        return;
    }
    match get_file_type(mf) {
        FileType::Object => {
            let priority = ctx.next_priority();
            out.push(PendingObject {
                mf,
                alive: true,
                priority,
            });
        }
        FileType::Tapi => {
            let idx = input_files::parse_dylib(ctx, mf);
            if weak {
                ctx.dylibs[idx].is_weak = true;
            }
        }
        FileType::Dylib => {
            let idx = input_files::parse_dylib_binary(ctx, mf);
            if weak {
                ctx.dylibs[idx].is_weak = true;
            }
        }
        FileType::Archive => {
            // Every member is parsed eagerly; whether it is *live* -
            // whether its content reaches the output - is decided by
            // symbol resolution and the liveness walk. -all_load and
            // -force_load make every member live up front; -ObjC does
            // so for members with Objective-C metadata, which register
            // classes by their mere presence.
            let members = input_files::read_archive_members(ctx, mf);
            for member in members {
                let alive = force_load
                    || ctx.args.all_load
                    || (ctx.args.load_objc && input_files::has_objc_sections(member));
                match get_file_type(member) {
                    FileType::LlvmBitcode => {
                        input_files::parse_bitcode(ctx, member, alive);
                    }
                    _ => {
                        let priority = ctx.next_priority();
                        out.push(PendingObject {
                            mf: member,
                            alive,
                            priority,
                        });
                    }
                }
            }
        }
        FileType::Fat => {
            let slice = input_files::get_fat_slice(ctx, mf);
            collect_file(ctx, slice, force_load, weak, out);
        }
        FileType::LlvmBitcode => {
            input_files::parse_bitcode(ctx, mf, true);
        }
        FileType::Empty => {}
        _ => fatal!(ctx, "{}: unknown file type", mf.name),
    }
}

/// Stages the queued object files in parallel and integrates them in
/// input order - the parallel front end of the mold design.
fn load_pending<E: Arch>(ctx: &mut Context<E>, pending: Vec<PendingObject>) {
    use rayon::prelude::*;
    let diag = ctx.diag.clone();
    let staged: Vec<input_files::StagedObject> = pending
        .par_iter()
        .map(|p| input_files::stage_object::<E>(&diag, p.mf, p.alive, p.priority))
        .collect();
    for st in staged {
        input_files::integrate_object(ctx, st);
    }
}

pub fn read_input_files<E: Arch>(ctx: &mut Context<E>) {
    let inputs = std::mem::take(&mut ctx.args.inputs);
    let mut queue: Vec<PendingObject> = Vec::new();
    for arg in &inputs {
        match arg {
            InputArg::File(path) => {
                let mf = MappedFile::must_open(&ctx.diag, Path::new(path));
                collect_file(ctx, mf, false, false, &mut queue);
            }
            InputArg::ForceLoad(path) => {
                let mf = MappedFile::must_open(&ctx.diag, Path::new(path));
                collect_file(ctx, mf, true, false, &mut queue);
            }
            InputArg::WeakFile(path) => {
                let mf = MappedFile::must_open(&ctx.diag, Path::new(path));
                collect_file(ctx, mf, false, true, &mut queue);
            }
            InputArg::Lib(name, weak) => match find_library(ctx, name) {
                Some(path) => {
                    let mf = MappedFile::must_open(&ctx.diag, &path);
                    collect_file(ctx, mf, false, *weak, &mut queue);
                }
                None => error!(ctx, "library not found: -l{name}"),
            },
            InputArg::Framework(name, weak) => match find_framework(ctx, name) {
                Some(path) => {
                    let mf = MappedFile::must_open(&ctx.diag, &path);
                    collect_file(ctx, mf, false, *weak, &mut queue);
                }
                None => error!(ctx, "framework not found: {name}"),
            },
        }
    }
    ctx.args.inputs = inputs;
    load_pending(ctx, queue);
}

/// Acts on auto-link options (LC_LINKER_OPTION) of live objects: each
/// names a library or framework the object needs, as if it had been on
/// the command line. Swift objects rely on this entirely. Returns true
/// if new inputs were loaded, in which case resolution must run again.
pub fn load_autolink_deps<E: Arch>(ctx: &mut Context<E>) -> bool {
    let mut pending: Vec<Vec<String>> = Vec::new();
    for obj in &ctx.objs {
        if !obj.is_alive {
            continue;
        }
        for opt in &obj.linker_options {
            if !ctx.processed_linker_options.contains(opt) {
                pending.push(opt.clone());
            }
        }
    }

    let before = (ctx.objs.len(), ctx.dylibs.len());
    let mut queue: Vec<PendingObject> = Vec::new();
    for opt in pending {
        ctx.processed_linker_options.insert(opt.clone());
        let strs: Vec<&str> = opt.iter().map(String::as_str).collect();
        match strs.as_slice() {
            [flag] if flag.starts_with("-l") => {
                let name = &flag[2..];
                match find_library(ctx, name) {
                    Some(path) => {
                        if let Some(mf) = MappedFile::open(&ctx.diag, &path) {
                            collect_file(ctx, mf, false, false, &mut queue);
                        }
                    }
                    None => crate::warn!(ctx, "auto-linked library not found: -l{name}"),
                }
            }
            ["-framework", name] => match find_framework(ctx, name) {
                Some(path) => {
                    if let Some(mf) = MappedFile::open(&ctx.diag, &path) {
                        collect_file(ctx, mf, false, false, &mut queue);
                    }
                }
                None => crate::warn!(ctx, "auto-linked framework not found: {name}"),
            },
            _ => crate::warn!(ctx, "unknown auto-link option: {:?}", opt),
        }
    }
    load_pending(ctx, queue);
    (ctx.objs.len(), ctx.dylibs.len()) != before
}

/// Resolves all symbols, following mold's model: every input including
/// each archive member has been parsed already, and resolution ranks
/// competing definitions (strong > weak > lazy archive member or dylib
/// > common), breaking ties by input order. A liveness walk then marks
/// the archive members whose definitions are actually referenced, and
/// a second round restricted to live files settles the final owners.
pub fn resolve_symbols<E: Arch>(ctx: &mut Context<E>) {
    clear_claims(ctx);
    do_resolve(ctx, false);
    mark_live_objects(ctx);
    clear_claims(ctx);
    do_resolve(ctx, true);
    claim_locals(ctx);
}

/// Non-external symbols are private to their object and never compete:
/// each gets its definition directly. Relocations reference them by
/// symbol index just like externals, so they need locations too.
fn claim_locals<E: Arch>(ctx: &mut Context<E>) {
    for obj_idx in 0..ctx.objs.len() {
        for i in 0..ctx.objs[obj_idx].nlists.len() {
            let nlist = ctx.objs[obj_idx].nlists[i];
            if nlist.is_stab() || nlist.is_extern() {
                continue;
            }
            let sym_id = ctx.objs[obj_idx].syms[i];
            match nlist.n_type() {
                N_ABS => {
                    let sym = &mut ctx.symtab[sym_id];
                    sym.origin = Origin::Obj(obj_idx);
                    sym.isec = None;
                    sym.value = nlist.n_value;
                }
                N_SECT => {
                    if let Some((isec, off)) = crate::input_files::find_subsec(
                        &ctx.isecs,
                        &ctx.objs[obj_idx].subsecs,
                        nlist.n_value,
                    ) {
                        let sym = &mut ctx.symtab[sym_id];
                        sym.origin = Origin::Obj(obj_idx);
                        sym.isec = Some(isec);
                        sym.value = off;
                        sym.no_dead_strip =
                            nlist.n_desc & (N_NO_DEAD_STRIP | REFERENCED_DYNAMICALLY) != 0;
                    }
                }
                _ => {}
            }
        }
    }
}

fn clear_claims<E: Arch>(ctx: &mut Context<E>) {
    for sym in &mut ctx.symtab.syms {
        if matches!(sym.origin, Origin::Obj(_) | Origin::Dylib(_)) || sym.is_common {
            sym.origin = Origin::Undef;
            sym.isec = None;
            sym.value = 0;
            sym.is_weak_def = false;
            sym.is_private_extern = false;
            sym.is_imported = false;
            sym.is_common = false;
            sym.common_p2align = 0;
            sym.no_dead_strip = false;
        }
    }
}

fn do_resolve<E: Arch>(ctx: &mut Context<E>, only_alive: bool) {
    // The best claim seen per symbol: (rank class << 32) | priority,
    // lower is better.
    let mut best = vec![u64::MAX; ctx.symtab.syms.len()];

    // Which symbols the files considered this round actually reference.
    // References from dead archive members must not count: they would
    // otherwise demand definitions nothing live needs.
    let mut used = vec![false; ctx.symtab.syms.len()];
    for obj in &ctx.objs {
        if only_alive && !obj.is_alive {
            continue;
        }
        for (nlist, &sym_id) in obj.nlists.iter().zip(&obj.syms) {
            if !nlist.is_stab() && nlist.is_extern() && nlist.n_type() == N_UNDF {
                used[sym_id] = true;
                if nlist.n_desc & N_WEAK_REF != 0 {
                    ctx.symtab[sym_id].is_weak_ref = true;
                }
            }
        }
    }
    for name in &ctx.args.forced_undefined {
        if let Some(id) = ctx.symtab.get(name) {
            used[id] = true;
        }
    }
    if let Some(id) = ctx.symtab.get(&ctx.args.entry) {
        used[id] = true;
    }

    for obj_idx in 0..ctx.objs.len() {
        let alive = ctx.objs[obj_idx].is_alive;
        if only_alive && !alive {
            continue;
        }
        let priority = ctx.objs[obj_idx].priority as u64;

        for i in 0..ctx.objs[obj_idx].nlists.len() {
            let nlist = ctx.objs[obj_idx].nlists[i];
            let sym_id = ctx.objs[obj_idx].syms[i];
            if nlist.is_stab() || !nlist.is_extern() {
                continue;
            }

            let is_weak = nlist.n_desc & N_WEAK_DEF != 0;
            let class: u64 = match nlist.n_type() {
                N_SECT | N_ABS if alive && !is_weak => 0,
                N_SECT | N_ABS if alive => 1,
                N_SECT | N_ABS => 2,
                N_UNDF if nlist.is_common() && alive => 3,
                _ => continue,
            };
            let rank = (class << 32) | priority;

            // Common symbols merge: the largest size and strictest
            // alignment win regardless of input order.
            if class == 3 {
                let sym = &mut ctx.symtab[sym_id];
                if best[sym_id] >> 32 == 3 {
                    sym.value = sym.value.max(nlist.n_value);
                    sym.common_p2align =
                        sym.common_p2align.max(((nlist.n_desc >> 8) & 0xf) as u8);
                    best[sym_id] = best[sym_id].min(rank);
                    continue;
                }
            }

            if rank >= best[sym_id] {
                if only_alive && rank >> 32 == 0 && best[sym_id] >> 32 == 0 && rank != best[sym_id]
                {
                    // Two live strong definitions.
                    error!(ctx, "duplicate symbol: {}", ctx.symtab[sym_id].name);
                }
                continue;
            }
            best[sym_id] = rank;

            let sym = &mut ctx.symtab[sym_id];
            sym.is_extern = true;
            sym.is_imported = false;
            sym.is_common = false;
            sym.is_weak_def = is_weak;
            sym.is_private_extern = nlist.n_type & N_PEXT != 0;
            sym.no_dead_strip =
                nlist.n_desc & (N_NO_DEAD_STRIP | REFERENCED_DYNAMICALLY) != 0;

            match nlist.n_type() {
                N_ABS => {
                    sym.origin = Origin::Obj(obj_idx);
                    sym.isec = None;
                    sym.value = nlist.n_value;
                }
                N_SECT => {
                    sym.origin = Origin::Obj(obj_idx);
                    match crate::input_files::find_subsec(
                        &ctx.isecs,
                        &ctx.objs[obj_idx].subsecs,
                        nlist.n_value,
                    ) {
                        Some((isec, off)) => {
                            let sym = &mut ctx.symtab[sym_id];
                            sym.isec = Some(isec);
                            sym.value = off;
                        }
                        None => {
                            // A symbol in a discarded (debug) section.
                            let sym = &mut ctx.symtab[sym_id];
                            sym.origin = Origin::Undef;
                            best[sym_id] = u64::MAX;
                        }
                    }
                }
                N_UNDF => {
                    // A common symbol takes a tentative claim.
                    let sym = &mut ctx.symtab[sym_id];
                    sym.origin = Origin::Undef;
                    sym.is_common = true;
                    sym.value = nlist.n_value;
                    sym.common_p2align = ((nlist.n_desc >> 8) & 0xf) as u8;
                }
                _ => unreachable!(),
            }
        }
    }

    // Dylib exports claim unresolved (or lazily-claimed) symbols; an
    // earlier dylib beats a later archive member and vice versa.
    for i in 0..ctx.symtab.syms.len() {
        let sym = &ctx.symtab[i];
        if !used[i] || sym.is_common {
            continue;
        }
        if best[i] >> 32 < 2 {
            continue;
        }
        let name = sym.name;
        for dylib_idx in 0..ctx.dylibs.len() {
            let dylib = &ctx.dylibs[dylib_idx];
            let rank = (2u64 << 32) | dylib.priority as u64;
            if rank < best[i] && dylib.exports.contains(name) {
                best[i] = rank;
                let sym = &mut ctx.symtab[i];
                sym.origin = Origin::Dylib(dylib_idx);
                sym.is_imported = true;
                sym.is_extern = true;
                sym.isec = None;
                sym.is_common = false;
                break;
            }
        }
    }

    // Record the final usage set for downstream passes.
    for (i, &u) in used.iter().enumerate() {
        ctx.symtab.syms[i].is_used = u;
    }
}

/// Marks archive members whose definitions live code references,
/// walking owner links to a fixed point.
fn mark_live_objects<E: Arch>(ctx: &mut Context<E>) {
    let mut queue: Vec<usize> = (0..ctx.objs.len())
        .filter(|&i| ctx.objs[i].is_alive)
        .collect();

    // The entry point and -u symbols are roots too.
    let mut root_syms: Vec<&str> = vec![ctx.args.entry.as_str()];
    root_syms.extend(ctx.args.forced_undefined.iter().map(String::as_str));
    for name in root_syms {
        if let Some(id) = ctx.symtab.get(name) {
            if let Origin::Obj(owner) = ctx.symtab[id].origin {
                if !ctx.objs[owner].is_alive {
                    ctx.objs[owner].is_alive = true;
                    queue.push(owner);
                }
            }
        }
    }

    while let Some(obj_idx) = queue.pop() {
        for i in 0..ctx.objs[obj_idx].nlists.len() {
            let nlist = ctx.objs[obj_idx].nlists[i];
            if nlist.is_stab() || !nlist.is_extern() || nlist.n_type() != N_UNDF {
                continue;
            }
            let sym_id = ctx.objs[obj_idx].syms[i];
            if let Origin::Obj(owner) = ctx.symtab[sym_id].origin {
                if !ctx.objs[owner].is_alive {
                    ctx.objs[owner].is_alive = true;
                    queue.push(owner);
                }
            }
        }
    }
}

/// Compiles all registered bitcode modules into one Mach-O object and
/// replaces the placeholder objects' symbol claims with the real ones.
pub fn run_lto<E: Arch>(ctx: &mut Context<E>) -> bool {
    if ctx.lto_modules.is_empty() {
        return false;
    }
    let plugin = ctx.lto_plugin.unwrap();

    // SAFETY: libLTO calls with handles created by the same library.
    let data = unsafe {
        let cg = (plugin.codegen_create)();
        if cg.is_null() {
            fatal!(ctx, "lto_codegen_create failed: {}", plugin.error_message());
        }
        (plugin.codegen_set_pic_model)(cg, crate::lto::LTO_CODEGEN_PIC_MODEL_DYNAMIC);

        for &(_, module) in &ctx.lto_modules {
            if (plugin.codegen_add_module)(cg, module as *mut _) {
                fatal!(ctx, "lto_codegen_add_module failed: {}", plugin.error_message());
            }
        }

        // Everything the rest of the link can see must survive the LTO
        // internalizer: every external symbol a bitcode module defines,
        // plus the entry point.
        let mut preserve: Vec<std::ffi::CString> = Vec::new();
        for sym in &ctx.symtab.syms {
            if let Origin::Obj(idx) = sym.origin {
                if ctx.objs[idx].lto_module.is_some() && sym.is_extern {
                    if let Ok(name) = std::ffi::CString::new(sym.name) {
                        preserve.push(name);
                    }
                }
            }
        }
        if let Ok(name) = std::ffi::CString::new(ctx.args.entry.as_str()) {
            preserve.push(name);
        }
        for name in &preserve {
            (plugin.codegen_add_must_preserve_symbol)(cg, name.as_ptr());
        }

        let mut size = 0usize;
        let ptr = (plugin.codegen_compile)(cg, &mut size);
        if ptr.is_null() {
            fatal!(ctx, "lto_codegen_compile failed: {}", plugin.error_message());
        }
        std::slice::from_raw_parts(ptr as *const u8, size).to_vec()
    };

    // Retire the placeholders: the compiled object provides the real
    // definitions, so they must neither claim nor reference anything in
    // the next resolution round.
    let modules = std::mem::take(&mut ctx.lto_modules);
    for &(obj_idx, _) in &modules {
        let ids = ctx.objs[obj_idx].syms.clone();
        for id in ids {
            let sym = &mut ctx.symtab[id];
            if sym.origin == Origin::Obj(obj_idx) {
                sym.origin = Origin::Undef;
                sym.isec = None;
                sym.value = 0;
                sym.is_weak_def = false;
            }
        }
        let obj = &mut ctx.objs[obj_idx];
        obj.is_alive = false;
        obj.nlists.clear();
        obj.syms.clear();
    }

    let mf = Box::leak(Box::new(crate::mapped_file::MappedFile {
        name: "<LTO>".to_string(),
        data: Vec::leak(data),
        parent: None,
    }));
    input_files::parse_object(ctx, mf, true);
    true
}

/// Converts surviving tentative definitions (common symbols) into real
/// definitions in a synthetic __DATA,__common zero-fill section.
pub fn convert_common_symbols<E: Arch>(ctx: &mut Context<E>) {
    for i in 0..ctx.symtab.syms.len() {
        let sym = &ctx.symtab[i];
        if !sym.is_common || sym.is_defined() {
            continue;
        }
        let (size, p2align) = (sym.value, sym.common_p2align);

        let hdr = MachSection {
            sectname: str_to_name("__common"),
            segname: str_to_name("__DATA"),
            size,
            p2align: p2align as u32,
            flags: S_ZEROFILL,
            ..Default::default()
        };
        ctx.isecs.push(InputSection {
            obj: usize::MAX,
            hdr,
            input_addr: 0,
            size,
            data: &[],
            relocs: Vec::new(),
            osec: usize::MAX,
            output_offset: 0,
            is_alive: true,
            replacement: None,
        });

        let sym = &mut ctx.symtab[i];
        sym.origin = Origin::Synthetic;
        sym.isec = Some(ctx.isecs.len() - 1);
        sym.value = 0;
        sym.is_common = false;
        sym.is_extern = true;
    }
}

/// Hides the subsections of archive members that resolution left
/// dead, so nothing of theirs reaches the output.
pub fn sweep_dead_files<E: Arch>(ctx: &mut Context<E>) {
    for isec in &mut ctx.isecs {
        if isec.obj != usize::MAX && !ctx.objs[isec.obj].is_alive {
            isec.is_alive = false;
        }
    }

    // Unwind records and FDEs of dead files go too, remapping the
    // record-to-FDE links around the removals.
    let mut fde_map = vec![usize::MAX; ctx.fdes.len()];
    let mut kept_fdes = Vec::new();
    let fdes = std::mem::take(&mut ctx.fdes);
    for (i, fde) in fdes.into_iter().enumerate() {
        if ctx.isecs[fde.isec].is_alive {
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

/// Merges identical literal elements across all live inputs: the first
/// live copy wins and the rest redirect to it.
pub fn merge_literals<E: Arch>(ctx: &mut Context<E>) {
    let mut map: std::collections::HashMap<(u32, &'static [u8]), usize> =
        std::collections::HashMap::new();
    for i in 0..ctx.isecs.len() {
        let isec = &ctx.isecs[i];
        if !isec.is_alive || isec.replacement.is_some() {
            continue;
        }
        let ty = isec.hdr.section_type();
        if !matches!(
            ty,
            S_CSTRING_LITERALS | S_4BYTE_LITERALS | S_8BYTE_LITERALS | S_16BYTE_LITERALS
        ) {
            continue;
        }
        match map.entry((ty, isec.data)) {
            std::collections::hash_map::Entry::Occupied(e) => {
                let winner = *e.get();
                let p2align = ctx.isecs[i].hdr.p2align;
                ctx.isecs[i].replacement = Some(winner);
                let w = &mut ctx.isecs[winner];
                w.hdr.p2align = w.hdr.p2align.max(p2align);
            }
            std::collections::hash_map::Entry::Vacant(e) => {
                e.insert(i);
            }
        }
    }
}

/// Synthesizes _objc_msgSend$<selector> stubs. With selector stubs
/// (the default since Xcode 14), the compiler calls these
/// linker-provided symbols instead of setting up the selector argument
/// itself; each stub loads the interned selector and tail-calls
/// _objc_msgSend.
pub fn create_objc_msgsend_stubs<E: Arch>(ctx: &mut Context<E>) {
    for i in 0..ctx.symtab.syms.len() {
        let sym = &ctx.symtab[i];
        if sym.is_defined() || !sym.is_used {
            continue;
        }
        let Some(sel) = sym.name.strip_prefix("_objc_msgSend$") else {
            continue;
        };
        let sel = sel.to_string();
        let idx = ctx.objc_stubs.len() as u32;
        let sym = &mut ctx.symtab[i];
        sym.origin = Origin::Synthetic;
        sym.objc_stub_idx = Some(idx);
        ctx.objc_stubs.push((i, sel));
    }

    if !ctx.objc_stubs.is_empty() {
        let id = ctx.symtab.intern("_objc_msgSend");
        ctx.symtab[id].is_used = true;
        ctx.objc_msgsend_sym = Some(id);

        // The stub machinery itself references _objc_msgSend; resolve
        // it now, since regular resolution has already run.
        if !ctx.symtab[id].is_defined() {
            if let Some(dylib) = ctx
                .dylibs
                .iter()
                .position(|d| d.exports.contains("_objc_msgSend"))
            {
                let sym = &mut ctx.symtab[id];
                sym.origin = Origin::Dylib(dylib);
                sym.is_imported = true;
                sym.is_extern = true;
            }
        }

        // Build the __objc_methname contents: one NUL-terminated string
        // per selector.
        for i in 0..ctx.objc_stubs.len() {
            ctx.objc_methname_offs.push(ctx.objc_methname_data.len() as u64);
            let sel = ctx.objc_stubs[i].1.clone();
            ctx.objc_methname_data.extend_from_slice(sel.as_bytes());
            ctx.objc_methname_data.push(0);
        }
    }
}

/// Reports references to symbols that are still unresolved; with
/// `-undefined dynamic_lookup` they become flat-namespace imports that
/// dyld resolves against any loaded image at run time.
pub fn check_undefined_symbols<E: Arch>(ctx: &mut Context<E>) {
    for i in 0..ctx.symtab.syms.len() {
        let sym = &ctx.symtab[i];
        if sym.is_used && !sym.is_defined() {
            if ctx.args.undefined_dynamic_lookup {
                let sym = &mut ctx.symtab[i];
                sym.origin = Origin::Dylib(usize::MAX);
                sym.is_imported = true;
                sym.is_extern = true;
            } else {
                error!(ctx, "undefined symbol: {}", sym.name);
            }
        }
    }
}

/// Removes subsections that are not reachable from the roots: the entry
/// point, exported symbols (for a dylib), and everything the format
/// requires to stay (initializers, no-dead-strip sections and symbols).
/// Reachability follows relocations and unwind-info edges.
pub fn dead_strip<E: Arch>(ctx: &mut Context<E>) {
    let mut live = vec![false; ctx.isecs.len()];
    let mut stack: Vec<usize> = Vec::new();
    let redirects: Vec<usize> = (0..ctx.isecs.len()).map(|i| ctx.resolve_isec(i)).collect();
    let mark = move |live: &mut Vec<bool>, stack: &mut Vec<usize>, id: usize| {
        let id = redirects[id];
        if !live[id] {
            live[id] = true;
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
            mark(&mut live, &mut stack, id);
        }
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
                mark(&mut live, &mut stack, isec);
            }
        }
    }
    if ctx.args.output_type == MH_EXECUTE {
        if let Some(id) = ctx.symtab.get(&ctx.args.entry) {
            if let Some(isec) = ctx.symtab[id].isec {
                mark(&mut live, &mut stack, isec);
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
                        mark(&mut live, &mut stack, isec);
                    }
                }
                RelocTarget::Section(isec) => mark(&mut live, &mut stack, isec),
            }
        }

        for &rec_idx in unwind_by_isec.get(&id).map(Vec::as_slice).unwrap_or(&[]) {
            let rec = &ctx.unwind_records[rec_idx];
            if let Some((lsda, _)) = rec.lsda {
                mark(&mut live, &mut stack, lsda);
            }
            let mut personality = rec.personality;
            if let Some(fde) = rec.fde {
                if let Some((lsda, _)) = ctx.fdes[fde].lsda {
                    mark(&mut live, &mut stack, lsda);
                }
                personality = personality.or(ctx.cies[ctx.fdes[fde].cie].personality);
            }
            if let Some(p) = personality {
                if let Some(isec) = ctx.symtab[p].isec {
                    mark(&mut live, &mut stack, isec);
                }
            }
        }
    }

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

/// Drops load commands for dylibs no symbol binds to
/// (-dead_strip_dylibs). Bind records name dylibs by their 1-based
/// load-command ordinal, so surviving dylibs are renumbered and symbol
/// origins remapped.
pub fn dead_strip_dylibs<E: Arch>(ctx: &mut Context<E>) {
    if !ctx.args.dead_strip_dylibs {
        return;
    }

    let mut used = vec![false; ctx.dylibs.len()];
    for sym in &ctx.symtab.syms {
        if let Origin::Dylib(idx) = sym.origin {
            if idx != usize::MAX {
                used[idx] = true;
            }
        }
    }

    let mut remap = vec![usize::MAX; ctx.dylibs.len()];
    let old = std::mem::take(&mut ctx.dylibs);
    for (i, mut dylib) in old.into_iter().enumerate() {
        if used[i] {
            remap[i] = ctx.dylibs.len();
            dylib.dylib_idx = ctx.dylibs.len() as i32 + 1;
            ctx.dylibs.push(dylib);
        }
    }

    for sym in &mut ctx.symtab.syms {
        if let Origin::Dylib(idx) = sym.origin {
            if idx != usize::MAX {
                sym.origin = Origin::Dylib(remap[idx]);
            }
        }
    }
}

/// Decides which symbols need a stub or a GOT slot, from how relocations
/// refer to them.
pub fn scan_relocs<E: Arch>(ctx: &mut Context<E>) {
    let mut classes = Vec::new();
    for isec in &ctx.isecs {
        if !isec.is_alive {
            continue;
        }
        for rel in &isec.relocs {
            if let Some(id) = ctx.reloc_target_sym(isec.obj, rel) {
                classes.push((id, E::classify_reloc(rel.r_type)));
            }
        }
    }

    for (id, class) in classes {
        let sym = &ctx.symtab[id];
        match class {
            RelocClass::Branch if sym.is_imported => {
                // A stub jumps through the symbol's GOT slot.
                add_stub(ctx, id);
                add_got(ctx, id);
            }
            RelocClass::Got => add_got(ctx, id),
            RelocClass::Tlv => {
                if ctx.symtab[id].is_imported {
                    fatal!(ctx, "not implemented: thread-locals imported from a dylib");
                }
                add_thread_ptr(ctx, id);
            }
            _ => {}
        }
    }
}

/// The synthesized objc stubs call _objc_msgSend through the GOT.
pub fn scan_objc_stubs<E: Arch>(ctx: &mut Context<E>) {
    if let Some(id) = ctx.objc_msgsend_sym {
        add_got(ctx, id);
    }
}

/// Personality functions are referenced from __unwind_info through the
/// GOT.
pub fn scan_unwind_personalities<E: Arch>(ctx: &mut Context<E>) {
    let mut personalities: Vec<_> = ctx
        .unwind_records
        .iter()
        .filter_map(|rec| rec.personality)
        .collect();
    personalities.extend(ctx.cies.iter().filter_map(|cie| cie.personality));
    for id in personalities {
        add_got(ctx, id);
    }
}

fn add_thread_ptr<E: Arch>(ctx: &mut Context<E>, id: crate::symbol::SymbolId) {
    if ctx.symtab[id].tlv_idx.is_none() {
        ctx.symtab[id].tlv_idx = Some(ctx.thread_ptr_syms.len() as u32);
        ctx.thread_ptr_syms.push(id);
    }
}

fn add_stub<E: Arch>(ctx: &mut Context<E>, id: crate::symbol::SymbolId) {
    if ctx.symtab[id].stub_idx.is_none() {
        ctx.symtab[id].stub_idx = Some(ctx.stub_syms.len() as u32);
        ctx.stub_syms.push(id);
    }
}

fn add_got<E: Arch>(ctx: &mut Context<E>, id: crate::symbol::SymbolId) {
    if ctx.symtab[id].got_idx.is_none() {
        ctx.symtab[id].got_idx = Some(ctx.got_syms.len() as u32);
        ctx.got_syms.push(id);
    }
}

/// Defines the symbols the linker itself provides.
pub fn create_synthetic_symbols<E: Arch>(ctx: &mut Context<E>) {
    if ctx.args.output_type == MH_EXECUTE {
        let id = ctx.symtab.intern("__mh_execute_header");
        let sym = &mut ctx.symtab[id];
        if !sym.is_defined() {
            sym.origin = Origin::Synthetic;
            sym.value = ctx.args.pagezero_size;
            sym.is_extern = true;
        }
    }

    // ___dso_handle identifies the image; C++ static destructors pass it
    // to __cxa_atexit. It resolves to the mach header but is never
    // exported.
    let id = ctx.symtab.intern("___dso_handle");
    let sym = &mut ctx.symtab[id];
    if !sym.is_defined() {
        sym.origin = Origin::Synthetic;
        sym.value = ctx.args.pagezero_size;
        sym.is_extern = false;
    }
}

/// Lays out the subsections of one big executable output section with
/// range-extension thunks interleaved, following mold's design: a
/// thunk is placed after each batch of code, and a batch never grows
/// so large that its thunk would be out of reach of the batch's own
/// branches - the layout cursor and the scan cursor stay within one
/// branch reach (minus margin) of each other, so placing a thunk can
/// never invalidate an earlier decision. Each relocation that might be
/// out of range records its thunk entry; relocation application then
/// uses the entry only when the direct branch really cannot reach.
fn create_range_extension_thunks<E: Arch>(
    ctx: &mut Context<E>,
    isecs: &[usize],
) -> Vec<output_chunks::Thunk> {
    const BATCH: u64 = 10 * 1024 * 1024;
    const MAX_THUNK: u64 = 1024 * 1024;
    let budget = E::BRANCH_RANGE / 2 - MAX_THUNK - BATCH;

    let mut thunks: Vec<output_chunks::Thunk> = Vec::new();
    let mut off: u64 = 0;
    let mut i = 0;

    // Distinguish placed subsections from ones still ahead.
    for &id in isecs {
        ctx.isecs[id].output_offset = u64::MAX;
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
            let n = scan_relocs_into_thunk::<E>(ctx, &[monster], thunk_off, &mut thunks);
            off = thunk_off + n * E::THUNK_SIZE;
            let isec = &mut ctx.isecs[monster];
            off = align_to(off, 1 << isec.hdr.p2align);
            isec.output_offset = off;
            off += isec.size;
            i += 1;
            continue;
        }

        // Place a batch: bounded by BATCH bytes, and by the thunk after
        // it staying within reach of the batch start.
        while i < isecs.len() {
            let isec = &ctx.isecs[isecs[i]];
            let aligned = align_to(off, 1 << isec.hdr.p2align);
            if i != batch_start
                && (aligned + isec.size - batch_start_off > budget
                    || aligned - batch_start_off >= BATCH)
            {
                break;
            }
            let isec = &mut ctx.isecs[isecs[i]];
            isec.output_offset = aligned;
            off = aligned + isec.size;
            i += 1;
        }

        let thunk_off = align_to(off, 16);
        let batch: Vec<usize> = isecs[batch_start..i].to_vec();
        let n = scan_relocs_into_thunk::<E>(ctx, &batch, thunk_off, &mut thunks);
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
    thunks: &mut Vec<output_chunks::Thunk>,
) -> u64 {
    let mut entry_of: std::collections::HashMap<crate::symbol::SymbolId, u64> =
        std::collections::HashMap::new();
    let mut nsyms = 0u64;

    for &isec_id in batch {
        for r in 0..ctx.isecs[isec_id].relocs.len() {
            let rel = ctx.isecs[isec_id].relocs[r];
            if E::classify_reloc(rel.r_type) != RelocClass::Branch {
                continue;
            }
            let Some(sym_id) = ctx.reloc_target_sym(ctx.isecs[isec_id].obj, &rel) else {
                continue;
            };

            let sym = &ctx.symtab[sym_id];
            if let (Origin::Obj(_), Some(target)) = (sym.origin, sym.isec) {
                let t = &ctx.isecs[ctx.resolve_isec(target)];
                if t.output_offset != u64::MAX {
                    let target_off = t.output_offset + sym.value;
                    if thunk_off.saturating_sub(target_off) < E::BRANCH_RANGE / 2 - 1024 * 1024
                    {
                        continue;
                    }
                }
            }

            let entry = *entry_of.entry(sym_id).or_insert_with(|| {
                let e = thunk_off + nsyms * E::THUNK_SIZE;
                nsyms += 1;
                e
            });
            ctx.isecs[isec_id].relocs[r].thunk_off = entry;
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

/// Well-known section names are ordered the way ld64 orders them/// Well-known section names are ordered the way ld64 orders them; unknown
/// sections come after, in input order.
fn output_section_rank(segname: &str, sectname: &str) -> u32 {
    match (segname, sectname) {
        ("__TEXT", "__text") => 0,
        ("__TEXT", _) => 1,
        // The thread-local initialization image must be contiguous:
        // __thread_data last among file-backed __DATA sections, and
        // __thread_bss first among zero-fill ones (zero-fill sections
        // sort after all file-backed ones).
        ("__DATA", "__thread_vars") => 8,
        ("__DATA", "__thread_data") => 9,
        ("__DATA", "__thread_bss") => 0,
        ("__DATA", "__bss") => 3,
        ("__DATA", "__common") => 4,
        _ => 2,
    }
}

/// Creates output section chunks and appends each input section to its
/// chunk, and groups chunks into segments.
pub fn create_output_chunks<E: Arch>(ctx: &mut Context<E>) {
    ctx.chunks.push(Chunk::new("__TEXT", "", ChunkKind::MachHeader));

    // Assign each input section to an output section, creating output
    // sections as needed.
    for i in 0..ctx.isecs.len() {
        if !ctx.isecs[i].is_alive || ctx.isecs[i].replacement.is_some() {
            continue;
        }
        let segname = ctx.isecs[i].hdr.segname().to_string();
        let sectname = ctx.isecs[i].hdr.sectname().to_string();

        let chunk_idx = match ctx.chunks.iter().position(|c| {
            matches!(c.kind, ChunkKind::Output { .. })
                && c.hdr.segname == segname
                && c.hdr.sectname == sectname
        }) {
            Some(idx) => idx,
            None => {
                let segname: &'static str = match segname.as_str() {
                    "__TEXT" => "__TEXT",
                    "__DATA_CONST" => "__DATA_CONST",
                    "__DATA" => "__DATA",
                    other => String::leak(other.to_string()),
                };
                let mut chunk = Chunk::new(
                    segname,
                    &sectname,
                    ChunkKind::Output {
                        isecs: vec![],
                        thunks: vec![],
                    },
                );
                chunk.hdr.flags = ctx.isecs[i].hdr.flags & !S_ATTR_DEBUG;
                ctx.chunks.push(chunk);
                ctx.chunks.len() - 1
            }
        };

        let chunk = &mut ctx.chunks[chunk_idx];
        chunk.hdr.p2align = chunk.hdr.p2align.max(ctx.isecs[i].hdr.p2align);
        // __thread_vars contains pointers but clang emits it with an
        // alignment of 1, so override.
        if chunk.hdr.flags & SECTION_TYPE == S_THREAD_LOCAL_VARIABLES {
            chunk.hdr.p2align = chunk.hdr.p2align.max(3);
        }
        chunk.hdr.flags |= ctx.isecs[i].hdr.flags & !SECTION_TYPE & !S_ATTR_DEBUG;
        let ChunkKind::Output { isecs, .. } = &mut chunk.kind else {
            unreachable!()
        };
        isecs.push(i);
        ctx.isecs[i].osec = chunk_idx;
    }

    // Compute each input section's offset within its output section,
    // inserting range-extension thunks into large executable sections.
    for chunk_idx in 0..ctx.chunks.len() {
        let ChunkKind::Output { isecs, .. } = &ctx.chunks[chunk_idx].kind else {
            continue;
        };
        let isecs = isecs.clone();

        let total: u64 = isecs.iter().map(|&id| ctx.isecs[id].size + 16).sum();
        let is_exec = ctx.chunks[chunk_idx].hdr.flags
            & (S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS)
            != 0;
        let thunks = if is_exec && total > E::BRANCH_RANGE / 2 {
            create_range_extension_thunks::<E>(ctx, &isecs)
        } else {
            let mut off = 0;
            for &id in &isecs {
                let isec = &mut ctx.isecs[id];
                off = align_to(off, 1 << isec.hdr.p2align);
                isec.output_offset = off;
                off += isec.size;
            }
            Vec::new()
        };

        let end = match thunks.last() {
            Some(t) => t.offset + t.syms.len() as u64 * E::THUNK_SIZE,
            None => 0,
        };
        let chunk = &mut ctx.chunks[chunk_idx];
        let data_end = isecs
            .last()
            .map(|&id| ctx.isecs[id].output_offset + ctx.isecs[id].size)
            .unwrap_or(0);
        chunk.hdr.size = end.max(data_end);
        let ChunkKind::Output { thunks: t, .. } = &mut chunk.kind else {
            unreachable!()
        };
        *t = thunks;
    }

    if !ctx.stub_syms.is_empty() {
        let mut chunk = Chunk::new("__TEXT", "__stubs", ChunkKind::Stubs);
        chunk.hdr.flags = S_SYMBOL_STUBS | S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS;
        chunk.hdr.p2align = 2;
        chunk.hdr.reserved2 = E::STUB_SIZE as u32;
        chunk.hdr.size = ctx.stub_syms.len() as u64 * E::STUB_SIZE;
        ctx.chunks.push(chunk);
    }

    if !ctx.got_syms.is_empty() {
        let mut chunk = Chunk::new("__DATA_CONST", "__got", ChunkKind::Got);
        chunk.hdr.flags = S_NON_LAZY_SYMBOL_POINTERS;
        chunk.hdr.p2align = 3;
        // Indirect symbol table entries for stubs come first, then the
        // GOT's.
        chunk.hdr.reserved1 = ctx.stub_syms.len() as u32;
        chunk.hdr.size = ctx.got_syms.len() as u64 * 8;
        ctx.chunks.push(chunk);
    }

    if !ctx.thread_ptr_syms.is_empty() {
        let mut chunk = Chunk::new("__DATA", "__thread_ptrs", ChunkKind::ThreadPtrs);
        chunk.hdr.flags = S_THREAD_LOCAL_VARIABLE_POINTERS;
        chunk.hdr.p2align = 3;
        chunk.hdr.size = ctx.thread_ptr_syms.len() as u64 * 8;
        ctx.chunks.push(chunk);
    }

    if !ctx.objc_stubs.is_empty() {
        let mut chunk = Chunk::new("__TEXT", "__objc_stubs", ChunkKind::ObjcStubs);
        chunk.hdr.flags = S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS;
        chunk.hdr.p2align = 5;
        chunk.hdr.size = ctx.objc_stubs.len() as u64 * E::OBJC_STUB_SIZE;
        ctx.chunks.push(chunk);

        let mut chunk = Chunk::new("__TEXT", "__objc_methname", ChunkKind::ObjcMethname);
        chunk.hdr.flags = S_CSTRING_LITERALS;
        chunk.hdr.size = ctx.objc_methname_data.len() as u64;
        ctx.chunks.push(chunk);

        let mut chunk = Chunk::new("__DATA", "__objc_selrefs", ChunkKind::ObjcSelrefs);
        chunk.hdr.flags = S_LITERAL_POINTERS | S_ATTR_NO_DEAD_STRIP;
        chunk.hdr.p2align = 3;
        chunk.hdr.size = ctx.objc_stubs.len() as u64 * 8;
        ctx.chunks.push(chunk);
    }

    // Sections synthesized from files by -sectcreate.
    let sectcreate = std::mem::take(&mut ctx.args.sectcreate);
    for (seg, sect, path) in &sectcreate {
        let Ok(data) = std::fs::read(path) else {
            fatal!(ctx, "-sectcreate: cannot read {path}");
        };
        let segname: &'static str = String::leak(seg.clone());
        let mut chunk = Chunk::new(
            segname,
            sect,
            ChunkKind::SectCreate {
                data: Vec::leak(data),
            },
        );
        let ChunkKind::SectCreate { data } = chunk.kind else {
            unreachable!()
        };
        chunk.hdr.size = data.len() as u64;
        ctx.chunks.push(chunk);
    }
    ctx.args.sectcreate = sectcreate;

    // Merge the objects' __objc_imageinfo records: the Swift version
    // must agree, the Swift language version is the newest, and the
    // category-class-properties bit holds only if every Objective-C
    // object has it.
    let infos: Vec<u32> = ctx
        .objs
        .iter()
        .filter(|o| o.is_alive)
        .filter_map(|o| o.objc_image_info)
        .collect();
    if !infos.is_empty() {
        let mut swift_version = 0;
        for &flags in &infos {
            let v = (flags >> 8) & 0xff;
            if swift_version == 0 {
                swift_version = v;
            } else if v != 0 && v != swift_version {
                error!(ctx, "incompatible __objc_imageinfo swift versions");
            }
        }
        let lang = infos.iter().map(|f| f >> 16).max().unwrap();
        let cat = infos.iter().all(|f| f & 0x40 != 0);
        let flags = (lang << 16) | (swift_version << 8) | if cat { 0x40 } else { 0 };

        ctx.objc_image_info_flags = flags;
        let mut chunk = Chunk::new("__DATA_CONST", "__objc_imageinfo", ChunkKind::ObjcImageInfo);
        chunk.hdr.p2align = 2;
        chunk.hdr.size = 8;
        ctx.chunks.push(chunk);
    }

    if !ctx.unwind_records.is_empty() {
        let mut chunk = Chunk::new("__TEXT", "__unwind_info", ChunkKind::UnwindInfo);
        chunk.hdr.p2align = 2;
        ctx.chunks.push(chunk);
    }

    // Lay out the surviving DWARF records: live CIEs first, then FDEs.
    // Their offsets are needed before layout, because the __unwind_info
    // encoding embeds each FDE's offset.
    // FDEs of folded copies duplicate their leader's; drop them.
    {
        let isecs = &ctx.isecs;
        ctx.fdes.retain(|fde| isecs[fde.isec].replacement.is_none());
    }
    if !ctx.fdes.is_empty() {
        for fde in &ctx.fdes {
            ctx.cies[fde.cie].is_alive = true;
        }
        let mut off = 0;
        for cie in &mut ctx.cies {
            if cie.is_alive {
                cie.output_offset = off;
                off += cie.data.len() as u32;
            }
        }
        for fde in &mut ctx.fdes {
            fde.output_offset = off;
            off += fde.data.len() as u32;
        }

        let mut chunk = Chunk::new("__TEXT", "__eh_frame", ChunkKind::EhFrame);
        chunk.hdr.p2align = 3;
        chunk.hdr.size = off as u64;
        ctx.chunks.push(chunk);
    }

    ctx.chunks.push(Chunk::new("__LINKEDIT", "", ChunkKind::ChainedFixups));
    ctx.chunks.push(Chunk::new("__LINKEDIT", "", ChunkKind::RebaseInfo));
    ctx.chunks.push(Chunk::new("__LINKEDIT", "", ChunkKind::BindInfo));
    ctx.chunks.push(Chunk::new("__LINKEDIT", "", ChunkKind::ExportTrie));
    ctx.chunks.push(Chunk::new("__LINKEDIT", "", ChunkKind::FunctionStarts));
    ctx.chunks.push(Chunk::new("__LINKEDIT", "", ChunkKind::Symtab));
    if !ctx.stub_syms.is_empty() || !ctx.got_syms.is_empty() {
        let mut chunk = Chunk::new("__LINKEDIT", "", ChunkKind::IndirectSymtab);
        chunk.hdr.size = (ctx.stub_syms.len() + ctx.got_syms.len()) as u64 * 4;
        ctx.chunks.push(chunk);
    }
    ctx.chunks.push(Chunk::new("__LINKEDIT", "", ChunkKind::Strtab));
    if ctx.args.adhoc_codesign {
        ctx.chunks
            .push(Chunk::new("__LINKEDIT", "", ChunkKind::CodeSignature));
    }

    // Group chunks into segments, in the standard segment order. Chunk
    // order within a segment follows section ranks.
    let mut order: Vec<usize> = (0..ctx.chunks.len()).collect();
    order.sort_by_key(|&i| {
        let c = &ctx.chunks[i];
        let seg_rank = match c.hdr.segname {
            "__TEXT" => 0,
            "__DATA_CONST" => 1,
            "__DATA" => 2,
            "__LINKEDIT" => 4,
            _ => 3,
        };
        let sect_rank = match c.kind {
            ChunkKind::MachHeader => 0,
            ChunkKind::UnwindInfo => 100,
            ChunkKind::EhFrame => 101,
            ChunkKind::CodeSignature => u32::MAX,
            _ => 1 + output_section_rank(c.hdr.segname, &c.hdr.sectname),
        };
        // Zero-fill sections go last in their segment so that they don't
        // occupy file space in the middle of it.
        (seg_rank, c.is_zerofill(), sect_rank, i)
    });

    let mut segments = Vec::new();
    if ctx.args.pagezero_size > 0 {
        segments.push(OutputSegment::new("__PAGEZERO"));
    }
    for idx in order {
        let segname = ctx.chunks[idx].hdr.segname;
        if segments.last().map(|s: &OutputSegment| s.name) != Some(segname) {
            segments.push(OutputSegment::new(segname));
        }
        segments.last_mut().unwrap().chunks.push(idx);
    }
    ctx.segments = segments;
}

/// Returns true if a local symbol should appear in the output symbol
/// table. Assembler temporaries, which begin with 'l' or 'L', are
/// dropped.
fn keep_local_symbol(name: &str) -> bool {
    !name.is_empty() && !name.starts_with('l') && !name.starts_with('L')
}

/// Builds the output symbol table contents: local symbols in input order,
/// then defined globals and undefined symbols, each sorted by name.
/// Symbol values are filled in when the table is copied out, after
/// addresses are assigned.
pub fn compute_symtab<E: Arch>(ctx: &mut Context<E>) {
    let ordinals = section_ordinals(ctx);
    let mut data = std::mem::take(&mut ctx.symtab_data);
    // Offset 1 is the empty string, offset 2 the "-" placeholder used
    // by stab source-file entries.
    data.strtab = vec![b' ', 0, b'-', 0];

    let add_string = |strtab: &mut Vec<u8>, s: &str| -> u32 {
        let off = strtab.len() as u32;
        strtab.extend_from_slice(s.as_bytes());
        strtab.push(0);
        off
    };

    // Swift AST paths for the debugger (-add_ast_path), as N_AST stabs.
    for path in &ctx.args.add_ast_paths {
        let n_strx = add_string(&mut data.strtab, path);
        data.entries.push((
            NList {
                n_strx,
                n_type: N_AST,
                ..Default::default()
            },
            None,
        ));
    }

    // Debug stabs. Mach-O binaries don't carry DWARF; instead, for each
    // object with debug info the symbol table gets stab entries telling
    // the debugger where the object file is (N_OSO) and where its
    // functions and globals ended up, and the debugger reads the DWARF
    // from the objects.
    if !ctx.args.strip_debug {
        let cwd = std::env::current_dir()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();

        for (obj_idx, obj) in ctx.objs.iter().enumerate() {
            if !obj.has_debug_info || !obj.is_alive {
                continue;
            }

            // The source-file N_SO's name is unused by debuggers; "-"
            // stands in. N_OSO points at the object (or "archive(member)"),
            // as an absolute path.
            data.entries.push((
                NList {
                    n_strx: 2,
                    n_type: N_SO,
                    ..Default::default()
                },
                None,
            ));
            let oso_name = match obj.mf.parent {
                Some(parent) if parent.name.starts_with('/') => obj.mf.name.clone(),
                Some(_) | None if obj.mf.name.starts_with('/') => obj.mf.name.clone(),
                _ => format!("{cwd}/{}", obj.mf.name),
            };
            data.entries.push((
                NList {
                    n_strx: add_string(&mut data.strtab, &oso_name),
                    n_type: N_OSO,
                    n_sect: E::CPUSUBTYPE as u8,
                    n_desc: 1,
                    n_value: 0,
                },
                None,
            ));

            for (nlist, &sym_id) in obj.nlists.iter().zip(&obj.syms) {
                let sym = &ctx.symtab[sym_id];
                if nlist.is_stab()
                    || !matches!(sym.origin, Origin::Obj(o) if o == obj_idx)
                    || (!nlist.is_extern() && !keep_local_symbol(sym.name))
                {
                    continue;
                }
                let Some(isec) = sym.isec else { continue };
                let isec_id = ctx.resolve_isec(isec);
                let isec = &ctx.isecs[isec_id];
                if !isec.is_alive {
                    continue;
                }

                let n_strx = add_string(&mut data.strtab, sym.name);
                let is_text = isec.hdr.segname() == "__TEXT"
                    && isec.hdr.flags & (S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS)
                        != 0;
                if is_text {
                    // A pair: the function's address, then its size.
                    data.entries.push((
                        NList {
                            n_strx,
                            n_type: N_FUN,
                            n_sect: ordinals[isec.osec],
                            ..Default::default()
                        },
                        Some(sym_id),
                    ));
                    data.entries.push((
                        NList {
                            n_strx: 1,
                            n_type: N_FUN,
                            n_value: isec.size,
                            ..Default::default()
                        },
                        None,
                    ));
                } else {
                    data.entries.push((
                        NList {
                            n_strx,
                            n_type: if nlist.is_extern() { N_GSYM } else { N_STSYM },
                            n_sect: ordinals[isec.osec],
                            ..Default::default()
                        },
                        Some(sym_id),
                    ));
                }
            }

            // An N_SO with an empty name closes the object's stabs.
            data.entries.push((
                NList {
                    n_strx: 1,
                    n_type: N_SO,
                    n_sect: 1,
                    ..Default::default()
                },
                None,
            ));
        }
    }

    // Local symbols (-x drops them)
    for obj in &ctx.objs {
        if ctx.args.strip_locals {
            break;
        }
        if !obj.is_alive {
            continue;
        }
        for (nlist, &sym_id) in obj.nlists.iter().zip(&obj.syms) {
            let sym = &ctx.symtab[sym_id];
            if nlist.is_stab() || nlist.is_extern() || !keep_local_symbol(sym.name) {
                continue;
            }
            let Some(isec) = sym.isec else { continue };
            let isec = ctx.resolve_isec(isec);
            if !matches!(sym.origin, Origin::Obj(_)) || !ctx.isecs[isec].is_alive {
                continue;
            }
            let n_strx = add_string(&mut data.strtab, sym.name);
            let ent = NList {
                n_strx,
                n_type: N_SECT,
                n_sect: ordinals[ctx.isecs[isec].osec],
                n_desc: 0,
                n_value: 0,
            };
            data.entries.push((ent, Some(sym_id)));
        }
    }
    // Private external symbols resolve globally but appear as locals
    // (with N_PEXT still set) in the output.
    for i in 0..ctx.symtab.syms.len() {
        let sym = &ctx.symtab[i];
        if !sym.is_extern || !sym.is_private_extern {
            continue;
        }
        let Origin::Obj(_) = sym.origin else { continue };
        let Some(isec) = sym.isec else { continue };
        let isec = ctx.resolve_isec(isec);
        if !ctx.isecs[isec].is_alive {
            continue;
        }
        let n_strx = add_string(&mut data.strtab, sym.name);
        let ent = NList {
            n_strx,
            n_type: N_SECT | N_PEXT,
            n_sect: ordinals[ctx.isecs[isec].osec],
            n_desc: 0,
            n_value: 0,
        };
        data.entries.push((ent, Some(i)));
    }
    data.nlocal = data.entries.len() as u32;

    // Defined global symbols, sorted by name
    let mut globals: Vec<usize> = (0..ctx.symtab.syms.len())
        .filter(|&i| {
            let sym = &ctx.symtab[i];
            sym.is_extern
                && !sym.is_private_extern
                && matches!(sym.origin, Origin::Obj(_) | Origin::Synthetic)
                && sym
                    .isec
                    .is_none_or(|isec| ctx.isecs[ctx.resolve_isec(isec)].is_alive)
        })
        .collect();
    globals.sort_by_key(|&i| ctx.symtab[i].name);

    for &i in &globals {
        let sym = &ctx.symtab[i];
        let n_strx = add_string(&mut data.strtab, sym.name);
        let (n_type, n_sect, mut n_desc) = match (sym.origin, sym.isec) {
            (_, Some(isec)) => (
                N_SECT | N_EXT,
                ordinals[ctx.isecs[ctx.resolve_isec(isec)].osec],
                0,
            ),
            (Origin::Synthetic, None) => (N_SECT | N_EXT, 1, REFERENCED_DYNAMICALLY),
            (_, None) => (N_ABS | N_EXT, 0, 0),
        };
        if sym.is_weak_def {
            n_desc |= N_WEAK_DEF;
        }
        let ent = NList {
            n_strx,
            n_type,
            n_sect,
            n_desc,
            n_value: 0,
        };
        data.entries.push((ent, Some(i)));
    }
    data.nextdef = data.entries.len() as u32 - data.nlocal;

    // Undefined (imported) symbols, sorted by name. The library ordinal
    // lives in the high byte of n_desc.
    let mut undefs: Vec<usize> = (0..ctx.symtab.syms.len())
        .filter(|&i| matches!(ctx.symtab[i].origin, Origin::Dylib(_)))
        .collect();
    undefs.sort_by_key(|&i| ctx.symtab[i].name);

    for &i in &undefs {
        let sym = &ctx.symtab[i];
        let Origin::Dylib(dylib) = sym.origin else {
            unreachable!()
        };
        let n_strx = add_string(&mut data.strtab, sym.name);
        // A flat-namespace import records the DYNAMIC_LOOKUP ordinal.
        let ordinal = if dylib == usize::MAX {
            (BIND_SPECIAL_DYLIB_FLAT_LOOKUP as u8) as u16
        } else {
            ctx.dylibs[dylib].dylib_idx as u16
        };
        let mut n_desc = ordinal << 8;
        if sym.is_weak_ref {
            n_desc |= N_WEAK_REF;
        }
        let ent = NList {
            n_strx,
            n_type: N_UNDF | N_EXT,
            n_sect: 0,
            n_desc,
            n_value: 0,
        };
        data.entries.push((ent, None));
    }
    data.nundef = undefs.len() as u32;

    // Record each global symbol's index for the indirect symbol table.
    for (i, (_, sym)) in data.entries.iter().enumerate() {
        if let Some(id) = sym {
            if ctx.symtab[*id].is_extern {
                data.global_index.insert(*id, i as u32);
            }
        }
    }
    for (i, &id) in undefs.iter().enumerate() {
        data.global_index
            .insert(id, data.nlocal + data.nextdef + i as u32);
    }

    // Pad the string table to 8 bytes.
    while data.strtab.len() % 8 != 0 {
        data.strtab.push(0);
    }

    ctx.symtab_data = data;
}

/// Assigns virtual addresses and file offsets to all segments and chunks.
pub fn assign_offsets<E: Arch>(ctx: &mut Context<E>) {
    let page = E::PAGE_SIZE;
    let mut addr = 0;
    let mut fileoff = 0;

    // Chunk sizes that are independent of the layout.
    let header_size = mach_header_size(ctx);
    let symtab_size = (ctx.symtab_data.entries.len() * size_of::<NList>()) as u64;
    let strtab_size = ctx.symtab_data.strtab.len() as u64;

    for seg_idx in 0..ctx.segments.len() {
        // Everything the bind stream describes (the GOT, data sections)
        // is laid out by the time we reach __LINKEDIT.
        if ctx.segments[seg_idx].name == "__LINKEDIT" {
            if ctx.use_chained_fixups() {
                build_chained_fixups(ctx);
            } else {
                ctx.rebase_data = build_rebase_info(ctx);
                ctx.bind_data = build_bind_info(ctx);
            }
            ctx.function_starts_data = build_function_starts(ctx);
        }

        if ctx.segments[seg_idx].name == "__PAGEZERO" {
            let seg = &mut ctx.segments[seg_idx];
            seg.cmd.vmaddr = 0;
            seg.cmd.vmsize = ctx.args.pagezero_size;
            addr = ctx.args.pagezero_size;
            continue;
        }

        let seg_vmaddr = addr;
        let seg_fileoff = fileoff;
        let mut cursor = fileoff;

        let chunk_idxs = ctx.segments[seg_idx].chunks.clone();

        // Regular chunks, in file order
        for &idx in &chunk_idxs {
            if ctx.chunks[idx].is_zerofill() {
                continue;
            }
            let size = match &ctx.chunks[idx].kind {
                ChunkKind::MachHeader => header_size,
                ChunkKind::Symtab => symtab_size,
                ChunkKind::Strtab => strtab_size,
                ChunkKind::UnwindInfo => output_chunks::encode_unwind_info(ctx).len() as u64,
                ChunkKind::ChainedFixups => ctx.chained_data.len() as u64,
                ChunkKind::RebaseInfo => ctx.rebase_data.len() as u64,
                ChunkKind::BindInfo => ctx.bind_data.len() as u64,
                ChunkKind::ExportTrie => output_chunks::encode_export_trie(ctx).len() as u64,
                ChunkKind::FunctionStarts => ctx.function_starts_data.len() as u64,
                ChunkKind::CodeSignature => {
                    cursor = align_to(cursor, 16);
                    code_signature_size(&ctx.args.output, cursor)
                }
                _ => ctx.chunks[idx].hdr.size,
            };
            let chunk = &mut ctx.chunks[idx];
            let p2align = match chunk.kind {
                ChunkKind::Symtab | ChunkKind::Strtab | ChunkKind::RebaseInfo
                | ChunkKind::BindInfo | ChunkKind::ChainedFixups | ChunkKind::ExportTrie
                | ChunkKind::FunctionStarts => 3,
                ChunkKind::IndirectSymtab => 2,
                ChunkKind::CodeSignature => 4,
                _ => chunk.hdr.p2align,
            };
            cursor = align_to(cursor, 1 << p2align);
            chunk.hdr.fileoff = cursor;
            chunk.hdr.addr = seg_vmaddr + (cursor - seg_fileoff);
            chunk.hdr.size = size;
            cursor += size;
        }

        let filesize = cursor - seg_fileoff;
        let mut vm_end = seg_vmaddr + filesize;

        // Zero-fill chunks occupy address space after the file-backed
        // part of the segment.
        for &idx in &chunk_idxs {
            if !ctx.chunks[idx].is_zerofill() {
                continue;
            }
            let chunk = &mut ctx.chunks[idx];
            vm_end = align_to(vm_end, 1 << chunk.hdr.p2align);
            chunk.hdr.addr = vm_end;
            chunk.hdr.fileoff = 0;
            vm_end += chunk.hdr.size;
        }

        // __LINKEDIT's file contents end exactly at the code signature;
        // other segments are padded to a page boundary in the file.
        let seg = &mut ctx.segments[seg_idx];
        seg.cmd.vmaddr = seg_vmaddr;
        seg.cmd.fileoff = seg_fileoff;
        if seg.name == "__LINKEDIT" {
            seg.cmd.filesize = filesize;
        } else {
            seg.cmd.filesize = align_to(filesize, page);
        }
        seg.cmd.vmsize = align_to(vm_end - seg_vmaddr, page).max(seg.cmd.filesize);

        addr = seg_vmaddr + seg.cmd.vmsize;
        fileoff = seg_fileoff + seg.cmd.filesize;
    }

    ctx.output_size = fileoff;

    // Thread pointers are relative to the start of the first
    // thread-local data section.
    ctx.tls_begin = ctx
        .chunks
        .iter()
        .filter(|c| {
            matches!(
                c.hdr.flags & SECTION_TYPE,
                S_THREAD_LOCAL_REGULAR | S_THREAD_LOCAL_ZEROFILL
            )
        })
        .map(|c| c.hdr.addr)
        .min()
        .unwrap_or(0);
}

/// Returns the load-command index of the segment containing `addr`, and
/// the offset within it.
fn segment_and_offset<E: Arch>(ctx: &Context<E>, addr: u64) -> (usize, u64) {
    for (i, seg) in ctx.segments.iter().enumerate() {
        if seg.cmd.vmaddr <= addr && addr < seg.cmd.vmaddr + seg.cmd.vmsize && seg.name != "__PAGEZERO"
        {
            return (i, addr - seg.cmd.vmaddr);
        }
    }
    unreachable!("no segment contains address {addr:#x}");
}

/// Builds the rebase opcode stream: it tells dyld which pointers in the
/// image it must slide when the image is loaded at a non-default address.
/// Every absolute address the linker writes into a data section gets a
/// record. Runs during layout, once every segment before __LINKEDIT has
/// an address.
fn build_rebase_info<E: Arch>(ctx: &Context<E>) -> Vec<u8> {
    let mut locs: Vec<u64> = Vec::new();

    // Pointers written for UNSIGNED relocations to local targets.
    for isec in &ctx.isecs {
        if !isec.is_alive || isec.replacement.is_some() {
            continue;
        }
        let base = ctx.chunks[isec.osec].hdr.addr + isec.output_offset;
        for rel in &isec.relocs {
            if E::classify_reloc(rel.r_type) != RelocClass::Plain
                || rel.size != 8
                || rel.is_pcrel
                || rel.is_subtracted
            {
                continue;
            }
            // Pointers to thread-local data are thread-pointer-relative
            // offsets, not addresses, so they are not rebased.
            let imported = ctx
                .reloc_target_sym(isec.obj, rel)
                .is_some_and(|id| ctx.symtab[id].is_imported);
            if !imported && !ctx.reloc_target_is_tls(isec.obj, rel) {
                locs.push(base + rel.offset as u64);
            }
        }
    }

    // __thread_ptrs slots hold descriptor addresses, which need
    // sliding.
    if let Some(idx) = output_chunks::find_chunk(ctx, |k| matches!(k, ChunkKind::ThreadPtrs)) {
        let addr = ctx.chunks[idx].hdr.addr;
        for (i, &id) in ctx.thread_ptr_syms.iter().enumerate() {
            if !ctx.symtab[id].is_imported {
                locs.push(addr + i as u64 * 8);
            }
        }
    }

    // Selector reference slots hold pointers into __objc_methname.
    if let Some(idx) = output_chunks::find_chunk(ctx, |k| matches!(k, ChunkKind::ObjcSelrefs)) {
        let addr = ctx.chunks[idx].hdr.addr;
        for i in 0..ctx.objc_stubs.len() {
            locs.push(addr + i as u64 * 8);
        }
    }

    // GOT slots that hold local addresses.
    if let Some(idx) = output_chunks::find_chunk(ctx, |k| matches!(k, ChunkKind::Got)) {
        let got_addr = ctx.chunks[idx].hdr.addr;
        for (i, &id) in ctx.got_syms.iter().enumerate() {
            if !ctx.symtab[id].is_imported {
                locs.push(got_addr + i as u64 * 8);
            }
        }
    }

    if locs.is_empty() {
        return Vec::new();
    }
    locs.sort_unstable();

    let mut buf = Vec::new();
    buf.push(REBASE_OPCODE_SET_TYPE_IMM | REBASE_TYPE_POINTER);
    for loc in locs {
        let (seg, off) = segment_and_offset(ctx, loc);
        buf.push(REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB | seg as u8);
        write_uleb(&mut buf, off);
        buf.push(REBASE_OPCODE_DO_REBASE_IMM_TIMES | 1);
    }
    buf.push(REBASE_OPCODE_DONE);
    while buf.len() % 8 != 0 {
        buf.push(0);
    }
    buf
}

/// Builds the bind opcode stream: it tells dyld which imported symbol to
/// write into each GOT slot. Runs during layout, once every segment
/// before __LINKEDIT has an address.
fn build_bind_info<E: Arch>(ctx: &Context<E>) -> Vec<u8> {
    let mut binds: Vec<(u64, crate::symbol::SymbolId, i64)> = Vec::new();

    // GOT slots for imported symbols.
    if let Some(idx) = output_chunks::find_chunk(ctx, |k| matches!(k, ChunkKind::Got)) {
        let got_addr = ctx.chunks[idx].hdr.addr;
        for (i, &id) in ctx.got_syms.iter().enumerate() {
            if ctx.symtab[id].is_imported {
                binds.push((got_addr + i as u64 * 8, id, 0));
            }
        }
    }

    // Pointers in data sections initialized with an imported symbol's
    // address.
    for isec in &ctx.isecs {
        if !isec.is_alive || isec.replacement.is_some() {
            continue;
        }
        let base = ctx.chunks[isec.osec].hdr.addr + isec.output_offset;
        for rel in &isec.relocs {
            if E::classify_reloc(rel.r_type) != RelocClass::Plain
                || rel.size != 8
                || rel.is_pcrel
                || rel.is_subtracted
            {
                continue;
            }
            if let Some(id) = ctx.reloc_target_sym(isec.obj, rel) {
                if ctx.symtab[id].is_imported {
                    binds.push((base + rel.offset as u64, id, rel.addend));
                }
            }
        }
    }

    if binds.is_empty() {
        return Vec::new();
    }
    binds.sort_unstable_by_key(|&(addr, _, _)| addr);

    let mut buf = Vec::new();
    let mut last_addend = 0i64;
    for (addr, id, addend) in binds {
        let sym = &ctx.symtab[id];
        let Origin::Dylib(dylib) = sym.origin else {
            unreachable!()
        };
        if dylib == usize::MAX {
            let imm = (BIND_SPECIAL_DYLIB_FLAT_LOOKUP & 0xf) as u8;
            buf.push(BIND_OPCODE_SET_DYLIB_SPECIAL_IMM | imm);
        } else {
            let ordinal = ctx.dylibs[dylib].dylib_idx;
            if ordinal < 16 {
                buf.push(BIND_OPCODE_SET_DYLIB_ORDINAL_IMM | ordinal as u8);
            } else {
                buf.push(BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB);
                write_uleb(&mut buf, ordinal as u64);
            }
        }
        let flags = if sym.is_weak_ref {
            BIND_SYMBOL_FLAGS_WEAK_IMPORT
        } else {
            0
        };
        buf.push(BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM | flags);
        buf.extend_from_slice(sym.name.as_bytes());
        buf.push(0);
        buf.push(BIND_OPCODE_SET_TYPE_IMM | BIND_TYPE_POINTER);
        // The addend is bind-machine state: it persists across
        // BIND opcodes, so emit SET_ADDEND_SLEB only on change.
        if addend != last_addend {
            buf.push(BIND_OPCODE_SET_ADDEND_SLEB);
            crate::util::write_sleb(&mut buf, addend);
            last_addend = addend;
        }
        let (seg, off) = segment_and_offset(ctx, addr);
        buf.push(BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB | seg as u8);
        write_uleb(&mut buf, off);
        buf.push(BIND_OPCODE_DO_BIND);
    }

    buf.push(BIND_OPCODE_DONE);
    while buf.len() % 8 != 0 {
        buf.push(0);
    }
    buf
}

/// The largest addend a chained bind can carry inline; anything bigger
/// goes into the import table.
const MAX_INLINE_ADDEND: u64 = 255;

/// Collects every dynamic fixup location: rebases (the linker wrote an
/// absolute address that dyld must slide) and binds (dyld writes an
/// imported symbol's address), with the bind addends.
fn collect_fixups<E: Arch>(ctx: &Context<E>) -> Vec<(u64, Option<crate::symbol::SymbolId>, u64)> {
    let mut fixups: Vec<(u64, Option<crate::symbol::SymbolId>, u64)> = Vec::new();

    for isec in &ctx.isecs {
        if !isec.is_alive || isec.replacement.is_some() {
            continue;
        }
        let base = ctx.chunks[isec.osec].hdr.addr + isec.output_offset;
        for rel in &isec.relocs {
            if E::classify_reloc(rel.r_type) != RelocClass::Plain
                || rel.size != 8
                || rel.is_pcrel
                || rel.is_subtracted
            {
                continue;
            }
            let addr = base + rel.offset as u64;
            match ctx.reloc_target_sym(isec.obj, rel) {
                Some(id) if ctx.symtab[id].is_imported => {
                    fixups.push((addr, Some(id), rel.addend as u64));
                }
                _ => {
                    if !ctx.reloc_target_is_tls(isec.obj, rel) {
                        fixups.push((addr, None, 0));
                    }
                }
            }
        }
    }

    if let Some(idx) = output_chunks::find_chunk(ctx, |k| matches!(k, ChunkKind::Got)) {
        let addr = ctx.chunks[idx].hdr.addr;
        for (i, &id) in ctx.got_syms.iter().enumerate() {
            let sym = Some(id).filter(|&id| ctx.symtab[id].is_imported);
            fixups.push((addr + i as u64 * 8, sym, 0));
        }
    }
    if let Some(idx) = output_chunks::find_chunk(ctx, |k| matches!(k, ChunkKind::ThreadPtrs)) {
        let addr = ctx.chunks[idx].hdr.addr;
        for (i, &id) in ctx.thread_ptr_syms.iter().enumerate() {
            let sym = Some(id).filter(|&id| ctx.symtab[id].is_imported);
            fixups.push((addr + i as u64 * 8, sym, 0));
        }
    }
    if let Some(idx) = output_chunks::find_chunk(ctx, |k| matches!(k, ChunkKind::ObjcSelrefs)) {
        let addr = ctx.chunks[idx].hdr.addr;
        for i in 0..ctx.objc_stubs.len() {
            fixups.push((addr + i as u64 * 8, None, 0));
        }
    }

    fixups.sort_unstable_by_key(|&(addr, _, _)| addr);
    fixups
}

/// Builds the LC_DYLD_CHAINED_FIXUPS payload. Instead of opcode
/// streams, chained fixups store, per page of each segment, the offset
/// of the first fixup; each 64-bit fixup word in the data itself then
/// encodes its target (a rebase value or an import ordinal) plus the
/// distance to the next fixup in the page, forming a chain dyld walks.
fn build_chained_fixups<E: Arch>(ctx: &mut Context<E>) {
    let fixups = collect_fixups(ctx);
    if fixups.is_empty() {
        ctx.chained_data.clear();
        ctx.fixups.clear();
        return;
    }

    // The import table: one entry per (symbol, table addend). Addends
    // up to 255 are carried inline in the fixup word and use the
    // symbol's base entry.
    let mut dynsyms: Vec<(crate::symbol::SymbolId, u64)> = fixups
        .iter()
        .filter_map(|&(_, sym, addend)| {
            sym.map(|s| (s, if addend <= MAX_INLINE_ADDEND { 0 } else { addend }))
        })
        .collect();
    dynsyms.sort_unstable();
    dynsyms.dedup();
    let mut ordinals = std::collections::HashMap::new();
    for (i, &(sym, _)) in dynsyms.iter().enumerate().rev() {
        ordinals.insert(sym, i);
    }

    let max_addend = dynsyms.iter().map(|&(_, a)| a).max().unwrap_or(0);
    let import_format = if max_addend == 0 {
        DYLD_CHAINED_IMPORT
    } else if max_addend <= u32::MAX as u64 {
        DYLD_CHAINED_IMPORT_ADDEND
    } else {
        DYLD_CHAINED_IMPORT_ADDEND64
    };

    let push32 = |buf: &mut Vec<u8>, v: u32| buf.extend_from_slice(&v.to_le_bytes());
    let push16 = |buf: &mut Vec<u8>, v: u16| buf.extend_from_slice(&v.to_le_bytes());
    let push64 = |buf: &mut Vec<u8>, v: u64| buf.extend_from_slice(&v.to_le_bytes());
    let pad8 = |buf: &mut Vec<u8>| {
        while buf.len() % 8 != 0 {
            buf.push(0);
        }
    };

    let mut buf = Vec::new();
    // dyld_chained_fixups_header; the offsets are backpatched.
    push32(&mut buf, 0); // fixups_version
    push32(&mut buf, 0); // starts_offset
    push32(&mut buf, 0); // imports_offset
    push32(&mut buf, 0); // symbols_offset
    push32(&mut buf, dynsyms.len() as u32);
    push32(&mut buf, import_format);
    push32(&mut buf, 0); // symbols_format: uncompressed
    pad8(&mut buf);

    // dyld_chained_starts_in_image
    let starts_offset = buf.len();
    buf[4..8].copy_from_slice(&(starts_offset as u32).to_le_bytes());
    let seg_count = ctx.segments.len();
    push32(&mut buf, seg_count as u32);
    let seg_info_table = buf.len();
    for _ in 0..seg_count {
        push32(&mut buf, 0);
    }
    pad8(&mut buf);

    // Per-segment page tables
    let image_base = ctx.args.pagezero_size;
    for (seg_idx, seg) in ctx.segments.iter().enumerate() {
        let lo = fixups.partition_point(|&(a, _, _)| a < seg.cmd.vmaddr);
        let hi = fixups.partition_point(|&(a, _, _)| a < seg.cmd.vmaddr + seg.cmd.vmsize);
        if lo == hi {
            continue;
        }
        let fx = &fixups[lo..hi];

        let off = buf.len() - starts_offset;
        let ent = seg_info_table + seg_idx * 4;
        buf[ent..ent + 4].copy_from_slice(&(off as u32).to_le_bytes());

        let page_size = E::PAGE_SIZE;
        let npages = ((fx.last().unwrap().0 + 1 - seg.cmd.vmaddr).div_ceil(page_size)) as usize;
        // The record is 22 bytes of fields plus one u16 per page,
        // padded to 8; the declared size must match the bytes present.
        let size = crate::util::align_to(22 + npages as u64 * 2, 8) as u32;
        let rec_start = buf.len();

        push32(&mut buf, size);
        push16(&mut buf, page_size as u16);
        push16(&mut buf, DYLD_CHAINED_PTR_64);
        push64(&mut buf, seg.cmd.vmaddr - image_base);
        push32(&mut buf, 0); // max_valid_pointer
        push16(&mut buf, npages as u16);
        let mut j = 0;
        for i in 0..npages {
            let page_addr = seg.cmd.vmaddr + i as u64 * page_size;
            while j < fx.len() && fx[j].0 < page_addr {
                j += 1;
            }
            if j < fx.len() && fx[j].0 < page_addr + page_size {
                push16(&mut buf, (fx[j].0 & (page_size - 1)) as u16);
            } else {
                push16(&mut buf, DYLD_CHAINED_PTR_START_NONE);
            }
        }
        buf.resize(rec_start + size as usize, 0);
    }

    // Import table
    let imports_offset = buf.len();
    buf[8..12].copy_from_slice(&(imports_offset as u32).to_le_bytes());
    let mut name_offs = Vec::with_capacity(dynsyms.len());
    let mut nameoff: u32 = 0;
    for (i, &(sym, _)) in dynsyms.iter().enumerate() {
        name_offs.push(nameoff);
        if i + 1 == dynsyms.len() || dynsyms[i + 1].0 != sym {
            nameoff += ctx.symtab[sym].name.len() as u32 + 1;
        }
    }
    for (i, &(sym, addend)) in dynsyms.iter().enumerate() {
        let s = &ctx.symtab[sym];
        let Origin::Dylib(dylib) = s.origin else {
            unreachable!()
        };
        let ordinal = if dylib == usize::MAX {
            BIND_SPECIAL_DYLIB_FLAT_LOOKUP as u8
        } else {
            ctx.dylibs[dylib].dylib_idx as u32 as u8
        };
        let weak = s.is_weak_ref as u32;
        match import_format {
            DYLD_CHAINED_IMPORT => {
                push32(&mut buf, ordinal as u32 | (weak << 8) | (name_offs[i] << 9));
            }
            DYLD_CHAINED_IMPORT_ADDEND => {
                push32(&mut buf, ordinal as u32 | (weak << 8) | (name_offs[i] << 9));
                push32(&mut buf, addend as u32);
            }
            _ => {
                push64(
                    &mut buf,
                    ordinal as u64 | ((weak as u64) << 16) | ((name_offs[i] as u64) << 32),
                );
                push64(&mut buf, addend);
            }
        }
    }

    // Symbol names
    let symbols_offset = buf.len();
    buf[12..16].copy_from_slice(&(symbols_offset as u32).to_le_bytes());
    for (i, &(sym, _)) in dynsyms.iter().enumerate() {
        if i + 1 == dynsyms.len() || dynsyms[i + 1].0 != sym {
            buf.extend_from_slice(ctx.symtab[sym].name.as_bytes());
            buf.push(0);
        }
    }
    pad8(&mut buf);

    ctx.chained_data = buf;
    ctx.fixups = fixups;
    ctx.fixup_imports = dynsyms;
    ctx.fixup_ordinals = ordinals;
}

/// Writes the fixup chains into the copied output: every fixup word is
/// rewritten to encode its payload plus the 4-byte-stride distance to
/// the next fixup in the same page.
fn write_fixup_chains<E: Arch>(ctx: &Context<E>, buf: &mut [u8]) {
    let page_mask = !(E::PAGE_SIZE - 1);

    for seg in &ctx.segments {
        let lo = ctx.fixups.partition_point(|&(a, _, _)| a < seg.cmd.vmaddr);
        let hi = ctx
            .fixups
            .partition_point(|&(a, _, _)| a < seg.cmd.vmaddr + seg.cmd.vmsize);
        let fx = &ctx.fixups[lo..hi];

        for (i, &(addr, sym, addend)) in fx.iter().enumerate() {
            let next = match fx.get(i + 1) {
                Some(&(next_addr, _, _)) if next_addr & page_mask == addr & page_mask => {
                    (next_addr - addr) / 4
                }
                _ => 0,
            };
            if addr % 4 != 0 {
                fatal!(ctx, "unaligned fixup; re-link with -no_fixup_chains");
            }

            let off = (seg.cmd.fileoff + (addr - seg.cmd.vmaddr)) as usize;
            let word = match sym {
                Some(sym) => {
                    // dyld_chained_ptr_64_bind
                    let ordinal = if addend <= MAX_INLINE_ADDEND {
                        ctx.fixup_ordinals[&sym] as u64
                    } else {
                        let base = ctx.fixup_ordinals[&sym];
                        ctx.fixup_imports[base..]
                            .iter()
                            .position(|&(s, a)| s == sym && a == addend)
                            .map(|p| (base + p) as u64)
                            .unwrap()
                    };
                    let inline_addend = if addend <= MAX_INLINE_ADDEND { addend } else { 0 };
                    ordinal | (inline_addend << 24) | (next << 51) | (1 << 63)
                }
                None => {
                    // dyld_chained_ptr_64_rebase; the word currently
                    // holds the absolute target address.
                    let val = u64::from_le_bytes(buf[off..off + 8].try_into().unwrap());
                    if val & 0x00ff_fff0_0000_0000 != 0 {
                        fatal!(ctx, "rebase target unencodable; re-link with -no_fixup_chains");
                    }
                    let target = val & 0xf_ffff_ffff;
                    let high8 = val >> 56;
                    target | (high8 << 36) | (next << 51)
                }
            };
            buf[off..off + 8].copy_from_slice(&word.to_le_bytes());
        }
    }
}

/// Builds the LC_FUNCTION_STARTS payload: the addresses of all
/// functions in __TEXT,__text, ULEB128 delta-encoded starting from the
/// image base. Debuggers and crash reporters use it to attribute
/// addresses to functions even for stripped binaries.
fn build_function_starts<E: Arch>(ctx: &Context<E>) -> Vec<u8> {
    if !ctx.args.function_starts {
        return Vec::new();
    }
    let mut addrs: Vec<u64> = Vec::new();
    for sym in &ctx.symtab.syms {
        if !matches!(sym.origin, Origin::Obj(_)) {
            continue;
        }
        let Some(isec) = sym.isec else { continue };
        let isec = &ctx.isecs[ctx.resolve_isec(isec)];
        if isec.is_alive && isec.hdr.segname() == "__TEXT" && isec.hdr.sectname() == "__text" {
            addrs.push(ctx.chunks[isec.osec].hdr.addr + isec.output_offset + sym.value);
        }
    }
    if addrs.is_empty() {
        return Vec::new();
    }
    addrs.sort_unstable();
    addrs.dedup();

    let mut buf = Vec::new();
    let mut last = ctx.args.pagezero_size;
    for addr in addrs {
        write_uleb(&mut buf, addr - last);
        last = addr;
    }
    buf.push(0);
    while buf.len() % 8 != 0 {
        buf.push(0);
    }
    buf
}

/// Resolves the entry point symbol.
pub fn resolve_entry<E: Arch>(ctx: &mut Context<E>) {
    if ctx.args.output_type != MH_EXECUTE {
        return;
    }
    match ctx.symtab.get(&ctx.args.entry) {
        Some(id) if ctx.symtab[id].is_defined() => ctx.entry_addr = ctx.sym_addr(id),
        _ => error!(ctx, "undefined symbol for entry point: {}", ctx.args.entry),
    }
}

/// Copies all chunks to the output buffer and applies relocations. The
/// code signature is computed last, over everything else.
/// Copies one chunk's contents into its slice of the output buffer.
/// The slice covers exactly [fileoff, fileoff + size).
fn copy_chunk<E: Arch>(ctx: &Context<E>, chunk: &Chunk, buf: &mut [u8]) {
    match &chunk.kind {
        ChunkKind::Output { isecs, thunks } => {
            for thunk in thunks {
                let off = thunk.offset as usize;
                let end = off + thunk.syms.len() * E::THUNK_SIZE as usize;
                E::write_thunk(ctx, chunk.hdr.addr + thunk.offset, &thunk.syms, &mut buf[off..end]);
            }
            for &id in isecs {
                let isec = &ctx.isecs[id];
                if isec.data.is_empty() {
                    continue;
                }
                let off = isec.output_offset as usize;
                let end = off + isec.data.len();
                buf[off..end].copy_from_slice(isec.data);
                let base = chunk.hdr.addr + isec.output_offset;
                E::apply_relocs(ctx, &isec.relocs, id, base, &mut buf[off..end]);
            }
        }
        ChunkKind::Stubs => E::write_stubs(ctx, chunk.hdr.addr, buf),
        ChunkKind::Got => {
            // Slots for imported symbols stay zero; dyld fills them
            // via the bind stream.
            for (i, &id) in ctx.got_syms.iter().enumerate() {
                if !ctx.symtab[id].is_imported {
                    buf[i * 8..i * 8 + 8].copy_from_slice(&ctx.sym_addr(id).to_le_bytes());
                }
            }
        }
        ChunkKind::ThreadPtrs => {
            for (i, &id) in ctx.thread_ptr_syms.iter().enumerate() {
                if !ctx.symtab[id].is_imported {
                    buf[i * 8..i * 8 + 8].copy_from_slice(&ctx.sym_addr(id).to_le_bytes());
                }
            }
        }
        ChunkKind::ObjcImageInfo => {
            buf[..4].copy_from_slice(&0u32.to_le_bytes());
            buf[4..8].copy_from_slice(&ctx.objc_image_info_flags.to_le_bytes());
        }
        ChunkKind::SectCreate { data } => buf[..data.len()].copy_from_slice(data),
        ChunkKind::ObjcStubs => E::write_objc_stubs(ctx, chunk.hdr.addr, buf),
        ChunkKind::ObjcMethname => {
            buf[..ctx.objc_methname_data.len()].copy_from_slice(&ctx.objc_methname_data);
        }
        ChunkKind::ObjcSelrefs => {
            let methname =
                output_chunks::find_chunk(ctx, |k| matches!(k, ChunkKind::ObjcMethname))
                    .unwrap();
            let methname_addr = ctx.chunks[methname].hdr.addr;
            for (i, &sel_off) in ctx.objc_methname_offs.iter().enumerate() {
                let val = methname_addr + sel_off;
                buf[i * 8..i * 8 + 8].copy_from_slice(&val.to_le_bytes());
            }
        }
        ChunkKind::UnwindInfo => {
            let data = output_chunks::encode_unwind_info(ctx);
            debug_assert_eq!(data.len() as u64, chunk.hdr.size);
            buf[..data.len()].copy_from_slice(&data);
        }
        ChunkKind::EhFrame => output_chunks::copy_eh_frame(ctx, buf),
        ChunkKind::ChainedFixups => {
            buf[..ctx.chained_data.len()].copy_from_slice(&ctx.chained_data)
        }
        ChunkKind::RebaseInfo => buf[..ctx.rebase_data.len()].copy_from_slice(&ctx.rebase_data),
        ChunkKind::BindInfo => buf[..ctx.bind_data.len()].copy_from_slice(&ctx.bind_data),
        ChunkKind::ExportTrie => {
            let data = output_chunks::encode_export_trie(ctx);
            buf[..data.len()].copy_from_slice(&data);
        }
        ChunkKind::FunctionStarts => {
            buf[..ctx.function_starts_data.len()].copy_from_slice(&ctx.function_starts_data);
        }
        ChunkKind::IndirectSymtab => {
            let mut off = 0;
            for &id in ctx.stub_syms.iter().chain(&ctx.got_syms) {
                let val = match ctx.symtab_data.global_index.get(&id) {
                    Some(&idx) => idx,
                    None => INDIRECT_SYMBOL_LOCAL,
                };
                buf[off..off + 4].copy_from_slice(&val.to_le_bytes());
                off += 4;
            }
        }
        ChunkKind::MachHeader
        | ChunkKind::Symtab
        | ChunkKind::Strtab
        | ChunkKind::CodeSignature => {}
    }
}

/// Copies all chunks to the output buffer and applies relocations, in
/// parallel: the buffer is carved into disjoint per-chunk slices, and
/// every chunk writes only within its own. The mach header, symbol
/// table (which also fills the string table), UUID and code signature
/// run serially afterwards, in that order, since each depends on the
/// bytes before it.
pub fn copy_chunks<E: Arch>(ctx: &Context<E>, buf: &mut [u8]) {
    use rayon::prelude::*;

    let mut jobs: Vec<(usize, usize, usize)> = ctx
        .chunks
        .iter()
        .enumerate()
        .filter(|(_, c)| {
            !matches!(
                c.kind,
                ChunkKind::MachHeader
                    | ChunkKind::Symtab
                    | ChunkKind::Strtab
                    | ChunkKind::CodeSignature
            ) && !c.is_zerofill()
        })
        .map(|(i, c)| (i, c.hdr.fileoff as usize, c.hdr.size as usize))
        .collect();
    jobs.sort_by_key(|&(_, off, _)| off);

    let mut slices: Vec<(usize, &mut [u8])> = Vec::with_capacity(jobs.len());
    let mut tail = &mut *buf;
    let mut consumed = 0;
    for &(idx, off, size) in &jobs {
        let (_gap, rest) = tail.split_at_mut(off - consumed);
        let (slice, rest) = rest.split_at_mut(size);
        slices.push((idx, slice));
        tail = rest;
        consumed = off + size;
    }

    slices
        .into_par_iter()
        .for_each(|(idx, slice)| copy_chunk(ctx, &ctx.chunks[idx], slice));

    if ctx.use_chained_fixups() {
        write_fixup_chains(ctx, buf);
    }
    output_chunks::copy_symtab(ctx, buf);
    output_chunks::copy_mach_header(ctx, buf);

    // The UUID identifies this build: a hash of the output contents,
    // stamped as a version-4 UUID. Hash with the UUID zeroed, then
    // rewrite the header; the code signature comes last and covers the
    // final bytes.
    let sig_start = output_chunks::find_chunk(ctx, |k| {
        matches!(k, ChunkKind::CodeSignature)
    })
    .map_or(buf.len(), |idx| ctx.chunks[idx].hdr.fileoff as usize);

    if ctx.args.uuid {
        let mut hash = [0; 32];
        crate::util::sha256(&buf[..sig_start], &mut hash);
        let mut uuid: [u8; 16] = hash[..16].try_into().unwrap();
        uuid[6] = (uuid[6] & 0x0f) | 0x40; // version 4
        uuid[8] = (uuid[8] & 0x3f) | 0x80; // RFC 4122 variant
        *ctx.uuid.lock().unwrap() = uuid;
        output_chunks::copy_mach_header(ctx, buf);
    }

    if ctx.args.adhoc_codesign {
        output_chunks::write_code_signature(ctx, buf);
    }
}
