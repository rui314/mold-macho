//! The linker passes, in the order the driver runs them.

use std::path::{Path, PathBuf};

use crate::arch::Arch;
use crate::cmdline::InputArg;
use crate::context::Context;
use crate::error;
use crate::fatal;
use crate::filetype::{get_file_type, FileType};
use crate::input_files;
use crate::input_sections::InputSection;
use crate::macho::*;
use crate::mapped_file::MappedFile;
use crate::output_chunks::{
    self, Chunk, ChunkKind, OutputSegment, SymtabData, code_signature_size, mach_header_size,
    section_ordinals,
};
use crate::arch::RelocClass;
use crate::symbol::Origin;
use crate::tapi;
use crate::util::{align_to, write_uleb};

/// Times a sub-phase to stderr when MOLD_TIMING is set - the
/// fine-grained companion to -print_statistics.
macro_rules! t {
    ($name:expr, $e:expr) => {{
        let t0 = std::time::Instant::now();
        let r = $e;
        if std::env::var_os("MOLD_TIMING").is_some() {
            eprintln!("    {} {:?}", $name, t0.elapsed());
        }
        r
    }};
}

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

    if !ctx.args.no_standard_dirs {
        if ctx.args.syslibroot.is_empty() {
            dirs.push(PathBuf::from("/usr/lib"));
        } else {
            for root in &ctx.args.syslibroot {
                dirs.push(Path::new(root).join("usr/lib"));
            }
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

    if !ctx.args.no_standard_dirs {
        if ctx.args.syslibroot.is_empty() {
            dirs.push(PathBuf::from("/System/Library/Frameworks"));
            dirs.push(PathBuf::from("/Library/Frameworks"));
        } else {
            for root in &ctx.args.syslibroot {
                dirs.push(Path::new(root).join("System/Library/Frameworks"));
                dirs.push(Path::new(root).join("Library/Frameworks"));
            }
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
    // By default each directory is tried for a dylib and then an
    // archive before moving on (-search_paths_first, ld64's default
    // since Xcode 4). -search_dylibs_first restores the older ld64
    // behavior: a dylib anywhere on the path beats an archive
    // anywhere.
    let passes: &[&[&str]] = if ctx.args.search_dylibs_first {
        &[&["tbd", "dylib"], &["a"]]
    } else {
        &[&["tbd", "dylib", "a"]]
    };
    for exts in passes {
        for dir in library_search_dirs(ctx) {
            for ext in *exts {
                let path = dir.join(format!("lib{name}.{ext}"));
                if path.is_file() {
                    return Some(path);
                }
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
    hidden: bool,
    priority: u32,
}

/// Classifies one input file. Dylib stubs and binaries are registered
/// immediately (they are cheap and order-sensitive); objects and
/// archive members are queued for parallel staging; bitcode is
/// registered immediately since libLTO calls are kept on one thread.
#[allow(clippy::too_many_arguments)]
fn collect_file<E: Arch>(
    ctx: &mut Context<E>,
    mf: &'static MappedFile,
    force_load: bool,
    weak: bool,
    reexport: bool,
    hidden: bool,
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
                hidden,
                priority,
            });
        }
        FileType::Tapi => {
            let idx = t!("parse_dylib(tbd)", input_files::parse_dylib(ctx, mf));
            ctx.dylibs[idx].is_weak |= weak;
            ctx.dylibs[idx].is_reexported |= reexport;
        }
        FileType::Dylib => {
            let idx = input_files::parse_dylib_binary(ctx, mf);
            ctx.dylibs[idx].is_weak |= weak;
            ctx.dylibs[idx].is_reexported |= reexport;
        }
        FileType::Archive => {
            // Every member is parsed eagerly; whether it is *live* -
            // whether its content reaches the output - is decided by
            // symbol resolution and the liveness walk. -all_load and
            // -force_load make every member live up front; -ObjC does
            // so for members with Objective-C metadata, which register
            // classes by their mere presence.
            let members = crate::archive_file::read_archive_members(ctx, mf);
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
                            hidden,
                            priority,
                        });
                    }
                }
            }
        }
        FileType::Fat => {
            let slice = input_files::get_fat_slice(ctx, mf);
            collect_file(ctx, slice, force_load, weak, reexport, hidden, out);
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
    let keep_debug = ctx.args.relocatable;
    let staged: Vec<input_files::StagedObject> = t!("stage", pending
        .par_iter()
        .map(|p| {
            input_files::stage_object::<E>(
                &diag,
                p.mf,
                p.alive,
                p.hidden,
                p.priority,
                keep_debug,
            )
        })
        .collect());

    // Intern every staged object's global names in one parallel batch
    // (mold's sharded symbol table), so the serial integration loop
    // below does no hashing. Names carry the xxh3 hashes staging
    // computed alongside them, so nothing here touches their bytes.
    // Each object's extern (name, hash) list is filtered in parallel -
    // a debug link scans millions of nlists here - then concatenated in
    // object order into the batch the sharded intern resolves at once.
    let per_obj: Vec<Vec<(&'static str, u64)>> = staged
        .par_iter()
        .map(|st| {
            let r = st.global_range();
            st.sym_names[r.clone()]
                .iter()
                .zip(&st.sym_hashes[r.clone()])
                .zip(st.nlists[r].iter())
                .filter(|((_, _), nlist)| !nlist.is_stab() && nlist.is_extern())
                .map(|((&name, &hash), _)| (name, hash))
                .collect()
        })
        .collect();
    let counts: Vec<usize> = per_obj.iter().map(Vec::len).collect();
    let mut batch: Vec<(&'static str, u64)> = Vec::with_capacity(counts.iter().sum());
    for v in per_obj {
        batch.extend(v);
    }
    let ids = t!("gather", ctx.symtab.gather(&batch));

    t!("integrate", input_files::integrate_objects(ctx, staged, ids, counts));
}

pub fn read_input_files<E: Arch>(ctx: &mut Context<E>) {
    // ld64 warns when a library is named twice; build systems that
    // knowingly repeat -l flags pass -no_warn_duplicate_libraries.
    if ctx.args.warn_duplicate_libraries {
        let mut seen = std::collections::HashSet::new();
        for arg in &ctx.args.inputs {
            if let InputArg::Lib(name, _) = arg {
                if !seen.insert(name.clone()) {
                    crate::warn!(ctx, "ignoring duplicate libraries: '-l{name}'");
                }
            }
        }
    }
    let inputs = std::mem::take(&mut ctx.args.inputs);

    // Warm the .tbd parse cache: resolve every input that will land
    // on a stub library and parse them all on all cores, then do the
    // same for the stubs they reexport - two waves cover an SDK's
    // umbrella trees. The serial loop below then finds every parse
    // already done.
    {
        let mut stubs: Vec<&'static MappedFile> = Vec::new();
        let consider = |path: &std::path::Path, stubs: &mut Vec<&'static MappedFile>| {
            if let Some(mf) = MappedFile::open(&ctx.diag, path) {
                if get_file_type(mf) == FileType::Tapi {
                    stubs.push(mf);
                }
            }
        };
        for arg in &inputs {
            match arg {
                InputArg::File(path) | InputArg::WeakFile(path) | InputArg::ReexportFile(path) => {
                    consider(Path::new(path), &mut stubs)
                }
                InputArg::Lib(name, _) | InputArg::ReexportLib(name) | InputArg::NeededLib(name) => {
                    if let Some(path) = find_library(ctx, name) {
                        consider(&path, &mut stubs);
                    }
                }
                InputArg::Framework(name, _) | InputArg::NeededFramework(name) => {
                    if let Some(path) = find_framework(ctx, name) {
                        consider(&path, &mut stubs);
                    }
                }
                _ => {}
            }
        }
        let wave1 = tapi::prefetch(&ctx.diag, &stubs);
        let mut deps: Vec<&'static MappedFile> = Vec::new();
        for tbd in &wave1 {
            for name in &tbd.external_reexports {
                if let Some(dep) = crate::input_files::find_reexport_file(ctx, name) {
                    if get_file_type(dep) == FileType::Tapi {
                        deps.push(dep);
                    }
                }
            }
        }
        tapi::prefetch(&ctx.diag, &deps);
    }

    let mut queue: Vec<PendingObject> = Vec::new();
    for arg in &inputs {
        match arg {
            InputArg::File(path) => {
                let mf = MappedFile::must_open(&ctx.diag, Path::new(path));
                collect_file(ctx, mf, false, false, false, false, &mut queue);
            }
            InputArg::ForceLoad(path) => {
                let mf = MappedFile::must_open(&ctx.diag, Path::new(path));
                collect_file(ctx, mf, true, false, false, false, &mut queue);
            }
            InputArg::WeakFile(path) => {
                let mf = MappedFile::must_open(&ctx.diag, Path::new(path));
                collect_file(ctx, mf, false, true, false, false, &mut queue);
            }
            InputArg::ReexportFile(path) => {
                let mf = MappedFile::must_open(&ctx.diag, Path::new(path));
                collect_file(ctx, mf, false, false, true, false, &mut queue);
            }
            InputArg::ReexportLib(name) => match find_library(ctx, name) {
                Some(path) => {
                    let mf = MappedFile::must_open(&ctx.diag, &path);
                    collect_file(ctx, mf, false, false, true, false, &mut queue);
                }
                None => error!(ctx, "library not found: -reexport-l{name}"),
            },
            InputArg::HiddenLib(name) => match find_library(ctx, name) {
                Some(path) => {
                    let mf = MappedFile::must_open(&ctx.diag, &path);
                    collect_file(ctx, mf, false, false, false, true, &mut queue);
                }
                None => error!(ctx, "library not found: -hidden-l{name}"),
            },
            InputArg::NeededLib(name) => match find_library(ctx, name) {
                Some(path) => {
                    let mf = MappedFile::must_open(&ctx.diag, &path);
                    let before = ctx.dylibs.len();
                    collect_file(ctx, mf, false, false, false, false, &mut queue);
                    for dylib in &mut ctx.dylibs[before..] {
                        dylib.is_needed = true;
                    }
                }
                None => error!(ctx, "library not found: -needed-l{name}"),
            },
            InputArg::NeededFramework(name) => match find_framework(ctx, name) {
                Some(path) => {
                    let mf = MappedFile::must_open(&ctx.diag, &path);
                    let before = ctx.dylibs.len();
                    collect_file(ctx, mf, false, false, false, false, &mut queue);
                    for dylib in &mut ctx.dylibs[before..] {
                        dylib.is_needed = true;
                    }
                }
                None => error!(ctx, "framework not found: {name}"),
            },
            InputArg::Lib(name, weak) => match find_library(ctx, name) {
                Some(path) => {
                    let mf = MappedFile::must_open(&ctx.diag, &path);
                    collect_file(ctx, mf, false, *weak, false, false, &mut queue);
                }
                None => error!(ctx, "library not found: -l{name}"),
            },
            InputArg::Framework(name, weak) => match find_framework(ctx, name) {
                Some(path) => {
                    let mf = MappedFile::must_open(&ctx.diag, &path);
                    collect_file(ctx, mf, false, *weak, false, false, &mut queue);
                }
                None => error!(ctx, "framework not found: {name}"),
            },
        }
    }
    ctx.args.inputs = inputs;
    t!("load_pending", load_pending(ctx, queue));
}

/// Acts on auto-link options (LC_LINKER_OPTION) of live objects: each
/// names a library or framework the object needs, as if it had been on
/// the command line. Swift objects rely on this entirely. Returns true
/// if new inputs were loaded, in which case resolution must run again.
/// What a round of auto-linking added to the link.
pub enum Autolinked {
    Nothing,
    /// Only dylibs, starting at this index. A dylib addition cannot
    /// change object-vs-object resolution (autolinked files get later
    /// priorities than everything already loaded), so a light claim
    /// pass replaces a full re-resolution.
    DylibsOnly(usize),
    Objects,
}

pub fn load_autolink_deps<E: Arch>(ctx: &mut Context<E>) -> Autolinked {
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
                            collect_file(ctx, mf, false, false, false, false, &mut queue);
                        }
                    }
                    None => crate::warn!(ctx, "auto-linked library not found: -l{name}"),
                }
            }
            ["-framework", name] => match find_framework(ctx, name) {
                Some(path) => {
                    if let Some(mf) = MappedFile::open(&ctx.diag, &path) {
                        collect_file(ctx, mf, false, false, false, false, &mut queue);
                    }
                }
                None => crate::warn!(ctx, "auto-linked framework not found: {name}"),
            },
            _ => crate::warn!(ctx, "unknown auto-link option: {:?}", opt),
        }
    }
    load_pending(ctx, queue);
    if ctx.objs.len() != before.0 {
        Autolinked::Objects
    } else if ctx.dylibs.len() != before.1 {
        Autolinked::DylibsOnly(before.1)
    } else {
        Autolinked::Nothing
    }
}

/// Lets newly auto-linked dylibs claim still-unresolved symbols. They
/// carry later priorities than every file already resolved, so they
/// can steal nothing - a full re-resolution would reach exactly this
/// outcome, at many times the cost.
pub fn claim_new_dylibs<E: Arch>(ctx: &mut Context<E>, first: usize) {
    use rayon::prelude::*;
    struct SymsPtr(*mut crate::symbol::Symbol);
    unsafe impl Sync for SymsPtr {}
    let syms_ptr = SymsPtr(ctx.symtab.syms.as_mut_ptr());
    let syms_ptr = &syms_ptr;
    let dylibs = &ctx.dylibs;
    (0..ctx.symtab.syms.len()).into_par_iter().for_each(|i| {
        // SAFETY: each index is written only by its own iteration.
        let sym = unsafe { &mut *syms_ptr.0.add(i) };
        if !sym.is_used() || sym.is_defined() {
            return;
        }
        for (dylib_idx, dylib) in dylibs.iter().enumerate().skip(first) {
            if dylib.exports.contains(sym.name()) {
                sym.set_origin(Origin::Dylib((dylib_idx) as u32));
                sym.set_is_imported(true);
                sym.set_is_extern(true);
                sym.set_isec(None);
                sym.set_is_common(false);
                break;
            }
        }
    });
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
    use rayon::prelude::*;
    // A local symbol belongs to exactly one object (locals get fresh
    // slots, never interned), so the per-object claims write disjoint
    // symbols and the objects proceed in parallel.
    struct SlotPtr(*mut crate::symbol::Symbol);
    unsafe impl Sync for SlotPtr {}
    let ptr = SlotPtr(ctx.symtab.syms.as_mut_ptr());
    let ptr = &ptr;
    let isecs = &ctx.isecs;
    ctx.objs.par_iter().enumerate().for_each(|(obj_idx, obj)| {
        for i in obj.local_range() {
            let nlist = &obj.nlists[i];
            if nlist.is_stab() || nlist.is_extern() {
                continue;
            }
            // SAFETY: disjoint per object, as above.
            let sym = unsafe { &mut *ptr.0.add(obj.syms[i] as usize) };
            match nlist.n_type() {
                N_ABS => {
                    sym.set_origin(Origin::Obj((obj_idx) as u32));
                    sym.set_isec(None);
                    sym.value = nlist.n_value;
                }
                N_SECT => {
                    if let Some((isec, off)) =
                        crate::input_files::find_subsec(isecs, &obj.subsecs, nlist.n_value)
                    {
                        sym.set_origin(Origin::Obj((obj_idx) as u32));
                        sym.set_isec(Some(isec as u32));
                        sym.value = off;
                        sym.set_no_dead_strip(nlist.n_desc & (N_NO_DEAD_STRIP | REFERENCED_DYNAMICALLY) != 0);
                    }
                }
                _ => {}
            }
        }
    });
}

fn clear_claims<E: Arch>(ctx: &mut Context<E>) {
    use rayon::prelude::*;
    ctx.symtab.syms.par_iter_mut().for_each(|sym| {
        if matches!(sym.origin(), Origin::Obj(_) | Origin::Dylib(_)) || sym.is_common() {
            sym.set_origin(Origin::Undef);
            sym.set_isec(None);
            sym.value = 0;
            sym.set_is_weak_def(false);
            sym.set_is_private_extern(false);
            sym.set_is_imported(false);
            sym.set_is_common(false);
            sym.common_p2align = 0;
            sym.set_no_dead_strip(false);
        }
    });
}

fn do_resolve<E: Arch>(ctx: &mut Context<E>, only_alive: bool) {
    use rayon::prelude::*;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    let n = ctx.symtab.syms.len();

    // Which symbols the files considered this round actually reference.
    // References from dead archive members must not count: they would
    // otherwise demand definitions nothing live needs.
    let used: Vec<AtomicBool> = (0..n).map(|_| AtomicBool::new(false)).collect();
    let weak_ref: Vec<AtomicBool> = (0..n).map(|_| AtomicBool::new(false)).collect();
    ctx.objs
        .par_iter()
        .filter(|obj| !only_alive || obj.is_alive)
        .for_each(|obj| {
            let r = obj.global_range();
            for (nlist, &sym_id) in obj.nlists[r.clone()].iter().zip(&obj.syms[r]) {
                if !nlist.is_stab() && nlist.is_extern() && nlist.n_type() == N_UNDF {
                    used[sym_id as usize].store(true, Ordering::Relaxed);
                    if nlist.n_desc & N_WEAK_REF != 0 {
                        weak_ref[sym_id as usize].store(true, Ordering::Relaxed);
                    }
                }
            }
        });
    for name in &ctx.args.forced_undefined {
        if let Some(id) = ctx.symtab.get(name) {
            used[id as usize].store(true, Ordering::Relaxed);
        }
    }
    if let Some(id) = ctx.symtab.get(&ctx.args.entry) {
        used[id as usize].store(true, Ordering::Relaxed);
    }

    // The rank of a definition: (class << 32) | priority, lower is
    // better. Ranks race into `best` with an atomic minimum, as in
    // mold: the race is order-free because the winner is the same
    // whatever the interleaving, and since each object has a unique
    // priority, exactly one object ends up owning each symbol.
    let rank_of = |obj: &crate::input_files::ObjectFile, nlist: &NList| -> Option<u64> {
        if nlist.is_stab() || !nlist.is_extern() {
            return None;
        }
        let is_weak = nlist.n_desc & N_WEAK_DEF != 0;
        let class: u64 = match nlist.n_type() {
            N_SECT | N_ABS if obj.is_alive && !is_weak => 0,
            N_SECT | N_ABS if obj.is_alive => 1,
            N_SECT | N_ABS => 2,
            N_UNDF if nlist.is_common() && obj.is_alive => 3,
            _ => return None,
        };
        Some((class << 32) | obj.priority as u64)
    };

    let best: Vec<AtomicU64> = (0..n).map(|_| AtomicU64::new(u64::MAX)).collect();
    ctx.objs
        .par_iter()
        .filter(|obj| !only_alive || obj.is_alive)
        .for_each(|obj| {
            let r = obj.global_range();
            for (nlist, &sym_id) in obj.nlists[r.clone()].iter().zip(&obj.syms[r]) {
                if let Some(rank) = rank_of(obj, nlist) {
                    best[sym_id as usize].fetch_min(rank, Ordering::Relaxed);
                }
            }
        });

    // Claim phase: each object writes the symbols whose race it won.
    // Ranks are unique per object, so every symbol has exactly one
    // writer and the parallel writes are disjoint.
    struct SymsPtr(*mut crate::symbol::Symbol);
    unsafe impl Sync for SymsPtr {}
    let syms_ptr = SymsPtr(ctx.symtab.syms.as_mut_ptr());
    let syms_ptr = &syms_ptr;
    let isecs = &ctx.isecs;
    let objs = &ctx.objs;
    // Duplicate strong definitions, reported after the race settles.
    let duplicates: std::sync::Mutex<Vec<(usize, usize)>> = std::sync::Mutex::new(Vec::new());

    objs.par_iter()
        .enumerate()
        .filter(|(_, obj)| !only_alive || obj.is_alive)
        .for_each(|(obj_idx, obj)| {
            let r = obj.global_range();
            for (nlist, &sym_id) in obj.nlists[r.clone()].iter().zip(&obj.syms[r]) {
                let Some(rank) = rank_of(obj, nlist) else {
                    continue;
                };
                let won = best[sym_id as usize].load(Ordering::Relaxed);
                if won != rank {
                    // Two live strong definitions of one name are an
                    // error whichever wins.
                    if only_alive && rank >> 32 == 0 && won >> 32 == 0 {
                        duplicates.lock().unwrap().push((sym_id as usize, obj_idx));
                    }
                    continue;
                }
                // SAFETY: this object holds the unique minimum rank
                // for sym_id, so no other thread writes this slot.
                let sym = unsafe { &mut *syms_ptr.0.add(sym_id as usize) };
                sym.set_is_extern(true);
                sym.set_is_imported(false);
                sym.set_is_common(false);
                sym.set_is_weak_def(nlist.n_desc & N_WEAK_DEF != 0);
                sym.set_is_private_extern(nlist.n_type & N_PEXT != 0 || obj.hidden);
                sym.set_no_dead_strip(nlist.n_desc & (N_NO_DEAD_STRIP | REFERENCED_DYNAMICALLY) != 0);

                match nlist.n_type() {
                    N_ABS => {
                        sym.set_origin(Origin::Obj((obj_idx) as u32));
                        sym.set_isec(None);
                        sym.value = nlist.n_value;
                    }
                    N_SECT => {
                        sym.set_origin(Origin::Obj((obj_idx) as u32));
                        match crate::input_files::find_subsec(
                            isecs,
                            &obj.subsecs,
                            nlist.n_value,
                        ) {
                            Some((isec, off)) => {
                                sym.set_isec(Some(isec as u32));
                                sym.value = off;
                            }
                            None => {
                                // A symbol in a discarded (debug)
                                // section resolves as if undefined.
                                sym.set_origin(Origin::Undef);
                                best[sym_id as usize].store(u64::MAX, Ordering::Relaxed);
                            }
                        }
                    }
                    N_UNDF => {
                        // A common symbol takes a tentative claim.
                        sym.set_origin(Origin::Undef);
                        sym.set_is_common(true);
                        sym.value = nlist.n_value;
                        sym.common_p2align = ((nlist.n_desc >> 8) & 0xf) as u8;
                    }
                    _ => unreachable!(),
                }
            }
        });

    // Common symbols merge: the largest size and strictest alignment
    // win regardless of input order, gathered from every common claim
    // once the class-3 winners are known.
    let commons: Vec<(crate::symbol::SymbolId, u64, u8)> = ctx
        .objs
        .par_iter()
        .filter(|obj| (!only_alive || obj.is_alive) && obj.is_alive)
        .flat_map_iter(|obj| {
            let r = obj.global_range();
            obj.nlists[r.clone()].iter().zip(&obj.syms[r]).filter_map(|(nlist, &sym_id)| {
                if !nlist.is_stab()
                    && nlist.is_extern()
                    && nlist.n_type() == N_UNDF
                    && nlist.is_common()
                    && best[sym_id as usize].load(Ordering::Relaxed) >> 32 == 3
                {
                    Some((sym_id, nlist.n_value, ((nlist.n_desc >> 8) & 0xf) as u8))
                } else {
                    None
                }
            })
        })
        .collect();
    for (sym_id, size, p2align) in commons {
        let sym = &mut ctx.symtab[sym_id];
        sym.value = sym.value.max(size);
        sym.common_p2align = sym.common_p2align.max(p2align);
    }

    // Report duplicates deterministically, sorted by symbol name.
    let mut duplicates = duplicates.into_inner().unwrap();
    duplicates.sort_by_key(|&(sym_id, obj_idx)| (ctx.symtab[sym_id].name(), obj_idx));
    duplicates.dedup();
    for (sym_id, obj_idx) in duplicates {
        let prev = match ctx.symtab[sym_id].origin() {
            Origin::Obj(idx) => file_display(&ctx.objs[idx as usize]),
            _ => "?".to_string(),
        };
        error!(
            ctx,
            "duplicate symbol: {}: {}: {}",
            file_display(&ctx.objs[obj_idx]),
            prev,
            ctx.symtab[sym_id].name()
        );
    }

    // Record weak references seen this round.
    for (i, w) in weak_ref.iter().enumerate() {
        if w.load(Ordering::Relaxed) {
            ctx.symtab.syms[i].set_is_weak_ref(true);
        }
    }

    // Dylib exports claim unresolved (or lazily-claimed) symbols; an
    // earlier dylib beats a later archive member and vice versa. A
    // relocatable link keeps every reference undefined instead.
    if ctx.args.relocatable {
        for (i, u) in used.iter().enumerate() {
            ctx.symtab.syms[i].set_is_used(u.load(Ordering::Relaxed));
        }
        return;
    }
    let dylibs = &ctx.dylibs;
    (0..n).into_par_iter().for_each(|i| {
        if !used[i].load(Ordering::Relaxed) {
            return;
        }
        // SAFETY: each index is written only by its own iteration.
        let sym = unsafe { &mut *syms_ptr.0.add(i) };
        if sym.is_common() || best[i].load(Ordering::Relaxed) >> 32 < 2 {
            return;
        }
        for (dylib_idx, dylib) in dylibs.iter().enumerate() {
            let rank = (2u64 << 32) | dylib.priority as u64;
            if rank < best[i].load(Ordering::Relaxed) && dylib.exports.contains(sym.name()) {
                best[i].store(rank, Ordering::Relaxed);
                sym.set_origin(Origin::Dylib((dylib_idx) as u32));
                sym.set_is_imported(true);
                sym.set_is_extern(true);
                sym.set_isec(None);
                sym.set_is_common(false);
                break;
            }
        }
    });

    // Record the final usage set for downstream passes.
    for (i, u) in used.iter().enumerate() {
        ctx.symtab.syms[i].set_is_used(u.load(Ordering::Relaxed));
    }
}

/// Marks archive members whose definitions live code references,
/// walking owner links to a fixed point.
fn mark_live_objects<E: Arch>(ctx: &mut Context<E>) {
    // Resolution runs in rounds and recomputes liveness each time, so
    // the -why_load record starts over with it.
    ctx.why_load.clear();
    let mut queue: Vec<usize> = (0..ctx.objs.len())
        .filter(|&i| ctx.objs[i].is_alive)
        .collect();

    // The entry point and -u symbols are roots too.
    let mut root_syms: Vec<&str> = vec![ctx.args.entry.as_str()];
    root_syms.extend(ctx.args.forced_undefined.iter().map(String::as_str));
    for name in root_syms {
        if let Some(id) = ctx.symtab.get(name) {
            if let Origin::Obj(owner) = ctx.symtab[id].origin() {
                let owner = owner as usize;
                if !ctx.objs[owner].is_alive {
                    ctx.objs[owner].is_alive = true;
                    ctx.why_load.insert(owner, ctx.symtab[id].name());
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
            if let Origin::Obj(owner) = ctx.symtab[sym_id].origin() {
                let owner = owner as usize;
                if !ctx.objs[owner].is_alive {
                    ctx.objs[owner].is_alive = true;
                    ctx.why_load.insert(owner, ctx.symtab[sym_id].name());
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
        // internalizer. For a dylib that is every external symbol a
        // bitcode module defines - each is an export. An executable
        // exports nothing that matters, so only symbols some non-LTO
        // code references (plus the entry point, and everything under
        // -export_dynamic, which exists exactly to let executables
        // keep their globals for dlsym) must survive; the rest can be
        // internalized and dead-stripped inside the module.
        let executable = ctx.args.output_type == MH_EXECUTE;
        let mut preserve: Vec<std::ffi::CString> = Vec::new();
        for sym in &ctx.symtab.syms {
            if let Origin::Obj(idx) = sym.origin() {
                if ctx.objs[idx as usize].lto_module.is_some() && sym.is_extern() {
                    if executable
                        && !ctx.args.export_dynamic
                        && !sym.is_used()
                        && sym.name() != ctx.args.entry
                        && !ctx.args.forced_undefined.iter().any(|n| n == sym.name())
                        && !ctx
                            .args
                            .exported_symbols
                            .as_ref()
                            .is_some_and(|list| list.iter().any(|n| n == sym.name()))
                    {
                        continue;
                    }
                    if let Ok(name) = std::ffi::CString::new(sym.name()) {
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

    // -object_path_lto keeps the machine-code object LTO produced.
    // Debug info stays in object files on Mach-O (the executable only
    // gets stabs pointing at them), and for LTO code that object
    // exists only inside the linker - Xcode passes a path under the
    // dSYM staging directory so dsymutil can find it afterwards.
    if let Some(path) = &ctx.args.object_path_lto {
        if std::fs::write(path, &data).is_err() {
            fatal!(ctx, "-object_path_lto: cannot write {path}");
        }
    }

    // Retire the placeholders: the compiled object provides the real
    // definitions, so they must neither claim nor reference anything in
    // the next resolution round.
    let modules = std::mem::take(&mut ctx.lto_modules);
    for &(obj_idx, _) in &modules {
        let ids = ctx.objs[obj_idx].syms.clone();
        for id in ids {
            let sym = &mut ctx.symtab[id];
            if sym.origin() == Origin::Obj((obj_idx) as u32) {
                sym.set_origin(Origin::Undef);
                sym.set_isec(None);
                sym.value = 0;
                sym.set_is_weak_def(false);
            }
        }
        let obj = &mut ctx.objs[obj_idx];
        obj.is_alive = false;
        obj.nlists = std::borrow::Cow::Borrowed(&[]);
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
        if !sym.is_common() || sym.is_defined() {
            continue;
        }
        let (size, p2align) = (sym.value, sym.common_p2align);

        let hdr: &'static MachSection = Box::leak(Box::new(MachSection {
            sectname: str_to_name("__common"),
            segname: str_to_name("__DATA"),
            size,
            p2align: p2align as u32,
            flags: S_ZEROFILL,
            ..Default::default()
        }));
        ctx.synthetic_hdrs.push(hdr);
        ctx.isecs.push(InputSection {
            obj: u32::MAX,
            shndx: (ctx.synthetic_hdrs.len() - 1) as u32,
            p2align: p2align as u8,
            input_addr: 0,
            size: size as u32,
            data_ptr: 0,
            rel_offset: 0,
            nrels: 0,
            osec: u32::MAX,
            output_offset: 0,
            flags: InputSection::flags_alive(),
            replacement: crate::input_sections::NO_REPLACEMENT,
            unwind_offset: 0,
            nunwind: 0,
        });

        let sym = &mut ctx.symtab[i];
        sym.set_origin(Origin::Synthetic);
        sym.set_isec(Some((ctx.isecs.len() - 1) as u32));
        sym.value = 0;
        sym.set_is_common(false);
        sym.set_is_extern(true);
    }
}

/// With -init_offsets, replaces __mod_init_func's absolute pointers
/// (which each need a rebase) with 32-bit image-relative offsets in a
/// __TEXT,__init_offsets section (type S_INIT_FUNC_OFFSETS), which
/// dyld runs the same way but never has to fix up.
pub fn convert_init_offsets<E: Arch>(ctx: &mut Context<E>) {
    // ld64 turns this on implicitly with chained fixups: the point of
    // chains is a fixup-free __DATA_CONST, and absolute initializer
    // pointers would drag rebases back in.
    if !ctx.args.init_offsets && !ctx.use_chained_fixups() {
        return;
    }
    for i in 0..ctx.isecs.len() {
        if ctx.hdr_of(&ctx.isecs[i]).section_type() != S_MOD_INIT_FUNC_POINTERS
            || !ctx.isecs[i].is_alive()
        {
            continue;
        }
        let mut relocs = ctx.isec_relocs(i).to_vec();
        relocs.sort_by_key(|r| r.offset);
        for rel in relocs {
            let obj = ctx.isecs[i].obj as usize;
            let target = match ctx.reloc_target_sym(obj, &rel) {
                Some(id) => {
                    let sym = &ctx.symtab[id];
                    match sym.isec() {
                        Some(isec) => (ctx.resolve_isec(isec as usize), sym.value),
                        None => continue,
                    }
                }
                None => match rel.target() {
                    crate::input_sections::RelocTarget::Section(isec) => {
                        (ctx.resolve_isec(isec as usize), rel.addend as u64)
                    }
                    _ => continue,
                },
            };
            ctx.init_funcs.push(target);
        }
        ctx.isecs[i].set_alive(false);
    }
}

/// Hides the subsections of archive members that resolution left
/// dead, so nothing of theirs reaches the output.
pub fn remove_unreachable_files<E: Arch>(ctx: &mut Context<E>) {
    for isec in ctx.isecs.iter_mut() {
        if isec.obj != u32::MAX && !ctx.objs[isec.obj as usize].is_alive {
            isec.set_alive(false);
        }
    }

    // Unwind records and FDEs of dead files go too, remapping the
    // record-to-FDE links around the removals.
    let mut fde_map = vec![usize::MAX; ctx.fdes.len()];
    let mut kept_fdes = Vec::new();
    let fdes = std::mem::take(&mut ctx.fdes);
    for (i, fde) in fdes.into_iter().enumerate() {
        if ctx.isecs[fde.isec].is_alive() {
            fde_map[i] = kept_fdes.len();
            kept_fdes.push(fde);
        }
    }
    ctx.fdes = kept_fdes;
    let isecs = &ctx.isecs;
    let map = &fde_map;
    ctx.unwind_records.retain_mut(|rec| {
        if !isecs[rec.isec as usize].is_alive() {
            return false;
        }
        if rec.fde_idx != crate::input_files::UNWIND_NONE {
            rec.fde_idx = map[rec.fde_idx as usize] as u32;
        }
        true
    });
    refresh_unwind_ranges(ctx);
}

/// Rebuilds each subsection's compact-unwind record range after the
/// records vector was compacted; the records stay grouped by
/// subsection, so one walk over runs restores every range.
pub fn refresh_unwind_ranges<E: Arch>(ctx: &mut Context<E>) {
    let mut i = 0;
    while i < ctx.unwind_records.len() {
        let isec = ctx.unwind_records[i].isec;
        let start = i;
        while i < ctx.unwind_records.len() && ctx.unwind_records[i].isec == isec {
            i += 1;
        }
        ctx.isecs[isec as usize].unwind_offset = start as u32;
        ctx.isecs[isec as usize].nunwind = (i - start) as u32;
    }
}

/// Merges identical literal elements across all live inputs: the first
/// live copy wins and the rest redirect to it.
pub fn merge_literals<E: Arch>(ctx: &mut Context<E>) {
    use rayon::prelude::*;

    // Deduplication follows the symbol table's sharded shape: every
    // element's content hash is computed in parallel, elements bin by
    // hash, and the shards resolve independently - within a shard the
    // first occurrence in input order wins, which is exactly the
    // winner the old serial single-map walk picked.
    let hashed: Vec<(u64, u32, u32)> = ctx
        .isecs
        .par_iter()
        .enumerate()
        .filter_map(|(i, isec)| {
            if !isec.is_alive() || isec.replacement != crate::input_sections::NO_REPLACEMENT {
                return None;
            }
            let ty = ctx.hdr_of(isec).section_type();
            if !matches!(
                ty,
                S_CSTRING_LITERALS | S_4BYTE_LITERALS | S_8BYTE_LITERALS | S_16BYTE_LITERALS
            ) {
                return None;
            }
            Some((xxhash_rust::xxh3::xxh3_64(isec.data()), ty, i as u32))
        })
        .collect();

    const NUM_SHARDS: usize = 64;
    let mut bins: Vec<Vec<(u64, u32, u32)>> = vec![Vec::new(); NUM_SHARDS];
    for &e in &hashed {
        bins[(e.0 % NUM_SHARDS as u64) as usize].push(e);
    }

    let isecs = &ctx.isecs;
    let folds: Vec<Vec<(u32, u32)>> = bins
        .into_par_iter()
        .map(|bin| {
            let mut map: hashbrown::HashMap<(u64, u32, &[u8]), u32> = hashbrown::HashMap::new();
            let mut out = Vec::new();
            for (hash, ty, i) in bin {
                match map.entry((hash, ty, isecs[i as usize].data())) {
                    hashbrown::hash_map::Entry::Occupied(e) => out.push((i, *e.get())),
                    hashbrown::hash_map::Entry::Vacant(e) => {
                        e.insert(i);
                    }
                }
            }
            out
        })
        .collect();

    for fold in folds {
        for (loser, winner) in fold {
            let p2align = ctx.isecs[loser as usize].p2align;
            ctx.isecs[loser as usize].replacement = winner as u32;
            let w = &mut ctx.isecs[winner as usize];
            w.p2align = w.p2align.max(p2align);
        }
    }

    // Point every symbol defined in a merged-away copy at the surviving
    // one - mold-rust makes the merged section's fragment the symbol's
    // origin - so a symbol's address never follows a replacement chain.
    // The copies are identical, so the symbol's offset is unchanged.
    // (Section-relative relocations still resolve through the chain in
    // isec_addr.)
    {
        use rayon::prelude::*;
        let isecs = &ctx.isecs;
        ctx.symtab.syms.par_iter_mut().for_each(|sym| {
            if let Some(i) = sym.isec() {
                let mut r = i as usize;
                while isecs[r].replacement != crate::input_sections::NO_REPLACEMENT {
                    r = isecs[r].replacement as usize;
                }
                if r != i as usize {
                    sym.set_isec(Some(r as u32));
                }
            }
        });
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
        if sym.is_defined() || !sym.is_used() {
            continue;
        }
        let Some(sel) = sym.name().strip_prefix("_objc_msgSend$") else {
            continue;
        };
        let sel = sel.to_string();
        let idx = ctx.objc_stubs.len() as u32;
        ctx.symtab[i].set_origin(Origin::Synthetic);
        ctx.sym_aux_mut(i as u32).objc_stub_idx = idx;
        ctx.objc_stubs.push((i as u32, sel));
    }

    if !ctx.objc_stubs.is_empty() {
        let id = ctx.symtab.intern("_objc_msgSend");
        ctx.symtab[id].set_is_used(true);
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
                sym.set_origin(Origin::Dylib((dylib) as u32));
                sym.set_is_imported(true);
                sym.set_is_extern(true);
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
/// Auto-hides eligible weak definitions in a main executable.
/// Compilers mark a weak definition whose address is never observed
/// with .weak_def_can_be_hidden (nlist n_desc carries N_WEAK_DEF and
/// N_WEAK_REF together); since dyld's runtime weak coalescing only
/// considers images that export the symbol and the executable is
/// first in load order anyway, ld64 demotes such symbols to
/// non-external - gone from the export trie and the external symbol
/// table. The scopes of coalesced copies merge: one plain
/// .weak_definition among them pins the symbol exported, and an
/// -exported_symbols_list naming it does too.
pub fn auto_hide_weak_defs<E: Arch>(ctx: &mut Context<E>) {
    if ctx.args.output_type != MH_EXECUTE {
        return;
    }

    // For each symbol, "seen a live weak def" and "every live weak def
    // may be hidden". A C++ debug link has millions of weak-def nlists
    // (every inline and template instance), so this reduces over them
    // in parallel into a dense array keyed by the symbol's id - mold's
    // pattern - rather than a serial fold into a hash map. Bit 0 marks
    // a symbol seen; bit 1 marks it as having a def that cannot hide.
    // Both bits are monotonic (only ever set), so racing relaxed
    // stores are safe.
    use rayon::prelude::*;
    use std::sync::atomic::{AtomicU8, Ordering};
    const SEEN: u8 = 1;
    const NOT_HIDABLE: u8 = 2;
    let flags: Vec<AtomicU8> = (0..ctx.symtab.syms.len()).map(|_| AtomicU8::new(0)).collect();
    ctx.objs.par_iter().for_each(|obj| {
        if !obj.is_alive {
            return;
        }
        let r = obj.global_range();
        for (nlist, &sym_id) in obj.nlists[r.clone()].iter().zip(&obj.syms[r]) {
            if nlist.is_stab()
                || !nlist.is_extern()
                || nlist.n_type() != N_SECT
                || nlist.n_desc & N_WEAK_DEF == 0
            {
                continue;
            }
            let bits = if nlist.n_desc & N_WEAK_REF != 0 { SEEN } else { SEEN | NOT_HIDABLE };
            flags[sym_id as usize].fetch_or(bits, Ordering::Relaxed);
        }
    });

    let exported = ctx.args.exported_symbols.as_ref();
    ctx.symtab
        .syms
        .par_iter_mut()
        .zip(&flags)
        .for_each(|(sym, f)| {
            let f = f.load(Ordering::Relaxed);
            if f & SEEN != 0
                && f & NOT_HIDABLE == 0
                && sym.is_weak_def()
                && sym.is_extern()
                && matches!(sym.origin(), Origin::Obj(_))
                && !exported.is_some_and(|list| list.iter().any(|n| n == sym.name()))
            {
                sym.set_is_private_extern(true);
            }
        });
}

/// Discards the losing copies of coalesced weak definitions. Symbol
/// resolution picks one definition per weak symbol, but the losing
/// objects' subsections still hold the duplicate bodies - a C++-heavy
/// link would otherwise ship every object's copy of every template
/// instantiation as anonymous dead weight (12MB of clang's 80MB
/// __text). Each losing subsection is redirected to the winner's, the
/// same replacement mechanism literal merging and ICF use, so
/// section-target relocations into a loser resolve into the winning
/// copy. Only exact-shape losers are folded: the defining symbol must
/// sit at the same offset in both, and the subsections must be the
/// same size - C++ guarantees identical weak instantiations, but a
/// mismatch means something odd, and keeping the copy is safe.
pub fn coalesce_weak_defs<E: Arch>(ctx: &mut Context<E>) {
    // A C++ debug link has millions of weak-def nlists (every inline
    // and template instance), so the scan that finds each losing copy
    // - filtering, and a find_subsec binary search per weak def - runs
    // in parallel per object. Only pure reads happen here (resolution
    // has already set origins, and find_subsec reads stable subsection
    // extents), so each object independently emits its candidate
    // (loser, winner) subsection pairs, unresolved, in nlist order.
    use rayon::prelude::*;
    let shared = &*ctx;
    let candidates: Vec<Vec<(usize, usize, u64, u64)>> = ctx
        .objs
        .par_iter()
        .enumerate()
        .map(|(obj_idx, obj)| {
            let mut out = Vec::new();
            if !obj.is_alive {
                return out;
            }
            let r = obj.global_range();
            for (nlist, &sym_id) in obj.nlists[r.clone()].iter().zip(&obj.syms[r]) {
                if nlist.is_stab()
                    || !nlist.is_extern()
                    || nlist.n_type() != N_SECT
                    || nlist.n_desc & N_WEAK_DEF == 0
                {
                    continue;
                }
                let sym = &shared.symtab[sym_id];
                let Origin::Obj(owner) = sym.origin() else { continue };
                if owner as usize == obj_idx {
                    continue;
                }
                let Some(winner) = sym.isec().map(|i| i as usize) else { continue };
                let Some((loser, off)) = crate::input_files::find_subsec(
                    &shared.isecs,
                    &obj.subsecs,
                    nlist.n_value,
                ) else {
                    continue;
                };
                out.push((loser, winner, off, sym.value));
            }
            out
        })
        .collect();

    // Applying the replacements is serial and order-dependent (a later
    // loser may resolve through an earlier one), so it stays a single
    // walk in object order - the same order and the same resolve/size
    // checks as the original loop, over only the qualifying weak defs.
    for list in candidates {
        for (loser, winner, off, sym_value) in list {
            let winner = ctx.resolve_isec(winner);
            let loser = ctx.resolve_isec(loser);
            if loser == winner
                || off != sym_value
                || ctx.isecs[loser].size != ctx.isecs[winner].size
                || ctx.isecs[loser].replacement != crate::input_sections::NO_REPLACEMENT
            {
                continue;
            }
            ctx.isecs[loser].replacement = winner as u32;
        }
    }
}

pub fn check_undefined_symbols<E: Arch>(ctx: &mut Context<E>) {
    // Errors name a file that wants the symbol; the map from symbol to
    // referencing object is built only once an error is certain.
    let mut referencers: Option<std::collections::HashMap<crate::symbol::SymbolId, usize>> = None;
    let mut who_wants = |ctx: &Context<E>, id: crate::symbol::SymbolId| -> String {
        let map = referencers.get_or_insert_with(|| {
            let mut map = std::collections::HashMap::new();
            for (obj_idx, obj) in ctx.objs.iter().enumerate() {
                if !obj.is_alive {
                    continue;
                }
                let r = obj.global_range();
                for (nlist, &sym_id) in obj.nlists[r.clone()].iter().zip(&obj.syms[r]) {
                    if !nlist.is_stab() && nlist.n_type() == N_UNDF && !nlist.is_common() {
                        map.entry(sym_id).or_insert(obj_idx);
                    }
                }
            }
            map
        });
        match map.get(&id) {
            Some(&obj_idx) => file_display(&ctx.objs[obj_idx]),
            None => "<synthesized>".to_string(),
        }
    };

    for i in 0..ctx.symtab.syms.len() {
        let sym = &ctx.symtab[i];
        if sym.is_used() && !sym.is_defined() {
            let allowed = ctx.args.undefined_dynamic_lookup
                || ctx.args.allowed_undefined.iter().any(|n| n == sym.name());
            if allowed {
                if ctx.args.undefined_warning {
                    crate::warn!(ctx, "undefined symbol: {}", ctx.symtab[i].name());
                }
                let sym = &mut ctx.symtab[i];
                sym.set_origin(Origin::Dylib((usize::MAX) as u32));
                sym.set_is_imported(true);
                sym.set_is_extern(true);
            } else {
                let file = who_wants(ctx, i as u32);
                error!(ctx, "undefined symbol: {}: {}", file, ctx.symtab[i].name());
            }
        }
    }
}

/// --print-dependencies prints, for every undefined symbol of every
/// object, which file's definition satisfied it - a line per edge:
/// "referencer<TAB>provider<TAB>u<TAB>symbol". Xcode's newer ld
/// grew this for build-graph auditing; it makes questions like "why
/// is this archive member in my binary" one grep.
pub fn print_dependencies<E: Arch>(ctx: &Context<E>) {
    if !ctx.args.print_dependencies {
        return;
    }
    for obj in &ctx.objs {
        if !obj.is_alive {
            continue;
        }
        let r = obj.global_range();
        for (nlist, &sym_id) in obj.nlists[r.clone()].iter().zip(&obj.syms[r]) {
            if nlist.is_stab() || nlist.n_type() != N_UNDF || nlist.is_common() {
                continue;
            }
            let sym = &ctx.symtab[sym_id];
            let provider = match sym.origin() {
                Origin::Obj(idx) => {
                    let idx = idx as usize;
                    if !ctx.objs[idx].is_alive || std::ptr::eq(&ctx.objs[idx], obj) {
                        continue;
                    }
                    file_display(&ctx.objs[idx])
                }
                Origin::Dylib(idx) if idx != u32::MAX => {
                    ctx.dylibs[idx as usize].install_name.clone()
                }
                _ => continue,
            };
            println!("{}\t{}\tu\t{}", file_display(obj), provider, sym.name());
        }
    }
}

/// -t traces the link's inputs: one line per file that contributes,
/// objects by path (archive members as archive(member)) and dylib
/// stubs by the path they were found at. In mold's model every input
/// is parsed eagerly, so rather than logging opens - which would list
/// archive members the link then discards - the trace reports what
/// actually took part.
pub fn print_trace<E: Arch>(ctx: &Context<E>) {
    if !ctx.args.trace {
        return;
    }
    for obj in &ctx.objs {
        if obj.is_alive {
            println!("{}", file_display(obj));
        }
    }
    for dylib in &ctx.dylibs {
        println!("{}", dylib.path);
    }
}

/// -why_load reports what dragged each archive member into the link:
/// "_symbol forced load of archive.a(member.o)", in ld64's wording.
/// Members loaded unconditionally (-all_load, -force_load) are
/// reported with the option as the reason.
pub fn print_why_load<E: Arch>(ctx: &Context<E>) {
    if !ctx.args.why_load {
        return;
    }
    for (idx, obj) in ctx.objs.iter().enumerate() {
        if !obj.is_alive || obj.mf.parent.is_none() {
            continue;
        }
        match ctx.why_load.get(&idx) {
            Some(name) => println!("{} forced load of {}", name, file_display(obj)),
            None => println!("-all_load or -force_load forced load of {}", file_display(obj)),
        }
    }
}

/// A file name for diagnostics: the object's path. Archive members
/// already carry their "archive(member)" form as their mapped-file
/// name.
pub(crate) fn file_display(obj: &crate::input_files::ObjectFile) -> String {
    obj.mf.name.clone()
}

/// Drops load commands for dylibs no symbol binds to
/// (-dead_strip_dylibs). Bind records name dylibs by their 1-based
/// load-command ordinal, so surviving dylibs are renumbered and symbol
/// origins remapped.
pub fn dead_strip_dylibs<E: Arch>(ctx: &mut Context<E>) {
    // A dylib built with -mark_dead_strippable_dylib asks every
    // linker to drop it when unused, so those are stripped even
    // without -dead_strip_dylibs.
    let strippable = |dylib: &crate::input_files::DylibFile| {
        ctx.args.dead_strip_dylibs || dylib.is_dead_strippable
    };
    if !ctx.dylibs.iter().any(|d| strippable(d)) {
        return;
    }

    let mut used = vec![false; ctx.dylibs.len()];
    for (i, dylib) in ctx.dylibs.iter().enumerate() {
        used[i] = dylib.is_needed || !strippable(dylib);
    }
    for sym in &ctx.symtab.syms {
        if let Origin::Dylib(idx) = sym.origin() {
            if idx != u32::MAX {
                used[idx as usize] = true;
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
        if let Origin::Dylib(idx) = sym.origin() {
            if idx != u32::MAX {
                sym.set_origin(Origin::Dylib(remap[idx as usize] as u32));
            }
        }
    }
}

/// Decides which symbols need a stub or a GOT slot, from how relocations
/// refer to them.
pub fn scan_relocations<E: Arch>(ctx: &mut Context<E>) {
    // Classification reads only; collect it on all cores. The apply
    // loop below stays serial so GOT and stub slots keep their
    // deterministic first-seen order.
    use rayon::prelude::*;
    let ctx_ref: &Context<E> = ctx;
    let classes: Vec<(crate::symbol::SymbolId, RelocClass)> = ctx_ref
        .isecs
        .par_iter()
        .filter(|isec| isec.is_alive())
        .flat_map_iter(|isec| {
            crate::input_files::isec_relocs_of(&ctx_ref.objs, isec).iter().filter_map(move |rel| {
                let id = ctx_ref.reloc_target_sym(isec.obj as usize, rel)?;
                let mut class = E::classify_reloc(rel.r_type);
                // A relaxable GOT load of a local symbol needs no
                // slot at all; an unrelaxable one is an ordinary GOT
                // reference.
                if class == RelocClass::GotLoad
                    && !E::can_relax_got_load(isec.data(), rel.offset, rel.r_type)
                {
                    class = RelocClass::Got;
                }
                // Plain references need no slot of any kind, and
                // they are the overwhelming majority; dropping them
                // here keeps the collected list (and the serial
                // apply loop below) small. The TLV/regular mismatch
                // check needs the TLV side only: a plain reference
                // to a thread-local is caught because thread-locals
                // are reached exclusively through TLV relocations,
                // checked against the symbol below either way.
                if class == RelocClass::Plain
                    && !is_thread_local_sym(ctx_ref, id)
                {
                    return None;
                }
                Some((id, class))
            })
        })
        .collect();

    for (id, class) in classes {
        let sym = &ctx.symtab[id];

        // Thread-locals live behind __thread_vars descriptors, so the
        // reference kind must agree with the symbol: a TLV load of
        // ordinary data would treat the variable's bytes as a
        // descriptor, and an ordinary load of a TLV would read the
        // descriptor as data. ld64 rejects both directions.
        if is_thread_local_sym(ctx, id) != matches!(class, RelocClass::Tlv) {
            fatal!(
                ctx,
                "illegal thread local variable reference to regular symbol `{}`",
                sym.name()
            );
        }

        match class {
            RelocClass::Branch if sym.is_imported() => {
                // A stub jumps through the symbol's GOT slot.
                add_stub(ctx, id);
                add_got(ctx, id);
            }
            RelocClass::Got => add_got(ctx, id),
            RelocClass::GotLoad if sym.is_imported() => add_got(ctx, id),
            // A TLV load of a local thread-local relaxes to the
            // descriptor's address; only imported ones need a
            // __thread_ptrs slot for dyld to fill.
            RelocClass::Tlv if sym.is_imported() => add_thread_ptr(ctx, id),
            _ => {}
        }
    }
}

/// True if the symbol resolves to a TLV descriptor: a definition in a
/// S_THREAD_LOCAL_VARIABLES section, or a dylib export listed as
/// thread-local. Symbols left to runtime lookup pass as either.
fn is_thread_local_sym<E: Arch>(ctx: &Context<E>, id: crate::symbol::SymbolId) -> bool {
    let sym = &ctx.symtab[id];
    match sym.origin() {
        crate::symbol::Origin::Obj(_) => sym.isec().map(|i| i as usize).is_some_and(|isec| {
            ctx.hdr_of(&ctx.isecs[isec]).flags & SECTION_TYPE == S_THREAD_LOCAL_VARIABLES
        }),
        crate::symbol::Origin::Dylib(idx) => {
            idx != u32::MAX && ctx.dylibs[idx as usize].tlv_exports.contains(sym.name())
        }
        _ => false,
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
        .filter_map(|rec| rec.personality())
        .collect();
    personalities.extend(ctx.cies.iter().filter_map(|cie| cie.personality));
    for id in personalities {
        add_got(ctx, id);
    }
}

fn add_thread_ptr<E: Arch>(ctx: &mut Context<E>, id: crate::symbol::SymbolId) {
    if ctx.sym_aux(id).tlv_idx == crate::symbol::NO_IDX {
        ctx.sym_aux_mut(id).tlv_idx = ctx.thread_ptr_syms.len() as u32;
        ctx.thread_ptr_syms.push(id);
    }
}

fn add_stub<E: Arch>(ctx: &mut Context<E>, id: crate::symbol::SymbolId) {
    if ctx.sym_aux(id).stub_idx == crate::symbol::NO_IDX {
        ctx.sym_aux_mut(id).stub_idx = ctx.stub_syms.len() as u32;
        ctx.stub_syms.push(id);
    }
}

fn add_got<E: Arch>(ctx: &mut Context<E>, id: crate::symbol::SymbolId) {
    if ctx.sym_aux(id).got_idx == crate::symbol::NO_IDX {
        ctx.sym_aux_mut(id).got_idx = ctx.got_syms.len() as u32;
        ctx.got_syms.push(id);
    }
}

/// Defines the symbols the linker itself provides.
pub fn add_synthetic_symbols<E: Arch>(ctx: &mut Context<E>) {
    if ctx.args.output_type == MH_EXECUTE {
        let id = ctx.symtab.intern("__mh_execute_header");
        let sym = &mut ctx.symtab[id];
        if !sym.is_defined() {
            sym.set_origin(Origin::Synthetic);
            sym.value = ctx.args.pagezero_size;
            sym.set_is_extern(true);
        }
    }

    // ___dso_handle identifies the image; C++ static destructors pass it
    // to __cxa_atexit. It resolves to the mach header but is never
    // exported.
    let id = ctx.symtab.intern("___dso_handle");
    let sym = &mut ctx.symtab[id];
    if !sym.is_defined() {
        sym.set_origin(Origin::Synthetic);
        sym.value = ctx.args.pagezero_size;
        sym.set_is_extern(false);
    }

    // -alias gives an existing definition a second name: the new
    // symbol shares the original's subsection and offset, so it lands
    // at the same address and is exported alongside it. Apple uses
    // aliases to publish compatibility names (e.g. libSystem's dozens
    // of $VARIANT names) without touching the source.
    let aliases = std::mem::take(&mut ctx.args.aliases);
    for (existing, new) in &aliases {
        let Some(src) = ctx.symtab.get(existing) else {
            error!(ctx, "-alias: undefined base symbol: {existing}");
            continue;
        };
        if !ctx.symtab[src].is_defined() {
            error!(ctx, "-alias: undefined base symbol: {existing}");
            continue;
        }
        let dst = ctx.symtab.intern(String::leak(new.clone()));
        if !ctx.symtab[dst].is_defined() {
            let (origin, isec, value) = {
                let s = &ctx.symtab[src];
                (s.origin(), s.isec(), s.value)
            };
            let sym = &mut ctx.symtab[dst];
            sym.set_origin(origin);
            sym.set_isec(isec);
            sym.value = value;
            sym.set_is_extern(true);
        }
    }
    ctx.args.aliases = aliases;

    // ld64's layout-boundary symbols: an undefined reference to
    // section$start$__SEG$__sect (or $end$, or segment$start$__SEG /
    // segment$end$__SEG) resolves to the boundary's final address, and
    // wills the named section into existence if nothing else creates
    // it. Their values can only be known after layout, so they are
    // claimed here and patched in fix_synthetic_symbols.
    for id in 0..ctx.symtab.syms.len() {
        let sym = &ctx.symtab[id];
        if !sym.is_used() || sym.is_defined() {
            continue;
        }
        let parsed = if let Some(rest) = sym.name().strip_prefix("section$") {
            rest.split_once('$').and_then(|(which, rest)| {
                rest.split_once('$').map(|(seg, sect)| {
                    (which == "start", seg.to_string(), Some(sect.to_string()))
                })
            })
        } else if let Some(rest) = sym.name().strip_prefix("segment$") {
            rest.split_once('$')
                .map(|(which, seg)| (which == "start", seg.to_string(), None))
        } else {
            None
        };
        let Some((is_start, seg, sect)) = parsed else {
            continue;
        };
        let sym = &mut ctx.symtab[id];
        sym.set_origin(Origin::Synthetic);
        sym.set_is_extern(false);
        ctx.boundary_syms.push((id as u32, is_start, seg, sect));
    }
}

/// Fills in the boundary symbols' addresses once every chunk and
/// segment has one.
pub fn fix_synthetic_symbols<E: Arch>(ctx: &mut Context<E>) {
    for i in 0..ctx.boundary_syms.len() {
        let (id, is_start, seg, sect) = ctx.boundary_syms[i].clone();
        let value = match &sect {
            Some(sect) => {
                let Some(chunk) = ctx
                    .chunks
                    .iter()
                    .find(|c| c.hdr.is_sect && c.hdr.segname == seg && c.hdr.sectname == *sect)
                else {
                    fatal!(ctx, "no section for boundary symbol: {}", ctx.symtab[id].name());
                };
                if is_start {
                    chunk.hdr.addr
                } else {
                    chunk.hdr.addr + chunk.hdr.size
                }
            }
            None => {
                let Some(segment) = ctx.segments.iter().find(|s| s.name == seg) else {
                    fatal!(ctx, "no segment for boundary symbol: {}", ctx.symtab[id].name());
                };
                if is_start {
                    segment.cmd.vmaddr
                } else {
                    segment.cmd.vmaddr + segment.cmd.vmsize
                }
            }
        };
        ctx.symtab[id].value = value;
    }
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
pub fn create_output_sections<E: Arch>(ctx: &mut Context<E>) {
    ctx.chunks.push(Chunk::new("__TEXT", "", ChunkKind::MachHeader));

    // Assign each input section to an output section, creating output
    // sections as needed. Keyed by the raw 16-byte name pairs, so the
    // hot loop does no allocation and no linear scans; chunks are
    // still created in first-encounter order.
    let attr_mask = if ctx.args.relocatable { !0 } else { !S_ATTR_DEBUG };
    let mut by_name: hashbrown::HashMap<([u8; 16], [u8; 16]), usize> =
        hashbrown::HashMap::new();
    // All subsections of one input section share the exact same leaked
    // header pointer and are contiguous in the arena, and a header
    // uniquely names one (object, section) - so a section's whole run
    // of subsections maps to the same output chunk. Cache the last
    // header pointer to skip the 32-byte name hash for all but the
    // first subsection of each section; on a debug link this turns
    // millions of hash lookups into a handful of thousands.
    let mut last_hdr: *const crate::macho::MachSection = std::ptr::null();
    let mut last_chunk: usize = 0;
    for i in 0..ctx.isecs.len() {
        if !ctx.isecs[i].is_alive() || ctx.isecs[i].replacement != crate::input_sections::NO_REPLACEMENT {
            continue;
        }
        let hdr = ctx.hdr_of(&ctx.isecs[i]);
        let hdr_ptr = hdr as *const crate::macho::MachSection;
        let chunk_idx = if hdr_ptr == last_hdr {
            last_chunk
        } else {
        let key = (hdr.segname, hdr.sectname);
        let idx = match by_name.get(&key) {
            Some(&idx) => idx,
            None => {
                let segname: &'static str = match hdr.segname() {
                    "__TEXT" => "__TEXT",
                    "__DATA_CONST" => "__DATA_CONST",
                    "__DATA" => "__DATA",
                    other => String::leak(other.to_string()),
                };
                let sectname = hdr.sectname().to_string();
                let mut chunk = Chunk::new(
                    segname,
                    &sectname,
                    ChunkKind::Output {
                        isecs: vec![],
                        thunks: vec![],
                    },
                );
                // A final image never contains debug sections, so the
                // attribute is dropped; a relocatable output keeps it,
                // marking the carried DWARF for the next link.
                chunk.hdr.flags = hdr.flags & attr_mask;
                ctx.chunks.push(chunk);
                by_name.insert(key, ctx.chunks.len() - 1);
                ctx.chunks.len() - 1
            }
        };
        last_hdr = hdr_ptr;
        last_chunk = idx;
        idx
        };

        let chunk = &mut ctx.chunks[chunk_idx];
        chunk.hdr.p2align = chunk.hdr.p2align.max(ctx.isecs[i].p2align as u32);
        // __thread_vars contains pointers but clang emits it with an
        // alignment of 1, so override.
        if chunk.hdr.flags & SECTION_TYPE == S_THREAD_LOCAL_VARIABLES {
            chunk.hdr.p2align = chunk.hdr.p2align.max(3);
        }
        chunk.hdr.flags |= hdr.flags & !SECTION_TYPE & attr_mask;
        let ChunkKind::Output { isecs, .. } = &mut chunk.kind else {
            unreachable!()
        };
        isecs.push(i as u32);
        ctx.isecs[i].osec = chunk_idx as u32;
    }

    // -sectalign overrides an output section's alignment, e.g. to
    // page-align a blob that will be mapped or measured separately.
    // It can only raise the alignment: subsections were placed by
    // their own requirements, which must still hold.
    for (seg, sect, p2align) in &ctx.args.sectalign.clone() {
        for chunk in &mut ctx.chunks {
            if chunk.hdr.is_sect && chunk.hdr.segname == *seg && chunk.hdr.sectname == *sect {
                chunk.hdr.p2align = chunk.hdr.p2align.max(*p2align as u32);
            }
        }
    }

    // -order_file moves the atoms it names to the front of their
    // output sections, in the file's order; everything else keeps its
    // input order behind them. A stable sort by rank does both.
    if let Some(ranks) = order_file_ranks(ctx) {
        for chunk in &mut ctx.chunks {
            if let ChunkKind::Output { isecs, .. } = &mut chunk.kind {
                isecs.sort_by_key(|&id| ranks[id as usize]);
            }
        }
    }

    // Compute each input section's offset within its output section.
    // Following mold's design, sections lay out in parallel: each
    // output section's offsets depend only on its own members, so the
    // per-section prefix sums run on all cores and the results are
    // written back serially. The exception is a __TEXT section big
    // enough to need range-extension thunks, whose creation scans and
    // annotates relocations; those (at most one per link in practice)
    // stay on the serial path.
    {
        use rayon::prelude::*;
        // Branches are not confined to their own section: __text,
        // __StaticInit, the stubs and every other executable section
        // share the __TEXT segment's address space, so once their
        // combined size comes near the branch reach, a branch from any
        // of them can be out of range. One gate over the total decides
        // for all of them (a small late section like __StaticInit is
        // exactly the one whose backward branches span the farthest).
        let mut exec_total: u64 = 0;
        for chunk in &ctx.chunks {
            if let ChunkKind::Output { isecs, .. } = &chunk.kind {
                if chunk.hdr.flags & (S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS)
                    != 0
                {
                    exec_total += isecs.iter().map(|&id| ctx.isecs[id].size as u64 + 16).sum::<u64>();
                }
            }
        }
        let need_thunks = exec_total > E::BRANCH_RANGE / 2 - 64 * 1024 * 1024;

        let mut thunked: Vec<usize> = Vec::new();
        let mut plain: Vec<(usize, Vec<crate::input_sections::InputSectionId>)> = Vec::new();
        for chunk_idx in 0..ctx.chunks.len() {
            let ChunkKind::Output { isecs, .. } = &ctx.chunks[chunk_idx].kind else {
                continue;
            };
            let is_exec = ctx.chunks[chunk_idx].hdr.flags
                & (S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS)
                != 0;
            if is_exec && need_thunks {
                thunked.push(chunk_idx);
            } else {
                plain.push((chunk_idx, isecs.clone()));
            }
        }

        let offsets: Vec<(usize, Vec<u64>, u64)> = plain
            .par_iter()
            .map(|(chunk_idx, isecs)| {
                let mut offs = Vec::with_capacity(isecs.len());
                let mut off = 0;
                for &id in isecs {
                    let isec = &ctx.isecs[id];
                    off = align_to(off, 1 << isec.p2align);
                    offs.push(off);
                    off += isec.size as u64;
                }
                (*chunk_idx, offs, off)
            })
            .collect();
        for (chunk_idx, offs, size) in offsets {
            let ChunkKind::Output { isecs, .. } = &ctx.chunks[chunk_idx].kind else {
                unreachable!()
            };
            for (&id, off) in isecs.clone().iter().zip(offs) {
                ctx.isecs[id].output_offset = off as u32;
            }
            ctx.chunks[chunk_idx].hdr.size = size;
        }

        for chunk_idx in thunked {
            let ChunkKind::Output { isecs, .. } = &ctx.chunks[chunk_idx].kind else {
                unreachable!()
            };
            let isecs = isecs.clone();
            let thunks = crate::thunks::create_range_extension_thunks::<E>(ctx, &isecs);
            let end = match thunks.last() {
                Some(t) => t.offset + t.syms.len() as u64 * E::THUNK_SIZE,
                None => 0,
            };
            let data_end = isecs
                .last()
                .map(|&id| ctx.isecs[id].output_offset as u64 + ctx.isecs[id].size as u64)
                .unwrap_or(0);
            let chunk = &mut ctx.chunks[chunk_idx];
            chunk.hdr.size = end.max(data_end);
            let ChunkKind::Output { thunks: t, .. } = &mut chunk.kind else {
                unreachable!()
            };
            *t = thunks;
        }
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

    if !ctx.init_funcs.is_empty() {
        let mut chunk = Chunk::new("__TEXT", "__init_offsets", ChunkKind::InitOffsets);
        chunk.hdr.flags = S_INIT_FUNC_OFFSETS;
        chunk.hdr.p2align = 2;
        chunk.hdr.size = ctx.init_funcs.len() as u64 * 4;
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

    // -add_empty_section synthesizes a zero-length section, giving
    // tools a named anchor (its section$start/end addresses) without
    // any content.
    let empties = std::mem::take(&mut ctx.args.add_empty_section);
    for (seg, sect) in &empties {
        let segname: &'static str = String::leak(seg.clone());
        let chunk = Chunk::new(segname, sect, ChunkKind::SectCreate { data: &[] });
        ctx.chunks.push(chunk);
    }
    ctx.args.add_empty_section = empties;

    // Sections that exist only because a boundary symbol names them.
    for i in 0..ctx.boundary_syms.len() {
        let (_, _, seg, Some(sect)) = &ctx.boundary_syms[i] else {
            continue;
        };
        if !ctx
            .chunks
            .iter()
            .any(|c| c.hdr.is_sect && c.hdr.segname == *seg && c.hdr.sectname == *sect)
        {
            let segname: &'static str = String::leak(seg.clone());
            let chunk = Chunk::new(segname, sect, ChunkKind::SectCreate { data: &[] });
            ctx.chunks.push(chunk);
        }
    }

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
        ctx.fdes.retain(|fde| isecs[fde.isec].replacement == crate::input_sections::NO_REPLACEMENT);
    }
    if !ctx.fdes.is_empty() {
        for fde in &ctx.fdes {
            ctx.cies[fde.cie as usize].is_alive = true;
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
    if ctx.args.data_in_code_info {
        ctx.chunks.push(Chunk::new("__LINKEDIT", "", ChunkKind::DataInCode));
    }
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
pub fn create_output_symtab<E: Arch>(
    ctx: &Context<E>,
    sorted_globals: &[crate::symbol::SymbolId],
) -> SymtabData {
    let ordinals = section_ordinals(ctx);
    let mut data = SymtabData::default();
    // The string table opens with " \0-\0": offset 1 is the empty
    // string, offset 2 the "-" placeholder for stab source-file
    // entries. copy_symtab writes this prefix; the deduplicated
    // strings follow it starting at offset 4.
    const STRTAB_PREFIX: usize = 4;

    // Names are collected alongside the entries and the string table
    // is built afterwards in one parallel pass (below); an entry
    // whose name is the empty sentinel keeps whatever fixed n_strx
    // its loop assigned (the "" and "-" placeholders).
    let mut names: Vec<&'static str> = Vec::new();


    // Swift AST paths for the debugger (-add_ast_path), as N_AST stabs.
    for path in &ctx.args.add_ast_paths {
        let n_strx = 0;
        names.push(String::leak(path.clone()));
        data.entries.push((
            NList {
                n_strx,
                n_type: N_AST,
                ..Default::default()
            },
            None,
        ));
    }

    let __t = std::time::Instant::now();
    // Debug stabs. Mach-O binaries don't carry DWARF; instead, for each
    // object with debug info the symbol table gets stab entries telling
    // the debugger where the object file is (N_OSO) and where its
    // functions and globals ended up, and the debugger reads the DWARF
    // from the objects.
    if !ctx.args.strip_debug {
        let cwd = std::env::current_dir()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        let cwd = &cwd;

        // Each object's stab run is independent; plan them in
        // parallel and append in object order, the same shape as the
        // per-object locals planning below.
        use rayon::prelude::*;
        let planned: Vec<Vec<(&'static str, NList, Option<crate::symbol::SymbolId>)>> = ctx
            .objs
            .par_iter()
            .enumerate()
            .map(|(obj_idx, obj)| {
                let mut out: Vec<(&'static str, NList, Option<crate::symbol::SymbolId>)> =
                    Vec::new();
                if !obj.has_debug_info || !obj.is_alive {
                    return out;
                }

                // The source-file N_SO's name is unused by debuggers; "-"
                // stands in. N_OSO points at the object (or
                // "archive(member)"), as an absolute path.
                out.push((
                    "",
                    NList {
                        n_strx: 2,
                        n_type: N_SO,
                        ..Default::default()
                    },
                    None,
                ));
                let mut oso_name = match obj.mf.parent {
                    Some(parent) if parent.name.starts_with('/') => obj.mf.name.clone(),
                    Some(_) | None if obj.mf.name.starts_with('/') => obj.mf.name.clone(),
                    _ => format!("{cwd}/{}", obj.mf.name),
                };
                // -oso_prefix strips a leading path from every N_OSO, so
                // debug builds relocated to another machine (or built in a
                // sandbox) can still find their objects relative to a
                // debugger's source map. "." means the current directory.
                if let Some(prefix) = &ctx.args.oso_prefix {
                    let prefix: &str =
                        if prefix == "." { &format!("{cwd}/") } else { prefix };
                    if let Some(rest) = oso_name.strip_prefix(prefix) {
                        oso_name = rest.to_string();
                    }
                }
                out.push((
                    String::leak(std::mem::take(&mut oso_name)),
                    NList {
                        n_strx: 0,
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
                        || !matches!(sym.origin(), Origin::Obj(o) if o as usize == obj_idx)
                        || (!nlist.is_extern() && !keep_local_symbol(sym.name()))
                    {
                        continue;
                    }
                    let Some(isec) = sym.isec().map(|i| i as usize) else { continue };
                    let isec_id = ctx.resolve_isec(isec as usize);
                    let isec = &ctx.isecs[isec_id];
                    if !isec.is_alive() {
                        continue;
                    }

                    let stab_name = sym.name();
                    let is_text = ctx.hdr_of(isec).segname() == "__TEXT"
                        && ctx.hdr_of(isec).flags
                            & (S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS)
                            != 0;
                    if is_text {
                        // A pair: the function's address, then its size.
                        out.push((
                            stab_name,
                            NList {
                                n_strx: 0,
                                n_type: N_FUN,
                                n_sect: ordinals[isec.osec as usize],
                                ..Default::default()
                            },
                            Some(sym_id),
                        ));
                        out.push((
                            "",
                            NList {
                                n_strx: 1,
                                n_type: N_FUN,
                                n_value: isec.size as u64,
                                ..Default::default()
                            },
                            None,
                        ));
                    } else {
                        out.push((
                            stab_name,
                            NList {
                                n_strx: 0,
                                n_type: if nlist.is_extern() { N_GSYM } else { N_STSYM },
                                n_sect: ordinals[isec.osec as usize],
                                ..Default::default()
                            },
                            Some(sym_id),
                        ));
                    }
                }

                // An N_SO with an empty name closes the object's stabs.
                out.push((
                    "",
                    NList {
                        n_strx: 1,
                        n_type: N_SO,
                        n_sect: 1,
                        ..Default::default()
                    },
                    None,
                ));
                out
            })
            .collect();
        // Write the planned stabs into prefix-summed ranges in
        // parallel, instead of appending object by object - mold's
        // populate_symtab shape. Each object owns a disjoint range
        // starting after whatever entries (e.g. AST paths) precede it.
        let start = data.entries.len();
        debug_assert_eq!(names.len(), start);
        let mut bases = Vec::with_capacity(planned.len());
        let mut total = start;
        for plan in &planned {
            bases.push(total);
            total += plan.len();
        }
        names.reserve(total - start);
        data.entries.reserve(total - start);
        struct NamePtr(*mut &'static str);
        unsafe impl Sync for NamePtr {}
        struct EntPtr(*mut (NList, Option<crate::symbol::SymbolId>));
        unsafe impl Sync for EntPtr {}
        let np = NamePtr(names.as_mut_ptr());
        let ep = EntPtr(data.entries.as_mut_ptr());
        let (np, ep) = (&np, &ep);
        planned.par_iter().zip(&bases).for_each(|(plan, &base)| {
            for (k, &(name, ent, sym)) in plan.iter().enumerate() {
                // SAFETY: [base, base+plan.len()) ranges are disjoint
                // across objects and lie within the reserved capacity.
                unsafe {
                    np.0.add(base + k).write(name);
                    ep.0.add(base + k).write((ent, sym));
                }
            }
        });
        // SAFETY: every slot in start..total was written above.
        unsafe {
            names.set_len(total);
            data.entries.set_len(total);
        }
    }

    if std::env::var_os("MOLD_TIMING").is_some() {
        eprintln!("      symtab-stabs {:?}", __t.elapsed());
    }
    let __t = std::time::Instant::now();

    // Local symbols (-x drops them), planned per object in parallel
    // - mold's plan_symtab per file - and appended in object order.
    if !ctx.args.strip_locals {
        use rayon::prelude::*;
        let ctx_ref: &Context<E> = ctx;
        let per_obj: Vec<Vec<(&'static str, NList, crate::symbol::SymbolId)>> = ctx_ref
            .objs
            .par_iter()
            .map(|obj| {
                let mut out = Vec::new();
                if !obj.is_alive {
                    return out;
                }
                let r = obj.local_range();
                for (nlist, &sym_id) in obj.nlists[r.clone()].iter().zip(&obj.syms[r]) {
                    let sym = &ctx_ref.symtab[sym_id];
                    if nlist.is_stab() || nlist.is_extern() || !keep_local_symbol(sym.name()) {
                        continue;
                    }
                    // -non_global_symbols_keep_list / _strip_list
                    // filter local symbols by name; stabs unaffected.
                    if let Some(keep) = &ctx_ref.args.local_keep_list {
                        if !keep.iter().any(|p| crate::util::glob_match(p, sym.name())) {
                            continue;
                        }
                    }
                    if ctx_ref
                        .args
                        .local_strip_list
                        .iter()
                        .any(|p| crate::util::glob_match(p, sym.name()))
                    {
                        continue;
                    }
                    let Some(isec) = sym.isec().map(|i| i as usize) else { continue };
                    let isec = ctx_ref.resolve_isec(isec);
                    if !matches!(sym.origin(), Origin::Obj(_)) || !ctx_ref.isecs[isec].is_alive() {
                        continue;
                    }
                    let ent = NList {
                        n_strx: 0,
                        n_type: N_SECT,
                        n_sect: ordinals[ctx_ref.isecs[isec].osec as usize],
                        n_desc: 0,
                        n_value: 0,
                    };
                    out.push((sym.name(), ent, sym_id));
                }
                out
            })
            .collect();
        for group in per_obj {
            for (name, ent, sym_id) in group {
                names.push(name);
                data.entries.push((ent, Some(sym_id)));
            }
        }
    }
    if std::env::var_os("MOLD_TIMING").is_some() {
        eprintln!("      symtab-locals {:?}", __t.elapsed());
    }
    let __t = std::time::Instant::now();
    // One parallel pass classifies the whole symbol table - private
    // externals (emitted among the locals), defined globals and
    // undefineds - instead of three full scans over millions of
    // slots.
    #[derive(Clone, Copy, PartialEq)]
    enum Class {
        No,
        Pext,
        Undef,
    }
    let classes: Vec<Class> = {
        use rayon::prelude::*;
        (0..ctx.symtab.syms.len())
            .into_par_iter()
            .map(|i| {
                let sym = &ctx.symtab[i];
                if matches!(sym.origin(), Origin::Dylib(_)) {
                    return Class::Undef;
                }
                if sym.is_extern()
                    && sym.is_private_extern()
                    && matches!(sym.origin(), Origin::Obj(_))
                    && sym
                        .isec()
                        .is_some_and(|isec| ctx.isecs[ctx.resolve_isec(isec as usize)].is_alive())
                {
                    return Class::Pext;
                }
                Class::No
            })
            .collect()
    };

    // Private external symbols resolve globally but appear as locals
    // (with N_PEXT still set) in the output.
    for (i, &class) in classes.iter().enumerate() {
        if class != Class::Pext {
            continue;
        }
        let sym = &ctx.symtab[i];
        let isec = ctx.resolve_isec(sym.isec().unwrap() as usize);
        names.push(sym.name());
        let ent = NList {
            n_strx: 0,
            n_type: N_SECT | N_PEXT,
            n_sect: ordinals[ctx.isecs[isec].osec as usize],
            n_desc: 0,
            n_value: 0,
        };
        data.entries.push((ent, Some(i as u32)));
    }
    data.nlocal = data.entries.len() as u32;

    // Defined global symbols, sorted by name; the caller sorted them
    // once for this table and the export trie both.
    use rayon::prelude::*;
    for &i in sorted_globals {
        let sym = &ctx.symtab[i];
        let n_strx = 0;
        names.push(sym.name());
        let (n_type, n_sect, mut n_desc) = match (sym.origin(), sym.isec()) {
            (_, Some(isec)) => (
                N_SECT | N_EXT,
                ordinals[ctx.isecs[ctx.resolve_isec(isec as usize)].osec as usize],
                0,
            ),
            (Origin::Synthetic, None) => (N_SECT | N_EXT, 1, REFERENCED_DYNAMICALLY),
            (_, None) => (N_ABS | N_EXT, 0, 0),
        };
        if sym.is_weak_def() {
            n_desc |= N_WEAK_DEF;
        }
        let ent = NList {
            n_strx,
            n_type,
            n_sect,
            n_desc,
            n_value: 0,
        };
        data.entries.push((ent, Some(i as u32)));
    }
    data.nextdef = data.entries.len() as u32 - data.nlocal;

    // Undefined (imported) symbols, sorted by name. The library ordinal
    // lives in the high byte of n_desc.
    let mut undefs: Vec<usize> = classes
        .par_iter()
        .enumerate()
        .filter(|&(_, &c)| c == Class::Undef)
        .map(|(i, _)| i)
        .collect();
    undefs.par_sort_unstable_by_key(|&i| crate::util::name_sort_key(ctx.symtab[i].name()));

    for &i in &undefs {
        let sym = &ctx.symtab[i];
        let Origin::Dylib(dylib) = sym.origin() else {
            unreachable!()
        };
        let n_strx = 0;
        names.push(sym.name());
        // A flat-namespace import records the DYNAMIC_LOOKUP ordinal.
        let ordinal = (ctx.bind_ordinal(dylib) as u8) as u16;
        let mut n_desc = ordinal << 8;
        if sym.is_weak_ref() {
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
    // Build the string table and assign every entry's n_strx in one
    // parallel pass, the same sharded shape as the symbol table:
    // names bin, each shard deduplicates its bin (first appearance
    // wins) and lays its unique names out as one blob, prefix sums
    // place the blobs, and the entries' offsets follow. Entries with
    // the empty sentinel keep their fixed placeholder offsets (1 is
    // "", 2 is "-").
    //
    // Dedup by pointer, not by string content: hashing 1.1M long
    // mangled names in full was the single most expensive step of a
    // debug link. Global, undefined and private-external names are
    // interned to canonical pointers, so pointer-dedup folds them
    // completely - including the weak-template names that repeat
    // across thousands of objects. Local and stab names instead point
    // into their object's mapped string table, so they dedup within an
    // object but keep one copy per object that defines them; that
    // costs about 1MB of a 154MB string table (still under ld64's),
    // far less than mold-rust, which dedups nothing here at all.
    {
        use rayon::prelude::*;
        debug_assert_eq!(names.len(), data.entries.len());
        // The bin key must (a) send equal names to one shard, so the
        // pointer-dedup inside the shard sees every copy, and (b) be
        // deterministic: a name's string-table offset is its shard's
        // base plus its rank there, so a key that moves one name to
        // another shard shifts every later shard's base and the n_strx
        // of most of the symbol table. Keying by the name's address
        // failed (b): stab strings such as N_OSO paths are heap
        // allocations made in a parallel per-object pass, and their
        // addresses follow thread scheduling, so the output was not
        // reproducible (mold guarantees it is). Key by the entry's
        // symbol id instead: it is assigned deterministically, equal
        // interned names share it (so dedup is unchanged), and reading
        // it touches no name bytes. The few id-less entries (N_SO,
        // N_OSO: one or two per object) hash their name's tail.
        const FIB: u64 = 0x9E37_79B9_7F4A_7C15;
        let hashes: Vec<u64> = names
            .par_iter()
            .zip(data.entries.par_iter())
            .map(|(n, (_, sym))| match sym {
                Some(id) => (*id as u64).wrapping_mul(FIB),
                None => {
                    let b = n.as_bytes();
                    xxhash_rust::xxh3::xxh3_64(&b[b.len().saturating_sub(16)..])
                }
            })
            .collect();
        const NS: usize = 64;
        let mut bins: Vec<Vec<u32>> = vec![Vec::new(); NS];
        for (i, (&h, n)) in hashes.iter().zip(&names).enumerate() {
            if !n.is_empty() {
                bins[(h % NS as u64) as usize].push(i as u32);
            }
        }

        struct ShardOut {
            /// Unique names in first-appearance order, with their
            /// shard-local byte offsets.
            uniq: Vec<(&'static str, u32)>,
            blob_len: u32,
            /// (entry index, shard-local unique index)
            resolved: Vec<(u32, u32)>,
        }
        let names_ref = &names;
        let shard_outs: Vec<ShardOut> = bins
            .into_par_iter()
            .map(|bin| {
                // Keyed by pointer: interned names dedup by identity.
                let mut map: hashbrown::HashMap<*const u8, u32> = hashbrown::HashMap::new();
                let mut uniq: Vec<(&'static str, u32)> = Vec::new();
                let mut blob_len = 0u32;
                let mut resolved = Vec::with_capacity(bin.len());
                for e in bin {
                    let name = names_ref[e as usize];
                    let idx = *map.entry(name.as_ptr()).or_insert_with(|| {
                        let off = blob_len;
                        uniq.push((name, off));
                        blob_len += name.len() as u32 + 1;
                        uniq.len() as u32 - 1
                    });
                    resolved.push((e, idx));
                }
                ShardOut {
                    uniq,
                    blob_len,
                    resolved,
                }
            })
            .collect();

        let mut bases = Vec::with_capacity(NS);
        let mut base = STRTAB_PREFIX as u32;
        for so in &shard_outs {
            bases.push(base);
            base += so.blob_len;
        }

        // Stamp each entry's n_strx in parallel (a name binned to one
        // shard and an entry resolved in one bin make the writes
        // disjoint). The string bytes are NOT materialized here -
        // copy_symtab writes them straight into the output file, so a
        // debug link avoids allocating, filling and then re-copying a
        // 150MB temporary string table.
        struct EntPtr(*mut (NList, Option<crate::symbol::SymbolId>));
        unsafe impl Sync for EntPtr {}
        let ents = EntPtr(data.entries.as_mut_ptr());
        let ents = &ents;
        shard_outs.par_iter().zip(&bases).for_each(|(so, &b)| {
            for &(e, idx) in &so.resolved {
                unsafe {
                    (*ents.0.add(e as usize)).0.n_strx = b + so.uniq[idx as usize].1;
                }
            }
        });

        // Collect the distinct strings with their final offsets for
        // copy_symtab to write.
        data.strtab_uniques = shard_outs
            .par_iter()
            .zip(&bases)
            .flat_map_iter(|(so, &b)| so.uniq.iter().map(move |&(name, off)| (b + off, name)))
            .collect();
        data.strtab_size = align_to(base as u64, 8) as usize;
    }

    // Record each global symbol's index for the indirect symbol table.
    data.output_sym_indices = vec![u32::MAX; ctx.symtab.syms.len()];
    for (i, (_, sym)) in data.entries.iter().enumerate() {
        if let Some(id) = sym {
            if ctx.symtab[*id].is_extern() {
                data.output_sym_indices[*id as usize] = i as u32;
            }
        }
    }
    for (i, &id) in undefs.iter().enumerate() {
        data.output_sym_indices[id] = data.nlocal + data.nextdef + i as u32;
    }

    if std::env::var_os("MOLD_TIMING").is_some() {
        eprintln!("      symtab-globals {:?}", __t.elapsed());
    }

    data
}

pub fn set_osec_offsets<E: Arch>(ctx: &mut Context<E>) {
    let page = E::PAGE_SIZE;
    let mut addr = 0;
    let mut fileoff = 0;
    let mut trie_cache: Option<Vec<u8>> = None;
    let mut unwind_cache: Option<(Vec<u8>, Vec<crate::symbol::SymbolId>)> = None;

    // The chunk list is final once layout begins; resolve the synthetic
    // slot sections once so per-slot address lookups are one index.
    for (i, chunk) in ctx.chunks.iter().enumerate() {
        match chunk.kind {
            ChunkKind::Stubs => ctx.stubs_chunk = i,
            ChunkKind::Got => ctx.got_chunk = i,
            ChunkKind::ThreadPtrs => ctx.thread_ptrs_chunk = i,
            ChunkKind::ObjcStubs => ctx.objc_stubs_chunk = i,
            _ => {}
        }
    }

    // Chunk sizes that are independent of the layout.
    let header_size = mach_header_size(ctx);

    for seg_idx in 0..ctx.segments.len() {
        // Everything the bind stream describes (the GOT, data sections)
        // is laid out by the time we reach __LINKEDIT.
        if ctx.segments[seg_idx].name == "__LINKEDIT" {
            // Every code and data address is final by now.
            // The LINKEDIT tables are independent of one another and
            // every address they read is final (the symbol table needs
            // none at all), so they build as one parallel task group;
            // the chunk loop below just consumes the cached bytes.
            // sold sizes its __LINKEDIT members with the same
            // parallel-for.
            enum Streams {
                Chained(ChainedFixups),
                Classic(Vec<u8>, Vec<u8>),
            }
            let use_chained = ctx.use_chained_fixups();
            let shared = &*ctx;
            // The defined globals, sorted by name, feed both the
            // symbol table and the export trie (identical filters);
            // sort once and share - on a debug link this is hundreds
            // of thousands of long mangled names.
            // The name sort feeds only the symtab and the trie, so it
            // runs inside their arm of the task group and the fixup
            // streams, function starts and data-in-code build under it.
            let sorted_globals_of = || -> Vec<crate::symbol::SymbolId> { t!("globals_sort", {
                use rayon::prelude::*;
                let mut v: Vec<crate::symbol::SymbolId> = (0..shared.symtab.syms.len())
                    .into_par_iter()
                    .filter(|&i| {
                        let sym = &shared.symtab[i];
                        sym.is_extern()
                            && !sym.is_private_extern()
                            && matches!(sym.origin(), Origin::Obj(_) | Origin::Synthetic)
                            && sym.isec().map(|i| i as usize).is_none_or(|isec| {
                                shared.isecs[shared.resolve_isec(isec)].is_alive()
                            })
                    })
                    .map(|i| i as u32)
                    .collect();
                v.par_sort_unstable_by_key(|&i| crate::util::name_sort_key(shared.symtab[i].name()));
                v
            })};
            let ((symtab, trie), (streams, (starts, dice))) = rayon::join(
                || {
                    let sorted_globals = sorted_globals_of();
                    let sorted_globals = &sorted_globals;
                    rayon::join(
                        || t!("symtab", create_output_symtab(shared, sorted_globals)),
                        || {
                            t!(
                                "trie_encode",
                                output_chunks::encode_export_trie(shared, sorted_globals)
                            )
                        },
                    )
                },
                || {
                    rayon::join(
                        || {
                            if use_chained {
                                Streams::Chained(t!(
                                    "chained_fixups",
                                    build_chained_fixups(shared)
                                ))
                            } else {
                                let (rebase, bind) = rayon::join(
                                    || t!("rebase_info", build_rebase_info(shared)),
                                    || t!("bind_info", build_bind_info(shared)),
                                );
                                Streams::Classic(rebase, bind)
                            }
                        },
                        || {
                            rayon::join(
                                || t!("function_starts", build_function_starts(shared)),
                                || t!("data_in_code", build_data_in_code(shared)),
                            )
                        },
                    )
                },
            );
            ctx.symtab_data = symtab;
            ctx.dice_data = dice;
            match streams {
                Streams::Chained(chained) => {
                    (ctx.chained_data, ctx.fixups, ctx.fixup_imports, ctx.fixup_ordinals) =
                        chained;
                }
                Streams::Classic(rebase, bind) => {
                    ctx.rebase_data = rebase;
                    ctx.bind_data = bind;
                }
            }
            ctx.function_starts_data = starts;
            trie_cache = Some(trie);
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

        // The output sections with range-extension thunks (executable
        // sections of __TEXT); their entries' addresses are recorded on
        // the symbols once this segment is placed.
        let thunked: Vec<usize> = chunk_idxs
            .iter()
            .copied()
            .filter(|&i| matches!(&ctx.chunks[i].kind, ChunkKind::Output { thunks, .. } if !thunks.is_empty()))
            .collect();
        // Regular chunks, in file order
        for &idx in &chunk_idxs {
            if ctx.chunks[idx].is_zerofill() {
                continue;
            }
            let size = match &ctx.chunks[idx].kind {
                ChunkKind::MachHeader => header_size,
                ChunkKind::Symtab => {
                    (ctx.symtab_data.entries.len() * size_of::<NList>()) as u64
                }
                ChunkKind::Strtab => ctx.symtab_data.strtab_size as u64,
                // Encoded once; the personality cells the encoding
                // cannot know yet (GOT addresses) come back as a
                // patch list for the copy phase.
                ChunkKind::UnwindInfo => {
                    let (data, personalities) =
                        t!("unwind_encode", output_chunks::encode_unwind_info(ctx));
                    let len = data.len() as u64;
                    unwind_cache = Some((data, personalities));
                    len
                }
                ChunkKind::ChainedFixups => ctx.chained_data.len() as u64,
                ChunkKind::RebaseInfo => ctx.rebase_data.len() as u64,
                ChunkKind::BindInfo => ctx.bind_data.len() as u64,
                // Encoded with the other LINKEDIT tables when layout
                // reached __LINKEDIT, and copied out verbatim later.
                // (__unwind_info above cannot get the same treatment:
                // its content includes personality GOT addresses,
                // which the data segments haven't fixed yet when
                // __TEXT is sized.)
                ChunkKind::ExportTrie => trie_cache.as_ref().unwrap().len() as u64,
                ChunkKind::FunctionStarts => ctx.function_starts_data.len() as u64,
                ChunkKind::DataInCode => (ctx.dice_data.len() * 8) as u64,
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
                | ChunkKind::FunctionStarts | ChunkKind::DataInCode => 3,
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

        if !thunked.is_empty() {
            crate::thunks::gather_thunk_addresses(ctx, &thunked);
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
    ctx.export_trie_data = trie_cache.unwrap_or_default();
    let (unwind_data, unwind_personalities) = unwind_cache.unwrap_or_default();
    ctx.unwind_info_data = unwind_data;
    ctx.unwind_personalities = unwind_personalities;

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
    for isec in ctx.isecs.iter() {
        if !isec.is_alive() || isec.replacement != crate::input_sections::NO_REPLACEMENT {
            continue;
        }
        let base = ctx.chunks[isec.osec as usize].hdr.addr + isec.output_offset as u64;
        for rel in crate::input_files::isec_relocs_of(&ctx.objs, isec) {
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
                .reloc_target_sym(isec.obj as usize, rel)
                .is_some_and(|id| ctx.symtab[id].is_imported());
            if !imported && !ctx.reloc_target_is_tls(isec.obj as usize, rel) {
                locs.push(base + rel.offset as u64);
            }
        }
    }

    // __thread_ptrs slots hold descriptor addresses, which need
    // sliding.
    if let Some(idx) = output_chunks::find_chunk(ctx, |k| matches!(k, ChunkKind::ThreadPtrs)) {
        let addr = ctx.chunks[idx].hdr.addr;
        for (i, &id) in ctx.thread_ptr_syms.iter().enumerate() {
            if !ctx.symtab[id].is_imported() {
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
            if !ctx.symtab[id].is_imported() {
                locs.push(got_addr + i as u64 * 8);
            }
        }
    }

    if locs.is_empty() {
        return Vec::new();
    }
    locs.sort_unstable();

    // Rebase locations cluster (pointer arrays, vtables), and the
    // opcodes have run-length forms for exactly that: a run of
    // adjacent pointers becomes one DO_REBASE_*_TIMES, and since the
    // state machine's address advances past each rebased slot, a gap
    // within a segment costs only an ADD_ADDR_ULEB. ld64 compresses
    // the same way; one SET_SEGMENT per pointer made this stream
    // over 20x larger.
    let mut buf = Vec::new();
    buf.push(REBASE_OPCODE_SET_TYPE_IMM | REBASE_TYPE_POINTER);
    let mut cur: Option<(u8, u64)> = None;
    let mut i = 0;
    while i < locs.len() {
        let (seg, off) = segment_and_offset(ctx, locs[i]);
        match cur {
            Some((cseg, coff)) if cseg == seg as u8 && off >= coff => {
                if off > coff {
                    buf.push(REBASE_OPCODE_ADD_ADDR_ULEB);
                    write_uleb(&mut buf, off - coff);
                }
            }
            _ => {
                buf.push(REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB | seg as u8);
                write_uleb(&mut buf, off);
            }
        }

        // Extend the run over adjacent 8-byte slots.
        let mut n = 1u64;
        while i + (n as usize) < locs.len() && locs[i + n as usize] == locs[i] + n * 8 {
            n += 1;
        }
        if n <= 15 {
            buf.push(REBASE_OPCODE_DO_REBASE_IMM_TIMES | n as u8);
        } else {
            buf.push(REBASE_OPCODE_DO_REBASE_ULEB_TIMES);
            write_uleb(&mut buf, n);
        }
        cur = Some((seg as u8, off + n * 8));
        i += n as usize;
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
            if ctx.symtab[id].is_imported() {
                binds.push((got_addr + i as u64 * 8, id, 0));
            }
        }
    }

    // __thread_ptrs slots for thread-locals imported from dylibs: dyld
    // writes the foreign TLV descriptor's address.
    if let Some(idx) = output_chunks::find_chunk(ctx, |k| matches!(k, ChunkKind::ThreadPtrs)) {
        let addr = ctx.chunks[idx].hdr.addr;
        for (i, &id) in ctx.thread_ptr_syms.iter().enumerate() {
            if ctx.symtab[id].is_imported() {
                binds.push((addr + i as u64 * 8, id, 0));
            }
        }
    }

    // Pointers in data sections initialized with an imported symbol's
    // address.
    for isec in ctx.isecs.iter() {
        if !isec.is_alive() || isec.replacement != crate::input_sections::NO_REPLACEMENT {
            continue;
        }
        let base = ctx.chunks[isec.osec as usize].hdr.addr + isec.output_offset as u64;
        for rel in crate::input_files::isec_relocs_of(&ctx.objs, isec) {
            if E::classify_reloc(rel.r_type) != RelocClass::Plain
                || rel.size != 8
                || rel.is_pcrel
                || rel.is_subtracted
            {
                continue;
            }
            if let Some(id) = ctx.reloc_target_sym(isec.obj as usize, rel) {
                if ctx.symtab[id].is_imported() {
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
        let Origin::Dylib(dylib) = sym.origin() else {
            unreachable!()
        };
        let ordinal = ctx.bind_ordinal(dylib);
        if ordinal < 0 {
            buf.push(BIND_OPCODE_SET_DYLIB_SPECIAL_IMM | (ordinal & 0xf) as u8);
        } else if ordinal < 16 {
            buf.push(BIND_OPCODE_SET_DYLIB_ORDINAL_IMM | ordinal as u8);
        } else {
            buf.push(BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB);
            write_uleb(&mut buf, ordinal as u64);
        }
        let flags = if sym.is_weak_ref() {
            BIND_SYMBOL_FLAGS_WEAK_IMPORT
        } else {
            0
        };
        buf.push(BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM | flags);
        buf.extend_from_slice(sym.name().as_bytes());
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
    use rayon::prelude::*;

    // Every subsection's fixups are independent; collect them on all
    // cores and sort the union in parallel, as mold does.
    let mut fixups: Vec<(u64, Option<crate::symbol::SymbolId>, u64)> = ctx
        .isecs
        .par_iter()
        .filter(|isec| isec.is_alive() && isec.replacement == crate::input_sections::NO_REPLACEMENT)
        .flat_map_iter(|isec| {
            let base = ctx.chunks[isec.osec as usize].hdr.addr + isec.output_offset as u64;
            crate::input_files::isec_relocs_of(&ctx.objs, isec).iter().filter_map(move |rel| {
                if E::classify_reloc(rel.r_type) != RelocClass::Plain
                    || rel.size != 8
                    || rel.is_pcrel
                    || rel.is_subtracted
                {
                    return None;
                }
                let addr = base + rel.offset as u64;
                // A chain link's stride is 4 bytes, so a fixup at an
                // unaligned address is unrepresentable. ld64 diagnoses
                // the offending input section rather than the output.
                if addr % 4 != 0 {
                    fatal!(
                        ctx,
                        "{}({},{}): unaligned base relocation",
                        file_display(&ctx.objs[isec.obj as usize]),
                        ctx.hdr_of(isec).segname(),
                        ctx.hdr_of(isec).sectname()
                    );
                }
                match ctx.reloc_target_sym(isec.obj as usize, rel) {
                    Some(id) if ctx.symtab[id].is_imported() => {
                        Some((addr, Some(id), rel.addend as u64))
                    }
                    _ => {
                        if !ctx.reloc_target_is_tls(isec.obj as usize, rel) {
                            Some((addr, None, 0))
                        } else {
                            None
                        }
                    }
                }
            })
        })
        .collect();

    if let Some(idx) = output_chunks::find_chunk(ctx, |k| matches!(k, ChunkKind::Got)) {
        let addr = ctx.chunks[idx].hdr.addr;
        for (i, &id) in ctx.got_syms.iter().enumerate() {
            let sym = Some(id).filter(|&id| ctx.symtab[id].is_imported());
            fixups.push((addr + i as u64 * 8, sym, 0));
        }
    }
    if let Some(idx) = output_chunks::find_chunk(ctx, |k| matches!(k, ChunkKind::ThreadPtrs)) {
        let addr = ctx.chunks[idx].hdr.addr;
        for (i, &id) in ctx.thread_ptr_syms.iter().enumerate() {
            let sym = Some(id).filter(|&id| ctx.symtab[id].is_imported());
            fixups.push((addr + i as u64 * 8, sym, 0));
        }
    }
    if let Some(idx) = output_chunks::find_chunk(ctx, |k| matches!(k, ChunkKind::ObjcSelrefs)) {
        let addr = ctx.chunks[idx].hdr.addr;
        for i in 0..ctx.objc_stubs.len() {
            fixups.push((addr + i as u64 * 8, None, 0));
        }
    }

    fixups.par_sort_unstable_by_key(|&(addr, _, _)| addr);
    fixups
}

/// Builds the LC_DYLD_CHAINED_FIXUPS payload. Instead of opcode
/// streams, chained fixups store, per page of each segment, the offset
/// of the first fixup; each 64-bit fixup word in the data itself then
/// encodes its target (a rebase value or an import ordinal) plus the
/// distance to the next fixup in the page, forming a chain dyld walks.
/// Builds the chained-fixups payload; returns the encoded bytes, the
/// collected fixups, the import table and the symbol->import ordinal
/// map, for the caller to store on the context.
type ChainedFixups = (
    Vec<u8>,
    Vec<(u64, Option<crate::symbol::SymbolId>, u64)>,
    Vec<(crate::symbol::SymbolId, u64)>,
    std::collections::HashMap<crate::symbol::SymbolId, usize>,
);

fn build_chained_fixups<E: Arch>(ctx: &Context<E>) -> ChainedFixups {
    let fixups = collect_fixups(ctx);
    if fixups.is_empty() {
        return Default::default();
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
            nameoff += ctx.symtab[sym].name().len() as u32 + 1;
        }
    }
    for (i, &(sym, addend)) in dynsyms.iter().enumerate() {
        let s = &ctx.symtab[sym];
        let Origin::Dylib(dylib) = s.origin() else {
            unreachable!()
        };
        let ordinal = ctx.bind_ordinal(dylib) as u8;
        let weak = s.is_weak_ref() as u32;
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
            buf.extend_from_slice(ctx.symtab[sym].name().as_bytes());
            buf.push(0);
        }
    }
    pad8(&mut buf);

    (buf, fixups, dynsyms, ordinals)
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
/// Reads the -order_file lists and ranks every subsection: the
/// subsection defining the file's first symbol gets rank 0 and so on;
/// unlisted subsections rank last. ld64's format is one
/// [arch:][object:]symbol per line with #-comments; the qualifiers
/// narrow a match, which this implementation approximates by
/// matching the bare symbol name.
fn order_file_ranks<E: Arch>(ctx: &Context<E>) -> Option<Vec<u64>> {
    if ctx.args.order_files.is_empty() {
        return None;
    }

    // A line is [arch:][object-file:]symbol. An arch qualifier gates
    // the whole line; an object qualifier narrows the match to
    // symbols from that file (compared by leaf name, as ld64 does).
    const ARCHS: [&str; 6] = ["arm64", "arm64e", "x86_64", "i386", "armv7", "ppc"];
    let mut rank_of: std::collections::HashMap<String, Vec<(Option<String>, u64)>> =
        std::collections::HashMap::new();
    let mut next = 0u64;
    for path in &ctx.args.order_files {
        let Ok(text) = std::fs::read_to_string(path) else {
            fatal!(ctx, "-order_file: cannot read {path}");
        };
        for line in text.lines() {
            let mut line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            if let Some((first, rest)) = line.split_once(':') {
                if ARCHS.contains(&first.trim()) {
                    if first.trim() != E::NAME {
                        continue;
                    }
                    line = rest.trim();
                }
            }
            let (file, name) = match line.split_once(':') {
                Some((file, name)) => (Some(file.trim().to_string()), name.trim()),
                None => (None, line),
            };
            rank_of.entry(name.to_string()).or_default().push((file, next));
            next += 1;
        }
    }

    let mut ranks = vec![u64::MAX; ctx.isecs.len()];
    for sym in &ctx.symtab.syms {
        let Origin::Obj(obj) = sym.origin() else {
            continue;
        };
        let obj = obj as usize;
        let Some(isec) = sym.isec().map(|i| i as usize) else { continue };
        let Some(entries) = rank_of.get(sym.name()) else {
            continue;
        };
        let leaf = ctx.objs[obj].mf.name.rsplit('/').next().unwrap_or("");
        for (file, r) in entries {
            let applies = match file {
                Some(f) => leaf == f || ctx.objs[obj].mf.name.ends_with(f),
                None => true,
            };
            if applies {
                let isec = ctx.resolve_isec(isec as usize);
                ranks[isec] = ranks[isec].min(*r);
            }
        }
    }
    Some(ranks)
}

/// Live data-in-code entries as (subsection, offset within it,
/// length, kind). In an object, an entry's offset is an address in
/// the object's own address space (sections there are laid out from
/// zero), which find_subsec maps to the owning subsection - entries
/// whose subsection was dead-stripped vanish with it.
/// Builds the LC_DATA_IN_CODE entries. Runs when layout reaches
/// __LINKEDIT: the __text file offsets the entries record are final by
/// then, so the table is built exactly once (sold builds its contents
/// in compute_size the same way) and copied out verbatim.
fn build_data_in_code<E: Arch>(ctx: &Context<E>) -> Vec<(u32, u16, u16)> {
    let mut out: Vec<(u32, u16, u16)> = Vec::new();
    for obj in &ctx.objs {
        if !obj.is_alive {
            continue;
        }
        for &(off, len, kind) in &obj.dice {
            let Some((isec, off_in)) =
                crate::input_files::find_subsec(&ctx.isecs, &obj.subsecs, off as u64)
            else {
                continue;
            };
            let isec = &ctx.isecs[ctx.resolve_isec(isec as usize)];
            if isec.is_alive() {
                let fileoff = ctx.chunks[isec.osec as usize].hdr.fileoff + isec.output_offset as u64 + off_in;
                out.push((fileoff as u32, len, kind));
            }
        }
    }
    out.sort_unstable();
    out
}

fn build_function_starts<E: Arch>(ctx: &Context<E>) -> Vec<u8> {
    if !ctx.args.function_starts {
        return Vec::new();
    }
    use rayon::prelude::*;
    let mut addrs: Vec<u64> = ctx
        .symtab
        .syms
        .par_iter()
        .filter_map(|sym| {
            if !matches!(sym.origin(), Origin::Obj(_)) {
                return None;
            }
            let isec = &ctx.isecs[ctx.resolve_isec(sym.isec()? as usize)];
            if isec.is_alive()
                && ctx.hdr_of(isec).segname() == "__TEXT"
                && ctx.hdr_of(isec).sectname() == "__text"
            {
                Some(ctx.chunks[isec.osec as usize].hdr.addr + isec.output_offset as u64 + sym.value)
            } else {
                None
            }
        })
        .collect();
    if addrs.is_empty() {
        return Vec::new();
    }
    addrs.par_sort_unstable();
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
            // Subsections copy and relocate in parallel, as in mold:
            // each occupies a disjoint slice of the output section
            // (relocations only ever write within their own
            // subsection), so the work distributes freely. A pointer
            // wrapper stands in for the aliasing split rayon can't
            // express directly.
            use rayon::prelude::*;
            struct BufPtr(*mut u8);
            unsafe impl Sync for BufPtr {}
            let bufp = BufPtr(buf.as_mut_ptr());
            let bufp = &bufp;
            isecs.par_iter().for_each(|&id| {
                let isec = &ctx.isecs[id];
                if isec.data().is_empty() {
                    return;
                }
                let off = isec.output_offset as usize;
                // SAFETY: subsections' [output_offset, +size) ranges
                // are disjoint by layout, so each iteration touches
                // its own slice.
                let slice = unsafe {
                    std::slice::from_raw_parts_mut(bufp.0.add(off), isec.data().len())
                };
                slice.copy_from_slice(isec.data());
                let base = chunk.hdr.addr + isec.output_offset as u64;
                E::apply_relocs(ctx, ctx.isec_relocs(id as usize), id as usize, base, slice);
            });
        }
        ChunkKind::Stubs => E::write_stubs(ctx, chunk.hdr.addr, buf),
        ChunkKind::Got => {
            // Slots for imported symbols stay zero; dyld fills them
            // via the bind stream.
            for (i, &id) in ctx.got_syms.iter().enumerate() {
                if !ctx.symtab[id].is_imported() {
                    buf[i * 8..i * 8 + 8].copy_from_slice(&ctx.sym_addr(id).to_le_bytes());
                }
            }
        }
        ChunkKind::ThreadPtrs => {
            for (i, &id) in ctx.thread_ptr_syms.iter().enumerate() {
                if !ctx.symtab[id].is_imported() {
                    buf[i * 8..i * 8 + 8].copy_from_slice(&ctx.sym_addr(id).to_le_bytes());
                }
            }
        }
        ChunkKind::ObjcImageInfo => {
            buf[..4].copy_from_slice(&0u32.to_le_bytes());
            buf[4..8].copy_from_slice(&ctx.objc_image_info_flags.to_le_bytes());
        }
        ChunkKind::SectCreate { data } => buf[..data.len()].copy_from_slice(data),
        ChunkKind::InitOffsets => {
            for (i, &(isec, off)) in ctx.init_funcs.iter().enumerate() {
                let val = (ctx.isec_addr(isec) + off - ctx.args.pagezero_size) as u32;
                buf[i * 4..i * 4 + 4].copy_from_slice(&val.to_le_bytes());
            }
        }
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
            let data = &ctx.unwind_info_data;
            debug_assert_eq!(data.len() as u64, chunk.hdr.size);
            buf[..data.len()].copy_from_slice(data);
            // Patch the personality cells now the GOT has addresses.
            let base = ctx.args.pagezero_size;
            for (i, &sym) in ctx.unwind_personalities.iter().enumerate() {
                let off = 28 + i * 4;
                let val = ctx.sym_got_addr(sym).wrapping_sub(base) as u32;
                buf[off..off + 4].copy_from_slice(&val.to_le_bytes());
            }
        }
        ChunkKind::EhFrame => output_chunks::copy_eh_frame(ctx, buf),
        ChunkKind::ChainedFixups => {
            buf[..ctx.chained_data.len()].copy_from_slice(&ctx.chained_data)
        }
        ChunkKind::RebaseInfo => buf[..ctx.rebase_data.len()].copy_from_slice(&ctx.rebase_data),
        ChunkKind::BindInfo => buf[..ctx.bind_data.len()].copy_from_slice(&ctx.bind_data),
        ChunkKind::ExportTrie => {
            let data = &ctx.export_trie_data;
            buf[..data.len()].copy_from_slice(data);
        }
        ChunkKind::FunctionStarts => {
            buf[..ctx.function_starts_data.len()].copy_from_slice(&ctx.function_starts_data);
        }
        ChunkKind::DataInCode => {
            let mut p = 0;
            for &(off, len, kind) in &ctx.dice_data {
                buf[p..p + 4].copy_from_slice(&off.to_le_bytes());
                buf[p + 4..p + 6].copy_from_slice(&len.to_le_bytes());
                buf[p + 6..p + 8].copy_from_slice(&kind.to_le_bytes());
                p += 8;
            }
        }
        ChunkKind::IndirectSymtab => {
            let mut off = 0;
            for &id in ctx.stub_syms.iter().chain(&ctx.got_syms) {
                let val = match ctx.symtab_data.output_sym_indices[id as usize] {
                    u32::MAX => INDIRECT_SYMBOL_LOCAL,
                    idx => idx,
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

    t!("par-copy", slices
        .into_par_iter()
        .for_each(|(idx, slice)| copy_chunk(ctx, &ctx.chunks[idx], slice)));

    if ctx.use_chained_fixups() {
        t!("write-chains", write_fixup_chains(ctx, buf));
    }
    t!("loh", E::apply_optimization_hints(ctx, buf));
    t!("copy_symtab", output_chunks::copy_symtab(ctx, buf));
    output_chunks::copy_mach_header(ctx, buf);

    // The UUID identifies this build: a hash of the output contents,
    // stamped as a version-4 UUID. Hash with the UUID zeroed, then
    // rewrite the header; the code signature comes last and covers the
    // final bytes.
    let sig_start = output_chunks::find_chunk(ctx, |k| {
        matches!(k, ChunkKind::CodeSignature)
    })
    .map_or(buf.len(), |idx| ctx.chunks[idx].hdr.fileoff as usize);

    let __uuid_t = std::time::Instant::now();
    if ctx.args.uuid {
        // A hash of hashes, as in mold: 4MiB blocks are digested on
        // all cores and the digests digested once more. Equally a
        // deterministic content hash, at memory bandwidth instead of
        // one core's SHA throughput.
        use rayon::prelude::*;
        let digests: Vec<[u8; 32]> = buf[..sig_start]
            .par_chunks(4 << 20)
            .map(|block| {
                let mut d = [0; 32];
                crate::util::sha256(block, &mut d);
                d
            })
            .collect();
        let flat: Vec<u8> = digests.concat();
        let mut hash = [0; 32];
        crate::util::sha256(&flat, &mut hash);
        let mut uuid: [u8; 16] = hash[..16].try_into().unwrap();
        uuid[6] = (uuid[6] & 0x0f) | 0x40; // version 4
        uuid[8] = (uuid[8] & 0x3f) | 0x80; // RFC 4122 variant
        *ctx.uuid.lock().unwrap() = uuid;
        output_chunks::copy_mach_header(ctx, buf);
    }
    if std::env::var_os("MOLD_TIMING").is_some() { eprintln!("    uuid {:?}", __uuid_t.elapsed()); }

    if ctx.args.adhoc_codesign {
        t!("codesign", output_chunks::write_code_signature(ctx, buf));
    }
}
