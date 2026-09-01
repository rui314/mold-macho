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

fn read_file<E: Arch>(ctx: &mut Context<E>, mf: &'static MappedFile, force_load: bool, weak: bool) {
    match get_file_type(mf) {
        FileType::Object => {
            input_files::parse_object(ctx, mf);
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
            // Archive members are normally loaded lazily: a member is
            // linked only once it defines a symbol that is undefined at
            // resolution time. -all_load and -force_load link every
            // member; -ObjC also links members with Objective-C
            // metadata, which register classes by their mere presence.
            let members = input_files::read_archive_members(ctx, mf);
            for member in members {
                if force_load
                    || ctx.args.all_load
                    || (ctx.args.load_objc && input_files::has_objc_sections(member))
                {
                    input_files::parse_object(ctx, member);
                } else {
                    ctx.lazy_objs.push(member);
                }
            }
        }
        FileType::Fat => {
            let slice = input_files::get_fat_slice(ctx, mf);
            read_file(ctx, slice, force_load, weak);
        }
        FileType::Empty => {}
        _ => fatal!(ctx, "{}: unknown file type", mf.name),
    }
}

pub fn read_input_files<E: Arch>(ctx: &mut Context<E>) {
    let inputs = std::mem::take(&mut ctx.args.inputs);
    for arg in &inputs {
        match arg {
            InputArg::File(path) => {
                let mf = MappedFile::must_open(&ctx.diag, Path::new(path));
                read_file(ctx, mf, false, false);
            }
            InputArg::ForceLoad(path) => {
                let mf = MappedFile::must_open(&ctx.diag, Path::new(path));
                read_file(ctx, mf, true, false);
            }
            InputArg::WeakFile(path) => {
                let mf = MappedFile::must_open(&ctx.diag, Path::new(path));
                read_file(ctx, mf, false, true);
            }
            InputArg::Lib(name, weak) => match find_library(ctx, name) {
                Some(path) => {
                    let mf = MappedFile::must_open(&ctx.diag, &path);
                    read_file(ctx, mf, false, *weak);
                }
                None => error!(ctx, "library not found: -l{name}"),
            },
            InputArg::Framework(name, weak) => match find_framework(ctx, name) {
                Some(path) => {
                    let mf = MappedFile::must_open(&ctx.diag, &path);
                    read_file(ctx, mf, false, *weak);
                }
                None => error!(ctx, "framework not found: {name}"),
            },
        }
    }
    ctx.args.inputs = inputs;
}

/// Loads archive members that define symbols still undefined, until no
/// member is needed anymore. A loaded member may itself use symbols that
/// another member defines, so this iterates to a fixed point.
pub fn resolve_archive_members<E: Arch>(ctx: &mut Context<E>) {
    // -u symbols count as undefined references from the start.
    let forced = std::mem::take(&mut ctx.args.forced_undefined);
    for name in &forced {
        let name: &'static str = String::leak(name.clone());
        let id = ctx.symtab.intern(name);
        ctx.symtab[id].is_used = true;
    }
    ctx.args.forced_undefined = forced;

    loop {
        let undefined: std::collections::HashSet<&str> = ctx
            .symtab
            .syms
            .iter()
            .filter(|sym| sym.is_used && !sym.is_defined() && !sym.is_common)
            .map(|sym| sym.name)
            .collect();
        if undefined.is_empty() {
            return;
        }

        let needed = ctx.lazy_objs.iter().position(|mf| {
            input_files::defined_symbol_names(mf)
                .iter()
                .any(|name| undefined.contains(name))
        });
        match needed {
            Some(idx) => {
                let mf = ctx.lazy_objs.remove(idx);
                input_files::parse_object(ctx, mf);
            }
            None => return,
        }
    }
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

/// Resolves symbols that no object file defines against the dylibs, in
/// command line order.
pub fn resolve_dylib_symbols<E: Arch>(ctx: &mut Context<E>) {
    for i in 0..ctx.symtab.syms.len() {
        let sym = &ctx.symtab[i];
        if sym.is_defined() || !sym.is_used {
            continue;
        }
        let name = sym.name;
        if let Some(dylib) = ctx.dylibs.iter().position(|d| d.exports.contains(name)) {
            let sym = &mut ctx.symtab[i];
            sym.origin = Origin::Dylib(dylib);
            sym.is_imported = true;
            sym.is_extern = true;
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

/// Reports references to symbols that are still unresolved.
pub fn check_undefined_symbols<E: Arch>(ctx: &Context<E>) {
    for sym in &ctx.symtab.syms {
        if sym.is_used && !sym.is_defined() {
            error!(ctx, "undefined symbol: {}", sym.name);
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

    // Section-level roots
    for (id, isec) in ctx.isecs.iter().enumerate() {
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
        isec.is_alive = live[id];
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

/// Well-known section names are ordered the way ld64 orders them; unknown
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
                let mut chunk = Chunk::new(segname, &sectname, ChunkKind::Output { isecs: vec![] });
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
        let ChunkKind::Output { isecs } = &mut chunk.kind else {
            unreachable!()
        };
        isecs.push(i);
        ctx.isecs[i].osec = chunk_idx;
    }

    // Compute each input section's offset within its output section.
    for chunk in &mut ctx.chunks {
        let ChunkKind::Output { isecs } = &chunk.kind else {
            continue;
        };
        let mut off = 0;
        for &id in isecs {
            let isec = &mut ctx.isecs[id];
            off = align_to(off, 1 << isec.hdr.p2align);
            isec.output_offset = off;
            off += isec.size;
        }
        chunk.hdr.size = off;
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

    // Merge the objects' __objc_imageinfo records: the Swift version
    // must agree, the Swift language version is the newest, and the
    // category-class-properties bit holds only if every Objective-C
    // object has it.
    let infos: Vec<u32> = ctx.objs.iter().filter_map(|o| o.objc_image_info).collect();
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
    data.strtab = vec![b' ', 0];

    let add_string = |strtab: &mut Vec<u8>, s: &str| -> u32 {
        let off = strtab.len() as u32;
        strtab.extend_from_slice(s.as_bytes());
        strtab.push(0);
        off
    };

    // Local symbols
    for obj in &ctx.objs {
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
        let mut n_desc = (ctx.dylibs[dylib].dylib_idx as u16) << 8;
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
            ctx.rebase_data = build_rebase_info(ctx);
            ctx.bind_data = build_bind_info(ctx);
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
                | ChunkKind::BindInfo | ChunkKind::ExportTrie
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
        let ordinal = ctx.dylibs[dylib].dylib_idx;
        if ordinal < 16 {
            buf.push(BIND_OPCODE_SET_DYLIB_ORDINAL_IMM | ordinal as u8);
        } else {
            buf.push(BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB);
            write_uleb(&mut buf, ordinal as u64);
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

/// Builds the LC_FUNCTION_STARTS payload: the addresses of all
/// functions in __TEXT,__text, ULEB128 delta-encoded starting from the
/// image base. Debuggers and crash reporters use it to attribute
/// addresses to functions even for stripped binaries.
fn build_function_starts<E: Arch>(ctx: &Context<E>) -> Vec<u8> {
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
pub fn copy_chunks<E: Arch>(ctx: &Context<E>, buf: &mut [u8]) {
    for chunk in &ctx.chunks {
        match &chunk.kind {
            ChunkKind::Output { isecs } => {
                for &id in isecs {
                    let isec = &ctx.isecs[id];
                    if isec.data.is_empty() {
                        continue;
                    }
                    let off = (chunk.hdr.fileoff + isec.output_offset) as usize;
                    let end = off + isec.data.len();
                    buf[off..end].copy_from_slice(isec.data);
                    let base = chunk.hdr.addr + isec.output_offset;
                    E::apply_relocs(ctx, &isec.relocs, isec.obj, base, &mut buf[off..end]);
                }
            }
            ChunkKind::Stubs => {
                let off = chunk.hdr.fileoff as usize;
                let end = off + chunk.hdr.size as usize;
                E::write_stubs(ctx, chunk.hdr.addr, &mut buf[off..end]);
            }
            ChunkKind::Got => {
                // Slots for imported symbols stay zero; dyld fills them
                // via the bind stream.
                for (i, &id) in ctx.got_syms.iter().enumerate() {
                    if !ctx.symtab[id].is_imported {
                        let off = chunk.hdr.fileoff as usize + i * 8;
                        buf[off..off + 8].copy_from_slice(&ctx.sym_addr(id).to_le_bytes());
                    }
                }
            }
            ChunkKind::ThreadPtrs => {
                for (i, &id) in ctx.thread_ptr_syms.iter().enumerate() {
                    if !ctx.symtab[id].is_imported {
                        let off = chunk.hdr.fileoff as usize + i * 8;
                        buf[off..off + 8].copy_from_slice(&ctx.sym_addr(id).to_le_bytes());
                    }
                }
            }
            ChunkKind::ObjcImageInfo => {
                let off = chunk.hdr.fileoff as usize;
                buf[off..off + 4].copy_from_slice(&0u32.to_le_bytes());
                buf[off + 4..off + 8]
                    .copy_from_slice(&ctx.objc_image_info_flags.to_le_bytes());
            }
            ChunkKind::ObjcStubs => {
                let off = chunk.hdr.fileoff as usize;
                let end = off + chunk.hdr.size as usize;
                E::write_objc_stubs(ctx, chunk.hdr.addr, &mut buf[off..end]);
            }
            ChunkKind::ObjcMethname => {
                let off = chunk.hdr.fileoff as usize;
                buf[off..off + ctx.objc_methname_data.len()]
                    .copy_from_slice(&ctx.objc_methname_data);
            }
            ChunkKind::ObjcSelrefs => {
                let methname = output_chunks::find_chunk(ctx, |k| {
                    matches!(k, ChunkKind::ObjcMethname)
                })
                .unwrap();
                let methname_addr = ctx.chunks[methname].hdr.addr;
                for (i, &sel_off) in ctx.objc_methname_offs.iter().enumerate() {
                    let off = chunk.hdr.fileoff as usize + i * 8;
                    let val = methname_addr + sel_off;
                    buf[off..off + 8].copy_from_slice(&val.to_le_bytes());
                }
            }
            ChunkKind::UnwindInfo => {
                let data = output_chunks::encode_unwind_info(ctx);
                debug_assert_eq!(data.len() as u64, chunk.hdr.size);
                let off = chunk.hdr.fileoff as usize;
                buf[off..off + data.len()].copy_from_slice(&data);
            }
            ChunkKind::EhFrame => output_chunks::copy_eh_frame(ctx, buf),
            ChunkKind::RebaseInfo => {
                let off = chunk.hdr.fileoff as usize;
                buf[off..off + ctx.rebase_data.len()].copy_from_slice(&ctx.rebase_data);
            }
            ChunkKind::BindInfo => {
                let off = chunk.hdr.fileoff as usize;
                buf[off..off + ctx.bind_data.len()].copy_from_slice(&ctx.bind_data);
            }
            ChunkKind::ExportTrie => {
                let data = output_chunks::encode_export_trie(ctx);
                let off = chunk.hdr.fileoff as usize;
                buf[off..off + data.len()].copy_from_slice(&data);
            }
            ChunkKind::FunctionStarts => {
                let off = chunk.hdr.fileoff as usize;
                buf[off..off + ctx.function_starts_data.len()]
                    .copy_from_slice(&ctx.function_starts_data);
            }
            ChunkKind::IndirectSymtab => {
                let mut off = chunk.hdr.fileoff as usize;
                for &id in ctx.stub_syms.iter().chain(&ctx.got_syms) {
                    let val = match ctx.symtab_data.global_index.get(&id) {
                        Some(&idx) => idx,
                        None => INDIRECT_SYMBOL_LOCAL,
                    };
                    buf[off..off + 4].copy_from_slice(&val.to_le_bytes());
                    off += 4;
                }
            }
            ChunkKind::Symtab => output_chunks::copy_symtab(ctx, buf),
            ChunkKind::MachHeader | ChunkKind::Strtab | ChunkKind::CodeSignature => {}
        }
    }

    output_chunks::copy_mach_header(ctx, buf);

    // The UUID identifies this build: a hash of the output contents,
    // stamped as a version-4 UUID. Hash with the UUID zeroed, then
    // rewrite the header; the code signature comes last and covers the
    // final bytes.
    let sig_start = output_chunks::find_chunk(ctx, |k| {
        matches!(k, ChunkKind::CodeSignature)
    })
    .map_or(buf.len(), |idx| ctx.chunks[idx].hdr.fileoff as usize);

    let mut hash = [0; 32];
    crate::util::sha256(&buf[..sig_start], &mut hash);
    let mut uuid: [u8; 16] = hash[..16].try_into().unwrap();
    uuid[6] = (uuid[6] & 0x0f) | 0x40; // version 4
    uuid[8] = (uuid[8] & 0x3f) | 0x80; // RFC 4122 variant
    *ctx.uuid.lock().unwrap() = uuid;
    output_chunks::copy_mach_header(ctx, buf);

    if ctx.args.adhoc_codesign {
        output_chunks::write_code_signature(ctx, buf);
    }
}
