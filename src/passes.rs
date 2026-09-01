//! The linker passes, in the order the driver runs them.

use std::path::{Path, PathBuf};

use crate::arch::Arch;
use crate::cmdline::InputArg;
use crate::context::Context;
use crate::error;
use crate::fatal;
use crate::filetype::{get_file_type, FileType};
use crate::input_files;
use crate::macho::*;
use crate::mapped_file::MappedFile;
use crate::output_chunks::{
    self, Chunk, ChunkKind, OutputSegment, code_signature_size, mach_header_size,
    section_ordinals,
};
use crate::symbol::Origin;
use crate::util::align_to;

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

fn read_file<E: Arch>(ctx: &mut Context<E>, mf: &'static MappedFile) {
    match get_file_type(mf) {
        FileType::Object => {
            input_files::parse_object(ctx, mf);
        }
        FileType::Tapi => {
            input_files::parse_dylib(ctx, mf);
        }
        FileType::Archive => {
            // Archive members are loaded lazily to resolve undefined
            // symbols. Not implemented yet; an unresolved symbol that a
            // member would satisfy is reported as undefined.
        }
        FileType::Fat => {
            let slice = input_files::get_fat_slice(ctx, mf);
            read_file(ctx, slice);
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
                read_file(ctx, mf);
            }
            InputArg::Lib(name) => match find_library(ctx, name) {
                Some(path) => {
                    let mf = MappedFile::must_open(&ctx.diag, &path);
                    read_file(ctx, mf);
                }
                None => error!(ctx, "library not found: -l{name}"),
            },
        }
    }
    ctx.args.inputs = inputs;
}

/// Defines the symbols the linker itself provides.
pub fn create_synthetic_symbols<E: Arch>(ctx: &mut Context<E>) {
    let id = ctx.symtab.intern("__mh_execute_header");
    let sym = &mut ctx.symtab[id];
    if !sym.is_defined() {
        sym.origin = Origin::Synthetic;
        sym.value = ctx.args.pagezero_size;
        sym.is_extern = true;
    }
}

/// Well-known section names are ordered the way ld64 orders them; unknown
/// sections come after, in input order.
fn output_section_rank(segname: &str, sectname: &str) -> u32 {
    match (segname, sectname) {
        ("__TEXT", "__text") => 0,
        ("__TEXT", _) => 1,
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
            off += isec.hdr.size;
        }
        chunk.hdr.size = off;
    }

    ctx.chunks.push(Chunk::new("__LINKEDIT", "", ChunkKind::Symtab));
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
            if !matches!(sym.origin, Origin::Obj(_)) {
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
    data.nlocal = data.entries.len() as u32;

    // Defined global symbols, sorted by name
    let mut globals: Vec<usize> = (0..ctx.symtab.syms.len())
        .filter(|&i| {
            let sym = &ctx.symtab[i];
            sym.is_extern && sym.is_defined()
        })
        .collect();
    globals.sort_by_key(|&i| ctx.symtab[i].name);

    for &i in &globals {
        let sym = &ctx.symtab[i];
        let n_strx = add_string(&mut data.strtab, sym.name);
        let (n_type, n_sect, n_desc) = match (sym.origin, sym.isec) {
            (Origin::Synthetic, _) => (N_SECT | N_EXT, 1, REFERENCED_DYNAMICALLY),
            (_, Some(isec)) => (N_SECT | N_EXT, ordinals[ctx.isecs[isec].osec], 0),
            (_, None) => (N_ABS | N_EXT, 0, 0),
        };
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
    data.nundef = 0;

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
                ChunkKind::Output { .. } => ctx.chunks[idx].hdr.size,
                ChunkKind::Symtab => symtab_size,
                ChunkKind::Strtab => strtab_size,
                ChunkKind::CodeSignature => {
                    cursor = align_to(cursor, 16);
                    code_signature_size(&ctx.args.output, cursor)
                }
            };
            let chunk = &mut ctx.chunks[idx];
            let p2align = match chunk.kind {
                ChunkKind::Symtab | ChunkKind::Strtab => 3,
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
}

/// Resolves the entry point symbol.
pub fn resolve_entry<E: Arch>(ctx: &mut Context<E>) {
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
            ChunkKind::Symtab => output_chunks::copy_symtab(ctx, buf),
            ChunkKind::MachHeader | ChunkKind::Strtab | ChunkKind::CodeSignature => {}
        }
    }

    output_chunks::copy_mach_header(ctx, buf);

    if ctx.args.adhoc_codesign {
        output_chunks::write_code_signature(ctx, buf);
    }
}
