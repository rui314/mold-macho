//! Output chunks: the pieces an output file is assembled from.
//!
//! A chunk is a contiguous byte range of the output: the mach header with
//! its load commands, an output section collecting input sections, or a
//! table in __LINKEDIT. Segments group chunks for the LC_SEGMENT_64 load
//! commands.

use crate::arch::Arch;
use crate::context::Context;
use crate::input_sections::InputSectionId;
use crate::macho::*;
use crate::symbol::SymbolId;
use crate::util::align_to;

#[derive(Debug)]
pub struct ChunkHeader {
    pub segname: &'static str,
    pub sectname: String,
    pub addr: u64,
    pub fileoff: u64,
    pub size: u64,
    pub p2align: u32,
    pub flags: u32,
    pub reserved1: u32,
    pub reserved2: u32,
    /// Whether the chunk is described by a section header in its
    /// segment's load command. Linkedit tables and the mach header are
    /// not.
    pub is_sect: bool,
}

#[derive(Debug)]
pub enum ChunkKind {
    /// The mach header, load commands and header padding.
    MachHeader,
    /// A section of the output image, concatenating input sections.
    Output { isecs: Vec<InputSectionId> },
    /// Jump stubs for calls to imported functions.
    Stubs,
    /// The global offset table: pointers to symbols, bound by dyld for
    /// imported ones.
    Got,
    /// Pointers to thread-local variable descriptors: what a
    /// TLVP-relocated instruction sequence loads from.
    ThreadPtrs,
    /// Linker-synthesized _objc_msgSend$<selector> stubs.
    ObjcStubs,
    /// Selector name strings for the synthesized objc stubs.
    ObjcMethname,
    /// Selector references (pointers into __objc_methname) loaded by the
    /// synthesized objc stubs.
    ObjcSelrefs,
    /// The __TEXT,__unwind_info section, generated from the objects'
    /// compact unwind records.
    UnwindInfo,
    /// The rebase opcode stream for LC_DYLD_INFO, in __LINKEDIT.
    RebaseInfo,
    /// The bind opcode stream for LC_DYLD_INFO, in __LINKEDIT.
    BindInfo,
    /// The export trie in __LINKEDIT: dyld's index of exported symbols.
    ExportTrie,
    /// The indirect symbol table in __LINKEDIT.
    IndirectSymtab,
    /// The symbol table in __LINKEDIT.
    Symtab,
    /// The string table in __LINKEDIT.
    Strtab,
    /// The ad-hoc code signature. Must be the last chunk in the file.
    CodeSignature,
}

#[derive(Debug)]
pub struct Chunk {
    pub hdr: ChunkHeader,
    pub kind: ChunkKind,
}

impl Chunk {
    pub fn new(segname: &'static str, sectname: &str, kind: ChunkKind) -> Chunk {
        Chunk {
            hdr: ChunkHeader {
                segname,
                sectname: sectname.to_string(),
                addr: 0,
                fileoff: 0,
                size: 0,
                p2align: 0,
                flags: 0,
                reserved1: 0,
                reserved2: 0,
                is_sect: matches!(
                    kind,
                    ChunkKind::Output { .. }
                        | ChunkKind::Stubs
                        | ChunkKind::Got
                        | ChunkKind::ThreadPtrs
                        | ChunkKind::ObjcStubs
                        | ChunkKind::ObjcMethname
                        | ChunkKind::ObjcSelrefs
                        | ChunkKind::UnwindInfo
                ),
            },
            kind,
        }
    }

    pub fn is_zerofill(&self) -> bool {
        matches!(
            self.hdr.flags & SECTION_TYPE,
            S_ZEROFILL | S_THREAD_LOCAL_ZEROFILL
        )
    }
}

/// A segment of the output file, grouping chunks.
#[derive(Debug, Default)]
pub struct OutputSegment {
    pub name: &'static str,
    /// Indices into `ctx.chunks`.
    pub chunks: Vec<usize>,
    pub cmd: SegmentCommand,
}

impl OutputSegment {
    pub fn new(name: &'static str) -> OutputSegment {
        OutputSegment {
            name,
            chunks: Vec::new(),
            cmd: SegmentCommand::default(),
        }
    }
}

/// Returns the maxprot/initprot for a well-known segment name.
pub fn segment_prot(name: &str) -> u32 {
    match name {
        "__PAGEZERO" => 0,
        "__TEXT" => VM_PROT_READ | VM_PROT_EXECUTE,
        "__LINKEDIT" => VM_PROT_READ,
        _ => VM_PROT_READ | VM_PROT_WRITE,
    }
}

/// The symbol table contents, laid out before addresses are known. The
/// symbol slot of each entry supplies its final `n_value` when the table
/// is copied to the output.
#[derive(Debug, Default)]
pub struct SymtabData {
    pub entries: Vec<(NList, Option<SymbolId>)>,
    pub strtab: Vec<u8>,
    pub nlocal: u32,
    pub nextdef: u32,
    pub nundef: u32,
    /// The output symbol table index of each global symbol, for the
    /// indirect symbol table.
    pub global_index: std::collections::HashMap<SymbolId, u32>,
}

pub fn find_chunk<E: Arch>(ctx: &Context<E>, f: impl Fn(&ChunkKind) -> bool) -> Option<usize> {
    ctx.chunks.iter().position(|c| f(&c.kind))
}

/// Returns, for each chunk, its 1-based section ordinal in the output, or
/// 0 for chunks that are not sections.
pub fn section_ordinals<E: Arch>(ctx: &Context<E>) -> Vec<u8> {
    let mut ordinals = vec![0; ctx.chunks.len()];
    let mut ord = 1;
    for seg in &ctx.segments {
        for &idx in &seg.chunks {
            if ctx.chunks[idx].hdr.is_sect {
                ordinals[idx] = ord;
                ord += 1;
            }
        }
    }
    ordinals
}

fn to_vec(record: &impl FileRecord) -> Vec<u8> {
    record.as_bytes().to_vec()
}

/// Appends a NUL-terminated string, padding the command to 8 bytes.
fn append_string(buf: &mut Vec<u8>, s: &str) {
    buf.extend_from_slice(s.as_bytes());
    buf.push(0);
    while buf.len() % 8 != 0 {
        buf.push(0);
    }
}

fn create_segment_cmd<E: Arch>(ctx: &Context<E>, seg: &OutputSegment) -> Vec<u8> {
    let mut cmd = seg.cmd;
    cmd.cmd = LC_SEGMENT_64;
    cmd.segname = str_to_name(seg.name);

    let sects: Vec<&Chunk> = seg
        .chunks
        .iter()
        .map(|&i| &ctx.chunks[i])
        .filter(|c| c.hdr.is_sect)
        .collect();

    cmd.nsects = sects.len() as u32;
    cmd.cmdsize = (size_of::<SegmentCommand>() + sects.len() * size_of::<MachSection>()) as u32;
    cmd.maxprot = segment_prot(seg.name);
    cmd.initprot = segment_prot(seg.name);
    // dyld makes __DATA_CONST read-only once binds are applied.
    if seg.name == "__DATA_CONST" {
        cmd.flags = SG_READ_ONLY;
    }

    let mut buf = to_vec(&cmd);
    for chunk in sects {
        let mut sect = MachSection {
            sectname: str_to_name(&chunk.hdr.sectname),
            segname: str_to_name(seg.name),
            addr: chunk.hdr.addr,
            size: chunk.hdr.size,
            offset: chunk.hdr.fileoff as u32,
            p2align: chunk.hdr.p2align,
            flags: chunk.hdr.flags,
            reserved1: chunk.hdr.reserved1,
            reserved2: chunk.hdr.reserved2,
            ..Default::default()
        };
        if chunk.is_zerofill() {
            sect.offset = 0;
        }
        buf.extend_from_slice(sect.as_bytes());
    }
    buf
}

fn create_dyld_info_cmd<E: Arch>(ctx: &Context<E>) -> Vec<u8> {
    let mut cmd = DyldInfoCommand {
        cmd: LC_DYLD_INFO_ONLY,
        cmdsize: size_of::<DyldInfoCommand>() as u32,
        ..Default::default()
    };
    if let Some(idx) = find_chunk(ctx, |k| matches!(k, ChunkKind::RebaseInfo)) {
        if ctx.chunks[idx].hdr.size > 0 {
            cmd.rebase_off = ctx.chunks[idx].hdr.fileoff as u32;
            cmd.rebase_size = ctx.chunks[idx].hdr.size as u32;
        }
    }
    if let Some(idx) = find_chunk(ctx, |k| matches!(k, ChunkKind::BindInfo)) {
        if ctx.chunks[idx].hdr.size > 0 {
            cmd.bind_off = ctx.chunks[idx].hdr.fileoff as u32;
            cmd.bind_size = ctx.chunks[idx].hdr.size as u32;
        }
    }
    if let Some(idx) = find_chunk(ctx, |k| matches!(k, ChunkKind::ExportTrie)) {
        if ctx.chunks[idx].hdr.size > 0 {
            cmd.export_off = ctx.chunks[idx].hdr.fileoff as u32;
            cmd.export_size = ctx.chunks[idx].hdr.size as u32;
        }
    }
    to_vec(&cmd)
}

fn create_symtab_cmd<E: Arch>(ctx: &Context<E>) -> Vec<u8> {
    let symtab = &ctx.chunks[find_chunk(ctx, |k| matches!(k, ChunkKind::Symtab)).unwrap()];
    let strtab = &ctx.chunks[find_chunk(ctx, |k| matches!(k, ChunkKind::Strtab)).unwrap()];

    let cmd = SymtabCommand {
        cmd: LC_SYMTAB,
        cmdsize: size_of::<SymtabCommand>() as u32,
        symoff: symtab.hdr.fileoff as u32,
        nsyms: ctx.symtab_data.entries.len() as u32,
        stroff: strtab.hdr.fileoff as u32,
        strsize: strtab.hdr.size as u32,
    };
    to_vec(&cmd)
}

fn create_dysymtab_cmd<E: Arch>(ctx: &Context<E>) -> Vec<u8> {
    let data = &ctx.symtab_data;
    let mut cmd = DysymtabCommand {
        cmd: LC_DYSYMTAB,
        cmdsize: size_of::<DysymtabCommand>() as u32,
        ilocalsym: 0,
        nlocalsym: data.nlocal,
        iextdefsym: data.nlocal,
        nextdefsym: data.nextdef,
        iundefsym: data.nlocal + data.nextdef,
        nundefsym: data.nundef,
        ..Default::default()
    };
    if let Some(idx) = find_chunk(ctx, |k| matches!(k, ChunkKind::IndirectSymtab)) {
        cmd.indirectsymoff = ctx.chunks[idx].hdr.fileoff as u32;
        cmd.nindirectsyms = (ctx.chunks[idx].hdr.size / 4) as u32;
    }
    to_vec(&cmd)
}

fn create_uuid_cmd<E: Arch>(_ctx: &Context<E>) -> Vec<u8> {
    let cmd = UuidCommand {
        cmd: LC_UUID,
        cmdsize: size_of::<UuidCommand>() as u32,
        uuid: [0; 16],
    };
    to_vec(&cmd)
}

fn create_build_version_cmd<E: Arch>(ctx: &Context<E>) -> Vec<u8> {
    let cmd = BuildVersionCommand {
        cmd: LC_BUILD_VERSION,
        cmdsize: size_of::<BuildVersionCommand>() as u32,
        platform: ctx.args.platform,
        minos: ctx.args.platform_minos,
        sdk: ctx.args.platform_sdk,
        ntools: 0,
    };
    to_vec(&cmd)
}

fn create_source_version_cmd<E: Arch>(_ctx: &Context<E>) -> Vec<u8> {
    let cmd = SourceVersionCommand {
        cmd: LC_SOURCE_VERSION,
        cmdsize: size_of::<SourceVersionCommand>() as u32,
        version: 0,
    };
    to_vec(&cmd)
}

fn create_load_dylib_cmd(dylib: &crate::input_files::DylibFile) -> Vec<u8> {
    let cmd = DylibCommand {
        cmd: LC_LOAD_DYLIB,
        cmdsize: 0,
        nameoff: size_of::<DylibCommand>() as u32,
        timestamp: 2,
        current_version: dylib.current_version,
        compatibility_version: dylib.compatibility_version,
    };
    let mut buf = to_vec(&cmd);
    append_string(&mut buf, &dylib.install_name);
    let size = buf.len() as u32;
    buf[4..8].copy_from_slice(&size.to_le_bytes());
    buf
}

fn create_dylinker_cmd() -> Vec<u8> {
    let cmd = DylinkerCommand {
        cmd: LC_LOAD_DYLINKER,
        cmdsize: 0,
        nameoff: size_of::<DylinkerCommand>() as u32,
    };
    let mut buf = to_vec(&cmd);
    append_string(&mut buf, "/usr/lib/dyld");
    let size = buf.len() as u32;
    buf[4..8].copy_from_slice(&size.to_le_bytes());
    buf
}

fn create_id_dylib_cmd<E: Arch>(ctx: &Context<E>) -> Vec<u8> {
    let name = ctx.args.install_name.as_deref().unwrap_or(&ctx.args.output);
    let cmd = DylibCommand {
        cmd: LC_ID_DYLIB,
        cmdsize: 0,
        nameoff: size_of::<DylibCommand>() as u32,
        timestamp: 0,
        current_version: encode_version(1, 0, 0),
        compatibility_version: encode_version(1, 0, 0),
    };
    let mut buf = to_vec(&cmd);
    append_string(&mut buf, name);
    let size = buf.len() as u32;
    buf[4..8].copy_from_slice(&size.to_le_bytes());
    buf
}

fn create_main_cmd<E: Arch>(ctx: &Context<E>) -> Vec<u8> {
    // The entry point is a file offset into __TEXT, whose file offset
    // is zero.
    let text = ctx.segments.iter().find(|s| s.name == "__TEXT").unwrap();
    let cmd = EntryPointCommand {
        cmd: LC_MAIN,
        cmdsize: size_of::<EntryPointCommand>() as u32,
        entryoff: ctx.entry_addr - text.cmd.vmaddr,
        stacksize: 0,
    };
    to_vec(&cmd)
}

fn create_code_signature_cmd<E: Arch>(ctx: &Context<E>, idx: usize) -> Vec<u8> {
    let chunk = &ctx.chunks[idx];
    let cmd = LinkEditDataCommand {
        cmd: LC_CODE_SIGNATURE,
        cmdsize: size_of::<LinkEditDataCommand>() as u32,
        dataoff: chunk.hdr.fileoff as u32,
        datasize: chunk.hdr.size as u32,
    };
    to_vec(&cmd)
}

pub fn create_load_commands<E: Arch>(ctx: &Context<E>) -> Vec<Vec<u8>> {
    let mut vec = Vec::new();

    for seg in &ctx.segments {
        vec.push(create_segment_cmd(ctx, seg));
    }

    vec.push(create_dyld_info_cmd(ctx));
    vec.push(create_symtab_cmd(ctx));
    vec.push(create_dysymtab_cmd(ctx));
    vec.push(create_uuid_cmd(ctx));
    vec.push(create_build_version_cmd(ctx));
    vec.push(create_source_version_cmd(ctx));

    for dylib in &ctx.dylibs {
        vec.push(create_load_dylib_cmd(dylib));
    }

    match ctx.args.output_type {
        MH_EXECUTE => {
            vec.push(create_dylinker_cmd());
            vec.push(create_main_cmd(ctx));
        }
        MH_DYLIB => vec.push(create_id_dylib_cmd(ctx)),
        _ => {}
    }

    if let Some(idx) = find_chunk(ctx, |k| matches!(k, ChunkKind::CodeSignature)) {
        vec.push(create_code_signature_cmd(ctx, idx));
    }
    vec
}

/// Returns the size of the mach header chunk: the header, the load
/// commands and the header padding.
pub fn mach_header_size<E: Arch>(ctx: &Context<E>) -> u64 {
    let cmds: usize = create_load_commands(ctx).iter().map(Vec::len).sum();
    size_of::<MachHeader>() as u64 + cmds as u64 + ctx.args.headerpad
}

pub fn copy_mach_header<E: Arch>(ctx: &Context<E>, buf: &mut [u8]) {
    let cmds = create_load_commands(ctx);

    let hdr = MachHeader {
        magic: MH_MAGIC_64,
        cputype: E::CPUTYPE,
        cpusubtype: E::CPUSUBTYPE,
        filetype: ctx.args.output_type,
        ncmds: cmds.len() as u32,
        sizeofcmds: cmds.iter().map(Vec::len).sum::<usize>() as u32,
        flags: MH_NOUNDEFS | MH_DYLDLINK | MH_TWOLEVEL,
        reserved: 0,
    };

    let mut hdr = hdr;
    match ctx.args.output_type {
        MH_EXECUTE => hdr.flags |= MH_PIE,
        MH_DYLIB => hdr.flags |= MH_NO_REEXPORTED_DYLIBS,
        _ => {}
    }
    if ctx
        .chunks
        .iter()
        .any(|c| c.hdr.flags & SECTION_TYPE == S_THREAD_LOCAL_VARIABLES)
    {
        hdr.flags |= MH_HAS_TLV_DESCRIPTORS;
    }
    hdr.write_to(buf);

    let mut off = size_of::<MachHeader>();
    for cmd in &cmds {
        buf[off..off + cmd.len()].copy_from_slice(cmd);
        off += cmd.len();
    }
}

pub fn copy_symtab<E: Arch>(ctx: &Context<E>, buf: &mut [u8]) {
    let chunk = &ctx.chunks[find_chunk(ctx, |k| matches!(k, ChunkKind::Symtab)).unwrap()];
    let mut off = chunk.hdr.fileoff as usize;
    for (nlist, sym) in &ctx.symtab_data.entries {
        let mut nlist = *nlist;
        if let Some(id) = sym {
            nlist.n_value = ctx.sym_addr(*id);
        }
        nlist.write_to(&mut buf[off..]);
        off += size_of::<NList>();
    }

    let chunk = &ctx.chunks[find_chunk(ctx, |k| matches!(k, ChunkKind::Strtab)).unwrap()];
    let off = chunk.hdr.fileoff as usize;
    buf[off..off + ctx.symtab_data.strtab.len()].copy_from_slice(&ctx.symtab_data.strtab);
}

/// A node of the export trie under construction.
#[derive(Default)]
struct TrieNode {
    children: Vec<(String, TrieNode)>,
    /// (flags, image-relative address) for an exported symbol ending
    /// here.
    export: Option<(u32, u64)>,
    offset: usize,
}

impl TrieNode {
    fn insert(&mut self, name: &str, export: (u32, u64)) {
        for (label, child) in &mut self.children {
            let common = name
                .bytes()
                .zip(label.bytes())
                .take_while(|(a, b)| a == b)
                .count();
            if common == 0 {
                continue;
            }
            if common < label.len() {
                // Split the edge: "foobar" -> "foo" + "bar".
                let rest = label[common..].to_string();
                *label = label[..common].to_string();
                let old = std::mem::take(child);
                child.children.push((rest, old));
            }
            if common == name.len() {
                child.export = Some(export);
            } else {
                child.insert(&name[common..], export);
            }
            return;
        }
        let mut node = TrieNode::default();
        node.export = Some(export);
        self.children.push((name.to_string(), node));
    }
}

fn uleb_len(mut val: u64) -> usize {
    let mut len = 1;
    while val >= 0x80 {
        val >>= 7;
        len += 1;
    }
    len
}

/// Encodes the export trie: dyld's index of the image's exported
/// symbols. It is a radix tree; each node holds an optional terminal
/// payload (flags and the symbol's image-relative address, both ULEB128)
/// and edges labeled with NUL-terminated string fragments pointing at
/// child nodes by ULEB128 offset within the trie. Since offsets are
/// variable-length, sizing iterates to a fixed point.
pub fn encode_export_trie<E: Arch>(ctx: &Context<E>) -> Vec<u8> {
    let base = ctx.args.pagezero_size;
    let mut root = TrieNode::default();
    let mut any = false;

    for id in 0..ctx.symtab.syms.len() {
        let sym = &ctx.symtab[id];
        if !sym.is_extern
            || !matches!(
                sym.origin,
                crate::symbol::Origin::Obj(_) | crate::symbol::Origin::Synthetic
            )
        {
            continue;
        }
        let flags = if sym.is_weak_def {
            EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION
        } else {
            0
        };
        root.insert(sym.name, (flags, ctx.sym_addr(id) - base));
        any = true;
    }
    if !any {
        return Vec::new();
    }

    // Nodes in pre-order, as raw pointers to sidestep the borrow of the
    // recursive structure.
    fn flatten(node: &mut TrieNode, out: &mut Vec<*mut TrieNode>) {
        out.push(node);
        node.children.sort_by(|a, b| a.0.cmp(&b.0));
        for (_, child) in &mut node.children {
            flatten(child, out);
        }
    }
    let mut nodes = Vec::new();
    flatten(&mut root, &mut nodes);

    // Assign node offsets until they stop moving.
    loop {
        let mut changed = false;
        let mut off = 0;
        for &node in &nodes {
            // SAFETY: the nodes all live in `root`, which outlives this
            // loop, and each is visited once per iteration.
            let node = unsafe { &mut *node };
            if node.offset != off {
                node.offset = off;
                changed = true;
            }
            let terminal_size = match node.export {
                Some((flags, addr)) => uleb_len(flags as u64) + uleb_len(addr),
                None => 0,
            };
            off += uleb_len(terminal_size as u64) + terminal_size + 1;
            for (label, child) in &node.children {
                off += label.len() + 1 + uleb_len(child.offset as u64);
            }
        }
        if !changed {
            break;
        }
    }

    let mut buf = Vec::new();
    for &node in &nodes {
        // SAFETY: as above.
        let node = unsafe { &*node };
        match node.export {
            Some((flags, addr)) => {
                let terminal_size = uleb_len(flags as u64) + uleb_len(addr);
                crate::util::write_uleb(&mut buf, terminal_size as u64);
                crate::util::write_uleb(&mut buf, flags as u64);
                crate::util::write_uleb(&mut buf, addr);
            }
            None => buf.push(0),
        }
        buf.push(node.children.len() as u8);
        for (label, child) in &node.children {
            buf.extend_from_slice(label.as_bytes());
            buf.push(0);
            crate::util::write_uleb(&mut buf, child.offset as u64);
        }
    }
    while buf.len() % 8 != 0 {
        buf.push(0);
    }
    buf
}

/// Encodes the __unwind_info section from the compact unwind records.
///
/// __unwind_info stores unwind records in two-level tables: a first-level
/// table of page entries, each covering up to 2^24 bytes of code, and
/// second-level pages holding 32-bit entries with the function's low
/// address bits and an index into a per-page encoding table.
///
/// This runs twice: once during layout for the section's size (function
/// addresses are final by then, so the size is stable) and once when the
/// output is written, with every referenced address final.
pub fn encode_unwind_info<E: Arch>(ctx: &Context<E>) -> Vec<u8> {
    let mut records = ctx.unwind_records.clone();
    if records.is_empty() {
        return Vec::new();
    }

    let base = ctx.args.pagezero_size;
    let func_addr =
        |r: &crate::input_files::UnwindRecord| ctx.isec_addr(r.isec) + r.input_offset as u64;

    // Assign personality indices, encoded in bits 28-29 of the encoding.
    let mut personalities: Vec<SymbolId> = Vec::new();
    for rec in &mut records {
        if let Some(p) = rec.personality {
            let idx = match personalities.iter().position(|&s| s == p) {
                Some(idx) => idx,
                None => {
                    personalities.push(p);
                    personalities.len() - 1
                }
            };
            if idx >= 3 {
                crate::fatal!(ctx, "too many personality functions");
            }
            rec.encoding |= ((idx + 1) as u32) << UNWIND_PERSONALITY_MASK.trailing_zeros();
        }
    }

    records.sort_by_key(func_addr);

    // Merge adjacent records with identical contents.
    let mut merged: Vec<crate::input_files::UnwindRecord> = Vec::with_capacity(records.len());
    for rec in records {
        match merged.last_mut() {
            Some(last)
                if func_addr(last) + last.code_len as u64 == func_addr(&rec)
                    && last.encoding == rec.encoding
                    && last.personality == rec.personality
                    && last.lsda.is_none()
                    && rec.lsda.is_none() =>
            {
                last.code_len += rec.code_len;
            }
            _ => merged.push(rec),
        }
    }
    let records = merged;

    // Split records into pages: each second-level page covers at most
    // 2^24 bytes of code and holds a bounded number of records.
    const MAX_PAGE_RECORDS: usize = 200;
    let mut pages: Vec<&[crate::input_files::UnwindRecord]> = Vec::new();
    let mut rest = &records[..];
    while !rest.is_empty() {
        let end_addr = func_addr(&rest[0]) + (1 << 24);
        let mut i = 1;
        while i < rest.len() && i < MAX_PAGE_RECORDS && func_addr(&rest[i]) < end_addr {
            i += 1;
        }
        pages.push(&rest[..i]);
        rest = &rest[i..];
    }

    let num_lsda = records.iter().filter(|r| r.lsda.is_some()).count();

    // Compute the layout of the section.
    let personality_off = 28;
    let page1_off = personality_off + personalities.len() * 4;
    let lsda_off = page1_off + (pages.len() + 1) * 12;
    let page2_off = lsda_off + num_lsda * 8;

    let push32 = |buf: &mut Vec<u8>, val: u32| buf.extend_from_slice(&val.to_le_bytes());
    let push16 = |buf: &mut Vec<u8>, val: u16| buf.extend_from_slice(&val.to_le_bytes());

    let mut buf = Vec::new();
    push32(&mut buf, UNWIND_SECTION_VERSION);
    push32(&mut buf, personality_off as u32); // common encodings (none)
    push32(&mut buf, 0);
    push32(&mut buf, personality_off as u32);
    push32(&mut buf, personalities.len() as u32);
    push32(&mut buf, page1_off as u32);
    push32(&mut buf, pages.len() as u32 + 1);

    // Personalities are image-relative pointers to the functions' GOT
    // slots.
    for &sym in &personalities {
        push32(&mut buf, ctx.sym_got_addr(sym).wrapping_sub(base) as u32);
    }

    // First-level pages, second-level pages and the LSDA table are
    // interdependent, so build the second-level pages and the LSDA table
    // in side buffers.
    let mut page1 = Vec::new();
    let mut lsda = Vec::new();
    let mut page2 = Vec::new();

    for span in &pages {
        push32(&mut page1, (func_addr(&span[0]) - base) as u32);
        push32(&mut page1, (page2_off + page2.len()) as u32);
        push32(&mut page1, (lsda_off + lsda.len()) as u32);

        for rec in *span {
            if let Some((isec, off)) = rec.lsda {
                push32(&mut lsda, (func_addr(rec) - base) as u32);
                push32(
                    &mut lsda,
                    (ctx.isec_addr(isec) + off as u64 - base) as u32,
                );
            }
        }

        // The page's encoding table, indexed by the entries.
        let mut encodings: Vec<u32> = Vec::new();
        for rec in *span {
            if !encodings.contains(&rec.encoding) {
                encodings.push(rec.encoding);
            }
        }

        push32(&mut page2, UNWIND_SECOND_LEVEL_COMPRESSED);
        push16(&mut page2, 12); // entries offset within the page
        push16(&mut page2, span.len() as u16);
        push16(&mut page2, (12 + span.len() * 4) as u16); // encodings offset
        push16(&mut page2, encodings.len() as u16);

        let page_base = func_addr(&span[0]);
        for rec in *span {
            let enc_idx = encodings.iter().position(|&e| e == rec.encoding).unwrap();
            let entry = (func_addr(rec) - page_base) as u32 | (enc_idx as u32) << 24;
            push32(&mut page2, entry);
        }
        for enc in &encodings {
            push32(&mut page2, *enc);
        }
    }

    // The terminating first-level entry.
    let last = records.last().unwrap();
    push32(&mut page1, (func_addr(last) + last.code_len as u64 + 1 - base) as u32);
    push32(&mut page1, 0);
    push32(&mut page1, (lsda_off + lsda.len()) as u32);

    buf.extend_from_slice(&page1);
    buf.extend_from_slice(&lsda);
    buf.extend_from_slice(&page2);
    buf
}

/// Returns the size of the code signature given the file offset it will
/// be placed at.
pub fn code_signature_size(output: &str, fileoff: u64) -> u64 {
    let ident_size = align_to(file_basename(output).len() as u64 + 1, 16);
    let nblocks = fileoff.div_ceil(CS_PAGE_SIZE);
    // Superblob header, one blob index, the code directory, the
    // identifier and the page hashes.
    12 + 8 + 88 + ident_size + nblocks * SHA256_SIZE as u64
}

fn file_basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap()
}

fn push_be32(buf: &mut Vec<u8>, val: u32) {
    buf.extend_from_slice(&val.to_be_bytes());
}

fn push_be64(buf: &mut Vec<u8>, val: u64) {
    buf.extend_from_slice(&val.to_be_bytes());
}

/// Computes the ad-hoc code signature over the file contents and writes
/// it at the code signature chunk's offset.
///
/// On ARM64 macOS a code signature is mandatory: the kernel refuses to
/// run an executable without one. The signature we create is just SHA256
/// hashes of every page, marked ad-hoc and linker-signed; no signing
/// identity is involved.
pub fn write_code_signature<E: Arch>(ctx: &Context<E>, buf: &mut [u8]) {
    let chunk = &ctx.chunks[find_chunk(ctx, |k| matches!(k, ChunkKind::CodeSignature)).unwrap()];
    let cs_off = chunk.hdr.fileoff;
    let ident = file_basename(&ctx.args.output);
    let ident_size = align_to(ident.len() as u64 + 1, 16);
    let nblocks = cs_off.div_ceil(CS_PAGE_SIZE);
    let cd_size = 88 + ident_size + nblocks * SHA256_SIZE as u64;

    let text = ctx.segments.iter().find(|s| s.name == "__TEXT").unwrap();

    // All code signature fields are big-endian.
    let mut sig = Vec::with_capacity(chunk.hdr.size as usize);

    // The superblob header and the index of its single blob, the code
    // directory.
    push_be32(&mut sig, CSMAGIC_EMBEDDED_SIGNATURE);
    push_be32(&mut sig, chunk.hdr.size as u32);
    push_be32(&mut sig, 1);
    push_be32(&mut sig, CSSLOT_CODEDIRECTORY);
    push_be32(&mut sig, 20);

    // The code directory.
    push_be32(&mut sig, CSMAGIC_CODEDIRECTORY);
    push_be32(&mut sig, cd_size as u32);
    push_be32(&mut sig, CS_SUPPORTSEXECSEG); // version
    push_be32(&mut sig, CS_ADHOC | CS_LINKER_SIGNED); // flags
    push_be32(&mut sig, (88 + ident_size) as u32); // hash offset
    push_be32(&mut sig, 88); // identifier offset
    push_be32(&mut sig, 0); // special slots
    push_be32(&mut sig, nblocks as u32); // code slots
    push_be32(&mut sig, cs_off as u32); // code limit
    sig.push(SHA256_SIZE as u8);
    sig.push(CS_HASHTYPE_SHA256);
    sig.push(0); // platform
    sig.push(CS_PAGE_SIZE.trailing_zeros() as u8);
    push_be32(&mut sig, 0); // spare2
    push_be32(&mut sig, 0); // scatter offset
    push_be32(&mut sig, 0); // team offset
    push_be32(&mut sig, 0); // spare3
    push_be64(&mut sig, 0); // code limit 64
    push_be64(&mut sig, text.cmd.fileoff); // exec segment base
    push_be64(&mut sig, text.cmd.filesize); // exec segment limit
    let exec_seg_flags = if ctx.args.output_type == MH_EXECUTE {
        CS_EXECSEG_MAIN_BINARY
    } else {
        0
    };
    push_be64(&mut sig, exec_seg_flags); // exec segment flags

    sig.extend_from_slice(ident.as_bytes());
    sig.resize(sig.len() + ident_size as usize - ident.len(), 0);

    // Hash each page of the file up to the signature itself.
    for i in 0..nblocks {
        let start = (i * CS_PAGE_SIZE) as usize;
        let end = std::cmp::min(start + CS_PAGE_SIZE as usize, cs_off as usize);
        let mut hash = [0; SHA256_SIZE];
        crate::util::sha256(&buf[start..end], &mut hash);
        sig.extend_from_slice(&hash);
    }

    debug_assert_eq!(sig.len() as u64, chunk.hdr.size);
    buf[cs_off as usize..cs_off as usize + sig.len()].copy_from_slice(&sig);
}
