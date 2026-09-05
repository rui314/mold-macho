//! Output chunks: the pieces an output file is assembled from.
//!
//! A chunk is a contiguous byte range of the output: the mach header with
//! its load commands, an output section collecting input sections, or a
//! table in __LINKEDIT. Each kind is a struct of its own holding a
//! ChunkHeader and the data it is written from, reached through the
//! typed fields of Context; a ChunkId names one, and `ctx.chunks` lists
//! the chunks of the output in file order. Segments group chunks for
//! the LC_SEGMENT_64 load commands. mold-rust's output_chunks has the
//! same shape.

pub mod chained_fixups;
pub mod dyld_info;
pub mod eh_frame;
pub mod export_trie;
pub mod got;
pub mod misc;
pub mod objc;
pub mod output_section;
pub mod symtab;
pub mod unwind_info;

use std::num::NonZeroU32;

use crate::arch::Arch;
use crate::context::Context;
use crate::macho::*;
use crate::symbol::{Origin, SymbolId};

pub use output_section::{OutputSection, Tail, Thunk};

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
    /// The 1-based ordinal of the section among the output's sections
    /// (what an nlist's n_sect holds), 0 for a chunk that is not a
    /// section; mold-rust's shndx.
    pub n_sect: u8,
}

impl ChunkHeader {
    /// The header of a section of the image.
    pub fn new(segname: &'static str, sectname: &str) -> ChunkHeader {
        ChunkHeader {
            segname,
            sectname: sectname.to_string(),
            addr: 0,
            fileoff: 0,
            size: 0,
            p2align: 0,
            flags: 0,
            reserved1: 0,
            reserved2: 0,
            is_sect: true,
            n_sect: 0,
        }
    }

    /// The header of a __LINKEDIT table, which no section header
    /// describes.
    pub fn linkedit() -> ChunkHeader {
        let mut hdr = ChunkHeader::new("__LINKEDIT", "");
        hdr.is_sect = false;
        hdr
    }

    pub fn is_zerofill(&self) -> bool {
        matches!(self.flags & SECTION_TYPE, S_ZEROFILL | S_THREAD_LOCAL_ZEROFILL)
    }
}

/// Index of an output section in `Context::output_sections`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct OutputSectionId(NonZeroU32);

impl OutputSectionId {
    #[inline]
    pub fn new(index: u32) -> OutputSectionId {
        let encoded = index.checked_add(1).expect("too many output sections");
        OutputSectionId(NonZeroU32::new(encoded).unwrap())
    }

    #[inline]
    pub fn index(self) -> usize {
        (self.0.get() - 1) as usize
    }
}

/// Names a chunk of the output. Every kind but the output sections and
/// the -sectcreate sections exists at most once, so the kind alone
/// names it; `Context::chunk_header` reaches any chunk's header, and
/// the typed Context field its data.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ChunkId {
    /// The mach header, load commands and header padding.
    MachHeader,
    /// A section of the output image, concatenating input sections.
    Output(OutputSectionId),
    Stubs,
    StubHelper,
    LazyPtrs,
    Got,
    ThreadPtrs,
    ObjcStubs,
    ObjcMethlist,
    ObjcImageInfo,
    /// A section created from a file by -sectcreate (or empty, for
    /// -add_empty_section): an index into `Context::sectcreate_sections`.
    SectCreate(u32),
    InitOffsets,
    UnwindInfo,
    EhFrame,
    RebaseInfo,
    BindInfo,
    WeakBindInfo,
    LazyBindInfo,
    ChainedFixups,
    ExportTrie,
    FunctionStarts,
    DataInCode,
    IndirectSymtab,
    Symtab,
    Strtab,
    /// Must be the last chunk in the file.
    CodeSignature,
}

impl ChunkId {
    /// The chunks that exist at most once, in the order `pack` numbers
    /// them.
    const UNITS: [ChunkId; 24] = [
        ChunkId::MachHeader,
        ChunkId::Stubs,
        ChunkId::StubHelper,
        ChunkId::LazyPtrs,
        ChunkId::Got,
        ChunkId::ThreadPtrs,
        ChunkId::ObjcStubs,
        ChunkId::ObjcMethlist,
        ChunkId::ObjcImageInfo,
        ChunkId::InitOffsets,
        ChunkId::UnwindInfo,
        ChunkId::EhFrame,
        ChunkId::RebaseInfo,
        ChunkId::BindInfo,
        ChunkId::WeakBindInfo,
        ChunkId::LazyBindInfo,
        ChunkId::ChainedFixups,
        ChunkId::ExportTrie,
        ChunkId::FunctionStarts,
        ChunkId::DataInCode,
        ChunkId::IndirectSymtab,
        ChunkId::Symtab,
        ChunkId::Strtab,
        ChunkId::CodeSignature,
    ];

    /// The id as one u32 (never u32::MAX), for InputSection, whose
    /// size counts: the top two bits say which of the three shapes it
    /// is, the rest holds the index. mold-rust's InputSection stores an
    /// Option<OutputSectionId>, a word too, since an ELF subsection
    /// only ever lands in an output section; a Mach-O subsection may
    /// also stand for a GOT slot or a rewritten method list.
    pub fn pack(self) -> u32 {
        match self {
            ChunkId::Output(id) => {
                let i = id.index() as u32;
                assert!(i < 1 << 30, "too many output sections");
                i
            }
            ChunkId::SectCreate(i) => (1 << 30) | i,
            _ => (2 << 30) | ChunkId::UNITS.iter().position(|&c| c == self).unwrap() as u32,
        }
    }

    #[inline]
    pub fn unpack(v: u32) -> ChunkId {
        let i = v & ((1 << 30) - 1);
        match v >> 30 {
            0 => ChunkId::Output(OutputSectionId::new(i)),
            1 => ChunkId::SectCreate(i),
            _ => ChunkId::UNITS[i as usize],
        }
    }
}

/// The mach header, load commands and header padding: the first
/// chunk of __TEXT.
#[derive(Debug)]
pub struct OutputMachHeader {
    pub hdr: ChunkHeader,
}

impl OutputMachHeader {
    pub fn new() -> OutputMachHeader {
        let mut hdr = ChunkHeader::new("__TEXT", "");
        hdr.is_sect = false;
        OutputMachHeader { hdr }
    }
}

/// A segment of the output file, grouping chunks.
#[derive(Debug, Default)]
pub struct OutputSegment {
    pub name: &'static str,
    pub chunks: Vec<ChunkId>,
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

/// Writes a chunk's bytes into its own slice of the output. The mach
/// header, the symbol and string tables and the code signature are
/// written serially after the parallel copy (see copy_chunks), so they
/// have nothing to do here.
pub fn copy_buf<E: Arch>(ctx: &Context<E>, id: ChunkId, buf: &mut [u8]) {
    match id {
        ChunkId::MachHeader | ChunkId::Symtab | ChunkId::Strtab | ChunkId::CodeSignature => {}
        ChunkId::Output(id) => output_section::copy_buf(ctx, id, buf),
        ChunkId::Stubs => got::stubs::copy_buf(ctx, buf),
        ChunkId::StubHelper => got::stub_helper::copy_buf(ctx, buf),
        ChunkId::LazyPtrs => got::lazy_ptrs::copy_buf(ctx, buf),
        ChunkId::Got => got::got::copy_buf(ctx, buf),
        ChunkId::ThreadPtrs => got::thread_ptrs::copy_buf(ctx, buf),
        ChunkId::ObjcStubs => objc::objc_stubs::copy_buf(ctx, buf),
        ChunkId::ObjcMethlist => objc::objc_methlist::copy_buf(ctx, buf),
        ChunkId::ObjcImageInfo => objc::objc_imageinfo::copy_buf(ctx, buf),
        ChunkId::SectCreate(i) => misc::sectcreate::copy_buf(ctx, i, buf),
        ChunkId::InitOffsets => misc::init_offsets::copy_buf(ctx, buf),
        ChunkId::UnwindInfo => unwind_info::copy_buf(ctx, buf),
        ChunkId::EhFrame => eh_frame::copy_buf(ctx, buf),
        ChunkId::RebaseInfo => dyld_info::rebase_info::copy_buf(ctx, buf),
        ChunkId::BindInfo => dyld_info::bind_info::copy_buf(ctx, buf),
        ChunkId::WeakBindInfo => dyld_info::weak_bind_info::copy_buf(ctx, buf),
        ChunkId::LazyBindInfo => dyld_info::lazy_bind_info::copy_buf(ctx, buf),
        ChunkId::ChainedFixups => chained_fixups::copy_buf(ctx, buf),
        ChunkId::ExportTrie => export_trie::copy_buf(ctx, buf),
        ChunkId::FunctionStarts => misc::function_starts::copy_buf(ctx, buf),
        ChunkId::DataInCode => misc::data_in_code::copy_buf(ctx, buf),
        ChunkId::IndirectSymtab => symtab::indirect_symtab::copy_buf(ctx, buf),
    }
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

    let sects: Vec<&ChunkHeader> = seg
        .chunks
        .iter()
        .map(|&id| ctx.chunk_header(id))
        .filter(|hdr| hdr.is_sect)
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
    for hdr in sects {
        let mut sect = MachSection {
            sectname: str_to_name(&hdr.sectname),
            segname: str_to_name(seg.name),
            addr: hdr.addr,
            size: hdr.size,
            offset: hdr.fileoff as u32,
            p2align: hdr.p2align,
            flags: hdr.flags,
            reserved1: hdr.reserved1,
            reserved2: hdr.reserved2,
            ..Default::default()
        };
        if hdr.is_zerofill() {
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
    let hdr = &ctx.rebase_info.hdr;
    if hdr.size > 0 {
        cmd.rebase_off = hdr.fileoff as u32;
        cmd.rebase_size = hdr.size as u32;
    }
    let hdr = &ctx.bind_info.hdr;
    if hdr.size > 0 {
        cmd.bind_off = hdr.fileoff as u32;
        cmd.bind_size = hdr.size as u32;
    }
    let hdr = &ctx.weak_bind_info.hdr;
    if hdr.size > 0 {
        cmd.weak_bind_off = hdr.fileoff as u32;
        cmd.weak_bind_size = hdr.size as u32;
    }
    let hdr = &ctx.lazy_bind_info.hdr;
    if hdr.size > 0 {
        cmd.lazy_bind_off = hdr.fileoff as u32;
        cmd.lazy_bind_size = hdr.size as u32;
    }
    let hdr = &ctx.export_trie.hdr;
    if hdr.size > 0 {
        cmd.export_off = hdr.fileoff as u32;
        cmd.export_size = hdr.size as u32;
    }
    to_vec(&cmd)
}

fn create_symtab_cmd<E: Arch>(ctx: &Context<E>) -> Vec<u8> {
    let cmd = SymtabCommand {
        cmd: LC_SYMTAB,
        cmdsize: size_of::<SymtabCommand>() as u32,
        symoff: ctx.symtab.hdr.fileoff as u32,
        nsyms: ctx.symtab.entries.len() as u32,
        stroff: ctx.strtab.hdr.fileoff as u32,
        strsize: ctx.strtab.hdr.size as u32,
    };
    to_vec(&cmd)
}

fn create_dysymtab_cmd<E: Arch>(ctx: &Context<E>) -> Vec<u8> {
    let data = &ctx.symtab;
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
    if ctx.chunks.contains(&ChunkId::IndirectSymtab) {
        cmd.indirectsymoff = ctx.indirect_symtab.hdr.fileoff as u32;
        cmd.nindirectsyms = (ctx.indirect_symtab.hdr.size / 4) as u32;
    }
    to_vec(&cmd)
}

fn create_function_starts_cmd<E: Arch>(ctx: &Context<E>) -> Vec<u8> {
    create_linkedit_data_cmd(LC_FUNCTION_STARTS, &ctx.function_starts.hdr)
}

fn create_uuid_cmd<E: Arch>(ctx: &Context<E>) -> Vec<u8> {
    let cmd = UuidCommand {
        cmd: LC_UUID,
        cmdsize: size_of::<UuidCommand>() as u32,
        uuid: *ctx.uuid.lock().unwrap(),
    };
    to_vec(&cmd)
}

fn create_build_version_cmd<E: Arch>(ctx: &Context<E>) -> Vec<u8> {
    let cmd = BuildVersionCommand {
        cmd: LC_BUILD_VERSION,
        cmdsize: (size_of::<BuildVersionCommand>() + 8) as u32,
        platform: ctx.args.platform,
        minos: ctx.args.platform_minos,
        sdk: ctx.args.platform_sdk,
        ntools: 1,
    };
    let mut buf = to_vec(&cmd);
    // A build_tool_version entry stamping which linker made the
    // image: {u32 tool, u32 version}. Apple's tools are 1..3
    // (clang/swift/ld); this linker identifies itself with sold's
    // number, 54321, so "otool -l | grep 'tool 54321'" spots our
    // output.
    buf.extend_from_slice(&54321u32.to_le_bytes());
    buf.extend_from_slice(&1u32.to_le_bytes());
    buf
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
        cmd: if dylib.is_reexported {
            LC_REEXPORT_DYLIB
        } else if dylib.is_weak {
            LC_LOAD_WEAK_DYLIB
        } else {
            LC_LOAD_DYLIB
        },
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
    let name = ctx
        .args
        .install_name
        .as_deref()
        .or(ctx.args.final_output.as_deref())
        .unwrap_or(&ctx.args.output);
    let cmd = DylibCommand {
        cmd: LC_ID_DYLIB,
        cmdsize: 0,
        nameoff: size_of::<DylibCommand>() as u32,
        timestamp: 0,
        current_version: ctx.args.current_version,
        compatibility_version: ctx.args.compatibility_version,
    };
    let mut buf = to_vec(&cmd);
    append_string(&mut buf, name);
    let size = buf.len() as u32;
    buf[4..8].copy_from_slice(&size.to_le_bytes());
    buf
}

// LC_RPATH and LC_SUB_FRAMEWORK share the layout of every
// single-string load command: a cmd/cmdsize header plus the offset of
// an inline NUL-terminated string, padded to an 8-byte multiple.
fn create_string_cmd(kind: u32, path: &str) -> Vec<u8> {
    let cmd = DylinkerCommand {
        cmd: kind,
        cmdsize: 0,
        nameoff: size_of::<DylinkerCommand>() as u32,
    };
    let mut buf = to_vec(&cmd);
    append_string(&mut buf, path);
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
        stacksize: ctx.args.stack_size,
    };
    to_vec(&cmd)
}

fn create_code_signature_cmd<E: Arch>(ctx: &Context<E>) -> Vec<u8> {
    create_linkedit_data_cmd(LC_CODE_SIGNATURE, &ctx.code_signature.hdr)
}

fn create_linkedit_data_cmd(cmd: u32, hdr: &ChunkHeader) -> Vec<u8> {
    let cmd = LinkEditDataCommand {
        cmd,
        cmdsize: size_of::<LinkEditDataCommand>() as u32,
        dataoff: hdr.fileoff as u32,
        datasize: hdr.size as u32,
    };
    to_vec(&cmd)
}

pub fn create_load_commands<E: Arch>(ctx: &Context<E>) -> Vec<Vec<u8>> {
    // In ld64's order: the segments; a dylib's identity; the dyld
    // tables; the symbol tables; the dynamic linker; identification
    // (UUID, build and source versions); the entry point; the
    // libraries; the run-path list; the code tables (function starts,
    // data-in-code); the signature last.
    let mut vec = Vec::new();

    for seg in &ctx.segments {
        vec.push(create_segment_cmd(ctx, seg));
    }

    if ctx.args.output_type == MH_DYLIB {
        vec.push(create_id_dylib_cmd(ctx));
        if let Some(name) = &ctx.args.umbrella {
            vec.push(create_string_cmd(LC_SUB_FRAMEWORK, name));
        }
        for client in &ctx.args.allowable_clients {
            vec.push(create_string_cmd(LC_SUB_CLIENT, client));
        }
    }

    // Chained fixups replace the classic dyld info; the export trie
    // then gets a load command of its own.
    if ctx.chained_fixups.hdr.size > 0 {
        vec.push(create_linkedit_data_cmd(LC_DYLD_CHAINED_FIXUPS, &ctx.chained_fixups.hdr));
        if ctx.export_trie.hdr.size > 0 {
            vec.push(create_linkedit_data_cmd(LC_DYLD_EXPORTS_TRIE, &ctx.export_trie.hdr));
        }
    } else {
        vec.push(create_dyld_info_cmd(ctx));
    }
    vec.push(create_symtab_cmd(ctx));
    vec.push(create_dysymtab_cmd(ctx));
    if ctx.args.output_type == MH_EXECUTE {
        vec.push(create_dylinker_cmd());
    }
    vec.push(create_uuid_cmd(ctx));
    vec.push(create_build_version_cmd(ctx));
    vec.push(create_source_version_cmd(ctx));
    if ctx.args.output_type == MH_EXECUTE {
        vec.push(create_main_cmd(ctx));
    }

    // Libraries in ordinal order (command-line order, then the
    // auto-linked ones).
    let mut dylibs: Vec<&crate::input_files::DylibFile> =
        ctx.dylibs.iter().filter(|d| !d.is_bundle_loader).collect();
    dylibs.sort_by_key(|d| d.dylib_idx);
    for dylib in dylibs {
        vec.push(create_load_dylib_cmd(dylib));
    }

    for rpath in &ctx.args.rpaths {
        vec.push(create_string_cmd(LC_RPATH, rpath));
    }

    if ctx.function_starts.hdr.size > 0 {
        vec.push(create_function_starts_cmd(ctx));
    }

    // ld64 always writes LC_DATA_IN_CODE, even with no entries;
    // tooling takes its absence as "old linker".
    if ctx.chunks.contains(&ChunkId::DataInCode) {
        vec.push(create_linkedit_data_cmd(LC_DATA_IN_CODE, &ctx.data_in_code.hdr));
    }

    if ctx.chunks.contains(&ChunkId::CodeSignature) {
        vec.push(create_code_signature_cmd(ctx));
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
        flags: if ctx.args.flat_namespace {
            MH_NOUNDEFS | MH_DYLDLINK
        } else {
            MH_NOUNDEFS | MH_DYLDLINK | MH_TWOLEVEL
        },
        reserved: 0,
    };

    let mut hdr = hdr;
    match ctx.args.output_type {
        MH_EXECUTE => hdr.flags |= MH_PIE,
        MH_DYLIB => {
            if !ctx.dylibs.iter().any(|d| d.is_reexported) {
                hdr.flags |= MH_NO_REEXPORTED_DYLIBS;
            }
            if ctx.args.mark_dead_strippable_dylib {
                hdr.flags |= MH_DEAD_STRIPPABLE_DYLIB;
            }
        }
        _ => {}
    }
    // MH_BINDS_TO_WEAK: the image binds to a symbol some dylib
    // defines weakly, or to one of its own coalescable weak
    // definitions (dyld must then consider weak coalescing when it
    // binds). ld-prime sets it on an executable calling a dylib's
    // weak definition, and on any image with weak-lookup binds.
    if ctx.symbols.syms.iter().any(|sym| match sym.origin() {
        Origin::Dylib(idx) => {
            idx != u32::MAX && sym.is_used() && ctx.dylibs[idx as usize].weak_exports.contains(sym.name())
        }
        _ => false,
    }) || ctx.chained_fixups.imports.iter().any(|&(id, _)| ctx.binds_weak_lookup(id))
        || !ctx.weak_bind_info.contents.is_empty()
    {
        hdr.flags |= MH_BINDS_TO_WEAK;
    }
    // MH_WEAK_DEFINES advertises exported weak symbols (auto-hidden and
    // private-extern weak definitions don't count, since no other
    // image can coalesce against them) and strong definitions that
    // override a dylib's weak export, which dyld must let win.
    if ctx.symbols.syms.iter().any(|sym| {
        sym.is_weak_def()
            && sym.is_extern()
            && !sym.is_private_extern()
            && sym.isec().map(|i| i as usize).is_some_and(|isec| ctx.isecs[isec].is_alive())
    }) || (0..ctx.symbols.syms.len()).any(|i| ctx.overrides_weak_export(i as u32))
    {
        hdr.flags |= MH_WEAK_DEFINES;
    }
    // -bind_at_load makes the stubs bind through the GOT instead of
    // lazily; ld-prime does not set MH_BINDATLOAD for it (dyld binds
    // everything at load anyway).
    if ctx.args.application_extension {
        hdr.flags |= MH_APP_EXTENSION_SAFE;
    }
    if ctx
        .chunks
        .iter()
        .any(|&id| ctx.chunk_header(id).flags & SECTION_TYPE == S_THREAD_LOCAL_VARIABLES)
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
    use rayon::prelude::*;
    let off = ctx.symtab.hdr.fileoff as usize;
    let entries = &ctx.symtab.entries;
    // Millions of entries, each wanting a sym_addr lookup for its
    // n_value: emit them in parallel blocks.
    const BLOCK: usize = 4096;
    buf[off..off + entries.len() * size_of::<NList>()]
        .par_chunks_mut(BLOCK * size_of::<NList>())
        .zip(entries.par_chunks(BLOCK))
        .for_each(|(out, ents)| {
            for (i, (nlist, sym)) in ents.iter().enumerate() {
                let mut nlist = *nlist;
                if let Some(id) = sym {
                    nlist.n_value = ctx.sym_addr(*id);
                }
                nlist.write_to(&mut out[i * size_of::<NList>()..]);
            }
        });

    // The string table is written straight into the output here - no
    // intermediate 150MB buffer. The " \0-\0" prefix (offsets 1 and 2
    // are the empty and "-" placeholders), then every distinct string
    // at its offset, on all cores; each string owns a disjoint range.
    let off = ctx.strtab.hdr.fileoff as usize;
    let strtab = &mut buf[off..off + ctx.symtab.strtab_size];
    strtab[..4].copy_from_slice(b" \0-\0");
    struct BufPtr(*mut u8);
    unsafe impl Sync for BufPtr {}
    let base = BufPtr(strtab.as_mut_ptr());
    let base = &base;
    ctx.symtab.strtab_uniques.par_iter().for_each(|&(o, name)| {
        let o = o as usize;
        // SAFETY: strings occupy disjoint [o, o+len+1) ranges within
        // the string table; the trailing NUL is already zero in buf.
        unsafe {
            std::ptr::copy_nonoverlapping(name.as_ptr(), base.0.add(o), name.len());
        }
    });
}

/// What an export trie terminal says about a symbol.
#[derive(Clone, Copy)]
enum Export {
    /// A symbol defined in this image: flags and image-relative address.
    Addr { flags: u32, addr: u64 },
    /// A symbol re-exported from a dylib under this name (an -alias of
    /// an imported symbol): the dylib's ordinal and the name it has
    /// there.
    Reexport { ordinal: u32, name: &'static str },
}

impl Export {
    /// The terminal's payload after its size: flags, then either the
    /// address or the ordinal and the re-exported name (an empty name
    /// means the same name).
    fn terminal_size(self) -> usize {
        match self {
            Export::Addr { flags, addr } => uleb_len(flags as u64) + uleb_len(addr),
            Export::Reexport { ordinal, name } => {
                uleb_len(EXPORT_SYMBOL_FLAGS_REEXPORT as u64) + uleb_len(ordinal as u64) + name.len() + 1
            }
        }
    }
}

/// A node of the export trie under construction.
#[derive(Default)]
struct TrieNode {
    /// Edge labels borrow from the symbol names themselves.
    children: Vec<(&'static str, TrieNode)>,
    /// The exported symbol ending here, if any.
    export: Option<Export>,
    offset: usize,
    /// Pre-order index, assigned by flatten; lets the sizing pass name
    /// a child by index without a pointer hash map.
    index: u32,
    /// Node count of this subtree (including this node), so that
    /// flatten can hand every subtree a disjoint slot range.
    size: u32,
}

/// Builds the subtrie for a sorted run of names that all share their
/// first `depth` bytes. The run splits into children by the byte at
/// `depth`, and each child's edge label is its group's remaining
/// common prefix (for a sorted group, the common prefix of its first
/// and last name). Sibling subtries build in parallel, so
/// construction parallelizes at every branching level - splitting on
/// leading bytes alone is useless when every Mach-O symbol starts
/// with '_'. Construction stays linear in the total name length.
fn build_trie(names: &[(&'static str, Export)], depth: usize) -> TrieNode {
    use rayon::prelude::*;
    let mut node = TrieNode::default();
    let mut rest = names;
    if let Some(&(name, export)) = rest.first() {
        if name.len() == depth {
            node.export = Some(export);
            rest = &rest[1..];
        }
    }
    let mut groups: Vec<&[(&'static str, Export)]> = Vec::new();
    while let Some(&(first, _)) = rest.first() {
        let b = first.as_bytes()[depth];
        let n = rest
            .iter()
            .take_while(|(n, _)| n.as_bytes()[depth] == b)
            .count();
        groups.push(&rest[..n]);
        rest = &rest[n..];
    }
    let build_child = |group: &&[(&'static str, Export)]| {
        let first = group[0].0;
        let last = group[group.len() - 1].0;
        let common = depth
            + first
                .bytes()
                .skip(depth)
                .zip(last.bytes().skip(depth))
                .take_while(|(a, b)| a == b)
                .count();
        (&first[depth..common], build_trie(group, common))
    };
    node.children = if names.len() >= 1024 {
        groups.par_iter().map(build_child).collect()
    } else {
        groups.iter().map(build_child).collect()
    };
    node
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
pub fn encode_export_trie<E: Arch>(
    ctx: &Context<E>,
    sorted_globals: &[SymbolId],
) -> Vec<u8> {
    use rayon::prelude::*;
    let base = ctx.args.pagezero_size;

    // The caller hands over the defined globals already sorted by
    // name - the same list the symbol table emits - so the trie only
    // filters the explicit export/unexport lists (order-preserving)
    // and never sorts.
    let exports: Vec<(&'static str, Export)> = sorted_globals
        .par_iter()
        .filter_map(|&id| {
            let sym = &ctx.symbols[id];
            if let Some(exported) = &ctx.args.exported_symbols {
                if !exported.iter().any(|pat| pat == sym.name()) {
                    return None;
                }
            }
            if ctx.args.unexported_symbols.iter().any(|pat| pat == sym.name()) {
                return None;
            }
            if let Some(&(_, target)) = ctx.indirect_aliases.iter().find(|&&(a, _)| a == id) {
                let Origin::Dylib(dylib) = ctx.symbols[target].origin() else {
                    return None;
                };
                let ordinal = ctx.bind_ordinal(dylib) as u32;
                return Some((sym.name(), Export::Reexport { ordinal, name: ctx.symbols[target].name() }));
            }
            // The kind bits tell a client linker (and dyld) that the
            // export is a TLV descriptor; ld64 sets them, and a
            // linker reading a stripped dylib's trie has nothing else
            // to go by.
            let mut flags = 0;
            if sym.is_weak_def() {
                flags |= EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION;
            }
            if crate::passes::is_thread_local_sym(ctx, id) {
                flags |= EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL;
            }
            Some((sym.name(), Export::Addr { flags, addr: ctx.sym_addr(id) - base }))
        })
        .collect();
    if exports.is_empty() {
        return Vec::new();
    }

    let mut root = build_trie(&exports, 0);

    // Nodes in pre-order, as raw pointers to sidestep the borrow of the
    // recursive structure. Two parallel passes in mold's prefix-sum
    // shape: count every subtree, then each subtree writes its
    // pre-order run into its own disjoint slot range of one
    // preallocated array - no appending or copying, and the pre-order
    // index is simply the slot number. Fan-out happens at nodes with
    // many children (the second level: every Mach-O name starts with
    // '_', so the root has one child).
    const FANOUT: usize = 8;
    fn count(node: &mut TrieNode) -> u32 {
        node.children.sort_by(|a, b| a.0.cmp(&b.0));
        let below: u32 = if node.children.len() >= FANOUT {
            node.children.par_iter_mut().map(|(_, c)| count(c)).sum()
        } else {
            node.children.iter_mut().map(|(_, c)| count(c)).sum()
        };
        node.size = 1 + below;
        node.size
    }
    struct Slots(*mut *mut TrieNode);
    unsafe impl Sync for Slots {}
    fn fill(node: &mut TrieNode, base: u32, slots: &Slots) {
        node.index = base;
        // SAFETY: every subtree owns [base, base+size), the ranges are
        // disjoint by construction of the prefix sums below, and the
        // array holds exactly root.size slots.
        unsafe { *slots.0.add(base as usize) = node };
        if node.children.len() >= FANOUT {
            let mut b = base + 1;
            let bases: Vec<u32> = node
                .children
                .iter()
                .map(|(_, c)| {
                    let x = b;
                    b += c.size;
                    x
                })
                .collect();
            node.children
                .par_iter_mut()
                .zip(bases)
                .for_each(|((_, c), cb)| fill(c, cb, slots));
        } else {
            let mut b = base + 1;
            for (_, c) in &mut node.children {
                fill(c, b, slots);
                b += c.size;
            }
        }
    }
    let total = count(&mut root) as usize;
    let mut nodes: Vec<*mut TrieNode> = vec![std::ptr::null_mut(); total];
    fill(&mut root, 0, &Slots(nodes.as_mut_ptr()));
    debug_assert!(nodes.iter().all(|p| !p.is_null()));

    // Assign node offsets until they stop moving. Everything except
    // the width of the child-offset ULEBs is invariant, so the
    // fixpoint (a couple of passes: offsets only grow as their ULEBs
    // widen) runs over precomputed per-node fixed sizes and child
    // index lists, no pointer chasing.
    // Each node's fixed size and the pre-order indices of its children.
    // flatten stamped every node's index, so a child names itself by
    // index with no pointer hash map, and the whole pass is a pure
    // per-node map that runs in parallel.
    struct NodePtr(*mut TrieNode);
    unsafe impl Sync for NodePtr {}
    let node_ptrs: Vec<NodePtr> = nodes.iter().map(|&p| NodePtr(p)).collect();
    let (fixed, kids): (Vec<usize>, Vec<Vec<u32>>) = node_ptrs
        .par_iter()
        .map(|np| {
            // SAFETY: nodes live in `root`, which outlives this function.
            let node = unsafe { &*np.0 };
            let terminal_size = match node.export {
                Some(export) => export.terminal_size(),
                None => 0,
            };
            let mut f = uleb_len(terminal_size as u64) + terminal_size + 1;
            let mut k = Vec::with_capacity(node.children.len());
            for (label, child) in &node.children {
                f += label.len() + 1;
                k.push(child.index);
            }
            (f, k)
        })
        .unzip();
    let mut offs = vec![0u32; nodes.len()];
    // Total encoded size, set on every pass (the loop always runs).
    let mut total;
    loop {
        let mut changed = false;
        let mut off = 0u32;
        for i in 0..nodes.len() {
            if offs[i] != off {
                offs[i] = off;
                changed = true;
            }
            off += fixed[i] as u32;
            for &c in &kids[i] {
                off += uleb_len(offs[c as usize] as u64) as u32;
            }
        }
        total = off;
        if !changed {
            break;
        }
    }
    for (i, &node) in nodes.iter().enumerate() {
        // SAFETY: as above; each node written once.
        unsafe { (*node).offset = offs[i] as usize };
    }

    // Emit every node into its final slot in parallel. Node i owns the
    // byte range [offs[i], offs[i+1]) (the last runs to `total`), the
    // ranges are disjoint and cover the buffer, and each node reads
    // only its children's offsets (already final) - so all writes are
    // independent. On a big Rust debug link the trie is tens of MB, so
    // this is the difference between a serial and a parallel memcpy.
    fn write_uleb_at(dst: &mut [u8], mut pos: usize, mut val: u64) -> usize {
        let start = pos;
        loop {
            let mut b = (val & 0x7f) as u8;
            val >>= 7;
            if val != 0 {
                b |= 0x80;
            }
            dst[pos] = b;
            pos += 1;
            if val == 0 {
                break;
            }
        }
        pos - start
    }
    let mut buf = vec![0u8; total as usize];
    {
        struct BufPtr(*mut u8);
        unsafe impl Sync for BufPtr {}
        let bp = BufPtr(buf.as_mut_ptr());
        let bp = &bp;
        let n = nodes.len();
        node_ptrs.par_iter().enumerate().for_each(|(i, np)| {
            let node = unsafe { &*np.0 };
            let start = offs[i] as usize;
            let end = if i + 1 < n { offs[i + 1] as usize } else { total as usize };
            // SAFETY: the [start, end) ranges are disjoint across nodes
            // and lie within the allocation of length `total`.
            let dst = unsafe { std::slice::from_raw_parts_mut(bp.0.add(start), end - start) };
            let mut p = 0;
            match node.export {
                Some(export @ Export::Addr { flags, addr }) => {
                    p += write_uleb_at(dst, p, export.terminal_size() as u64);
                    p += write_uleb_at(dst, p, flags as u64);
                    p += write_uleb_at(dst, p, addr);
                }
                Some(export @ Export::Reexport { ordinal, name }) => {
                    p += write_uleb_at(dst, p, export.terminal_size() as u64);
                    p += write_uleb_at(dst, p, EXPORT_SYMBOL_FLAGS_REEXPORT as u64);
                    p += write_uleb_at(dst, p, ordinal as u64);
                    dst[p..p + name.len()].copy_from_slice(name.as_bytes());
                    p += name.len();
                    dst[p] = 0;
                    p += 1;
                }
                None => {
                    dst[p] = 0;
                    p += 1;
                }
            }
            dst[p] = node.children.len() as u8;
            p += 1;
            for (label, child) in &node.children {
                dst[p..p + label.len()].copy_from_slice(label.as_bytes());
                p += label.len();
                dst[p] = 0;
                p += 1;
                p += write_uleb_at(dst, p, child.offset as u64);
            }
            debug_assert_eq!(p, end - start);
        });
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
/// Encodes __unwind_info. The personality entries are image-relative
/// pointers to GOT slots, whose addresses are not final when __TEXT
/// (and this section's size) is computed - so they are returned as a
/// patch list instead of written, and the copy phase fills the cells
/// at offsets 28, 32, ... once the GOT has its address. Everything
/// else in the encoding is final at sizing time.
pub fn encode_unwind_info<E: Arch>(ctx: &Context<E>) -> (Vec<u8>, Vec<SymbolId>) {
    use rayon::prelude::*;
    let mut records: Vec<crate::input_files::UnwindRecord> = ctx
        .unwind_records
        .par_iter()
        .filter(|rec| {
            ctx.isecs[rec.isec as usize].is_alive() && ctx.isecs[rec.isec as usize].replacement == crate::input_sections::NO_REPLACEMENT
        })
        .cloned()
        .collect();
    if records.is_empty() {
        return (Vec::new(), Vec::new());
    }

    let base = ctx.args.pagezero_size;
    let func_addr =
        |r: &crate::input_files::UnwindRecord| ctx.isec_addr(r.isec as usize) + r.input_offset as u64;

    // Records synthesized from DWARF unwind info encode the FDE's
    // offset in __eh_frame in the low 24 bits.
    for rec in &mut records {
        if let Some(fde) = rec.fde() {
            rec.encoding = E::UNWIND_MODE_DWARF | (ctx.fdes[fde].output_offset & 0xff_ffff);
        }
    }

    // Assign personality indices, encoded in bits 28-29 of the encoding.
    let mut personalities: Vec<SymbolId> = Vec::new();
    for rec in &mut records {
        if let Some(p) = rec.personality() {
            let idx = match personalities.iter().position(|&s| s == p) {
                Some(idx) => idx,
                None => {
                    personalities.push(p);
                    personalities.len() - 1
                }
            };
            if idx >= 3 {
                crate::fatal!("too many personality functions");
            }
            rec.encoding |= ((idx + 1) as u32) << UNWIND_PERSONALITY_MASK.trailing_zeros();
        }
    }

    records.par_sort_by_key(func_addr);

    // Merge adjacent records with identical contents.
    let mut merged: Vec<crate::input_files::UnwindRecord> = Vec::with_capacity(records.len());
    for rec in records {
        match merged.last_mut() {
            Some(last)
                if func_addr(last) + last.code_len as u64 == func_addr(&rec)
                    && last.encoding == rec.encoding
                    && last.personality() == rec.personality()
                    && last.lsda().is_none()
                    && rec.lsda().is_none() =>
            {
                last.code_len += rec.code_len;
            }
            _ => merged.push(rec),
        }
    }
    let records = merged;

    // The common encodings table: the encodings the image uses more
    // than once, most frequent first, up to 127 of them (a compressed
    // entry's 8-bit index names a common encoding below the table's
    // count and a page-local one above it). ld64 fills it the same
    // way; a one-off encoding - every DWARF-mode one, with its FDE
    // offset - stays page-local.
    let common: Vec<(u32, usize)> = {
        let mut freq: std::collections::HashMap<u32, (usize, usize)> = std::collections::HashMap::new();
        for (i, rec) in records.iter().enumerate() {
            let e = freq.entry(rec.encoding).or_insert((0, i));
            e.0 += 1;
        }
        let mut all: Vec<(u32, usize, usize)> = freq.into_iter().map(|(e, (n, first))| (e, n, first)).collect();
        all.sort_by(|a, b| b.1.cmp(&a.1).then(a.2.cmp(&b.2)));
        all.into_iter().filter(|&(_, n, _)| n > 1).take(127).map(|(e, n, _)| (e, n)).collect()
    };
    let common_idx: std::collections::HashMap<u32, u32> =
        common.iter().enumerate().map(|(i, &(e, _))| (e, i as u32)).collect();

    // Second-level pages, 4096 bytes each, filled from the end of the
    // record list as ld64 does (so the first page is the partial one).
    // A compressed page holds 32-bit entries (a 24-bit offset from the
    // page's first function and an 8-bit encoding index) plus its
    // page-local encodings; a regular page 8-byte entries. Each page
    // takes the format that holds more of the remaining records.
    const PAGE_SIZE: usize = 4096;
    const COMPRESSED_HDR: usize = 12;
    const REGULAR_HDR: usize = 8;
    struct Page {
        start: usize,
        end: usize,
        compressed: bool,
        encodings: Vec<u32>,
    }
    let mut pages: Vec<Page> = Vec::new();
    let mut end = records.len();
    while end > 0 {
        let last_addr = func_addr(&records[end - 1]);
        let mut encs: Vec<u32> = Vec::new();
        let mut n = 0;
        let mut i = end;
        while i > 0 {
            let rec = &records[i - 1];
            let is_common = common_idx.contains_key(&rec.encoding);
            let new_enc = !is_common && !encs.contains(&rec.encoding);
            if new_enc && common.len() + encs.len() + 1 > 256 {
                break;
            }
            let encs_len = encs.len() + new_enc as usize;
            if COMPRESSED_HDR + (n + 1) * 4 + encs_len * 4 > PAGE_SIZE {
                break;
            }
            if last_addr - func_addr(rec) >= (1 << 24) {
                break;
            }
            if new_enc {
                encs.push(rec.encoding);
            }
            n += 1;
            i -= 1;
        }
        let regular = end.min((PAGE_SIZE - REGULAR_HDR) / 8);
        if n >= regular {
            pages.push(Page { start: end - n, end, compressed: true, encodings: encs });
            end -= n;
        } else {
            pages.push(Page { start: end - regular, end, compressed: false, encodings: Vec::new() });
            end -= regular;
        }
    }
    pages.reverse();

    let num_lsda = records.iter().filter(|r| r.lsda().is_some()).count();

    // Compute the layout of the section.
    let common_off = 28;
    let personality_off = common_off + common.len() * 4;
    let page1_off = personality_off + personalities.len() * 4;
    let lsda_off = page1_off + (pages.len() + 1) * 12;
    let page2_off = lsda_off + num_lsda * 8;

    let push32 = |buf: &mut Vec<u8>, val: u32| buf.extend_from_slice(&val.to_le_bytes());
    let push16 = |buf: &mut Vec<u8>, val: u16| buf.extend_from_slice(&val.to_le_bytes());

    let mut buf = Vec::new();
    push32(&mut buf, UNWIND_SECTION_VERSION);
    push32(&mut buf, common_off as u32);
    push32(&mut buf, common.len() as u32);
    push32(&mut buf, personality_off as u32);
    push32(&mut buf, personalities.len() as u32);
    push32(&mut buf, page1_off as u32);
    push32(&mut buf, pages.len() as u32 + 1);
    for &(enc, _) in &common {
        push32(&mut buf, enc);
    }

    // Personalities are image-relative pointers to the functions' GOT
    // slots, patched in by the copy phase (see above).
    for &_sym in &personalities {
        push32(&mut buf, 0);
    }

    // Each second-level page's blob and LSDA rows depend only on its
    // own records, so the pages build in parallel; the first-level
    // index is then a serial walk over the blob lengths.
    struct PageOut {
        page2: Vec<u8>,
        lsda: Vec<u8>,
        first: u32,
    }
    let outs: Vec<PageOut> = pages
        .par_iter()
        .map(|page| {
            let span = &records[page.start..page.end];
            let mut page2 = Vec::new();
            let mut lsda = Vec::new();
            for rec in span {
                if let Some((isec, off)) = rec.lsda() {
                    push32(&mut lsda, (func_addr(rec) - base) as u32);
                    push32(&mut lsda, (ctx.isec_addr(isec) + off as u64 - base) as u32);
                }
            }

            if page.compressed {
                push32(&mut page2, UNWIND_SECOND_LEVEL_COMPRESSED);
                push16(&mut page2, COMPRESSED_HDR as u16); // entries offset
                push16(&mut page2, span.len() as u16);
                push16(&mut page2, (COMPRESSED_HDR + span.len() * 4) as u16); // encodings offset
                push16(&mut page2, page.encodings.len() as u16);
                let page_base = func_addr(&span[0]);
                for rec in span {
                    let enc_idx = match common_idx.get(&rec.encoding) {
                        Some(&i) => i,
                        None => {
                            common.len() as u32
                                + page.encodings.iter().position(|&e| e == rec.encoding).unwrap() as u32
                        }
                    };
                    let entry = (func_addr(rec) - page_base) as u32 | enc_idx << 24;
                    push32(&mut page2, entry);
                }
                for enc in &page.encodings {
                    push32(&mut page2, *enc);
                }
            } else {
                push32(&mut page2, UNWIND_SECOND_LEVEL_REGULAR);
                push16(&mut page2, REGULAR_HDR as u16);
                push16(&mut page2, span.len() as u16);
                for rec in span {
                    push32(&mut page2, (func_addr(rec) - base) as u32);
                    push32(&mut page2, rec.encoding);
                }
            }
            PageOut {
                page2,
                lsda,
                first: (func_addr(&span[0]) - base) as u32,
            }
        })
        .collect();

    let mut page1 = Vec::new();
    let mut lsda = Vec::new();
    let mut page2 = Vec::new();
    for out in &outs {
        push32(&mut page1, out.first);
        push32(&mut page1, (page2_off + page2.len()) as u32);
        push32(&mut page1, (lsda_off + lsda.len()) as u32);
        lsda.extend_from_slice(&out.lsda);
        page2.extend_from_slice(&out.page2);
    }

    // The terminating first-level entry.
    let last = records.last().unwrap();
    push32(&mut page1, (func_addr(last) + last.code_len as u64 + 1 - base) as u32);
    push32(&mut page1, 0);
    push32(&mut page1, (lsda_off + lsda.len()) as u32);

    buf.extend_from_slice(&page1);
    buf.extend_from_slice(&lsda);
    buf.extend_from_slice(&page2);
    (buf, personalities)
}
