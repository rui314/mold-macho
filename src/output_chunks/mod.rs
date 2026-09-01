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
                is_sect: matches!(kind, ChunkKind::Output { .. }),
            },
            kind,
        }
    }

    pub fn is_zerofill(&self) -> bool {
        self.hdr.flags & SECTION_TYPE == S_ZEROFILL
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
            ..Default::default()
        };
        if chunk.is_zerofill() {
            sect.offset = 0;
        }
        buf.extend_from_slice(sect.as_bytes());
    }
    buf
}

fn create_dyld_info_cmd<E: Arch>(_ctx: &Context<E>) -> Vec<u8> {
    // No rebase, bind or export info yet: the command is present with
    // empty tables, which dyld accepts.
    let cmd = DyldInfoCommand {
        cmd: LC_DYLD_INFO_ONLY,
        cmdsize: size_of::<DyldInfoCommand>() as u32,
        ..Default::default()
    };
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
    let cmd = DysymtabCommand {
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

    vec.push(create_dylinker_cmd());
    vec.push(create_main_cmd(ctx));

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
        filetype: MH_EXECUTE,
        ncmds: cmds.len() as u32,
        sizeofcmds: cmds.iter().map(Vec::len).sum::<usize>() as u32,
        flags: MH_NOUNDEFS | MH_DYLDLINK | MH_TWOLEVEL | MH_PIE,
        reserved: 0,
    };
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
    push_be64(&mut sig, CS_EXECSEG_MAIN_BINARY); // exec segment flags

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
