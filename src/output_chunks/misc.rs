//! The smaller synthetic chunks: -sectcreate sections, __init_offsets,
//! and the LC_FUNCTION_STARTS, LC_DATA_IN_CODE and LC_CODE_SIGNATURE
//! tables in __LINKEDIT.

use crate::arch::Arch;
use crate::context::Context;
use crate::macho::*;
use crate::output_chunks::ChunkHeader;

/// A section created from a file by -sectcreate, or an empty one for
/// -add_empty_section and for a section only a boundary symbol names.
#[derive(Debug)]
pub struct SectCreateSection {
    pub hdr: ChunkHeader,
    pub contents: &'static [u8],
}

impl SectCreateSection {
    pub fn new(segname: &'static str, sectname: &str, contents: &'static [u8]) -> SectCreateSection {
        let mut hdr = ChunkHeader::new(segname, sectname);
        hdr.size = contents.len() as u64;
        SectCreateSection { hdr, contents }
    }
}

pub mod sectcreate {
    use super::*;

    pub fn copy_buf<E: Arch>(ctx: &Context<E>, idx: u32, buf: &mut [u8]) {
        let data = ctx.sectcreate_sections[idx as usize].contents;
        buf[..data.len()].copy_from_slice(data);
    }
}

/// __TEXT,__init_offsets: 32-bit image-relative initializer offsets,
/// replacing __mod_init_func's absolute pointers.
#[derive(Debug)]
pub struct InitOffsetsSection {
    pub hdr: ChunkHeader,
    /// Initializer targets in run order: the subsection and offset of
    /// each initializer function.
    pub init_funcs: Vec<(usize, u64)>,
}

impl InitOffsetsSection {
    pub fn new() -> InitOffsetsSection {
        let mut hdr = ChunkHeader::new("__TEXT", "__init_offsets");
        hdr.flags = S_INIT_FUNC_OFFSETS;
        hdr.p2align = 2;
        InitOffsetsSection { hdr, init_funcs: Vec::new() }
    }
}

pub mod init_offsets {
    use super::*;

    pub fn copy_buf<E: Arch>(ctx: &Context<E>, buf: &mut [u8]) {
        for (i, &(isec, off)) in ctx.init_offsets.init_funcs.iter().enumerate() {
            let val = (ctx.isec_addr(isec) + off - ctx.args.pagezero_size) as u32;
            buf[i * 4..i * 4 + 4].copy_from_slice(&val.to_le_bytes());
        }
    }
}

/// LC_FUNCTION_STARTS data: delta-encoded function addresses, used by
/// debuggers and crash reporters.
#[derive(Debug)]
pub struct FunctionStartsSection {
    pub hdr: ChunkHeader,
    /// The encoded table, built during layout.
    pub contents: Vec<u8>,
}

impl FunctionStartsSection {
    pub fn new() -> FunctionStartsSection {
        FunctionStartsSection { hdr: ChunkHeader::linkedit(), contents: Vec::new() }
    }
}

pub mod function_starts {
    use super::*;

    pub fn copy_buf<E: Arch>(ctx: &Context<E>, buf: &mut [u8]) {
        let data = &ctx.function_starts.contents;
        buf[..data.len()].copy_from_slice(data);
    }
}

/// LC_DATA_IN_CODE: ranges inside __text that hold data (jump tables,
/// inline constants), so disassemblers and the signature verifier can
/// treat them as bytes.
#[derive(Debug)]
pub struct DataInCodeSection {
    pub hdr: ChunkHeader,
    /// The entries (fileoff, length, kind), built once when layout
    /// reaches __LINKEDIT.
    pub entries: Vec<(u32, u16, u16)>,
}

impl DataInCodeSection {
    pub fn new() -> DataInCodeSection {
        DataInCodeSection { hdr: ChunkHeader::linkedit(), entries: Vec::new() }
    }
}

pub mod data_in_code {
    use super::*;

    pub fn copy_buf<E: Arch>(ctx: &Context<E>, buf: &mut [u8]) {
        let mut p = 0;
        for &(off, len, kind) in &ctx.data_in_code.entries {
            buf[p..p + 4].copy_from_slice(&off.to_le_bytes());
            buf[p + 4..p + 6].copy_from_slice(&len.to_le_bytes());
            buf[p + 6..p + 8].copy_from_slice(&kind.to_le_bytes());
            p += 8;
        }
    }
}

/// The ad-hoc code signature. Must be the last chunk in the file.
#[derive(Debug)]
pub struct CodeSignatureSection {
    pub hdr: ChunkHeader,
}

impl CodeSignatureSection {
    pub fn new() -> CodeSignatureSection {
        CodeSignatureSection { hdr: ChunkHeader::linkedit() }
    }
}
