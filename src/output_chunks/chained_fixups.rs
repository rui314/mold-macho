//! The LC_DYLD_CHAINED_FIXUPS payload in __LINKEDIT: the modern
//! replacement for the rebase and bind opcode streams, with the fixup
//! chains it describes threaded through the data sections.

use crate::arch::Arch;
use crate::context::Context;
use crate::output_chunks::ChunkHeader;
use crate::symbol::SymbolId;

#[derive(Debug)]
pub struct ChainedFixupsSection {
    pub hdr: ChunkHeader,
    /// The encoded payload, built during layout.
    pub contents: Vec<u8>,
    /// Every dynamic fixup location, sorted by address: (address,
    /// bound symbol or None for a rebase, addend).
    pub fixups: Vec<(u64, Option<SymbolId>, u64)>,
    /// The import table: (symbol, table addend), sorted; and each
    /// symbol's first ordinal.
    pub imports: Vec<(SymbolId, u64)>,
    pub ordinals: std::collections::HashMap<SymbolId, usize>,
}

impl ChainedFixupsSection {
    pub fn new() -> ChainedFixupsSection {
        ChainedFixupsSection {
            hdr: ChunkHeader::linkedit(),
            contents: Vec::new(),
            fixups: Vec::new(),
            imports: Vec::new(),
            ordinals: std::collections::HashMap::new(),
        }
    }
}

pub fn copy_buf<E: Arch>(ctx: &Context<E>, buf: &mut [u8]) {
    let data = &ctx.chained_fixups.contents;
    buf[..data.len()].copy_from_slice(data);
}
