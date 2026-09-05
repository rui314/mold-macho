//! The export trie in __LINKEDIT: dyld's index of exported symbols.

use crate::arch::Arch;
use crate::context::Context;
use crate::output_chunks::ChunkHeader;

#[derive(Debug)]
pub struct ExportTrieSection {
    pub hdr: ChunkHeader,
    /// The trie, encoded once when its chunk is sized (every address is
    /// final by then) and reused when copied out.
    pub contents: Vec<u8>,
}

impl ExportTrieSection {
    pub fn new() -> ExportTrieSection {
        ExportTrieSection { hdr: ChunkHeader::linkedit(), contents: Vec::new() }
    }
}

pub fn copy_buf<E: Arch>(ctx: &Context<E>, buf: &mut [u8]) {
    let data = &ctx.export_trie.contents;
    buf[..data.len()].copy_from_slice(data);
}
