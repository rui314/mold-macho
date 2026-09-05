//! __TEXT,__unwind_info: the compact unwind table, generated from the
//! objects' __compact_unwind records.

use crate::arch::Arch;
use crate::context::Context;
use crate::output_chunks::ChunkHeader;
use crate::symbol::SymbolId;

#[derive(Debug)]
pub struct UnwindInfoSection {
    pub hdr: ChunkHeader,
    /// The encoded table, except its personality cells (GOT addresses
    /// unknown when __TEXT is sized): the symbols to patch into offsets
    /// 28, 32, ... at copy time.
    pub contents: Vec<u8>,
    pub personalities: Vec<SymbolId>,
}

impl UnwindInfoSection {
    pub fn new() -> UnwindInfoSection {
        let mut hdr = ChunkHeader::new("__TEXT", "__unwind_info");
        hdr.p2align = 2;
        UnwindInfoSection { hdr, contents: Vec::new(), personalities: Vec::new() }
    }
}

pub fn copy_buf<E: Arch>(ctx: &Context<E>, buf: &mut [u8]) {
    let sec = &ctx.unwind_info;
    debug_assert_eq!(sec.contents.len() as u64, sec.hdr.size);
    buf[..sec.contents.len()].copy_from_slice(&sec.contents);
    // Patch the personality cells now the GOT has addresses; the header
    // says where the array is (after the common encodings).
    let base = ctx.args.pagezero_size;
    let personality_off = u32::from_le_bytes(sec.contents[12..16].try_into().unwrap()) as usize;
    for (i, &sym) in sec.personalities.iter().enumerate() {
        let off = personality_off + i * 4;
        let val = ctx.sym_got_addr(sym).wrapping_sub(base) as u32;
        buf[off..off + 4].copy_from_slice(&val.to_le_bytes());
    }
}
