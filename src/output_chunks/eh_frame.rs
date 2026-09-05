//! __TEXT,__eh_frame: the re-synthesized DWARF unwind records that
//! compact unwind can't express.

use crate::arch::Arch;
use crate::context::Context;
use crate::output_chunks::ChunkHeader;

#[derive(Debug)]
pub struct EhFrameSection {
    pub hdr: ChunkHeader,
}

impl EhFrameSection {
    pub fn new() -> EhFrameSection {
        let mut hdr = ChunkHeader::new("__TEXT", "__eh_frame");
        hdr.p2align = 3;
        EhFrameSection { hdr }
    }
}

pub fn copy_buf<E: Arch>(ctx: &Context<E>, buf: &mut [u8]) {
    super::copy_eh_frame(ctx, buf);
}
