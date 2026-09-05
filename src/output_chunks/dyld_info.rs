//! The LC_DYLD_INFO opcode streams in __LINKEDIT: rebase, bind, weak
//! bind and lazy bind. mold-rust's dynamic.rs holds the ELF dynamic
//! relocation tables they stand in for.

use crate::arch::Arch;
use crate::context::Context;
use crate::output_chunks::ChunkHeader;

/// The rebase opcode stream: every pointer dyld slides.
#[derive(Debug)]
pub struct RebaseInfoSection {
    pub hdr: ChunkHeader,
    /// The stream, built during layout.
    pub contents: Vec<u8>,
}

impl RebaseInfoSection {
    pub fn new() -> RebaseInfoSection {
        RebaseInfoSection { hdr: ChunkHeader::linkedit(), contents: Vec::new() }
    }
}

pub mod rebase_info {
    use super::*;

    pub fn copy_buf<E: Arch>(ctx: &Context<E>, buf: &mut [u8]) {
        let data = &ctx.rebase_info.contents;
        buf[..data.len()].copy_from_slice(data);
    }
}

/// The bind opcode stream: every slot dyld fills with an import.
#[derive(Debug)]
pub struct BindInfoSection {
    pub hdr: ChunkHeader,
    /// The stream, built during layout.
    pub contents: Vec<u8>,
}

impl BindInfoSection {
    pub fn new() -> BindInfoSection {
        BindInfoSection { hdr: ChunkHeader::linkedit(), contents: Vec::new() }
    }
}

pub mod bind_info {
    use super::*;

    pub fn copy_buf<E: Arch>(ctx: &Context<E>, buf: &mut [u8]) {
        let data = &ctx.bind_info.contents;
        buf[..data.len()].copy_from_slice(data);
    }
}

/// The weak-bind opcode stream: the slots dyld redirects when another
/// image's copy of one of this image's weak definitions wins
/// coalescing.
#[derive(Debug)]
pub struct WeakBindInfoSection {
    pub hdr: ChunkHeader,
    /// The stream, built during layout.
    pub contents: Vec<u8>,
}

impl WeakBindInfoSection {
    pub fn new() -> WeakBindInfoSection {
        WeakBindInfoSection { hdr: ChunkHeader::linkedit(), contents: Vec::new() }
    }
}

pub mod weak_bind_info {
    use super::*;

    pub fn copy_buf<E: Arch>(ctx: &Context<E>, buf: &mut [u8]) {
        let data = &ctx.weak_bind_info.contents;
        buf[..data.len()].copy_from_slice(data);
    }
}

/// The lazy-bind opcode stream: one record per lazy pointer, entered
/// by its stub helper on first call.
#[derive(Debug)]
pub struct LazyBindInfoSection {
    pub hdr: ChunkHeader,
    /// The stream, built during layout, and each stub's record offset
    /// in it (what its stub helper entry pushes for dyld_stub_binder).
    pub contents: Vec<u8>,
    pub offsets: Vec<u32>,
}

impl LazyBindInfoSection {
    pub fn new() -> LazyBindInfoSection {
        LazyBindInfoSection { hdr: ChunkHeader::linkedit(), contents: Vec::new(), offsets: Vec::new() }
    }
}

pub mod lazy_bind_info {
    use super::*;

    pub fn copy_buf<E: Arch>(ctx: &Context<E>, buf: &mut [u8]) {
        let data = &ctx.lazy_bind_info.contents;
        buf[..data.len()].copy_from_slice(data);
    }
}
