//! Input sections.

use crate::macho::MachSection;

pub type InputSectionId = usize;

/// What a relocation refers to.
#[derive(Clone, Copy, Debug)]
pub enum RelocTarget {
    /// An index into the owning object's symbol list.
    Sym(usize),
    /// A subsection. During target-specific relocation reading this is
    /// an index into the object's section header list; input file
    /// parsing rewrites it to an index into the global subsection
    /// arena.
    Section(usize),
}

/// A relocation in a form independent of the raw Mach-O records: the
/// addend is explicit, and the target is a symbol or a section.
#[derive(Clone, Copy, Debug)]
pub struct Reloc {
    /// Offset within the containing section.
    pub offset: u32,
    pub r_type: u8,
    /// Size in bytes of the relocated field.
    pub size: u8,
    pub is_pcrel: bool,
    /// True if the previous record is a SUBTRACTOR paired with this one.
    pub is_subtracted: bool,
    pub target: RelocTarget,
    pub addend: i64,
    /// For a branch that may be out of range: the offset of a
    /// range-extension thunk entry within the output section, assigned
    /// during layout. u64::MAX when the branch needs no thunk.
    pub thunk_off: u64,
}

/// A subsection of an input object file's section.
///
/// Mach-O linking granularity is the subsection: objects are built with
/// MH_SUBSECTIONS_VIA_SYMBOLS, and each section is split at its symbols,
/// so that unreferenced pieces can be dead-stripped. `hdr` is the
/// containing section's header; `input_addr` and `size` delimit this
/// piece of it.
#[derive(Debug)]
pub struct InputSection {
    /// Index of the object file this section came from.
    pub obj: usize,
    pub hdr: MachSection,
    /// This subsection's address in the object's address space.
    pub input_addr: u64,
    pub size: u64,
    /// The subsection contents; empty for zero-fill sections.
    pub data: &'static [u8],
    /// This subsection's relocations: a range in the owning object's
    /// `relocs` arena, offsets relative to the subsection. sold keeps
    /// rel_offset/nrels per subsection the same way, rather than a Vec
    /// per subsection - a debug link has millions of relocations.
    pub rel_offset: u32,
    pub nrels: u32,
    /// The output section chunk this section is appended to.
    pub osec: usize,
    /// Offset from the start of the output section.
    pub output_offset: u64,
    /// The final output address. Layout visits one output section at a
    /// time and assigns its contents global addresses on the spot;
    /// everything that depends on code or data addresses (the trie,
    /// LINKEDIT streams) comes later in the file, so nothing is ever
    /// computed twice.
    pub addr: u64,
    pub is_alive: bool,
    /// For a literal merged with an identical one, the surviving copy.
    pub replacement: Option<usize>,
    /// This subsection's compact-unwind records: a range in
    /// ctx.unwind_records, as sold keeps unwind_offset/nunwind on each
    /// subsection (records arrive grouped by function).
    pub unwind_offset: u32,
    pub nunwind: u32,
}
