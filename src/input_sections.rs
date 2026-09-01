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
    /// Relocations, with offsets relative to this subsection.
    pub relocs: Vec<Reloc>,
    /// The output section chunk this section is appended to.
    pub osec: usize,
    /// Offset from the start of the output section.
    pub output_offset: u64,
    pub is_alive: bool,
    /// For a literal merged with an identical one, the surviving copy.
    pub replacement: Option<usize>,
}
