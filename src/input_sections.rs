//! Input sections.

use crate::macho::MachSection;

pub type InputSectionId = usize;

/// What a relocation refers to.
#[derive(Clone, Copy, Debug)]
pub enum RelocTarget {
    /// An index into the owning object's symbol list.
    Sym(usize),
    /// An index into the owning object's section list.
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

/// A section from an input object file.
#[derive(Debug)]
pub struct InputSection {
    /// Index of the object file this section came from.
    pub obj: usize,
    pub hdr: MachSection,
    /// The section contents; empty for zero-fill sections.
    pub data: &'static [u8],
    pub relocs: Vec<Reloc>,
    /// The output section chunk this section is appended to.
    pub osec: usize,
    /// Offset from the start of the output section.
    pub output_offset: u64,
}
