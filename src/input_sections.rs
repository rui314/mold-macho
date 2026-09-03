//! Input sections.

use crate::macho::MachSection;

pub type InputSectionId = usize;

/// What a relocation refers to.
#[derive(Clone, Copy, Debug)]
pub enum RelocTarget {
    /// An index into the owning object's symbol list.
    Sym(u32),
    /// A subsection. During target-specific relocation reading this is
    /// an index into the object's section header list; input file
    /// parsing rewrites it to an index into the global subsection
    /// arena.
    Section(u32),
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
    /// The target, packed into one word: a symbol or subsection index
    /// in the low 31 bits, with `TARGET_SECTION` set for a subsection.
    /// Read through `target()`, write through `set_target()` or
    /// `RelocTarget::pack()`; as a two-word enum it padded the struct
    /// from 24 to 32 bytes, and a debug link holds ~12M of these.
    pub target: u32,
    pub addend: i64,
    /// For a branch that may be out of range: the offset of a
    /// range-extension thunk entry within the output section, assigned
    /// during layout. u32::MAX when the branch needs no thunk.
    pub thunk_off: u32,
}

// A Reloc is the size of an ELF RELA entry, which mold-rust reads from
// the mapping without materializing anything; Mach-O needs the record
// processed (ADDEND fusion, SUBTRACTOR pairing, subsection rebasing),
// so this is the form that processing produces.
const _: () = assert!(std::mem::size_of::<Reloc>() == 24);

const TARGET_SECTION: u32 = 1 << 31;

impl RelocTarget {
    #[inline]
    pub fn pack(self) -> u32 {
        match self {
            RelocTarget::Sym(i) => {
                debug_assert!(i & TARGET_SECTION == 0);
                i
            }
            RelocTarget::Section(i) => {
                debug_assert!(i & TARGET_SECTION == 0);
                i | TARGET_SECTION
            }
        }
    }
}

impl Reloc {
    #[inline]
    pub fn target(&self) -> RelocTarget {
        if self.target & TARGET_SECTION != 0 {
            RelocTarget::Section(self.target & !TARGET_SECTION)
        } else {
            RelocTarget::Sym(self.target)
        }
    }
    #[inline]
    pub fn set_target(&mut self, t: RelocTarget) {
        self.target = t.pack();
    }
}

/// A subsection of an input object file's section.
///
/// Mach-O linking granularity is the subsection: objects are built with
/// MH_SUBSECTIONS_VIA_SYMBOLS, and each section is split at its symbols,
/// so that unreferenced pieces can be dead-stripped. `hdr` is the
/// containing section's header; `input_addr` and `size` delimit this
/// piece of it.
/// Sentinel for `InputSection::replacement`: no surviving copy.
pub const NO_REPLACEMENT: u32 = u32::MAX;

#[derive(Debug)]
pub struct InputSection {
    /// Index of the object file this section came from (u32 to keep the
    /// struct small; `usize::MAX` becomes `u32::MAX` for a synthetic
    /// section with no object).
    pub obj: u32,
    /// The parent section's header. Subsections of one section share it,
    /// so it is referenced, not embedded - mold-rust keeps only a
    /// reference too. `p2align` is held inline because it is the one
    /// header field the linker raises per subsection.
    pub hdr: &'static MachSection,
    pub p2align: u8,
    /// This subsection's address in the object's address space. Object
    /// files stay well under 4 GiB, so a u32 holds it.
    pub input_addr: u32,
    pub size: u64,
    /// The subsection contents, as a bare pointer - the length is
    /// `size` - or 0 when there are none (a zero-fill or empty
    /// section). Stored as an integer, not a slice, to save 8 bytes and
    /// keep the struct trivially Send/Sync; read through `data()`.
    /// mold-rust likewise keeps `contents` as a bare address.
    pub data_ptr: usize,
    /// This subsection's relocations: a range in the owning object's
    /// `relocs` arena, offsets relative to the subsection. sold keeps
    /// rel_offset/nrels per subsection the same way, rather than a Vec
    /// per subsection - a debug link has millions of relocations.
    pub rel_offset: u32,
    pub nrels: u32,
    /// The output section chunk this section is appended to (u32 index;
    /// `u32::MAX` until assigned).
    pub osec: u32,
    /// Offset from the start of the output section (u32::MAX marks a
    /// subsection not yet placed, during thunk layout). An output
    /// section stays well under 4 GiB, so a u32 suffices.
    pub output_offset: u32,
    pub is_alive: bool,
    /// For a literal merged with an identical one, the surviving copy's
    /// subsection index, or `NO_REPLACEMENT`. A u32 sentinel rather than
    /// an `Option<usize>` (16 bytes) keeps the struct small.
    pub replacement: u32,
    /// This subsection's compact-unwind records: a range in
    /// ctx.unwind_records, as sold keeps unwind_offset/nunwind on each
    /// subsection (records arrive grouped by function).
    pub unwind_offset: u32,
    pub nunwind: u32,
}

// InputSection is the highest-count struct in a link (millions on a
// debug build), so it is kept compact - mold-rust's is 64 bytes; ours
// carries a few Mach-O-specific fields more.
const _: () = assert!(std::mem::size_of::<InputSection>() == 64);

impl InputSection {
    /// This subsection's bytes. Empty for a zero-fill or empty section;
    /// otherwise the `size` bytes at `data_ptr` (which point into the
    /// mmap'd input, so they live for the whole link).
    #[inline]
    pub fn data(&self) -> &'static [u8] {
        if self.data_ptr == 0 {
            &[]
        } else {
            // SAFETY: for a non-empty section data_ptr is the start of
            // `size` valid bytes in the leaked/mmap'd input, and every
            // such section is built with size == contents.len().
            unsafe { std::slice::from_raw_parts(self.data_ptr as *const u8, self.size as usize) }
        }
    }
}
