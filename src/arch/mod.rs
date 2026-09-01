//! Target architecture abstraction.
//!
//! The linker is generic over [`Arch`], which selects a CPU type and the
//! target-dependent relocation handling. Each target is instantiated in a
//! crate of its own under targets/.

mod arm64;

pub use arm64::Arm64;

use crate::context::Context;
use crate::error::Diagnostics;
use crate::input_sections::Reloc;
use crate::macho::{MachRel, MachSection};

/// How a relocation type uses its target symbol.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelocClass {
    /// A branch, which needs a stub if the target is imported.
    Branch,
    /// A reference through the GOT.
    Got,
    /// A reference to a thread-local variable pointer.
    Tlv,
    /// A direct reference.
    Plain,
}

pub trait Arch: Copy + Default + Send + Sync + 'static {
    const NAME: &'static str;
    const CPUTYPE: u32;
    const CPUSUBTYPE: u32;
    const PAGE_SIZE: u64;
    /// The size of one __stubs entry.
    const STUB_SIZE: u64;
    /// The compact unwind encoding mode meaning "use DWARF instead".
    const UNWIND_MODE_DWARF: u32;
    /// The size of one __objc_stubs entry.
    const OBJC_STUB_SIZE: u64;
    /// The relocation types for a plain absolute word, a subtraction
    /// pair, and a GOT-relative pointer.
    const RELOC_UNSIGNED: u8;
    const RELOC_SUBTRACTOR: u8;
    const RELOC_GOTPC: u8;

    /// Classifies a relocation type by how it uses its target.
    fn classify_reloc(r_type: u8) -> RelocClass;

    /// Writes the __stubs section: for each symbol in `ctx.stub_syms`, a
    /// jump through the symbol's __got slot. `addr` is the section's
    /// address and `buf` its bytes in the output.
    fn write_stubs(ctx: &Context<Self>, addr: u64, buf: &mut [u8]);

    /// Writes the __objc_stubs section: for each _objc_msgSend$<sel>
    /// symbol, code that loads the selector from its __objc_selrefs
    /// slot and tail-calls _objc_msgSend through the GOT.
    fn write_objc_stubs(ctx: &Context<Self>, addr: u64, buf: &mut [u8]);

    /// Converts raw relocation records of one input section into
    /// [`Reloc`]s. Mach-O encodes addends target-dependently: some are
    /// embedded in the relocated field, some are separate records.
    fn read_relocs(
        diag: &Diagnostics,
        file_name: &str,
        sections: &[MachSection],
        hdr: &MachSection,
        file_data: &[u8],
        rels: &[MachRel],
    ) -> Vec<Reloc>;

    /// Applies the relocations of one input section to `buf`, its bytes
    /// in the output. `obj` is the object the section came from and
    /// `base` the output address of the section.
    fn apply_relocs(ctx: &Context<Self>, rels: &[Reloc], obj: usize, base: u64, buf: &mut [u8]);
}

/// Returns the target name for a Mach-O CPU type, if we know it.
pub fn cputype_name(cputype: u32) -> Option<&'static str> {
    use crate::macho::*;
    match cputype {
        CPU_TYPE_ARM64 => Some("arm64"),
        CPU_TYPE_X86_64 => Some("x86_64"),
        _ => None,
    }
}
