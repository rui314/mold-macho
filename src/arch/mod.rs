//! Target architecture abstraction.
//!
//! The linker is generic over [`Arch`], which selects a CPU type and the
//! target-dependent relocation handling. Each target is instantiated in a
//! crate of its own under targets/.

mod arm64;
mod x86_64;

pub use arm64::Arm64;
pub use x86_64::X86_64;

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
    /// A load through the GOT that can relax to a direct address
    /// computation when the target is local.
    GotLoad,
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
    /// The span a branch instruction can cover (both directions
    /// together), and the size of one range-extension thunk entry.
    const BRANCH_RANGE: u64;
    const THUNK_SIZE: u64;
    /// The relocation types for a plain absolute word, a subtraction
    /// pair, and a GOT-relative pointer.
    const RELOC_UNSIGNED: u8;
    const RELOC_SUBTRACTOR: u8;
    const RELOC_GOTPC: u8;
    /// The explicit-addend relocation type, for targets that have one.
    const RELOC_ADDEND: u8;

    /// Whether re-emitting this relocation type in a relocatable output
    /// needs an explicit addend record when its addend is nonzero.
    fn relocatable_needs_addend(r_type: u8) -> bool;

    /// Classifies a relocation type by how it uses its target.
    fn classify_reloc(r_type: u8) -> RelocClass;

    /// True if the GotLoad relocation at `offset` sits on the
    /// instruction shape the relaxation rewrites.
    fn can_relax_got_load(data: &[u8], offset: u32, r_type: u8) -> bool;

    /// Writes the __stubs section: for each symbol in `ctx.stub_syms`, a
    /// jump through the symbol's __got slot. `addr` is the section's
    /// address and `buf` its bytes in the output.
    fn write_stubs(ctx: &Context<Self>, addr: u64, buf: &mut [u8]);

    /// Writes the __objc_stubs section: for each _objc_msgSend$<sel>
    /// symbol, code that loads the selector from its __objc_selrefs
    /// slot and tail-calls _objc_msgSend through the GOT.
    fn write_objc_stubs(ctx: &Context<Self>, addr: u64, buf: &mut [u8]);

    /// Writes one range-extension thunk's entries. `addr` is the
    /// thunk's address and `buf` its bytes.
    fn write_thunk(ctx: &Context<Self>, addr: u64, syms: &[crate::symbol::SymbolId], buf: &mut [u8]);

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
    /// in the output. `isec` is the subsection's arena index and `base`
    /// its output address.
    fn apply_relocs(ctx: &Context<Self>, rels: &[Reloc], isec: usize, base: u64, buf: &mut [u8]);

    /// Applies LC_LINKER_OPTIMIZATION_HINT rewrites after relocation.
    /// Only arm64 defines hints; the default does nothing.
    fn apply_optimization_hints(_ctx: &Context<Self>, _buf: &mut [u8]) {}
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
