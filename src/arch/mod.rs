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

pub trait Arch: Copy + Default + Send + Sync + 'static {
    const NAME: &'static str;
    const CPUTYPE: u32;
    const CPUSUBTYPE: u32;
    const PAGE_SIZE: u64;

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
