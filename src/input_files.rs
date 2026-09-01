//! Input file parsing: object files, dylib stubs and archives.

use crate::arch::Arch;
use crate::context::Context;
use crate::error;
use crate::fatal;
use crate::input_sections::InputSection;
use crate::macho::*;
use crate::mapped_file::MappedFile;
use crate::symbol::{Origin, SymbolId};
use crate::tapi;

/// A relocatable object file.
#[derive(Debug)]
pub struct ObjectFile {
    pub mf: &'static MappedFile,
    /// Section headers in ordinal order (all segments' sections
    /// concatenated in load command order).
    pub sect_hdrs: Vec<MachSection>,
    /// The input section for each header; None for discarded sections
    /// such as debug info.
    pub sections: Vec<Option<usize>>,
    pub nlists: Vec<NList>,
    /// The symbol slot for each nlist entry.
    pub syms: Vec<SymbolId>,
}

/// A dynamic library, from a .tbd stub or a dylib binary.
#[derive(Debug)]
pub struct DylibFile {
    pub install_name: String,
    pub current_version: u32,
    pub compatibility_version: u32,
    /// The 1-based ordinal used to refer to this dylib in bind records.
    pub dylib_idx: i32,
    pub exports: std::collections::HashSet<String>,
}

/// Returns true for sections that don't become part of the output image.
fn is_discarded_section(hdr: &MachSection) -> bool {
    // Debug sections, including __LD,__compact_unwind, are consumed by
    // other tools or, later, by the linker itself; they are never copied
    // to the output.
    hdr.flags & S_ATTR_DEBUG != 0 || hdr.segname() == "__DWARF" || hdr.segname() == "__LD"
}

pub fn parse_object<E: Arch>(ctx: &mut Context<E>, mf: &'static MappedFile) -> usize {
    let data = mf.data;
    let hdr = MachHeader::read_from(data);

    if hdr.cputype != E::CPUTYPE {
        fatal!(
            ctx,
            "{}: incompatible CPU type: expected {}",
            mf.name,
            E::NAME
        );
    }

    let obj_idx = ctx.objs.len();
    let mut sect_hdrs = Vec::new();
    let mut symtab_cmd = None;

    // Read load commands
    let mut off = size_of::<MachHeader>();
    for _ in 0..hdr.ncmds {
        let lc = LoadCommand::read_from(&data[off..]);
        match lc.cmd {
            LC_SEGMENT_64 => {
                let seg = SegmentCommand::read_from(&data[off..]);
                for i in 0..seg.nsects as usize {
                    let sect_off =
                        off + size_of::<SegmentCommand>() + i * size_of::<MachSection>();
                    sect_hdrs.push(MachSection::read_from(&data[sect_off..]));
                }
            }
            LC_SYMTAB => symtab_cmd = Some(SymtabCommand::read_from(&data[off..])),
            _ => {}
        }
        off += lc.cmdsize as usize;
    }

    // Create input sections
    let mut sections = Vec::with_capacity(sect_hdrs.len());
    for sect in &sect_hdrs {
        if is_discarded_section(sect) {
            sections.push(None);
            continue;
        }

        let contents = if sect.section_type() == S_ZEROFILL {
            &[]
        } else {
            &data[sect.offset as usize..(sect.offset as u64 + sect.size) as usize]
        };

        let rels: Vec<MachRel> =
            read_array(data, sect.reloff as usize, sect.nreloc as usize);
        let relocs = E::read_relocs(&ctx.diag, &mf.name, &sect_hdrs, sect, data, &rels);

        ctx.isecs.push(InputSection {
            obj: obj_idx,
            hdr: *sect,
            data: contents,
            relocs,
            osec: usize::MAX,
            output_offset: 0,
        });
        sections.push(Some(ctx.isecs.len() - 1));
    }

    // Read symbols
    let mut nlists: Vec<NList> = Vec::new();
    let mut strtab: &'static [u8] = &[];
    if let Some(cmd) = symtab_cmd {
        nlists = read_array(data, cmd.symoff as usize, cmd.nsyms as usize);
        strtab = &data[cmd.stroff as usize..(cmd.stroff + cmd.strsize) as usize];
    }

    let mut syms = Vec::with_capacity(nlists.len());
    for nlist in &nlists {
        syms.push(parse_symbol(ctx, obj_idx, &sect_hdrs, &sections, strtab, nlist, &mf.name));
    }

    ctx.objs.push(ObjectFile {
        mf,
        sect_hdrs,
        sections,
        nlists,
        syms,
    });
    obj_idx
}

fn symbol_name(strtab: &'static [u8], nlist: &NList) -> &'static str {
    let off = nlist.n_strx as usize;
    let rest = &strtab[off..];
    let len = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
    std::str::from_utf8(&rest[..len]).unwrap_or("")
}

fn parse_symbol<E: Arch>(
    ctx: &mut Context<E>,
    obj_idx: usize,
    sect_hdrs: &[MachSection],
    sections: &[Option<usize>],
    strtab: &'static [u8],
    nlist: &NList,
    file_name: &str,
) -> SymbolId {
    let name = symbol_name(strtab, nlist);

    if nlist.is_stab() {
        return ctx.symtab.add_local(name);
    }

    let id = if nlist.is_extern() {
        ctx.symtab.intern(name)
    } else {
        ctx.symtab.add_local(name)
    };

    match nlist.n_type() {
        N_UNDF => {
            // The definition may come from another file; leave the slot
            // as it is, but remember that it is referenced.
            ctx.symtab[id].is_used = true;
        }
        N_ABS => {
            let sym = &mut ctx.symtab[id];
            if let Origin::Obj(_) = sym.origin {
                error!(ctx, "duplicate symbol: {name}");
            } else {
                let sym = &mut ctx.symtab[id];
                sym.origin = Origin::Obj(obj_idx);
                sym.isec = None;
                sym.value = nlist.n_value;
                sym.is_extern = nlist.is_extern();
            }
        }
        N_SECT => {
            let sect_idx = nlist.n_sect as usize - 1;
            let Some(&isec) = sections.get(sect_idx) else {
                fatal!(ctx, "{file_name}: invalid section index for {name}");
            };
            // A symbol in a discarded section (e.g. a debug section
            // label) is not defined.
            let Some(isec) = isec else {
                return id;
            };

            let is_weak = nlist.n_desc & N_WEAK_DEF != 0;
            let sym = &ctx.symtab[id];
            match sym.origin {
                Origin::Obj(_) if !sym.is_weak_def && !is_weak => {
                    error!(ctx, "duplicate symbol: {name}");
                }
                Origin::Obj(_) if is_weak => {
                    // Keep the existing definition.
                }
                _ => {
                    let value = nlist.n_value - sect_hdrs[sect_idx].addr;
                    let sym = &mut ctx.symtab[id];
                    sym.origin = Origin::Obj(obj_idx);
                    sym.isec = Some(isec);
                    sym.value = value;
                    sym.is_extern = nlist.is_extern();
                    sym.is_weak_def = is_weak;
                    sym.is_imported = false;
                }
            }
        }
        _ => fatal!(ctx, "{file_name}: unsupported symbol type for {name}"),
    }
    id
}

/// Returns the slice of a fat (universal) file matching the target's CPU
/// type. Fat headers are big-endian.
pub fn get_fat_slice<E: Arch>(
    ctx: &Context<E>,
    mf: &'static MappedFile,
) -> &'static MappedFile {
    let data = mf.data;
    let read_be32 =
        |off: usize| u32::from_be_bytes(data[off..off + 4].try_into().unwrap());

    let nfat_arch = read_be32(4) as usize;
    for i in 0..nfat_arch {
        let off = 8 + i * 20;
        if read_be32(off) == E::CPUTYPE {
            let obj_off = read_be32(off + 8) as usize;
            let obj_size = read_be32(off + 12) as usize;
            let name = format!("{}(for architecture {})", mf.name, E::NAME);
            return mf.slice(name, &data[obj_off..obj_off + obj_size]);
        }
    }
    fatal!(ctx, "{}: fat file does not contain {}", mf.name, E::NAME);
}

pub fn parse_dylib<E: Arch>(ctx: &mut Context<E>, mf: &'static MappedFile) -> usize {
    let tbd = tapi::parse(&ctx.diag, mf);
    let idx = ctx.dylibs.len();
    let mut exports: std::collections::HashSet<String> =
        tbd.exports.into_iter().collect();
    exports.extend(tbd.weak_exports);
    ctx.dylibs.push(DylibFile {
        install_name: tbd.install_name,
        current_version: tbd.current_version,
        compatibility_version: encode_version(1, 0, 0),
        dylib_idx: idx as i32 + 1,
        exports,
    });
    idx
}
