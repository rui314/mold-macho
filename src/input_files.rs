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

    if let Some(hdr) = sect_hdrs
        .iter()
        .find(|s| s.segname() == "__LD" && s.sectname() == "__compact_unwind")
    {
        parse_compact_unwind(ctx, hdr, &sect_hdrs, &sections, &syms, &nlists, data, &mf.name);
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
            let sym = &mut ctx.symtab[id];
            sym.is_used = true;
            // A common symbol is a tentative definition: any real
            // definition beats it, and the largest tentative size wins.
            if nlist.is_common() && !sym.is_defined() {
                sym.is_common = true;
                sym.value = sym.value.max(nlist.n_value);
                sym.common_p2align = sym.common_p2align.max(((nlist.n_desc >> 8) & 0xf) as u8);
            }
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
                    sym.is_common = false;
                }
            }
        }
        _ => fatal!(ctx, "{file_name}: unsupported symbol type for {name}"),
    }
    id
}

/// A record from a __compact_unwind section, describing how to unwind
/// the stack through one function.
#[derive(Clone, Debug)]
pub struct UnwindRecord {
    /// The input section holding the function.
    pub isec: usize,
    /// The function's offset within `isec`.
    pub input_offset: u32,
    pub code_len: u32,
    pub encoding: u32,
    pub personality: Option<SymbolId>,
    /// The language-specific data area: an input section and an offset
    /// within it.
    pub lsda: Option<(usize, u32)>,
}

/// Parses a __LD,__compact_unwind section into unwind records. The
/// section is an array of 32-byte entries whose pointer fields are set by
/// relocations.
fn parse_compact_unwind<E: Arch>(
    ctx: &mut Context<E>,
    hdr: &MachSection,
    sect_hdrs: &[MachSection],
    sections: &[Option<usize>],
    syms: &[SymbolId],
    nlists: &[NList],
    data: &'static [u8],
    file_name: &str,
) {
    const ENTRY_SIZE: usize = 32;
    if hdr.size % ENTRY_SIZE as u64 != 0 {
        fatal!(ctx, "{file_name}: invalid __compact_unwind section size");
    }

    let read_u64 = |off: u64| {
        let off = (hdr.offset as u64 + off) as usize;
        u64::from_le_bytes(data[off..off + 8].try_into().unwrap())
    };

    let num_entries = (hdr.size / ENTRY_SIZE as u64) as usize;
    let mut records = Vec::with_capacity(num_entries);
    for i in 0..num_entries {
        records.push(UnwindRecord {
            isec: usize::MAX,
            input_offset: 0,
            code_len: u32::from_le_bytes({
                let off = hdr.offset as usize + i * ENTRY_SIZE + 8;
                data[off..off + 4].try_into().unwrap()
            }),
            encoding: u32::from_le_bytes({
                let off = hdr.offset as usize + i * ENTRY_SIZE + 12;
                data[off..off + 4].try_into().unwrap()
            }),
            personality: None,
            lsda: None,
        });
    }

    // A section and the offset within it, for an address in the object.
    let find_section = |addr: u64| -> Option<(usize, u32)> {
        let idx = sect_hdrs
            .iter()
            .position(|sec| sec.addr <= addr && addr < sec.addr + sec.size)?;
        Some((sections[idx]?, (addr - sect_hdrs[idx].addr) as u32))
    };

    let rels: Vec<MachRel> = read_array(data, hdr.reloff as usize, hdr.nreloc as usize);
    for r in &rels {
        if r.r_address as u64 >= hdr.size || r.r_length() != 3 {
            fatal!(ctx, "{file_name}: __compact_unwind: unsupported relocation");
        }
        let idx = r.r_address as usize / ENTRY_SIZE;
        let value = read_u64(r.r_address as u64);

        match r.r_address as usize % ENTRY_SIZE {
            // The function the record covers
            0 => {
                if r.is_extern() {
                    let sym = &ctx.symtab[syms[r.r_symbolnum() as usize]];
                    let Some(isec) = sym.isec else {
                        fatal!(ctx, "{file_name}: __compact_unwind: bad function reference");
                    };
                    records[idx].isec = isec;
                    records[idx].input_offset = (sym.value + value) as u32;
                } else {
                    let Some((isec, off)) = find_section(value) else {
                        fatal!(ctx, "{file_name}: __compact_unwind: bad function reference");
                    };
                    records[idx].isec = isec;
                    records[idx].input_offset = off;
                }
            }
            // The personality function
            16 => {
                let sym = if r.is_extern() {
                    Some(syms[r.r_symbolnum() as usize])
                } else {
                    // Resolve a section-relative reference back to the
                    // symbol at that address.
                    nlists
                        .iter()
                        .position(|n| n.is_extern() && n.n_value == value)
                        .map(|i| syms[i])
                };
                let Some(sym) = sym else {
                    fatal!(ctx, "{file_name}: __compact_unwind: unsupported personality");
                };
                records[idx].personality = Some(sym);
            }
            // The language-specific data area
            24 => {
                if r.is_extern() {
                    let sym = &ctx.symtab[syms[r.r_symbolnum() as usize]];
                    let Some(isec) = sym.isec else {
                        fatal!(ctx, "{file_name}: __compact_unwind: bad LSDA reference");
                    };
                    records[idx].lsda = Some((isec, (sym.value + value) as u32));
                } else {
                    let Some(lsda) = find_section(value) else {
                        fatal!(ctx, "{file_name}: __compact_unwind: bad LSDA reference");
                    };
                    records[idx].lsda = Some(lsda);
                }
            }
            _ => fatal!(ctx, "{file_name}: __compact_unwind: unsupported relocation"),
        }
    }

    // Ignore records that point to DWARF unwind info; those are
    // synthesized from __eh_frame instead. Object files usually don't
    // contain such records, but `ld -r` output does.
    records.retain(|rec| {
        rec.isec != usize::MAX && (rec.encoding & UNWIND_MODE_MASK) != E::UNWIND_MODE_DWARF
    });
    ctx.unwind_records.extend(records);
}

/// Splits an archive into its members. Members use the BSD convention:
/// a name of "#1/<len>" means the real name is the first <len> bytes of
/// the member data.
pub fn read_archive_members<E: Arch>(
    ctx: &Context<E>,
    mf: &'static MappedFile,
) -> Vec<&'static MappedFile> {
    let data = mf.data;
    let mut members = Vec::new();
    let mut off = 8;

    while off + 60 <= data.len() {
        let hdr = &data[off..off + 60];
        let field = |range: std::ops::Range<usize>| {
            std::str::from_utf8(&hdr[range])
                .unwrap_or("")
                .trim_end()
                .to_string()
        };
        let name = field(0..16);
        let Ok(size) = field(48..58).parse::<usize>() else {
            fatal!(ctx, "{}: malformed archive member header", mf.name);
        };

        let mut body = off + 60;
        let mut body_size = size;
        let name = if let Some(len) = name.strip_prefix("#1/") {
            let Ok(len) = len.parse::<usize>() else {
                fatal!(ctx, "{}: malformed archive member name", mf.name);
            };
            let raw = &data[body..body + len];
            body += len;
            body_size -= len;
            let end = raw.iter().position(|&b| b == 0).unwrap_or(len);
            String::from_utf8_lossy(&raw[..end]).into_owned()
        } else {
            name
        };

        if !name.starts_with("__.SYMDEF") {
            let full_name = format!("{}({})", mf.name, name);
            members.push(mf.slice(full_name, &data[body..body + body_size]));
        }

        off += 60 + size;
        off += off & 1; // members are aligned to even offsets
    }
    members
}

/// Returns the names of the global symbols an object file defines,
/// without creating any linker state. Used to decide whether to load an
/// archive member.
pub fn defined_symbol_names(mf: &MappedFile) -> Vec<&'static str> {
    let data = mf.data;
    let hdr = MachHeader::read_from(data);
    let mut names = Vec::new();

    let mut off = size_of::<MachHeader>();
    for _ in 0..hdr.ncmds {
        let lc = LoadCommand::read_from(&data[off..]);
        if lc.cmd == LC_SYMTAB {
            let cmd = SymtabCommand::read_from(&data[off..]);
            let nlists: Vec<NList> = read_array(data, cmd.symoff as usize, cmd.nsyms as usize);
            let strtab: &[u8] =
                &data[cmd.stroff as usize..(cmd.stroff + cmd.strsize) as usize];
            // SAFETY: input files are leaked, so the string table lives
            // for the rest of the process.
            let strtab: &'static [u8] = unsafe { std::mem::transmute(strtab) };
            for nlist in &nlists {
                if !nlist.is_stab()
                    && nlist.is_extern()
                    && (nlist.n_type() != N_UNDF || nlist.is_common())
                {
                    names.push(symbol_name(strtab, nlist));
                }
            }
        }
        off += lc.cmdsize as usize;
    }
    names
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

/// Parses a Mach-O dylib binary: its identity from LC_ID_DYLIB and its
/// exported symbols. The defined-external range of the symbol table
/// serves as the export list; the authoritative source is the export
/// trie, but the symbol table matches it for the dylibs we link against.
pub fn parse_dylib_binary<E: Arch>(ctx: &mut Context<E>, mf: &'static MappedFile) -> usize {
    let data = mf.data;
    let hdr = MachHeader::read_from(data);

    let mut install_name = String::new();
    let mut current_version = encode_version(1, 0, 0);
    let mut compatibility_version = encode_version(1, 0, 0);
    let mut symtab_cmd = None;
    let mut dysymtab_cmd = None;

    let mut off = size_of::<MachHeader>();
    for _ in 0..hdr.ncmds {
        let lc = LoadCommand::read_from(&data[off..]);
        match lc.cmd {
            LC_ID_DYLIB => {
                let cmd = DylibCommand::read_from(&data[off..]);
                let name = &data[off + cmd.nameoff as usize..off + cmd.cmdsize as usize];
                let len = name.iter().position(|&b| b == 0).unwrap_or(name.len());
                install_name = String::from_utf8_lossy(&name[..len]).into_owned();
                current_version = cmd.current_version;
                compatibility_version = cmd.compatibility_version;
            }
            LC_SYMTAB => symtab_cmd = Some(SymtabCommand::read_from(&data[off..])),
            LC_DYSYMTAB => dysymtab_cmd = Some(DysymtabCommand::read_from(&data[off..])),
            _ => {}
        }
        off += lc.cmdsize as usize;
    }

    if install_name.is_empty() {
        fatal!(ctx, "{}: dylib has no LC_ID_DYLIB", mf.name);
    }

    let mut exports = std::collections::HashSet::new();
    if let (Some(sym), Some(dysym)) = (symtab_cmd, dysymtab_cmd) {
        let nlists: Vec<NList> = read_array(data, sym.symoff as usize, sym.nsyms as usize);
        let strtab = &data[sym.stroff as usize..(sym.stroff + sym.strsize) as usize];
        // SAFETY: input files are leaked, so the string table lives for
        // the rest of the process.
        let strtab: &'static [u8] = unsafe { std::mem::transmute(strtab) };
        let range = dysym.iextdefsym as usize..(dysym.iextdefsym + dysym.nextdefsym) as usize;
        for nlist in &nlists[range] {
            exports.insert(symbol_name(strtab, nlist).to_string());
        }
    }

    let idx = ctx.dylibs.len();
    ctx.dylibs.push(DylibFile {
        install_name,
        current_version,
        compatibility_version,
        dylib_idx: idx as i32 + 1,
        exports,
    });
    idx
}

/// Locates the stub or binary for a reexported library's install name
/// under the syslibroot.
fn find_reexport_file<E: Arch>(
    ctx: &Context<E>,
    install_name: &str,
) -> Option<&'static MappedFile> {
    let roots: Vec<String> = if ctx.args.syslibroot.is_empty() {
        vec![String::new()]
    } else {
        ctx.args.syslibroot.clone()
    };

    for root in &roots {
        let base = std::path::Path::new(root).join(install_name.trim_start_matches('/'));
        let mut candidates = vec![base.with_extension("tbd")];
        candidates.push(std::path::PathBuf::from(format!("{}.tbd", base.display())));
        candidates.push(base);
        for path in candidates {
            if let Some(mf) = MappedFile::open(&ctx.diag, &path) {
                return Some(mf);
            }
        }
    }
    None
}

pub fn parse_dylib<E: Arch>(ctx: &mut Context<E>, mf: &'static MappedFile) -> usize {
    let tbd = tapi::parse(&ctx.diag, mf);
    let idx = ctx.dylibs.len();
    let mut exports: std::collections::HashSet<String> =
        tbd.exports.into_iter().collect();
    exports.extend(tbd.weak_exports);

    // A dylib's reexported libraries resolve through it in the two-level
    // namespace, so their exports count as this dylib's. Reexports not
    // inlined in this .tbd are separate files, possibly reexporting
    // further.
    let mut queue = tbd.external_reexports;
    let mut visited = std::collections::HashSet::new();
    while let Some(name) = queue.pop() {
        if !visited.insert(name.clone()) {
            continue;
        }
        let Some(dep) = find_reexport_file(ctx, &name) else {
            crate::warn!(ctx, "{}: reexported library not found: {}", mf.name, name);
            continue;
        };
        let dep_tbd = tapi::parse(&ctx.diag, dep);
        exports.extend(dep_tbd.exports);
        exports.extend(dep_tbd.weak_exports);
        queue.extend(dep_tbd.external_reexports);
    }

    ctx.dylibs.push(DylibFile {
        install_name: tbd.install_name,
        current_version: tbd.current_version,
        compatibility_version: encode_version(1, 0, 0),
        dylib_idx: idx as i32 + 1,
        exports,
    });
    idx
}
