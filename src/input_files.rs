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
    /// All of this object's subsections, sorted by input address.
    pub subsecs: Vec<usize>,
    pub nlists: Vec<NList>,
    /// The symbol slot for each nlist entry.
    pub syms: Vec<SymbolId>,
}

/// Finds the subsection containing `addr` among `subsecs` (sorted by
/// input address), returning it with the offset within it.
pub fn find_subsec(
    isecs: &[InputSection],
    subsecs: &[usize],
    addr: u64,
) -> Option<(usize, u64)> {
    let i = subsecs.partition_point(|&id| isecs[id].input_addr <= addr);
    if i == 0 {
        return None;
    }
    let id = subsecs[i - 1];
    let isec = &isecs[id];
    if addr < isec.input_addr + isec.size || (isec.size == 0 && addr == isec.input_addr) {
        Some((id, addr - isec.input_addr))
    } else {
        None
    }
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

    // Read the symbol table
    let mut nlists: Vec<NList> = Vec::new();
    let mut strtab: &'static [u8] = &[];
    if let Some(cmd) = symtab_cmd {
        nlists = read_array(data, cmd.symoff as usize, cmd.nsyms as usize);
        strtab = &data[cmd.stroff as usize..(cmd.stroff + cmd.strsize) as usize];
    }

    // Split each section into subsections at its symbols, the Mach-O
    // linking granularity, so that unreferenced pieces can later be
    // dead-stripped. Alternate entry points (N_ALT_ENTRY) don't start a
    // new subsection, and literal sections are element-oriented rather
    // than symbol-oriented, so they stay whole.
    let split_ok = hdr.flags & MH_SUBSECTIONS_VIA_SYMBOLS != 0;
    let mut split_points: Vec<Vec<u64>> = vec![Vec::new(); sect_hdrs.len()];
    if split_ok {
        for nlist in &nlists {
            if !nlist.is_stab()
                && nlist.n_type() == N_SECT
                && nlist.n_desc & N_ALT_ENTRY == 0
                && nlist.n_sect >= 1
            {
                if let Some(points) = split_points.get_mut(nlist.n_sect as usize - 1) {
                    points.push(nlist.n_value);
                }
            }
        }
    }

    let is_literal = |sect: &MachSection| {
        matches!(
            sect.section_type(),
            S_CSTRING_LITERALS
                | S_4BYTE_LITERALS
                | S_8BYTE_LITERALS
                | S_16BYTE_LITERALS
                | S_LITERAL_POINTERS
        )
    };

    // Subsections of each section, by section ordinal.
    let mut by_ordinal: Vec<Vec<usize>> = vec![Vec::new(); sect_hdrs.len()];
    let mut subsecs: Vec<usize> = Vec::new();

    for (i, sect) in sect_hdrs.iter().enumerate() {
        if is_discarded_section(sect)
            || (sect.segname() == "__TEXT" && sect.sectname() == "__eh_frame")
        {
            continue;
        }

        let mut points = std::mem::take(&mut split_points[i]);
        if is_literal(sect) {
            points.clear();
        }
        points.push(sect.addr);
        points.retain(|&a| sect.addr <= a && a <= sect.addr + sect.size);
        points.sort_unstable();
        points.dedup();

        for (j, &start) in points.iter().enumerate() {
            let end = points.get(j + 1).copied().unwrap_or(sect.addr + sect.size);
            let contents = if sect.section_type() == S_ZEROFILL
                || sect.section_type() == S_THREAD_LOCAL_ZEROFILL
            {
                &[]
            } else {
                let lo = sect.offset as u64 + (start - sect.addr);
                &data[lo as usize..(lo + (end - start)) as usize]
            };
            ctx.isecs.push(InputSection {
                obj: obj_idx,
                hdr: *sect,
                input_addr: start,
                size: end - start,
                data: contents,
                relocs: Vec::new(),
                osec: usize::MAX,
                output_offset: 0,
                is_alive: true,
            });
            by_ordinal[i].push(ctx.isecs.len() - 1);
            subsecs.push(ctx.isecs.len() - 1);
        }
    }

    subsecs.sort_by_key(|&id| ctx.isecs[id].input_addr);

    // Read each section's relocations and distribute them to its
    // subsections, rebasing location offsets and section-relative
    // targets to subsections.
    for (i, sect) in sect_hdrs.iter().enumerate() {
        if by_ordinal[i].is_empty() || sect.nreloc == 0 {
            continue;
        }
        let raw: Vec<MachRel> = read_array(data, sect.reloff as usize, sect.nreloc as usize);
        let rels = E::read_relocs(&ctx.diag, &mf.name, &sect_hdrs, sect, data, &raw);

        for mut rel in rels {
            let loc_addr = sect.addr + rel.offset as u64;
            let Some((sub, sub_off)) = find_subsec(&ctx.isecs, &by_ordinal[i], loc_addr)
            else {
                fatal!(ctx, "{}: relocation outside its section", mf.name);
            };
            rel.offset = sub_off as u32;

            if let crate::input_sections::RelocTarget::Section(sect_pos) = rel.target {
                let taddr = (sect_hdrs[sect_pos].addr as i64 + rel.addend) as u64;
                let Some((tsub, toff)) = find_subsec(&ctx.isecs, &subsecs, taddr) else {
                    fatal!(ctx, "{}: relocation against a discarded section", mf.name);
                };
                rel.target = crate::input_sections::RelocTarget::Section(tsub);
                rel.addend = toff as i64;
            }
            ctx.isecs[sub].relocs.push(rel);
        }
    }

    // Parse symbols
    let mut syms = Vec::with_capacity(nlists.len());
    for nlist in &nlists {
        syms.push(parse_symbol(
            ctx, obj_idx, &by_ordinal, strtab, nlist, &mf.name,
        ));
    }

    let unwind_start = ctx.unwind_records.len();
    if let Some(hdr) = sect_hdrs
        .iter()
        .find(|s| s.segname() == "__LD" && s.sectname() == "__compact_unwind")
    {
        parse_compact_unwind(ctx, hdr, &subsecs, &syms, &nlists, data, &mf.name);
    }

    if let Some(hdr) = sect_hdrs
        .iter()
        .find(|s| s.segname() == "__TEXT" && s.sectname() == "__eh_frame")
    {
        parse_eh_frame(
            ctx,
            obj_idx,
            hdr,
            &subsecs,
            &syms,
            &nlists,
            data,
            unwind_start,
            &mf.name,
        );
    }

    ctx.objs.push(ObjectFile {
        mf,
        sect_hdrs,
        subsecs,
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
    by_ordinal: &[Vec<usize>],
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
            if nlist.n_desc & N_WEAK_REF != 0 {
                sym.is_weak_ref = true;
            }
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
            let Some(subsecs) = by_ordinal.get(nlist.n_sect as usize - 1) else {
                fatal!(ctx, "{file_name}: invalid section index for {name}");
            };
            // A symbol in a discarded section (e.g. a debug section
            // label) is not defined.
            let Some((isec, value)) = find_subsec(&ctx.isecs, subsecs, nlist.n_value)
            else {
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
                    let sym = &mut ctx.symtab[id];
                    sym.origin = Origin::Obj(obj_idx);
                    sym.isec = Some(isec);
                    sym.value = value;
                    sym.is_extern = nlist.is_extern();
                    sym.is_weak_def = is_weak;
                    sym.is_imported = false;
                    sym.is_common = false;
                    sym.no_dead_strip =
                        nlist.n_desc & (N_NO_DEAD_STRIP | REFERENCED_DYNAMICALLY) != 0;
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
    /// For a record synthesized from DWARF unwind info, the FDE it
    /// points to (an index into `ctx.fdes`).
    pub fde: Option<usize>,
}

/// Parses a __LD,__compact_unwind section into unwind records. The
/// section is an array of 32-byte entries whose pointer fields are set by
/// relocations.
fn parse_compact_unwind<E: Arch>(
    ctx: &mut Context<E>,
    hdr: &MachSection,
    subsecs: &[usize],
    syms: &[SymbolId],
    nlists: &[NList],
    data: &'static [u8],
    file_name: &str,
) {
    // A snapshot of the object's subsection geometry, so lookups don't
    // borrow the context.
    let geo: Vec<(u64, u64, usize)> = subsecs
        .iter()
        .map(|&id| (ctx.isecs[id].input_addr, ctx.isecs[id].size, id))
        .collect();
    let find_subsec = |addr: u64| -> Option<(usize, u32)> {
        let i = geo.partition_point(|&(start, _, _)| start <= addr);
        if i == 0 {
            return None;
        }
        let (start, size, id) = geo[i - 1];
        if addr < start + size || (size == 0 && addr == start) {
            Some((id, (addr - start) as u32))
        } else {
            None
        }
    };
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
            fde: None,
        });
    }

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
                    let Some((isec, off)) = find_subsec(value) else {
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
                    let Some(lsda) = find_subsec(value) else {
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

/// A DWARF Common Information Entry from an object's __eh_frame.
#[derive(Debug)]
pub struct Cie {
    pub obj: usize,
    pub input_addr: u32,
    /// Contents with subtraction pairs already applied.
    pub data: Vec<u8>,
    pub personality: Option<SymbolId>,
    /// Offset of the personality cell within this CIE.
    pub personality_offset: u32,
    /// Size of the LSDA pointer declared by the augmentation ('L'), or
    /// 0 if none.
    pub lsda_size: u8,
    pub output_offset: u32,
    pub is_alive: bool,
}

/// A DWARF Frame Description Entry from an object's __eh_frame.
#[derive(Debug)]
pub struct Fde {
    pub obj: usize,
    pub input_addr: u32,
    pub data: Vec<u8>,
    /// Index into `ctx.cies`.
    pub cie: usize,
    /// The function the FDE describes.
    pub isec: usize,
    pub func_offset: u32,
    pub code_len: u32,
    pub lsda: Option<(usize, u32)>,
    pub output_offset: u32,
}

fn read_uleb_at(data: &[u8], pos: &mut usize) -> u64 {
    let mut val = 0;
    let mut shift = 0;
    loop {
        let byte = data[*pos];
        *pos += 1;
        val |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            return val;
        }
        shift += 7;
    }
}

/// Parses a __TEXT,__eh_frame section. Unlike other sections it is not
/// copied through: the linker re-synthesizes it, keeping only FDEs for
/// functions that have no compact unwind record, patching each CIE's
/// personality cell to be GOT-relative, and dropping the rest.
#[allow(clippy::too_many_arguments)]
fn parse_eh_frame<E: Arch>(
    ctx: &mut Context<E>,
    obj_idx: usize,
    hdr: &MachSection,
    subsecs: &[usize],
    syms: &[SymbolId],
    nlists: &[NList],
    data: &'static [u8],
    new_unwind_start: usize,
    file_name: &str,
) {
    let geo: Vec<(u64, u64, usize)> = subsecs
        .iter()
        .map(|&id| (ctx.isecs[id].input_addr, ctx.isecs[id].size, id))
        .collect();
    let find_subsec = |addr: u64| -> Option<(usize, u32)> {
        let i = geo.partition_point(|&(start, _, _)| start <= addr);
        if i == 0 {
            return None;
        }
        let (start, size, id) = geo[i - 1];
        if addr < start + size || (size == 0 && addr == start) {
            Some((id, (addr - start) as u32))
        } else {
            None
        }
    };
    let mut contents =
        data[hdr.offset as usize..(hdr.offset as u64 + hdr.size) as usize].to_vec();
    let rels: Vec<MachRel> = read_array(data, hdr.reloff as usize, hdr.nreloc as usize);

    // Pre-apply subtraction pairs so record contents become
    // self-relative; leave GOT-relative personality references for
    // later.
    let mut i = 0;
    while i < rels.len() {
        let r1 = rels[i];
        if r1.r_type() == E::RELOC_SUBTRACTOR {
            let r2 = rels[i + 1];
            i += 2;
            if r2.r_type() != E::RELOC_UNSIGNED || !r1.is_extern() || !r2.is_extern() {
                fatal!(ctx, "{file_name}: __eh_frame: unsupported relocation pair");
            }
            let target1 = nlists[r1.r_symbolnum() as usize].n_value;
            let target2 = nlists[r2.r_symbolnum() as usize].n_value;
            let loc = &mut contents[r1.r_address as usize..];
            let delta = target2.wrapping_sub(target1);
            match r1.r_length() {
                2 => {
                    let val = u32::from_le_bytes(loc[..4].try_into().unwrap());
                    loc[..4].copy_from_slice(&val.wrapping_add(delta as u32).to_le_bytes());
                }
                3 => {
                    let val = u64::from_le_bytes(loc[..8].try_into().unwrap());
                    let add = delta as u32 as i32 as i64 as u64;
                    loc[..8].copy_from_slice(&val.wrapping_add(add).to_le_bytes());
                }
                _ => fatal!(ctx, "{file_name}: __eh_frame: invalid relocation size"),
            }
        } else if r1.r_type() == E::RELOC_GOTPC {
            i += 1;
        } else {
            fatal!(ctx, "{file_name}: __eh_frame: unknown relocation type");
        }
    }

    // Split the section into records: a zero ID marks a CIE, anything
    // else is an FDE pointing back at its CIE.
    let first_cie = ctx.cies.len();
    let mut fdes: Vec<(u32, Vec<u8>)> = Vec::new();
    let mut pos = 0;
    while pos < contents.len() {
        let len = u32::from_le_bytes(contents[pos..pos + 4].try_into().unwrap()) as usize;
        if len == 0xffff_ffff {
            fatal!(ctx, "{file_name}: __eh_frame: extended length is not supported");
        }
        let rec = contents[pos..pos + 4 + len].to_vec();
        let id = u32::from_le_bytes(rec[4..8].try_into().unwrap());
        let input_addr = hdr.addr as u32 + pos as u32;
        if id == 0 {
            ctx.cies.push(Cie {
                obj: obj_idx,
                input_addr,
                data: rec,
                personality: None,
                personality_offset: 0,
                lsda_size: 0,
                output_offset: 0,
                is_alive: false,
            });
        } else {
            fdes.push((input_addr, rec));
        }
        pos += 4 + len;
    }

    // Validate CIE augmentations and record LSDA encodings.
    let diag = ctx.diag.clone();
    for cie in &mut ctx.cies[first_cie..] {
        let data = &cie.data;
        if data.get(9).copied() != Some(b'z') {
            continue;
        }
        let aug_start = 9;
        let aug_end = aug_start + data[aug_start..].iter().position(|&b| b == 0).unwrap();
        let mut pos = aug_end + 1;
        read_uleb_at(data, &mut pos); // code alignment
        read_uleb_at(data, &mut pos); // data alignment
        read_uleb_at(data, &mut pos); // return address register
        read_uleb_at(data, &mut pos); // augmentation data length
        for &c in &data[aug_start + 1..aug_end] {
            match c {
                b'L' => {
                    cie.lsda_size = match data[pos] & 0xf {
                        0x3 => 4,  // DW_EH_PE_sdata4... actually udata4
                        0xb => 4,  // DW_EH_PE_sdata4
                        0x0 => 8,  // DW_EH_PE_absptr
                        enc => fatal!(
                            diag,
                            "{file_name}: __eh_frame: unknown LSDA encoding: {enc:#x}"
                        ),
                    };
                    pos += 1;
                }
                b'P' => {
                    // DW_EH_PE_indirect | DW_EH_PE_pcrel | DW_EH_PE_sdata4
                    if data[pos] != 0x9b {
                        fatal!(
                            diag,
                            "{file_name}: __eh_frame: unknown personality encoding: {:#x}",
                            data[pos]
                        );
                    }
                    pos += 5;
                }
                b'R' => pos += 1,
                _ => fatal!(diag, "{file_name}: __eh_frame: unknown augmentation"),
            }
        }
    }

    // Personality references appear as GOT-relative relocations inside
    // a CIE.
    for r in &rels {
        if r.r_type() != E::RELOC_GOTPC {
            continue;
        }
        let addr = hdr.addr as u32 + r.r_address;
        let Some(cie) = ctx.cies[first_cie..].iter_mut().find(|c| {
            c.input_addr <= addr && addr < c.input_addr + c.data.len() as u32
        }) else {
            fatal!(diag, "{file_name}: __eh_frame: stray personality relocation");
        };
        if !r.is_extern() {
            fatal!(diag, "{file_name}: __eh_frame: unsupported personality reference");
        }
        cie.personality = Some(syms[r.r_symbolnum() as usize]);
        cie.personality_offset = addr - cie.input_addr;
    }

    // Functions that already have a compact unwind record don't need
    // their FDE; the compact record wins.
    let covered: std::collections::HashSet<(usize, u32)> = ctx.unwind_records
        [new_unwind_start..]
        .iter()
        .map(|rec| (rec.isec, rec.input_offset))
        .collect();

    for (input_addr, rec) in fdes {
        let cie_off = u32::from_le_bytes(rec[4..8].try_into().unwrap());
        let cie_addr = input_addr + 4 - cie_off;
        let Some(cie) = ctx.cies[first_cie..]
            .iter()
            .position(|c| c.input_addr == cie_addr)
        else {
            fatal!(ctx, "{file_name}: __eh_frame: FDE with an invalid CIE pointer");
        };
        let cie = first_cie + cie;

        // The function address: the pre-applied pc_begin field is
        // relative to itself.
        let pc_begin = i64::from_le_bytes(rec[8..16].try_into().unwrap());
        let func_addr = (input_addr as u64 + 8).wrapping_add_signed(pc_begin);
        let code_len = u64::from_le_bytes(rec[16..24].try_into().unwrap()) as u32;

        let Some((isec, func_offset)) = find_subsec(func_addr) else {
            fatal!(ctx, "{file_name}: __eh_frame: FDE with an invalid function");
        };

        if covered.contains(&(isec, func_offset)) {
            continue;
        }

        // The LSDA pointer, if the CIE declares one: also pre-applied to
        // be self-relative.
        let mut lsda = None;
        if ctx.cies[cie].lsda_size != 0 {
            let mut pos = 24;
            read_uleb_at(&rec, &mut pos);
            let cell = i32::from_le_bytes(rec[pos..pos + 4].try_into().unwrap());
            let lsda_addr = (input_addr as u64 + pos as u64).wrapping_add_signed(cell as i64);
            let Some((lsda_isec, lsda_off)) = find_subsec(lsda_addr) else {
                fatal!(ctx, "{file_name}: __eh_frame: FDE with an invalid LSDA");
            };
            lsda = Some((lsda_isec, lsda_off));
        }

        let fde_idx = ctx.fdes.len();
        ctx.fdes.push(Fde {
            obj: obj_idx,
            input_addr,
            data: rec,
            cie,
            isec,
            func_offset,
            code_len,
            lsda: lsda.map(|(i, o)| (i, o)),
            output_offset: 0,
        });

        // Synthesize a compact unwind record pointing at the FDE so that
        // the unwinder can find it through __unwind_info.
        ctx.unwind_records.push(UnwindRecord {
            isec,
            input_offset: func_offset,
            code_len,
            encoding: 0,
            personality: None,
            lsda: None,
            fde: Some(fde_idx),
        });
    }
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

/// Returns true if an object contains Objective-C class or category
/// metadata, which -ObjC forces to be linked from archives.
pub fn has_objc_sections(mf: &MappedFile) -> bool {
    let data = mf.data;
    if data.len() < size_of::<MachHeader>() {
        return false;
    }
    let hdr = MachHeader::read_from(data);
    if hdr.magic != MH_MAGIC_64 {
        return false;
    }
    let mut off = size_of::<MachHeader>();
    for _ in 0..hdr.ncmds {
        let lc = LoadCommand::read_from(&data[off..]);
        if lc.cmd == LC_SEGMENT_64 {
            let seg = SegmentCommand::read_from(&data[off..]);
            for i in 0..seg.nsects as usize {
                let sect_off = off + size_of::<SegmentCommand>() + i * size_of::<MachSection>();
                let sect = MachSection::read_from(&data[sect_off..]);
                if matches!(
                    sect.sectname(),
                    "__objc_classlist" | "__objc_catlist" | "__objc_nlclslist" | "__objc_nlcatlist"
                ) {
                    return true;
                }
            }
        }
        off += lc.cmdsize as usize;
    }
    false
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
    add_dylib(
        ctx,
        DylibFile {
            install_name,
            current_version,
            compatibility_version,
            dylib_idx: idx as i32 + 1,
            exports,
        },
    )
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

    add_dylib(
        ctx,
        DylibFile {
            install_name: tbd.install_name,
            current_version: tbd.current_version,
            compatibility_version: encode_version(1, 0, 0),
            dylib_idx: idx as i32 + 1,
            exports,
        },
    )
}

/// Registers a dylib, deduplicating by install name: several libraries
/// (libc, libm, ...) are stubs for the same /usr/lib/libSystem.B.dylib,
/// and dyld refuses an image that lists one install name twice.
fn add_dylib<E: Arch>(ctx: &mut Context<E>, dylib: DylibFile) -> usize {
    if let Some(idx) = ctx
        .dylibs
        .iter()
        .position(|d| d.install_name == dylib.install_name)
    {
        let exports = dylib.exports;
        ctx.dylibs[idx].exports.extend(exports);
        return idx;
    }
    ctx.dylibs.push(dylib);
    ctx.dylibs.len() - 1
}
