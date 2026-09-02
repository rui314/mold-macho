//! Input file parsing: object files, dylib stubs and archives.

use crate::arch::Arch;
use crate::context::Context;
use crate::fatal;
use crate::input_sections::InputSection;
use crate::macho::*;
use crate::mapped_file::MappedFile;
use crate::symbol::SymbolId;
use crate::tapi;

/// A relocatable object file.
#[derive(Debug)]
pub struct ObjectFile {
    pub mf: &'static MappedFile,
    /// False for an archive member no live code needs (yet). Dead
    /// files' subsections never reach the output.
    pub is_alive: bool,
    /// Position in input order, for resolution tie-breaking: the
    /// earlier file wins.
    pub priority: u32,
    /// LC_LINKER_OPTION auto-link requests, acted on only if the file
    /// is live.
    pub linker_options: Vec<Vec<String>>,
    /// -hidden-l: this file's external definitions become private
    /// externals.
    pub hidden: bool,
    /// Section headers in ordinal order (all segments' sections
    /// concatenated in load command order).
    pub sect_hdrs: Vec<MachSection>,
    /// All of this object's subsections, sorted by input address.
    pub subsecs: Vec<usize>,
    /// The flags word of the object's __objc_imageinfo, if it has one.
    pub objc_image_info: Option<u32>,
    /// True if the object carries DWARF debug info, so the output gets
    /// debug stabs pointing back at it.
    pub has_debug_info: bool,
    /// For a bitcode input, the lto_module handle: the object is a
    /// placeholder that only claims symbols until LTO compiles it.
    pub lto_module: Option<usize>,
    pub nlists: Vec<NList>,
    /// The symbol slot for each nlist entry.
    pub syms: Vec<SymbolId>,
    /// LC_DATA_IN_CODE entries: (file offset in the object, length,
    /// kind).
    pub dice: Vec<(u32, u16, u16)>,
    /// LC_LINKER_OPTIMIZATION_HINT entries: (kind, instruction
    /// addresses in the object's address space).
    pub loh: Vec<(u8, Vec<u64>)>,
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
    /// The path the library was loaded from, for -t.
    pub path: String,
    pub install_name: String,
    pub current_version: u32,
    pub compatibility_version: u32,
    /// The 1-based ordinal used to refer to this dylib in bind records.
    pub dylib_idx: i32,
    /// Position in input order, for resolution tie-breaking.
    pub priority: u32,
    /// True if loaded with LC_LOAD_WEAK_DYLIB: dyld tolerates the
    /// library missing at load time.
    pub is_weak: bool,
    /// True if re-exported (LC_REEXPORT_DYLIB): this image's clients
    /// resolve the library's exports through this image.
    pub is_reexported: bool,
    /// -needed-l: keep the load command even under -dead_strip_dylibs.
    pub is_needed: bool,
    /// MH_DEAD_STRIPPABLE_DYLIB: drop the load command whenever no
    /// symbol binds to this dylib, even without -dead_strip_dylibs.
    pub is_dead_strippable: bool,
    /// MH_APP_EXTENSION_SAFE: built with -application_extension, so
    /// app-extension clients may link it.
    pub is_app_extension_safe: bool,
    /// LC_SUB_FRAMEWORK: this dylib belongs to the named umbrella and
    /// may only be linked by it or by an allowed client.
    pub sub_framework: Option<String>,
    /// LC_SUB_CLIENT: clients allowed to link this subframework.
    pub sub_clients: Vec<String>,
    pub exports: std::collections::HashSet<String>,
    /// The subset of exports that are thread-local variables.
    pub tlv_exports: std::collections::HashSet<String>,
}

/// Returns true for sections that don't become part of the output image.
fn is_discarded_section(hdr: &MachSection, keep_debug: bool) -> bool {
    // Debug sections, including __LD,__compact_unwind, are consumed by
    // other tools or, later, by the linker itself; they are never
    // copied into a final image. A relocatable (-r) output is another
    // object, though: its DWARF must ride along, or the merged object
    // becomes undebuggable - the final link's stabs will name it as
    // the place to find debug info.
    if keep_debug {
        return hdr.segname() == "__LD";
    }
    hdr.flags & S_ATTR_DEBUG != 0 || hdr.segname() == "__DWARF" || hdr.segname() == "__LD"
}

/// An object file parsed in isolation: all cross-references are local
/// indices, so staging runs in parallel across files with no shared
/// state; `integrate_object` rebases them into the global arenas.
pub struct StagedObject {
    pub mf: &'static MappedFile,
    pub alive: bool,
    pub hidden: bool,
    pub priority: u32,
    pub sect_hdrs: Vec<MachSection>,
    pub linker_options: Vec<Vec<String>>,
    pub isecs: Vec<InputSection>,
    pub subsecs: Vec<usize>,
    pub nlists: Vec<NList>,
    pub sym_names: Vec<&'static str>,
    /// xxh3 of each extern non-stab name (0 otherwise), computed here
    /// so the serial intern path never hashes.
    pub sym_hashes: Vec<u64>,
    pub unwind: Vec<UnwindRecord>,
    pub cies: Vec<Cie>,
    pub fdes: Vec<Fde>,
    pub objc_image_info: Option<u32>,
    pub has_debug_info: bool,
    /// LC_DATA_IN_CODE entries: (file offset in the object, length,
    /// kind).
    pub dice: Vec<(u32, u16, u16)>,
    /// LC_LINKER_OPTIMIZATION_HINT entries: (kind, instruction
    /// addresses in the object's address space).
    pub loh: Vec<(u8, Vec<u64>)>,
}

/// Parses one object file without touching any linker state.
pub fn stage_object<E: Arch>(
    diag: &crate::error::Diagnostics,
    mf: &'static MappedFile,
    alive: bool,
    hidden: bool,
    priority: u32,
    keep_debug: bool,
) -> StagedObject {
    let data = mf.data;
    let hdr = MachHeader::read_from(data);

    if hdr.cputype != E::CPUTYPE {
        fatal!(
            diag,
            "{}: incompatible CPU type: expected {}",
            mf.name,
            E::NAME
        );
    }

    let mut isecs: Vec<InputSection> = Vec::new();
    let mut sect_hdrs = Vec::new();
    let mut symtab_cmd = None;
    let mut linker_options = Vec::new();
    let mut dice = Vec::new();
    let mut loh = Vec::new();

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
            LC_LINKER_OPTION => {
                // Auto-link requests: the object names libraries it
                // needs, as NUL-terminated strings after a count.
                let count = u32::from_le_bytes(data[off + 8..off + 12].try_into().unwrap());
                let mut strs = Vec::with_capacity(count as usize);
                let mut p = off + 12;
                for _ in 0..count {
                    let rest = &data[p..off + lc.cmdsize as usize];
                    let len = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
                    strs.push(String::from_utf8_lossy(&rest[..len]).into_owned());
                    p += len + 1;
                }
                linker_options.push(strs);
            }
            LC_DATA_IN_CODE => {
                let cmd = LinkEditDataCommand::read_from(&data[off..]);
                for i in 0..cmd.datasize as usize / 8 {
                    let p = cmd.dataoff as usize + i * 8;
                    dice.push((
                        u32::from_le_bytes(data[p..p + 4].try_into().unwrap()),
                        u16::from_le_bytes(data[p + 4..p + 6].try_into().unwrap()),
                        u16::from_le_bytes(data[p + 6..p + 8].try_into().unwrap()),
                    ));
                }
            }
            LC_LINKER_OPTIMIZATION_HINT => {
                // A stream of ULEB128 triples-and-more: kind, argument
                // count, then that many instruction addresses.
                let cmd = LinkEditDataCommand::read_from(&data[off..]);
                let payload =
                    &data[cmd.dataoff as usize..(cmd.dataoff + cmd.datasize) as usize];
                let mut pos = 0;
                while pos < payload.len() {
                    let kind = read_uleb_at(payload, &mut pos);
                    if kind == 0 {
                        break;
                    }
                    let count = read_uleb_at(payload, &mut pos);
                    let addrs = (0..count)
                        .map(|_| read_uleb_at(payload, &mut pos))
                        .collect();
                    loh.push((kind as u8, addrs));
                }
            }
            _ => {}
        }
        off += lc.cmdsize as usize;
    }

    // Read the symbol table
    let mut nlists: Vec<NList> = Vec::new();
    let mut strtab: &'static [u8] = &[];
    if let Some(cmd) = symtab_cmd {
        nlists = read_array(data, cmd.symoff as usize, cmd.nsyms as usize);
        strtab = validate_strtab(&data[cmd.stroff as usize..(cmd.stroff + cmd.strsize) as usize]);
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
        // __eh_frame is re-synthesized from parsed CIE/FDE records, and
        // __objc_imageinfo sections are merged into one synthesized
        // record; neither is copied through.
        if is_discarded_section(sect, keep_debug)
            || (sect.segname() == "__TEXT" && sect.sectname() == "__eh_frame")
            || sect.sectname() == "__objc_imageinfo"
        {
            continue;
        }

        // Literal sections are element-oriented: split them per element
        // (per string, or per fixed-size literal) so identical elements
        // can be merged across objects.
        let mut points = std::mem::take(&mut split_points[i]);
        if is_literal(sect) {
            points.clear();
            let contents =
                &data[sect.offset as usize..(sect.offset as u64 + sect.size) as usize];
            match sect.section_type() {
                S_CSTRING_LITERALS => {
                    let mut start = 0;
                    while start < contents.len() {
                        points.push(sect.addr + start as u64);
                        let Some(len) = contents[start..].iter().position(|&b| b == 0)
                        else {
                            fatal!(diag, "{}: malformed __cstring section", mf.name);
                        };
                        start += len + 1;
                    }
                }
                S_4BYTE_LITERALS => points.extend((0..sect.size).step_by(4).map(|o| sect.addr + o)),
                S_8BYTE_LITERALS => points.extend((0..sect.size).step_by(8).map(|o| sect.addr + o)),
                S_16BYTE_LITERALS => {
                    points.extend((0..sect.size).step_by(16).map(|o| sect.addr + o))
                }
                _ => {}
            }
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
            isecs.push(InputSection {
                obj: usize::MAX,
                hdr: *sect,
                input_addr: start,
                size: end - start,
                data: contents,
                relocs: Vec::new(),
                osec: usize::MAX,
                output_offset: 0,
                is_alive: true,
                replacement: None,
            });
            by_ordinal[i].push(isecs.len() - 1);
            subsecs.push(isecs.len() - 1);
        }
    }

    subsecs.sort_by_key(|&id| isecs[id].input_addr);

    // Read each section's relocations and distribute them to its
    // subsections, rebasing location offsets and section-relative
    // targets to subsections.
    for (i, sect) in sect_hdrs.iter().enumerate() {
        if by_ordinal[i].is_empty() || sect.nreloc == 0 {
            continue;
        }
        let raw: Vec<MachRel> = read_array(data, sect.reloff as usize, sect.nreloc as usize);
        let rels = E::read_relocs(diag, &mf.name, &sect_hdrs, sect, data, &raw);

        for mut rel in rels {
            let loc_addr = sect.addr + rel.offset as u64;
            let Some((sub, sub_off)) = find_subsec(&isecs, &by_ordinal[i], loc_addr)
            else {
                fatal!(diag, "{}: relocation outside its section", mf.name);
            };
            rel.offset = sub_off as u32;

            if let crate::input_sections::RelocTarget::Section(sect_pos) = rel.target {
                let taddr = (sect_hdrs[sect_pos].addr as i64 + rel.addend) as u64;
                let Some((tsub, toff)) = find_subsec(&isecs, &subsecs, taddr) else {
                    fatal!(diag, "{}: relocation against a discarded section", mf.name);
                };
                rel.target = crate::input_sections::RelocTarget::Section(tsub);
                rel.addend = toff as i64;
            }
            isecs[sub].relocs.push(rel);
        }
    }

    // Record symbol names; interning happens at integration.
    let sym_names: Vec<&'static str> = nlists
        .iter()
        .map(|nlist| symbol_name(strtab, nlist))
        .collect();

    let mut unwind = Vec::new();
    let mut cies = Vec::new();
    let mut fdes = Vec::new();
    if let Some(hdr) = sect_hdrs
        .iter()
        .find(|s| s.segname() == "__LD" && s.sectname() == "__compact_unwind")
    {
        parse_compact_unwind::<E>(diag, hdr, &isecs, &subsecs, &nlists, data, &mf.name, &mut unwind);
    }

    if let Some(hdr) = sect_hdrs
        .iter()
        .find(|s| s.segname() == "__TEXT" && s.sectname() == "__eh_frame")
    {
        parse_eh_frame::<E>(
            diag, hdr, &isecs, &subsecs, &nlists, data, &mf.name, &mut unwind, &mut cies,
            &mut fdes,
        );
    }

    let objc_image_info = sect_hdrs
        .iter()
        .find(|s| s.sectname() == "__objc_imageinfo")
        .map(|s| {
            let off = s.offset as usize + 4;
            u32::from_le_bytes(data[off..off + 4].try_into().unwrap())
        });
    let has_debug_info = sect_hdrs
        .iter()
        .any(|s| s.segname() == "__DWARF" && s.sectname() == "__debug_info");

    let sym_hashes: Vec<u64> = nlists
        .iter()
        .zip(&sym_names)
        .map(|(nlist, name)| {
            if !nlist.is_stab() && nlist.is_extern() {
                crate::symbol::hash_key(name)
            } else {
                0
            }
        })
        .collect();

    StagedObject {
        mf,
        alive,
        hidden,
        priority,
        sect_hdrs,
        linker_options,
        isecs,
        subsecs,
        nlists,
        sym_names,
        sym_hashes,
        unwind,
        cies,
        dice,
        loh,
        fdes,
        objc_image_info,
        has_debug_info,
    }
}

/// Appends a staged object to the global arenas, rebasing its local
/// indices and interning its symbol names.
pub fn integrate_object<E: Arch>(ctx: &mut Context<E>, staged: StagedObject) -> usize {
    integrate_object_with(ctx, staged, None)
}

/// Like integrate_object, with the global symbols' ids already interned
/// by a bulk pass (in nlist order, one entry per extern non-stab nlist).
/// Integrates a whole staging batch at once, mold-style: every
/// object's arena positions (subsection, CIE, FDE and local-symbol
/// bases) come from prefix sums over the batch, so the rebasing of
/// indices - the actual work - runs on all cores, and the serial
/// remainder is moving the rebased vectors into the global arenas.
/// Produces exactly the layout the one-at-a-time path would.
pub fn integrate_objects<E: Arch>(
    ctx: &mut Context<E>,
    mut staged: Vec<StagedObject>,
    ids: Vec<crate::symbol::SymbolId>,
    counts: Vec<usize>,
) {
    use rayon::prelude::*;

    let obj_base = ctx.objs.len();
    let mut isec_base = ctx.isecs.len();
    let mut cie_base = ctx.cies.len();
    let mut fde_base = ctx.fdes.len();
    let mut locals_base = ctx.symtab.syms.len();
    let mut id_base = 0usize;

    struct Bases {
        isec: usize,
        cie: usize,
        fde: usize,
        locals: usize,
        ids: usize,
    }
    let mut bases = Vec::with_capacity(staged.len());
    for (st, &nids) in staged.iter().zip(&counts) {
        let n_locals = st
            .nlists
            .iter()
            .filter(|n| n.is_stab() || !n.is_extern())
            .count();
        bases.push(Bases {
            isec: isec_base,
            cie: cie_base,
            fde: fde_base,
            locals: locals_base,
            ids: id_base,
        });
        isec_base += st.isecs.len();
        cie_base += st.cies.len();
        fde_base += st.fdes.len();
        locals_base += n_locals;
        id_base += nids;
    }

    // The rebasing, in parallel; each object also reports its local
    // symbol names in order for the serial arena extension below.
    let syms_of: Vec<Vec<crate::symbol::SymbolId>> = staged
        .par_iter_mut()
        .enumerate()
        .map(|(i, st)| {
            let base = &bases[i];
            let obj_idx = obj_base + i;

            let mut syms = Vec::with_capacity(st.nlists.len());
            let mut next_local = base.locals;
            let mut next_id = base.ids;
            for nlist in &st.nlists {
                if nlist.is_stab() || !nlist.is_extern() {
                    syms.push(next_local);
                    next_local += 1;
                } else {
                    syms.push(ids[next_id]);
                    next_id += 1;
                }
            }

            for isec in &mut st.isecs {
                isec.obj = obj_idx;
                for rel in &mut isec.relocs {
                    if let crate::input_sections::RelocTarget::Section(local) = rel.target {
                        rel.target =
                            crate::input_sections::RelocTarget::Section(base.isec + local);
                    }
                }
            }
            for sub in &mut st.subsecs {
                *sub += base.isec;
            }
            for rec in &mut st.unwind {
                rec.isec += base.isec;
                if let Some((lsda, _)) = &mut rec.lsda {
                    *lsda += base.isec;
                }
                if let Some(fde) = &mut rec.fde {
                    *fde += base.fde;
                }
                if let Some(p) = &mut rec.personality {
                    *p = syms[*p];
                }
            }
            for cie in &mut st.cies {
                cie.obj = obj_idx;
                if let Some(p) = &mut cie.personality {
                    *p = syms[*p];
                }
            }
            for fde in &mut st.fdes {
                fde.obj = obj_idx;
                fde.isec += base.isec;
                fde.cie += base.cie;
                if let Some((lsda, _)) = &mut fde.lsda {
                    *lsda += base.isec;
                }
            }
            syms
        })
        .collect();

    // Serial arena extension: pure moves and Symbol construction.
    for (st, syms) in staged.into_iter().zip(syms_of) {
        for (nlist, name) in st.nlists.iter().zip(&st.sym_names) {
            if nlist.is_stab() || !nlist.is_extern() {
                ctx.symtab.add_local(name);
            }
        }
        ctx.isecs.extend(st.isecs);
        ctx.unwind_records.extend(st.unwind);
        ctx.cies.extend(st.cies);
        ctx.fdes.extend(st.fdes);
        ctx.objs.push(ObjectFile {
            mf: st.mf,
            is_alive: st.alive,
            priority: st.priority,
            linker_options: st.linker_options,
            hidden: st.hidden,
            sect_hdrs: st.sect_hdrs,
            subsecs: st.subsecs,
            objc_image_info: st.objc_image_info,
            has_debug_info: st.has_debug_info,
            nlists: st.nlists,
            syms,
            lto_module: None,
            dice: st.dice,
            loh: st.loh,
        });
    }
}

pub fn integrate_object_with<E: Arch>(
    ctx: &mut Context<E>,
    staged: StagedObject,
    pre_interned: Option<Vec<crate::symbol::SymbolId>>,
) -> usize {
    let obj_idx = ctx.objs.len();
    let isec_base = ctx.isecs.len();
    let fde_base = ctx.fdes.len();
    let cie_base = ctx.cies.len();

    for mut isec in staged.isecs {
        isec.obj = obj_idx;
        for rel in &mut isec.relocs {
            if let crate::input_sections::RelocTarget::Section(local) = rel.target {
                rel.target = crate::input_sections::RelocTarget::Section(isec_base + local);
            }
        }
        ctx.isecs.push(isec);
    }

    let mut syms = Vec::with_capacity(staged.nlists.len());
    let mut pre = pre_interned.map(Vec::into_iter);
    for (nlist, name) in staged.nlists.iter().zip(&staged.sym_names) {
        let id = if nlist.is_stab() || !nlist.is_extern() {
            ctx.symtab.add_local(name)
        } else {
            match &mut pre {
                Some(iter) => iter.next().unwrap(),
                None => ctx.symtab.intern(name),
            }
        };
        syms.push(id);
    }

    for mut rec in staged.unwind {
        rec.isec += isec_base;
        if let Some((lsda, _)) = &mut rec.lsda {
            *lsda += isec_base;
        }
        if let Some(fde) = &mut rec.fde {
            *fde += fde_base;
        }
        // The personality was recorded as a local symbol index.
        if let Some(p) = &mut rec.personality {
            *p = syms[*p];
        }
        ctx.unwind_records.push(rec);
    }
    for mut cie in staged.cies {
        cie.obj = obj_idx;
        if let Some(p) = &mut cie.personality {
            *p = syms[*p];
        }
        ctx.cies.push(cie);
    }
    for mut fde in staged.fdes {
        fde.obj = obj_idx;
        fde.isec += isec_base;
        fde.cie += cie_base;
        if let Some((lsda, _)) = &mut fde.lsda {
            *lsda += isec_base;
        }
        ctx.fdes.push(fde);
    }

    ctx.objs.push(ObjectFile {
        mf: staged.mf,
        is_alive: staged.alive,
        priority: staged.priority,
        linker_options: staged.linker_options,
        hidden: staged.hidden,
        sect_hdrs: staged.sect_hdrs,
        subsecs: staged.subsecs.into_iter().map(|i| i + isec_base).collect(),
        objc_image_info: staged.objc_image_info,
        has_debug_info: staged.has_debug_info,
        nlists: staged.nlists,
        syms,
        lto_module: None,
        dice: staged.dice,
        loh: staged.loh,
    });
    obj_idx
}

/// Parses one object and adds it to the link immediately.
pub fn parse_object<E: Arch>(ctx: &mut Context<E>, mf: &'static MappedFile, alive: bool) -> usize {
    let priority = ctx.next_priority();
    let diag = ctx.diag.clone();
    let staged = stage_object::<E>(&diag, mf, alive, false, priority, ctx.args.relocatable);
    integrate_object(ctx, staged)
}

/// Loads the LTO plugin on first use.
pub fn ensure_lto_plugin<E: Arch>(ctx: &mut Context<E>) -> crate::lto::Plugin {
    if ctx.lto_plugin.is_none() {
        ctx.lto_plugin = Some(crate::lto::load_plugin(
            &ctx.diag,
            ctx.args.lto_library.as_deref(),
        ));
    }
    ctx.lto_plugin.unwrap()
}

/// Registers a bitcode input: a placeholder object that claims the
/// module's symbols so resolution works, compiled for real by LTO once
/// all inputs are known.
pub fn parse_bitcode<E: Arch>(ctx: &mut Context<E>, mf: &'static MappedFile, alive: bool) -> usize {
    let plugin = ensure_lto_plugin(ctx);
    let (module, lsyms) = crate::lto::parse_module(&ctx.diag, &plugin, mf.data, &mf.name);

    let obj_idx = ctx.objs.len();
    let mut syms = Vec::new();
    let mut nlists = Vec::new();

    // Symbols are expressed as synthesized nlists so that the regular
    // resolution pass handles bitcode like any object.
    for ls in lsyms {
        if !ls.is_extern && ls.is_defined {
            continue;
        }
        let name: &'static str = String::leak(ls.name);
        let id = ctx.symtab.intern(name);
        let mut nlist = NList::default();
        if ls.is_defined {
            nlist.n_type = N_ABS | N_EXT | if ls.is_private_extern { N_PEXT } else { 0 };
            if ls.is_weak_def {
                nlist.n_desc |= N_WEAK_DEF;
            }
        } else {
            nlist.n_type = N_UNDF | N_EXT;
        }
        nlists.push(nlist);
        syms.push(id);
    }

    let priority = ctx.next_priority();
    ctx.objs.push(ObjectFile {
        mf,
        is_alive: alive,
        priority,
        linker_options: Vec::new(),
        hidden: false,
        sect_hdrs: Vec::new(),
        subsecs: Vec::new(),
        objc_image_info: None,
        has_debug_info: false,
        nlists,
        syms,
        lto_module: Some(module),
        dice: Vec::new(),
        loh: Vec::new(),
    });
    ctx.lto_modules.push((obj_idx, module));
    obj_idx
}

/// Extracts one NUL-terminated name from a string table already
/// validated as UTF-8 by validate_strtab. The NUL scan goes through
/// libc's memchr, which is vectorized; a per-name from_utf8 was a
/// quarter of all staging time on big links.
fn symbol_name(strtab: &'static [u8], nlist: &NList) -> &'static str {
    let off = nlist.n_strx as usize;
    if off >= strtab.len() {
        return "";
    }
    let rest = &strtab[off..];
    // SAFETY: memchr reads within `rest`; the result is bounded by
    // its length.
    let len = unsafe {
        let p = libc::memchr(rest.as_ptr() as *const _, 0, rest.len());
        if p.is_null() {
            rest.len()
        } else {
            (p as usize) - (rest.as_ptr() as usize)
        }
    };
    // SAFETY: the whole table was checked as UTF-8 up front; any
    // slice of it on a codepoint boundary is valid, and a NUL
    // boundary always is.
    unsafe { std::str::from_utf8_unchecked(&rest[..len]) }
}

/// Checks a whole string table as UTF-8 once - vastly cheaper than
/// validating millions of short names one by one. Returns an empty
/// table (degrading names to "") for the pathological non-UTF-8 case.
fn validate_strtab(strtab: &'static [u8]) -> &'static [u8] {
    match std::str::from_utf8(strtab) {
        Ok(_) => strtab,
        Err(e) => &strtab[..e.valid_up_to()],
    }
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
#[allow(clippy::too_many_arguments)]
fn parse_compact_unwind<E: Arch>(
    diag: &crate::error::Diagnostics,
    hdr: &MachSection,
    isecs: &[InputSection],
    subsecs: &[usize],
    nlists: &[NList],
    data: &'static [u8],
    file_name: &str,
    out: &mut Vec<UnwindRecord>,
) {
    let geo: Vec<(u64, u64, usize)> = subsecs
        .iter()
        .map(|&id| (isecs[id].input_addr, isecs[id].size, id))
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
        fatal!(diag, "{file_name}: invalid __compact_unwind section size");
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
            fatal!(diag, "{file_name}: __compact_unwind: unsupported relocation");
        }
        let idx = r.r_address as usize / ENTRY_SIZE;
        let value = read_u64(r.r_address as u64);

        match r.r_address as usize % ENTRY_SIZE {
            // The function the record covers. For an extern reference
            // the target is this object's own definition, located by
            // its nlist value.
            0 => {
                let addr = if r.is_extern() {
                    nlists[r.r_symbolnum() as usize].n_value + value
                } else {
                    value
                };
                let Some((isec, off)) = find_subsec(addr) else {
                    fatal!(diag, "{file_name}: __compact_unwind: bad function reference");
                };
                records[idx].isec = isec;
                records[idx].input_offset = off;
            }
            // The personality function, recorded as a local symbol
            // index and mapped to a symbol at integration.
            16 => {
                let sym = if r.is_extern() {
                    Some(r.r_symbolnum() as usize)
                } else {
                    // Resolve a section-relative reference back to the
                    // symbol at that address.
                    nlists
                        .iter()
                        .position(|n| n.is_extern() && n.n_value == value)
                };
                let Some(sym) = sym else {
                    fatal!(diag, "{file_name}: __compact_unwind: unsupported personality");
                };
                records[idx].personality = Some(sym);
            }
            // The language-specific data area
            24 => {
                let addr = if r.is_extern() {
                    nlists[r.r_symbolnum() as usize].n_value + value
                } else {
                    value
                };
                let Some(lsda) = find_subsec(addr) else {
                    fatal!(diag, "{file_name}: __compact_unwind: bad LSDA reference");
                };
                records[idx].lsda = Some(lsda);
            }
            _ => fatal!(diag, "{file_name}: __compact_unwind: unsupported relocation"),
        }
    }

    // Ignore records that point to DWARF unwind info; those are
    // synthesized from __eh_frame instead. Object files usually don't
    // contain such records, but `ld -r` output does.
    records.retain(|rec| {
        rec.isec != usize::MAX && (rec.encoding & UNWIND_MODE_MASK) != E::UNWIND_MODE_DWARF
    });
    out.extend(records);
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

pub fn read_uleb_at(data: &[u8], pos: &mut usize) -> u64 {
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
    diag: &crate::error::Diagnostics,
    hdr: &MachSection,
    isecs: &[InputSection],
    subsecs: &[usize],
    nlists: &[NList],
    data: &'static [u8],
    file_name: &str,
    unwind: &mut Vec<UnwindRecord>,
    out_cies: &mut Vec<Cie>,
    out_fdes: &mut Vec<Fde>,
) {
    let geo: Vec<(u64, u64, usize)> = subsecs
        .iter()
        .map(|&id| (isecs[id].input_addr, isecs[id].size, id))
        .collect();
    let find_local = |addr: u64| -> Option<(usize, u32)> {
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
                fatal!(diag, "{file_name}: __eh_frame: unsupported relocation pair");
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
                _ => fatal!(diag, "{file_name}: __eh_frame: invalid relocation size"),
            }
        } else if r1.r_type() == E::RELOC_GOTPC {
            i += 1;
        } else {
            fatal!(diag, "{file_name}: __eh_frame: unknown relocation type");
        }
    }

    // Split the section into records: a zero ID marks a CIE, anything
    // else is an FDE pointing back at its CIE.
    let mut fdes: Vec<(u32, Vec<u8>)> = Vec::new();
    let mut pos = 0;
    while pos < contents.len() {
        let len = u32::from_le_bytes(contents[pos..pos + 4].try_into().unwrap()) as usize;
        if len == 0xffff_ffff {
            fatal!(diag, "{file_name}: __eh_frame: extended length is not supported");
        }
        let rec = contents[pos..pos + 4 + len].to_vec();
        let id = u32::from_le_bytes(rec[4..8].try_into().unwrap());
        let input_addr = hdr.addr as u32 + pos as u32;
        if id == 0 {
            out_cies.push(Cie {
                obj: usize::MAX,
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
    for cie in out_cies.iter_mut() {
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
        let Some(cie) = out_cies.iter_mut().find(|c| {
            c.input_addr <= addr && addr < c.input_addr + c.data.len() as u32
        }) else {
            fatal!(diag, "{file_name}: __eh_frame: stray personality relocation");
        };
        if !r.is_extern() {
            fatal!(diag, "{file_name}: __eh_frame: unsupported personality reference");
        }
        // A local symbol index, mapped to a symbol at integration.
        cie.personality = Some(r.r_symbolnum() as usize);
        cie.personality_offset = addr - cie.input_addr;
    }

    // Functions that already have a compact unwind record don't need
    // their FDE; the compact record wins.
    let covered: std::collections::HashSet<(usize, u32)> = unwind
        .iter()
        .map(|rec| (rec.isec, rec.input_offset))
        .collect();

    for (input_addr, rec) in fdes {
        let cie_off = u32::from_le_bytes(rec[4..8].try_into().unwrap());
        let cie_addr = input_addr + 4 - cie_off;
        let Some(cie) = out_cies.iter().position(|c| c.input_addr == cie_addr) else {
            fatal!(diag, "{file_name}: __eh_frame: FDE with an invalid CIE pointer");
        };

        // The function address: the pre-applied pc_begin field is
        // relative to itself.
        let pc_begin = i64::from_le_bytes(rec[8..16].try_into().unwrap());
        let func_addr = (input_addr as u64 + 8).wrapping_add_signed(pc_begin);
        let code_len = u64::from_le_bytes(rec[16..24].try_into().unwrap()) as u32;

        let Some((isec, func_offset)) = find_local(func_addr) else {
            fatal!(diag, "{file_name}: __eh_frame: FDE with an invalid function");
        };

        if covered.contains(&(isec, func_offset)) {
            continue;
        }

        // The LSDA pointer, if the CIE declares one: also pre-applied to
        // be self-relative.
        let mut lsda = None;
        if out_cies[cie].lsda_size != 0 {
            let mut pos = 24;
            read_uleb_at(&rec, &mut pos);
            let cell = i32::from_le_bytes(rec[pos..pos + 4].try_into().unwrap());
            let lsda_addr = (input_addr as u64 + pos as u64).wrapping_add_signed(cell as i64);
            let Some((lsda_isec, lsda_off)) = find_local(lsda_addr) else {
                fatal!(diag, "{file_name}: __eh_frame: FDE with an invalid LSDA");
            };
            lsda = Some((lsda_isec, lsda_off));
        }

        let fde_idx = out_fdes.len();
        out_fdes.push(Fde {
            obj: usize::MAX,
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
        unwind.push(UnwindRecord {
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
            let strtab: &'static [u8] = validate_strtab(unsafe { std::mem::transmute(strtab) });
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
    let mut reexports: Vec<String> = Vec::new();
    let mut rpaths: Vec<String> = Vec::new();
    let mut sub_framework: Option<String> = None;
    let mut sub_clients: Vec<String> = Vec::new();

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
            LC_REEXPORT_DYLIB => {
                let cmd = DylibCommand::read_from(&data[off..]);
                let name = &data[off + cmd.nameoff as usize..off + cmd.cmdsize as usize];
                let len = name.iter().position(|&b| b == 0).unwrap_or(name.len());
                reexports.push(String::from_utf8_lossy(&name[..len]).into_owned());
            }
            LC_RPATH => {
                let cmd = DylinkerCommand::read_from(&data[off..]);
                let name = &data[off + cmd.nameoff as usize..off + cmd.cmdsize as usize];
                let len = name.iter().position(|&b| b == 0).unwrap_or(name.len());
                let mut rpath = String::from_utf8_lossy(&name[..len]).into_owned();
                if let Some(rest) = rpath.strip_prefix("@loader_path/") {
                    rpath = format!("{}/{rest}", dir_of(&mf.name));
                }
                rpaths.push(rpath);
            }
            LC_SUB_FRAMEWORK | LC_SUB_CLIENT => {
                let cmd = DylinkerCommand::read_from(&data[off..]);
                let name = &data[off + cmd.nameoff as usize..off + cmd.cmdsize as usize];
                let len = name.iter().position(|&b| b == 0).unwrap_or(name.len());
                let name = String::from_utf8_lossy(&name[..len]).into_owned();
                if lc.cmd == LC_SUB_FRAMEWORK {
                    sub_framework = Some(name);
                } else {
                    sub_clients.push(name);
                }
            }
            _ => {}
        }
        off += lc.cmdsize as usize;
    }

    if install_name.is_empty() {
        fatal!(ctx, "{}: dylib has no LC_ID_DYLIB", mf.name);
    }

    let mut exports = std::collections::HashSet::new();
    let mut tlv_exports = std::collections::HashSet::new();
    if let (Some(sym), Some(dysym)) = (symtab_cmd, dysymtab_cmd) {
        let nlists: Vec<NList> = read_array(data, sym.symoff as usize, sym.nsyms as usize);
        let strtab = &data[sym.stroff as usize..(sym.stroff + sym.strsize) as usize];
        // SAFETY: input files are leaked, so the string table lives for
        // the rest of the process.
        let strtab: &'static [u8] = validate_strtab(unsafe { std::mem::transmute(strtab) });
        // A TLV export is recognizable by its section: n_sect names a
        // S_THREAD_LOCAL_VARIABLES section (the __thread_vars
        // descriptors).
        let tlv_sects = thread_local_section_ordinals(data, &hdr);
        let range = dysym.iextdefsym as usize..(dysym.iextdefsym + dysym.nextdefsym) as usize;
        for nlist in &nlists[range] {
            let name = symbol_name(strtab, nlist).to_string();
            if tlv_sects.contains(&nlist.n_sect) {
                tlv_exports.insert(name.clone());
            }
            exports.insert(name);
        }
    }

    // A dylib's clients see its reexported libraries' exports through
    // it; merge them in, following the chain. Each queue entry keeps
    // the referencing dylib's directory and rpaths, since @loader_path
    // and @rpath in an install name are relative to the referrer.
    let mut queue: Vec<(String, String, Vec<String>)> = reexports
        .into_iter()
        .map(|name| (name, dir_of(&mf.name), rpaths.clone()))
        .collect();
    let mut visited = std::collections::HashSet::new();
    while let Some((name, loader_dir, loader_rpaths)) = queue.pop() {
        if !visited.insert(name.clone()) {
            continue;
        }
        let Some(dep) = resolve_dylib_ref(ctx, &name, &loader_dir, &loader_rpaths) else {
            crate::warn!(ctx, "{}: reexported library not found: {}", mf.name, name);
            continue;
        };
        match crate::filetype::get_file_type(dep) {
            crate::filetype::FileType::Tapi => {
                let mut dep_tbd = tapi::parse(&ctx.diag, dep);
                interpret_ld_symbols(ctx, &mut dep_tbd);
                tlv_exports.extend(dep_tbd.tlv_exports.iter().cloned());
                exports.extend(dep_tbd.tlv_exports);
                exports.extend(dep_tbd.exports);
                exports.extend(dep_tbd.weak_exports);
                for dep_name in dep_tbd.external_reexports {
                    queue.push((dep_name, dir_of(&dep.name), Vec::new()));
                }
            }
            crate::filetype::FileType::Dylib => {
                let (dep_exports, dep_tlvs, dep_reexports, dep_rpaths) =
                    dylib_binary_exports(&ctx.diag, dep);
                exports.extend(dep_exports);
                tlv_exports.extend(dep_tlvs);
                for dep_name in dep_reexports {
                    queue.push((dep_name, dir_of(&dep.name), dep_rpaths.clone()));
                }
            }
            _ => crate::warn!(ctx, "{}: unsupported reexported library: {}", mf.name, name),
        }
    }

    let idx = ctx.dylibs.len();
    let priority = ctx.next_priority();
    add_dylib(
        ctx,
        DylibFile {
            path: mf.name.clone(),
            install_name,
            current_version,
            compatibility_version,
            dylib_idx: idx as i32 + 1,
            priority,
            is_weak: false,
            is_reexported: false,
            is_needed: false,
            is_dead_strippable: hdr.flags & MH_DEAD_STRIPPABLE_DYLIB != 0,
            is_app_extension_safe: hdr.flags & MH_APP_EXTENSION_SAFE != 0,
            sub_framework,
            sub_clients,
            exports,
            tlv_exports,
        },
    )
}

/// Returns the 1-based ordinals of S_THREAD_LOCAL_VARIABLES sections.
fn thread_local_section_ordinals(data: &[u8], hdr: &MachHeader) -> Vec<u8> {
    let mut ordinals = Vec::new();
    let mut ordinal = 0u8;
    let mut off = size_of::<MachHeader>();
    for _ in 0..hdr.ncmds {
        let lc = LoadCommand::read_from(&data[off..]);
        if lc.cmd == LC_SEGMENT_64 {
            let seg = SegmentCommand::read_from(&data[off..]);
            for i in 0..seg.nsects as usize {
                let sect = MachSection::read_from(
                    &data[off + size_of::<SegmentCommand>() + i * size_of::<MachSection>()..],
                );
                ordinal += 1;
                if sect.flags & SECTION_TYPE == S_THREAD_LOCAL_VARIABLES {
                    ordinals.push(ordinal);
                }
            }
        }
        off += lc.cmdsize as usize;
    }
    ordinals
}

/// Reads a dylib binary's exported symbols and reexported install
/// names, for following reexport chains.
fn dylib_binary_exports(
    _diag: &crate::error::Diagnostics,
    mf: &'static MappedFile,
) -> (Vec<String>, Vec<String>, Vec<String>, Vec<String>) {
    let data = mf.data;
    let hdr = MachHeader::read_from(data);
    let mut symtab_cmd = None;
    let mut dysymtab_cmd = None;
    let mut reexports = Vec::new();
    let mut rpaths = Vec::new();

    let mut off = size_of::<MachHeader>();
    for _ in 0..hdr.ncmds {
        let lc = LoadCommand::read_from(&data[off..]);
        match lc.cmd {
            LC_SYMTAB => symtab_cmd = Some(SymtabCommand::read_from(&data[off..])),
            LC_DYSYMTAB => dysymtab_cmd = Some(DysymtabCommand::read_from(&data[off..])),
            LC_REEXPORT_DYLIB => {
                let cmd = DylibCommand::read_from(&data[off..]);
                let name = &data[off + cmd.nameoff as usize..off + cmd.cmdsize as usize];
                let len = name.iter().position(|&b| b == 0).unwrap_or(name.len());
                reexports.push(String::from_utf8_lossy(&name[..len]).into_owned());
            }
            LC_RPATH => {
                let cmd = DylinkerCommand::read_from(&data[off..]);
                let name = &data[off + cmd.nameoff as usize..off + cmd.cmdsize as usize];
                let len = name.iter().position(|&b| b == 0).unwrap_or(name.len());
                let mut rpath = String::from_utf8_lossy(&name[..len]).into_owned();
                if let Some(rest) = rpath.strip_prefix("@loader_path/") {
                    rpath = format!("{}/{rest}", dir_of(&mf.name));
                }
                rpaths.push(rpath);
            }
            _ => {}
        }
        off += lc.cmdsize as usize;
    }

    let mut exports = Vec::new();
    let mut tlv_exports = Vec::new();
    if let (Some(sym), Some(dysym)) = (symtab_cmd, dysymtab_cmd) {
        let nlists: Vec<NList> = read_array(data, sym.symoff as usize, sym.nsyms as usize);
        let strtab = &data[sym.stroff as usize..(sym.stroff + sym.strsize) as usize];
        // SAFETY: input files are leaked, so the string table lives for
        // the rest of the process.
        let strtab: &'static [u8] = validate_strtab(unsafe { std::mem::transmute(strtab) });
        let tlv_sects = thread_local_section_ordinals(data, &hdr);
        let range = dysym.iextdefsym as usize..(dysym.iextdefsym + dysym.nextdefsym) as usize;
        for nlist in &nlists[range] {
            let name = symbol_name(strtab, nlist).to_string();
            if tlv_sects.contains(&nlist.n_sect) {
                tlv_exports.push(name.clone());
            }
            exports.push(name);
        }
    }
    (exports, tlv_exports, reexports, rpaths)
}

fn dir_of(path: &str) -> String {
    match path.rsplit_once('/') {
        Some((dir, _)) => dir.to_string(),
        None => ".".to_string(),
    }
}

/// Resolves a dependent dylib's install name the way dyld would, but
/// at link time: @loader_path is the directory of the dylib that
/// names the dependency, @rpath tries that dylib's own LC_RPATH
/// entries, and @executable_path stands for the output executable's
/// directory (or -executable_path).
fn resolve_dylib_ref<E: Arch>(
    ctx: &Context<E>,
    name: &str,
    loader_dir: &str,
    loader_rpaths: &[String],
) -> Option<&'static MappedFile> {
    if let Some(rest) = name.strip_prefix("@loader_path/") {
        return find_reexport_file(ctx, &format!("{loader_dir}/{rest}"));
    }
    if let Some(rest) = name.strip_prefix("@executable_path/") {
        let exe = match &ctx.args.executable_path {
            Some(path) => path.clone(),
            None if ctx.args.output_type == MH_EXECUTE => ctx.args.output.clone(),
            None => return None,
        };
        return find_reexport_file(ctx, &format!("{}/{rest}", dir_of(&exe)));
    }
    if let Some(rest) = name.strip_prefix("@rpath/") {
        for rpath in loader_rpaths {
            if let Some(mf) = find_reexport_file(ctx, &format!("{rpath}/{rest}")) {
                return Some(mf);
            }
        }
        return None;
    }
    find_reexport_file(ctx, name)
}

/// Locates the stub or binary for a reexported library's install name
/// under the syslibroot.
fn find_reexport_file<E: Arch>(
    ctx: &Context<E>,
    install_name: &str,
) -> Option<&'static MappedFile> {
    // Try under each syslibroot, then the raw path: reexports between
    // freshly built dylibs use absolute install names outside any SDK.
    let mut roots: Vec<String> = ctx.args.syslibroot.clone();
    roots.push(String::new());

    for root in &roots {
        let base = if root.is_empty() {
            std::path::PathBuf::from(install_name)
        } else {
            std::path::Path::new(root).join(install_name.trim_start_matches('/'))
        };
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

/// Interprets a .tbd's "$ld$..." export names. These are not symbols
/// but directives to the linker, invented so a stub library could
/// change shape per deployment target without a file format change:
/// $ld$add$os<ver>$<sym> exports <sym> only when the target equals
/// <ver>, $ld$hide$os<ver>$<sym> hides one, $ld$install_name$os<ver>$
/// <name> substitutes the recorded install name, and
/// $ld$previous$<name>$<compat>$<platform>$<lo>$<hi>$<sym>$ applies
/// <name> when the target platform matches and lo <= minos < hi
/// (the per-symbol form never worked in ld64 and is ignored, as sold
/// found). Apple uses these when a symbol moves between libraries:
/// old targets keep binding it where it used to live.
fn interpret_ld_symbols<E: Arch>(ctx: &Context<E>, tbd: &mut tapi::TbdFile) {
    let minos = ctx.args.platform_minos;
    let mut added: Vec<String> = Vec::new();
    let mut hidden: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut install_name: Option<String> = None;

    for name in &tbd.exports {
        if let Some(rest) = name.strip_prefix("$ld$previous$") {
            let f: Vec<&str> = rest.split('$').collect();
            if f.len() < 6 {
                crate::warn!(ctx, "malformed linker directive: {name}");
            } else if f[5].is_empty()
                && f[2].parse::<u32>() == Ok(ctx.args.platform)
                && tapi::parse_version(f[3]) <= minos
                && minos < tapi::parse_version(f[4])
            {
                install_name = Some(f[0].to_string());
            }
        } else if let Some(rest) = name.strip_prefix("$ld$add$os") {
            if let Some((ver, sym)) = rest.split_once('$') {
                if tapi::parse_version(ver) == minos {
                    added.push(sym.to_string());
                }
            }
        } else if let Some(rest) = name.strip_prefix("$ld$hide$os") {
            if let Some((ver, sym)) = rest.split_once('$') {
                if tapi::parse_version(ver) == minos {
                    hidden.insert(sym.to_string());
                }
            }
        } else if let Some(rest) = name.strip_prefix("$ld$install_name$os") {
            if let Some((ver, new_name)) = rest.split_once('$') {
                if tapi::parse_version(ver) == minos {
                    install_name = Some(new_name.to_string());
                }
            }
        }
    }

    tbd.exports
        .retain(|n| !n.starts_with("$ld$") && !hidden.contains(n));
    tbd.weak_exports.retain(|n| !hidden.contains(n));
    tbd.exports.extend(added);
    if let Some(name) = install_name {
        tbd.install_name = name;
    }
}

pub fn parse_dylib<E: Arch>(ctx: &mut Context<E>, mf: &'static MappedFile) -> usize {
    let mut tbd = tapi::parse(&ctx.diag, mf);
    interpret_ld_symbols(ctx, &mut tbd);
    let idx = ctx.dylibs.len();
    let mut exports: std::collections::HashSet<String> =
        tbd.exports.into_iter().collect();
    exports.extend(tbd.weak_exports);
    let mut tlv_exports: std::collections::HashSet<String> =
        tbd.tlv_exports.into_iter().collect();
    exports.extend(tlv_exports.iter().cloned());

    // A dylib's reexported libraries resolve through it in the two-level
    // namespace, so their exports count as this dylib's. Reexports not
    // inlined in this .tbd are separate files, possibly reexporting
    // further.
    let mut queue: Vec<(String, String)> = tbd
        .external_reexports
        .into_iter()
        .map(|name| (name, dir_of(&mf.name)))
        .collect();
    let mut visited = std::collections::HashSet::new();
    while let Some((name, loader_dir)) = queue.pop() {
        if !visited.insert(name.clone()) {
            continue;
        }
        let Some(dep) = resolve_dylib_ref(ctx, &name, &loader_dir, &[]) else {
            crate::warn!(ctx, "{}: reexported library not found: {}", mf.name, name);
            continue;
        };
        let mut dep_tbd = tapi::parse(&ctx.diag, dep);
        interpret_ld_symbols(ctx, &mut dep_tbd);
        exports.extend(dep_tbd.exports);
        exports.extend(dep_tbd.weak_exports);
        tlv_exports.extend(dep_tbd.tlv_exports.iter().cloned());
        exports.extend(dep_tbd.tlv_exports);
        for dep_name in dep_tbd.external_reexports {
            queue.push((dep_name, dir_of(&dep.name)));
        }
    }

    let priority = ctx.next_priority();
    add_dylib(
        ctx,
        DylibFile {
            path: mf.name.clone(),
            install_name: tbd.install_name,
            current_version: tbd.current_version,
            compatibility_version: encode_version(1, 0, 0),
            dylib_idx: idx as i32 + 1,
            priority,
            is_weak: false,
            is_reexported: false,
            is_needed: false,
            is_dead_strippable: false,
            is_app_extension_safe: !tbd.not_app_extension_safe,
            sub_framework: None,
            sub_clients: Vec::new(),
            exports,
            tlv_exports,
        },
    )
}

/// Registers a dylib, deduplicating by install name: several libraries
/// (libc, libm, ...) are stubs for the same /usr/lib/libSystem.B.dylib,
/// and dyld refuses an image that lists one install name twice.
fn add_dylib<E: Arch>(ctx: &mut Context<E>, dylib: DylibFile) -> usize {
    // An app extension runs in a constrained sandbox; a dylib must opt
    // in (ld64's -application_extension sets MH_APP_EXTENSION_SAFE, or
    // a .tbd omits not_app_extension_safe) before extension code may
    // link it. ld64 warns rather than errs, and -w silences it.
    if ctx.args.application_extension && !dylib.is_app_extension_safe {
        crate::warn!(
            ctx,
            "linking against a dylib which is not safe for use in application extensions: {}",
            dylib.install_name
        );
    }

    // A subframework may only be linked by its umbrella or by a client
    // it names. The client's identity is -client_name, or the output's
    // leaf name with any "lib" prefix and extension shed - the same
    // derivation ld64 uses.
    if let Some(umbrella) = &dylib.sub_framework {
        let client = match &ctx.args.client_name {
            Some(name) => name.clone(),
            None => {
                let leaf = ctx.args.output.rsplit('/').next().unwrap_or("");
                let stem = leaf.split('.').next().unwrap_or(leaf);
                stem.strip_prefix("lib").unwrap_or(stem).to_string()
            }
        };
        let ours = ctx.args.umbrella.as_deref() == Some(umbrella.as_str());
        if !ours && client != *umbrella && !dylib.sub_clients.contains(&client) {
            crate::error!(
                ctx,
                "cannot link directly with {}: not an allowed client of umbrella framework {}",
                dylib.install_name,
                umbrella
            );
        }
    }
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
