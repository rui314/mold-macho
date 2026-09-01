//! -r: relocatable output.
//!
//! `ld -r` combines object files into one bigger object file instead
//! of a final image: sections are merged and laid out from address 0
//! in a single nameless segment, symbols keep their definitions and
//! undefined references, and - the essential part - relocations are
//! *regenerated* against the merged section and symbol tables rather
//! than applied. No dyld structures, no code signature.
//!
//! Section contents are copied raw (relocations stay unapplied), so
//! fields that embed addends keep them; only non-external relocations
//! need their embedded target addresses rewritten into the merged
//! address space. Debug info is not carried over yet.

use std::collections::HashMap;

use crate::arch::Arch;
use crate::context::Context;
use crate::error;
use crate::fatal;
use crate::input_sections::RelocTarget;
use crate::macho::*;
use crate::output_chunks::ChunkKind;
use crate::output_file;
use crate::symbol::Origin;
use crate::util::align_to;

pub fn link<E: Arch>(ctx: &mut Context<E>) {
    // Lay out the merged sections from address zero, zero-fill
    // sections last: an object's file image mirrors its address
    // space (each section's file offset is the segment's plus its
    // address), so content sections must precede the sections that
    // occupy addresses but no file bytes.
    let mut addr: u64 = 0;
    let mut section_chunks: Vec<usize> = (0..ctx.chunks.len())
        .filter(|&idx| matches!(ctx.chunks[idx].kind, ChunkKind::Output { .. }))
        .collect();
    section_chunks.sort_by_key(|&idx| ctx.chunks[idx].is_zerofill());
    for &idx in &section_chunks {
        let chunk = &mut ctx.chunks[idx];
        addr = align_to(addr, 1 << chunk.hdr.p2align);
        chunk.hdr.addr = addr;
        addr += chunk.hdr.size;
    }
    let vmsize = addr;

    // The output symbol table: locals per object, then defined
    // externals, then undefineds, with an index map for relocations.
    let mut strtab: Vec<u8> = vec![b' ', 0];
    let add_string = |strtab: &mut Vec<u8>, s: &str| -> u32 {
        let off = strtab.len() as u32;
        strtab.extend_from_slice(s.as_bytes());
        strtab.push(0);
        off
    };

    // Section ordinals are 1-based positions among the emitted
    // sections only.
    let mut ordinals = vec![0u8; ctx.chunks.len()];
    for (i, &idx) in section_chunks.iter().enumerate() {
        ordinals[idx] = i as u8 + 1;
    }
    let mut nlists_out: Vec<NList> = Vec::new();
    let mut index_of_sym: HashMap<usize, u32> = HashMap::new();

    let sym_addr = |ctx: &Context<E>, id: usize| -> u64 {
        let sym = &ctx.symtab[id];
        match sym.isec {
            Some(isec) => {
                let isec = &ctx.isecs[ctx.resolve_isec(isec)];
                ctx.chunks[isec.osec].hdr.addr + isec.output_offset + sym.value
            }
            None => sym.value,
        }
    };

    // Local symbols.
    for obj in &ctx.objs {
        if !obj.is_alive {
            continue;
        }
        for (nlist, &sym_id) in obj.nlists.iter().zip(&obj.syms) {
            if nlist.is_stab() || nlist.is_extern() {
                continue;
            }
            let sym = &ctx.symtab[sym_id];
            let Some(isec) = sym.isec else { continue };
            let isec = ctx.resolve_isec(isec);
            if !ctx.isecs[isec].is_alive || sym.name.is_empty() {
                continue;
            }
            index_of_sym.insert(sym_id, nlists_out.len() as u32);
            nlists_out.push(NList {
                n_strx: add_string(&mut strtab, sym.name),
                n_type: nlist.n_type,
                n_sect: ordinals[ctx.isecs[isec].osec],
                n_desc: nlist.n_desc,
                n_value: sym_addr(ctx, sym_id),
            });
        }
    }
    let nlocal = nlists_out.len() as u32;

    // Defined externals, sorted by name.
    let mut globals: Vec<usize> = (0..ctx.symtab.syms.len())
        .filter(|&i| {
            let sym = &ctx.symtab[i];
            sym.is_extern
                && matches!(sym.origin, Origin::Obj(_))
                && sym
                    .isec
                    .is_none_or(|isec| ctx.isecs[ctx.resolve_isec(isec)].is_alive)
        })
        .collect();
    globals.sort_by_key(|&i| ctx.symtab[i].name);
    for &i in &globals {
        let sym = &ctx.symtab[i];
        let (n_type, n_sect) = match sym.isec {
            Some(isec) => (
                N_SECT | N_EXT | if sym.is_private_extern { N_PEXT } else { 0 },
                ordinals[ctx.isecs[ctx.resolve_isec(isec)].osec],
            ),
            None => (N_ABS | N_EXT, 0),
        };
        let mut n_desc = 0;
        if sym.is_weak_def {
            n_desc |= N_WEAK_DEF;
        }
        index_of_sym.insert(i, nlists_out.len() as u32);
        nlists_out.push(NList {
            n_strx: add_string(&mut strtab, sym.name),
            n_type,
            n_sect,
            n_desc,
            n_value: sym_addr(ctx, i),
        });
    }
    let nextdef = nlists_out.len() as u32 - nlocal;

    // Undefined and tentative symbols, sorted by name.
    let mut undefs: Vec<usize> = (0..ctx.symtab.syms.len())
        .filter(|&i| {
            let sym = &ctx.symtab[i];
            sym.is_used && (!sym.is_defined() || sym.is_common)
        })
        .collect();
    undefs.sort_by_key(|&i| ctx.symtab[i].name);
    for &i in &undefs {
        let sym = &ctx.symtab[i];
        let mut n_desc = 0;
        let mut n_value = 0;
        if sym.is_common {
            n_value = sym.value;
            n_desc |= (sym.common_p2align as u16) << 8;
        }
        index_of_sym.insert(i, nlists_out.len() as u32);
        nlists_out.push(NList {
            n_strx: add_string(&mut strtab, sym.name),
            n_type: N_UNDF | N_EXT,
            n_sect: 0,
            n_desc,
            n_value,
        });
    }
    let nundef = nlists_out.len() as u32 - nlocal - nextdef;
    while strtab.len() % 8 != 0 {
        strtab.push(0);
    }

    // Synthetic sections appended after the merged input sections.
    // `patches` are self-relative pointer cells that can only be
    // filled once the section's own address is known: value =
    // target_addr - (section_addr + offset).
    struct ExtraSection {
        segname: &'static str,
        sectname: &'static str,
        flags: u32,
        data: Vec<u8>,
        relocs: Vec<MachRel>,
        patches: Vec<(u32, u64, u8)>,
        addr: u64,
        fileoff: u64,
        reloff: u64,
    }
    let mut extras: Vec<ExtraSection> = Vec::new();

    // Re-synthesize __LD,__compact_unwind so unwind info survives the
    // merge: one 32-byte entry per record, its pointer fields set by
    // UNSIGNED relocations exactly as compilers emit them. Records
    // synthesized from DWARF FDEs are regenerated by the next link
    // from the __eh_frame emitted below, and are skipped here.
    let mut cu_data: Vec<u8> = Vec::new();
    let mut cu_relocs: Vec<MachRel> = Vec::new();
    for rec in &ctx.unwind_records {
        let isec = &ctx.isecs[rec.isec];
        if !isec.is_alive || rec.fde.is_some() {
            continue;
        }
        let entry = cu_data.len() as u32;
        let func_addr = ctx.chunks[isec.osec].hdr.addr + isec.output_offset
            + rec.input_offset as u64;
        cu_data.extend_from_slice(&func_addr.to_le_bytes());
        cu_data.extend_from_slice(&rec.code_len.to_le_bytes());
        cu_data.extend_from_slice(&rec.encoding.to_le_bytes());
        cu_relocs.push(MachRel {
            r_address: entry,
            bits: ordinals[isec.osec] as u32 | (3 << 25),
        });

        match rec.personality {
            Some(p) => {
                let Some(&symnum) = index_of_sym.get(&p) else {
                    fatal!(ctx, "-r: unwind personality lost: {}", ctx.symtab[p].name);
                };
                cu_data.extend_from_slice(&0u64.to_le_bytes());
                cu_relocs.push(MachRel {
                    r_address: entry + 16,
                    bits: symnum | (3 << 25) | (1 << 27),
                });
            }
            None => cu_data.extend_from_slice(&0u64.to_le_bytes()),
        }

        match rec.lsda {
            Some((lsda, off)) => {
                let l = &ctx.isecs[ctx.resolve_isec(lsda)];
                let lsda_addr = ctx.chunks[l.osec].hdr.addr + l.output_offset + off as u64;
                cu_data.extend_from_slice(&lsda_addr.to_le_bytes());
                cu_relocs.push(MachRel {
                    r_address: entry + 24,
                    bits: ordinals[l.osec] as u32 | (3 << 25),
                });
            }
            None => cu_data.extend_from_slice(&0u64.to_le_bytes()),
        }
    }
    if !cu_data.is_empty() {
        extras.push(ExtraSection {
            segname: "__LD",
            sectname: "__compact_unwind",
            flags: S_ATTR_DEBUG,
            data: cu_data,
            relocs: cu_relocs,
            patches: Vec::new(),
            addr: 0,
            fileoff: 0,
            reloff: 0,
        });
    }

    // Re-synthesize __TEXT,__eh_frame for functions whose unwind info
    // exists only as DWARF FDEs. The section uses the same implicit
    // self-relative addressing compilers emit - pc_begin and the LSDA
    // pointer are distances valid in the merged object's own address
    // space, needing no relocations - except the CIE's personality
    // cell, which names an external symbol and so carries the one
    // relocation objects conventionally have here: a 4-byte pc-rel
    // GOT reference (clang emits exactly this shape).
    let mut eh_data: Vec<u8> = Vec::new();
    let mut eh_relocs: Vec<MachRel> = Vec::new();
    let mut eh_patches: Vec<(u32, u64, u8)> = Vec::new();
    {
        let kept: Vec<usize> = (0..ctx.fdes.len())
            .filter(|&i| ctx.isecs[ctx.resolve_isec(ctx.fdes[i].isec)].is_alive)
            .collect();
        let mut cie_off: HashMap<usize, u32> = HashMap::new();
        for &f in &kept {
            let c = ctx.fdes[f].cie;
            if cie_off.contains_key(&c) {
                continue;
            }
            let cie = &ctx.cies[c];
            let off = eh_data.len() as u32;
            cie_off.insert(c, off);
            eh_data.extend_from_slice(&cie.data);
            if let Some(p) = cie.personality {
                let Some(&symnum) = index_of_sym.get(&p) else {
                    fatal!(ctx, "-r: unwind personality lost: {}", ctx.symtab[p].name);
                };
                let cell = (off + cie.personality_offset) as usize;
                eh_data[cell..cell + 4].copy_from_slice(&0u32.to_le_bytes());
                eh_relocs.push(MachRel {
                    r_address: off + cie.personality_offset,
                    bits: symnum
                        | (1 << 24)
                        | (2 << 25)
                        | (1 << 27)
                        | ((E::RELOC_GOTPC as u32) << 28),
                });
            }
        }
        for &f in &kept {
            let fde = &ctx.fdes[f];
            let off = eh_data.len() as u32;
            eh_data.extend_from_slice(&fde.data);
            let cie_ptr = off + 4 - cie_off[&fde.cie];
            eh_data[off as usize + 4..off as usize + 8]
                .copy_from_slice(&cie_ptr.to_le_bytes());

            let isec = &ctx.isecs[ctx.resolve_isec(fde.isec)];
            let func_addr =
                ctx.chunks[isec.osec].hdr.addr + isec.output_offset + fde.func_offset as u64;
            eh_patches.push((off + 8, func_addr, 8));

            if let Some((lsda, lsda_off)) = fde.lsda {
                let mut pos = 24;
                while eh_data[(off + pos) as usize] & 0x80 != 0 {
                    pos += 1;
                }
                pos += 1;
                let l = &ctx.isecs[ctx.resolve_isec(lsda)];
                let lsda_addr =
                    ctx.chunks[l.osec].hdr.addr + l.output_offset + lsda_off as u64;
                eh_patches.push((off + pos, lsda_addr, ctx.cies[fde.cie].lsda_size));
            }
        }
    }
    if !eh_data.is_empty() {
        extras.push(ExtraSection {
            segname: "__TEXT",
            sectname: "__eh_frame",
            // S_COALESCED plus the no-TOC/strip/live-support
            // attributes, the flags compilers give this section.
            flags: 0x6800_000b,
            data: eh_data,
            relocs: eh_relocs,
            patches: eh_patches,
            addr: 0,
            fileoff: 0,
            reloff: 0,
        });
    }

    // Regenerate each section's relocations against the merged tables.
    let mut sect_relocs: Vec<Vec<MachRel>> = Vec::new();
    for &chunk_idx in &section_chunks {
        let ChunkKind::Output { isecs, .. } = &ctx.chunks[chunk_idx].kind else {
            unreachable!()
        };
        let mut rels: Vec<MachRel> = Vec::new();
        for &id in isecs {
            let isec = &ctx.isecs[id];
            for rel in &isec.relocs {
                let r_address = (isec.output_offset + rel.offset as u64) as u32;
                let length = rel.size.trailing_zeros();

                match rel.target {
                    RelocTarget::Sym(idx) => {
                        let sym_id = ctx.objs[isec.obj].syms[idx];
                        let Some(&symnum) = index_of_sym.get(&sym_id) else {
                            fatal!(
                                ctx,
                                "-r: cannot re-emit relocation against {}",
                                ctx.symtab[sym_id].name
                            );
                        };
                        // An explicit addend record precedes relocations
                        // whose instruction can't hold one.
                        if rel.addend != 0 && E::relocatable_needs_addend(rel.r_type) {
                            rels.push(MachRel {
                                r_address,
                                bits: (rel.addend as u32 & 0xff_ffff)
                                    | (2 << 25)
                                    | ((E::RELOC_ADDEND as u32) << 28),
                            });
                        }
                        rels.push(MachRel {
                            r_address,
                            bits: symnum
                                | ((rel.is_pcrel as u32) << 24)
                                | (length << 25)
                                | (1 << 27)
                                | ((rel.r_type as u32) << 28),
                        });
                    }
                    RelocTarget::Section(target) => {
                        let target = ctx.resolve_isec(target);
                        let t = &ctx.isecs[target];
                        let ord = ordinals[t.osec] as u32;
                        rels.push(MachRel {
                            r_address,
                            bits: ord
                                | ((rel.is_pcrel as u32) << 24)
                                | (length << 25)
                                | ((rel.r_type as u32) << 28),
                        });
                    }
                }
            }
        }
        sect_relocs.push(rels);
    }

    // File layout: header, one segment command with all sections,
    // symtab commands; then section contents, relocations, symbols and
    // strings.
    let ncmds = 4;
    let num_sections = section_chunks.len() + extras.len();
    let seg_cmd_size = size_of::<SegmentCommand>() + num_sections * size_of::<MachSection>();
    let sizeofcmds = seg_cmd_size
        + size_of::<BuildVersionCommand>()
        + size_of::<SymtabCommand>()
        + size_of::<DysymtabCommand>();
    let mut off = (size_of::<MachHeader>() + sizeofcmds) as u64;

    let seg_fileoff = off;
    let mut sect_offsets = Vec::new();
    for &chunk_idx in &section_chunks {
        let chunk = &mut ctx.chunks[chunk_idx];
        if chunk.is_zerofill() {
            sect_offsets.push(0u64);
            continue;
        }
        // Mirror the address layout so the segment's filesize can
        // never exceed its vmsize.
        let fileoff = seg_fileoff + chunk.hdr.addr;
        chunk.hdr.fileoff = fileoff;
        sect_offsets.push(fileoff);
        off = fileoff + chunk.hdr.size;
    }
    // The synthetic sections sit last, in both file and address space.
    let mut extra_addr = align_to(vmsize, 8);
    let mut vmsize = vmsize;
    for extra in &mut extras {
        off = align_to(off, 8);
        extra.fileoff = off;
        extra.addr = extra_addr;
        off += extra.data.len() as u64;
        extra_addr += align_to(extra.data.len() as u64, 8);
        vmsize = extra.addr + extra.data.len() as u64;

        // Self-relative cells can be resolved now the address is set.
        for &(cell, target, size) in &extra.patches {
            let val = target.wrapping_sub(extra.addr + cell as u64);
            let cell = cell as usize;
            match size {
                4 => extra.data[cell..cell + 4]
                    .copy_from_slice(&(val as u32).to_le_bytes()),
                8 => extra.data[cell..cell + 8].copy_from_slice(&val.to_le_bytes()),
                _ => unreachable!(),
            }
        }
    }
    let content_end = off;
    off = align_to(off, 8);
    let mut reloff = Vec::new();
    for rels in &sect_relocs {
        reloff.push(off);
        off += (rels.len() * size_of::<MachRel>()) as u64;
    }
    for extra in &mut extras {
        extra.reloff = off;
        off += (extra.relocs.len() * size_of::<MachRel>()) as u64;
    }
    let symoff = off;
    off += (nlists_out.len() * size_of::<NList>()) as u64;
    let stroff = off;
    off += strtab.len() as u64;

    let mut buf = vec![0u8; off as usize];

    // Mach header
    let hdr = MachHeader {
        magic: MH_MAGIC_64,
        cputype: E::CPUTYPE,
        cpusubtype: E::CPUSUBTYPE,
        filetype: MH_OBJECT,
        ncmds,
        sizeofcmds: sizeofcmds as u32,
        flags: MH_SUBSECTIONS_VIA_SYMBOLS,
        reserved: 0,
    };
    hdr.write_to(&mut buf);
    let mut p = size_of::<MachHeader>();

    // The single nameless segment
    let seg = SegmentCommand {
        cmd: LC_SEGMENT_64,
        cmdsize: seg_cmd_size as u32,
        segname: [0; 16],
        vmaddr: 0,
        vmsize,
        fileoff: seg_fileoff,
        filesize: content_end - seg_fileoff,
        maxprot: VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE,
        initprot: VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE,
        nsects: num_sections as u32,
        flags: 0,
    };
    seg.write_to(&mut buf[p..]);
    p += size_of::<SegmentCommand>();

    for (i, &chunk_idx) in section_chunks.iter().enumerate() {
        let chunk = &ctx.chunks[chunk_idx];
        let sect = MachSection {
            sectname: str_to_name(&chunk.hdr.sectname),
            segname: str_to_name(chunk.hdr.segname),
            addr: chunk.hdr.addr,
            size: chunk.hdr.size,
            offset: sect_offsets[i] as u32,
            p2align: chunk.hdr.p2align,
            reloff: if sect_relocs[i].is_empty() {
                0
            } else {
                reloff[i] as u32
            },
            nreloc: sect_relocs[i].len() as u32,
            flags: chunk.hdr.flags,
            reserved1: 0,
            reserved2: 0,
            reserved3: 0,
        };
        sect.write_to(&mut buf[p..]);
        p += size_of::<MachSection>();
    }

    for extra in &extras {
        let sect = MachSection {
            sectname: str_to_name(extra.sectname),
            segname: str_to_name(extra.segname),
            addr: extra.addr,
            size: extra.data.len() as u64,
            offset: extra.fileoff as u32,
            p2align: 3,
            reloff: extra.reloff as u32,
            nreloc: extra.relocs.len() as u32,
            flags: extra.flags,
            reserved1: 0,
            reserved2: 0,
            reserved3: 0,
        };
        sect.write_to(&mut buf[p..]);
        p += size_of::<MachSection>();
    }

    let bv = BuildVersionCommand {
        cmd: LC_BUILD_VERSION,
        cmdsize: size_of::<BuildVersionCommand>() as u32,
        platform: ctx.args.platform,
        minos: ctx.args.platform_minos,
        sdk: ctx.args.platform_sdk,
        ntools: 0,
    };
    bv.write_to(&mut buf[p..]);
    p += size_of::<BuildVersionCommand>();

    let st = SymtabCommand {
        cmd: LC_SYMTAB,
        cmdsize: size_of::<SymtabCommand>() as u32,
        symoff: symoff as u32,
        nsyms: nlists_out.len() as u32,
        stroff: stroff as u32,
        strsize: strtab.len() as u32,
    };
    st.write_to(&mut buf[p..]);
    p += size_of::<SymtabCommand>();

    let dst_cmd = DysymtabCommand {
        cmd: LC_DYSYMTAB,
        cmdsize: size_of::<DysymtabCommand>() as u32,
        ilocalsym: 0,
        nlocalsym: nlocal,
        iextdefsym: nlocal,
        nextdefsym: nextdef,
        iundefsym: nlocal + nextdef,
        nundefsym: nundef,
        ..Default::default()
    };
    dst_cmd.write_to(&mut buf[p..]);

    // Section contents: raw copies, with non-external targets' embedded
    // addresses rewritten into the merged address space.
    for (i, &chunk_idx) in section_chunks.iter().enumerate() {
        let ChunkKind::Output { isecs, .. } = &ctx.chunks[chunk_idx].kind else {
            unreachable!()
        };
        if sect_offsets[i] == 0 {
            continue;
        }
        let base = sect_offsets[i] as usize;
        for &id in isecs {
            let isec = &ctx.isecs[id];
            if isec.data.is_empty() {
                continue;
            }
            let dst = base + isec.output_offset as usize;
            buf[dst..dst + isec.data.len()].copy_from_slice(isec.data);

            for rel in &isec.relocs {
                let RelocTarget::Section(target) = rel.target else {
                    continue;
                };
                let target = ctx.resolve_isec(target);
                let t = &ctx.isecs[target];
                let target_addr =
                    ctx.chunks[t.osec].hdr.addr + t.output_offset + rel.addend as u64;
                let loc = dst + rel.offset as usize;
                if rel.r_type == E::RELOC_UNSIGNED && !rel.is_pcrel {
                    match rel.size {
                        8 => buf[loc..loc + 8].copy_from_slice(&target_addr.to_le_bytes()),
                        4 => buf[loc..loc + 4]
                            .copy_from_slice(&(target_addr as u32).to_le_bytes()),
                        _ => {}
                    }
                } else if rel.is_pcrel {
                    // Pcrel non-external fields embed target - (P + 4).
                    let here = ctx.chunks[chunk_idx].hdr.addr
                        + isec.output_offset
                        + rel.offset as u64;
                    let val = target_addr.wrapping_sub(here + 4) as u32;
                    if rel.size == 4 {
                        buf[loc..loc + 4].copy_from_slice(&val.to_le_bytes());
                    }
                } else {
                    error!(ctx, "-r: unsupported non-external relocation");
                }
            }
        }
    }

    for extra in &extras {
        let fo = extra.fileoff as usize;
        buf[fo..fo + extra.data.len()].copy_from_slice(&extra.data);
        let mut p = extra.reloff as usize;
        for rel in &extra.relocs {
            rel.write_to(&mut buf[p..]);
            p += size_of::<MachRel>();
        }
    }

    // Relocations, symbols, strings
    for (i, rels) in sect_relocs.iter().enumerate() {
        let mut p = reloff[i] as usize;
        for rel in rels {
            rel.write_to(&mut buf[p..]);
            p += size_of::<MachRel>();
        }
    }
    let mut p = symoff as usize;
    for nlist in &nlists_out {
        nlist.write_to(&mut buf[p..]);
        p += size_of::<NList>();
    }
    buf[stroff as usize..stroff as usize + strtab.len()].copy_from_slice(&strtab);

    output_file::write(&ctx.diag, &ctx.args.output, &buf);
}
