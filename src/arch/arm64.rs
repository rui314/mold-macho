//! The ARM64 (AArch64) target.

use crate::arch::Arch;
use crate::context::Context;
use crate::error::Diagnostics;
use crate::error;
use crate::fatal;
use crate::input_sections::{Reloc, RelocTarget};
use crate::macho::*;
use crate::output_chunks;
use crate::util::{bits, sign_extend};

#[derive(Clone, Copy, Default)]
pub struct Arm64;

fn page(val: u64) -> u64 {
    val & !0xfff
}

/// Computes the ADRP immediate for reaching `hi`'s page from `lo`'s page.
fn page_offset(hi: u64, lo: u64) -> u32 {
    let val = page(hi).wrapping_sub(page(lo));
    ((bits(val, 13, 12) << 29) | (bits(val, 32, 14) << 5)) as u32
}

fn read32(loc: &[u8]) -> u32 {
    u32::from_le_bytes(loc[..4].try_into().unwrap())
}

fn write32(loc: &mut [u8], val: u32) {
    loc[..4].copy_from_slice(&val.to_le_bytes());
}

fn write64(loc: &mut [u8], val: u64) {
    loc[..8].copy_from_slice(&val.to_le_bytes());
}

/// Writes an immediate to an ADD, LDR or STR instruction.
fn write_add_ldst(loc: &mut [u8], val: u64) {
    let insn = read32(loc);
    let mut scale = 0;

    if insn & 0x3b00_0000 == 0x3900_0000 {
        // LDR/STR accesses an aligned 1, 2, 4, 8 or 16 byte data on memory.
        // The immediate is scaled by the data size, so we need to know the
        // data size to write a correct immediate.
        //
        // The most significant two bits of the instruction usually
        // specifies the data size.
        scale = bits(insn as u64, 31, 30);

        // Vector and byte LDR/STR shares the same scale bits.
        // We can distinguish them by looking at other bits.
        if scale == 0 && insn & 0x0480_0000 == 0x0480_0000 {
            scale = 4;
        }
    }

    write32(loc, insn | ((bits(val, 11, scale as u32) as u32) << 10));
}

impl Arch for Arm64 {
    const NAME: &'static str = "arm64";
    const CPUTYPE: u32 = CPU_TYPE_ARM64;
    const CPUSUBTYPE: u32 = CPU_SUBTYPE_ARM64_ALL;
    const PAGE_SIZE: u64 = 16384;
    const STUB_SIZE: u64 = 12;
    const UNWIND_MODE_DWARF: u32 = UNWIND_ARM64_MODE_DWARF;
    const OBJC_STUB_SIZE: u64 = 32;
    const RELOC_UNSIGNED: u8 = ARM64_RELOC_UNSIGNED;
    const RELOC_SUBTRACTOR: u8 = ARM64_RELOC_SUBTRACTOR;
    const RELOC_GOTPC: u8 = ARM64_RELOC_POINTER_TO_GOT;

    fn classify_reloc(r_type: u8) -> crate::arch::RelocClass {
        use crate::arch::RelocClass;
        match r_type {
            ARM64_RELOC_BRANCH26 => RelocClass::Branch,
            ARM64_RELOC_GOT_LOAD_PAGE21
            | ARM64_RELOC_GOT_LOAD_PAGEOFF12
            | ARM64_RELOC_POINTER_TO_GOT => RelocClass::Got,
            ARM64_RELOC_TLVP_LOAD_PAGE21 | ARM64_RELOC_TLVP_LOAD_PAGEOFF12 => RelocClass::Tlv,
            _ => RelocClass::Plain,
        }
    }

    fn write_stubs(ctx: &Context<Self>, addr: u64, buf: &mut [u8]) {
        for (i, &sym) in ctx.stub_syms.iter().enumerate() {
            let ent = &mut buf[i * 12..];
            let ent_addr = addr + i as u64 * 12;
            let ptr_addr = ctx.sym_got_addr(sym);

            // adrp x16, $ptr@PAGE; ldr x16, [x16, $ptr@PAGEOFF]; br x16
            write32(&mut ent[0..], 0x9000_0010 | page_offset(ptr_addr, ent_addr));
            write32(&mut ent[4..], 0xf940_0210 | (bits(ptr_addr, 11, 3) as u32) << 10);
            write32(&mut ent[8..], 0xd61f_0200);
        }
    }

    fn write_objc_stubs(ctx: &Context<Self>, addr: u64, buf: &mut [u8]) {
        let selrefs =
            output_chunks::find_chunk(ctx, |k| matches!(k, output_chunks::ChunkKind::ObjcSelrefs))
                .unwrap();
        let selrefs_addr = ctx.chunks[selrefs].hdr.addr;
        let msgsend_got = ctx.sym_got_addr(ctx.objc_msgsend_sym.unwrap());

        for i in 0..ctx.objc_stubs.len() {
            let ent = &mut buf[i * 32..];
            let ent_addr = addr + i as u64 * 32;
            let sel_addr = selrefs_addr + i as u64 * 8;

            // adrp x1, sel@PAGE; ldr x1, [x1, sel@PAGEOFF]
            // adrp x16, _objc_msgSend@GOTPAGE; ldr x16, [...]; br x16
            write32(&mut ent[0..], 0x9000_0001 | page_offset(sel_addr, ent_addr));
            write32(&mut ent[4..], 0xf940_0021 | (bits(sel_addr, 11, 3) as u32) << 10);
            write32(&mut ent[8..], 0x9000_0010 | page_offset(msgsend_got, ent_addr + 8));
            write32(&mut ent[12..], 0xf940_0210 | (bits(msgsend_got, 11, 3) as u32) << 10);
            write32(&mut ent[16..], 0xd61f_0200);
            write32(&mut ent[20..], 0xd420_0020);
            write32(&mut ent[24..], 0xd420_0020);
            write32(&mut ent[28..], 0xd420_0020);
        }
    }

    fn read_relocs(
        diag: &Diagnostics,
        file_name: &str,
        sections: &[MachSection],
        hdr: &MachSection,
        file_data: &[u8],
        rels: &[MachRel],
    ) -> Vec<Reloc> {
        let mut vec = Vec::with_capacity(rels.len());
        let mut i = 0;

        while i < rels.len() {
            let mut addend: i64 = 0;

            // A Mach-O relocation doesn't contain an addend. UNSIGNED
            // relocs have addends in the relocated field. Addends for
            // other types of relocations are specified by prepending an
            // ADDEND reloc.
            match rels[i].r_type() {
                ARM64_RELOC_UNSIGNED => {
                    let off = hdr.offset as usize + rels[i].r_address as usize;
                    match 1 << rels[i].r_length() {
                        4 => {
                            let val = &file_data[off..off + 4];
                            addend = i32::from_le_bytes(val.try_into().unwrap()) as i64;
                        }
                        8 => {
                            let val = &file_data[off..off + 8];
                            addend = i64::from_le_bytes(val.try_into().unwrap());
                        }
                        _ => fatal!(diag, "{file_name}: bad relocation size"),
                    }
                }
                ARM64_RELOC_ADDEND => {
                    addend = sign_extend(rels[i].r_symbolnum() as u64, 23);
                    i += 1;
                }
                _ => {}
            }

            let r = &rels[i];
            let is_subtracted = i > 0 && rels[i - 1].r_type() == ARM64_RELOC_SUBTRACTOR;

            // A relocation refers to either a symbol or a section.
            let (target, addend) = if r.is_extern() {
                (RelocTarget::Sym(r.r_symbolnum() as usize), addend)
            } else {
                let addr = if r.is_pcrel() {
                    (hdr.addr + r.r_address as u64).wrapping_add_signed(addend)
                } else {
                    addend as u64
                };
                let Some(idx) = sections
                    .iter()
                    .position(|sec| sec.addr <= addr && addr < sec.addr + sec.size)
                else {
                    fatal!(diag, "{file_name}: bad relocation: {}", r.r_address);
                };
                let target = RelocTarget::Section(idx);
                (target, (addr - sections[idx].addr) as i64)
            };

            vec.push(Reloc {
                offset: r.r_address,
                r_type: r.r_type(),
                size: 1 << r.r_length(),
                is_pcrel: r.is_pcrel(),
                is_subtracted,
                target,
                addend,
            });
            i += 1;
        }

        vec
    }

    fn apply_relocs(ctx: &Context<Self>, rels: &[Reloc], obj: usize, base: u64, buf: &mut [u8]) {
        let mut i = 0;
        while i < rels.len() {
            let r = &rels[i];
            let loc = &mut buf[r.offset as usize..];
            let s = ctx.reloc_target_addr(obj, r);
            let a = r.addend;
            let p = base + r.offset as u64;

            match r.r_type {
                ARM64_RELOC_UNSIGNED => {
                    debug_assert!(r.size == 8);
                    // An imported symbol's address is written by dyld,
                    // via a bind record.
                    let imported = ctx
                        .reloc_target_sym(obj, r)
                        .is_some_and(|id| ctx.symtab[id].is_imported);
                    if imported {
                        // The slot is filled by dyld.
                    } else if ctx.reloc_target_is_tls(obj, r) {
                        // __thread_vars holds thread-pointer-relative
                        // offsets into the TLS initialization image.
                        write64(loc, s.wrapping_add_signed(a) - ctx.tls_begin);
                    } else {
                        write64(loc, s.wrapping_add_signed(a));
                    }
                }
                ARM64_RELOC_SUBTRACTOR => {
                    // A SUBTRACTOR relocation is always followed by an
                    // UNSIGNED relocation. They work as a pair to
                    // materialize a relative address between two locations.
                    i += 1;
                    debug_assert!(rels[i].r_type == ARM64_RELOC_UNSIGNED);
                    let val = ctx
                        .reloc_target_addr(obj, &rels[i])
                        .wrapping_add_signed(rels[i].addend)
                        .wrapping_sub(s);
                    match r.size {
                        4 => write32(loc, val as u32),
                        8 => write64(loc, val),
                        _ => fatal!(ctx, "bad SUBTRACTOR relocation size"),
                    }
                }
                ARM64_RELOC_BRANCH26 => {
                    let val = s.wrapping_add_signed(a).wrapping_sub(p) as i64;
                    if !(-(1 << 27)..1 << 27).contains(&val) {
                        error!(ctx, "branch target out of range: {val:x}");
                    }
                    write32(loc, read32(loc) | bits(val as u64, 27, 2) as u32);
                }
                ARM64_RELOC_TLVP_LOAD_PAGE21 => {
                    let t = ctx.sym_tlv_ptr_addr(ctx.reloc_target_sym(obj, r).unwrap());
                    let val = read32(loc) | page_offset(t.wrapping_add_signed(a), p);
                    write32(loc, val);
                }
                ARM64_RELOC_TLVP_LOAD_PAGEOFF12 => {
                    let t = ctx.sym_tlv_ptr_addr(ctx.reloc_target_sym(obj, r).unwrap());
                    write_add_ldst(loc, t.wrapping_add_signed(a));
                }
                ARM64_RELOC_PAGE21 => {
                    let val = read32(loc) | page_offset(s.wrapping_add_signed(a), p);
                    write32(loc, val);
                }
                ARM64_RELOC_PAGEOFF12 => {
                    write_add_ldst(loc, s.wrapping_add_signed(a));
                }
                ARM64_RELOC_GOT_LOAD_PAGE21 => {
                    let g = ctx.sym_got_addr(ctx.reloc_target_sym(obj, r).unwrap());
                    let val = read32(loc) | page_offset(g.wrapping_add_signed(a), p);
                    write32(loc, val);
                }
                ARM64_RELOC_GOT_LOAD_PAGEOFF12 => {
                    let g = ctx.sym_got_addr(ctx.reloc_target_sym(obj, r).unwrap());
                    write_add_ldst(loc, g.wrapping_add_signed(a));
                }
                ARM64_RELOC_POINTER_TO_GOT => {
                    let g = ctx.sym_got_addr(ctx.reloc_target_sym(obj, r).unwrap());
                    debug_assert!(r.size == 4);
                    write32(loc, g.wrapping_add_signed(a).wrapping_sub(p) as u32);
                }
                _ => fatal!(ctx, "unsupported relocation type: {}", r.r_type),
            }
            i += 1;
        }
    }
}
