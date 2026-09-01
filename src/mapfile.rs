//! -map file output: a report of where every object file, section and
//! symbol ended up, in ld64's format.

use std::io::Write;

use crate::arch::Arch;
use crate::context::Context;
use crate::error::errno_string;
use crate::fatal;
use crate::symbol::Origin;

/// Writes the -dependency_info file: Xcode's incremental build system
/// reads it to learn which files the link actually consumed. The
/// format is binary: an opcode byte then a NUL-terminated string -
/// 0x00 version, 0x10 input file, 0x11 file that was looked up but
/// missing, 0x40 output file.
pub fn write_dependency_info<E: Arch>(ctx: &Context<E>) {
    let Some(path) = &ctx.args.dependency_info else {
        return;
    };
    let Ok(file) = std::fs::File::create(path) else {
        fatal!(ctx, "cannot open {path}: {}", errno_string());
    };
    let mut out = std::io::BufWriter::new(file);
    let mut emit = |op: u8, s: &str| {
        let _ = out.write_all(&[op]);
        let _ = out.write_all(s.as_bytes());
        let _ = out.write_all(&[0]);
    };

    emit(0x00, concat!("mold-macho ", env!("CARGO_PKG_VERSION")));
    let mut inputs: Vec<&str> = ctx
        .objs
        .iter()
        .filter(|o| o.is_alive)
        .map(|o| o.mf.parent.map(|p| p.name.as_str()).unwrap_or(o.mf.name.as_str()))
        .collect();
    inputs.extend(ctx.visited_files.iter().map(String::as_str));
    inputs.sort_unstable();
    inputs.dedup();
    for name in inputs {
        emit(0x10, name);
    }
    emit(0x40, &ctx.args.output);
}

pub fn print_map<E: Arch>(ctx: &Context<E>) {
    let Some(path) = &ctx.args.map else { return };
    let Ok(file) = std::fs::File::create(path) else {
        fatal!(ctx, "cannot open {path}: {}", errno_string());
    };
    let mut out = std::io::BufWriter::new(file);

    let _ = writeln!(out, "# Path: {}", ctx.args.output);
    let _ = writeln!(out, "# Arch: {}", E::NAME);
    let _ = writeln!(out, "# Object files:");
    for (i, obj) in ctx.objs.iter().enumerate() {
        if obj.is_alive {
            let _ = writeln!(out, "[{i:3}] {}", obj.mf.name);
        }
    }

    let _ = writeln!(out, "# Sections:");
    let _ = writeln!(out, "# Address\tSize    \tSegment\tSection");
    for seg in &ctx.segments {
        for &idx in &seg.chunks {
            let chunk = &ctx.chunks[idx];
            if chunk.hdr.is_sect {
                let _ = writeln!(
                    out,
                    "0x{:08X}\t0x{:08X}\t{}\t{}",
                    chunk.hdr.addr, chunk.hdr.size, chunk.hdr.segname, chunk.hdr.sectname
                );
            }
        }
    }

    // Defined symbols with their addresses and owning objects, sorted by
    // address.
    let mut syms: Vec<(u64, usize, &str)> = Vec::new();
    for i in 0..ctx.symtab.syms.len() {
        let sym = &ctx.symtab[i];
        let Origin::Obj(obj) = sym.origin else {
            continue;
        };
        let Some(isec) = sym.isec else { continue };
        if !ctx.isecs[ctx.resolve_isec(isec)].is_alive || sym.name.is_empty() {
            continue;
        }
        syms.push((ctx.sym_addr(i), obj, sym.name));
    }
    syms.sort();

    let _ = writeln!(out, "# Symbols:");
    let _ = writeln!(out, "# Address\tFile  Name");
    for (addr, obj, name) in syms {
        let _ = writeln!(out, "0x{addr:08X}\t[{obj:3}] {name}");
    }
}
