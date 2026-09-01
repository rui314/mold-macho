//! The linker driver: runs the passes in order.

use crate::arch::Arch;
use crate::cmdline;
use crate::context::Context;
use crate::error::Diagnostics;
use crate::output_file;
use crate::passes;

/// Runs the linker with the given command line. Returns the exit status.
///
/// `link_for_target` links for a named target, or reports the target the
/// inputs are actually for; the executable provides it, as the targets
/// are instantiated in crates of their own.
pub fn main(
    argv: Vec<String>,
    link_for_target: impl Fn(&str, &[String], &Diagnostics) -> Result<i32, String>,
) -> i32 {
    let diag = Diagnostics::new(false);

    // Guess the target from -arch, falling back to the host. If the
    // guess turns out wrong, start over with the right one.
    let mut target = argv
        .windows(2)
        .find(|w| w[0] == "-arch")
        .map(|w| w[1].clone())
        .unwrap_or_else(|| host_target().to_string());

    loop {
        match link_for_target(&target, &argv, &diag) {
            Ok(status) => return status,
            Err(actual) => target = actual,
        }
    }
}

fn host_target() -> &'static str {
    if cfg!(target_arch = "aarch64") {
        "arm64"
    } else {
        "x86_64"
    }
}

/// Links for the target `E`, or reports the target the inputs are
/// actually for.
pub fn link<E: Arch>(cmdline: &[String], diag: &Diagnostics) -> Result<i32, String> {
    let args = cmdline::parse_args(diag, cmdline);

    if let Some(arch) = &args.arch {
        if arch != E::NAME {
            return Err(arch.clone());
        }
    }

    let mut ctx: Context<E> = Context::new(args, Diagnostics::new(false));

    // Read input files and resolve symbols
    passes::read_input_files(&mut ctx);
    ctx.diag.checkpoint();
    passes::create_synthetic_symbols(&mut ctx);
    passes::resolve_archive_members(&mut ctx);
    passes::convert_common_symbols(&mut ctx);
    passes::create_objc_msgsend_stubs(&mut ctx);
    passes::resolve_dylib_symbols(&mut ctx);
    passes::check_undefined_symbols(&ctx);
    ctx.diag.checkpoint();
    if ctx.args.dead_strip {
        passes::dead_strip(&mut ctx);
    }
    passes::scan_relocs(&mut ctx);
    passes::scan_unwind_personalities(&mut ctx);
    passes::scan_objc_stubs(&mut ctx);

    // Decide the output layout
    passes::create_output_chunks(&mut ctx);
    passes::compute_symtab(&mut ctx);
    passes::assign_offsets(&mut ctx);
    passes::resolve_entry(&mut ctx);
    ctx.diag.checkpoint();

    // Write the output
    let mut buf = vec![0; ctx.output_size as usize];
    passes::copy_chunks(&ctx, &mut buf);
    ctx.diag.checkpoint();
    output_file::write(&ctx.diag, &ctx.args.output, &buf);

    Ok(0)
}
