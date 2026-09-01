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

    // Guess the target from -arch, then from the first Mach-O input
    // file, falling back to the host. If the guess turns out wrong,
    // start over with the right one.
    let mut target = argv
        .windows(2)
        .find(|w| w[0] == "-arch")
        .map(|w| w[1].clone())
        .or_else(|| sniff_target(&argv))
        .unwrap_or_else(|| host_target().to_string());

    loop {
        match link_for_target(&target, &argv, &diag) {
            Ok(status) => return status,
            Err(actual) => target = actual,
        }
    }
}

/// Reads the CPU type of the first Mach-O file named on the command
/// line, if any.
fn sniff_target(argv: &[String]) -> Option<String> {
    use crate::macho::*;
    for arg in &argv[1..] {
        if arg.starts_with('-') {
            continue;
        }
        let Ok(data) = std::fs::read(arg) else { continue };
        if data.len() < 8 {
            continue;
        }
        let magic = u32::from_le_bytes(data[..4].try_into().unwrap());
        if magic == MH_MAGIC_64 {
            let cputype = u32::from_le_bytes(data[4..8].try_into().unwrap());
            if let Some(name) = crate::arch::cputype_name(cputype) {
                return Some(name.to_string());
            }
        }
    }
    None
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
    let cmdline = cmdline::expand_response_files(diag, cmdline);
    let args = cmdline::parse_args(diag, &cmdline);

    if let Some(arch) = &args.arch {
        if arch != E::NAME {
            return Err(arch.clone());
        }
    }

    let mut ctx: Context<E> = Context::new(args, Diagnostics::new(false));
    ctx.diag.set_suppress_warnings(ctx.args.suppress_warnings);

    // Read every input eagerly, then resolve; loading auto-linked
    // libraries or the LTO output adds inputs, so resolution repeats
    // until the input set is stable.
    passes::read_input_files(&mut ctx);
    ctx.diag.checkpoint();
    loop {
        passes::resolve_symbols(&mut ctx);
        if !passes::load_autolink_deps(&mut ctx) {
            break;
        }
    }
    if passes::run_lto(&mut ctx) {
        loop {
            passes::resolve_symbols(&mut ctx);
            if !passes::load_autolink_deps(&mut ctx) {
                break;
            }
        }
    }
    passes::sweep_dead_files(&mut ctx);
    if ctx.args.relocatable {
        passes::merge_literals(&mut ctx);
        passes::create_output_chunks(&mut ctx);
        crate::relocatable::link(&mut ctx);
        ctx.diag.checkpoint();
        return Ok(0);
    }
    passes::convert_init_offsets(&mut ctx);
    passes::merge_literals(&mut ctx);
    passes::create_synthetic_symbols(&mut ctx);
    passes::convert_common_symbols(&mut ctx);
    passes::create_objc_msgsend_stubs(&mut ctx);
    passes::auto_hide_weak_defs(&mut ctx);
    passes::check_undefined_symbols(&mut ctx);
    passes::print_dependencies(&ctx);
    passes::dead_strip_dylibs(&mut ctx);
    ctx.diag.checkpoint();
    if ctx.args.dead_strip {
        passes::dead_strip(&mut ctx);
    }
    if ctx.args.deduplicate {
        crate::icf::fold_identical_code(&mut ctx);
    }
    passes::scan_relocs(&mut ctx);
    passes::scan_unwind_personalities(&mut ctx);
    passes::scan_objc_stubs(&mut ctx);

    // Decide the output layout
    passes::create_output_chunks(&mut ctx);
    passes::compute_symtab(&mut ctx);
    passes::assign_offsets(&mut ctx);
    passes::resolve_boundary_symbols(&mut ctx);
    passes::resolve_entry(&mut ctx);
    ctx.diag.checkpoint();
    crate::mapfile::print_map(&ctx);
    crate::mapfile::write_dependency_info(&ctx);

    // Write the output
    let mut buf = vec![0; ctx.output_size as usize];
    passes::copy_chunks(&ctx, &mut buf);
    ctx.diag.checkpoint();
    output_file::write(&ctx.diag, &ctx.args.output, &buf);

    Ok(0)
}
