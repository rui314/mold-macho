//! The linker driver: runs the passes in order.

use crate::arch::Arch;
use crate::cmdline;
use crate::dead_strip;
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

    // Fork so exit latency (unmapping every input) hides behind the
    // parent's return, as in mold; MOLD_NO_FORK=1 keeps one process
    // for debuggers and profilers.
    if std::env::var_os("MOLD_NO_FORK").is_none() {
        crate::subprocess::fork_child();
    }

    let mut ctx: Context<E> = Context::new(args, Diagnostics::new(false));
    ctx.diag.set_suppress_warnings(ctx.args.suppress_warnings);

    // -print_statistics phase timer, in the spirit of mold's --perf.
    let t0 = std::time::Instant::now();
    let mut phases: Vec<(&str, std::time::Duration)> = Vec::new();
    let mut last = t0;
    let mut lap = |phases: &mut Vec<(&str, std::time::Duration)>, name: &'static str| {
        let now = std::time::Instant::now();
        phases.push((name, now - last));
        last = now;
    };

    // Read every input eagerly, then resolve; loading auto-linked
    // libraries or the LTO output adds inputs, so resolution repeats
    // until the input set is stable.
    passes::read_input_files(&mut ctx);
    ctx.diag.checkpoint();
    lap(&mut phases, "parse");
    loop {
        passes::resolve_symbols(&mut ctx);
        match passes::load_autolink_deps(&mut ctx) {
            passes::Autolinked::Nothing => break,
            passes::Autolinked::DylibsOnly(first) => {
                passes::claim_new_dylibs(&mut ctx, first);
                break;
            }
            passes::Autolinked::Objects => {}
        }
    }
    if passes::run_lto(&mut ctx) {
        loop {
            passes::resolve_symbols(&mut ctx);
            match passes::load_autolink_deps(&mut ctx) {
                passes::Autolinked::Nothing => break,
                passes::Autolinked::DylibsOnly(first) => {
                    passes::claim_new_dylibs(&mut ctx, first);
                    break;
                }
                passes::Autolinked::Objects => {}
            }
        }
    }
    lap(&mut phases, "resolve");
    passes::remove_unreachable_files(&mut ctx);
    if ctx.args.relocatable {
        passes::merge_literals(&mut ctx);
        passes::create_output_sections(&mut ctx);
        crate::relocatable::link(&mut ctx);
        ctx.diag.checkpoint();
        return Ok(0);
    }
    passes::convert_init_offsets(&mut ctx);
    {
        let tt = std::time::Instant::now();
        passes::merge_literals(&mut ctx);
        if std::env::var_os("MOLD_TIMING").is_some() {
            eprintln!("    merge_literals {:?}", tt.elapsed());
        }
    }
    passes::add_synthetic_symbols(&mut ctx);
    passes::convert_common_symbols(&mut ctx);
    passes::create_objc_msgsend_stubs(&mut ctx);
    passes::auto_hide_weak_defs(&mut ctx);
    passes::coalesce_weak_defs(&mut ctx);
    passes::check_undefined_symbols(&mut ctx);
    passes::print_dependencies(&ctx);
    passes::print_why_load(&ctx);
    passes::print_trace(&ctx);
    passes::dead_strip_dylibs(&mut ctx);
    ctx.diag.checkpoint();
    if ctx.args.dead_strip {
        let tt = std::time::Instant::now();
        dead_strip::dead_strip(&mut ctx);
        if std::env::var_os("MOLD_TIMING").is_some() {
            eprintln!("    dead_strip {:?}", tt.elapsed());
        }
    }
    if ctx.args.deduplicate {
        let tt = std::time::Instant::now();
        crate::icf::icf_sections(&mut ctx);
        if std::env::var_os("MOLD_TIMING").is_some() {
            eprintln!("    icf {:?}", tt.elapsed());
        }
    }
    lap(&mut phases, "passes");
    {
        let tt = std::time::Instant::now();
        passes::scan_relocations(&mut ctx);
        if std::env::var_os("MOLD_TIMING").is_some() {
            eprintln!("    scan_relocations {:?}", tt.elapsed());
        }
    }
    passes::scan_unwind_personalities(&mut ctx);
    passes::scan_objc_stubs(&mut ctx);

    // Decide the output layout
    let tt = std::time::Instant::now();
    passes::create_output_sections(&mut ctx);
    let t_sections = tt.elapsed();
    // The output symbol table builds inside set_osec_offsets, as part
    // of the parallel __LINKEDIT task group.
    let tt = std::time::Instant::now();
    passes::set_osec_offsets(&mut ctx);
    let t_offsets = tt.elapsed();
    if std::env::var_os("MOLD_TIMING").is_some() {
        eprintln!("    sections {t_sections:?} offsets {t_offsets:?}");
    }
    passes::fix_synthetic_symbols(&mut ctx);
    passes::resolve_entry(&mut ctx);
    ctx.diag.checkpoint();
    crate::mapfile::print_map(&ctx);
    crate::mapfile::write_dependency_info(&ctx);
    lap(&mut phases, "layout");

    // Write the output
    let mut buf = vec![0; ctx.output_size as usize];
    passes::copy_chunks(&ctx, &mut buf);
    ctx.diag.checkpoint();
    output_file::write(&ctx.diag, &ctx.args.output, &buf);
    crate::subprocess::notify_parent();
    lap(&mut phases, "copy+write");

    // ld64's -print_statistics reports its phase times and memory to
    // stderr; ours reports phases and the sizes that drive them.
    if ctx.args.print_statistics {
        eprintln!("ld total time: {:>8.1?}", t0.elapsed());
        for (name, dur) in &phases {
            eprintln!("  {name:<10} {dur:>8.1?}");
        }
        eprintln!(
            "  objects: {} alive of {}; dylibs: {}; output: {} bytes",
            ctx.objs.iter().filter(|o| o.is_alive).count(),
            ctx.objs.len(),
            ctx.dylibs.len(),
            ctx.output_size,
        );
    }

    Ok(0)
}
