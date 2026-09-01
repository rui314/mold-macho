//! The `ld64.mold` executable: runs the linker instantiated for the
//! target the inputs are for. Each target is instantiated in a crate of
//! its own so that the compiler can build them in parallel, and a feature
//! per target decides which of them are built in.

use mold_macho::error::Diagnostics;

fn link_for_target(target: &str, cmdline: &[String], diag: &Diagnostics) -> Result<i32, String> {
    match target {
        #[cfg(feature = "arm64")]
        "arm64" => mold_macho_target_arm64::link(cmdline, diag),
        _ => {
            diag.fatal(format_args!("unsupported target: {target}"));
        }
    }
}

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    let status = mold_macho::driver::main(argv, link_for_target);
    mold_macho::error::exit_after_cleanup(status);
}
