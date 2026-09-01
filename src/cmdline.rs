//! Command line parsing.
//!
//! The command line is compatible with Apple's ld64: options are single-dash
//! long names, and input files and `-l` options are position-dependent.

use crate::error::Diagnostics;
use crate::fatal;
use crate::macho::*;

/// An input in command line order.
#[derive(Clone, Debug)]
pub enum InputArg {
    /// A file path.
    File(String),
    /// `-lfoo`: a library to search for in the library paths. The flag
    /// marks a weak library (`-weak-lfoo`).
    Lib(String, bool),
    /// `-framework Foo`: a framework to search for in the framework
    /// paths. The flag marks a weak framework.
    Framework(String, bool),
    /// `-force_load path`: an archive all of whose members are linked.
    ForceLoad(String),
    /// `-weak_library path`: a dylib whose absence is tolerated at load
    /// time.
    WeakFile(String),
}

/// Parsed command line arguments.
#[derive(Debug)]
pub struct Args {
    pub output: String,
    /// The output file type: MH_EXECUTE, MH_DYLIB or MH_BUNDLE.
    pub output_type: u32,
    pub install_name: Option<String>,
    pub arch: Option<String>,
    pub entry: String,
    pub platform: u32,
    pub platform_minos: u32,
    pub platform_sdk: u32,
    pub syslibroot: Vec<String>,
    pub library_paths: Vec<String>,
    pub framework_paths: Vec<String>,
    pub inputs: Vec<InputArg>,
    pub rpaths: Vec<String>,
    pub adhoc_codesign: bool,
    pub dead_strip: bool,
    pub all_load: bool,
    pub load_objc: bool,
    pub dynamic: bool,
    pub headerpad: u64,
    pub pagezero_size: u64,
}

impl Default for Args {
    fn default() -> Self {
        Args {
            output: "a.out".to_string(),
            output_type: MH_EXECUTE,
            install_name: None,
            arch: None,
            entry: "_main".to_string(),
            platform: PLATFORM_MACOS,
            platform_minos: encode_version(0, 0, 0),
            platform_sdk: encode_version(0, 0, 0),
            syslibroot: Vec::new(),
            library_paths: Vec::new(),
            framework_paths: Vec::new(),
            inputs: Vec::new(),
            rpaths: Vec::new(),
            adhoc_codesign: true,
            dead_strip: false,
            all_load: false,
            load_objc: false,
            dynamic: true,
            headerpad: 0x100,
            pagezero_size: 0x1_0000_0000,
        }
    }
}

/// Parses an X.Y.Z version string.
fn parse_version(diag: &Diagnostics, arg: &str) -> u32 {
    let mut it = arg.split('.');
    let mut next = |what| match it.next() {
        None => 0,
        Some(s) => match s.parse() {
            Ok(num) => num,
            Err(_) => fatal!(diag, "malformed version number: {what}: {arg}"),
        },
    };
    let major = next("major");
    let minor = next("minor");
    let patch = next("patch");
    encode_version(major, minor, patch)
}

fn parse_platform(diag: &Diagnostics, arg: &str) -> u32 {
    match arg {
        "macos" | "macosx" => PLATFORM_MACOS,
        _ => fatal!(diag, "unsupported platform: {arg}"),
    }
}

pub fn parse_args(diag: &Diagnostics, cmdline: &[String]) -> Args {
    let mut args = Args::default();
    let mut i = 1;

    let next_arg = |i: &mut usize| -> &str {
        *i += 1;
        match cmdline.get(*i) {
            Some(val) => val,
            None => fatal!(diag, "option {}: argument missing", cmdline[*i - 1]),
        }
    };

    while i < cmdline.len() {
        let opt = cmdline[i].as_str();
        match opt {
            "-o" => args.output = next_arg(&mut i).to_string(),
            "-arch" => args.arch = Some(next_arg(&mut i).to_string()),
            "-e" => args.entry = next_arg(&mut i).to_string(),
            "-platform_version" => {
                args.platform = parse_platform(diag, next_arg(&mut i));
                args.platform_minos = parse_version(diag, next_arg(&mut i));
                args.platform_sdk = parse_version(diag, next_arg(&mut i));
            }
            "-syslibroot" => args.syslibroot.push(next_arg(&mut i).to_string()),
            "-L" => args.library_paths.push(next_arg(&mut i).to_string()),
            "-l" => args
                .inputs
                .push(InputArg::Lib(next_arg(&mut i).to_string(), false)),
            "-framework" => args
                .inputs
                .push(InputArg::Framework(next_arg(&mut i).to_string(), false)),
            "-weak_framework" => args
                .inputs
                .push(InputArg::Framework(next_arg(&mut i).to_string(), true)),
            "-weak_library" => args
                .inputs
                .push(InputArg::WeakFile(next_arg(&mut i).to_string())),
            "-filelist" => {
                // A file listing one input path per line, optionally
                // with a directory prefix after a comma.
                let arg = next_arg(&mut i).to_string();
                let (path, dir) = match arg.split_once(',') {
                    Some((path, dir)) => (path.to_string(), format!("{dir}/")),
                    None => (arg, String::new()),
                };
                match std::fs::read_to_string(&path) {
                    Ok(text) => {
                        for line in text.lines() {
                            if !line.is_empty() {
                                args.inputs.push(InputArg::File(format!("{dir}{line}")));
                            }
                        }
                    }
                    Err(_) => fatal!(diag, "cannot read -filelist file: {path}"),
                }
            }
            "-F" => args.framework_paths.push(next_arg(&mut i).to_string()),
            "-dylib" => args.output_type = MH_DYLIB,
            "-bundle" => args.output_type = MH_BUNDLE,
            "-rpath" => args.rpaths.push(next_arg(&mut i).to_string()),
            "-install_name" | "-dylib_install_name" => {
                args.install_name = Some(next_arg(&mut i).to_string())
            }
            "-adhoc_codesign" => args.adhoc_codesign = true,
            "-no_adhoc_codesign" => args.adhoc_codesign = false,
            "-dynamic" => args.dynamic = true,
            "-headerpad" => {
                let val = next_arg(&mut i);
                match u64::from_str_radix(val.trim_start_matches("0x"), 16) {
                    Ok(num) => args.headerpad = num,
                    Err(_) => fatal!(diag, "malformed -headerpad: {val}"),
                }
            }

            "-dead_strip" => args.dead_strip = true,
            "-all_load" => args.all_load = true,
            "-noall_load" => args.all_load = false,
            "-ObjC" => args.load_objc = true,
            "-force_load" => args
                .inputs
                .push(InputArg::ForceLoad(next_arg(&mut i).to_string())),

            // Ignored options
            "-demangle" | "-no_deduplicate" | "-no_uuid" => {}

            // Ignored options with an argument
            "-lto_library" | "-mllvm" | "-dependency_info" | "-object_path_lto" => {
                next_arg(&mut i);
            }

            _ => {
                if let Some(name) = opt.strip_prefix("-weak-l") {
                    args.inputs.push(InputArg::Lib(name.to_string(), true));
                } else if let Some(name) = opt.strip_prefix("-l") {
                    args.inputs.push(InputArg::Lib(name.to_string(), false));
                } else if let Some(path) = opt.strip_prefix("-L") {
                    args.library_paths.push(path.to_string());
                } else if let Some(path) = opt.strip_prefix("-F") {
                    args.framework_paths.push(path.to_string());
                } else if opt.starts_with('-') {
                    fatal!(diag, "unknown command line option: {opt}");
                } else {
                    args.inputs.push(InputArg::File(opt.to_string()));
                }
            }
        }
        i += 1;
    }

    // A dylib is loaded at an arbitrary address; only a main executable
    // reserves the low 4 GiB against NULL dereferences.
    if args.output_type != MH_EXECUTE {
        args.pagezero_size = 0;
    }

    args
}
