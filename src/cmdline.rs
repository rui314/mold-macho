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
    /// `-reexport-lfoo` / `-reexport_library path`: a dylib whose
    /// exports this dylib re-exports as its own.
    ReexportLib(String),
    ReexportFile(String),
    /// `-hidden-lfoo`: an archive whose external symbols are demoted
    /// to private externals.
    HiddenLib(String),
    /// `-needed-lfoo` / `-needed_framework Foo`: always keep the
    /// dylib's load command.
    NeededLib(String),
    NeededFramework(String),
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
    /// -S: do not emit debug stab symbols.
    pub strip_debug: bool,
    pub all_load: bool,
    pub load_objc: bool,
    /// Symbols to treat as undefined from the start (-u), forcing
    /// archive members that define them to be linked.
    pub forced_undefined: Vec<String>,
    /// If set, only these symbols are exported (-exported_symbols_list
    /// or -exported_symbol).
    pub exported_symbols: Option<Vec<String>>,
    /// Symbols to remove from the exported set.
    pub unexported_symbols: Vec<String>,
    pub current_version: u32,
    pub compatibility_version: u32,
    /// -map: write a map file describing the output layout.
    pub map: Option<String>,
    /// -dependency_info: write Xcode's binary dependency listing.
    pub dependency_info: Option<String>,
    /// Emit chained fixups instead of classic dyld info. None means
    /// "decide from the deployment target".
    pub fixup_chains: Option<bool>,
    /// The libLTO to load for bitcode inputs (-lto_library).
    pub lto_library: Option<String>,
    /// -stack_size: the main thread's stack size, recorded in LC_MAIN.
    pub stack_size: u64,
    /// -sectcreate: sections to synthesize from files:
    /// (segment, section, path).
    pub sectcreate: Vec<(String, String, String)>,
    /// -r: produce a relocatable object instead of a final image.
    pub relocatable: bool,
    /// -flat_namespace: bind imports by name across all loaded images
    /// instead of to specific dylibs.
    pub flat_namespace: bool,
    /// -Z: do not search the standard library and framework
    /// directories.
    pub no_standard_dirs: bool,
    /// -x: strip non-global symbols from the output symbol table.
    pub strip_locals: bool,
    /// Fold identical functions (on by default; -no_deduplicate turns
    /// it off).
    pub deduplicate: bool,
    /// Emit LC_FUNCTION_STARTS (on by default).
    pub function_starts: bool,
    /// -init_offsets: emit initializers as 32-bit image offsets
    /// (__init_offsets) instead of absolute pointers (__mod_init_func).
    pub init_offsets: bool,
    /// Compute a content-hash LC_UUID (on by default; -no_uuid leaves
    /// it zeroed - dyld refuses executables without the load command).
    pub uuid: bool,
    /// -w: suppress warnings.
    pub suppress_warnings: bool,
    /// -undefined dynamic_lookup: leave unresolved symbols to be looked
    /// up in any loaded image at run time.
    pub undefined_dynamic_lookup: bool,
    /// -undefined warning/suppress: report unresolved symbols without
    /// failing (they resolve like dynamic_lookup).
    pub undefined_warning: bool,
    /// -U: individual symbols allowed to stay undefined.
    pub allowed_undefined: Vec<String>,
    /// -dead_strip_dylibs: drop load commands for dylibs nothing binds
    /// to.
    pub dead_strip_dylibs: bool,
    /// -bind_at_load: ask dyld to resolve all bindings at load time.
    pub bind_at_load: bool,
    /// -application_extension: mark the image safe for app extensions.
    pub application_extension: bool,
    /// -add_ast_path: Swift AST paths recorded as N_AST stabs for the
    /// debugger.
    pub add_ast_paths: Vec<String>,
    pub dynamic: bool,
    pub headerpad: u64,
    /// -search_dylibs_first: search every path for a dylib before
    /// falling back to archives.
    pub search_dylibs_first: bool,
    /// -umbrella: declare this dylib a subframework of the named
    /// umbrella framework (LC_SUB_FRAMEWORK).
    pub umbrella: Option<String>,
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
            strip_debug: false,
            all_load: false,
            load_objc: false,
            forced_undefined: Vec::new(),
            exported_symbols: None,
            unexported_symbols: Vec::new(),
            current_version: encode_version(1, 0, 0),
            compatibility_version: encode_version(1, 0, 0),
            map: None,
            dependency_info: None,
            fixup_chains: None,
            lto_library: None,
            stack_size: 0,
            sectcreate: Vec::new(),
            relocatable: false,
            flat_namespace: false,
            no_standard_dirs: false,
            strip_locals: false,
            deduplicate: true,
            function_starts: true,
            init_offsets: false,
            uuid: true,
            suppress_warnings: false,
            undefined_dynamic_lookup: false,
            undefined_warning: false,
            allowed_undefined: Vec::new(),
            dead_strip_dylibs: false,
            bind_at_load: false,
            application_extension: false,
            add_ast_paths: Vec::new(),
            dynamic: true,
            headerpad: 0x100,
            search_dylibs_first: false,
            umbrella: None,
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

/// Parses a symbol list file: one symbol per line, '#' starts a
/// comment.
fn symbol_list(text: &str) -> Vec<String> {
    text.lines()
        .map(|line| line.split('#').next().unwrap_or("").trim())
        .filter(|line| !line.is_empty())
        .map(String::from)
        .collect()
}

/// ld64 numeric option arguments are hexadecimal, with or without a
/// 0x prefix.
fn parse_hex(diag: &Diagnostics, opt: &str, val: &str) -> u64 {
    match u64::from_str_radix(val.trim_start_matches("0x"), 16) {
        Ok(num) => num,
        Err(_) => fatal!(diag, "malformed {opt}: {val}"),
    }
}

/// Expands @file response-file arguments, splitting the file's contents
/// on whitespace with simple quote handling.
pub fn expand_response_files(_diag: &Diagnostics, argv: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(argv.len());
    for arg in argv {
        if let Some(path) = arg.strip_prefix('@') {
            // Option arguments like "@rpath/libfoo.dylib" also start
            // with '@': expand only when the file actually exists.
            let Ok(text) = std::fs::read_to_string(path) else {
                out.push(arg.clone());
                continue;
            };
            let mut cur = String::new();
            let mut quote: Option<char> = None;
            for c in text.chars() {
                match quote {
                    Some(q) if c == q => quote = None,
                    Some(_) => cur.push(c),
                    None if c == '"' || c == '\'' => quote = Some(c),
                    None if c.is_whitespace() => {
                        if !cur.is_empty() {
                            out.push(std::mem::take(&mut cur));
                        }
                    }
                    None => cur.push(c),
                }
            }
            if !cur.is_empty() {
                out.push(cur);
            }
        } else {
            out.push(arg.clone());
        }
    }
    out
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
            "-needed_framework" => args
                .inputs
                .push(InputArg::NeededFramework(next_arg(&mut i).to_string())),
            "-weak_library" => args
                .inputs
                .push(InputArg::WeakFile(next_arg(&mut i).to_string())),
            "-reexport_library" => args
                .inputs
                .push(InputArg::ReexportFile(next_arg(&mut i).to_string())),
            "-sub_library" => args
                .inputs
                .push(InputArg::ReexportLib(next_arg(&mut i).to_string())),
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
            "-map" => args.map = Some(next_arg(&mut i).to_string()),
            "-fixup_chains" => args.fixup_chains = Some(true),
            "-no_fixup_chains" => args.fixup_chains = Some(false),
            "-adhoc_codesign" => args.adhoc_codesign = true,
            "-no_adhoc_codesign" => args.adhoc_codesign = false,
            "-dynamic" => args.dynamic = true,
            "-headerpad" => args.headerpad = parse_hex(diag, opt, next_arg(&mut i)),
            "-pagezero_size" => {
                args.pagezero_size = parse_hex(diag, opt, next_arg(&mut i))
            }
            "-stack_size" => args.stack_size = parse_hex(diag, opt, next_arg(&mut i)),
            "-sectcreate" => {
                let seg = next_arg(&mut i).to_string();
                let sect = next_arg(&mut i).to_string();
                let file = next_arg(&mut i).to_string();
                args.sectcreate.push((seg, sect, file));
            }
            "-x" => args.strip_locals = true,
            "-Z" => args.no_standard_dirs = true,
            "-r" => args.relocatable = true,
            "-flat_namespace" => args.flat_namespace = true,
            "-twolevel_namespace" => args.flat_namespace = false,
            "-undefined" => match next_arg(&mut i) {
                "error" => args.undefined_dynamic_lookup = false,
                "dynamic_lookup" => args.undefined_dynamic_lookup = true,
                "warning" | "suppress" => {
                    args.undefined_dynamic_lookup = true;
                    args.undefined_warning = true;
                }
                treatment => fatal!(diag, "-undefined: unsupported treatment: {treatment}"),
            },
            "-U" => args
                .allowed_undefined
                .push(next_arg(&mut i).to_string()),
            "-w" => args.suppress_warnings = true,
            "-help" => {
                println!("Usage: ld64.mold [options] file...");
                crate::error::exit_after_cleanup(0);
            }

            "-dead_strip" => args.dead_strip = true,
            "-dead_strip_dylibs" => args.dead_strip_dylibs = true,
            "-bind_at_load" => args.bind_at_load = true,
            "-application_extension" => args.application_extension = true,
            "-no_application_extension" => args.application_extension = false,
            "-add_ast_path" => args
                .add_ast_paths
                .push(next_arg(&mut i).to_string()),
            "-S" => args.strip_debug = true,
            "-all_load" => args.all_load = true,
            "-u" => args
                .forced_undefined
                .push(next_arg(&mut i).to_string()),
            "-exported_symbol" => args
                .exported_symbols
                .get_or_insert_with(Vec::new)
                .push(next_arg(&mut i).to_string()),
            "-exported_symbols_list" => {
                let path = next_arg(&mut i).to_string();
                let list = args.exported_symbols.get_or_insert_with(Vec::new);
                match std::fs::read_to_string(&path) {
                    Ok(text) => list.extend(symbol_list(&text)),
                    Err(_) => fatal!(diag, "cannot read -exported_symbols_list: {path}"),
                }
            }
            "-unexported_symbol" => args
                .unexported_symbols
                .push(next_arg(&mut i).to_string()),
            "-unexported_symbols_list" => {
                let path = next_arg(&mut i).to_string();
                match std::fs::read_to_string(&path) {
                    Ok(text) => args.unexported_symbols.extend(symbol_list(&text)),
                    Err(_) => fatal!(diag, "cannot read -unexported_symbols_list: {path}"),
                }
            }
            "-current_version" => {
                args.current_version = parse_version(diag, next_arg(&mut i))
            }
            "-compatibility_version" => {
                args.compatibility_version = parse_version(diag, next_arg(&mut i))
            }
            // ld64 prints its version banner to stdout and continues
            // with the link.
            "-v" => println!(
                "mold-macho {} (compatible with Apple ld64)",
                env!("CARGO_PKG_VERSION")
            ),
            "-noall_load" => args.all_load = false,
            "-ObjC" => args.load_objc = true,
            "-force_load" => args
                .inputs
                .push(InputArg::ForceLoad(next_arg(&mut i).to_string())),

            // The default library search behavior already matches
            // -search_paths_first: each path is tried for both a dylib
            // and an archive before moving to the next.
            "-search_paths_first" => args.search_dylibs_first = false,
            "-search_dylibs_first" => args.search_dylibs_first = true,
            "-umbrella" => args.umbrella = Some(next_arg(&mut i).to_string()),

            // Reserve enough header padding that install_name_tool can
            // grow install names in place.
            "-headerpad_max_install_names" => {
                args.headerpad = args.headerpad.max(1024);
            }

            "-no_deduplicate" => args.deduplicate = false,
            "-function_starts" => args.function_starts = true,
            "-init_offsets" => args.init_offsets = true,
            "-no_function_starts" => args.function_starts = false,

            "-no_uuid" => args.uuid = false,

            // The old pre-LC_BUILD_VERSION way of stating the
            // deployment target, still emitted by clang for older
            // -mmacosx-version-min targets. It fixes the platform to
            // macOS; the SDK version stays unset, as ld64 records when
            // it isn't told.
            "-macos_version_min" | "-macosx_version_min" => {
                args.platform = PLATFORM_MACOS;
                args.platform_minos = parse_version(diag, next_arg(&mut i));
            }

            // Ignored options. ld64 takes -O<n> as a linker
            // optimization level hint. This linker's output is always
            // deterministic, so -reproducible has nothing to switch on.
            "-demangle" | "-reproducible" | "-O0" | "-O1" | "-O2" | "-O3" => {}

            "-lto_library" => args.lto_library = Some(next_arg(&mut i).to_string()),

            "-dependency_info" => {
                args.dependency_info = Some(next_arg(&mut i).to_string())
            }

            // Ignored options with an argument
            "-mllvm" | "-object_path_lto" => {
                next_arg(&mut i);
            }

            _ => {
                if let Some(name) = opt.strip_prefix("-reexport-l") {
                    args.inputs.push(InputArg::ReexportLib(name.to_string()));
                } else if let Some(name) = opt.strip_prefix("-hidden-l") {
                    args.inputs.push(InputArg::HiddenLib(name.to_string()));
                } else if let Some(name) = opt.strip_prefix("-needed-l") {
                    args.inputs.push(InputArg::NeededLib(name.to_string()));
                } else if let Some(name) = opt.strip_prefix("-weak-l") {
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
