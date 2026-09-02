//! TAPI text-based dylib stub (.tbd) files.
//!
//! SDKs don't ship dylib binaries; each dylib is described by a YAML file
//! giving its install name, exported symbols and reexports. We don't need
//! a general YAML parser: TAPI files are machine-generated and regular, so
//! a line-oriented scan is enough.
//!
//! A .tbd file may contain multiple YAML documents: the first one is the
//! library itself, and the rest are the libraries it reexports, inlined.
//! Since reexported symbols resolve through the top-level library, all
//! documents' exports are merged.

use crate::error::Diagnostics;
use crate::fatal;
use crate::mapped_file::MappedFile;

#[derive(Debug, Default)]
#[derive(Clone)]
pub struct TbdFile {
    pub install_name: String,
    pub current_version: u32,
    pub exports: Vec<&'static str>,
    pub weak_exports: Vec<&'static str>,
    /// Exports that are thread-local variables (listed separately in
    /// .tbd files; a TLV can only be referenced through TLV
    /// relocations).
    pub tlv_exports: Vec<&'static str>,
    /// The library was built without -application_extension.
    pub not_app_extension_safe: bool,
    /// Install names of reexported libraries described in *other* files
    /// (reexports inlined as documents in this file are already merged
    /// into `exports`).
    pub external_reexports: Vec<&'static str>,
}

/// Strips a YAML scalar's surrounding quotes, if any.
fn unquote(s: &str) -> &str {
    let s = s.trim();
    s.strip_prefix('\'')
        .and_then(|s| s.strip_suffix('\''))
        .or_else(|| s.strip_prefix('"').and_then(|s| s.strip_suffix('"')))
        .unwrap_or(s)
}

fn memchr_from(bytes: &[u8], needle: u8, from: usize) -> Option<usize> {
    if from >= bytes.len() {
        return None;
    }
    // SAFETY: memchr reads within the given range.
    let p = unsafe {
        libc::memchr(
            bytes.as_ptr().add(from) as *const _,
            needle as i32,
            bytes.len() - from,
        )
    };
    if p.is_null() {
        None
    } else {
        Some(p as usize - bytes.as_ptr() as usize)
    }
}

pub fn parse_version(val: &str) -> u32 {
    let mut nums = val.split('.').map(|s| s.parse().unwrap_or(0));
    let major = nums.next().unwrap_or(1);
    let minor = nums.next().unwrap_or(0);
    let patch = nums.next().unwrap_or(0);
    crate::macho::encode_version(major, minor, patch)
}

/// Parses a .tbd file, merging exports of all its documents.
/// A memoized parse. Stub parsing is pure string work over the mapped
/// file, so results are cached by the file's address and the big SDK
/// stubs (libSystem's tree, framework umbrellas) can be parsed once,
/// in parallel, by prefetch() before the serial input loop needs them.
pub fn parse_cached(diag: &Diagnostics, mf: &'static MappedFile) -> TbdFile {
    static CACHE: std::sync::Mutex<Option<hashbrown::HashMap<usize, TbdFile>>> =
        std::sync::Mutex::new(None);
    let key = mf.data.as_ptr() as usize;
    if let Some(tbd) = CACHE
        .lock()
        .unwrap()
        .get_or_insert_with(hashbrown::HashMap::new)
        .get(&key)
    {
        return tbd.clone();
    }
    let tbd = parse(diag, mf);
    CACHE
        .lock()
        .unwrap()
        .get_or_insert_with(hashbrown::HashMap::new)
        .insert(key, tbd.clone());
    tbd
}

/// Warms the parse cache on all cores.
pub fn prefetch(diag: &Diagnostics, mfs: &[&'static MappedFile]) -> Vec<TbdFile> {
    use rayon::prelude::*;
    mfs.par_iter().map(|mf| parse_cached(diag, mf)).collect()
}

pub fn parse(diag: &Diagnostics, mf: &MappedFile) -> TbdFile {
    let Ok(text): Result<&'static str, _> = std::str::from_utf8(mf.data) else {
        fatal!(diag, "{}: invalid UTF-8 in .tbd file", mf.name);
    };

    let mut tbd = TbdFile {
        install_name: String::new(),
        current_version: crate::macho::encode_version(1, 0, 0),
        exports: Vec::new(),
        weak_exports: Vec::new(),
        tlv_exports: Vec::new(),
        not_app_extension_safe: false,
        external_reexports: Vec::new(),
    };

    let mut doc_names: Vec<&'static str> = Vec::new();
    let mut reexports: Vec<&'static str> = Vec::new();

    // One pass over the file. Lines are walked with memchr; a line
    // whose (indentation- and "- "-stripped) head matches a key has
    // its flow list "[ a, b, ... ]" - which may span lines - consumed
    // in place, so nothing is ever scanned twice. Longer keys are
    // tested first so "symbols:" cannot claim "weak-symbols:" lines.
    let bytes = text.as_bytes();
    let mut pos = 0usize;
    let mut doc = 0usize;

    // What a matched key does with its list items.
    enum Sink {
        Exports,
        ObjcClass,
        ObjcEhType,
        ObjcIvar,
        Weak,
        Tlv,
        Reexports,
    }

    while pos < bytes.len() {
        let eol = match memchr_from(bytes, b'\n', pos) {
            Some(i) => i,
            None => bytes.len(),
        };
        let line = text[pos..eol].trim_start();
        let mut next = eol + 1;

        if line.starts_with("---") {
            doc += 1;
        } else {
            let line = line.strip_prefix("- ").unwrap_or(line);
            if let Some(val) = line.strip_prefix("install-name:") {
                doc_names.push(unquote(val));
                if doc <= 1 && tbd.install_name.is_empty() {
                    tbd.install_name = unquote(val).to_string();
                }
            } else if doc <= 1 && line.starts_with("current-version:") {
                tbd.current_version = parse_version(unquote(&line["current-version:".len()..]));
            } else if doc <= 1 && line.starts_with("flags:") {
                if line.contains("not_app_extension_safe") {
                    tbd.not_app_extension_safe = true;
                }
            } else {
                let sink = if line.starts_with("thread-local-symbols:") {
                    Some(Sink::Tlv)
                } else if line.starts_with("weak-symbols:") {
                    Some(Sink::Weak)
                } else if line.starts_with("symbols:") {
                    Some(Sink::Exports)
                } else if line.starts_with("objc-classes:") {
                    Some(Sink::ObjcClass)
                } else if line.starts_with("objc-eh-types:") {
                    Some(Sink::ObjcEhType)
                } else if line.starts_with("objc-ivars:") {
                    Some(Sink::ObjcIvar)
                } else if doc <= 1 && line.starts_with("libraries:") {
                    Some(Sink::Reexports)
                } else {
                    None
                };
                if let Some(sink) = sink {
                    // The list starts at '[' (possibly on this line)
                    // and runs to the matching ']', across lines.
                    if let Some(open) = memchr_from(bytes, b'[', pos) {
                        let close = memchr_from(bytes, b']', open).unwrap_or(bytes.len());
                        for item in text[open + 1..close].split(',') {
                            let item = unquote(item.trim());
                            if item.is_empty() {
                                continue;
                            }
                            match sink {
                                Sink::Exports => tbd.exports.push(item),
                                Sink::Weak => tbd.weak_exports.push(item),
                                Sink::Tlv => tbd.tlv_exports.push(item),
                                Sink::Reexports => reexports.push(item),
                                Sink::ObjcClass => {
                                    tbd.exports
                                        .push(String::leak(format!("_OBJC_CLASS_$_{item}")));
                                    tbd.exports.push(String::leak(format!(
                                        "_OBJC_METACLASS_$_{item}"
                                    )));
                                }
                                Sink::ObjcEhType => tbd
                                    .exports
                                    .push(String::leak(format!("_OBJC_EHTYPE_$_{item}"))),
                                Sink::ObjcIvar => tbd
                                    .exports
                                    .push(String::leak(format!("_OBJC_IVAR_$_{item}"))),
                            }
                        }
                        next = memchr_from(bytes, b'\n', close).map_or(bytes.len(), |i| i + 1);
                    }
                }
            }
        }
        pos = next;
    }

    // Reexported libraries not inlined as documents live in files of
    // their own and must be loaded separately.
    tbd.external_reexports = reexports
        .into_iter()
        .filter(|name| !doc_names.contains(name))
        .collect();

    if tbd.install_name.is_empty() {
        fatal!(diag, "{}: no install-name in .tbd file", mf.name);
    }
    tbd
}
