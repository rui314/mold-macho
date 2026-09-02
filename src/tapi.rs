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

/// Reads the flow list (`[ a, b, ... ]`, possibly spanning lines)
/// following position `pos`, appending its elements to `out`.
fn read_list(text: &'static str, pos: usize, out: &mut Vec<&'static str>, prefix: &str) {
    let Some(start) = text[pos..].find('[') else {
        return;
    };
    let start = pos + start + 1;
    let Some(end) = text[start..].find(']') else {
        return;
    };
    for item in text[start..start + end].split(',') {
        let item = unquote(item.trim());
        if !item.is_empty() {
            // Plain names borrow straight out of the mapped file; the
            // few Objective-C entries that need a mangling prefix are
            // leaked (bounded by the small objc lists).
            if prefix.is_empty() {
                out.push(item);
            } else {
                out.push(String::leak(format!("{prefix}{item}")));
            }
        }
    }
}

/// Reads all `<key>: [ ... ]` lists in a document.
fn read_lists(doc: &'static str, key: &str, out: &mut Vec<&'static str>, prefix: &str) {
    let pat = format!("{key}:");
    let mut pos = 0;
    while let Some(found) = doc[pos..].find(&pat) {
        let at = pos + found;
        // The key must be a whole word: "symbols" must not match
        // "weak-symbols".
        let line_ok = doc[..at]
            .chars()
            .next_back()
            .map_or(true, |c| c == '\n' || c == ' ');
        pos = at + pat.len();
        if line_ok {
            read_list(doc, pos, out, prefix);
        }
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

    let mut doc_names = Vec::new();
    let mut reexports = Vec::new();

    for (i, doc) in text.split("\n---").enumerate() {
        for line in doc.lines() {
            if let Some(val) = line.strip_prefix("install-name:") {
                doc_names.push(unquote(val));
                if i == 0 {
                    tbd.install_name = unquote(val).to_string();
                }
            } else if i == 0 {
                if let Some(val) = line.strip_prefix("current-version:") {
                    tbd.current_version = parse_version(unquote(val));
                } else if let Some(val) = line.strip_prefix("flags:") {
                    if val.contains("not_app_extension_safe") {
                        tbd.not_app_extension_safe = true;
                    }
                }
            }
        }

        if i == 0 {
            read_lists(doc, "libraries", &mut reexports, "");
        }

        // Merge the exported symbols of every document. Objective-C
        // entities are exported under mangled symbol names.
        read_lists(doc, "symbols", &mut tbd.exports, "");
        read_lists(doc, "objc-classes", &mut tbd.exports, "_OBJC_CLASS_$_");
        read_lists(doc, "objc-classes", &mut tbd.exports, "_OBJC_METACLASS_$_");
        read_lists(doc, "objc-eh-types", &mut tbd.exports, "_OBJC_EHTYPE_$_");
        read_lists(doc, "objc-ivars", &mut tbd.exports, "_OBJC_IVAR_$_");
        read_lists(doc, "weak-symbols", &mut tbd.weak_exports, "");
        read_lists(doc, "thread-local-symbols", &mut tbd.tlv_exports, "");
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
