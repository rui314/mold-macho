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

/// A JSON value, as much of JSON as a TBD v5 file uses. Strings borrow
/// from the file (input files are leaked); one with an escape is
/// unescaped into a leaked copy.
enum Json {
    Null,
    Bool,
    Num,
    Str(&'static str),
    Arr(Vec<Json>),
    Obj(Vec<(&'static str, Json)>),
}

impl Json {
    fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Obj(fields) => fields.iter().find(|(k, _)| *k == key).map(|(_, v)| v),
            _ => None,
        }
    }
    fn arr(&self) -> &[Json] {
        match self {
            Json::Arr(items) => items,
            _ => &[],
        }
    }
    fn str(&self) -> Option<&'static str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }
    /// The strings of an array-valued key.
    fn strs(&self, key: &str) -> impl Iterator<Item = &'static str> + '_ {
        self.get(key).map(Json::arr).unwrap_or(&[]).iter().filter_map(Json::str)
    }
}

struct JsonParser<'a> {
    diag: &'a Diagnostics,
    file: &'a str,
    text: &'static str,
    pos: usize,
}

impl JsonParser<'_> {
    fn fail(&self, what: &str) -> ! {
        fatal!(self.diag, "{}: malformed .tbd JSON at byte {}: {what}", self.file, self.pos);
    }

    fn skip_ws(&mut self) {
        let b = self.text.as_bytes();
        while self.pos < b.len() && matches!(b[self.pos], b' ' | b'\t' | b'\n' | b'\r') {
            self.pos += 1;
        }
    }

    fn eat(&mut self, c: u8) -> bool {
        self.skip_ws();
        if self.text.as_bytes().get(self.pos) == Some(&c) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn value(&mut self) -> Json {
        self.skip_ws();
        let b = self.text.as_bytes();
        match b.get(self.pos) {
            Some(b'{') => {
                self.pos += 1;
                let mut fields = Vec::new();
                if !self.eat(b'}') {
                    loop {
                        self.skip_ws();
                        let key = self.string();
                        if !self.eat(b':') {
                            self.fail("expected ':'");
                        }
                        let val = self.value();
                        fields.push((key, val));
                        if self.eat(b',') {
                            continue;
                        }
                        if self.eat(b'}') {
                            break;
                        }
                        self.fail("expected ',' or '}'");
                    }
                }
                Json::Obj(fields)
            }
            Some(b'[') => {
                self.pos += 1;
                let mut items = Vec::new();
                if !self.eat(b']') {
                    loop {
                        items.push(self.value());
                        if self.eat(b',') {
                            continue;
                        }
                        if self.eat(b']') {
                            break;
                        }
                        self.fail("expected ',' or ']'");
                    }
                }
                Json::Arr(items)
            }
            Some(b'"') => Json::Str(self.string()),
            Some(b't') if self.text[self.pos..].starts_with("true") => {
                self.pos += 4;
                Json::Bool
            }
            Some(b'f') if self.text[self.pos..].starts_with("false") => {
                self.pos += 5;
                Json::Bool
            }
            Some(b'n') if self.text[self.pos..].starts_with("null") => {
                self.pos += 4;
                Json::Null
            }
            Some(_) => {
                let start = self.pos;
                while self.pos < b.len()
                    && matches!(b[self.pos], b'0'..=b'9' | b'-' | b'+' | b'.' | b'e' | b'E')
                {
                    self.pos += 1;
                }
                if self.text[start..self.pos].parse::<f64>().is_err() {
                    self.fail("expected a value");
                }
                Json::Num
            }
            None => self.fail("unexpected end of file"),
        }
    }

    fn string(&mut self) -> &'static str {
        let b = self.text.as_bytes();
        if b.get(self.pos) != Some(&b'"') {
            self.fail("expected a string");
        }
        self.pos += 1;
        let start = self.pos;
        let mut escaped = false;
        while self.pos < b.len() && b[self.pos] != b'"' {
            if b[self.pos] == b'\\' {
                escaped = true;
                self.pos += 1;
            }
            self.pos += 1;
        }
        if self.pos >= b.len() {
            self.fail("unterminated string");
        }
        let raw = &self.text[start..self.pos];
        self.pos += 1;
        if !escaped {
            return raw;
        }
        let mut out = String::with_capacity(raw.len());
        let mut chars = raw.chars();
        while let Some(c) = chars.next() {
            if c != '\\' {
                out.push(c);
                continue;
            }
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some('r') => out.push('\r'),
                Some('b') => out.push('\u{8}'),
                Some('f') => out.push('\u{c}'),
                Some('u') => {
                    let hex: String = chars.by_ref().take(4).collect();
                    match u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32) {
                        Some(ch) => out.push(ch),
                        None => self.fail("bad \\u escape"),
                    }
                }
                Some(other) => out.push(other),
                None => self.fail("bad escape"),
            }
        }
        String::leak(out)
    }
}

/// Parses a TBD v5 file: JSON with a "main_library" object and, for
/// reexported libraries inlined in the same file, a "libraries" array
/// of objects of the same shape. Symbols are listed per target group;
/// as with the YAML formats, the groups are merged (the SDK's stubs
/// describe the same library for every target).
fn parse_json(diag: &Diagnostics, file: &str, text: &'static str) -> TbdFile {
    let mut p = JsonParser { diag, file, text, pos: 0 };
    let root = p.value();

    let mut tbd = TbdFile {
        install_name: String::new(),
        current_version: crate::macho::encode_version(1, 0, 0),
        exports: Vec::new(),
        weak_exports: Vec::new(),
        tlv_exports: Vec::new(),
        not_app_extension_safe: false,
        external_reexports: Vec::new(),
    };

    // Adds one library object's symbols.
    let add_symbols = |tbd: &mut TbdFile, lib: &Json| {
        for key in ["exported_symbols", "reexported_symbols"] {
            for group in lib.get(key).map(Json::arr).unwrap_or(&[]) {
                for section in ["data", "text"] {
                    let Some(kinds) = group.get(section) else { continue };
                    tbd.exports.extend(kinds.strs("global"));
                    tbd.weak_exports.extend(kinds.strs("weak"));
                    tbd.tlv_exports.extend(kinds.strs("thread_local"));
                    for name in kinds.strs("objc_class") {
                        tbd.exports.push(String::leak(format!("_OBJC_CLASS_$_{name}")));
                        tbd.exports.push(String::leak(format!("_OBJC_METACLASS_$_{name}")));
                    }
                    for name in kinds.strs("objc_eh_type") {
                        tbd.exports.push(String::leak(format!("_OBJC_EHTYPE_$_{name}")));
                    }
                    for name in kinds.strs("objc_ivar") {
                        tbd.exports.push(String::leak(format!("_OBJC_IVAR_$_{name}")));
                    }
                }
            }
        }
    };

    let Some(main) = root.get("main_library") else {
        fatal!(diag, "{file}: no main_library in .tbd file");
    };
    if let Some(name) = main.get("install_names").map(Json::arr).and_then(|a| a.first()) {
        if let Some(s) = name.get("name").and_then(Json::str) {
            tbd.install_name = s.to_string();
        }
    }
    if let Some(v) = main.get("current_versions").map(Json::arr).and_then(|a| a.first()) {
        if let Some(s) = v.get("version").and_then(Json::str) {
            tbd.current_version = parse_version(s);
        }
    }
    for flags in main.get("flags").map(Json::arr).unwrap_or(&[]) {
        if flags.strs("attributes").any(|a| a == "not_app_extension_safe") {
            tbd.not_app_extension_safe = true;
        }
    }
    add_symbols(&mut tbd, main);

    // Reexported libraries: those inlined in "libraries" merge in here;
    // the others live in files of their own.
    let mut doc_names: Vec<&'static str> = Vec::new();
    for lib in root.get("libraries").map(Json::arr).unwrap_or(&[]) {
        for name in lib.get("install_names").map(Json::arr).unwrap_or(&[]) {
            if let Some(s) = name.get("name").and_then(Json::str) {
                doc_names.push(s);
            }
        }
        add_symbols(&mut tbd, lib);
    }
    for group in main.get("reexported_libraries").map(Json::arr).unwrap_or(&[]) {
        for name in group.strs("names") {
            if !doc_names.contains(&name) && !tbd.external_reexports.contains(&name) {
                tbd.external_reexports.push(name);
            }
        }
    }

    if tbd.install_name.is_empty() {
        fatal!(diag, "{file}: no install name in .tbd file");
    }
    tbd
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

    // TBD version 5 is JSON (tapi's current output, and what Xcode
    // writes for the "eager linking" stubs of frameworks built in the
    // same workspace); versions 1-4 are YAML.
    if text.trim_start().starts_with('{') {
        return parse_json(diag, &mf.name, text);
    }

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
