//! TAPI text-based dylib stub (.tbd) files.
//!
//! SDKs don't ship dylib binaries; each dylib is described by a YAML file
//! giving its install name, exported symbols and reexports. We don't need
//! a general YAML parser: TAPI files are machine-generated and regular, so
//! a line-oriented scan is enough.

use crate::error::Diagnostics;
use crate::fatal;
use crate::mapped_file::MappedFile;

#[derive(Debug, Default)]
pub struct TbdFile {
    pub install_name: String,
    pub current_version: u32,
}

/// Strips a YAML scalar's surrounding quotes, if any.
fn unquote(s: &str) -> &str {
    let s = s.trim();
    s.strip_prefix('\'')
        .and_then(|s| s.strip_suffix('\''))
        .or_else(|| s.strip_prefix('"').and_then(|s| s.strip_suffix('"')))
        .unwrap_or(s)
}

/// Parses the main document of a .tbd file. A file may contain more
/// documents after the first one, describing reexported libraries; they
/// are not handled yet.
pub fn parse(diag: &Diagnostics, mf: &MappedFile) -> TbdFile {
    let Ok(text) = std::str::from_utf8(mf.data) else {
        fatal!(diag, "{}: invalid UTF-8 in .tbd file", mf.name);
    };

    // Documents after the first describe reexported libraries.
    let doc = match text[3..].find("\n---") {
        Some(pos) => &text[..pos + 3],
        None => text,
    };

    let mut tbd = TbdFile {
        install_name: String::new(),
        current_version: crate::macho::encode_version(1, 0, 0),
    };

    for line in doc.lines() {
        if let Some(val) = line.strip_prefix("install-name:") {
            tbd.install_name = unquote(val).to_string();
        } else if let Some(val) = line.strip_prefix("current-version:") {
            let mut nums = unquote(val).split('.').map(|s| s.parse().unwrap_or(0));
            let major = nums.next().unwrap_or(1);
            let minor = nums.next().unwrap_or(0);
            let patch = nums.next().unwrap_or(0);
            tbd.current_version = crate::macho::encode_version(major, minor, patch);
        }
    }

    if tbd.install_name.is_empty() {
        fatal!(diag, "{}: no install-name in .tbd file", mf.name);
    }
    tbd
}
