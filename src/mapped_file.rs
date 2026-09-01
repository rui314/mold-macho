//! Input file access.
//!
//! Every input file is read once and kept in memory for the whole link,
//! because sections, symbol names and relocation tables of object files
//! are used until the output is written. Files are therefore leaked with a
//! `'static` lifetime rather than tracked with reference counts, which
//! keeps lifetimes out of every data structure that refers to file
//! contents.

use std::path::Path;

use crate::error::{errno_string, Diagnostics};
use crate::fatal;

/// An input file's contents, alive for the rest of the process.
#[derive(Debug)]
pub struct MappedFile {
    pub name: String,
    pub data: &'static [u8],
    /// For an archive member, the containing archive's name.
    pub parent: Option<&'static MappedFile>,
}

impl MappedFile {
    /// Reads a file, or returns None if it doesn't exist.
    pub fn open(diag: &Diagnostics, path: &Path) -> Option<&'static MappedFile> {
        if !path.is_file() {
            return None;
        }
        let data = match std::fs::read(path) {
            Ok(data) => data,
            Err(_) => fatal!(diag, "cannot open {}: {}", path.display(), errno_string()),
        };
        Some(Box::leak(Box::new(MappedFile {
            name: path.to_string_lossy().into_owned(),
            data: Vec::leak(data),
            parent: None,
        })))
    }

    /// Reads a file, failing if it doesn't exist.
    pub fn must_open(diag: &Diagnostics, path: &Path) -> &'static MappedFile {
        match MappedFile::open(diag, path) {
            Some(mf) => mf,
            None => fatal!(diag, "cannot open {}: no such file", path.display()),
        }
    }

    /// Creates a view of a slice of this file, for an archive member.
    pub fn slice(&'static self, name: String, data: &'static [u8]) -> &'static MappedFile {
        Box::leak(Box::new(MappedFile {
            name,
            data,
            parent: Some(self),
        }))
    }
}
