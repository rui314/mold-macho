//! Input file access.
//!
//! Every input file is memory-mapped, as in mold: the kernel pages
//! bytes in on first touch, nothing is copied up front, and pages the
//! link never reads (debug sections of dead archive members, say)
//! never cost anything. Mappings are leaked with a `'static` lifetime
//! rather than tracked with reference counts, which keeps lifetimes
//! out of every data structure that refers to file contents.

use std::path::Path;

use crate::error::errno_string;
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
    /// Maps a file, or returns None if it doesn't exist. Opens are
    /// memoized by path: a file named twice (a library on the command
    /// line and in a prefetch, an archive listed repeatedly) gets one
    /// mapping, which also lets downstream caches key by data address.
    pub fn open(path: &Path) -> Option<&'static MappedFile> {
        static CACHE: std::sync::Mutex<
            Option<std::collections::HashMap<std::path::PathBuf, &'static MappedFile>>,
        > = std::sync::Mutex::new(None);
        if let Some(&mf) = CACHE
            .lock()
            .unwrap()
            .get_or_insert_with(std::collections::HashMap::new)
            .get(path)
        {
            return Some(mf);
        }
        if !path.is_file() {
            return None;
        }
        let Ok(file) = std::fs::File::open(path) else {
            fatal!("cannot open {}: {}", path.display(), errno_string());
        };
        // An empty file cannot be mapped; give it an empty slice.
        let len = file.metadata().map(|m| m.len()).unwrap_or(0);
        let data: &'static [u8] = if len == 0 {
            &[]
        } else {
            // SAFETY: the mapping outlives every reference (it is
            // leaked), and linkers conventionally assume inputs are
            // not modified during the link.
            match unsafe { memmap2::Mmap::map(&file) } {
                Ok(map) => {
                    let slice: &'static [u8] =
                        unsafe { std::slice::from_raw_parts(map.as_ptr(), map.len()) };
                    std::mem::forget(map);
                    slice
                }
                Err(_) => fatal!("cannot mmap {}: {}", path.display(), errno_string()),
            }
        };
        let mf: &'static MappedFile = Box::leak(Box::new(MappedFile {
            name: path.to_string_lossy().into_owned(),
            data,
            parent: None,
        }));
        CACHE
            .lock()
            .unwrap()
            .get_or_insert_with(std::collections::HashMap::new)
            .insert(path.to_path_buf(), mf);
        Some(mf)
    }

    /// Reads a file, failing if it doesn't exist.
    pub fn must_open(path: &Path) -> &'static MappedFile {
        match MappedFile::open(path) {
            Some(mf) => mf,
            None => fatal!("cannot open {}: no such file", path.display()),
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
