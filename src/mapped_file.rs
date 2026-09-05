//! Input file access.
//!
//! Every input file is memory-mapped, as in mold: the kernel pages
//! bytes in on first touch, nothing is copied up front, and pages the
//! link never reads (debug sections of dead archive members, say)
//! never cost anything. Mappings are leaked with a `'static` lifetime
//! rather than tracked with reference counts, which keeps lifetimes
//! out of every data structure that refers to file contents.

use std::io;
use std::path::Path;

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
    /// Maps a file. Opens are memoized by path: a file named twice (a
    /// library on the command line and in a prefetch, an archive listed
    /// repeatedly) gets one mapping, which also lets downstream caches
    /// key by data address. A path that is not a regular file (a
    /// framework directory, say) reads as not found.
    fn open_impl(path: &Path) -> io::Result<&'static MappedFile> {
        static CACHE: std::sync::Mutex<
            Option<std::collections::HashMap<std::path::PathBuf, &'static MappedFile>>,
        > = std::sync::Mutex::new(None);
        if let Some(&mf) = CACHE
            .lock()
            .unwrap()
            .get_or_insert_with(std::collections::HashMap::new)
            .get(path)
        {
            return Ok(mf);
        }
        let file = std::fs::File::open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(io::Error::from(io::ErrorKind::NotFound));
        }
        // An empty file cannot be mapped; give it an empty slice.
        let data: &'static [u8] = if metadata.len() == 0 {
            &[]
        } else {
            // SAFETY: the mapping outlives every reference (it is
            // leaked), and linkers conventionally assume inputs are
            // not modified during the link.
            let map = unsafe { memmap2::Mmap::map(&file) }?;
            let slice: &'static [u8] =
                unsafe { std::slice::from_raw_parts(map.as_ptr(), map.len()) };
            std::mem::forget(map);
            slice
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
        Ok(mf)
    }

    /// Maps a file, or returns None if it doesn't exist. Any other
    /// failure - permission denied, an unmappable file - is reported
    /// with the operating system's own words rather than as "not
    /// found".
    pub fn open(path: &Path) -> Option<&'static MappedFile> {
        match Self::open_impl(path) {
            Ok(mf) => Some(mf),
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => fatal!("cannot open {}: {e}", path.display()),
        }
    }

    /// Maps a file that must exist.
    pub fn must_open(path: &Path) -> &'static MappedFile {
        Self::open_impl(path).unwrap_or_else(|e| fatal!("cannot open {}: {e}", path.display()))
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
