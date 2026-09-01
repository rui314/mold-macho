//! Input file type detection.

use crate::macho::*;
use crate::mapped_file::MappedFile;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileType {
    Unknown,
    Empty,
    Object,
    Dylib,
    Archive,
    /// A TAPI text-based dylib stub (.tbd), a YAML description of a dylib
    /// that ships in SDKs in place of the binary.
    Tapi,
    Fat,
}

pub fn get_file_type(mf: &MappedFile) -> FileType {
    let data = mf.data;
    if data.is_empty() {
        return FileType::Empty;
    }

    if data.len() >= 8 && &data[..8] == b"!<arch>\n" {
        return FileType::Archive;
    }

    if data.starts_with(b"--- !tapi-tbd") || data.starts_with(b"---\narchs:") {
        return FileType::Tapi;
    }

    if data.len() >= size_of::<MachHeader>() {
        let hdr = MachHeader::read_from(data);
        if hdr.magic == MH_MAGIC_64 {
            return match hdr.filetype {
                MH_OBJECT => FileType::Object,
                MH_DYLIB => FileType::Dylib,
                _ => FileType::Unknown,
            };
        }
        if hdr.magic.swap_bytes() == FAT_MAGIC {
            return FileType::Fat;
        }
    }

    FileType::Unknown
}
