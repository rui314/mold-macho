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
    /// An LLVM bitcode file, produced by -flto; compiled by libLTO at
    /// link time.
    LlvmBitcode,
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

    // Raw LLVM bitcode, or the bitcode wrapper header.
    if data.starts_with(b"BC\xc0\xde") || data.starts_with(&0x0b17_c0deu32.to_le_bytes()) {
        return FileType::LlvmBitcode;
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
