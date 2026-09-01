//! Mach-O file format constants.

// Magic numbers
pub const MH_MAGIC_64: u32 = 0xfeed_facf;
pub const FAT_MAGIC: u32 = 0xcafe_babe;

// CPU types
pub const CPU_TYPE_X86_64: u32 = 0x0100_0007;
pub const CPU_TYPE_ARM64: u32 = 0x0100_000c;

// CPU subtypes
pub const CPU_SUBTYPE_X86_64_ALL: u32 = 3;
pub const CPU_SUBTYPE_ARM64_ALL: u32 = 0;

// File types
pub const MH_OBJECT: u32 = 1;
pub const MH_EXECUTE: u32 = 2;
pub const MH_DYLIB: u32 = 6;
pub const MH_DSYM: u32 = 10;
pub const MH_BUNDLE: u32 = 8;

// Mach header flags
pub const MH_NOUNDEFS: u32 = 0x1;
pub const MH_DYLDLINK: u32 = 0x4;
pub const MH_TWOLEVEL: u32 = 0x80;
pub const MH_PIE: u32 = 0x20_0000;
pub const MH_HAS_TLV_DESCRIPTORS: u32 = 0x80_0000;
pub const MH_NO_REEXPORTED_DYLIBS: u32 = 0x10_0000;
pub const MH_SUBSECTIONS_VIA_SYMBOLS: u32 = 0x2000;

// Load command types
pub const LC_REQ_DYLD: u32 = 0x8000_0000;
pub const LC_SYMTAB: u32 = 0x2;
pub const LC_DYSYMTAB: u32 = 0xb;
pub const LC_LOAD_DYLIB: u32 = 0xc;
pub const LC_ID_DYLIB: u32 = 0xd;
pub const LC_LOAD_DYLINKER: u32 = 0xe;
pub const LC_LOAD_WEAK_DYLIB: u32 = 0x18 | LC_REQ_DYLD;
pub const LC_SEGMENT_64: u32 = 0x19;
pub const LC_UUID: u32 = 0x1b;
pub const LC_RPATH: u32 = 0x1c | LC_REQ_DYLD;
pub const LC_CODE_SIGNATURE: u32 = 0x1d;
pub const LC_REEXPORT_DYLIB: u32 = 0x1f | LC_REQ_DYLD;
pub const LC_DYLD_INFO: u32 = 0x22;
pub const LC_DYLD_INFO_ONLY: u32 = 0x22 | LC_REQ_DYLD;
pub const LC_VERSION_MIN_MACOSX: u32 = 0x24;
pub const LC_FUNCTION_STARTS: u32 = 0x26;
pub const LC_MAIN: u32 = 0x28 | LC_REQ_DYLD;
pub const LC_DATA_IN_CODE: u32 = 0x29;
pub const LC_SOURCE_VERSION: u32 = 0x2a;
pub const LC_BUILD_VERSION: u32 = 0x32;
pub const LC_DYLD_EXPORTS_TRIE: u32 = 0x33 | LC_REQ_DYLD;
pub const LC_DYLD_CHAINED_FIXUPS: u32 = 0x34 | LC_REQ_DYLD;

// Platform identifiers for LC_BUILD_VERSION
pub const PLATFORM_MACOS: u32 = 1;

// Segment protections
pub const VM_PROT_READ: u32 = 1;
pub const VM_PROT_WRITE: u32 = 2;
pub const VM_PROT_EXECUTE: u32 = 4;

// Section types (low 8 bits of the flags field)
pub const SECTION_TYPE: u32 = 0xff;
pub const S_REGULAR: u32 = 0x0;
pub const S_ZEROFILL: u32 = 0x1;
pub const S_CSTRING_LITERALS: u32 = 0x2;
pub const S_4BYTE_LITERALS: u32 = 0x3;
pub const S_8BYTE_LITERALS: u32 = 0x4;
pub const S_LITERAL_POINTERS: u32 = 0x5;
pub const S_NON_LAZY_SYMBOL_POINTERS: u32 = 0x6;
pub const S_LAZY_SYMBOL_POINTERS: u32 = 0x7;
pub const S_SYMBOL_STUBS: u32 = 0x8;
pub const S_MOD_INIT_FUNC_POINTERS: u32 = 0x9;
pub const S_COALESCED: u32 = 0xb;
pub const S_16BYTE_LITERALS: u32 = 0xe;
pub const S_THREAD_LOCAL_REGULAR: u32 = 0x11;
pub const S_THREAD_LOCAL_ZEROFILL: u32 = 0x12;
pub const S_THREAD_LOCAL_VARIABLES: u32 = 0x13;
pub const S_INIT_FUNC_OFFSETS: u32 = 0x16;

// Section attributes
pub const S_ATTR_PURE_INSTRUCTIONS: u32 = 0x8000_0000;
pub const S_ATTR_NO_DEAD_STRIP: u32 = 0x1000_0000;
pub const S_ATTR_LIVE_SUPPORT: u32 = 0x0800_0000;
pub const S_ATTR_DEBUG: u32 = 0x0200_0000;
pub const S_ATTR_SOME_INSTRUCTIONS: u32 = 0x0000_0400;

// Symbol types (n_type field of nlist)
pub const N_STAB: u8 = 0xe0;
pub const N_PEXT: u8 = 0x10;
pub const N_TYPE: u8 = 0x0e;
pub const N_EXT: u8 = 0x01;

pub const N_UNDF: u8 = 0x0;
pub const N_ABS: u8 = 0x2;
pub const N_SECT: u8 = 0xe;
pub const N_INDR: u8 = 0xa;

// Symbol descriptions (n_desc field of nlist)
pub const N_WEAK_REF: u16 = 0x0040;
pub const N_WEAK_DEF: u16 = 0x0080;
pub const N_NO_DEAD_STRIP: u16 = 0x0020;
pub const N_ALT_ENTRY: u16 = 0x0200;
pub const REFERENCED_DYNAMICALLY: u16 = 0x0010;

// ARM64 relocation types
pub const ARM64_RELOC_UNSIGNED: u8 = 0;
pub const ARM64_RELOC_SUBTRACTOR: u8 = 1;
pub const ARM64_RELOC_BRANCH26: u8 = 2;
pub const ARM64_RELOC_PAGE21: u8 = 3;
pub const ARM64_RELOC_PAGEOFF12: u8 = 4;
pub const ARM64_RELOC_GOT_LOAD_PAGE21: u8 = 5;
pub const ARM64_RELOC_GOT_LOAD_PAGEOFF12: u8 = 6;
pub const ARM64_RELOC_POINTER_TO_GOT: u8 = 7;
pub const ARM64_RELOC_TLVP_LOAD_PAGE21: u8 = 8;
pub const ARM64_RELOC_TLVP_LOAD_PAGEOFF12: u8 = 9;
pub const ARM64_RELOC_ADDEND: u8 = 10;

// Code signature constants. Note that unlike the rest of Mach-O, code
// signature data structures are big-endian.
pub const CSMAGIC_EMBEDDED_SIGNATURE: u32 = 0xfade_0cc0;
pub const CSMAGIC_CODEDIRECTORY: u32 = 0xfade_0c02;
pub const CSSLOT_CODEDIRECTORY: u32 = 0;
pub const CS_ADHOC: u32 = 0x2;
pub const CS_LINKER_SIGNED: u32 = 0x2_0000;
pub const CS_SUPPORTSEXECSEG: u32 = 0x2_0400;
pub const CS_HASHTYPE_SHA256: u8 = 2;
pub const CS_EXECSEG_MAIN_BINARY: u64 = 0x1;
pub const SHA256_SIZE: usize = 32;

// The page size used for code signature hashing. This is independent of
// the target's virtual memory page size; ld64 always hashes in 4 KiB
// blocks.
pub const CS_PAGE_SIZE: u64 = 4096;

// Special dylib ordinals for two-level namespace binds
pub const BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE: i32 = 0;
pub const BIND_SPECIAL_DYLIB_SELF: i32 = -1;
