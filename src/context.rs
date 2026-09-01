//! The linker context: everything about one link, from parsed arguments
//! to output chunks.

use std::marker::PhantomData;
use std::sync::Arc;

use crate::arch::Arch;
use crate::cmdline::Args;
use crate::error;
use crate::error::{Diagnostics, HasDiagnostics};
use crate::input_files::{DylibFile, ObjectFile};
use crate::macho::{S_THREAD_LOCAL_REGULAR, S_THREAD_LOCAL_ZEROFILL};
use crate::input_sections::{InputSection, InputSectionId, Reloc, RelocTarget};
use crate::output_chunks::{find_chunk, Chunk, ChunkKind, OutputSegment, SymtabData};
use crate::symbol::{Origin, SymbolId, SymbolTable};

pub struct Context<E: Arch> {
    pub diag: Arc<Diagnostics>,
    pub args: Args,
    pub objs: Vec<ObjectFile>,
    pub dylibs: Vec<DylibFile>,
    pub symtab: SymbolTable,
    /// All input sections, in one arena.
    pub isecs: Vec<InputSection>,
    /// Input-order counter for resolution tie-breaking.
    pub priority_counter: u32,
    /// Files already loaded, so a library named twice (command line
    /// plus auto-link) is read once.
    pub visited_files: std::collections::HashSet<String>,
    /// The loaded libLTO, once a bitcode input has been seen.
    pub lto_plugin: Option<crate::lto::Plugin>,
    /// Bitcode modules registered for LTO: the pseudo object index and
    /// the lto_module handle.
    pub lto_modules: Vec<(usize, usize)>,
    /// Auto-link options already acted on.
    pub processed_linker_options: std::collections::HashSet<Vec<String>>,
    /// Unwind records from all objects' __compact_unwind sections.
    pub unwind_records: Vec<crate::input_files::UnwindRecord>,
    /// DWARF CIEs and FDEs from all objects' __eh_frame sections.
    pub cies: Vec<crate::input_files::Cie>,
    pub fdes: Vec<crate::input_files::Fde>,
    pub chunks: Vec<Chunk>,
    pub segments: Vec<OutputSegment>,
    pub symtab_data: SymtabData,
    /// Symbols with a __stubs entry, in stub order.
    pub stub_syms: Vec<SymbolId>,
    /// Symbols with a __got slot, in slot order.
    pub got_syms: Vec<SymbolId>,
    /// Thread-local symbols with a __thread_ptrs slot, in slot order.
    pub thread_ptr_syms: Vec<SymbolId>,
    /// _objc_msgSend$<selector> symbols, in __objc_stubs entry order,
    /// with their selector names.
    pub objc_stubs: Vec<(SymbolId, String)>,
    /// The _objc_msgSend symbol, once objc stubs exist.
    pub objc_msgsend_sym: Option<SymbolId>,
    /// section$start/end and segment$start/end symbols to resolve
    /// after layout: (symbol, is_start, segment, section).
    pub boundary_syms: Vec<(SymbolId, bool, String, Option<String>)>,
    /// Contents of the synthesized __objc_methname section, and each
    /// selector's offset in it.
    pub objc_methname_data: Vec<u8>,
    pub objc_methname_offs: Vec<u64>,
    /// The rebase opcode stream for LC_DYLD_INFO, built during layout.
    pub rebase_data: Vec<u8>,
    /// The bind opcode stream for LC_DYLD_INFO, built during layout.
    pub bind_data: Vec<u8>,
    /// The LC_FUNCTION_STARTS contents, built during layout.
    pub function_starts_data: Vec<u8>,
    /// Every dynamic fixup location, sorted by address, when emitting
    /// chained fixups: (address, bound symbol or None for a rebase,
    /// addend).
    pub fixups: Vec<(u64, Option<SymbolId>, u64)>,
    /// The chained-fixups import table: (symbol, table addend), sorted;
    /// and each symbol's first ordinal.
    pub fixup_imports: Vec<(SymbolId, u64)>,
    pub fixup_ordinals: std::collections::HashMap<SymbolId, usize>,
    /// The encoded LC_DYLD_CHAINED_FIXUPS payload, built during layout.
    pub chained_data: Vec<u8>,
    /// The address of the first thread-local data section. Thread
    /// pointers are encoded relative to it.
    pub tls_begin: u64,
    /// Deduplication map for literal elements: (section type, contents)
    /// to the surviving subsection.
    pub literals: std::collections::HashMap<(u32, &'static [u8]), usize>,
    /// The merged __objc_imageinfo flags word.
    pub objc_image_info_flags: u32,
    /// Initializer targets for -init_offsets, in run order: the
    /// subsection and offset of each initializer function.
    pub init_funcs: Vec<(usize, u64)>,
    /// The output's UUID, computed from its contents.
    pub uuid: std::sync::Mutex<[u8; 16]>,
    /// The resolved address of the entry point symbol.
    pub entry_addr: u64,
    /// Total size of the output file.
    pub output_size: u64,
    _marker: PhantomData<E>,
}

impl<E: Arch> HasDiagnostics for Context<E> {
    fn diagnostics(&self) -> &Diagnostics {
        &self.diag
    }
}

impl<E: Arch> Context<E> {
    pub fn new(args: Args, diag: Diagnostics) -> Context<E> {
        Context {
            diag: Arc::new(diag),
            args,
            objs: Vec::new(),
            dylibs: Vec::new(),
            symtab: SymbolTable::default(),
            isecs: Vec::new(),
            priority_counter: 0,
            lto_plugin: None,
            lto_modules: Vec::new(),
            visited_files: std::collections::HashSet::new(),
            processed_linker_options: std::collections::HashSet::new(),
            unwind_records: Vec::new(),
            cies: Vec::new(),
            fdes: Vec::new(),
            chunks: Vec::new(),
            segments: Vec::new(),
            symtab_data: SymtabData::default(),
            stub_syms: Vec::new(),
            got_syms: Vec::new(),
            thread_ptr_syms: Vec::new(),
            objc_stubs: Vec::new(),
            objc_msgsend_sym: None,
            boundary_syms: Vec::new(),
            objc_methname_data: Vec::new(),
            objc_methname_offs: Vec::new(),
            rebase_data: Vec::new(),
            bind_data: Vec::new(),
            function_starts_data: Vec::new(),
            fixups: Vec::new(),
            fixup_imports: Vec::new(),
            fixup_ordinals: std::collections::HashMap::new(),
            chained_data: Vec::new(),
            tls_begin: 0,
            literals: std::collections::HashMap::new(),
            objc_image_info_flags: 0,
            init_funcs: Vec::new(),
            uuid: std::sync::Mutex::new([0; 16]),
            entry_addr: 0,
            output_size: 0,
            _marker: PhantomData,
        }
    }

    /// Returns the bind ordinal for a symbol imported from `dylib`:
    /// the dylib's load-command ordinal under two-level namespace, or
    /// the flat-lookup sentinel with -flat_namespace / dynamic lookup.
    pub fn bind_ordinal(&self, dylib: usize) -> i32 {
        if self.args.flat_namespace || dylib == usize::MAX {
            crate::macho::BIND_SPECIAL_DYLIB_FLAT_LOOKUP
        } else {
            self.dylibs[dylib].dylib_idx
        }
    }

    /// Returns the next input-order priority value.
    pub fn next_priority(&mut self) -> u32 {
        self.priority_counter += 1;
        self.priority_counter
    }

    /// Returns true if the output uses chained fixups rather than
    /// classic dyld rebase/bind opcodes.
    pub fn use_chained_fixups(&self) -> bool {
        self.args.fixup_chains.unwrap_or_else(|| {
            self.args.platform == crate::macho::PLATFORM_MACOS
                && self.args.platform_minos >= crate::macho::encode_version(13, 0, 0)
        })
    }

    /// Follows literal-merge redirects to the surviving subsection.
    pub fn resolve_isec(&self, mut id: InputSectionId) -> InputSectionId {
        while let Some(rep) = self.isecs[id].replacement {
            id = rep;
        }
        id
    }

    /// Returns the output address of an input section.
    pub fn isec_addr(&self, id: InputSectionId) -> u64 {
        let isec = &self.isecs[self.resolve_isec(id)];
        self.chunks[isec.osec].hdr.addr + isec.output_offset
    }

    /// Returns the output address of a symbol.
    pub fn sym_addr(&self, id: SymbolId) -> u64 {
        let sym = &self.symtab[id];
        match sym.origin {
            Origin::Undef => {
                error!(self, "undefined symbol: {}", sym.name);
                0
            }
            Origin::Obj(_) | Origin::Synthetic => match (sym.isec, sym.objc_stub_idx) {
                (Some(isec), _) => self.isec_addr(isec) + sym.value,
                (None, Some(idx)) => {
                    let chunk =
                        find_chunk(self, |k| matches!(k, ChunkKind::ObjcStubs)).unwrap();
                    self.chunks[chunk].hdr.addr + idx as u64 * E::OBJC_STUB_SIZE
                }
                (None, None) => sym.value,
            },
            // A branch to a dylib symbol goes through its stub. Other
            // references to dylib symbols are filled in by dyld; the
            // relocation scan has already validated them.
            Origin::Dylib(_) => match sym.stub_idx {
                Some(_) => self.sym_stub_addr(id),
                None => 0,
            },
        }
    }

    /// Returns the address of a symbol's __stubs entry.
    pub fn sym_stub_addr(&self, id: SymbolId) -> u64 {
        let idx = find_chunk(self, |k| matches!(k, ChunkKind::Stubs)).unwrap();
        self.chunks[idx].hdr.addr + self.symtab[id].stub_idx.unwrap() as u64 * E::STUB_SIZE
    }

    /// Returns the address of a symbol's __got slot.
    pub fn sym_got_addr(&self, id: SymbolId) -> u64 {
        let idx = find_chunk(self, |k| matches!(k, ChunkKind::Got)).unwrap();
        self.chunks[idx].hdr.addr + self.symtab[id].got_idx.unwrap() as u64 * 8
    }

    /// Returns the address of a symbol's __thread_ptrs slot.
    pub fn sym_tlv_ptr_addr(&self, id: SymbolId) -> u64 {
        let idx = find_chunk(self, |k| matches!(k, ChunkKind::ThreadPtrs)).unwrap();
        self.chunks[idx].hdr.addr + self.symtab[id].tlv_idx.unwrap() as u64 * 8
    }

    /// Returns the symbol a relocation refers to, if it refers to one.
    pub fn reloc_target_sym(&self, obj: usize, rel: &Reloc) -> Option<SymbolId> {
        match rel.target {
            RelocTarget::Sym(idx) => Some(self.objs[obj].syms[idx]),
            RelocTarget::Section(_) => None,
        }
    }

    /// Returns the input section a relocation's target lives in, if any.
    pub fn reloc_target_isec(&self, obj: usize, rel: &Reloc) -> Option<InputSectionId> {
        match rel.target {
            RelocTarget::Sym(idx) => self.symtab[self.objs[obj].syms[idx]].isec,
            RelocTarget::Section(idx) => Some(idx),
        }
    }

    /// Returns true if a relocation's target is thread-local data.
    pub fn reloc_target_is_tls(&self, obj: usize, rel: &Reloc) -> bool {
        self.reloc_target_isec(obj, rel).is_some_and(|isec| {
            matches!(
                self.isecs[isec].hdr.section_type(),
                S_THREAD_LOCAL_REGULAR | S_THREAD_LOCAL_ZEROFILL
            )
        })
    }

    /// Resolves a relocation target to its output address.
    pub fn reloc_target_addr(&self, obj: usize, rel: &Reloc) -> u64 {
        match rel.target {
            RelocTarget::Sym(idx) => self.sym_addr(self.objs[obj].syms[idx]),
            RelocTarget::Section(idx) => self.isec_addr(idx),
        }
    }
}
