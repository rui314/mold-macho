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
    /// Archive members not yet loaded; a member is loaded when it
    /// defines a symbol that is still undefined.
    pub lazy_objs: Vec<&'static crate::mapped_file::MappedFile>,
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
    /// The address of the first thread-local data section. Thread
    /// pointers are encoded relative to it.
    pub tls_begin: u64,
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
            lazy_objs: Vec::new(),
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
            objc_methname_data: Vec::new(),
            objc_methname_offs: Vec::new(),
            rebase_data: Vec::new(),
            bind_data: Vec::new(),
            function_starts_data: Vec::new(),
            tls_begin: 0,
            entry_addr: 0,
            output_size: 0,
            _marker: PhantomData,
        }
    }

    /// Returns the output address of an input section.
    pub fn isec_addr(&self, id: InputSectionId) -> u64 {
        let isec = &self.isecs[id];
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
