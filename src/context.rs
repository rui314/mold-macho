//! The linker context: everything about one link, from parsed arguments
//! to output chunks.

use std::marker::PhantomData;
use std::sync::Arc;

use crate::arch::Arch;
use crate::cmdline::Args;
use crate::error;
use crate::error::{Diagnostics, HasDiagnostics};
use crate::input_files::{DylibFile, ObjectFile};
use crate::input_sections::{InputSection, InputSectionId, Reloc, RelocTarget};
use crate::output_chunks::{Chunk, OutputSegment, SymtabData};
use crate::symbol::{Origin, SymbolId, SymbolTable};

pub struct Context<E: Arch> {
    pub diag: Arc<Diagnostics>,
    pub args: Args,
    pub objs: Vec<ObjectFile>,
    pub dylibs: Vec<DylibFile>,
    pub symtab: SymbolTable,
    /// All input sections, in one arena.
    pub isecs: Vec<InputSection>,
    pub chunks: Vec<Chunk>,
    pub segments: Vec<OutputSegment>,
    pub symtab_data: SymtabData,
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
            chunks: Vec::new(),
            segments: Vec::new(),
            symtab_data: SymtabData::default(),
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
            Origin::Obj(_) | Origin::Synthetic => match sym.isec {
                Some(isec) => self.isec_addr(isec) + sym.value,
                None => sym.value,
            },
            Origin::Dylib(_) => {
                error!(self, "cannot reference dylib symbol yet: {}", sym.name);
                0
            }
        }
    }

    /// Resolves a relocation target to its output address.
    pub fn reloc_target_addr(&self, obj: usize, rel: &Reloc) -> u64 {
        match rel.target {
            RelocTarget::Sym(idx) => self.sym_addr(self.objs[obj].syms[idx]),
            RelocTarget::Section(idx) => match self.objs[obj].sections[idx] {
                Some(isec) => self.isec_addr(isec),
                None => {
                    error!(self, "relocation against a discarded section");
                    0
                }
            },
        }
    }
}
