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
use crate::input_sections::{InputSection, Reloc, RelocTarget};
use crate::output_chunks::{Chunk, OutputSegment, SymtabData};
use crate::symbol::{Origin, SymbolId, SymbolTable};

pub struct Context<E: Arch> {
    pub diag: Arc<Diagnostics>,
    pub args: Args,
    pub objs: Vec<ObjectFile>,
    pub dylibs: Vec<DylibFile>,
    pub symtab: SymbolTable,
    /// All input sections, in one arena.
    pub isecs: crate::input_sections::InputSections,
    /// Section headers of the linker-synthesized input sections (those
    /// with obj == u32::MAX), indexed by their shndx.
    pub synthetic_hdrs: Vec<&'static crate::macho::MachSection>,
    /// Per-symbol synthetic-slot indices (SymbolId-indexed), grown
    /// lazily; mold-rust's SymbolAux side table.
    pub sym_aux: Vec<crate::symbol::SymAux>,
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
    /// Synthetic subsections standing for __got slots that absorbed
    /// __objc_classrefs entries (see fold_objc_classrefs); their osec
    /// is set once the __got chunk exists.
    pub objc_classref_slots: Vec<u32>,
    /// Sequence number of the next dylib named on the command line or
    /// by an auto-link option; orders their load commands.
    pub dylib_load_seq: u32,
    /// Thread-local symbols with a __thread_ptrs slot, in slot order.
    pub thread_ptr_syms: Vec<SymbolId>,
    /// _objc_msgSend$<selector> symbols, in __objc_stubs entry order,
    /// with their selector names.
    pub objc_stubs: Vec<(SymbolId, String)>,
    /// The _objc_msgSend symbol, once objc stubs exist.
    pub objc_msgsend_sym: Option<SymbolId>,
    /// -alias names for imported symbols: (alias, imported target).
    /// Emitted as N_INDR symbols and re-export trie entries.
    pub indirect_aliases: Vec<(SymbolId, SymbolId)>,
    /// section$start/end and segment$start/end symbols to resolve
    /// after layout: (symbol, is_start, segment, section).
    pub boundary_syms: Vec<(SymbolId, bool, String, Option<String>)>,
    /// For -why_load: the symbol that made each object live, refreshed
    /// each resolution round.
    pub why_load: std::collections::HashMap<usize, &'static str>,
    /// The export trie, encoded once when its chunk is sized (every
    /// address is final by then) and reused when copied out.
    pub export_trie_data: Vec<u8>,
    /// __unwind_info likewise, except its personality cells (GOT
    /// addresses unknown when __TEXT is sized): the symbols to patch
    /// into offsets 28, 32, ... at copy time.
    pub unwind_info_data: Vec<u8>,
    pub unwind_personalities: Vec<crate::symbol::SymbolId>,
    /// Chunk indices of the synthetic slot sections, resolved once at
    /// the start of layout so per-slot address lookups don't search
    /// the chunk list (mold keeps direct references on Context too).
    pub stubs_chunk: usize,
    pub got_chunk: usize,
    pub thread_ptrs_chunk: usize,
    pub objc_stubs_chunk: usize,
    /// The output sections carrying the synthesized selector strings
    /// and selector references as their tail (see Tail).
    pub objc_methname_chunk: usize,
    pub objc_selrefs_chunk: usize,
    /// Contents of the synthesized __objc_methname tail, and each
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
    /// LC_DATA_IN_CODE entries (fileoff, length, kind), built once
    /// when layout reaches __LINKEDIT.
    pub dice_data: Vec<(u32, u16, u16)>,
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
            isecs: Default::default(),
            synthetic_hdrs: Vec::new(),
            sym_aux: Vec::new(),
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
            objc_classref_slots: Vec::new(),
            dylib_load_seq: 0,
            thread_ptr_syms: Vec::new(),
            objc_stubs: Vec::new(),
            objc_msgsend_sym: None,
            indirect_aliases: Vec::new(),
            boundary_syms: Vec::new(),
            why_load: std::collections::HashMap::new(),
            export_trie_data: Vec::new(),
            unwind_info_data: Vec::new(),
            unwind_personalities: Vec::new(),
            stubs_chunk: usize::MAX,
            got_chunk: usize::MAX,
            thread_ptrs_chunk: usize::MAX,
            objc_stubs_chunk: usize::MAX,
            objc_methname_chunk: usize::MAX,
            objc_selrefs_chunk: usize::MAX,
            objc_methname_data: Vec::new(),
            objc_methname_offs: Vec::new(),
            rebase_data: Vec::new(),
            bind_data: Vec::new(),
            function_starts_data: Vec::new(),
            fixups: Vec::new(),
            fixup_imports: Vec::new(),
            fixup_ordinals: std::collections::HashMap::new(),
            chained_data: Vec::new(),
            dice_data: Vec::new(),
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

    /// Address of the synthesized selector reference slot for objc stub
    /// `i`: the tail of the __objc_selrefs output section.
    pub fn objc_selref_addr(&self, i: usize) -> u64 {
        let chunk = &self.chunks[self.objc_selrefs_chunk];
        chunk.hdr.addr + chunk.tail_off + i as u64 * 8
    }

    /// Address of the synthesized selector name string for objc stub
    /// `i`: in the tail of the __objc_methname output section.
    pub fn objc_methname_addr(&self, i: usize) -> u64 {
        let chunk = &self.chunks[self.objc_methname_chunk];
        chunk.hdr.addr + chunk.tail_off + self.objc_methname_offs[i]
    }

    /// The library ordinal as the chained-fixups import formats encode
    /// it in a `bits`-wide field: dylib ordinals as they are, the
    /// special ones as negative values in the field's two's complement,
    /// and, unlike the bind opcodes, the main executable as -1 (0 is
    /// the image itself there).
    pub fn chained_import_ordinal(&self, dylib: u32, bits: u32) -> u64 {
        let ordinal = match self.bind_ordinal(dylib) {
            crate::macho::BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE => -1i64,
            n => n as i64,
        };
        (ordinal as u64) & ((1u64 << bits) - 1)
    }

    /// The library ordinal in an undefined symbol's n_desc:
    /// EXECUTABLE_ORDINAL (0xff) for the -bundle_loader executable,
    /// DYNAMIC_LOOKUP_ORDINAL (0xfe) for flat lookup, else the dylib's.
    pub fn nlist_library_ordinal(&self, dylib: u32) -> u8 {
        match self.bind_ordinal(dylib) {
            crate::macho::BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE => 0xff,
            n => n as u8,
        }
    }

    /// Returns the bind ordinal for a symbol imported from `dylib`:
    /// the dylib's load-command ordinal under two-level namespace, or
    /// the flat-lookup sentinel with -flat_namespace / dynamic lookup.
    pub fn bind_ordinal(&self, dylib: u32) -> i32 {
        if self.args.flat_namespace || dylib == u32::MAX {
            crate::macho::BIND_SPECIAL_DYLIB_FLAT_LOOKUP
        } else {
            self.dylibs[dylib as usize].dylib_idx
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
        // ld-prime's defaults: chained fixups from macOS 12 on arm64 and
        // from macOS 13 on x86_64 (below that, classic dyld info with
        // lazy binding), and never under -undefined dynamic_lookup or
        // suppress - only an explicit -fixup_chains overrides that.
        self.args.fixup_chains.unwrap_or_else(|| {
            if self.args.undefined_dynamic_lookup && !self.args.undefined_is_warning {
                return false;
            }
            let min = if E::CPUTYPE == crate::macho::CPU_TYPE_ARM64 { 12 } else { 13 };
            self.args.platform == crate::macho::PLATFORM_MACOS
                && self.args.platform_minos >= crate::macho::encode_version(min, 0, 0)
        })
    }

    /// The parent section header of a subsection, through its object's
    /// section list (or the synthetic table) - mold-rust resolves a
    /// section's shdr through its file the same way.
    #[inline]
    pub fn hdr_of(&self, isec: &InputSection) -> &'static crate::macho::MachSection {
        if isec.obj == u32::MAX {
            self.synthetic_hdrs[isec.shndx as usize]
        } else {
            &self.objs[isec.obj as usize].sect_hdrs[isec.shndx as usize]
        }
    }

    /// Follows literal-merge redirects to the surviving subsection.
    pub fn resolve_isec(&self, mut id: usize) -> usize {
        while self.isecs[id].replacement != crate::input_sections::NO_REPLACEMENT {
            id = self.isecs[id].replacement as usize;
        }
        id
    }

    /// A symbol's synthetic-slot indices, from the side table. Returns
    /// the all-absent default for symbols with no slots (the table is
    /// grown lazily by the first setter).
    pub fn sym_aux(&self, id: SymbolId) -> &crate::symbol::SymAux {
        // Sparse, as mold-rust's SymbolAux: the symbol carries an index
        // into the table, NONE for the vast majority that have no slot.
        match self.symtab[id].aux_idx {
            crate::symbol::NONE => &crate::symbol::NONE_AUX,
            i => &self.sym_aux[i as usize],
        }
    }

    /// Mutable access to a symbol's slot indices, growing the side table
    /// to cover it. Called only from the serial slot-assignment passes.
    pub fn sym_aux_mut(&mut self, id: SymbolId) -> &mut crate::symbol::SymAux {
        // Allocate the symbol's entry on first use; the table holds only
        // the symbols that take a slot (mold-rust's sparse SymbolAux).
        if self.symtab[id].aux_idx == crate::symbol::NONE {
            self.symtab[id].aux_idx = self.sym_aux.len() as u32;
            self.sym_aux.push(Default::default());
        }
        let i = self.symtab[id].aux_idx as usize;
        &mut self.sym_aux[i]
    }

    /// A subsection's relocations, sliced from its object's reloc arena
    /// (subsections keep only a rel_offset/nrels range, sold-style).
    pub fn isec_relocs(&self, id: usize) -> &[crate::input_sections::Reloc] {
        let isec = &self.isecs[id];
        if isec.obj == u32::MAX {
            return &[];
        }
        let off = isec.rel_offset as usize;
        &self.objs[isec.obj as usize].relocs[off..off + isec.nrels as usize]
    }

    /// Returns the output address of an input section. Layout stores
    /// every subsection's final address the moment its output section
    /// is placed (literal-merge losers borrow their survivor's), so
    /// this is one field read.
    /// A subsection's output address: its output section's address plus
    /// its offset there, as mold-rust's isec.addr(ctx) derives it - not
    /// a cached field, which cost 8 bytes on every subsection. A
    /// literal-merge loser reports its surviving copy's address (the
    /// redirect is followed only when one exists, so the common case is
    /// one branch); an unplaced subsection reports 0.
    #[inline]
    pub fn isec_addr(&self, id: usize) -> u64 {
        let mut isec = &self.isecs[id];
        if isec.replacement != crate::input_sections::NO_REPLACEMENT {
            isec = &self.isecs[self.resolve_isec(id)];
        }
        if isec.osec == u32::MAX || isec.output_offset == u32::MAX {
            return 0;
        }
        self.chunks[isec.osec as usize].hdr.addr + isec.output_offset as u64
    }

    /// Returns the output address of a symbol.
    pub fn sym_addr(&self, id: SymbolId) -> u64 {
        let sym = &self.symtab[id];
        match sym.origin() {
            Origin::Undef => {
                error!(self, "undefined symbol: {}", sym.name());
                0
            }
            Origin::Obj(_) | Origin::Synthetic => {
                if let Some(isec) = sym.isec().map(|i| i as usize) {
                    self.isec_addr(isec) + sym.value
                } else if self.sym_aux(id).objc_stub_idx != crate::symbol::NO_IDX {
                    self.chunks[self.objc_stubs_chunk].hdr.addr
                        + self.sym_aux(id).objc_stub_idx as u64 * E::OBJC_STUB_SIZE
                } else {
                    sym.value
                }
            }
            // A branch to a dylib symbol goes through its stub. Other
            // references to dylib symbols are filled in by dyld; the
            // relocation scan has already validated them.
            Origin::Dylib(_) => {
                if self.sym_aux(id).stub_idx != crate::symbol::NO_IDX {
                    self.sym_stub_addr(id)
                } else {
                    0
                }
            }
        }
    }

    /// Returns the address of a symbol's __stubs entry.
    pub fn sym_stub_addr(&self, id: SymbolId) -> u64 {
        self.chunks[self.stubs_chunk].hdr.addr
            + self.sym_aux(id).stub_idx as u64 * E::STUB_SIZE
    }

    /// Returns the address of a symbol's __got slot.
    pub fn sym_got_addr(&self, id: SymbolId) -> u64 {
        self.chunks[self.got_chunk].hdr.addr + self.sym_aux(id).got_idx as u64 * 8
    }

    /// Returns the address of a symbol's __thread_ptrs slot.
    pub fn sym_tlv_ptr_addr(&self, id: SymbolId) -> u64 {
        self.chunks[self.thread_ptrs_chunk].hdr.addr
            + self.sym_aux(id).tlv_idx as u64 * 8
    }

    /// Returns the symbol a relocation refers to, if it refers to one.
    pub fn reloc_target_sym(&self, obj: usize, rel: &Reloc) -> Option<SymbolId> {
        match rel.target() {
            RelocTarget::Sym(idx) => Some(self.objs[obj].syms[idx as usize]),
            RelocTarget::Section(_) => None,
        }
    }

    /// Returns the input section a relocation's target lives in, if any.
    pub fn reloc_target_isec(&self, obj: usize, rel: &Reloc) -> Option<usize> {
        match rel.target() {
            RelocTarget::Sym(idx) => self.symtab[self.objs[obj].syms[idx as usize]].isec().map(|i| i as usize),
            RelocTarget::Section(idx) => Some(idx as usize),
        }
    }

    /// Returns true if a relocation's target is thread-local data.
    pub fn reloc_target_is_tls(&self, obj: usize, rel: &Reloc) -> bool {
        self.reloc_target_isec(obj, rel).is_some_and(|isec| {
            matches!(
                self.hdr_of(&self.isecs[isec]).section_type(),
                S_THREAD_LOCAL_REGULAR | S_THREAD_LOCAL_ZEROFILL
            )
        })
    }

    /// Resolves a relocation target to its output address.
    pub fn reloc_target_addr(&self, obj: usize, rel: &Reloc) -> u64 {
        match rel.target() {
            RelocTarget::Sym(idx) => self.sym_addr(self.objs[obj].syms[idx as usize]),
            RelocTarget::Section(idx) => self.isec_addr(idx as usize),
        }
    }
}
