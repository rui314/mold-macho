//! Symbols and the global symbol table.

use std::collections::HashMap;

use crate::input_sections::InputSectionId;

pub type SymbolId = usize;

/// Where a symbol's definition comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    /// Not defined by any input file (yet).
    Undef,
    /// Defined by an object file.
    Obj(usize),
    /// Exported by a dylib.
    Dylib(usize),
    /// Defined by the linker itself, e.g. `__mh_execute_header`.
    Synthetic,
}

#[derive(Clone, Debug)]
pub struct Symbol {
    pub name: &'static str,
    pub origin: Origin,
    /// The section the symbol is defined in, for `N_SECT` symbols.
    pub isec: Option<InputSectionId>,
    /// Offset from the start of `isec`, or the absolute value for `N_ABS`
    /// symbols.
    pub value: u64,
    pub is_extern: bool,
    pub is_weak_def: bool,
    /// True if the definition is in a dylib, so references need dynamic
    /// binding.
    pub is_imported: bool,
    /// True if some relocation refers to this symbol, which makes an
    /// unresolved symbol an error.
    pub is_used: bool,
    /// True for a tentative definition (a common symbol) not yet
    /// converted to a real one; `value` holds its size.
    pub is_common: bool,
    pub common_p2align: u8,
    /// The symbol's entry in __stubs, if branches to it need one.
    pub stub_idx: Option<u32>,
    /// The symbol's entry in __got, if it is address-taken through the
    /// GOT.
    pub got_idx: Option<u32>,
    /// The symbol's slot in __thread_ptrs, for thread-local variables.
    pub tlv_idx: Option<u32>,
    /// The symbol's entry in __objc_stubs, for linker-synthesized
    /// _objc_msgSend$selector stubs.
    pub objc_stub_idx: Option<u32>,
}

impl Symbol {
    fn new(name: &'static str) -> Symbol {
        Symbol {
            name,
            origin: Origin::Undef,
            isec: None,
            value: 0,
            is_extern: false,
            is_weak_def: false,
            is_imported: false,
            is_used: false,
            is_common: false,
            common_p2align: 0,
            stub_idx: None,
            got_idx: None,
            tlv_idx: None,
            objc_stub_idx: None,
        }
    }

    pub fn is_defined(&self) -> bool {
        self.origin != Origin::Undef
    }
}

/// All symbols in this link. Global symbols are interned by name so that
/// all references to one name share a slot; local symbols get anonymous
/// slots of their own.
#[derive(Default, Debug)]
pub struct SymbolTable {
    map: HashMap<&'static str, SymbolId>,
    pub syms: Vec<Symbol>,
}

impl SymbolTable {
    /// Returns the symbol for a global name, creating it if needed.
    pub fn intern(&mut self, name: &'static str) -> SymbolId {
        *self.map.entry(name).or_insert_with(|| {
            self.syms.push(Symbol::new(name));
            self.syms.len() - 1
        })
    }

    /// Returns the symbol for a global name if it exists.
    pub fn get(&self, name: &str) -> Option<SymbolId> {
        self.map.get(name).copied()
    }

    /// Creates an anonymous slot for a file-local symbol.
    pub fn add_local(&mut self, name: &'static str) -> SymbolId {
        self.syms.push(Symbol::new(name));
        self.syms.len() - 1
    }
}

impl std::ops::Index<SymbolId> for SymbolTable {
    type Output = Symbol;

    fn index(&self, id: SymbolId) -> &Symbol {
        &self.syms[id]
    }
}

impl std::ops::IndexMut<SymbolId> for SymbolTable {
    fn index_mut(&mut self, id: SymbolId) -> &mut Symbol {
        &mut self.syms[id]
    }
}
