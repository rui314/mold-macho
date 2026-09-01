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
    /// True for a private external symbol (visibility hidden): it
    /// resolves globally at link time but is neither exported nor kept
    /// as an external symbol in the output.
    pub is_private_extern: bool,
    /// True if references to this symbol may go unresolved at load
    /// time (a weak import).
    pub is_weak_ref: bool,
    /// True if the symbol must survive dead-stripping.
    pub no_dead_strip: bool,
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
            is_private_extern: false,
            is_weak_ref: false,
            no_dead_strip: false,
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
///
/// The name map is sharded by a hash of the name, following mold's
/// symbol table: one-off lookups route to a single shard, and
/// intern_batch resolves a whole link's worth of names with the
/// shards processed in parallel.
#[derive(Debug)]
pub struct SymbolTable {
    shards: Vec<HashMap<&'static str, SymbolId>>,
    pub syms: Vec<Symbol>,
}

const NUM_SHARDS: usize = 64;

/// The sharding hash: FNV-1a, cheap and stable. Each shard's HashMap
/// hashes again internally; this only has to spread names evenly.
fn shard_of(name: &str) -> usize {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in name.as_bytes() {
        h = (h ^ b as u64).wrapping_mul(0x100_0000_01b3);
    }
    (h % NUM_SHARDS as u64) as usize
}

impl Default for SymbolTable {
    fn default() -> SymbolTable {
        SymbolTable {
            shards: (0..NUM_SHARDS).map(|_| HashMap::new()).collect(),
            syms: Vec::new(),
        }
    }
}

impl SymbolTable {
    /// Returns the symbol for a global name, creating it if needed.
    pub fn intern(&mut self, name: &'static str) -> SymbolId {
        *self.shards[shard_of(name)].entry(name).or_insert_with(|| {
            self.syms.push(Symbol::new(name));
            self.syms.len() - 1
        })
    }

    /// Returns the symbol for a global name if it exists.
    pub fn get(&self, name: &str) -> Option<SymbolId> {
        self.shards[shard_of(name)].get(name).copied()
    }

    /// Creates an anonymous slot for a file-local symbol.
    pub fn add_local(&mut self, name: &'static str) -> SymbolId {
        self.syms.push(Symbol::new(name));
        self.syms.len() - 1
    }

    /// Interns every name in `batch` at once, returning ids aligned
    /// with it. Names are binned by shard, the shards resolve their
    /// bins in parallel (an existing id, or a shard-local new index),
    /// new symbols take contiguous id ranges per shard - a prefix sum
    /// over the shards' new counts - and one serial scatter writes the
    /// results. Ids depend only on input order and the sharding hash,
    /// so output remains deterministic.
    pub fn intern_batch(&mut self, batch: &[&'static str]) -> Vec<SymbolId> {
        use rayon::prelude::*;

        let mut bins: Vec<Vec<u32>> = vec![Vec::new(); NUM_SHARDS];
        for (i, name) in batch.iter().enumerate() {
            bins[shard_of(name)].push(i as u32);
        }

        enum Resolved {
            Old(SymbolId),
            New(u32),
        }
        let results: Vec<(Vec<(u32, Resolved)>, Vec<&'static str>)> = self
            .shards
            .par_iter_mut()
            .zip(bins)
            .map(|(shard, bin)| {
                let mut news: Vec<&'static str> = Vec::new();
                let mut newmap: HashMap<&'static str, u32> = HashMap::new();
                let mut out = Vec::with_capacity(bin.len());
                for i in bin {
                    let name = batch[i as usize];
                    match shard.get(name) {
                        Some(&id) => out.push((i, Resolved::Old(id))),
                        None => {
                            let idx = *newmap.entry(name).or_insert_with(|| {
                                news.push(name);
                                news.len() as u32 - 1
                            });
                            out.push((i, Resolved::New(idx)));
                        }
                    }
                }
                (out, news)
            })
            .collect();

        let mut bases = Vec::with_capacity(NUM_SHARDS);
        let mut base = self.syms.len();
        for (_, news) in &results {
            bases.push(base);
            base += news.len();
        }
        self.syms.reserve(base - self.syms.len());
        for (_, news) in &results {
            for name in news {
                self.syms.push(Symbol::new(name));
            }
        }
        self.shards
            .par_iter_mut()
            .zip(&results)
            .zip(&bases)
            .for_each(|((shard, (_, news)), &b)| {
                for (k, name) in news.iter().enumerate() {
                    shard.insert(name, b + k);
                }
            });

        let mut ids = vec![0; batch.len()];
        for ((out, _), &b) in results.iter().zip(&bases) {
            for &(i, ref r) in out {
                ids[i as usize] = match r {
                    Resolved::Old(id) => *id,
                    Resolved::New(k) => b + *k as usize,
                };
            }
        }
        ids
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
