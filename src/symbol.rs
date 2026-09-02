//! Symbols and the global symbol table.



pub type SymbolId = usize;

/// Where a symbol's definition comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    /// Not defined by any input file (yet).
    Undef,
    /// Defined by an object file (index; u32 to keep Symbol small).
    Obj(u32),
    /// Exported by a dylib (index).
    Dylib(u32),
    /// Defined by the linker itself, e.g. `__mh_execute_header`.
    Synthetic,
}

#[derive(Clone, Debug)]
pub struct Symbol {
    pub name: &'static str,
    pub origin: Origin,
    /// The section the symbol is defined in, for `N_SECT` symbols.
    /// The defining subsection (u32 index, not usize, to keep Symbol
    /// small); use `.map(|i| i as usize)` to index ctx.isecs.
    pub isec: Option<u32>,
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
}

/// Sentinel for a synthetic-slot index a symbol does not have.
pub const NO_IDX: u32 = u32::MAX;

/// A symbol's synthetic-slot indices (__stubs, __got, __thread_ptrs,
/// __objc_stubs), each `NO_IDX` when absent. Only the few symbols that
/// take a slot ever have one, so these live in a side table indexed by
/// SymbolId - mold-rust's SymbolAux - keeping Symbol itself small, as
/// it is loaded in every symbol scan.
#[derive(Clone, Copy)]
pub struct SymAux {
    pub stub_idx: u32,
    pub got_idx: u32,
    pub tlv_idx: u32,
    pub objc_stub_idx: u32,
}

impl Default for SymAux {
    fn default() -> SymAux {
        SymAux {
            stub_idx: NO_IDX,
            got_idx: NO_IDX,
            tlv_idx: NO_IDX,
            objc_stub_idx: NO_IDX,
        }
    }
}

impl Symbol {
    pub(crate) fn new(name: &'static str) -> Symbol {
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
/// symbol table: keys carry their xxh3 hash, computed in parallel
/// while files are staged, the maps hash by passing that value
/// through, and gather resolves a whole link's worth of names
/// with the shards processed in parallel.
#[derive(Debug)]
pub struct SymbolTable {
    shards: Vec<ShardMap>,
    pub syms: Vec<Symbol>,
}

pub const NUM_SHARDS: usize = 64;

/// The hash of a symbol table key, which the sharded table and its
/// callers share. Computed once per name, at staging time when
/// possible.
pub fn hash_key(key: &str) -> u64 {
    xxhash_rust::xxh3::xxh3_64(key.as_bytes())
}

fn shard_of(hash: u64) -> usize {
    (hash % NUM_SHARDS as u64) as usize
}

/// A map key that hashes by its precomputed hash and compares by the
/// name, as in mold-rust.
#[derive(Clone, Copy, Debug)]
struct Key {
    hash: u64,
    key: &'static str,
}

impl PartialEq for Key {
    fn eq(&self, other: &Key) -> bool {
        self.hash == other.hash && self.key == other.key
    }
}
impl Eq for Key {}

impl std::hash::Hash for Key {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        state.write_u64(self.hash);
    }
}

#[derive(Default)]
struct PassThroughHasher(u64);

impl std::hash::Hasher for PassThroughHasher {
    fn finish(&self) -> u64 {
        self.0
    }
    fn write(&mut self, _: &[u8]) {
        unreachable!("keys hash by their precomputed hash")
    }
    fn write_u64(&mut self, hash: u64) {
        self.0 = hash;
    }
}

type ShardMap =
    hashbrown::HashMap<Key, SymbolId, std::hash::BuildHasherDefault<PassThroughHasher>>;

/// A hash map over borrowed names with caller-supplied xxh3 hashes -
/// the symbol table's key discipline, reusable wherever names are
/// deduplicated (the output string table).
#[derive(Default)]
pub struct PrehashedMap<V>(
    hashbrown::HashMap<Key, V, std::hash::BuildHasherDefault<PassThroughHasher>>,
);

impl<V> PrehashedMap<V> {
    pub fn get(&self, name: &str, hash: u64) -> Option<&V> {
        // SAFETY: the key is only compared during this call.
        let probe = Key {
            hash,
            key: unsafe { std::mem::transmute::<&str, &'static str>(name) },
        };
        self.0.get(&probe)
    }

    pub fn insert(&mut self, name: &'static str, hash: u64, value: V) {
        self.0.insert(Key { hash, key: name }, value);
    }
}

impl Default for SymbolTable {
    fn default() -> SymbolTable {
        SymbolTable {
            shards: (0..NUM_SHARDS).map(|_| ShardMap::default()).collect(),
            syms: Vec::new(),
        }
    }
}

impl SymbolTable {
    /// Returns the symbol for a global name, creating it if needed.
    pub fn intern(&mut self, name: &'static str) -> SymbolId {
        let hash = hash_key(name);
        *self.shards[shard_of(hash)]
            .entry(Key { hash, key: name })
            .or_insert_with(|| {
                self.syms.push(Symbol::new(name));
                self.syms.len() - 1
            })
    }

    /// Returns the symbol for a global name if it exists.
    pub fn get(&self, name: &str) -> Option<SymbolId> {
        let hash = hash_key(name);
        // SAFETY-free trick from mold: lookups build a key borrowing
        // the probe name; only inserts require 'static.
        let probe = Key {
            hash,
            // The key is only compared during this call.
            key: unsafe { std::mem::transmute::<&str, &'static str>(name) },
        };
        self.shards[shard_of(hash)].get(&probe).copied()
    }

    /// Creates an anonymous slot for a file-local symbol.
    pub fn add_local(&mut self, name: &'static str) -> SymbolId {
        self.syms.push(Symbol::new(name));
        self.syms.len() - 1
    }

    /// Interns every (name, precomputed-hash) pair at once, returning
    /// ids aligned with the batch. Names are binned by shard without
    /// touching their bytes, the shards resolve their bins in
    /// parallel, new symbols take contiguous id ranges per shard, and
    /// one serial scatter hands the ids back. Ids depend only on
    /// input order and the hash, so links stay deterministic.
    pub fn gather(&mut self, batch: &[(&'static str, u64)]) -> Vec<SymbolId> {
        use rayon::prelude::*;

        let mut bins: Vec<Vec<u32>> = vec![Vec::new(); NUM_SHARDS];
        for (i, &(_, hash)) in batch.iter().enumerate() {
            bins[shard_of(hash)].push(i as u32);
        }

        enum Resolved {
            Old(SymbolId),
            New(u32),
        }
        let results: Vec<(Vec<(u32, Resolved)>, Vec<(&'static str, u64)>)> = self
            .shards
            .par_iter_mut()
            .zip(bins)
            .map(|(shard, bin)| {
                // Names first seen in this batch, with their hash, so
                // the insert pass below never re-hashes them; final ids
                // are assigned once the shards' ranges are known.
                let mut news: Vec<(&'static str, u64)> = Vec::new();
                let mut newmap: ShardMap = ShardMap::default();
                let mut out = Vec::with_capacity(bin.len());
                for i in bin {
                    let (name, hash) = batch[i as usize];
                    let key = Key { hash, key: name };
                    if let Some(&id) = shard.get(&key) {
                        out.push((i, Resolved::Old(id)));
                        continue;
                    }
                    let idx = *newmap.entry(key).or_insert_with(|| {
                        news.push((name, hash));
                        news.len() - 1
                    });
                    out.push((i, Resolved::New(idx as u32)));
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

        // Initialize the new symbols into their prefix-summed ranges in
        // parallel - the same disjoint-range contract integrate uses for
        // local symbols - so a debug link's millions of new globals are
        // constructed on all cores, not pushed one at a time.
        let old_len = self.syms.len();
        let total_new = base - old_len;
        self.syms.reserve(total_new);
        {
            struct SlotPtr(*mut Symbol);
            unsafe impl Sync for SlotPtr {}
            let ptr = SlotPtr(self.syms.as_mut_ptr());
            let ptr = &ptr;
            results.par_iter().zip(&bases).for_each(|((_, news), &b)| {
                for (k, &(name, _)) in news.iter().enumerate() {
                    // SAFETY: [b, b+news.len()) ranges are disjoint
                    // across shards and lie within the reserved space.
                    unsafe { ptr.0.add(b + k).write(Symbol::new(name)) };
                }
            });
            // SAFETY: every slot in old_len..old_len+total_new was
            // written exactly once above.
            unsafe { self.syms.set_len(old_len + total_new) };
        }

        // Insert the new names with their final ids, reusing the hash
        // computed during staging (no re-hash here).
        self.shards
            .par_iter_mut()
            .zip(&results)
            .zip(&bases)
            .for_each(|((shard, (_, news)), &b)| {
                for (k, &(name, hash)) in news.iter().enumerate() {
                    shard.insert(Key { hash, key: name }, b + k);
                }
            });

        // Scatter each batch entry's resolved id in parallel; every
        // batch index appears in exactly one shard's output list, so
        // the writes are disjoint.
        let mut ids = vec![0usize; batch.len()];
        {
            struct IdPtr(*mut usize);
            unsafe impl Sync for IdPtr {}
            let ptr = IdPtr(ids.as_mut_ptr());
            let ptr = &ptr;
            results.par_iter().zip(&bases).for_each(|((out, _), &b)| {
                for &(i, ref r) in out {
                    let v = match r {
                        Resolved::Old(id) => *id,
                        Resolved::New(k) => b + *k as usize,
                    };
                    // SAFETY: each batch index i is produced by exactly
                    // one shard, so these writes never overlap.
                    unsafe { *ptr.0.add(i as usize) = v };
                }
            });
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
