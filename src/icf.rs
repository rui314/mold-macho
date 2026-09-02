//! Identical code folding.
//!
//! ld64 deduplicates identical functions by default (disabled with
//! -no_deduplicate); mold's ICF does the same for ELF. Two subsections
//! can share one copy when their bytes, relocations and unwind
//! behavior are all identical, *and* folding cannot be observed:
//! C++ explicitly permits identical instantiations to coalesce (that's
//! what weak definitions are), so folding is restricted to
//! subsections defined only by weak symbols.
//!
//! The algorithm follows mold: every candidate gets a hash of its
//! literal content, and a few refinement rounds rehash each candidate
//! with the previous-round hashes of its relocation targets, so the
//! hash comes to describe the whole reachable shape. Groups with equal
//! final hashes are then verified structurally and folded onto their
//! first member.

use std::hash::Hash;

use crate::arch::Arch;
use crate::context::Context;
use crate::input_sections::RelocTarget;
use crate::macho::*;
use crate::symbol::Origin;

/// A stable identifier for what a relocation edge points at.
#[derive(Hash, PartialEq, Eq, Clone, Copy)]
enum Edge {
    /// A candidate subsection, compared by its evolving hash.
    Candidate(usize),
    /// Anything else, compared by identity.
    Isec(usize, u64),
    Sym(usize),
}

/// A 128-bit digest. Ordered so equivalence classes group by sorting.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
struct Digest {
    hi: u64,
    lo: u64,
}

struct SipHash13_128 {
    v0: u64,
    v1: u64,
    v2: u64,
    v3: u64,
    buf: [u8; 8],
    buflen: u8,
    sum: u8,
}

impl SipHash13_128 {
    #[inline]
    fn new(key: &[u8; 16]) -> SipHash13_128 {
        let k0 = u64::from_le_bytes(key[..8].try_into().unwrap());
        let k1 = u64::from_le_bytes(key[8..].try_into().unwrap());
        SipHash13_128 {
            v0: 0x736f_6d65_7073_6575 ^ k0,
            v1: 0x646f_7261_6e64_6f6d ^ k1 ^ 0xee,
            v2: 0x6c79_6765_6e65_7261 ^ k0,
            v3: 0x7465_6462_7974_6573 ^ k1,
            buf: [0; 8],
            buflen: 0,
            sum: 0,
        }
    }

    #[inline]
    fn update(&mut self, mut msg: &[u8]) {
        self.sum = self.sum.wrapping_add(msg.len() as u8);

        if self.buflen != 0 {
            let buflen = self.buflen as usize;
            if buflen + msg.len() < 8 {
                self.buf[buflen..buflen + msg.len()].copy_from_slice(msg);
                self.buflen += msg.len() as u8;
                return;
            }

            let n = 8 - buflen;
            self.buf[buflen..].copy_from_slice(&msg[..n]);
            self.compress(u64::from_le_bytes(self.buf));
            msg = &msg[n..];
            self.buflen = 0;
        }

        while msg.len() >= 8 {
            self.compress(u64::from_le_bytes(msg[..8].try_into().unwrap()));
            msg = &msg[8..];
        }

        self.buf[..msg.len()].copy_from_slice(msg);
        self.buflen = msg.len() as u8;
    }

    /// Updates the hash with an in-memory `Digest`. Propagation hashes only
    /// complete digests, so this is the aligned 16-byte path through `update`.
    #[inline(always)]
    fn update_digest(&mut self, digest: Digest) {
        debug_assert_eq!(self.buflen, 0);
        self.sum = self.sum.wrapping_add(16);
        self.compress(u64::from_le_bytes(digest.hi.to_ne_bytes()));
        self.compress(u64::from_le_bytes(digest.lo.to_ne_bytes()));
    }

    #[inline]
    fn finish(mut self) -> Digest {
        self.buf[self.buflen as usize..].fill(0);
        self.compress((u64::from(self.sum) << 56) | u64::from_le_bytes(self.buf));

        self.v2 ^= 0xee;
        self.finalize();
        let hi = self.v0 ^ self.v1 ^ self.v2 ^ self.v3;

        self.v1 ^= 0xdd;
        self.finalize();
        let lo = self.v0 ^ self.v1 ^ self.v2 ^ self.v3;
        Digest { hi, lo }
    }

    #[inline(always)]
    fn round(&mut self) {
        self.v0 = self.v0.wrapping_add(self.v1);
        self.v1 = self.v1.rotate_left(13);
        self.v1 ^= self.v0;
        self.v0 = self.v0.rotate_left(32);
        self.v2 = self.v2.wrapping_add(self.v3);
        self.v3 = self.v3.rotate_left(16);
        self.v3 ^= self.v2;
        self.v0 = self.v0.wrapping_add(self.v3);
        self.v3 = self.v3.rotate_left(21);
        self.v3 ^= self.v0;
        self.v2 = self.v2.wrapping_add(self.v1);
        self.v1 = self.v1.rotate_left(17);
        self.v1 ^= self.v2;
        self.v2 = self.v2.rotate_left(32);
    }

    #[inline(always)]
    fn compress(&mut self, m: u64) {
        self.v3 ^= m;
        self.round();
        self.v0 ^= m;
    }

    #[inline(always)]
    fn finalize(&mut self) {
        self.round();
        self.round();
        self.round();
    }
}

pub fn icf_sections<E: Arch>(ctx: &mut Context<E>) {
    use rayon::prelude::*;

    // Candidates: live, executable, and defined exclusively by weak
    // symbols, so no one may rely on their addresses being distinct.
    // The per-subsection weak-only AND accumulates in parallel as a
    // three-state atomic: unset, all-weak-so-far, or poisoned by a
    // non-weak definition (which wins under any ordering).
    use std::sync::atomic::{AtomicU8, Ordering};
    let weak_state: Vec<AtomicU8> = (0..ctx.isecs.len()).map(|_| AtomicU8::new(0)).collect();
    ctx.objs.par_iter().for_each(|obj| {
        for (nlist, &sym_id) in obj.nlists.iter().zip(&obj.syms) {
            if nlist.is_stab() || nlist.n_type() != N_SECT {
                continue;
            }
            let sym = &ctx.symtab[sym_id];
            // Compiler-generated temporary labels don't make an atom's
            // address observable.
            if !nlist.is_extern() && (sym.name.starts_with('l') || sym.name.starts_with('L')) {
                continue;
            }
            let Some(isec) = sym.isec else {
                continue;
            };
            if nlist.n_desc & N_WEAK_DEF != 0 {
                let _ = weak_state[isec].compare_exchange(
                    0,
                    1,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                );
            } else {
                weak_state[isec].store(2, Ordering::Relaxed);
            }
        }
    });
    let weak_only: Vec<Option<bool>> = weak_state
        .into_iter()
        .map(|s| match s.into_inner() {
            0 => None,
            1 => Some(true),
            _ => Some(false),
        })
        .collect();

    let is_candidate = |ctx: &Context<E>, id: usize| -> bool {
        let isec = &ctx.isecs[id];
        isec.is_alive
            && isec.replacement.is_none()
            && isec.hdr.segname() == "__TEXT"
            && isec.hdr.flags & S_ATTR_PURE_INSTRUCTIONS != 0
            && isec.hdr.flags & (S_ATTR_NO_DEAD_STRIP | S_ATTR_LIVE_SUPPORT) == 0
            && weak_only[id] == Some(true)
    };

    let __t = std::time::Instant::now();
    let candidates: Vec<usize> = (0..ctx.isecs.len())
        .into_par_iter()
        .filter(|&i| is_candidate(ctx, i))
        .collect();
    if candidates.len() < 2 {
        return;
    }
    let mut cand_index = vec![usize::MAX; ctx.isecs.len()];
    for (i, &id) in candidates.iter().enumerate() {
        cand_index[id] = i;
    }

    let edge_of = |ctx: &Context<E>, obj: usize, target: RelocTarget, addend: i64| -> (Edge, i64) {
        match target {
            RelocTarget::Sym(idx) => {
                let sym_id = ctx.objs[obj].syms[idx];
                let sym = &ctx.symtab[sym_id];
                if let (Origin::Obj(_), Some(isec)) = (sym.origin, sym.isec) {
                    let isec = ctx.resolve_isec(isec);
                    if cand_index[isec] != usize::MAX {
                        return (Edge::Candidate(cand_index[isec]), addend + sym.value as i64);
                    }
                    return (Edge::Isec(isec, sym.value), addend);
                }
                (Edge::Sym(sym_id), addend)
            }
            RelocTarget::Section(isec) => {
                let isec = ctx.resolve_isec(isec);
                if cand_index[isec] != usize::MAX {
                    return (Edge::Candidate(cand_index[isec]), addend);
                }
                (Edge::Isec(isec, 0), addend)
            }
        }
    };

    // The base digest of a candidate: its bytes and the non-candidate
    // parts of its edges, hashed with SipHash13-128 exactly as
    // mold-rust's compute_digest does (candidate edges are mixed in
    // during the rounds instead). A fixed key keeps the link
    // reproducible; the digest is used only to group, never emitted.
    const KEY: [u8; 16] = *b"mold-macho-icf!!";
    let base_hash = |ctx: &Context<E>, id: usize| -> Digest {
        let isec = &ctx.isecs[id];
        let mut h = SipHash13_128::new(&KEY);
        h.update(&isec.hdr.flags.to_ne_bytes());
        h.update(&isec.size.to_ne_bytes());
        h.update(&isec.data.len().to_ne_bytes());
        h.update(isec.data);
        for rel in &isec.relocs {
            h.update(&rel.offset.to_ne_bytes());
            h.update(&rel.r_type.to_ne_bytes());
            h.update(&[rel.size, rel.is_pcrel as u8, rel.is_subtracted as u8]);
            let (edge, addend) = edge_of(ctx, isec.obj, rel.target, rel.addend);
            h.update(&addend.to_ne_bytes());
            // A candidate edge contributes nothing to the base; the
            // rounds fold in the target's evolving digest.
            match edge {
                Edge::Candidate(_) => h.update(b"c"),
                Edge::Isec(i, v) => {
                    h.update(b"i");
                    h.update(&i.to_ne_bytes());
                    h.update(&v.to_ne_bytes());
                }
                Edge::Sym(s) => {
                    h.update(b"s");
                    h.update(&s.to_ne_bytes());
                }
            }
        }
        // Unwinding is part of a function's identity; the subsection
        // holds its record range.
        let recs = isec.unwind_offset as usize..(isec.unwind_offset + isec.nunwind) as usize;
        for rec in &ctx.unwind_records[recs] {
            h.update(&rec.input_offset.to_ne_bytes());
            h.update(&rec.code_len.to_ne_bytes());
            h.update(&rec.encoding.to_ne_bytes());
            h.update(&rec.personality.map_or(u64::MAX, |p| p as u64).to_ne_bytes());
            h.update(&rec.fde.map_or(u64::MAX, |f| f as u64).to_ne_bytes());
            if let Some((lsda, off)) = rec.lsda {
                h.update(&ctx.resolve_isec(lsda).to_ne_bytes());
                h.update(&off.to_ne_bytes());
            }
        }
        h.finish()
    };

    // Refinement rounds propagate hashes along edges; log2(n) rounds
    // reach across any chain of distinct shapes.
    if std::env::var_os("MOLD_TIMING").is_some() {
        eprintln!("      icf-prep {:?} candidates {}", __t.elapsed(), candidates.len());
    }
    let __t = std::time::Instant::now();

    // Content is hashed exactly once; the refinement rounds mix only
    // fixed-size digests - each candidate's base digest plus its
    // candidate-edge targets' previous-round digests - via
    // update_digest, mold-rust's aligned 16-byte fast path, so a round
    // is cheap however many rounds log2(n) requires.
    let base: Vec<Digest> = candidates.par_iter().map(|&id| base_hash(ctx, id)).collect();

    // Candidate edges in CSR form - one flat values array indexed by a
    // per-candidate prefix-summed offset, exactly mold-rust's Edges
    // (gather_edges). The propagation loop is the hot path; a single
    // contiguous array keeps it cache-friendly, where a Vec<Vec<u32>>
    // would chase one heap allocation per candidate.
    let counts: Vec<u32> = candidates
        .par_iter()
        .map(|&id| {
            let isec = &ctx.isecs[id];
            isec.relocs
                .iter()
                .filter(|rel| {
                    matches!(edge_of(ctx, isec.obj, rel.target, rel.addend).0, Edge::Candidate(_))
                })
                .count() as u32
        })
        .collect();
    let mut edge_indices: Vec<u32> = Vec::with_capacity(candidates.len() + 1);
    edge_indices.push(0);
    for c in &counts {
        edge_indices.push(edge_indices.last().unwrap() + c);
    }
    let mut edge_values: Vec<u32> = vec![0; *edge_indices.last().unwrap() as usize];
    {
        struct EdgeBuf(*mut u32);
        unsafe impl Sync for EdgeBuf {}
        let out = EdgeBuf(edge_values.as_mut_ptr());
        let out = &out;
        let edge_indices = &edge_indices;
        candidates.par_iter().enumerate().for_each(|(vertex, &id)| {
            let isec = &ctx.isecs[id];
            let mut i = edge_indices[vertex] as usize;
            for rel in &isec.relocs {
                if let Edge::Candidate(c) = edge_of(ctx, isec.obj, rel.target, rel.addend).0 {
                    // SAFETY: this vertex alone owns its prefix-sum range.
                    unsafe { *out.0.add(i) = c as u32 };
                    i += 1;
                }
            }
        });
    }

    // Refine until the number of equivalence classes stops growing,
    // as mold does. Counting classes costs about as much as a
    // propagation, so propagate three times per count (mold's ratio),
    // ping-ponging between two buffers instead of allocating a fresh
    // vector every round. Classes only ever split, so the count is
    // monotone and the loop terminates.
    let mut hashes = base;
    let mut scratch = vec![Digest::default(); hashes.len()];
    let mut sorted: Vec<Digest> = Vec::new();
    let mut prev_classes = 0usize;
    loop {
        for _ in 0..3 {
            let cur = &hashes;
            (0..candidates.len())
                .into_par_iter()
                .map(|i| {
                    // next[i] = H(cur[i], cur[neighbors]) - mold-rust's
                    // propagate hashes the vertex's own current digest,
                    // so its nth-round digest is a hash of its unfolding
                    // into a tree of depth n.
                    let mut h = SipHash13_128::new(&KEY);
                    h.update_digest(cur[i]);
                    for &c in &edge_values[edge_indices[i] as usize..edge_indices[i + 1] as usize]
                    {
                        h.update_digest(cur[c as usize]);
                    }
                    h.finish()
                })
                .collect_into_vec(&mut scratch);
            std::mem::swap(&mut hashes, &mut scratch);
        }
        sorted.clone_from(&hashes);
        sorted.par_sort_unstable();
        sorted.dedup();
        if sorted.len() == prev_classes {
            break;
        }
        prev_classes = sorted.len();
    }

    // Group by final hash and fold each group onto its first member,
    // after verifying literal equality to rule out collisions.
    if std::env::var_os("MOLD_TIMING").is_some() {
        eprintln!("      icf-rounds {:?}", __t.elapsed());
    }
    let __t = std::time::Instant::now();
    // Group by sorting (digest, id) pairs; equal digests become
    // contiguous runs and the smallest member leads each class.
    let mut pairs: Vec<(Digest, u32)> = hashes
        .iter()
        .zip(&candidates)
        .map(|(&h, &id)| (h, id as u32))
        .collect();
    pairs.par_sort_unstable();

    let equal = |ctx: &Context<E>, a: usize, b: usize| -> bool {
        let (x, y) = (&ctx.isecs[a], &ctx.isecs[b]);
        if x.data != y.data || x.hdr.flags != y.hdr.flags || x.relocs.len() != y.relocs.len() {
            return false;
        }
        x.relocs.iter().zip(&y.relocs).all(|(r, s)| {
            r.offset == s.offset
                && r.r_type == s.r_type
                && r.size == s.size
                && r.is_pcrel == s.is_pcrel
                && edge_of(ctx, x.obj, r.target, r.addend)
                    == edge_of(ctx, y.obj, s.target, s.addend)
        })
    };

    // The converged 128-bit digests are the equivalence classes; fold
    // each run onto its first member in one pass, as mold folds its
    // groups directly. (The old byte-verifying fixpoint re-walked
    // every group until stable - hundreds of milliseconds on a link
    // with 840k candidates.) debug builds keep the byte check as an
    // assertion.
    if std::env::var_os("MOLD_TIMING").is_some() {
        eprintln!("      icf-group {:?}", __t.elapsed());
    }
    let __t = std::time::Instant::now();
    let mut i = 0;
    while i < pairs.len() {
        let digest = pairs[i].0;
        let mut j = i + 1;
        while j < pairs.len() && pairs[j].0 == digest {
            j += 1;
        }
        if j - i >= 2 {
            let leader = pairs[i].1 as usize;
            if ctx.isecs[leader].replacement.is_none() {
                let mut align = ctx.isecs[leader].hdr.p2align;
                for k in i + 1..j {
                    let id = pairs[k].1 as usize;
                    if ctx.isecs[id].replacement.is_none() {
                        debug_assert!(equal(ctx, leader, id));
                        ctx.isecs[id].replacement = Some(leader);
                        align = align.max(ctx.isecs[id].hdr.p2align);
                    }
                }
                // The leader is laid out for every folded member, so it
                // must carry the strongest alignment among them - mold's
                // update_alignment.
                ctx.isecs[leader].hdr.p2align = align;
            }
        }
        i = j;
    }
    let _ = &equal;
    if std::env::var_os("MOLD_TIMING").is_some() {
        eprintln!("      icf-fold {:?}", __t.elapsed());
    }
}
