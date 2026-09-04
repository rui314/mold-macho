//! Small utility functions.

/// Rounds `val` up to the next multiple of `align`. `align` must be a
/// power of two.
pub fn align_to(val: u64, align: u64) -> u64 {
    debug_assert!(align.is_power_of_two());
    (val + align - 1) & !(align - 1)
}

/// Rounds `val` up to the next value congruent to `modulus` modulo
/// `align`: the smallest x >= val with x % align == modulus. ld64
/// places every atom this way, keeping the offset it had within its
/// section modulo the section's alignment, not merely rounding up to
/// the section's alignment.
pub fn align_to_mod(val: u64, align: u64, modulus: u64) -> u64 {
    debug_assert!(align.is_power_of_two() && modulus < align);
    if val <= modulus {
        modulus
    } else {
        align_to(val - modulus, align) + modulus
    }
}

/// Returns the bit field of `val` from bit `hi` down to bit `lo`,
/// inclusive.
pub fn bits(val: u64, hi: u32, lo: u32) -> u64 {
    (val >> lo) & ((1 << (hi - lo + 1)) - 1)
}

/// Sign-extends a value whose sign bit is bit `n`.
pub fn sign_extend(val: u64, n: u32) -> i64 {
    ((val << (63 - n)) as i64) >> (63 - n)
}

/// A sort key that orders strings like the strings themselves but
/// settles most comparisons on one integer: the first eight bytes,
/// big-endian, zero-padded. Symbol names cannot contain NULs, so
/// (prefix, name) order equals plain name order. Mach-O sorts its
/// global symbols and export-trie input by name (ELF mold never
/// name-sorts), and mangled names share long prefixes, which makes
/// plain str comparison the sort's bottleneck.
pub fn name_sort_key(name: &str) -> (u64, &str) {
    let b = name.as_bytes();
    let mut p = [0u8; 8];
    let n = b.len().min(8);
    p[..n].copy_from_slice(&b[..n]);
    (u64::from_be_bytes(p), name)
}

/// Appends a ULEB128-encoded value.
/// Matches a symbol-list pattern: literal text with `*` wildcards,
/// the dialect ld64 uses in its various symbol list files.
pub fn glob_match(pat: &str, name: &str) -> bool {
    let mut parts = pat.split('*');
    let first = parts.next().unwrap_or("");
    if !name.starts_with(first) {
        return false;
    }
    let mut pos = first.len();
    let mut rest: Vec<&str> = parts.collect();
    let last = rest.pop();
    for part in rest {
        match name[pos..].find(part) {
            Some(i) => pos = pos + i + part.len(),
            None => return false,
        }
    }
    match last {
        Some(l) => name.len() >= pos + l.len() && name.ends_with(l),
        None => pos == name.len(),
    }
}

pub fn write_sleb(buf: &mut Vec<u8>, mut val: i64) {
    loop {
        let byte = (val & 0x7f) as u8;
        val >>= 7;
        let done = (val == 0 && byte & 0x40 == 0) || (val == -1 && byte & 0x40 != 0);
        buf.push(if done { byte } else { byte | 0x80 });
        if done {
            return;
        }
    }
}

pub fn write_uleb(buf: &mut Vec<u8>, mut val: u64) {
    loop {
        let byte = (val & 0x7f) as u8;
        val >>= 7;
        if val == 0 {
            buf.push(byte);
            return;
        }
        buf.push(byte | 0x80);
    }
}

/// Computes the SHA-256 hash of `data` into `out`.
///
/// libSystem, which every macOS process links against, exports the
/// CommonCrypto implementation, so we use it rather than pulling in a
/// Rust crypto crate.
pub fn sha256(data: &[u8], out: &mut [u8; 32]) {
    extern "C" {
        fn CC_SHA256(data: *const u8, len: u32, md: *mut u8) -> *mut u8;
    }
    // SAFETY: CC_SHA256 reads `len` bytes and writes exactly 32 bytes.
    unsafe {
        CC_SHA256(data.as_ptr(), data.len() as u32, out.as_mut_ptr());
    }
}
