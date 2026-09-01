//! Small utility functions.

/// Rounds `val` up to the next multiple of `align`. `align` must be a
/// power of two.
pub fn align_to(val: u64, align: u64) -> u64 {
    debug_assert!(align.is_power_of_two());
    (val + align - 1) & !(align - 1)
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
