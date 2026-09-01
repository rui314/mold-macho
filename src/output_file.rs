//! Output file writing.
//!
//! Unlike mold for ELF, the output is built in an anonymous buffer and
//! written with one write() call, not through a shared mapping of the
//! file. That is deliberate: on macOS, a vnode that has ever had a
//! writable shared mapping fails ad-hoc code-signature validation at
//! exec time - the binary is killed with SIGKILL even though codesign
//! reports it valid on disk, msync changes nothing, and rename()ing a
//! mapped-written temp file over the destination does not help because
//! the taint follows the vnode. Only content that reaches the file via
//! write() (or a fresh copy) executes. LLVM's FileOutputBuffer falls
//! back to in-memory buffers for executables on Darwin for the same
//! reason.

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Mutex;

use crate::error::{errno_string, Diagnostics};
use crate::fatal;

/// The output path of the in-progress link, removed on a fatal error so
/// that a failed link doesn't leave a partial file behind.
static OUTPUT_PATH: Mutex<Option<PathBuf>> = Mutex::new(None);

/// Removes a partially-written output file after a fatal error.
pub fn cleanup() {
    if let Ok(mut guard) = OUTPUT_PATH.lock() {
        if let Some(path) = guard.take() {
            let _ = std::fs::remove_file(path);
        }
    }
}

pub fn write(diag: &Diagnostics, path: &str, buf: &[u8]) {
    // Remove an existing file first. Overwriting a running executable is
    // an error on some systems, and on macOS the kernel caches code
    // signature state per vnode, so a fresh file avoids stale-signature
    // kills.
    let _ = std::fs::remove_file(path);
    *OUTPUT_PATH.lock().unwrap() = Some(PathBuf::from(path));

    if let Err(_) = std::fs::write(path, buf) {
        fatal!(diag, "cannot write {path}: {}", errno_string());
    }
    if let Err(_) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)) {
        fatal!(diag, "cannot chmod {path}: {}", errno_string());
    }

    *OUTPUT_PATH.lock().unwrap() = None;
}
