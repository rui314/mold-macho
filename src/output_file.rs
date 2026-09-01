//! Output file writing.

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
