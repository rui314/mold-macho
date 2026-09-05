//! Error, warning and fatal-error reporting.
//!
//! Errors don't abort the link immediately: the linker keeps going so that
//! all problems are reported in one run, then exits before writing the
//! output. Fatal errors are for conditions the linker can't continue past.
//!
//! mold links once per process, so the diagnostic settings, the error
//! state and the lock that keeps worker threads' messages from
//! interleaving are process-wide, as in mold-rust: nothing has to carry
//! a diagnostics handle to be able to report.

use std::fmt;
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

static COLOR: AtomicBool = AtomicBool::new(false);
static FATAL_WARNINGS: AtomicBool = AtomicBool::new(false);
static SUPPRESS_WARNINGS: AtomicBool = AtomicBool::new(false);
static HAS_ERROR: AtomicBool = AtomicBool::new(false);
static OUTPUT_LOCK: Mutex<()> = Mutex::new(());

pub fn set_color(on: bool) {
    COLOR.store(on, Ordering::Relaxed);
}

pub fn set_fatal_warnings(on: bool) {
    FATAL_WARNINGS.store(on, Ordering::Relaxed);
}

pub fn set_suppress_warnings(on: bool) {
    SUPPRESS_WARNINGS.store(on, Ordering::Relaxed);
}

pub fn has_error() -> bool {
    HAS_ERROR.load(Ordering::Relaxed)
}

fn emit(prefix_mono: &str, prefix_color: &str, msg: fmt::Arguments) {
    let prefix = if COLOR.load(Ordering::Relaxed) {
        prefix_color
    } else {
        prefix_mono
    };
    let text = format!("{prefix}{msg}\n");
    let _guard = OUTPUT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _ = io::stderr().write_all(text.as_bytes());
}

/// Reports an unrecoverable error and exits.
pub fn fatal(msg: fmt::Arguments) -> ! {
    emit("mold: fatal: ", "mold: \x1b[0;1;31mfatal:\x1b[0m ", msg);
    exit_after_cleanup(1);
}

/// Reports an error.
pub fn error(msg: fmt::Arguments) {
    emit("mold: error: ", "mold: \x1b[0;1;31merror:\x1b[0m ", msg);
    HAS_ERROR.store(true, Ordering::Relaxed);
}

/// Reports a warning. With `-fatal_warnings` it is promoted to an error.
pub fn warn(msg: fmt::Arguments) {
    if SUPPRESS_WARNINGS.load(Ordering::Relaxed) {
        return;
    }
    if FATAL_WARNINGS.load(Ordering::Relaxed) {
        emit("mold: error: ", "mold: \x1b[0;1;31merror:\x1b[0m ", msg);
        HAS_ERROR.store(true, Ordering::Relaxed);
    } else {
        emit("mold: warning: ", "mold: \x1b[0;1;35mwarning:\x1b[0m ", msg);
    }
}

/// Prints an informational message to stdout.
pub fn out(msg: fmt::Arguments) {
    let text = format!("{msg}\n");
    let _guard = OUTPUT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _ = io::stdout().write_all(text.as_bytes());
}

/// Exits with a failure status if any error has been reported.
pub fn checkpoint() {
    if has_error() {
        exit_after_cleanup(1);
    }
}

/// Removes a partially-written output file, then terminates the process
/// without running destructors. Input files are mapped for the process's
/// lifetime, so there is nothing else to release.
pub fn exit_after_cleanup(status: i32) -> ! {
    crate::output_file::cleanup();
    let _ = io::stdout().flush();
    let _ = io::stderr().flush();
    // SAFETY: `_exit` only terminates the process.
    unsafe { libc::_exit(status) }
}

#[macro_export]
macro_rules! fatal {
    ($($arg:tt)*) => {
        $crate::error::fatal(format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! error {
    ($($arg:tt)*) => {
        $crate::error::error(format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! warn {
    ($($arg:tt)*) => {
        $crate::error::warn(format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! out {
    ($($arg:tt)*) => {
        $crate::error::out(format_args!($($arg)*))
    };
}

pub fn errno_string() -> String {
    io::Error::last_os_error().to_string()
}
