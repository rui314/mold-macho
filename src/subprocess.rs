//! Process management, ported from mold-rust's subprocess.rs.
//!
//! Exiting a program with large memory usage is slow - unmapping
//! gigabytes of input files can take a hundred milliseconds or more,
//! all of it after the output is already on disk. To hide the
//! latency, the linker forks at startup: the child does the actual
//! linking and pokes a pipe the moment the output is complete; the
//! parent exits right then, and the child's teardown happens off
//! anyone's critical path. If the child dies before notifying, the
//! parent relays its exit status (or signal) instead.

use std::sync::atomic::{AtomicI32, Ordering};

static PIPE_WRITE_FD: AtomicI32 = AtomicI32::new(-1);

pub fn fork_child() {
    let mut pipefd = [0i32; 2];
    // SAFETY: plain libc calls with valid arguments.
    unsafe {
        if libc::pipe(pipefd.as_mut_ptr()) == -1 {
            eprintln!("mold: pipe failed");
            std::process::exit(1);
        }
        let pid = libc::fork();
        if pid == -1 {
            eprintln!("mold: fork failed");
            std::process::exit(1);
        }
        if pid > 0 {
            // Parent: wait for the child's "output written" byte, or
            // for its death.
            libc::close(pipefd[1]);
            let mut buf = [0u8; 1];
            if libc::read(pipefd[0], buf.as_mut_ptr() as *mut libc::c_void, 1) == 1 {
                libc::_exit(0);
            }
            let mut status = 0;
            libc::waitpid(pid, &mut status, 0);
            if libc::WIFEXITED(status) {
                libc::_exit(libc::WEXITSTATUS(status));
            }
            if libc::WIFSIGNALED(status) {
                libc::raise(libc::WTERMSIG(status));
            }
            libc::_exit(1);
        }
        // Child
        libc::close(pipefd[0]);
    }
    PIPE_WRITE_FD.store(pipefd[1], Ordering::Relaxed);
}

/// Tells the parent that the output is complete.
pub fn notify_parent() {
    let fd = PIPE_WRITE_FD.swap(-1, Ordering::Relaxed);
    if fd == -1 {
        return;
    }
    let buf = [1u8];
    // SAFETY: fd is a valid pipe write end.
    unsafe {
        libc::write(fd, buf.as_ptr() as *const libc::c_void, 1);
    }
}
