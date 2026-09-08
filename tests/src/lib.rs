//! Runs mold's shell tests in parallel for Cargo's test harness.
//!
//! The tests themselves are shell scripts, so that they exercise exactly
//! the same inputs and toolchains as the system linker. The runner owns
//! test discovery, scheduling and reporting. Tests run natively on the
//! host; there is no cross-linking support yet.

use std::env;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::sync::Mutex;

struct TestJob {
    script: PathBuf,
    name: String,
    arch: &'static str,
}

/// Returns the architectures to test: the host's, plus x86_64 under
/// Rosetta when available.
fn test_archs() -> Vec<&'static str> {
    let host = if cfg!(target_arch = "aarch64") {
        "arm64"
    } else {
        "x86_64"
    };
    let mut archs = vec![host];
    if host == "arm64"
        && Command::new("arch")
            .args(["-x86_64", "/usr/bin/true"])
            .status()
            .is_ok_and(|s| s.success())
    {
        archs.push("x86_64");
    }
    archs
}

#[derive(PartialEq, Eq)]
enum Outcome {
    Pass,
    Skip,
    Fail,
}

fn run_one(job: &TestJob, root: &Path, linker: &Path) -> (Outcome, String) {
    let output = Command::new("bash")
        .arg(&job.script)
        .current_dir(root)
        .env("mold", linker)
        .env("ARCH", job.arch)
        .output();

    let output = match output {
        Ok(output) => output,
        Err(e) => return (Outcome::Fail, format!("cannot run bash: {e}")),
    };

    let mut log = String::from_utf8_lossy(&output.stdout).into_owned();
    log.push_str(&String::from_utf8_lossy(&output.stderr));

    let outcome = if !output.status.success() {
        Outcome::Fail
    } else if log.contains("skipped") {
        Outcome::Skip
    } else {
        Outcome::Pass
    };
    (outcome, log)
}

/// Discovers and runs the test scripts in `cases`, using the linker at
/// `linker`. Command line arguments are substring patterns selecting a
/// subset of tests.
pub fn run(cases: &Path, linker: &Path) -> ExitCode {
    let patterns: Vec<String> = env::args().skip(1).filter(|a| !a.starts_with('-')).collect();

    let mut jobs = Vec::new();
    let mut entries: Vec<_> = std::fs::read_dir(cases)
        .expect("cannot read test directory")
        .map(|e| e.unwrap().path())
        .collect();
    entries.sort();

    let archs = test_archs();
    for path in entries {
        if path.extension().map_or(true, |e| e != "sh") {
            continue;
        }
        let name = path.file_stem().unwrap().to_string_lossy().into_owned();
        if patterns.is_empty() || patterns.iter().any(|p| name.contains(p.as_str())) {
            for &arch in &archs {
                jobs.push(TestJob {
                    script: path.clone(),
                    name: format!("{name} ({arch})"),
                    arch,
                });
            }
        }
    }

    // Tests write their outputs under out/test in the repository root.
    let root = cases.parent().unwrap().parent().unwrap().to_path_buf();
    let linker = std::fs::canonicalize(linker).expect("linker not found");

    let jobs = &jobs;
    let next = &Mutex::new(0usize);
    let failed = &Mutex::new(Vec::new());
    let nthreads = std::thread::available_parallelism().map_or(1, |n| n.get());

    std::thread::scope(|scope| {
        for _ in 0..nthreads.min(jobs.len()) {
            let root = root.clone();
            let linker = linker.clone();
            scope.spawn(move || loop {
                let idx = {
                    let mut next = next.lock().unwrap();
                    let idx = *next;
                    *next += 1;
                    idx
                };
                let Some(job) = jobs.get(idx) else { return };

                let (outcome, log) = run_one(job, &root, &linker);
                match outcome {
                    Outcome::Pass => println!("Testing {} ... OK", job.name),
                    Outcome::Skip => println!("Testing {} ... skipped", job.name),
                    Outcome::Fail => {
                        println!("Testing {} ... FAILED", job.name);
                        failed.lock().unwrap().push((job.name.clone(), log));
                    }
                }
            });
        }
    });

    let failed = failed.lock().unwrap();
    if failed.is_empty() {
        return ExitCode::SUCCESS;
    }

    println!();
    for (name, log) in failed.iter() {
        println!("==== {name} ====");
        println!("{log}");
    }
    println!("{} test(s) failed", failed.len());
    ExitCode::FAILURE
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Output;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn run_script(body: &str) -> Output {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let dir = env::temp_dir().join(format!(
            "mold-harness-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&dir).unwrap();
        let common = Path::new(env!("CARGO_MANIFEST_DIR")).join("cases/common.inc");
        let output = Command::new("bash")
            .args(["-c", &format!("source \"$1\"\n{body}"), "harness-test"])
            .arg(common)
            .env("mold", "unused")
            .current_dir(&dir)
            .output().unwrap();
        std::fs::remove_dir_all(dir).unwrap();
        output
    }

    #[test]
    fn negated_failure_at_exit_is_not_success() {
        let output = run_script("! true");
        assert!(!output.status.success());
        assert!(!String::from_utf8_lossy(&output.stdout).contains("OK"));
    }

    #[test]
    fn negative_assertion_stops_before_later_commands() {
        let output = run_script("not true\necho reached");
        assert!(!output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(!stdout.contains("reached"));
        assert!(!stdout.contains("OK"));
        assert!(String::from_utf8_lossy(&output.stderr).contains("unexpectedly succeeded"));
    }

    #[test]
    fn explicit_exit_status_is_preserved() {
        assert_eq!(run_script("exit 7").status.code(), Some(7));
    }

    #[test]
    fn expected_failure_and_success_pass() {
        let output = run_script("not false\ntrue");
        assert!(output.status.success());
        assert!(String::from_utf8_lossy(&output.stdout).contains("OK"));
    }

    #[test]
    fn skip_remains_successful() {
        let output = run_script("skip");
        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("skipped"));
        assert!(!stdout.contains("OK"));
    }
}
