//! macOS enforcement: Seatbelt via in-process `sandbox_init` — no
//! `sandbox-exec` binary. The profile installs either on the current
//! process (`apply`) or in the child's `pre_exec` (`install`); either
//! way the sandbox state is inherited by every later exec.

use super::error::Error;
use super::policy::Policy;
use super::seatbelt::seatbelt_profile;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::Path;

unsafe extern "C" {
    fn sandbox_init(profile: *const c_char, flags: u64, errorbuf: *mut *mut c_char) -> c_int;
    // From sandbox.h: the kernel answers for the PROCESS itself, so code
    // inside the sandbox cannot fake the answer. kind 0 = no filter (is
    // there a sandbox at all); kind 1 = filter by path.
    fn sandbox_check(pid: c_int, operation: *const c_char, kind: c_int, ...) -> c_int;
}

/// Whether this process runs in ANY sandbox — the kernel's answer, not
/// the process's claim. The precondition check for installing a second
/// profile: macOS cannot nest them.
#[must_use]
pub fn sandboxed() -> bool {
    // Safe: a null operation with no filter takes no further argument
    unsafe { sandbox_check(std::process::id().cast_signed(), std::ptr::null(), 0) == 1 }
}

/// Whether this process's sandbox DENIES `operation` (such as
/// `file-write-data`) on `path`. The honest way to test a policy:
/// the kernel verdict, not a shell probe that could misfire for
/// unrelated reasons. The path must EXIST — the kernel evaluates the
/// rule against the path's inode, and a missing path answers denied.
/// A path with an interior null byte (possible in an `OsStr`) also
/// answers `false` — "not denied", the conservative reading for a
/// test helper.
#[must_use]
pub fn denies(operation: &str, path: &Path) -> bool {
    let (Ok(op), Ok(path)) = (
        CString::new(operation),
        CString::new(path.as_os_str().as_bytes()),
    ) else {
        return false;
    };
    // Safe: both strings outlive the call, which only reads them
    unsafe {
        sandbox_check(
            std::process::id().cast_signed(),
            op.as_ptr(),
            1,
            path.as_ptr(),
        ) == 1
    }
}

/// Compile the profile and run `sandbox_init`. Every road into
/// `sandbox_init` crosses this one point — `restrict_self`, `exec`'s
/// `pre_exec`, and the allow-default posture — so a sandboxed process
/// gets the TYPED `Error::Nested` refusal no matter which door it
/// tried. Returning `Error` (not a stringly-typed `io::Error`) lets the
/// direct roads surface `Error::Nested` and the launcher road wrap it
/// in an `io::Error` that callers can downcast back to `Error`.
fn compile_and_run(profile: &str) -> Result<(), Error> {
    if sandboxed() {
        return Err(Error::Nested);
    }
    let profile = CString::new(profile).map_err(|e| Error::Io(std::io::Error::other(e)))?;
    unsafe {
        let mut errorbuf: *mut c_char = std::ptr::null_mut();
        if sandbox_init(profile.as_ptr(), 0, std::ptr::addr_of_mut!(errorbuf)) != 0 {
            // the errorbuf is libsystem-allocated and tiny; on this
            // failure-only path it is left to the process's allocator
            // rather than redeclaring libc's `free` under our own name
            let detail = if errorbuf.is_null() {
                "no detail".to_owned()
            } else {
                CStr::from_ptr(errorbuf).to_string_lossy().into_owned()
            };
            return Err(Error::Policy(format!("sandbox_init: {detail}")));
        }
    }
    Ok(())
}

/// In-process application: the profile installs NOW — the process itself
/// becomes the sandbox, and its state is inherited by every later exec.
///
/// # Errors
/// `Error::Nested` when this process is already sandboxed (macOS cannot
/// install a second profile); fails when the profile cannot compile or
/// install.
pub fn apply(policy: &Policy) -> Result<(), Error> {
    // `compile_and_run` is the single nesting wall: the typed
    // `Error::Nested` flows straight back to `restrict_self` callers.
    compile_and_run(&seatbelt_profile(policy))
}

/// In-process application of an already-generated profile string — the
/// allow-default posture hands its generated profile here.
///
/// # Errors
/// `Error::Nested` when this process is already sandboxed; fails when
/// the profile cannot compile or install.
pub fn apply_profile(profile: &str) -> Result<(), Error> {
    // Same single nesting wall as `apply` — no duplicate `sandboxed()`
    // probe, no stringly-typed error.
    compile_and_run(profile)
}

/// Launcher application: the profile installs in the child's `pre_exec`
/// — confined from its first instruction. Failures surface at `spawn` as
/// the command's error (the profile compiles per-spawn, not here).
///
/// The `pre_exec` closure stores the typed `Error` as the inner error of
/// the `io::Error` it returns, so a launcher failure can be inspected:
///
/// ```ignore
/// if let Err(e) = cmd.spawn() {
///     if let Some(Error::Nested) = e.get_ref().and_then(|r| r.downcast_ref::<Error>()) {
///         // the process was already sandboxed
///     }
/// }
/// ```
///
/// # Errors
/// Never fails here — every failure is carried by the `pre_exec`
/// closure and surfaces at `spawn`.
#[allow(clippy::unnecessary_wraps)]
pub fn install(command: &mut std::process::Command, policy: &Policy) -> Result<(), Error> {
    // profile generation happens ONCE here, per `exec()` call — not per
    // spawn. High-frequency callers that spawn many children from one
    // policy can hoist it further with `install_profile`.
    install_profile(command, &seatbelt_profile(policy))
}

/// Install a PRE-GENERATED Seatbelt profile into a child's `pre_exec` —
/// the hoisting path for callers that spawn many children from one
/// policy. Generate the profile once with [`seatbelt_profile`], then
/// reuse it here so path canonicalization does not run per child.
///
/// # Errors
/// Never fails here — every failure is carried by the `pre_exec`
/// closure and surfaces at `spawn` as an `io::Error` whose inner error
/// downcasts to [`crate::Error`].
#[allow(clippy::unnecessary_wraps)]
pub fn install_profile(command: &mut std::process::Command, profile: &str) -> Result<(), Error> {
    let profile = profile.to_owned();
    unsafe {
        command.pre_exec(move || compile_and_run(&profile).map_err(std::io::Error::other));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `compile_and_run` returns the TYPED `Error::Nested` (not an opaque
    /// string) when this process is already sandboxed — the single wall
    /// every road into `sandbox_init` crosses.
    #[test]
    #[allow(clippy::unwrap_used)]
    fn compile_and_run_reports_typed_nested_when_sandboxed() {
        unsafe extern "C" {
            fn fork() -> i32;
            fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
            fn _exit(code: i32) -> !;
        }
        let policy = Policy::write_confined("/tmp/seatlock-nested-probe");
        unsafe {
            let pid = fork();
            assert!(pid >= 0, "fork failed");
            if pid == 0 {
                // confine this process, then ask compile_and_run directly
                if apply(&policy).is_err() {
                    _exit(1);
                }
                let nested = matches!(compile_and_run("(version 1)"), Err(Error::Nested));
                _exit(i32::from(nested));
            }
            let mut status = 0;
            let waited = loop {
                let w = waitpid(pid, std::ptr::addr_of_mut!(status), 0);
                if w != -1 || std::io::Error::last_os_error().raw_os_error() != Some(4) {
                    break w;
                }
            };
            let err = std::io::Error::last_os_error();
            assert_eq!(waited, pid, "errno: {err}");
            let code = (status >> 8) & 0xff;
            assert_eq!(code, 1, "compile_and_run must return typed Error::Nested");
        }
    }
}
