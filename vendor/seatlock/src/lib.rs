//! seatlock: reusable OS-level sandbox enforcement for processes.
//!
//! On macOS it uses Seatbelt, applied directly inside the process with
//! `sandbox_init` (no `sandbox-exec` wrapper binary). On Linux it uses
//! Landlock, which confines filesystem access, TCP and UDP ports, and
//! scopes such as signals and abstract sockets, together with Linux
//! capability drops and the `NO_NEW_PRIVS` flag.
//! **Deny by default**: what is not granted does not exist — reads need
//! a grant (world-read is the grant `"/"`), writes need `write_allow`,
//! network needs `NetworkPolicy` port rules; on Linux the read right
//! also narrows EXECUTE to granted trees.
//!
//! Two APIs:
//! - [`Policy::exec(program, args)`][Policy::exec] — the launcher
//!   pattern: the policy installs in the child's `pre_exec`, confined
//!   from its first instruction.
//! - [`Policy::restrict_self()`][Policy::restrict_self] — in-process
//!   enforcement (`landlock_restrict_self` / `sandbox_init` applied
//!   NOW): everything after the call, and every child, is confined.
//!
//! Under the `serde` feature the policy derives Serialize/Deserialize —
//! a confinement is a portable artifact. seatlock has no consumer
//! concepts: what a write root means, which paths deserve denying, is
//! the caller's vocabulary. Every field is enforced wherever the OS can
//! express it; the per-field platform gaps are named on the fields
//! themselves and in `docs/features.md`.

mod allow_default;
mod error;
pub mod known;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
mod policy;
mod seatbelt;
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
mod stub;

pub use allow_default::{
    Access, AllowDefaultPolicy, allow_default_profile, real, resolved, ruled_parents,
};
pub use error::Error;
#[cfg(target_os = "macos")]
pub use macos::{apply_profile, denies, install_profile, sandboxed};
pub use policy::{
    DevAccess, ExecLogging, NetworkMode, NetworkPolicy, Policy, PrivilegeGain, ScopeMode,
    TempAccess,
};
pub use seatbelt::seatbelt_profile;

#[cfg(target_os = "linux")]
use linux as platform;
#[cfg(target_os = "macos")]
use macos as platform;
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
use stub as platform;

impl Policy {
    /// Apply the policy to the CURRENT process: everything after this
    /// call is confined — every allocation, file touch, socket, and every
    /// child process this process spawns (confinement is inherited,
    /// unconditionally). In-process enforcement: Landlock's
    /// `landlock_restrict_self` on Linux, `sandbox_init` on macOS.
    ///
    /// Apply it before opening files or sockets and before spawning the
    /// work (and on Linux, before spawning threads — enforcement syncs
    /// across threads via `TSYNC` where the kernel supports it;
    /// `BestEffort` degrades that silently on old kernels). Capability
    /// drops and `NO_NEW_PRIVS` are applied first, so nothing after the
    /// call can re-raise a privilege. For confining a program from ITS
    /// first instruction instead, use [`Policy::exec`].
    ///
    /// # Errors
    /// Fails when the platform enforcement cannot be installed — a
    /// policy that cannot be applied must not pretend: the caller gets
    /// the error, never an unconfined process that "went along with it".
    pub fn restrict_self(&self) -> Result<(), Error> {
        let policy = canonicalize(self);
        platform::apply(&policy)
    }

    /// A `Command` for `program args` confined from its FIRST
    /// instruction: the policy installs in the child's `pre_exec` — the
    /// child never runs one unconfined instruction, and every descendant
    /// inherits the confinement. The returned command is the caller's to
    /// finish (`current_dir`, env, fds, spawn) — only the confinement is
    /// already installed.
    ///
    /// This is the launcher pattern: no wrapper binary, no second
    /// process. For confining already-running code instead, use
    /// [`Policy::restrict_self`].
    ///
    /// # Errors
    /// Fails when the platform enforcement (Seatbelt profile compile or
    /// Landlock ruleset) cannot be installed on the command.
    pub fn exec(&self, program: &str, args: &[&str]) -> Result<std::process::Command, Error> {
        let mut command = std::process::Command::new(program);
        command.args(args);
        install(&mut command, self)?;
        Ok(command)
    }
}

/// Apply an [`AllowDefaultPolicy`] to the CURRENT process — the
/// allow-default posture's enforcement point, the mirror of
/// [`Policy::restrict_self`]. Free function, not a method: the policy is
/// a data record, enforcement is the crate's business.
///
/// Missing writable roots are created first — a profile rule cannot
/// make the child able to `mkdir` its own write root (directory
/// creation is a `file-write*`), so a grant on a missing dir must
/// exist before the confinement installs. Then the kernel is asked
/// whether this process is already sandboxed (`sandbox_check`) — macOS
/// cannot nest Seatbelt profiles, and the honest answer is
/// `Error::Nested`, never a partially confined process.
///
/// # Errors
/// `Error::Nested` when already sandboxed (macOS); `Error::Policy` for
/// an unenforceable policy (relative or non-UTF-8 paths); `Error::Io`
/// when a writable root cannot be created.
#[cfg(target_os = "macos")]
pub fn restrict_allow_default(policy: &AllowDefaultPolicy) -> Result<(), Error> {
    // a sandboxed process gets the named refusal BEFORE any filesystem
    // mutation — a doomed apply must not leave roots behind
    if sandboxed() {
        return Err(Error::Nested);
    }

    // the grants must exist before the child loses the right to make
    // them — mirror the deny-by-default canonicalize()
    for root in &policy.writable {
        std::fs::create_dir_all(root)?;
    }

    let profile = allow_default_profile(policy)?;
    apply_profile(&profile)
}

/// The allow-default posture has no Linux enforcement: its semantics
/// (deny-by-exception over a world-readable filesystem) have no
/// Landlock expression. This stub exists so a cross-platform caller
/// hits the wall at the ENFORCEMENT point, with a named error — never
/// silently unconfined.
///
/// # Errors
/// Always `Error::Unsupported`.
#[cfg(not(target_os = "macos"))]
pub fn restrict_allow_default(_policy: &AllowDefaultPolicy) -> Result<(), Error> {
    Err(Error::Unsupported(
        "the allow-default posture is Seatbelt-shaped and only macOS enforces it — \
         use the deny-by-default Policy (Landlock) on Linux"
            .into(),
    ))
}

/// The shared application point for [`Policy::exec`]: canonicalize the
/// policy's write grants — creating missing roots (Landlock pins rules
/// to inodes at enforce time, so a missing root would silently carry no
/// write rule; the policy grants write there, so making it exist is
/// coherent) — then hand the policy to the platform.
fn install(command: &mut std::process::Command, policy: &Policy) -> Result<(), Error> {
    let policy = canonicalize(policy);
    platform::install(command, &policy)
}

/// Canonicalize a policy's write grants: create missing roots (Landlock
/// pins rules to inodes, so a missing root would silently carry no write
/// rule; the policy grants write there, so making it exist is coherent)
/// and expand the temp/dev meta-grants. Shared by both enforcement
/// points so `restrict_self` and `exec` agree.
fn canonicalize(policy: &Policy) -> Policy {
    let mut policy = policy.clone();
    let mut canonical_writes = Vec::new();
    for p in &policy.write_allow {
        // Fail closed: only a root that EXISTS after creation and resolves
        // to a real path becomes a grant. Adding the original (possibly
        // hostile or uncreatable) path would grant a rule the OS may match
        // to a different inode than the caller intended — and it made
        // macOS emit a subpath rule for a path Linux silently skipped.
        if let Ok(real) = std::fs::create_dir_all(p).and_then(|()| std::fs::canonicalize(p)) {
            canonical_writes.push(real);
        }
    }
    if policy.allow_temp == TempAccess::Granted {
        canonical_writes.push(std::env::temp_dir());
        canonical_writes.push(std::path::PathBuf::from("/tmp"));
        canonical_writes.push(std::path::PathBuf::from("/private/tmp"));
    }
    if policy.allow_dev == DevAccess::Granted {
        canonical_writes.push(std::path::PathBuf::from("/dev"));
    }
    policy.write_allow = canonical_writes;
    policy
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{DevAccess, Policy, TempAccess};

    /// The allow-default posture, proven with KERNEL verdicts: the
    /// child applies the policy, then asks `sandbox_check` whether
    /// writes outside the grant are denied and writes inside are not —
    /// the kernel's answer for the process itself, which no shell probe
    /// can fake. The second apply attempt must fail `Nested`: macOS
    /// cannot install a profile inside a sandbox.
    #[test]
    #[allow(clippy::unwrap_used)]
    #[cfg(target_os = "macos")]
    fn restrict_allow_default_confines_writes_and_reports_nested() {
        unsafe extern "C" {
            fn fork() -> i32;
            fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
            fn _exit(code: i32) -> !;
        }
        let dir = tempfile::tempdir().unwrap();
        let policy = AllowDefaultPolicy::write_confined(dir.path());
        // the kernel matches the RESOLVED path, so the probes must speak
        // resolved paths too — /var/folders and /private/var/folders
        // name the same dir but not the same rule
        let inside = real(&dir.path().join("ok.txt"));
        let outside = real(&dir.path().parent().unwrap().join("allow-default-probe.txt"));

        unsafe {
            let pid = fork();
            assert!(pid >= 0, "fork failed");
            if pid == 0 {
                // the kernel needs a real inode to answer for — create
                // the inside probe while still unconfined
                std::fs::write(&inside, b"probe").unwrap();
                // verdict rides the exit code: bit0 = applied, bit1 =
                // kernel denies writes outside, bit2 = kernel allows
                // writes inside, bit3 = second apply reports Nested
                let applied = u8::from(restrict_allow_default(&policy).is_ok());
                let outside_denied = u8::from(denies("file-write-data", &outside));
                let inside_allowed = u8::from(!denies("file-write-data", &inside));
                let nested = u8::from(matches!(
                    restrict_allow_default(&policy),
                    Err(Error::Nested)
                ));
                _exit(i32::from(
                    applied | (outside_denied << 1) | (inside_allowed << 2) | (nested << 3),
                ));
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
            assert_eq!(
                code,
                0b1111,
                "allow-default verdict bits (code {code}): applied={} \
                 outside_denied={} inside_allowed={} nested={}",
                code & 1,
                (code >> 1) & 1,
                (code >> 2) & 1,
                (code >> 3) & 1
            );
            assert!(!outside.exists());
        }
    }

    /// The macOS nesting wall, typed (the kernel's answer, matched on
    /// the error): the FIRST `restrict_self` applies, the SECOND
    /// reports `Error::Nested` — the named refusal, never an opaque
    /// `sandbox_init` failure. The wall is what makes the kapi kubelet's
    /// parent confinement YIELD to its children's on macOS.
    #[test]
    #[allow(clippy::unwrap_used)]
    #[cfg(target_os = "macos")]
    fn restrict_self_twice_reports_nested() {
        unsafe extern "C" {
            fn fork() -> i32;
            fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
            fn _exit(code: i32) -> !;
        }
        let dir = tempfile::tempdir().unwrap();
        let policy = Policy::write_confined(dir.path());
        unsafe {
            let pid = fork();
            assert!(pid >= 0, "fork failed");
            if pid == 0 {
                // verdict rides the exit code: bit0 = first apply ok,
                // bit1 = the second apply reports Nested
                let applied = u8::from(policy.restrict_self().is_ok());
                let nested = u8::from(matches!(policy.restrict_self(), Err(Error::Nested)));
                _exit(i32::from(applied | (nested << 1)));
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
            assert_eq!(
                code,
                0b11,
                "nested verdict bits (code {code}): applied={} nested={}",
                code & 1,
                (code >> 1) & 1
            );
        }
    }

    /// The launcher road stores the typed `Error` as the inner error of
    /// the `io::Error` the `pre_exec` closure returns, so a launcher
    /// failure can be inspected with `downcast_ref::<Error>()` instead
    /// of matching an opaque string.
    #[test]
    fn nested_error_survives_io_error_wrapping() {
        let wrapped = std::io::Error::other(Error::Nested);
        assert!(
            wrapped
                .get_ref()
                .and_then(|r| r.downcast_ref::<Error>())
                .is_some_and(|e| matches!(e, Error::Nested)),
            "the typed error must survive io::Error::other on the pre_exec road"
        );
    }

    /// A pre-generated profile can be reused to launch children: the
    /// hoisting path skips per-child path canonicalization.
    #[test]
    #[allow(clippy::unwrap_used)]
    #[cfg(target_os = "macos")]
    fn install_profile_launches_a_confined_child() {
        let dir = tempfile::tempdir().unwrap();
        let policy = Policy::write_confined(dir.path());
        let profile = seatbelt_profile(&policy);
        let mut cmd = std::process::Command::new("sh");
        cmd.arg("-c").arg("true");
        install_profile(&mut cmd, &profile).unwrap();
        assert!(cmd.status().unwrap().success());
    }

    /// An uncreatable write root is dropped rather than kept as a bogus
    /// grant: a path whose parent is a regular file cannot exist as a
    /// directory, so `create_dir_all` fails and the canonicalized policy
    /// carries no grant for it. (The profile generator stays pure and
    /// takes the raw policy as-is — the fail-closed drop happens at the
    /// enforcement paths that call `canonicalize`, i.e. `exec`/`restrict_self`.)
    #[test]
    #[allow(clippy::unwrap_used)]
    fn uncreatable_write_root_is_not_granted() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("a-file");
        std::fs::write(&file, b"x").unwrap();
        let child = file.join("cannot-be-created");
        let policy = Policy::write_confined(&child);
        let canonical = canonicalize(&policy);
        assert!(
            !canonical.write_allow.iter().any(|p| p == &child),
            "a path that cannot be created must not become a write grant: {:?}",
            canonical.write_allow
        );
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn profile_contains_root() {
        let p = Policy::write_confined("/tmp/boxes/c-demo");
        let prof = seatbelt_profile(&p);
        assert!(prof.contains("(deny file-write*)"));
        assert!(prof.contains("(allow default)"));
    }

    #[test]
    #[allow(clippy::unwrap_used)] // tests: panics are the failure mode
    fn exec_builds_a_confined_command() {
        let dir = tempfile::tempdir().unwrap();
        let policy = Policy::write_confined(dir.path());
        let cmd = policy.exec("echo", &["ok"]).unwrap();
        assert_eq!(cmd.get_program().to_string_lossy(), "echo");
        assert_eq!(cmd.get_args().count(), 1);
    }

    /// The linux-only privilege test lives in the linux module's tests
    /// (cfg-gated there); the fork proof below is the cross-platform
    /// `restrict_self` guarantee.
    #[test]
    #[allow(clippy::unwrap_used)] // tests: panics are the failure mode
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn restrict_self_confines_the_current_process() {
        unsafe extern "C" {
            fn fork() -> i32;
            fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
            fn _exit(code: i32) -> !;
        }
        let dir = tempfile::tempdir().unwrap();
        let policy = {
            let mut p = Policy::write_confined(dir.path());
            // temp/dev writes are granted by default — the proof needs a
            // path OUTSIDE every grant
            p.allow_temp = TempAccess::Denied;
            p.allow_dev = DevAccess::Denied;
            p
        };
        let inside = dir.path().join("ok.txt");
        let outside = dir.path().parent().unwrap().join("seatlock-deny-probe.txt");

        unsafe {
            let pid = fork();
            assert!(pid >= 0, "fork failed");
            if pid == 0 {
                // the verdict rides the exit code: bit0 = applied, bit1 =
                // writes inside the grant still work, bit2 = writes
                // outside refused
                let applied = u8::from(policy.restrict_self().is_ok());
                let inside_ok = u8::from(
                    std::fs::write(&inside, "in").is_ok()
                        && std::fs::write(&inside, "still in").is_ok(),
                );
                let outside_denied = u8::from(std::fs::write(&outside, "out").is_err());
                _exit(i32::from(
                    applied | (inside_ok << 1) | (outside_denied << 2),
                ));
            }
            let mut status = 0;
            // retry EINTR — the child may land before we wait
            let waited = loop {
                let w = waitpid(pid, std::ptr::addr_of_mut!(status), 0);
                if w != -1 || std::io::Error::last_os_error().raw_os_error() != Some(4) {
                    break w;
                }
            };
            let err = std::io::Error::last_os_error();
            assert_eq!(waited, pid, "errno: {err}");
            let code = (status >> 8) & 0xff;
            // 0b111: applied AND inside-writes work AND outside-writes denied
            assert_eq!(
                code,
                0b111,
                "restrict_self verdict bits (code {code}): applied={} \
                 inside_ok={} outside_denied={}",
                code & 1,
                (code >> 1) & 1,
                (code >> 2) & 1
            );
            assert_eq!(std::fs::read_to_string(&inside).unwrap(), "still in");
            assert!(!outside.exists());
        }
    }
}
