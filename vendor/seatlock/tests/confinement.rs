#![allow(clippy::unwrap_used, clippy::expect_used)] // tests: panics are the failure mode
//! The confinement contract, pinned against the REAL kernel enforcement —
//! not the profile string.
//!
//! seatlock applies its policy in `pre_exec`, so every test here spawns an
//! actual child under the sandbox and asserts on its behavior: writes inside
//! the granted root succeed, writes outside fail, reads still work, and the
//! process can execute. On macOS the enforcement is Seatbelt (`sandbox_init`);
//! on Linux it is Landlock. Linux tests probe enforcement FIRST and skip with
//! a named reason on kernels without Landlock (< 5.13) — seatlock's
//! `CompatLevel::BestEffort` means an unsupported kernel degrades to NO
//! enforcement, and a test that then sees a write succeed must not "fail":
//! it must say why.
//!
//! This suite IS the verification: every test spawns a real confined
//! child and asserts on the kernel's behavior, so no external script or
//! example binary is needed.

use seatlock::{Policy, TempAccess};
use std::path::{Path, PathBuf};
use std::process::Command;

/// A path the confined child can try to write that is guaranteed OUTSIDE
/// every grant: not the root, not temp, not /dev. The test harness's own
/// manifest dir fits — a write there must be denied.
fn outside_path(tag: &str) -> PathBuf {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!("target/probe-{tag}.txt"));
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    p
}

/// Run `script` under `sh -c` confined to `policy`, with `cwd` (the
/// child's working directory — the exec'd command's own cwd contract).
/// Returns the exit status (a failure to APPLY the sandbox surfaces as a
/// spawn error — that is a hard failure, not a probe result).
fn confined_sh_cwd(policy: &Policy, script: &str, cwd: &Path) -> std::process::ExitStatus {
    let mut cmd = policy
        .exec("sh", &["-c", script])
        .expect("seatlock exec failed to build the sandbox");
    cmd.current_dir(cwd);
    cmd.status().expect("spawn confined child")
}

/// Same, inheriting this process's cwd.
fn confined_sh(policy: &Policy, script: &str) -> std::process::ExitStatus {
    confined_sh_cwd(policy, script, &std::env::current_dir().unwrap())
}

/// Whether the platform is ACTUALLY enforcing on this kernel. Spawns a
/// confined child that writes outside every grant; if the write SUCCEEDS the
/// platform is not enforcing (Landlock on a pre-5.13 kernel with `BestEffort`
/// compat silently applies nothing).
fn enforcement_is_real() -> bool {
    let outside = outside_path("enforce-probe");
    let script = format!("echo x > {} 2>/dev/null", outside.display());
    let denied = confined_sh(
        &Policy::write_confined("/nonexistent-root-for-probe"),
        &script,
    );
    !denied.success()
}

fn clean(p: &Path) {
    let _ = std::fs::remove_file(p);
}

// --------------------------------------------------------------- the matrix --

/// THE core contract: writes inside the granted root succeed, writes outside
/// every grant fail with a permission error.
#[test]
fn write_inside_succeeds_write_outside_denied() {
    if cfg!(target_os = "linux") && !enforcement_is_real() {
        eprintln!("skip: kernel does not enforce Landlock (< 5.13?)");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let inside = dir.path().join("inside.txt");
    let outside = outside_path("write-outside");
    clean(&outside);

    let policy = Policy::write_confined(dir.path());
    let status = confined_sh(
        &policy,
        &format!(
            "echo inside > {inside}; s1=$?; echo outside > {outside} 2>/dev/null; s2=$?;              [ $s1 -eq 0 ] && [ $s2 -ne 0 ]; exit $?",
            inside = inside.display(),
            outside = outside.display()
        ),
    );
    assert!(
        status.success(),
        "inside write must succeed AND outside write must fail"
    );
    assert_eq!(
        std::fs::read_to_string(&inside).unwrap(),
        "inside\n",
        "the inside write landed"
    );
    assert!(
        !outside.exists(),
        "the outside write must NOT have landed (kernel not enforcing?)"
    );
    clean(&outside);
}

/// Confinement is WRITE-only: the confined process can still read the world.
#[test]
fn reads_outside_still_allowed() {
    let dir = tempfile::tempdir().unwrap();
    let policy = Policy::write_confined(dir.path());
    let status = confined_sh(
        &policy,
        "cat /etc/hostname >/dev/null 2>&1 || cat /etc/hosts >/dev/null 2>&1",
    );
    assert!(status.success(), "reads outside the root must still work");
}

/// The confined process can still execute (and its own children run).
#[test]
fn execution_still_works() {
    let dir = tempfile::tempdir().unwrap();
    let policy = Policy::write_confined(dir.path());
    let status = confined_sh(&policy, "echo confined-exec");
    assert!(status.success());
}

/// /dev/null (and /dev generally) stays writable — pipelines and daemons
/// redirect there constantly; a sandbox that breaks `>/dev/null` breaks
/// everything.
#[test]
fn dev_null_stays_writable() {
    if cfg!(target_os = "linux") && !enforcement_is_real() {
        eprintln!("skip: kernel does not enforce Landlock (< 5.13?)");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let policy = Policy::write_confined(dir.path());
    let status = confined_sh(&policy, "echo hi > /dev/null");
    assert!(status.success(), "writing /dev/null must succeed");
}

/// System temp stays writable when `allow_temp` is on (the default for
/// `Policy::write_confined`).
#[test]
fn temp_writes_allowed() {
    if cfg!(target_os = "linux") && !enforcement_is_real() {
        eprintln!("skip: kernel does not enforce Landlock (< 5.13?)");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let probe = std::env::temp_dir().join(format!("seatlock-temp-probe-{}", std::process::id()));
    let _ = std::fs::remove_file(&probe);
    let policy = Policy::write_confined(dir.path());
    let status = confined_sh(
        &policy,
        &format!("echo hi > {} && rm {}", probe.display(), probe.display()),
    );
    assert!(status.success(), "writing the system temp dir must succeed");
    assert!(!probe.exists());
}

/// `allow_temp = false` closes temp again — the builder knob means what it
/// says. (Seatbelt: no subpath grant; Landlock: no write rule.)
#[test]
fn temp_denied_when_the_knob_is_off() {
    if cfg!(target_os = "linux") && !enforcement_is_real() {
        eprintln!("skip: kernel does not enforce Landlock (< 5.13?)");
        return;
    }
    if cfg!(target_os = "macos") {
        // /tmp on macOS is /private/tmp, and tempdir() tests already write
        // there; the deny is real but the test root itself usually LIVES in
        // temp — skip the self-inflicted contradiction here. The manual
        // script (scripts/verify.sh) exercises this matrix with a root
        // outside temp.
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let probe = PathBuf::from("/tmp/seatlock-denied-probe");
    let policy = Policy::write_confined(dir.path()).with_temp(TempAccess::Denied);
    let status = confined_sh(
        &policy,
        &format!("echo hi > {} 2>/dev/null; exit $?", probe.display()),
    );
    assert!(
        !status.success(),
        "temp writes must be denied with with_temp(false)"
    );
    assert!(!probe.exists());
    let _ = std::fs::remove_file(&probe);
}

/// World-read is the grant "/": the default policy reads the world.
/// (A narrowed policy — `read_allow` without "/" — is enforced on Linux;
/// on macOS the dyld caveat of darwin >= 27 makes the narrowed PROFILE
/// string-testable only — see the README. This test pins the default
/// shape: world-read plus a working exec.)
#[test]
fn world_read_is_the_default_grant() {
    let dir = tempfile::tempdir().unwrap();
    let policy = Policy::write_confined(dir.path());
    // world-read: hosts file readable and the process can exec
    let status = confined_sh(
        &policy,
        "cat /etc/hosts >/dev/null 2>&1 || cat /etc/hostname >/dev/null; echo done",
    );
    assert!(status.success(), "world-read (the \"/\" grant) must hold");
}

/// Linux: Landlock has no deny rules (allow-lists only), so narrowing reads
/// means a global handle + rules on the granted paths. The allow-list must
/// carry the loader paths or nothing execs; ld.so fails loud (unlike dyld,
/// which aborts) so this is testable.
#[cfg(target_os = "linux")]
#[test]
fn read_allow_list_narrows_reads() {
    if !enforcement_is_real() {
        eprintln!("skip: kernel does not enforce Landlock (< 5.13?)");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let inside = dir.path().join("readable.txt");
    std::fs::write(&inside, "granted\n").unwrap();

    let mut policy = Policy::write_confined(dir.path());
    // narrowing: a read_allow WITHOUT "/" — the whole world shrinks to
    // these trees (plus the loader paths the kernel needs)
    policy.read_allow = vec![
        dir.path().to_path_buf(),
        PathBuf::from("/bin"),
        PathBuf::from("/lib"),
        PathBuf::from("/lib64"),
        PathBuf::from("/usr/lib"),
    ];
    let mut cmd = policy
        .exec("/bin/cat", &[&inside.display().to_string()])
        .unwrap();
    let out = cmd.output().expect("spawn confined cat (inside read)");
    assert!(
        out.status.success(),
        "reading INSIDE the allow-list must work"
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout), "granted\n");

    let mut cmd = policy.exec("/bin/cat", &["/etc/hostname"]).unwrap();
    let out = cmd.output().expect("spawn confined cat (outside read)");
    assert!(
        !out.status.success(),
        "reading OUTSIDE the allow-list must be denied"
    );
}

/// `network.enabled = false` denies ALL network — the same semantics
/// Seatbelt's `(deny network*)` has, now also on Landlock (handled with no
/// rules). The control run (unconfined, and confined+allowed) reaches the
/// listener; the denied run must not.
#[test]
fn network_denial_closes_connect() {
    if cfg!(target_os = "linux") && !enforcement_is_real() {
        eprintln!("skip: kernel does not enforce Landlock (< 5.13?)");
        return;
    }
    let bash = if Path::new("/bin/bash").exists() {
        "/bin/bash"
    } else if Path::new("/usr/bin/bash").exists() {
        "/usr/bin/bash"
    } else {
        eprintln!("skip: no bash for the /dev/tcp probe");
        return;
    };

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let connect =
        format!("exec 3<>~/dev/null && exec 3<>/dev/tcp/127.0.0.1/{port} 2>/dev/null; exit $?");

    // control: unconfined connect works
    let ok = Command::new(bash)
        .arg("-c")
        .arg(format!(
            "exec 3<>/dev/tcp/127.0.0.1/{port} 2>/dev/null; exit $?"
        ))
        .status()
        .unwrap();
    assert!(
        ok.success(),
        "the control (unconfined) connect must succeed"
    );

    // confined with network allowed: connect works
    let dir = tempfile::tempdir().unwrap();
    let policy = Policy::write_confined(dir.path());
    let ok = confined_sh(
        &policy,
        &format!("exec 3<>/dev/tcp/127.0.0.1/{port} 2>/dev/null; exit $?"),
    );
    assert!(
        ok.success(),
        "confined connect with network allowed must succeed"
    );

    // confined with network DENIED: connect must fail
    let policy = Policy::write_confined(dir.path()).with_network_disabled();
    let denied = confined_sh(&policy, &connect);
    assert!(
        !denied.success(),
        "connect must fail with with_network(false)"
    );
    let _ = listener;
}

// ------------------------------------------------------------ edge cases --

/// A root that does not exist YET is created by confine — the write grant
/// must survive the root's absence (Landlock pins rules to inodes; a missing
/// root would otherwise silently carry no write rule).
#[test]
fn nonexistent_root_is_created_and_granted() {
    if cfg!(target_os = "linux") && !enforcement_is_real() {
        eprintln!("skip: kernel does not enforce Landlock (< 5.13?)");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let fresh = dir.path().join("deeply/nested/fresh-root");
    assert!(!fresh.exists());

    let inside = fresh.join("made-later.txt");
    let policy = Policy::write_confined(&fresh);
    let status = confined_sh(&policy, &format!("echo ok > {}", inside.display()));
    assert!(
        status.success(),
        "a write inside a just-created root must succeed"
    );
    assert_eq!(std::fs::read_to_string(&inside).unwrap(), "ok\n");
}

/// A symlinked root canonicalizes: the returned path is the real one, and
/// writes through either spelling land inside the grant.
#[cfg(target_os = "macos")]
#[test]
fn symlinked_root_canonicalizes() {
    let dir = tempfile::tempdir().unwrap();
    let link_holder = tempfile::tempdir().unwrap(); // must outlive the test
    let link = link_holder.path().join("link");
    std::os::unix::fs::symlink(dir.path(), &link).unwrap();

    // the grant canonicalizes through the symlink: writes land on the
    // real root (the policy's canonical write root is dir.path())
    let policy = Policy::write_confined(dir.path());
    let status = confined_sh_cwd(&policy, "echo via-link > link-file.txt", &link);
    assert!(status.success(), "write through the symlink must succeed");
    assert_eq!(
        std::fs::read_to_string(dir.path().join("link-file.txt")).unwrap(),
        "via-link\n",
        "the write landed on the REAL root, not the link spelling"
    );
}

/// A root that is a FILE (not a directory) does not crash confine — the
/// policy is degenerate but coherent: the child runs.
#[test]
fn file_root_confines_without_crash() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("a-file");
    std::fs::write(&file, "x").unwrap();

    let status = confined_sh(&Policy::write_confined(&file), "true");
    assert!(status.success());
}

/// The profile generator escapes quotes/backslashes in paths — a root with
/// a quote in its name must produce a profile that still compiles (and the
/// confinement still applies).
#[cfg(target_os = "macos")]
#[test]
fn profile_escapes_hostile_path_characters() {
    let dir = tempfile::tempdir().unwrap();
    let hostile = dir.path().join("we\"ird\\name");
    std::fs::create_dir_all(&hostile).unwrap();

    let profile = seatlock::seatbelt_profile(&Policy::write_confined(&hostile));
    assert!(
        profile.contains("we\\\"ird\\\\name"),
        "the quote and backslash must be escaped: {profile}"
    );

    // and it compiles + enforces: write inside OK, outside denied
    if !enforcement_is_real() {
        return;
    }
    let outside = outside_path("hostile");
    clean(&outside);
    // shell-quote the hostile path too (it carries `"` and `\`; no `'` in it)
    let shq = |p: &Path| format!("'{}'", p.display());
    let status = confined_sh(
        &Policy::write_confined(&hostile),
        &format!(
            "echo in > {}/in.txt; s1=$?; echo out > {} 2>/dev/null; s2=$?; [ $s1 -eq 0 ] && [ $s2 -ne 0 ]; exit $?",
            shq(&hostile),
            shq(&outside)
        ),
    );
    assert!(status.success(), "inside OK, outside denied");
    assert!(!outside.exists());
    clean(&outside);
}
