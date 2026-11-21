//! An AGENT SESSION without any VM: the hardened policy directly on the
//! host, running a simulated coding-agent workload. This is the "no VM
//! backend, just seatlock" story — the sandbox is the policy, the agent
//! is an ordinary process, and everything the agent touches outside its
//! grants is refused by the kernel.
//!
//! The simulated agent is a shell script doing what coding agents do:
//! scaffold a workspace, write/edit/delete files, read the project and
//! its own config, run build steps that litter temp — and the hostile
//! extras every sandbox must refuse: escaping the workspace, tunneling
//! through symlinks, dropping artifacts into the repo that runs it.

#![allow(clippy::unwrap_used, clippy::expect_used)] // tests: panics are the failure mode

use seatlock::{Policy, TempAccess};
use std::path::Path;

/// A probe path OUTSIDE every grant: the crate's own target dir (not the
/// workspace, not temp, not /dev).
fn outside(tag: &str) -> String {
    let p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(format!("target/agent-probe-{tag}.txt"));
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    let _ = std::fs::remove_file(&p);
    p.display().to_string()
}

/// The agent sandbox: hardened policy over a workspace. THE shape every
/// host-side agent runner should use.
fn agent_sandbox(workspace: &Path) -> Policy {
    Policy::hardened(workspace)
}

/// Landlock's `BestEffort` degrades silently on old kernels — probe first
/// so a "denied" write succeeding there is a skip, not a false failure.
fn enforcement_is_real() -> bool {
    if !cfg!(target_os = "linux") {
        return true;
    }
    let dir = tempfile::tempdir().unwrap();
    let outside = outside("enforce");
    let mut cmd = Policy::write_confined(dir.path())
        .with_temp(TempAccess::Denied)
        .exec("sh", &["-c", &format!("echo x > {outside} 2>/dev/null")])
        .unwrap();
    !cmd.status().unwrap().success()
}

/// Run the agent script with the workspace as its cwd — an agent is
/// launched IN its workspace; relative writes land in the grant.
fn run(policy: &Policy, workspace: &Path, script: &str) -> (bool, String) {
    let mut cmd = policy.exec("sh", &["-c", script]).unwrap();
    cmd.current_dir(workspace);
    let out = cmd.output().unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

/// The happy path: a full agent session inside the workspace — scaffold,
/// write, edit, delete, nested dirs, a build step that litters temp —
/// all succeeds, and the workspace holds exactly what the agent made.
#[test]
fn an_agent_session_inside_the_workspace_succeeds() {
    let ws = tempfile::tempdir().unwrap();
    let policy = agent_sandbox(ws.path());
    let script = "
        set -e
        mkdir -p src/tests
        printf 'fn main() {}\\n' > src/main.rs
        printf 'mod t;\\n' >> src/main.rs
        printf '# project\\n' > README.md
        echo edit >> README.md
        sed -i.bak '/mod t/d' src/main.rs 2>/dev/null || sed -i '/mod t/d' src/main.rs
        rm README.md.bak 2>/dev/null || true
        echo 'build litter' > /tmp/build-litter
        rm /tmp/build-litter
        cat src/main.rs > /dev/null
        test -f src/main.rs && ! test -f README.md.bak
    ";
    let (ok, err) = run(&policy, ws.path(), script);
    assert!(ok, "the agent session must succeed: {err}");
    assert!(ws.path().join("src/main.rs").exists());
    assert!(ws.path().join("src/tests").is_dir());
}

/// The hostile path: every escape an agent might attempt — directly,
/// through a symlink tunnel, into the repo that RUNS the sandbox, into
/// the operator's dotfiles, into /bin — all refused, and the workspace
/// stays intact.
#[test]
fn every_escape_an_agent_might_try_is_refused() {
    if !enforcement_is_real() {
        eprintln!("skip: kernel does not enforce Landlock");
        return;
    }
    let ws = tempfile::tempdir().unwrap();
    let policy = agent_sandbox(ws.path());
    let runner = outside("runner-repo"); // where THIS test crate lives
    let ssh_probe = format!("{}/.ssh/agent-wrote", std::env::var("HOME").unwrap());
    let bin_probe = "/usr/local/agent-bin-probe".to_string(); // /usr is read-only in the seat
    let _ = std::fs::remove_file(&ssh_probe);

    // one confined session, four attempts, each failing — the script
    // asserts the refusal of every one of them
    let script = format!(
        "
        set -e
        echo legit > legit.txt
        # 1. direct escape into the runner repo
        echo x > {runner} 2>/dev/null && exit 10
        # 2. symlink tunnel out of the workspace
        ln -s {home} tunnel && echo x > tunnel/agent-wrote 2>/dev/null && exit 11
        # 3. the operator's dotfiles are not writable
        echo x > {ssh_probe} 2>/dev/null && exit 12
        # 4. /bin (and the system) are not writable
        echo x > {bin_probe} 2>/dev/null && exit 13
        test -f legit.txt
        ",
        runner = runner,
        home = std::env::var("HOME").unwrap(),
        ssh_probe = ssh_probe,
        bin_probe = bin_probe,
    );
    let (ok, err) = run(&policy, ws.path(), &script);
    assert!(ok, "every escape must be refused: {err}");
    assert!(!Path::new(&runner).exists(), "the runner repo was written");
    assert!(!Path::new(&ssh_probe).exists(), "~/.ssh was written");
    assert!(!Path::new(&bin_probe).exists(), "the system write landed");
    assert!(
        ws.path().join("legit.txt").exists(),
        "the legit write still worked"
    );
    let _ = std::fs::remove_file(&ssh_probe);
}

/// Network is the agent's choice at sandbox-build time: deny-all closes
/// every socket (the exfiltration story), while the default keeps the
/// agent's fetches working.
#[test]
fn the_network_story_is_the_operators_choice() {
    if !enforcement_is_real() {
        eprintln!("skip: kernel does not enforce Landlock");
        return;
    }
    let bash = if Path::new("/bin/bash").exists() {
        "/bin/bash"
    } else {
        "/usr/bin/bash"
    };
    let ws = tempfile::tempdir().unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    // default: the agent can reach out (fetches, package registries)
    let open = agent_sandbox(ws.path());
    let mut cmd = open
        .exec(
            bash,
            &[
                "-c",
                &format!("exec 3<>/dev/tcp/127.0.0.1/{port} 2>/dev/null; exit $?"),
            ],
        )
        .unwrap();
    assert!(
        cmd.status().unwrap().success(),
        "the default keeps fetches working"
    );

    // deny-all: an agent that must not phone home cannot
    let closed = agent_sandbox(ws.path()).with_network_disabled();
    let mut cmd = closed
        .exec(
            bash,
            &[
                "-c",
                &format!("exec 3<>/dev/tcp/127.0.0.1/{port} 2>/dev/null; exit $?"),
            ],
        )
        .unwrap();
    assert!(
        !cmd.status().unwrap().success(),
        "deny-all closes the exfil socket"
    );
    drop(listener);
}

/// The hardened extras are IN the session: `NO_NEW_PRIVS` rides every
/// exec the agent makes (Linux), so a planted setuid binary gains
/// nothing.
#[cfg(target_os = "linux")]
#[test]
fn planted_privilege_escalation_gains_nothing() {
    if !enforcement_is_real() {
        eprintln!("skip: kernel does not enforce Landlock");
        return;
    }
    let ws = tempfile::tempdir().unwrap();
    let policy = agent_sandbox(ws.path());
    let status = {
        let mut cmd = policy
            .exec(
                "sh",
                &["-c", "grep -q 'NoNewPrivs:[[:space:]]*1' /proc/self/status"],
            )
            .unwrap();
        cmd.status().unwrap()
    };
    assert!(
        status.success(),
        "NNP rides the session: a planted setuid binary gains nothing"
    );
}
