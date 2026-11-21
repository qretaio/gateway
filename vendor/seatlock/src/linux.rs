//! Linux enforcement: Landlock (upstream main, ABI 10 — tcp + udp port
//! rules, scopes) plus the capability story (bounding-set drops via the
//! `caps` crate, `NO_NEW_PRIVS` via prctl). Deny by default: the ruleset
//! handles read+write and rules ONLY the grants — the read right carries
//! execute, so ungranted trees cannot be executed either.

use super::error::Error;
use super::policy::{ExecLogging, NetworkMode, Policy, PrivilegeGain, ScopeMode};
use std::os::unix::process::CommandExt;

/// In-process application: privilege drops first (nothing after the call
/// can re-raise), then the Landlock ruleset restricts the current thread
/// — and every thread via `TSYNC` where the kernel supports it.
///
/// # Errors
/// Fails when the privilege drop or the ruleset cannot be installed.
pub fn apply(policy: &Policy) -> Result<(), Error> {
    drop_privileges(policy)?;
    lockdown(policy).map_err(|e| Error::Landlock(e.to_string()))
}

/// Launcher application: the whole policy (privileges + ruleset)
/// installs in the child's `pre_exec` — confined from its first
/// instruction. Failures surface at `spawn` as the command's error.
#[allow(clippy::unnecessary_wraps)]
pub fn install(command: &mut std::process::Command, policy: &Policy) -> Result<(), Error> {
    let policy = policy.clone();
    unsafe {
        command.pre_exec(move || {
            run_policy(&policy).map_err(|e| std::io::Error::other(e.to_string()))
        });
    }
    Ok(())
}

/// The full child-side sequence: privilege drops, then the ruleset.
fn run_policy(policy: &Policy) -> Result<(), Box<dyn std::error::Error>> {
    drop_privileges(policy)?;
    lockdown(policy)
}

fn drop_privileges(policy: &Policy) -> Result<(), Error> {
    if policy.no_new_privs == PrivilegeGain::Prevented {
        set_no_new_privs()?;
    }
    let drops = parse_capabilities(&policy.drop_capabilities, &policy.keep_capabilities)?;
    if drops.is_empty() {
        return Ok(());
    }
    for cap in drops {
        if caps::drop(None, caps::CapSet::Bounding, cap).is_err() {
            // EPERM without CAP_SETPCAP is acceptable ONLY when the goal
            // state already holds: the process holds no permitted
            // capabilities, and NNP (set above) bars the exec-time paths
            // (setuid) that could gain any — verified, not assumed.
            let permitted = caps::read(None, caps::CapSet::Permitted).unwrap_or_default();
            if !permitted.is_empty() || policy.no_new_privs != PrivilegeGain::Prevented {
                return Err(Error::Landlock(format!(
                    "capability drop failed: {} (hold CAP_SETPCAP, or enable \
                     no_new_privs and run with no capabilities)",
                    {
                        let e: Box<dyn std::error::Error> = std::io::Error::last_os_error().into();
                        e
                    }
                )));
            }
        }
    }
    Ok(())
}

fn set_no_new_privs() -> Result<(), Error> {
    // PR_SET_NO_NEW_PRIVS = 38; a libc dependency is not worth one prctl
    const PR_SET_NO_NEW_PRIVS: libc::c_int = 38;
    let rc = unsafe { libc::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

/// Parse a policy capability name into the kernel's — `all` expands to
/// every capability the platform knows. `keep` names are subtracted from
/// the result (a broad `"all"` drop can spare the ones the process
/// genuinely needs). Unknown names are an ERROR, never a silent skip.
fn parse_capabilities(names: &[String], keep: &[String]) -> Result<Vec<caps::Capability>, Error> {
    let mut keeps = Vec::new();
    for name in keep {
        keeps.push(
            name.parse::<caps::Capability>()
                .map_err(|_| Error::Landlock(format!("unknown capability '{name}'")))?,
        );
    }
    let mut out: Vec<caps::Capability> = Vec::new();
    for name in names {
        if name == "all" {
            for c in caps::all() {
                if !keeps.contains(&c) && !out.contains(&c) {
                    out.push(c);
                }
            }
            continue;
        }
        let cap = name
            .parse::<caps::Capability>()
            .map_err(|_| Error::Landlock(format!("unknown capability '{name}'")))?;
        if !keeps.contains(&cap) && !out.contains(&cap) {
            out.push(cap);
        }
    }
    Ok(out)
}

fn lockdown(policy: &Policy) -> Result<(), Box<dyn std::error::Error>> {
    use landlock::{
        ABI, AccessFs, AccessNet, CompatLevel, Compatible, NetPort, PathBeneath, PathFd, Ruleset,
        RulesetAttr, RulesetCreatedAttr, Scope,
    };
    let abi = ABI::V10;
    let mut ruleset = Ruleset::default();

    // port rules to add once the ruleset is created (landlock wants them
    // added after `create`)
    let mut ports: Vec<(AccessNet, u16)> = Vec::new();

    // filesystem, deny by default: handle read + write and rule ONLY the
    // grants — an empty grant set denies all writes, and the read right
    // carries execute, so ungranted trees cannot be executed either.
    let mut fs_access = AccessFs::from_read(abi);
    fs_access |= AccessFs::from_write(abi);
    ruleset = ruleset.handle_access(fs_access)?;

    // network. Three shapes, mirroring Seatbelt:
    //   Disabled: deny ALL (handle all four types, no rules)
    //   Enabled with any port list ("ported"): deny-all base, then
    //     allow only the named ports — an unlisted access type is denied
    //     entirely (handle it with no rules), matching Seatbelt's
    //     `(deny network*)` + per-port allows
    //   Enabled with no port lists: unrestricted (handle nothing)
    if policy.network.mode == NetworkMode::Disabled {
        ruleset = ruleset.handle_access(AccessNet::BindTcp)?;
        ruleset = ruleset.handle_access(AccessNet::ConnectTcp)?;
        ruleset = ruleset.handle_access(AccessNet::BindUdp)?;
        ruleset = ruleset.handle_access(AccessNet::ConnectSendUdp)?;
    } else {
        let ported = policy.network.tcp_bind.is_some()
            || policy.network.tcp_connect.is_some()
            || policy.network.udp_bind.is_some()
            || policy.network.udp_connect.is_some();
        if ported {
            ruleset = ruleset.handle_access(AccessNet::BindTcp)?;
            ruleset = ruleset.handle_access(AccessNet::ConnectTcp)?;
            ruleset = ruleset.handle_access(AccessNet::BindUdp)?;
            ruleset = ruleset.handle_access(AccessNet::ConnectSendUdp)?;
            let collect = |ports: &Option<Vec<u16>>, sink: &mut Vec<(AccessNet, u16)>, access| {
                if let Some(list) = ports {
                    for &port in list {
                        sink.push((access, port));
                    }
                }
            };
            collect(&policy.network.tcp_bind, &mut ports, AccessNet::BindTcp);
            collect(
                &policy.network.tcp_connect,
                &mut ports,
                AccessNet::ConnectTcp,
            );
            collect(&policy.network.udp_bind, &mut ports, AccessNet::BindUdp);
            collect(
                &policy.network.udp_connect,
                &mut ports,
                AccessNet::ConnectSendUdp,
            );
        }
    }

    // scopes
    if policy.scope_abstract_unix_socket == ScopeMode::Enabled {
        ruleset = ruleset.scope(Scope::AbstractUnixSocket)?;
    }
    if policy.scope_signal == ScopeMode::Enabled {
        ruleset = ruleset.scope(Scope::Signal)?;
    }

    let mut created = ruleset.create()?;

    // read grants (deny-by-default: a nonexistent grant path is NO access
    // — fails closed, per the field's contract; the world-read grant is
    // simply "/")
    for p in &policy.read_allow {
        if let Ok(fd) = PathFd::new(p) {
            created = created.add_rule(PathBeneath::new(fd, AccessFs::from_read(abi)))?;
        }
    }
    // write grants
    let write_access = AccessFs::from_write(abi);
    for p in &policy.write_allow {
        if let Ok(fd) = PathFd::new(p) {
            created = created.add_rule(PathBeneath::new(fd, write_access))?;
        }
    }

    // network port rules (only meaningful when the network is allowed at
    // all — handled-but-ruleless access types above deny everything).
    // dedupe: an allow-list is a set, not a multiset. AccessNet is a
    // bitflag without Ord, so the sort keys on the port alone — same
    // (access, port) pairs still land adjacent, which is all dedup needs
    if policy.network.mode == NetworkMode::Enabled {
        let mut ports = ports;
        ports.sort_by_key(|(_, port)| *port);
        ports.dedup();
        for (access, port) in ports {
            created = created.add_rule(NetPort::new(port, access))?;
        }
    }

    created
        .set_compatibility(CompatLevel::BestEffort)
        .log_new_exec(policy.force_log == ExecLogging::On)?
        .restrict_self()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{Policy, PrivilegeGain};

    /// The whole privilege story, proven against the real kernel: the
    /// confined child asserts its OWN state — `NO_NEW_PRIVS` set, both
    /// dropped caps gone from the bounding set — and the drop survives
    /// exec (the whole point). Cap-drop verification needs `capsh`; if
    /// it is absent the test still asserts NNP and skips only that part.
    #[test]
    #[allow(clippy::unwrap_used)] // tests: panics are the failure mode
    fn no_new_privs_and_capability_drops_take_effect() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let mut p = Policy::write_confined(dir.path());
        p.no_new_privs = PrivilegeGain::Prevented;
        p.drop_capabilities = vec!["net_raw".into(), "sys_admin".into()];
        let mut cmd = p
            .exec(
                "sh",
                &[
                    "-c",
                    "grep -q 'NoNewPrivs:[[:space:]]*1' /proc/self/status || exit 10\n\
                     command -v capsh >/dev/null 2>&1 || exit 0\n\
                     bnd=$(awk '/CapBnd/{print $2}' /proc/self/status)\n\
                     capsh --decode=$bnd | grep -qE 'cap_net_raw|cap_sys_admin' && exit 11 || exit 0",
                ],
            )
            .unwrap();
        // NOTE: this test runs UNPRIVILEGED in CI — the drops fail with
        // EPERM and the permitted-set-empty path must carry them (the
        // goal state already holds). A privileged run exercises the real
        // drops; both must pass. `capsh` may be absent (slim CI images);
        // in that case the child exits 0 after verifying NNP.
        let out = cmd.output().unwrap();
        let err = String::from_utf8_lossy(&out.stderr).to_string();
        let mut stderr = std::io::stderr();
        let _ = stderr.write_all(out.stderr.as_slice());
        assert!(
            out.status.success(),
            "nnp/capdrop child failed with {:?}; {err}",
            out.status.code()
        );
        // apply() in-process would confine THIS test process (every
        // other test would inherit it); the exec path above proves the
        // same policy end to end.
    }
}

#[cfg(test)]
mod hardened_tests {
    use super::super::policy::Policy;

    /// An unprivileged process (every CI runner) can still take the
    /// hardened preset: the drops EPERM, the permitted set is verified
    /// empty, and NNP is set — the goal state holds, so `apply()` succeeds.
    #[test]
    #[allow(clippy::unwrap_used)] // tests: panics are the failure mode
    fn hardened_works_unprivileged() {
        let dir = tempfile::tempdir().unwrap();
        let p = Policy::hardened(dir.path());
        // in-process would confine this test process; prove via exec
        let mut cmd = p
            .exec(
                "sh",
                &["-c", "grep -q 'NoNewPrivs:[[:space:]]*1' /proc/self/status"],
            )
            .unwrap();
        assert!(cmd.status().unwrap().success());
    }
}
