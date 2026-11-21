//! The Seatbelt (SBPL) profile generator — pure, testable: the exact
//! profile the macOS enforcement installs, inspectable without running.

use crate::policy::Policy;
use std::path::Path;

fn dedup_ports(v: Option<&Vec<u16>>) -> Vec<u16> {
    let mut out = v.cloned().unwrap_or_default();
    out.sort_unstable();
    out.dedup();
    out
}

#[must_use]
pub fn seatbelt_profile(policy: &Policy) -> String {
    let quote = |path: &Path| {
        std::fs::canonicalize(path)
            .unwrap_or_else(|_| path.to_path_buf())
            .display()
            .to_string()
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
    };
    let mut lines = vec!["(version 1)".to_string(), "(allow default)".to_string()];

    // READ: denied unless granted. A narrowed policy (read_allow without
    // "/") injects the platform read essentials — the loader's boot path
    // must read, and darwin >= 27 aborts dyld on a denied boot-path read
    // even with the loader dirs granted (see the README caveat: on macOS
    // keep world-read and narrow by config instead of a global read-deny).
    let narrowed = !policy.read_allow.iter().any(|p| p == Path::new("/"));
    if narrowed {
        lines.push("(deny file-read*)".to_string());
        let read_essentials = ["/usr", "/System", "/bin", "/sbin", "/dev", "/Library"];
        for essential in read_essentials {
            lines.push(format!("(allow file-read* (subpath \"{essential}\"))"));
        }
        for p in &policy.read_allow {
            lines.push(format!("(allow file-read* (subpath \"{}\"))", quote(p)));
        }
    }
    // WRITES: denied everywhere except the grants.
    lines.push("(deny file-write*)".to_string());
    lines.push("(allow file-write*".to_string());
    for p in &policy.write_allow {
        lines.push(format!("    (subpath \"{}\")", quote(p)));
    }
    if policy.allow_temp == crate::policy::TempAccess::Granted {
        let tmp = quote(&std::env::temp_dir());
        lines.push(format!("    (subpath \"{tmp}\")"));
        lines.push("    (subpath \"/private/tmp\")".to_string());
        lines.push("    (subpath \"/tmp\")".to_string());
    }
    if policy.allow_dev == crate::policy::DevAccess::Granted {
        lines.push("    (literal \"/dev/null\")".to_string());
        lines.push("    (subpath \"/dev\")".to_string());
    }
    lines.push(")".to_string());

    // NETWORK: three shapes, mirroring landlock exactly —
    //   ports configured: deny all, then allow JUST the named ports
    //   allow, no port lists: unrestricted (nothing emitted)
    //   deny-all, no port lists: `(deny network*)`
    // BIND rules predicate on the LOCAL address (a bind names the local
    // endpoint); CONNECT rules predicate on the REMOTE one.
    if policy.network.mode == crate::policy::NetworkMode::Disabled {
        lines.push("(deny network*)".to_string());
    } else {
        let ported = policy.network.tcp_bind.is_some()
            || policy.network.tcp_connect.is_some()
            || policy.network.udp_bind.is_some()
            || policy.network.udp_connect.is_some();
        if ported {
            lines.push("(deny network*)".to_string());
            for p in dedup_ports(policy.network.tcp_bind.as_ref()) {
                lines.push(format!("(allow network-bind (local ip \"*:{p}\"))"));
            }
            // SBPL speaks host:port — the HOST first, the port last
            // ("host must be * or localhost"); the port in the host
            // position fails the whole profile at sandbox_init.
            for p in dedup_ports(policy.network.tcp_connect.as_ref()) {
                lines.push(format!("(allow network-outbound (remote tcp \"*:{p}\"))"));
            }
            for p in dedup_ports(policy.network.udp_bind.as_ref()) {
                lines.push(format!("(allow network-bind (local ip \"*:{p}\"))"));
            }
            for p in dedup_ports(policy.network.udp_connect.as_ref()) {
                lines.push(format!("(allow network-outbound (remote udp \"*:{p}\"))"));
            }
        }
    }
    lines.join("\n")
}

#[cfg(test)]
mod seatbelt_tests {
    use super::seatbelt_profile;
    use crate::policy::{
        DevAccess, ExecLogging, NetworkMode, NetworkPolicy, Policy, PrivilegeGain, ScopeMode,
        TempAccess,
    };

    fn ported() -> Policy {
        Policy {
            write_allow: vec![],
            read_allow: vec![],
            network: NetworkPolicy {
                mode: NetworkMode::Enabled,
                tcp_bind: Some(vec![8080]),
                tcp_connect: Some(vec![53, 443]),
                udp_bind: Some(vec![]),
                udp_connect: Some(vec![53]),
            },
            scope_abstract_unix_socket: ScopeMode::Enabled,
            scope_signal: ScopeMode::Enabled,
            force_log: ExecLogging::Off,
            drop_capabilities: vec!["all".to_owned()],
            keep_capabilities: vec![],
            no_new_privs: PrivilegeGain::Prevented,
            allow_temp: TempAccess::Denied,
            allow_dev: DevAccess::Denied,
        }
    }

    /// SBPL speaks host:port — the port rides LAST. A port in the host
    /// position ("53:*") fails the whole profile at `sandbox_init` with
    /// "host must be * or localhost", and every ported spawn EINVALs:
    /// the kubelet's macOS children were the first consumer of the
    /// ported shape (the bind rules were always right; only the remote
    /// rules carried the defect).
    #[test]
    #[allow(clippy::unwrap_used)]
    fn the_remote_rules_name_the_port_last() {
        let prof = seatbelt_profile(&ported());
        for want in [
            "(allow network-outbound (remote tcp \"*:53\"))",
            "(allow network-outbound (remote tcp \"*:443\"))",
            "(allow network-outbound (remote udp \"*:53\"))",
            "(allow network-bind (local ip \"*:8080\"))",
        ] {
            assert!(prof.contains(want), "missing {want} in:\n{prof}");
        }
        assert!(
            !prof.contains(":*\""),
            "the port never rides in the host position:\n{prof}"
        );
    }
}
