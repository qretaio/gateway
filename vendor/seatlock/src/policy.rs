//! The policy IS the configuration: `Policy` (+ `NetworkPolicy`) is the
//! minimal, portable description of a sandbox — write roots, read rules,
//! network ports, scopes, capability drops. Under the `serde` feature it
//! derives Serialize/Deserialize, so a configuration can ride a queue or
//! a spec file. seatlock has no consumer concepts: what a write root
//! means, which paths deserve denying, is the caller's vocabulary.

use std::path::PathBuf;

/// Whether network access is permitted at all. `Disabled` denies every
/// socket (tcp + udp, bind + connect) on both platforms. `Enabled` (the
/// default) keeps the network open — this matches the posture of
/// `Policy::write_confined`/`Policy::default` so programmatic and
/// deserialized policies agree on the default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum NetworkMode {
    Disabled,
    #[default]
    Enabled,
}

/// Whether writes under the system temp dir are granted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum TempAccess {
    Denied,
    #[default]
    Granted,
}

/// Whether writes under /dev are granted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum DevAccess {
    Denied,
    #[default]
    Granted,
}

/// Whether exec-time privilege gain is prevented (`NO_NEW_PRIVS`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum PrivilegeGain {
    #[default]
    Allowed,
    Prevented,
}

/// Whether a Landlock scope (signals / abstract unix sockets) is enforced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum ScopeMode {
    #[default]
    Disabled,
    Enabled,
}

/// Whether denied operations are logged on exec (Landlock).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum ExecLogging {
    #[default]
    Off,
    On,
}

/// Network policy. A port list that is `Some` is an ALLOW-LIST: the
/// daemon-side handling of that access type denies everything else on it.
/// `mode = Disabled` denies ALL network (tcp + udp, both platforms).
/// The master switch is an enum rather than a bool, so its meaning is
/// self-describing in serialized form.
#[derive(Debug, Clone, Default)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(default, deny_unknown_fields)
)]
pub struct NetworkPolicy {
    /// TCP ports allowed to bind (server). `None` => unrestricted.
    /// Duplicates are ignored (an allow-list is a set).
    pub tcp_bind: Option<Vec<u16>>,
    /// TCP ports allowed to connect to (client). `None` => unrestricted.
    /// Duplicates are ignored (an allow-list is a set).
    pub tcp_connect: Option<Vec<u16>>,
    /// UDP ports allowed to bind. `None` => unrestricted.
    /// Duplicates are ignored (an allow-list is a set).
    pub udp_bind: Option<Vec<u16>>,
    /// UDP ports allowed to connect/send to. `None` => unrestricted.
    /// Duplicates are ignored (an allow-list is a set).
    pub udp_connect: Option<Vec<u16>>,
    /// Master switch: `Disabled` denies all network, ports included.
    pub mode: NetworkMode,
}

/// Deny by default is THE posture: what is not granted does not exist.
/// Reads need a grant (or the explicit world-read opt-in
/// [`Policy::read_allow_all`]), writes need [`Policy::write_allow`],
/// network needs [`NetworkPolicy::mode`]/port rules; on Linux the read
/// right also narrows EXECUTE to granted trees.
#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(default, deny_unknown_fields)
)]
pub struct Policy {
    /// Paths granted read+write. A missing root is CREATED at apply time:
    /// Landlock pins rules to inodes, so a missing root would silently
    /// carry no write rule (writes INSIDE the grant denied).
    pub write_allow: Vec<PathBuf>,
    /// Paths granted read-only. World-read is the grant `"/"` — a policy
    /// whose `read_allow` carries no `"/"` is NARROWED: only the listed
    /// trees (plus the platform read essentials on macOS — see the README
    /// caveat on darwin >= 27 dyld) are readable, everything else is no
    /// access. A grant on a nonexistent path is no access (deny-by-default
    /// fails closed).
    pub read_allow: Vec<PathBuf>,
    pub network: NetworkPolicy,
    /// Scope: deny opening abstract Unix sockets outside the domain
    /// (landlock only — SBPL has no domain concept; ignored on macOS).
    pub scope_abstract_unix_socket: ScopeMode,
    /// Scope: deny sending signals outside the domain (landlock only;
    /// ignored on macOS).
    pub scope_signal: ScopeMode,
    /// Log denied operations on exec (landlock).
    pub force_log: ExecLogging,
    /// Capabilities dropped from the thread's BOUNDING set before exec
    /// (linux only — macOS has no capability sets). Kernel names without
    /// the `cap_` prefix (`net_raw`, `dac_override`, …), or `all` for the
    /// whole set. Dropping requires `CAP_SETPCAP`; a refusal is an ERROR,
    /// never a silent no-op — a policy that cannot be enforced must not
    /// pretend.
    pub drop_capabilities: Vec<String>,
    /// Capabilities spared from a broad drop: the effective drop set is
    /// `drop_capabilities` minus these (`all` minus `net_bind_service`
    /// sheds everything but the low-port bind). Linux only.
    pub keep_capabilities: Vec<String>,
    /// `NO_NEW_PRIVS` before exec: exec-time privilege gain becomes
    /// impossible (setuid binaries stay powerless; Landlock requires it
    /// anyway). Linux only.
    pub no_new_privs: PrivilegeGain,
    /// Writes granted under the system temp dir.
    pub allow_temp: TempAccess,
    /// Writes granted under /dev.
    pub allow_dev: DevAccess,
}

impl Default for Policy {
    /// The serde default posture (a partial policy file fills the rest
    /// from this): writes confined to the current directory, world-read,
    /// network open. Prefer the presets — `write_confined`/`hardened` —
    /// in code.
    fn default() -> Self {
        Self::write_confined(".")
    }
}

impl Policy {
    /// The baseline preset: writes confined to `root` (+ temp, + /dev),
    /// world-read, network open. The piebox worker shape.
    pub fn write_confined(root: impl Into<PathBuf>) -> Self {
        Self {
            write_allow: vec![root.into()],
            read_allow: vec![PathBuf::from("/")],
            network: NetworkPolicy {
                mode: NetworkMode::Enabled,
                ..NetworkPolicy::default()
            },
            scope_abstract_unix_socket: ScopeMode::Disabled,
            scope_signal: ScopeMode::Disabled,
            force_log: ExecLogging::Off,
            drop_capabilities: Vec::new(),
            keep_capabilities: Vec::new(),
            no_new_privs: PrivilegeGain::Allowed,
            allow_temp: TempAccess::Granted,
            allow_dev: DevAccess::Granted,
        }
    }

    /// The advanced preset: `write_confined` PLUS `NO_NEW_PRIVS`, the
    /// ENTIRE capability set dropped from the bounding set (linux), and
    /// both landlock scopes applied — no privilege gain, no cross-domain
    /// signaling or socket peeking. Network stays open: tighten with
    /// [`Policy::with_network`] or port lists. On Linux the capability
    /// drops REQUIRE `CAP_SETPCAP` — with one honest exception: an
    /// UNPRIVILEGED process (empty permitted set) that sets NNP has
    /// nothing to drop and no way to gain any (the goal state is
    /// verified, not assumed); anything else fails loudly — a policy
    /// that cannot be enforced must not silently downgrade.
    #[must_use]
    pub fn hardened(root: impl Into<PathBuf>) -> Self {
        let mut p = Self::write_confined(root);
        p.no_new_privs = PrivilegeGain::Prevented;
        p.drop_capabilities = vec!["all".to_string()];
        p.scope_abstract_unix_socket = ScopeMode::Enabled;
        p.scope_signal = ScopeMode::Enabled;
        p
    }

    /// Replace the network policy.
    #[must_use]
    pub fn with_network(mut self, network: NetworkPolicy) -> Self {
        self.network = network;
        self
    }

    /// Convenience: deny all network.
    #[must_use]
    pub fn with_network_disabled(mut self) -> Self {
        self.network.mode = NetworkMode::Disabled;
        self
    }

    /// Capabilities dropped from the bounding set (`"all"` for the whole
    /// set; kernel names without the `cap_` prefix). Linux only.
    #[must_use]
    pub fn with_capability_drops(mut self, names: Vec<String>) -> Self {
        self.drop_capabilities = names;
        self
    }

    /// Capabilities spared from a broad drop (see `keep_capabilities`).
    #[must_use]
    pub fn with_capability_keeps(mut self, names: Vec<String>) -> Self {
        self.keep_capabilities = names;
        self
    }

    #[must_use]
    pub fn with_no_new_privs(mut self, v: PrivilegeGain) -> Self {
        self.no_new_privs = v;
        self
    }

    #[must_use]
    pub fn with_signal_scope(mut self, v: ScopeMode) -> Self {
        self.scope_signal = v;
        self
    }

    #[must_use]
    pub fn with_unix_socket_scope(mut self, v: ScopeMode) -> Self {
        self.scope_abstract_unix_socket = v;
        self
    }

    #[must_use]
    pub fn with_temp(mut self, v: TempAccess) -> Self {
        self.allow_temp = v;
        self
    }

    #[must_use]
    pub fn with_dev(mut self, v: DevAccess) -> Self {
        self.allow_dev = v;
        self
    }
}

// enums are already pub at module root; nothing to re-export.

#[cfg(test)]
mod tests {
    use super::*;

    /// The network default must agree across all three paths: the type
    /// default, the write-confined preset, and the policy default. A
    /// mismatch makes a partially deserialized policy open a different
    /// posture than the same policy built in code.
    #[test]
    fn network_defaults_agree_across_paths() {
        assert_eq!(NetworkPolicy::default().mode, NetworkMode::Enabled);
        assert_eq!(
            Policy::write_confined("/tmp/w").network.mode,
            NetworkMode::Enabled
        );
        assert_eq!(Policy::default().network.mode, NetworkMode::Enabled);
    }
}
