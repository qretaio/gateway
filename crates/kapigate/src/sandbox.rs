//! The gateway's self-confinement (kapi.spec EDGE-FR-015): a seatlock policy
//! derived FROM the config — the grants are exactly what the gateway
//! already does, so a listener/kapi/node change re-derives them.
//! Deny by default: writes granted nowhere (the gateway is stateless:
//! the cache and the asset trees live in memory), reads narrowed to
//! the resolver + loader essentials (Linux; macOS keeps world-read —
//! the platform's dyld caveat makes narrowed boot reads unusable),
//! network allow-listed to the ports the config already names, the
//! capability set dropped, no privilege gains, both Landlock scopes on.
//!
//! Applied via `restrict_self` AFTER the config loads and BEFORE the
//! runtime builds its threads (a thread spawned pre-policy stays
//! ambient forever) and before anything binds — an open fd is access
//! the policy cannot revoke.

use std::collections::BTreeSet;
use std::net::SocketAddr;

use seatlock::{
    DevAccess, ExecLogging, NetworkMode, NetworkPolicy, Policy, PrivilegeGain, ScopeMode,
    TempAccess,
};

/// The port of a `host:port` string (the config's addresses are all
/// that shape); `None` for anything else (the grant is skipped — an
/// unparseable endpoint would otherwise grant nothing sensible).
/// The port of an `addr` or URL string; `None` grants nothing.
pub fn port_of(addr: &str) -> Option<u16> {
    if let Ok(socket) = addr.parse::<SocketAddr>() {
        return Some(socket.port());
    }
    // host:port without the scheme — rsplit the last colon.
    addr.rsplit_once(':').and_then(|(_, p)| p.parse().ok())
}

/// The policy for THIS config (FR-015: derived, never hand-listed).
/// `macos_world_read` is compile-time (the dyld caveat), the rest is
/// pure derivation.
#[must_use]
pub fn policy(config: &crate::config::GatewayConfig) -> Policy {
    // connect grants: the kapi coordinator, every configured node,
    // DNS + TLS for the asset pulls, and any gateway-backend ports the
    // rows may name ([sandbox] extra_connect).
    let mut connect: BTreeSet<u16> = BTreeSet::from([53, 443]);
    if let Some(kapi) = &config.kapi
        && let Some(p) = port_of(
            kapi.url
                .trim_start_matches("http://")
                .trim_start_matches("https://"),
        )
    {
        connect.insert(p);
    }
    for addr in config.nodes.values() {
        if let Some(p) = port_of(addr) {
            connect.insert(p);
        }
    }
    if let Some(default_node) = &config.defaults.node
        && let Some(addr) = config.nodes.get(default_node)
        && let Some(p) = port_of(addr)
    {
        connect.insert(p);
    }
    for p in &config.sandbox.extra_connect {
        connect.insert(*p);
    }

    let bind = port_of(&config.listen.addr);

    #[cfg(target_os = "macos")]
    let read_allow = vec![std::path::PathBuf::from("/")];
    #[cfg(not(target_os = "macos"))]
    let mut read_allow = vec![
        std::path::PathBuf::from("/etc/resolv.conf"),
        std::path::PathBuf::from("/etc/hosts"),
        std::path::PathBuf::from("/etc/nsswitch.conf"),
        std::path::PathBuf::from("/etc/gai.conf"),
        std::path::PathBuf::from("/lib"),
        std::path::PathBuf::from("/lib64"),
        std::path::PathBuf::from("/usr/lib"),
    ];
    // A kubelet child's Landlock domain INTERSECTS this one. The node
    // re-execs its own binary for the off-process component compiler;
    // without a grant here that exec is EACCES even though the child's
    // own policy reads "/". The operator declares the extra paths in
    // [gateway.sandbox] (e.g. wisolate's launch binary).
    #[cfg(not(target_os = "macos"))]
    read_allow.extend(
        config
            .sandbox
            .extra_read
            .iter()
            .map(std::path::PathBuf::from),
    );

    Policy {
        // The gateway writes NOTHING: cache and assets are in-memory
        // (FR-014's honest cold start), and the addr/state files the
        // node keeps do not exist here.
        write_allow: vec![],
        read_allow,
        network: NetworkPolicy {
            mode: NetworkMode::Enabled,
            tcp_bind: Some(bind.into_iter().collect()),
            tcp_connect: Some(connect.into_iter().collect()),
            // UDP bind denied outright (Some(empty) = allow-list with
            // no entries); UDP connect: DNS only. On kernels below the
            // UDP ABI these degrade BestEffort (DEC-008) — DNS keeps
            // working, just unenforced.
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

/// Whether the gateway's own face confinement applies at all — the
/// macOS nesting wall (FR-010's child-confinement law): this process
/// ALWAYS composes the kubelet (the spawn arm is part of the gateway),
/// and macOS cannot install a Seatbelt profile inside a sandboxed
/// process — a confined gateway would kill every child's profile
/// install at the door, and the CHILD's seatlock is the one that must
/// be enabled. So on macOS the face confinement yields to the
/// children's; on Linux Landlock nests and both apply.
#[must_use]
pub fn parent_confines() -> bool {
    !cfg!(target_os = "macos")
}

/// Apply the confinement. A refusal is FATAL: a policy that cannot be
/// enforced must not pretend (the seatlock law) — the unit restarts
/// and the operator sees the reason. On macOS the face confinement
/// YIELDS to the kubelet's children (loudly, never silently).
pub fn apply(config: &crate::config::GatewayConfig) {
    if !parent_confines() {
        eprintln!(
            "gateway: the face sandbox YIELDS on macOS — Seatbelt cannot nest, and this \
             process's kubelet spawns children that must wear their own seatlocks \
             (FR-010's child-confinement law wins); the gateway face runs unconfined"
        );
        return;
    }
    let policy = policy(config);
    if let Err(e) = policy.restrict_self() {
        eprintln!("gateway: sandbox apply failed: {e}");
        std::process::exit(1);
    }
    eprintln!("gateway: confined (writes none, reads narrowed, ports derived from config)");
}
