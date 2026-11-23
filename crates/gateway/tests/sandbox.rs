//! The confinement derivation law (kapi.spec EDGE-FR-015): the policy is
//! DERIVED from the config — every port the gateway already talks to
//! names itself in the connect grant, the listen port names itself in
//! the bind grant, writes grant nowhere, and the extra_connect knob is
//! the only hand-named addition.

use gateway::config::{
    CachePushConfig, DefaultsConfig, DrainConfig, GatewayConfig, KapiConfig, ListenConfig,
    RollConfig, SandboxConfig,
};

fn config() -> GatewayConfig {
    GatewayConfig {
        listen: ListenConfig {
            addr: "0.0.0.0:8787".to_owned(),
        },
        tls: None,
        kapi: Some(KapiConfig {
            url: "http://127.0.0.1:8643".to_owned(),
        }),
        nodes: [
            ("node-a".to_owned(), "127.0.0.1:8789".to_owned()),
            ("backup-node".to_owned(), "10.0.0.7:9001".to_owned()),
        ]
        .into_iter()
        .collect(),
        defaults: DefaultsConfig {
            node: Some("node-a".to_owned()),
        },
        drain: DrainConfig {
            timeout_secs: Some(2),
        },
        registry: Default::default(),
        cache_push: Some(CachePushConfig {
            token: "push-secret".to_owned(),
        }),
        sandbox: SandboxConfig {
            enabled: true,
            extra_connect: vec![9901],
            extra_read: Vec::new(),
        },
        roll: RollConfig { converge_secs: 30 },
        deploy: None,
        waf: Default::default(),
        ratelimit: Default::default(),
        verified_bots: Default::default(),
        pow: Default::default(),
        hardening: Default::default(),
    }
}

/// The connect grant is the DERIVED set: kapi, every node (the
/// default's own lookup included), DNS, TLS, plus extra_connect.
#[test]
fn the_connect_grant_names_every_port_the_config_talks_to() {
    let policy = gateway::sandbox::policy(&config());
    let connect = policy.network.tcp_connect.clone().expect("an allow-list");
    for port in [8643, 8789, 9001, 53, 443, 9901] {
        assert!(
            connect.contains(&port),
            "port {port} rides the derived grant: {connect:?}"
        );
    }
    assert_eq!(
        connect.len(),
        6,
        "no grant beyond the derived set: {connect:?}"
    );
}

/// A kubelet child's Landlock domain intersects the gateway's: a node
/// that re-execs itself (the off-process compiler) needs its launch
/// binary granted here too. [gateway.sandbox] extra_read is the knob.
#[cfg(not(target_os = "macos"))]
#[test]
fn extra_read_grants_a_child_reexec_target() {
    let mut cfg = config();
    cfg.sandbox.extra_read = vec!["/usr/local/bin/wisolate".to_owned()];
    let policy = gateway::sandbox::policy(&cfg);
    assert!(
        policy
            .read_allow
            .iter()
            .any(|p| p == std::path::Path::new("/usr/local/bin/wisolate")),
        "the node's launch binary is granted through the gateway's domain"
    );
    let base = gateway::sandbox::policy(&config());
    assert!(
        !base
            .read_allow
            .iter()
            .any(|p| p == std::path::Path::new("/usr/local/bin/wisolate")),
        "without the knob the grant is absent (deny by default)"
    );
}

/// The bind grant is the listener's own port.
#[test]
fn the_bind_grant_is_the_listen_port() {
    let policy = gateway::sandbox::policy(&config());
    assert_eq!(
        policy.network.tcp_bind.as_deref(),
        Some(&[8787u16][..]),
        "the listen port binds"
    );
}

/// Deny by default: writes grant nowhere; temp and /dev stay denied;
/// the capability set drops whole; no privilege gains.
#[test]
fn the_gateway_writes_nothing_and_gains_nothing() {
    let policy = gateway::sandbox::policy(&config());
    assert!(
        policy.write_allow.is_empty(),
        "the gateway is stateless: no write grants"
    );
    assert_eq!(policy.drop_capabilities, ["all".to_owned()]);
    assert_eq!(policy.no_new_privs, seatlock::PrivilegeGain::Prevented);
    assert_eq!(policy.allow_temp, seatlock::TempAccess::Denied);
    assert_eq!(policy.allow_dev, seatlock::DevAccess::Denied);
}

/// The UDP posture: binds denied outright, connects DNS-only (the
/// ABI-6 kernel degrades them BestEffort — DEC-008 — but the LAW is
/// named regardless).
#[test]
fn udp_is_denied_except_dns() {
    let policy = gateway::sandbox::policy(&config());
    assert_eq!(policy.network.udp_bind.as_deref(), Some(&[][..]));
    assert_eq!(policy.network.udp_connect.as_deref(), Some(&[53u16][..]));
}

/// macOS keeps world-read (the dyld caveat, FR-015); Linux narrows.
#[cfg(target_os = "macos")]
#[test]
fn macos_reads_stay_world() {
    let policy = gateway::sandbox::policy(&config());
    assert!(
        policy
            .read_allow
            .iter()
            .any(|p| p == std::path::Path::new("/")),
        "darwin 27+ aborts on narrowed boot reads: world-read stays"
    );
}

/// The macOS nesting wall (FR-010's child-confinement law): the gateway
/// process always composes the kubelet, so on macOS its own face
/// confinement YIELDS to the children's seatlocks (Seatbelt cannot
/// nest — the child's is the sandbox that must be enabled); on Linux
/// Landlock nests and both apply.
#[test]
fn the_face_yields_to_the_children_on_macos() {
    assert_eq!(
        gateway::sandbox::parent_confines(),
        !cfg!(target_os = "macos"),
        "the gateway face yields on macOS, confines on Linux"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn linux_reads_narrow_to_resolver_and_loader() {
    let policy = gateway::sandbox::policy(&config());
    for p in ["/etc/resolv.conf", "/lib", "/usr/lib"] {
        assert!(
            policy
                .read_allow
                .iter()
                .any(|g| g == std::path::Path::new(p)),
            "{p} rides the narrowed read set: {:?}",
            policy.read_allow
        );
    }
    assert!(
        !policy
            .read_allow
            .iter()
            .any(|p| p == std::path::Path::new("/")),
        "narrowed means narrowed"
    );
}
