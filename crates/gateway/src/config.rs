//! The gateway's config (TOML): listeners, the kapi coordinator, the node
//! address map, the cache-push credential. What the config carries, the
//! gateway does; what kapi carries, the watch applies. No route
//! configuration lives here (kapi.spec DEC-002) — the table is kapi's.

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct GatewayConfig {
    /// The plain HTTP listener for everything the gateway serves
    /// (`[listen] addr`; TLS rides `[tls]` when present).
    #[serde(default, rename = "listen")]
    pub listen: ListenConfig,
    /// Optional TLS termination (`[tls]`): cert + key PEM paths, its own
    /// listen address. Absent = plain HTTP only (dev).
    #[serde(default)]
    pub tls: Option<TlsConfig>,
    /// The kapi coordinator (`[kapi] url`) — the route table's source
    /// of truth (kapi.spec EDGE-FR-002). OPTIONAL: the embedded arm
    /// (`kapi server --config` with `[gateway]`) injects the
    /// in-process server's URL and needs no section; the standalone
    /// `kapi gateway` subcommand refuses a config without one.
    #[serde(default)]
    pub kapi: Option<KapiConfig>,
    /// The node address map (`[nodes]`): node name -> serving address
    /// (`host:port` of the node's private listener). The override and
    /// the fallback for nodes whose kapi row names no address yet (the
    /// kubelet's row stamps the kapi URL in `spec.endpoint` today).
    #[serde(default)]
    pub nodes: std::collections::BTreeMap<String, String>,
    /// The default node (`[defaults] node`): the address a route with
    /// no Running pod takes (scale-to-zero — no pods to name a node).
    #[serde(default)]
    pub defaults: DefaultsConfig,
    /// The drain posture (`[drain] timeout_secs`): the shutdown
    /// barrier's budget for in-flight requests. Absent = wait forever
    /// (graceful-handover's default law); `Some(n)` forces the outcome
    /// after n seconds, naming the units still live.
    #[serde(default)]
    pub drain: DrainConfig,
    /// The registry bearer tokens (`[registry.<host>]`): the gateway
    /// pulls app artifacts (the asset store) with a per-host token;
    /// a host absent from the map pulls unauthenticated (loopback).
    #[serde(default)]
    pub registry: std::collections::BTreeMap<String, String>,
    /// The cache-push bearer (`[cache_push] token`): the only caller
    /// allowed to put cache entries (the node, over the private
    /// network). Absent = the face refuses every put.
    #[serde(default)]
    pub cache_push: Option<CachePushConfig>,
    /// The roll posture (`[roll] converge_secs`): the boot's budget for
    /// the seed LIST and the predecessor handshake. A boot that cannot
    /// converge inside it aborts fail-closed — nothing bound, the
    /// predecessor keeps serving (kapi.spec EDGE-FR-010/FR-013).
    #[serde(default)]
    pub roll: RollConfig,
    /// The CRI deploy arm (`[deploy.cri]`, EDGE-FR-017): when present,
    /// the gateway drives Deployment rows through a CRI engine (CRI-O
    /// with crun) instead of only local child processes. The config is
    /// native — paths to CRI-O's own drop-ins and a RuntimeClass YAML
    /// directory on the node, never a kapi-specific dialect.
    #[serde(default)]
    pub deploy: Option<DeployConfig>,
    /// The self-confinement posture (`[sandbox] enabled`, kapi.spec
    /// FR-015): apply a seatlock policy via `restrict_self` after the
    /// config loads — deny by default, the grants derived from the
    /// config itself. Defaults OFF (the dev loop unrestricted).
    #[serde(default)]
    pub sandbox: SandboxConfig,
}

/// The deploy arm's CRI configuration (`[deploy.cri]`).
#[derive(Debug, Clone, Deserialize, Default)]
pub struct DeployConfig {
    /// The CRI block: the node's native runtime config + RuntimeClass
    /// files, and the node name the workloads bind to.
    #[serde(default)]
    pub cri: Option<CriConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CriConfig {
    /// CRI-O's drop-in directory (default `/etc/crio/crio.conf.d`).
    #[serde(default = "default_crio_conf_dir")]
    pub conf_dir: std::path::PathBuf,
    /// RuntimeClass manifest directory (default `/etc/kapi/runtimeclasses`).
    #[serde(default = "default_runtime_class_dir")]
    pub runtime_class_dir: std::path::PathBuf,
    /// The node identity the deployed workloads bind to.
    #[serde(default = "default_cri_node")]
    pub node_name: String,
}

fn default_crio_conf_dir() -> std::path::PathBuf {
    std::path::PathBuf::from("/etc/crio/crio.conf.d")
}
fn default_runtime_class_dir() -> std::path::PathBuf {
    std::path::PathBuf::from("/etc/kapi/runtimeclasses")
}
fn default_cri_node() -> String {
    "kapi-node".to_owned()
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct SandboxConfig {
    /// Apply the confinement at boot.
    #[serde(default)]
    pub enabled: bool,
    /// tcp connect ports gateway-backend rows may name beyond the
    /// derived set (kapi, nodes, 443, 53).
    #[serde(default)]
    pub extra_connect: Vec<u16>,
    /// Extra read/execute grants for the gateway's own Landlock domain.
    /// Landlock domains INTERSECT down the process tree: a kubelet child
    /// (e.g. the wisolate node) can only exec binaries the gateway may
    /// also execute. The node re-execs itself for its off-process
    /// component compiler, so its launch binary needs a grant here.
    #[serde(default)]
    pub extra_read: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RollConfig {
    /// Seconds the boot may take to converge before it aborts.
    #[serde(default = "default_roll_budget")]
    pub converge_secs: u64,
}

fn default_roll_budget() -> u64 {
    30
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ListenConfig {
    #[serde(default = "default_listen_addr")]
    pub addr: String,
}

fn default_listen_addr() -> String {
    "0.0.0.0:8080".to_owned()
}

#[derive(Debug, Clone, Deserialize)]
pub struct TlsConfig {
    pub cert: String,
    pub key: String,
    #[serde(default = "default_tls_listen")]
    pub listen: String,
}

fn default_tls_listen() -> String {
    "0.0.0.0:8443".to_owned()
}

#[derive(Debug, Clone, Deserialize)]
pub struct KapiConfig {
    pub url: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct DrainConfig {
    /// Seconds to wait the in-flight requests out before forcing.
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct DefaultsConfig {
    /// The node NAME a pod-less route serves through.
    #[serde(default)]
    pub node: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CachePushConfig {
    pub token: String,
}

fn section_enabled() -> bool {
    true
}

/// The `[gateway]` section of kapi.toml: the enabled flag beside the
/// gateway's own posture — the section's fields nest exactly as the
/// standalone config file carried them (listen, nodes, defaults, ...).
/// Presence reads as intent: `enabled` defaults true.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct GatewaySection {
    #[serde(default = "section_enabled")]
    pub enabled: bool,
    #[serde(flatten)]
    pub config: GatewayConfig,
}

impl GatewayConfig {
    pub fn load(path: &str) -> Result<Self, String> {
        let raw = std::fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
        toml::from_str(&raw).map_err(|e| format!("parse {path}: {e}"))
    }

    /// The serving address for a node name: the config map first, then
    /// the node row's own stamp (`status.addresses`, the k8s shape the
    /// kubelet may carry later), else `None` (the route 503s).
    pub fn node_addr(&self, node: &str, row_addresses: Option<&[String]>) -> Option<String> {
        if let Some(addr) = self.nodes.get(node) {
            return Some(addr.clone());
        }
        row_addresses.and_then(|list| list.first().cloned())
    }

    /// The network grants this config's posture needs, derived (the
    /// kapi.spec EDGE-FR-015 law: the policy is derived, never
    /// hand-listed): the listen port in the bind set; every node-map
    /// port, TLS 443 and the config's `extra_connect` in the connect
    /// set. The embedded arm (`kapi server --with-gateway`) folds these
    /// into kapi's own policy; the standalone subcommand applies them
    /// through this crate's sandbox.
    #[must_use]
    pub fn network_grants(&self) -> (Vec<u16>, Vec<u16>) {
        let mut binds = Vec::new();
        if let Some(port) = crate::sandbox::port_of(&self.listen.addr) {
            binds.push(port);
        }
        if let Some(tls) = &self.tls
            && let Some(port) = crate::sandbox::port_of(&tls.listen)
        {
            binds.push(port);
        }
        let mut connects: std::collections::BTreeSet<u16> = std::collections::BTreeSet::new();
        for addr in self.nodes.values() {
            if let Some(port) = crate::sandbox::port_of(addr) {
                connects.insert(port);
            }
        }
        connects.insert(443);
        connects.extend(self.sandbox.extra_connect.iter().copied());
        (binds, connects.into_iter().collect())
    }
}
