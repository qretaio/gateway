//! The route table: the gateway's view of what the fleet serves, rebuilt
//! from the kapi watch (kapi.spec EDGE-FR-002) and consulted per request
//! (FR-001's matcher, gateway-core). The delta application is a pure
//! function — the informer feeds rows in, the table answers
//! (host, path) -> node. No route configuration of the gateway's own
//! (kapi.spec DEC-002).
//!
//! THE LIVE ROUTE INDEX (owner directives 2026-11-16: "venndb as the
//! live index built from the delta updates from the watch api" +
//! "it is even better if we can directly filter based on target url
//! since we support path based routing like k8s gateways"): the keyed
//! maps stay the delta truth, and every route-family delta rebuilds the
//! vennDB index derived from them — one row per pattern, the folded
//! host AND the pattern's path prefix as the filter columns. `resolve`
//! queries the index with the target url — exact host, path-prefix
//! predicate (`path_where`, the matcher's `starts_with` law) — so the
//! candidate set that leaves the index is already the set of MATCHING
//! patterns, and the unchanged law finishes it (FR-001's
//! `route_specificity` for the longest-prefix rank, ties to the lowest
//! (org, app)). The index is derived from the deltas and from nothing
//! else, so DEC-002 still holds — it has no configuration surface of
//! its own. The pod binding and the node stamps keep their keyed-map
//! laws (a pod phase flip mutates one row's identity — the append-only
//! index shape would turn every pod delta into a rebuild for a lookup a
//! BTreeMap already answers in one step).

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

use kapigate_core::routes::route_specificity;
use venndb::VennDB;

/// One route row in the live index: one PATTERN (an app may carry
/// several). The query columns are the matcher's own pattern-side fold
/// ([`pattern_host`] + [`pattern_path`], the `route_specificity` split
/// mirrored exactly and pinned by the equivalence tests below): the ci
/// law folds the pattern side at build time, the request side arrives
/// folded from the serving entry.
#[derive(Debug, Clone, VennDB)]
struct RouteRow {
    #[venndb(filter)]
    host: String,
    /// The pattern's path prefix after the `*` trim — the `path_where`
    /// predicate's input (the request path `starts_with` this).
    #[venndb(filter)]
    path: String,
    #[venndb(filter)]
    org: String,
    #[venndb(filter)]
    app: String,
    /// The raw pattern — the specificity law's input.
    #[venndb(skip)]
    pattern: String,
}

/// The matcher's pattern-side host fold (route_specificity's own split
/// — `host` or `host/path…`, the host lowercased): the index's query
/// column is exactly this, so a host-filtered candidate set is exactly
/// the set the matcher would have passed to the path check.
fn pattern_host(pattern: &str) -> String {
    match pattern.split_once('/') {
        Some((host, _)) => host.to_ascii_lowercase(),
        None => pattern.to_ascii_lowercase(),
    }
}

/// The matcher's pattern-side path fold, verbatim: the `/`-prefixed
/// remainder with the trailing `*` trimmed (a bare-host pattern's path
/// is `/`, which every request path starts with). The `path_where`
/// predicate applies the request side of the same law.
fn pattern_path(pattern: &str) -> String {
    match pattern.split_once('/') {
        Some((_, p)) => format!("/{p}").trim_end_matches('*').to_owned(),
        None => "/".to_owned(),
    }
}

/// The kapi families the table reads. The route-carrying family is the
/// typed Gateway API HttpRoute (gateway.networking.k8s.io/v1) — built by
/// the wisolate controller from app/worker GSS routes, and the ONLY
/// source of routes (k8s model). The pods (the node binding:
/// `labels.app` + `labels.org` -> `spec.nodeName`), the nodes (the
/// address stamp when a row carries one), the fleet's kapinodes and
/// the k8s secrets complete the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Family {
    /// Typed Gateway API HTTPRoute — the gateway's route source.
    Httproutes,
    Pods,
    /// The k8s-style node rows (the node's beat registers itself) —
    /// the address stamps the routing resolution reads.
    Nodes,
    /// The fleet's KapiNode rows: the MACHINES. The table stores
    /// nothing for them — the kubelet (the spawn arm) owns them.
    Kapinodes,
    /// The k8s Secrets (owner directive 2026-11-16: "let's use proper
    /// k8s secrets, apply it to kapi server and let the gateway/kubelet
    /// populate that based on all the namespace rules"): the pull
    /// credentials live as `kubernetes.io/dockerconfigjson` Secrets in
    /// each namespace; the table keeps the raw bodies and both arms
    /// (the asset store's per-app pulls, the kubelet's child env)
    /// resolve through [`Table::registry_auth`].
    Secrets,
    /// Typed AssetsOnlyApp CRs (kapi.qreta.io): a public/ virtual FS and
    /// an optional HTTPRoute backend. Consulted BEFORE the HTTPRoute
    /// fallback for every request path.
    AssetsOnlyApp,
    /// Typed WafRule CRs (gateway.qreta.io): the gateway's own WAF rules,
    /// watched from kapi and compiled into the live wirefilter ruleset.
    /// The CR set is the dynamic half of the WAF; the TOML `[[waf.rules]]`
    /// section is the static half (both fold into one ruleset).
    WafRules,
    /// Typed RateLimit CRs (gateway.qreta.io): namespace-local rate limits,
    /// each rule a wirefilter selector + dynamic group key + per-IP window.
    /// Watched like WafRule; folded into the live compiled ruleset.
    RateLimits,
}

impl Family {
    /// The kapi plural path segment.
    pub fn plural(self) -> &'static str {
        match self {
            Self::Httproutes => "httproutes",
            Self::Pods => "pods",
            Self::Nodes => "nodes",
            Self::Kapinodes => "kapinodes",
            Self::Secrets => "secrets",
            Self::AssetsOnlyApp => "assetsonlyapps",
            Self::WafRules => "wafrules",
            Self::RateLimits => "ratelimits",
        }
    }

    /// The kapi path prefix: the core group's pods ride `/api/v1`, the
    /// typed Gateway API routes ride `/apis/gateway.networking.k8s.io/v1`,
    /// the fleet's kapinodes ride the native group.
    pub fn list_path(self) -> String {
        match self {
            Self::Pods => "/api/v1/pods".to_owned(),
            Self::Nodes => "/api/v1/nodes".to_owned(),
            Self::Secrets => "/api/v1/secrets".to_owned(),
            Self::Httproutes => "/apis/gateway.networking.k8s.io/v1/httproutes".to_owned(),
            Self::WafRules => format!(
                "/apis/{}/{}",
                kapigate_core::crd::GROUP_VERSION,
                Self::WafRules.plural()
            ),
            Self::RateLimits => format!(
                "/apis/{}/{}",
                kapigate_core::crd::GROUP_VERSION,
                Self::RateLimits.plural()
            ),
            other => format!("/apis/kapi.qreta.io/v1alpha1/{}", other.plural()),
        }
    }

    /// The only route-carrying family: typed HTTPRoutes. No stamp, no
    /// labelSelector — the family IS the route set (the k8s model).
    fn carries_routes(self) -> bool {
        matches!(self, Self::Httproutes)
    }

    /// No bespoke filter: HTTPRoutes are selective by being their own
    /// typed kind, not by a label stamp (k8s model).
    #[must_use]
    pub fn watch_selector(self) -> Option<&'static str> {
        None
    }
}

/// The group/version path prefix for a family's watch and list calls.
pub const NATIVE_GROUP_PATH: &str = "/apis/kapi.qreta.io/v1alpha1";

/// One resolved route: the node to serve through and the app identity
/// the cache scope names (the fingerprint rides the row's annotation
/// when the kubelet stamps it; absent, the cache consult is inert).
#[derive(Debug, Clone)]
pub struct Resolved {
    /// The node that answers, when one does (no Running pod and no
    /// default node = `None` — the route is known, the backend absent).
    pub node: Option<String>,
    pub org: String,
    pub app: String,
    /// The serving fingerprint when the row carries one.
    pub fingerprint: Option<String>,
    /// The row's `spec.image` and `spec.assets` — the asset store's
    /// pull ref and law input.
    pub image: Option<String>,
    pub assets: Option<crate::AssetSpec>,
    /// The AssetsOnlyApp binding for this (org, app), when one exists.
    /// `server.rs` consults it BEFORE the HTTPRoute backend fallback.
    pub assets_only_apps: Option<AssetsOnlyAppBinding>,
}

impl Resolved {
    /// The FR-081 cache scope the app pushes under:
    /// `{org}/{state_id}/{serving_fingerprint}`.
    pub fn cache_scope(&self) -> Option<String> {
        let fingerprint = self.fingerprint.as_ref()?;
        Some(format!("{}/{}/{}", self.org, self.app, fingerprint))
    }
}

/// One app-kind row's projection: the route patterns (both manifest
/// spellings folded — `Route` is untagged) and the serving fingerprint
/// annotation when stamped.
#[derive(Debug, Clone)]
struct AppEntry {
    /// The kapi family that owns the row (the three compute kinds share
    /// one map; a re-list clears only its own family's rows).
    family: Family,
    patterns: Vec<String>,
    fingerprint: Option<String>,
    /// The HttpRoute metadata.names pointing at this (org, app) — an
    /// AssetsOnlyApp CR's `httpRouteRef` joins against any of them so
    /// sibling HTTPRoutes for the same backend never clobber one another.
    route_names: BTreeSet<String>,
}

/// The table. BTreeMap/BTreeSet everywhere: the resolution tie-break is
/// deterministic (max specificity, then lowest org, then lowest app —
/// the node's own route law's org tie-break).
#[derive(Default)]
pub struct Table {
    /// (org, app) -> the app-kind row's projection.
    routes: BTreeMap<(String, String), AppEntry>,
    /// (org, app) -> the node names of the app's Running pods.
    pods: BTreeMap<(String, String), BTreeSet<String>>,
    /// node name -> the row's own address stamp (`status.addresses`).
    node_rows: BTreeMap<String, Vec<String>>,
    /// The live route index (vennDB) — derived from `routes` by every
    /// route-family delta, consulted by `resolve` with the target url
    /// (host + path-prefix predicate). Never an input of its own.
    index: RouteRowDB,
    /// (namespace, name) -> the raw Secret body (the dockerconfigjson
    /// pull credentials' namespace rules, parsed at resolve time).
    secrets: BTreeMap<(String, String), serde_json::Value>,
    /// (org, name) -> a AssetsOnlyApp CR's resolved binding. Keyed by the
    /// CR's own metadata name; `http_route_ref` names the fallback route.
    assets_only_apps: BTreeMap<(String, String), AssetsOnlyAppBinding>,
    /// (namespace, name) -> a WafRule CR's ordered rules. Keyed by the
    /// CR's metadata so a delta is a single map edit; the gateway folds
    /// every CR's rules (in name order) into the live compiled ruleset.
    waf_rules: BTreeMap<(String, String), Vec<kapigate_core::crd::WafRuleEntry>>,
    /// Bumped on every WafRules family delta. The serving face compares
    /// it against its last compile and recompiles only when the CR set
    /// actually changed — no work on the hot path when rules are static.
    waf_rules_generation: u64,
    /// (namespace, name) -> a RateLimit CR's ordered rules. Keyed by the
    /// CR's metadata so a delta is a single map edit; a rule's namespace
    /// is the scope in which it applies (the served route's namespace).
    rate_limits: BTreeMap<(String, String), Vec<kapigate_core::crd::RateLimitEntry>>,
    /// Bumped on every RateLimits family delta (generation-gated like WAF).
    rate_limits_generation: u64,
}

/// The gateway's view of a AssetsOnlyApp CR: the OCI/volume source, the
/// resolved public paths/hashes/header rules, and the optional route
/// whose backend handles non-asset paths.
#[derive(Debug, Clone)]
pub struct AssetsOnlyAppBinding {
    pub org: String,
    pub name: String,
    /// OCI image ref (mutually exclusive with volume).
    pub oci: Option<String>,
    /// k8s volume name (mutually exclusive with oci).
    pub volume: Option<String>,
    /// Optional HTTPRoute name; absent = 404 on a non-asset path.
    pub http_route_ref: Option<String>,
    pub not_found_handling: kapigate_core::assets_only_app::NotFoundHandling,
    /// url path (no leading slash) -> byte length, under public/.
    pub public_paths: BTreeMap<String, u64>,
    pub hashes: BTreeMap<String, String>,
    pub header_rules: Vec<kapigate_core::assets::HeaderRule>,
}

/// A registry credential: the shape the pull's Authorization header
/// takes. The config/env ladder rides Bearer (the `[registry.<host>]`
/// token); a dockerconfigjson Secret rides Basic (the `auth` field's
/// base64 `user:token`, applied verbatim — the header needs no
/// decoding).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryAuth {
    Bearer(String),
    Basic(String),
}

impl RegistryAuth {
    /// The Authorization header value.
    #[must_use]
    pub fn header(&self) -> String {
        match self {
            Self::Bearer(token) => format!("Bearer {token}"),
            Self::Basic(auth) => format!("Basic {auth}"),
        }
    }

    /// The Basic credential split into (user, token) for an OCI Bearer
    /// token exchange. The dockerconfigjson `auth` is base64(user:token).
    #[must_use]
    pub fn basic_parts(&self) -> Option<(String, String)> {
        let Self::Basic(auth) = self else {
            return None;
        };
        let raw = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, auth).ok()?;
        let text = String::from_utf8(raw).ok()?;
        let (user, token) = text.split_once(':')?;
        Some((user.to_owned(), token.to_owned()))
    }
}

impl Table {
    /// Rebuild the live index from the route map (the delta truth).
    /// One row per pattern; the fleet's pattern count makes this a
    /// microsecond-scale cost per delta, paid on the watch side —
    /// never on the request path.
    fn rebuild_index(&mut self) {
        self.index = RouteRowDB::from_rows(
            self.routes
                .iter()
                .flat_map(|((org, app), entry)| {
                    entry.patterns.iter().map(move |pattern| RouteRow {
                        host: pattern_host(pattern),
                        path: pattern_path(pattern),
                        org: org.clone(),
                        app: app.clone(),
                        pattern: pattern.clone(),
                    })
                })
                .collect(),
        );
    }
}

impl Table {
    /// Apply one watch event (or one full-list row). Pure: the table
    /// mutates, nothing else — the informer owns the I/O around it. A
    /// route-family delta rebuilds the live index from the new truth.
    pub fn apply(&mut self, family: Family, event_type: &str, object: &serde_json::Value) {
        match event_type {
            "ADDED" | "MODIFIED" => self.upsert(family, object),
            "DELETED" => self.remove(family, object),
            _ => return,
        }
        if family.carries_routes() {
            self.rebuild_index();
        }
        if family == Family::WafRules {
            self.waf_rules_generation = self.waf_rules_generation.wrapping_add(1);
        }
        if family == Family::RateLimits {
            self.rate_limits_generation = self.rate_limits_generation.wrapping_add(1);
        }
    }

    /// Replace one family wholesale (the re-list law: the informer
    /// lists, the table clears the family and applies the rows).
    /// Kapinodes store nothing here — the kubelet owns them (the
    /// informer feeds that family to the spawn arm directly). A
    /// route-family re-list rebuilds the live index ONCE, after the
    /// family has landed.
    pub fn replace(&mut self, family: Family, items: &[serde_json::Value]) {
        let routes_family = family.carries_routes();
        match family {
            Family::Httproutes => {
                self.routes.retain(|_, entry| entry.family != family);
            }
            Family::Pods => self.pods.clear(),
            Family::Nodes => self.node_rows.clear(),
            Family::Secrets => self.secrets.clear(),
            Family::AssetsOnlyApp => self.assets_only_apps.clear(),
            Family::WafRules => self.waf_rules.clear(),
            Family::RateLimits => self.rate_limits.clear(),
            Family::Kapinodes => return,
        }
        for item in items {
            self.upsert(family, item);
        }
        if routes_family {
            self.rebuild_index();
        }
        if family == Family::WafRules {
            self.waf_rules_generation = self.waf_rules_generation.wrapping_add(1);
        }
        if family == Family::RateLimits {
            self.rate_limits_generation = self.rate_limits_generation.wrapping_add(1);
        }
    }

    fn upsert(&mut self, family: Family, object: &serde_json::Value) {
        match family {
            Family::Kapinodes => {}
            Family::Httproutes => {
                let Some((org, app, entry)) = httproute_row(family, object) else {
                    return;
                };
                if entry.patterns.is_empty() {
                    self.routes.remove(&(org, app));
                } else {
                    self.routes.insert((org, app), entry);
                }
            }
            Family::Pods => {
                let Some((org, app, node)) = pod_row(object) else {
                    return;
                };
                self.pods.entry((org, app)).or_default().insert(node);
            }
            Family::Nodes => {
                let Some((name, addrs)) = node_row(object) else {
                    return;
                };
                if addrs.is_empty() {
                    self.node_rows.remove(&name);
                } else {
                    self.node_rows.insert(name, addrs);
                }
            }
            Family::Secrets => {
                let Some((namespace, name)) = secret_row(object) else {
                    return;
                };
                self.secrets.insert((namespace, name), object.clone());
            }
            Family::AssetsOnlyApp => {
                let Some((org, name, binding)) = assets_only_app_row(object) else {
                    return;
                };
                self.assets_only_apps.insert((org, name), binding);
            }
            Family::WafRules => {
                let Some((namespace, name, rules)) = waf_rule_row(object) else {
                    return;
                };
                self.waf_rules.insert((namespace, name), rules);
            }
            Family::RateLimits => {
                let Some((namespace, name, rules)) = rate_limit_row(object) else {
                    return;
                };
                self.rate_limits.insert((namespace, name), rules);
            }
        }
    }

    fn remove(&mut self, family: Family, object: &serde_json::Value) {
        match family {
            Family::Kapinodes => {}
            Family::Httproutes => {
                if let Some((org, app, _)) = httproute_row(family, object) {
                    self.routes.remove(&(org, app));
                }
            }
            Family::Pods => {
                if let Some((org, app, node)) = pod_row(object) {
                    let key = (org, app);
                    if let Some(set) = self.pods.get_mut(&key) {
                        set.remove(&node);
                        if set.is_empty() {
                            self.pods.remove(&key);
                        }
                    }
                }
            }
            Family::Nodes => {
                if let Some((name, _)) = node_row(object) {
                    self.node_rows.remove(&name);
                }
            }
            Family::Secrets => {
                if let Some((namespace, name)) = secret_row(object) {
                    self.secrets.remove(&(namespace, name));
                }
            }
            Family::AssetsOnlyApp => {
                if let Some((org, name, _)) = assets_only_app_row(object) {
                    self.assets_only_apps.remove(&(org, name));
                }
            }
            Family::WafRules => {
                if let Some((namespace, name, _)) = waf_rule_row(object) {
                    self.waf_rules.remove(&(namespace, name));
                }
            }
            Family::RateLimits => {
                if let Some((namespace, name, _)) = rate_limit_row(object) {
                    self.rate_limits.remove(&(namespace, name));
                }
            }
        }
    }

    /// The WAF ruleset generation. Bumped on every WafRules family delta;
    /// the serving face uses it to know when to recompile.
    #[must_use]
    pub fn waf_rules_generation(&self) -> u64 {
        self.waf_rules_generation
    }

    /// The ordered WAF rules from every watched `WafRule` CR, folded into
    /// the law's shape. BTreeMap order (namespace, then name) is the
    /// deterministic compile order; within a CR the spec's order is kept.
    /// A CR whose rule name is blank is skipped — an audit header needs
    /// an identity. The TOML-configured rules are prepended by the caller
    /// (the gateway) so static rules run before watched ones.
    #[must_use]
    pub fn waf_rules(&self) -> Vec<kapigate_core::waf::WafRule> {
        self.waf_rules
            .values()
            .flatten()
            .filter(|r| !r.name.is_empty())
            .map(|r| kapigate_core::waf::WafRule {
                name: r.name.clone(),
                expression: r.expression.clone(),
                action: r.action,
                status: r.status,
                body: r.body.clone(),
                headers: r
                    .headers
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect(),
                enabled: r.enabled,
            })
            .collect()
    }

    /// The RateLimits generation. Bumped on every RateLimits family delta.
    #[must_use]
    pub fn rate_limits_generation(&self) -> u64 {
        self.rate_limits_generation
    }

    /// The watched `RateLimit` CR rules, grouped by namespace. BTreeMap
    /// order makes the compile order deterministic; within a CR the
    /// spec's order is kept. Blank rule names are skipped (an audit header
    /// needs an identity), and invalid numeric rules are skipped at the
    /// row parse seam so one bad CR cannot poison the set.
    #[must_use]
    pub fn rate_limits(&self) -> Vec<(String, Vec<kapigate_core::crd::RateLimitEntry>)> {
        self.rate_limits
            .iter()
            .map(|((namespace, _), rules)| {
                (
                    namespace.clone(),
                    rules
                        .iter()
                        .filter(|r| !r.name.is_empty() && r.validate().is_ok())
                        .cloned()
                        .collect(),
                )
            })
            .collect()
    }

    /// Resolve (host, path) to the app identity + the node address,
    /// by the matcher law (exact Host, longest prefix) and the pod
    /// binding. `None` = the route table does not know the host (404).
    /// `Some((resolved, None))` = the route matches but no node
    /// answers (no Running pod, no default node, no address — 503).
    pub fn resolve(
        &self,
        host: &str,
        path: &str,
        node_addr: impl Fn(&str, Option<&[String]>) -> Option<String>,
        default_node: Option<&str>,
    ) -> Option<(Resolved, Option<String>)> {
        // The live index takes the TARGET URL: the exact-host filter
        // (the pattern side folded at build; the request side arrives
        // folded from the serving entry) AND the path-prefix predicate
        // (the matcher's starts_with law, applied per candidate path
        // column). What leaves the index is already the set of MATCHING
        // patterns. The LAW is unchanged and stays here:
        // route_specificity ranks the matches (longest prefix), ties
        // break to the lowest (org, app) — the same argmax the linear
        // scan over the whole map produced.
        let request_path = if path.is_empty() { "/" } else { path };
        let mut query = self.index.query();
        query
            .host(host.to_owned())
            .path_where(|p| request_path.starts_with(p.as_str()));
        let mut best: Option<(usize, (&str, &str))> = None;
        if let Some(matches) = query.execute() {
            for row in matches.iter() {
                if let Some(spec) = route_specificity(&row.pattern, host, path) {
                    let better = match best {
                        None => true,
                        Some((best_spec, best_key)) => {
                            spec > best_spec
                                || (spec == best_spec
                                    && (row.org.as_str(), row.app.as_str()) < best_key)
                        }
                    };
                    if better {
                        best = Some((spec, (row.org.as_str(), row.app.as_str())));
                    }
                }
            }
        }
        let (org, app) = best?.1;
        let entry = self.routes.get(&(org.to_owned(), app.to_owned()))?;
        // First Running pod's node wins (deterministic BTreeSet order);
        // no pods at all takes the default node (scale-to-zero); no
        // node at all leaves the route known and the backend absent.
        let node_choice: Option<(String, Option<Vec<String>>)> = self
            .pods
            .get(&(org.to_owned(), app.to_owned()))
            .and_then(|set| set.iter().next().cloned())
            .map(|node| {
                let addrs = self.node_rows.get(&node).cloned();
                (node, addrs)
            })
            .or_else(|| {
                default_node.map(|node| {
                    let addrs = self.node_rows.get(node).cloned();
                    (node.to_owned(), addrs)
                })
            });
        let (node, addr) = match node_choice {
            Some((node, addrs)) => {
                let addr = node_addr(&node, addrs.as_deref());
                (Some(node), addr)
            }
            None => (None, None),
        };
        // The AssetsOnlyApp join: a CR in this org whose http_route_ref
        // names this HttpRoute (or whose name is the app) binds the
        // public/ tree consulted BEFORE the route's backend.
        let binding = self
            .assets_only_apps
            .iter()
            .find(|((pa_org, pa_name), pa)| {
                pa_org == org
                    && (pa
                        .http_route_ref
                        .as_deref()
                        .is_some_and(|r| entry.route_names.contains(r))
                        || pa_name == app)
            })
            .map(|(_, pa)| pa.clone());
        Some((
            Resolved {
                node,
                org: org.to_owned(),
                app: app.to_owned(),
                fingerprint: entry.fingerprint.clone(),
                image: binding.as_ref().and_then(|b| b.oci.clone()),
                assets: binding.as_ref().map(|b| crate::AssetSpec {
                    // AssetsOnlyApp serves assets first; there is no
                    // run_worker_first flag — the route backend is the
                    // fallback, expressed by http_route_ref.
                    run_worker_first: false,
                    hashes: b.hashes.clone(),
                    header_rules: b.header_rules.clone(),
                }),
                assets_only_apps: binding,
            },
            addr,
        ))
    }

    /// The namespace's registry credential for a pull: the
    /// dockerconfigjson Secrets of the app's OWN namespace (the
    /// namespace rules — another namespace's secret is another
    /// tenant's). `None` = the caller's static ladder (config map,
    /// env) applies.
    #[must_use]
    pub fn registry_auth(&self, namespace: &str, registry: &str) -> Option<RegistryAuth> {
        registry_auth_from_secrets(&self.secrets, namespace, registry)
    }

    /// The node's namespace's ghcr token for the spawn arm's child:
    /// the dockerconfigjson Secret of THE NODE ROW'S OWN NAMESPACE
    /// (the k8s kubelet law — a pod's pulls carry the pod's namespace's
    /// imagePullSecrets; a node row scopes its child the same way),
    /// decoded to the token half. The row's own env wins over it at
    /// spawn time.
    #[must_use]
    pub fn child_pull_token(&self, namespace: &str) -> Option<String> {
        child_pull_token(&self.secrets, namespace)
    }

    /// The health face's counts: (apps, apps-with-running-pods, nodes).
    pub fn counts(&self) -> (usize, usize, usize) {
        let served = self
            .routes
            .keys()
            .filter(|k| self.pods.contains_key(*k))
            .count();
        (self.routes.len(), served, self.node_rows.len())
    }
}

/// A Secret row: (namespace, name) — the identity the deltas key on.
fn secret_row(object: &serde_json::Value) -> Option<(String, String)> {
    let namespace = object.pointer("/metadata/namespace")?.as_str()?.to_owned();
    let name = object.pointer("/metadata/name")?.as_str()?.to_owned();
    Some((namespace, name))
}

/// THE NAMESPACE RULES for pull credentials (owner directive
/// 2026-11-16: "let the gateway/kubelet populate that based on all the
/// namespace rules"): a namespace's `kubernetes.io/dockerconfigjson`
/// Secrets name the registries their `auths` map carries, and the
/// lowest (namespace, name) wins a tie — the same deterministic
/// lowest-key law the route resolution rides. An app's pull resolves
/// through ITS OWN namespace first; the caller's ladder (config map,
/// env) applies only when no Secret answers.
fn registry_auth_from_secrets(
    secrets: &BTreeMap<(String, String), serde_json::Value>,
    namespace: &str,
    registry: &str,
) -> Option<RegistryAuth> {
    const DOCKERCONFIGJSON: &str = "kubernetes.io/dockerconfigjson";
    for ((ns, _name), body) in secrets.iter() {
        if ns != namespace {
            continue;
        }
        if body.pointer("/type").and_then(serde_json::Value::as_str) != Some(DOCKERCONFIGJSON) {
            continue;
        }
        let Some(auth) = dockerconfig_auth(body, registry) else {
            continue;
        };
        return Some(RegistryAuth::Basic(auth));
    }
    None
}

/// The `auths/{registry}/auth` field off a Secret's embedded config:
/// `data` carries it base64-wrapped (the k8s convention), a verbatim
/// `stringData` apply carries it as plain JSON — both spellings
/// answer, the apply grammar decides the storage, not the reader.
fn dockerconfig_auth(body: &serde_json::Value, registry: &str) -> Option<String> {
    if let Some(encoded) = body
        .pointer("/data/.dockerconfigjson")
        .and_then(serde_json::Value::as_str)
        && let Ok(decoded) =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded)
    {
        let config = String::from_utf8_lossy(&decoded);
        if let Ok(config) = serde_json::from_str::<serde_json::Value>(&config)
            && let Some(auth) = config
                .pointer(&format!("/auths/{registry}/auth"))
                .and_then(serde_json::Value::as_str)
        {
            return Some(auth.to_owned());
        }
    }
    body.pointer("/stringData/.dockerconfigjson")
        .and_then(serde_json::Value::as_str)
        .and_then(|config| serde_json::from_str::<serde_json::Value>(config).ok())
        .and_then(|config| {
            config
                .pointer(&format!("/auths/{registry}/auth"))
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })
}

/// The node's namespace's ghcr token for the SPAWN arm's child: the
/// dockerconfigjson entry's auth decodes to `user:token`, and the
/// child's own pull ladder takes the token as GHCR_TOKEN. Only THE
/// NAMESPACE'S secrets answer (the lowest (namespace, name) inside it
/// wins the tie) — a node row scopes its child exactly as a k8s pod
/// scopes its pulls: by its own namespace, never another tenant's.
fn child_pull_token(
    secrets: &BTreeMap<(String, String), serde_json::Value>,
    namespace: &str,
) -> Option<String> {
    for ((ns, _name), body) in secrets.iter() {
        if ns != namespace {
            continue;
        }
        if body.pointer("/type").and_then(serde_json::Value::as_str)
            != Some("kubernetes.io/dockerconfigjson")
        {
            continue;
        }
        let Some(auth) = dockerconfig_auth(body, "ghcr.io") else {
            continue;
        };
        let Ok(user_token) =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, auth)
        else {
            continue;
        };
        let user_token = String::from_utf8_lossy(&user_token);
        if let Some((_, token)) = user_token.split_once(':') {
            return Some(token.to_owned());
        }
    }
    None
}

/// A typed AssetsOnlyApp CR -> (org, name, binding). The spec's oci/volume
/// are mutually exclusive; an invalid row (both/neither) contributes no
/// binding — the kapi controller marks it not-ready. The status carries
/// the resolved public/ paths + hashes + header rules.
fn assets_only_app_row(object: &serde_json::Value) -> Option<(String, String, AssetsOnlyAppBinding)> {
    use kapigate_core::assets_only_app::{AssetsOnlyAppSpec, AssetsOnlyAppStatus};
    let org = object.pointer("/metadata/namespace")?.as_str()?.to_owned();
    let name = object.pointer("/metadata/name")?.as_str()?.to_owned();
    let spec: AssetsOnlyAppSpec = serde_json::from_value(object.get("spec")?.clone()).ok()?;
    if !spec.valid() {
        return None;
    }
    let status: AssetsOnlyAppStatus = object
        .get("status")
        .cloned()
        .and_then(|s| serde_json::from_value(s).ok())
        .unwrap_or_default();
    Some((
        org.clone(),
        name.clone(),
        AssetsOnlyAppBinding {
            org,
            name,
            oci: spec.oci,
            volume: spec.volume,
            http_route_ref: spec.http_route_ref,
            not_found_handling: spec.not_found_handling,
            public_paths: status.public_paths,
            hashes: status.hashes,
            header_rules: status.header_rules,
        },
    ))
}

/// A typed WafRule CR -> (namespace, name, ordered rules). A malformed
/// spec (bad JSON shape) contributes nothing — the kapi controller marks
/// it not-ready and the gateway keeps its last good ruleset. The rules
/// themselves are validated at compile time on the recompile seam.
fn waf_rule_row(
    object: &serde_json::Value,
) -> Option<(String, String, Vec<kapigate_core::crd::WafRuleEntry>)> {
    let namespace = object.pointer("/metadata/namespace")?.as_str()?.to_owned();
    let name = object.pointer("/metadata/name")?.as_str()?.to_owned();
    let spec: kapigate_core::crd::WafRuleSpec =
        serde_json::from_value(object.get("spec")?.clone()).ok()?;
    // A single CR carrying more rules than the WAF's compile cap is
    // rejected at the watch seam: keep the last-good ruleset rather than
    // letting one oversized row poison the whole combined set.
    if spec.rules.len() > kapigate_core::waf::MAX_RULES {
        eprintln!(
            "[gateway] WafRule CR {namespace}/{name} carries {} rules (cap {}); ignored",
            spec.rules.len(),
            kapigate_core::waf::MAX_RULES
        );
        return None;
    }
    Some((namespace, name, spec.rules))
}

/// A typed RateLimit CR -> (namespace, name, ordered rules). A malformed
/// spec contributes nothing — the kapi controller marks it not-ready and
/// the gateway keeps its last-good ruleset. Numeric fields and the rule
/// cap are validated here; selectors are compiled on the recompile seam.
fn rate_limit_row(
    object: &serde_json::Value,
) -> Option<(String, String, Vec<kapigate_core::crd::RateLimitEntry>)> {
    let namespace = object.pointer("/metadata/namespace")?.as_str()?.to_owned();
    let name = object.pointer("/metadata/name")?.as_str()?.to_owned();
    let spec: kapigate_core::crd::RateLimitSpec =
        serde_json::from_value(object.get("spec")?.clone()).ok()?;
    if spec.rules.len() > kapigate_core::waf::MAX_RULES
        || spec.rules.iter().any(|r| r.validate().is_err())
    {
        eprintln!(
            "[gateway] RateLimit CR {namespace}/{name} has invalid or oversized rules; ignored"
        );
        return None;
    }
    Some((namespace, name, spec.rules))
}

/// A typed HttpRoute row: (org, app, projection). The route's hostnames
/// × each rule's path matches become the host/path patterns the matcher
/// already consumes. The app identity comes from the first rule's
/// backendRef name (the service the wisolate controller named after the
/// app), falling back to metadata.name. Asset fields are absent — the
/// gateway builds on route manifests only; asset pulls resolve through
/// the controller's own path.
fn httproute_row(family: Family, object: &serde_json::Value) -> Option<(String, String, AppEntry)> {
    let org = object.pointer("/metadata/namespace")?.as_str()?.to_owned();
    let app = object
        .pointer("/spec/rules/0/backendRefs/0/name")
        .and_then(Value::as_str)
        .or_else(|| object.pointer("/metadata/name")?.as_str())?
        .to_owned();
    // Asset data no longer rides the route as an annotation — it lives
    // in a typed AssetsOnlyApp CR. The route's metadata.name is the join
    // key a CR's httpRouteRef names.
    let route_names = object
        .pointer("/metadata/name")
        .and_then(Value::as_str)
        .map(|s| BTreeSet::from([s.to_owned()]))
        .unwrap_or_default();
    let mut entry = AppEntry {
        family,
        patterns: Vec::new(),
        fingerprint: object
            .pointer("/metadata/annotations/kapi.qreta.io~1fingerprint")
            .and_then(Value::as_str)
            .map(str::to_owned),
        route_names,
    };
    let hosts: Vec<&str> = object
        .pointer("/spec/hostnames")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let paths: Vec<&str> = object
        .pointer("/spec/rules")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|rule| rule.pointer("/matches").and_then(Value::as_array))
        .flatten()
        .filter_map(|m| m.pointer("/path/value").and_then(Value::as_str))
        .collect();
    for host in &hosts {
        if paths.is_empty() {
            entry.patterns.push((*host).to_owned());
        } else {
            for path in &paths {
                // GSS pattern spelling: "host/path" (a "/" path keeps the
                // bare host, the matcher's own fold).
                entry.patterns.push(if *path == "/" {
                    (*host).to_owned()
                } else {
                    format!("{}{}", host, path)
                });
            }
        }
    }
    Some((org, app, entry))
}

/// A pod row: (org, app, node) — Running only (a Pending pod binds
/// nothing; the kubelet drives the phase).
fn pod_row(object: &serde_json::Value) -> Option<(String, String, String)> {
    let org = object.pointer("/metadata/namespace")?.as_str()?.to_owned();
    let app = object.pointer("/metadata/labels/app")?.as_str()?.to_owned();
    let node = object.pointer("/spec/nodeName")?.as_str()?.to_owned();
    let phase = object
        .pointer("/status/phase")
        .and_then(|p| p.as_str())
        .unwrap_or("Pending");
    (phase == "Running").then_some((org, app, node))
}

/// A node row: (name, status.addresses) — the k8s address shape the
/// kubelet may stamp (`[{type, address}]`); the row's `spec.endpoint`
/// is the kapi URL today and never a serving address.
fn node_row(object: &serde_json::Value) -> Option<(String, Vec<String>)> {
    let name = object.pointer("/metadata/name")?.as_str()?.to_owned();
    let addrs = object
        .pointer("/status/addresses")
        .and_then(|a| a.as_array())
        .map(|list| {
            list.iter()
                .filter_map(|a| a.get("address").and_then(|v| v.as_str()))
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    Some((name, addrs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    /// An app-shaped route seed → typed HttpRoute body. The test grammar
    /// stays the familiar host/path list; the body is the k8s-native
    /// shape the gateway now reads.
    fn hr_ns(namespace: &str, name: &str, routes: &[&str]) -> Value {
        let mut hostnames = Vec::new();
        let mut paths = Vec::new();
        for r in routes {
            let (host, path) = match r.split_once('/') {
                Some((h, p)) => (h, format!("/{}", p)),
                None => (*r, "/".to_owned()),
            };
            if !hostnames.contains(&host.to_owned()) {
                hostnames.push(host.to_owned());
            }
            if !paths.contains(&path) {
                paths.push(path);
            }
        }
        let matches: Vec<Value> = paths
            .iter()
            .map(|p| json!({"path": {"type": "PathPrefix", "value": p}}))
            .collect();
        json!({
            "apiVersion": "gateway.networking.k8s.io/v1", "kind": "HTTPRoute",
            "metadata": {"name": name, "namespace": namespace},
            "spec": {
                "hostnames": hostnames,
                "rules": [{"matches": matches, "backendRefs": [{"name": name, "port": 80}]}]
            }
        })
    }

    fn hr(name: &str, routes: &[&str]) -> Value {
        hr_ns("acme", name, routes)
    }

    fn addr_map() -> impl Fn(&str, Option<&[String]>) -> Option<String> {
        |node, row| {
            if let Some(addr) = row.and_then(|l| l.first()) {
                return Some(addr.clone());
            }
            match node {
                "node-a" => Some("10.0.0.1:8080".to_owned()),
                "node-b" => Some("10.0.0.2:8080".to_owned()),
                _ => None,
            }
        }
    }

    fn seed() -> Table {
        let mut t = Table::default();
        t.apply(
            Family::Httproutes,
            "ADDED",
            &hr("orders", &["orders.example.com", "orders.example.com/api"]),
        );
        t.apply(
            Family::Pods,
            "ADDED",
            &json!({
                "metadata": {"name": "acme-orders", "namespace": "acme",
                             "labels": {"app": "orders", "org": "acme"}},
                "spec": {"nodeName": "node-a"},
                "status": {"phase": "Running"}
            }),
        );
        t
    }

    #[test]
    fn the_longest_route_wins_and_names_the_node() {
        let t = seed();
        let resolve = |t: &Table, host: &str, path: &str| {
            t.resolve(host, path, addr_map(), None)
                .map(|(r, addr)| (r.node, addr))
        };
        // The bare host and the deep prefix both match; the deeper
        // pattern's specificity sorts first — the node answers either.
        assert_eq!(
            resolve(&t, "orders.example.com", "/api/v1/x"),
            Some((Some("node-a".to_owned()), Some("10.0.0.1:8080".to_owned())))
        );
        assert!(resolve(&t, "orders.example.com", "/x").is_some());
        assert_eq!(resolve(&t, "other.example.com", "/"), None);
    }

    #[test]
    fn a_pod_delete_scales_the_route_to_nothing() {
        let mut t = seed();
        t.apply(
            Family::Pods,
            "DELETED",
            &json!({
                "metadata": {"name": "acme-orders", "namespace": "acme",
                             "labels": {"app": "orders", "org": "acme"}},
                "spec": {"nodeName": "node-a"},
                "status": {"phase": "Running"}
            }),
        );
        // No pods, no default node: the route matches but no node
        // answers — the gateway's honest 503, never a 404.
        let (r, addr) = t
            .resolve("orders.example.com", "/", addr_map(), None)
            .unwrap();
        assert_eq!(r.app, "orders");
        assert_eq!(r.node, None);
        assert_eq!(addr, None);
        // The default node takes it (scale-to-zero).
        let (r, addr) = t
            .resolve("orders.example.com", "/", addr_map(), Some("node-b"))
            .unwrap();
        assert_eq!(r.node, Some("node-b".to_owned()));
        assert_eq!(addr, Some("10.0.0.2:8080".to_owned()));
    }

    #[test]
    fn a_pending_pod_binds_nothing() {
        let mut t = Table::default();
        t.apply(
            Family::Pods,
            "ADDED",
            &json!({
                "metadata": {"name": "acme-orders", "namespace": "acme",
                             "labels": {"app": "orders", "org": "acme"}},
                "spec": {"nodeName": "node-a"},
                "status": {"phase": "Pending"}
            }),
        );
        assert!(t.resolve("h", "/", addr_map(), None).is_none());
    }

    #[test]
    fn a_podless_route_503s_without_a_default_node() {
        let mut t = Table::default();
        t.apply(
            Family::Httproutes,
            "ADDED",
            &hr("orders", &["orders.example.com"]),
        );
        // The route MATCHES (the table knows it) but no node answers.
        let (r, addr) = t
            .resolve("orders.example.com", "/", addr_map(), None)
            .unwrap();
        assert_eq!(r.app, "orders");
        assert_eq!(r.node, None);
        assert_eq!(addr, None);
    }

    #[test]
    fn the_assets_only_apps_cr_joins_the_route() {
        let mut t = Table::default();
        t.apply(
            Family::Httproutes,
            "ADDED",
            &hr("orders", &["orders.example.com"]),
        );
        // A AssetsOnlyApp CR whose http_route_ref names the route's
        // metadata.name ("orders") supplies the public/ tree.
        t.apply(
            Family::AssetsOnlyApp,
            "ADDED",
            &json!({
                "metadata": {"name": "orders-assets", "namespace": "acme"},
                "spec": {"oci": "ghcr.io/qretaio/orders:sha", "httpRouteRef": "orders"},
                "status": {"publicPaths": {"index.html": 3},
                           "hashes": {"index.html": "abc"}, "headerRules": []}
            }),
        );
        let (r, _) = t
            .resolve("orders.example.com", "/", addr_map(), None)
            .unwrap();
        assert_eq!(r.image.as_deref(), Some("ghcr.io/qretaio/orders:sha"));
        let spec = r.assets.expect("the AssetsOnlyApp spec reaches the gateway");
        assert_eq!(
            spec.hashes.get("index.html").map(String::as_str),
            Some("abc")
        );
        assert!(!spec.run_worker_first);
        assert!(r.assets_only_apps.is_some());
    }

    #[test]
    fn a_assets_only_apps_cr_without_route_ref_has_no_backend() {
        let mut t = Table::default();
        t.apply(
            Family::Httproutes,
            "ADDED",
            &hr("orders", &["orders.example.com"]),
        );
        t.apply(
            Family::AssetsOnlyApp,
            "ADDED",
            &json!({
                "metadata": {"name": "orders", "namespace": "acme"},
                "spec": {"volume": "orders-vol"},
                "status": {"publicPaths": {"index.html": 3}}
            }),
        );
        let (r, _) = t
            .resolve("orders.example.com", "/", addr_map(), None)
            .unwrap();
        let binding = r.assets_only_apps.expect("the CR joined by app name");
        assert_eq!(binding.http_route_ref, None);
        assert_eq!(binding.volume.as_deref(), Some("orders-vol"));
    }

    #[test]
    fn both_route_spellings_fold_to_patterns() {
        let mut t = Table::default();
        // Both spellings of a route fold to the pattern the matcher eats:
        // the object form here, the bare-string form below.
        t.apply(
            Family::Httproutes,
            "ADDED",
            &hr("echo", &["echo.example.com/ws"]),
        );
        t.apply(
            Family::Httproutes,
            "ADDED",
            &hr("bare", &["bare.example.com"]),
        );
        let (r, _) = t
            .resolve("echo.example.com", "/ws", addr_map(), Some("node-a"))
            .unwrap();
        assert_eq!(r.app, "echo");
        let (r, _) = t
            .resolve("bare.example.com", "/", addr_map(), Some("node-a"))
            .unwrap();
        assert_eq!(r.app, "bare");
    }

    #[test]
    fn replace_relists_a_family_wholesale() {
        let mut t = seed();
        t.replace(Family::Httproutes, &[hr("fresh", &["fresh.example.com"])]);
        assert!(
            t.resolve("orders.example.com", "/", addr_map(), None)
                .is_none()
        );
        // The fresh app has no pods yet: the default node takes it.
        assert!(
            t.resolve("fresh.example.com", "/", addr_map(), Some("node-a"))
                .is_some()
        );
    }

    #[test]
    fn the_cache_scope_needs_a_fingerprint() {
        let mut t = seed();
        // No fingerprint stamped yet: the consult is inert.
        let (r, _) = t
            .resolve("orders.example.com", "/", addr_map(), None)
            .unwrap();
        assert!(r.cache_scope().is_none());
        // The annotation stamps it and the scope takes FR-081's shape.
        let mut r = hr("orders", &["orders.example.com"]);
        r["metadata"]["annotations"] = json!({"kapi.qreta.io/fingerprint": "fp-7"});
        t.apply(Family::Httproutes, "MODIFIED", &r);
        let (r, _) = t
            .resolve("orders.example.com", "/", addr_map(), None)
            .unwrap();
        assert_eq!(r.cache_scope().as_deref(), Some("acme/orders/fp-7"));
    }

    #[test]
    fn a_node_row_address_serves_when_the_map_is_silent() {
        let mut t = seed();
        t.apply(
            Family::Nodes,
            "ADDED",
            &json!({
                "metadata": {"name": "node-a"},
                "status": {"addresses": [{"type": "InternalIP", "address": "192.168.1.9:80"}]}
            }),
        );
        let (_, addr) = t
            .resolve(
                "orders.example.com",
                "/",
                |_, row| row.and_then(|l| l.first()).cloned(),
                None,
            )
            .unwrap();
        assert_eq!(addr.as_deref(), Some("192.168.1.9:80"));
    }

    #[test]
    fn the_namespace_rules_resolve_the_pull_credentials() {
        // Owner directive 2026-11-16: "let's use proper k8s secrets,
        // apply it to kapi server and let the gateway/kubelet populate
        // that based on all the namespace rules" — the dockerconfigjson
        // Secret of the app's OWN namespace answers; another
        // namespace's is another tenant's; a non-dockerconfigjson
        // secret is ignored; the lowest (namespace, name) wins a tie.
        use base64::Engine as _;
        let config = |auth: &str| {
            format!(
                "{{\"auths\":{{\"ghcr.io\":{{\"auth\":\"{}\"}}}}}}",
                base64::engine::general_purpose::STANDARD.encode(auth)
            )
        };
        let secret = |namespace: &str, name: &str, config: &str| {
            json!({
                "apiVersion": "v1", "kind": "Secret",
                "metadata": {"name": name, "namespace": namespace},
                "type": "kubernetes.io/dockerconfigjson",
                "data": {".dockerconfigjson":
                    base64::engine::general_purpose::STANDARD.encode(config)},
            })
        };
        let mut t = Table::default();
        t.apply(
            Family::Secrets,
            "ADDED",
            &secret("qreta", "pull", &config("user:qreta-token")),
        );
        t.apply(
            Family::Secrets,
            "ADDED",
            &secret("mgmt", "pull", &config("user:mgmt-token")),
        );

        // The namespace rules: qreta's app resolves qreta's secret.
        let auth = t.registry_auth("qreta", "ghcr.io").unwrap();
        assert_eq!(
            auth.header(),
            format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode("user:qreta-token")
            )
        );
        // Another namespace is another tenant's credential.
        assert!(t.registry_auth("lo", "ghcr.io").is_none());
        // Another registry inside the same secret misses.
        assert!(t.registry_auth("qreta", "docker.io").is_none());

        // The re-list replaces the family; a delete takes one row out.
        t.replace(
            Family::Secrets,
            &[secret("qreta", "pull", &config("user:fresh-token"))],
        );
        let auth = t.registry_auth("qreta", "ghcr.io").unwrap();
        assert_eq!(
            auth.header(),
            format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode("user:fresh-token")
            )
        );
        t.apply(Family::Secrets, "DELETED", &secret("qreta", "pull", "{}"));
        assert!(t.registry_auth("qreta", "ghcr.io").is_none());

        // A non-dockerconfigjson secret never answers, whatever it
        // carries.
        t.apply(
            Family::Secrets,
            "ADDED",
            &json!({
                "apiVersion": "v1", "kind": "Secret",
                "metadata": {"name": "opaque", "namespace": "lo"},
                "type": "Opaque",
                "data": {".dockerconfigjson":
                    base64::engine::general_purpose::STANDARD.encode(config("user:x"))},
            }),
        );
        assert!(t.registry_auth("lo", "ghcr.io").is_none());
    }

    #[test]
    fn the_child_pull_token_decodes_the_node_namespace_secret() {
        // The spawn arm's face, ns-scoped like k8s (a pod's pulls carry
        // the pod's namespace's imagePullSecrets): the NODE ROW'S OWN
        // namespace's lowest dockerconfigjson Secret decodes to the
        // token half (the child's own ladder takes GHCR_TOKEN).
        // Another namespace's secret is another tenant's — never this
        // node's credential.
        use base64::Engine as _;
        let enc = |s: &str| base64::engine::general_purpose::STANDARD.encode(s);
        let secret = |namespace: &str, name: &str, user_token: &str| {
            let config = format!(
                "{{\"auths\":{{\"ghcr.io\":{{\"auth\":\"{}\"}}}}}}",
                enc(user_token)
            );
            json!({
                "apiVersion": "v1", "kind": "Secret",
                "metadata": {"name": name, "namespace": namespace},
                "type": "kubernetes.io/dockerconfigjson",
                "data": {".dockerconfigjson": enc(&config)},
            })
        };
        let mut t = Table::default();
        assert!(t.child_pull_token("mgmt").is_none(), "no secrets, no token");
        t.apply(
            Family::Secrets,
            "ADDED",
            &secret("mgmt", "pull", "user:mgmt-token"),
        );
        assert_eq!(t.child_pull_token("mgmt").as_deref(), Some("mgmt-token"));
        // The tie law inside the namespace: the lowest name wins.
        t.apply(
            Family::Secrets,
            "ADDED",
            &secret("mgmt", "aaa", "user:first-token"),
        );
        assert_eq!(t.child_pull_token("mgmt").as_deref(), Some("first-token"));
        // Another namespace's secret is never this node's credential.
        t.apply(
            Family::Secrets,
            "ADDED",
            &secret("acme", "pull", "user:acme-token"),
        );
        assert_eq!(t.child_pull_token("mgmt").as_deref(), Some("first-token"));
        assert_eq!(t.child_pull_token("acme").as_deref(), Some("acme-token"));
        assert!(t.child_pull_token("lo").is_none());
    }

    #[test]
    fn the_route_family_needs_no_watch_selector() {
        // The k8s model: routes are selective by being typed HttpRoutes,
        // not by a stamp/filter — every family streams unfiltered.
        for f in [
            Family::Httproutes,
            Family::Pods,
            Family::Nodes,
            Family::Kapinodes,
        ] {
            assert_eq!(f.watch_selector(), None, "{}", f.plural());
        }
    }

    #[test]
    fn the_list_paths_split_by_group() {
        assert_eq!(Family::Pods.list_path(), "/api/v1/pods");
        assert_eq!(
            Family::Httproutes.list_path(),
            "/apis/gateway.networking.k8s.io/v1/httproutes"
        );
        assert_eq!(
            Family::WafRules.list_path(),
            "/apis/gateway.qreta.io/v1alpha1/wafrules"
        );
    }

    /// A WafRule CR's ordered rules land in the table and bump the
    /// generation; deleting it clears the rules and bumps again.
    #[test]
    fn wafrule_crs_are_tracked_with_a_generation() {
        let mut t = Table::default();
        assert_eq!(t.waf_rules_generation(), 0);
        let cr = json!({
            "apiVersion": "gateway.qreta.io/v1alpha1", "kind": "WafRule",
            "metadata": {"name": "scanners", "namespace": "acme"},
            "spec": {"rules": [
                {"name": "no-scanners", "expression": r#"http.ua contains "sqlmap""#}
            ]}
        });
        t.apply(Family::WafRules, "ADDED", &cr);
        assert_eq!(t.waf_rules_generation(), 1);
        let rules = t.waf_rules();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].name, "no-scanners");
        t.apply(Family::WafRules, "DELETED", &cr);
        assert_eq!(t.waf_rules_generation(), 2);
        assert!(t.waf_rules().is_empty());
    }

    /// The old law, verbatim: the linear argmax scan over every known
    /// row's patterns (max specificity, ties to the lowest (org, app)).
    /// The live index must answer with exactly this, at every delta.
    fn linear_scan(
        rows: &[(&str, &str, &[&str])],
        host: &str,
        path: &str,
    ) -> Option<(String, String)> {
        let mut best: Option<(usize, (String, String))> = None;
        for (org, app, patterns) in rows {
            for pattern in *patterns {
                if let Some(spec) = route_specificity(pattern, host, path) {
                    let better = match &best {
                        None => true,
                        Some((bs, bk)) => {
                            spec > *bs
                                || (spec == *bs && (*org, *app) < (bk.0.as_str(), bk.1.as_str()))
                        }
                    };
                    if better {
                        best = Some((spec, ((*org).to_owned(), (*app).to_owned())));
                    }
                }
            }
        }
        best.map(|(_, k)| k)
    }

    /// Every probe resolves to what the linear scan says — the index is
    /// a face over the law, never a second opinion.
    fn assert_index_equals_scan(
        t: &Table,
        rows: &[(&str, &str, &[&str])],
        probes: &[(&str, &str)],
    ) {
        for (host, path) in probes {
            let got = t
                .resolve(host, path, addr_map(), None)
                .map(|(r, _)| (r.org, r.app));
            assert_eq!(
                got,
                linear_scan(rows, host, path),
                "resolve({host}, {path}) disagrees with the linear scan"
            );
        }
    }

    #[test]
    fn the_live_index_matches_the_linear_scan_through_deltas() {
        // Owner directive 2026-11-16: vennDB is the live index built
        // from the watch deltas. The deltas below drive the table
        // through upsert / modify / delete / family re-list; at every
        // step the index's answers equal the linear scan over the rows
        // the table SHOULD hold — including the tie-breaks.
        let mut t = Table::default();
        let seed = hr("orders", &["orders.example.com", "orders.example.com/api"]);
        t.apply(Family::Httproutes, "ADDED", &seed);
        let mut rows = vec![(
            "acme",
            "orders",
            ["orders.example.com", "orders.example.com/api"].as_slice(),
        )];
        assert_index_equals_scan(
            &t,
            &rows,
            &[
                ("orders.example.com", "/"),
                ("orders.example.com", "/api/v1"),
                ("orders.example.com", "/apix"),
                ("other.example.com", "/"),
            ],
        );

        // A second org carries the bare host only: the deep probe stays
        // acme's (longer pattern), the shallow probe ties on the bare
        // pattern and breaks to the lowest org — with a RUNNING pod on
        // acme only, a tie-break bug would also swap the node away.
        t.apply(
            Family::Pods,
            "ADDED",
            &json!({
                "metadata": {"name": "acme-orders", "namespace": "acme",
                             "labels": {"app": "orders"}},
                "spec": {"nodeName": "node-a"},
                "status": {"phase": "Running"}
            }),
        );
        t.apply(
            Family::Httproutes,
            "ADDED",
            &hr_ns("beta", "orders", &["orders.example.com"]),
        );
        rows.push(("beta", "orders", ["orders.example.com"].as_slice()));
        assert_index_equals_scan(
            &t,
            &rows,
            &[
                ("orders.example.com", "/api/v1"),
                ("orders.example.com", "/x"),
            ],
        );
        // The tie-break named the org with the pod: the node answers.
        let (r, addr) = t
            .resolve("orders.example.com", "/x", addr_map(), None)
            .unwrap();
        assert_eq!(
            (r.org.as_str(), r.node.as_deref(), addr.as_deref()),
            ("acme", Some("node-a"), Some("10.0.0.1:8080"))
        );

        // The modify drops acme's bare host: the shallow probe flips to
        // beta (route known, no pod — the honest None node).
        t.apply(
            Family::Httproutes,
            "MODIFIED",
            &hr("orders", &["orders.example.com/api"]),
        );
        rows[0].2 = ["orders.example.com/api"].as_slice();
        assert_index_equals_scan(&t, &rows, &[("orders.example.com", "/x")]);
        let (r, addr) = t
            .resolve("orders.example.com", "/x", addr_map(), None)
            .unwrap();
        assert_eq!(
            (r.org.as_str(), r.node.is_none(), addr.is_none()),
            ("beta", true, true)
        );

        // The delete empties beta: the shallow probe falls back to the
        // default node law — nothing matches without a default, the
        // deep probe still names acme.
        t.apply(
            Family::Httproutes,
            "DELETED",
            &hr_ns("beta", "orders", &["orders.example.com"]),
        );
        rows.pop();
        assert_index_equals_scan(
            &t,
            &rows,
            &[
                ("orders.example.com", "/x"),
                ("orders.example.com", "/api/v1"),
            ],
        );

        // The re-list replaces the family WHOLESALE — mixed-case
        // pattern spelling included (the fold is the index's build
        // law) — so the stale "orders" rows are gone while a later
        // delta adds "echo" back.
        t.replace(
            Family::Httproutes,
            &[hr_ns("gamma", "fresh", &["Fresh.Example.COM"])],
        );
        t.apply(
            Family::Httproutes,
            "ADDED",
            &hr_ns("gamma", "echo", &["echo.example.com/ws"]),
        );
        assert_index_equals_scan(
            &t,
            &[
                ("gamma", "fresh", ["Fresh.Example.COM"].as_slice()),
                ("gamma", "echo", ["echo.example.com/ws"].as_slice()),
            ],
            &[
                ("fresh.example.com", "/"),
                ("orders.example.com", "/"),
                ("echo.example.com", "/ws"),
                ("echo.example.com", "/other"),
            ],
        );
        // The REQUEST host stays as-given: a mixed-case request host
        // misses exactly as the matcher's own law demands.
        assert!(
            t.resolve("Fresh.Example.COM", "/", addr_map(), None)
                .is_none()
        );
        // The default node takes the podless fresh route (scale-to-zero).
        let (r, _) = t
            .resolve("fresh.example.com", "/", addr_map(), Some("node-b"))
            .unwrap();
        assert_eq!(r.node.as_deref(), Some("node-b"));
    }

    #[test]
    fn a_pod_delta_never_touches_the_route_index() {
        // Pods and nodes ride their own keyed maps: their deltas
        // rebuild nothing, and a route resolves before and after the
        // pod lands — the binding flips the NODE, never the route.
        let mut t = Table::default();
        t.apply(
            Family::Httproutes,
            "ADDED",
            &hr("orders", &["orders.example.com"]),
        );
        let (r, _addr) = t
            .resolve("orders.example.com", "/", addr_map(), Some("node-b"))
            .unwrap();
        assert_eq!(r.org.as_str(), "acme");
        t.apply(
            Family::Nodes,
            "ADDED",
            &json!({
                "metadata": {"name": "node-b"},
                "status": {"addresses": [{"type": "InternalIP", "address": "192.168.1.9:80"}]}
            }),
        );
        let (_, addr) = t
            .resolve("orders.example.com", "/", addr_map(), Some("node-b"))
            .unwrap();
        assert_eq!(addr.as_deref(), Some("192.168.1.9:80"));
        t.apply(
            Family::Pods,
            "ADDED",
            &json!({
                "metadata": {"name": "acme-orders", "namespace": "acme",
                             "labels": {"app": "orders"}},
                "spec": {"nodeName": "node-a"},
                "status": {"phase": "Running"}
            }),
        );
        let (r, addr) = t
            .resolve("orders.example.com", "/", addr_map(), None)
            .unwrap();
        assert_eq!(r.node.as_deref(), Some("node-a"));
        assert_eq!(addr.as_deref(), Some("10.0.0.1:8080"));
    }
}
