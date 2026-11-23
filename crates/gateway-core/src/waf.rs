//! The WAF filter law (wirefilter): parse Wireshark-like expressions,
//! compile them ONCE into `Arc<Filter>`, and execute them against a
//! request snapshot. A pure law over plain data — no I/O, no clock,
//! `forbid(unsafe)` (the crate-wide wall).
//!
//! The engine is Cloudflare's unreleased 0.7 master of
//! [`wirefilter-engine`](https://github.com/cloudflare/wirefilter) (pinned
//! in Cargo.toml). That version matters: its compiled `Filter` is
//! `Send + Sync` (0.6.1's `Box<dyn Fn>` is not), so a `WafRules` set can
//! be built at boot and shared as one `Arc` across every serving task.
//! Compilation is therefore paid once, not per request — the benchmark
//! (`benches/waf_engines.rs`) measures the difference.
//!
//! Fail-closed posture: if a compiled rule cannot be executed at request
//! time (a scheme/type bug the boot-time parse should have caught), the
//! request is blocked rather than waved through. A WAF that errs must
//! err toward denying traffic.

use std::sync::{Arc, LazyLock};

use serde::{Deserialize, Serialize};
use wirefilter::{ExecutionContext, Filter, Scheme};

/// Path prefixes reserved for the node's private/admin faces. These are
/// NEVER reachable through the public gateway: an admin channel (e.g. an
/// on-demand token-minting endpoint) lives on the node's private listener,
/// and exposing it at the edge would hand the internet a privileged door.
/// The deny is built into the WAF law — it is not an operator-authored
/// `WafRule`, so no config or watched CR can disable it, and it runs even
/// when the configurable ruleset is empty (the WAF's `is_empty` fast path
/// is below this check).
pub const PRIVATE_PATH_PREFIXES: &[&str] = &["/__private/", "/__internal/"];

/// The `x-gateway-waf` rule name stamped on a reserved-prefix block.
pub const PRIVATE_PATH_RULE: &str = "reserved-private-path";

/// Path segments that must never be served from the public edge. These
/// are the names attackers probe for after a misconfigured static-file
/// server exposes a working directory: env files, private keys, VCS and
/// cloud-credential directories, and secret config files. The deny is
/// segment-based (any depth), so `/app/.env`, `/.env`, `/a/b/env.prod`
/// and `/foo/id_rsa` are all blocked — not just one level deep.
///
/// This complements the repo's *secret scanning* (gitleaks, `.gitignore`):
/// scanning stops a secret being committed; these rules stop a secret
/// that is already on disk from being served by accident.
const DENIED_PATH_SEGMENTS: &[&str] = &[
    // env files: `.env`, `app.env`, `env.local`, `env.production`
    ".env",
    "env.local",
    "env.production",
    "env.prod",
    "env.staging",
    "env.dev",
    "env.test",
    "env.example.local",
    // private keys / certs with embedded keys
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "id_rsa.pub",
    ".htpasswd",
    ".netrc",
    ".npmrc",
    ".git-credentials",
    ".gitconfig",
    "credentials",
    "secrets.yaml",
    "secrets.yml",
    "secrets.json",
    "secrets.toml",
    "secret.env",
    // VCS / credential directories (any segment match)
    ".git",
    ".svn",
    ".hg",
    ".ssh",
    ".aws",
    ".kube",
    ".docker",
    ".config",
];

/// Filename suffixes never served at the edge (private keys / certs).
/// Matched on the LAST path segment only.
const DENIED_FILE_SUFFIXES: &[&str] = &[
    ".env", ".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".asc",
];

/// True when `path` starts with one of the reserved private/admin
/// prefixes. A request to exactly `/__private` (no trailing slash) is also
/// denied: the prefixes are directory roots, so a bare root must not slip
/// through while its children are blocked.
#[must_use]
pub fn is_private_prefix(path: &str) -> bool {
    PRIVATE_PATH_PREFIXES.iter().any(|prefix| {
        path.starts_with(prefix)
            || path == prefix.strip_suffix('/').expect("prefix ends in /")
    })
}

/// True when the last segment of `path` is an env/secret file. Covers the
/// `/*/.env`, `/*/*.env`, `/*/env.*` shapes at ANY depth (not just one
/// level) — a single-level matcher would miss `/a/b/.env`.
#[must_use]
pub fn is_secret_file_path(path: &str) -> bool {
    let last = path.rsplit('/').next().unwrap_or(path);
    let lower = last.to_ascii_lowercase();
    // `env.*` / `.env.*` (any extension — `.env.local`, `.env.prod`,
    // `env.production`) and any `*.env` / key suffix.
    if lower.starts_with("env.")
        || lower.starts_with(".env.")
        || DENIED_FILE_SUFFIXES.iter().any(|s| lower.ends_with(s))
    {
        return true;
    }
    DENIED_PATH_SEGMENTS
        .iter()
        .any(|seg| lower == *seg || lower == format!("{seg}.*"))
}

/// True when any segment of `path` is a denied secret/VCS/credential
/// directory name (`.git/`, `.aws/`, `.ssh/`, ...), at any depth.
#[must_use]
pub fn has_secret_dir_segment(path: &str) -> bool {
    path.split('/')
        .any(|seg| DENIED_PATH_SEGMENTS.iter().any(|d| seg.eq_ignore_ascii_case(d)))
}

/// The combined built-in deny: reserved admin prefixes, secret/env
/// files, and secret directory segments — all at any depth.
#[must_use]
pub fn is_private_path(path: &str) -> bool {
    is_private_prefix(path) || is_secret_file_path(path) || has_secret_dir_segment(path)
}

/// Bound the compiled form of a single `matches` regex. wirefilter's
/// default is 10 MiB; keep that cap explicit so a rule author cannot
/// silently raise it by changing the engine's defaults. `regex_automata`
/// is linear-time, so the cap bounds memory, not catastrophic backtracking.
const REGEX_COMPILED_SIZE_LIMIT: usize = 10 * (1 << 20);
/// A wildcard with an unbounded number of `*` metacharacters expands to an
/// unbounded NFA at compile time. wirefilter's default is `usize::MAX`;
/// cap it so a malformed rule is a config refusal, not a memory blowup.
const WILDCARD_STAR_LIMIT: usize = 64;
/// Bound the expression tree depth (wirefilter's default is 128).
const MAX_NESTING_DEPTH: u16 = 128;
/// Bound the number of rules a single CR may contribute. A WAF set is
/// operator-authored, but a typo or a tenant with CR write access must not
/// turn into a gateway-wide compile-time denial of service.
pub const MAX_RULES: usize = 512;

/// One WAF rule: a name for the audit trail, a wirefilter expression,
/// an action, and the response a block returns. `enabled` lets an
/// operator park a rule without deleting it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WafRule {
    /// The rule's identity — stamped on a block so an operator can see
    /// which rule fired without reading its expression.
    pub name: String,
    /// The Wireshark-like filter expression. wirefilter 0.7 supports
    /// `==`, `!=`, `<`/`>` ordering, `contains`, `matches` (regex),
    /// `wildcard`, `in {…}`, `&` (int), boolean `and`/`or`/`not`, and
    /// field truthiness. E.g. `http.method == "POST" and http.ua contains "sqlmap"`.
    pub expression: String,
    /// What to do when the expression matches.
    #[serde(default)]
    pub action: WafAction,
    /// The HTTP status a block returns (default 403).
    #[serde(default = "default_block_status")]
    pub status: u16,
    /// The body a block returns (default "blocked by the WAF\n").
    #[serde(default = "default_block_body")]
    pub body: String,
    /// A parked rule never runs.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_block_status() -> u16 {
    403
}
fn default_block_body() -> String {
    "blocked by the WAF\n".to_owned()
}
fn default_enabled() -> bool {
    true
}

impl Default for WafRule {
    fn default() -> Self {
        Self {
            name: String::new(),
            expression: String::new(),
            action: WafAction::default(),
            status: default_block_status(),
            body: default_block_body(),
            enabled: default_enabled(),
        }
    }
}

/// The action a matching rule takes. `Challenge` uses 503 to signal
/// "come back through the challenge face" instead of a flat 403; that
/// face is not implemented yet, so it is an honest "not served" answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WafAction {
    /// Return the rule's status + body (403 by default).
    #[default]
    Block,
    /// Signal a challenge (503 by default).
    Challenge,
}

/// The request facts the WAF can filter on. Values are borrowed so a
/// serving task builds one view of the inbound request; the gateway
/// constructs it after trimming the client's reserved headers.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WafRequest<'a> {
    /// The request method (e.g. `GET`).
    pub method: &'a str,
    /// The Host header, lowercased, without a `:port` suffix.
    pub host: &'a str,
    /// The URL path (always `/`-prefixed).
    pub path: &'a str,
    /// The raw query string WITHOUT the leading `?` (empty if none).
    pub query: &'a str,
    /// The User-Agent header (empty if absent).
    pub user_agent: &'a str,
    /// The Referer header (empty if absent).
    pub referer: &'a str,
    /// The Content-Type header (empty if absent).
    pub content_type: &'a str,
    /// The client IP, parsed from the connection / the gateway-minted
    /// `x-forwarded-for`. `None` becomes the 0.0.0.0 sentinel at evaluate
    /// time; rules that must distinguish an unknown client from a real
    /// address should gate on the `ip.known` field.
    pub client_ip: Option<std::net::IpAddr>,
    /// The client port (0 when unknown). wirefilter's Int is `i64`.
    pub client_port: i64,
    /// Whether the inbound connection was TLS.
    pub tls: bool,
}

/// The verdict: allow the request through, or block it with a response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WafVerdict {
    /// No enabled rule matched.
    Allow,
    /// A rule matched: the response the gateway returns, and the name
    /// of the rule that fired (for the `x-gateway-waf` header).
    Block {
        rule: String,
        status: u16,
        body: String,
        action: WafAction,
    },
}

impl WafVerdict {
    /// Whether the verdict blocks the request.
    #[must_use]
    pub fn is_blocked(&self) -> bool {
        matches!(self, Self::Block { .. })
    }

    /// The blocking rule's name, if any.
    #[must_use]
    pub fn rule(&self) -> Option<&str> {
        match self {
            Self::Block { rule, .. } => Some(rule),
            Self::Allow => None,
        }
    }
}

/// A configuration-time rule error (a rule that would never compile).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WafRuleError {
    /// The offending rule's name.
    pub rule: String,
    /// The engine's error text.
    pub message: String,
}

impl std::fmt::Display for WafRuleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "waf rule {}: {}", self.rule, self.message)
    }
}

/// The request field registry. `Scheme` is an `Arc` internally, so one
/// shared static serves every evaluation; clones in contexts / filters
/// are pointer-copies with pointer-identity equality.
static SCHEME: LazyLock<Scheme> = LazyLock::new(|| {
    Scheme! {
        http.method: Bytes,
        http.host: Bytes,
        http.path: Bytes,
        http.query: Bytes,
        http.ua: Bytes,
        http.referer: Bytes,
        http.content_type: Bytes,
        ip.addr: Ip,
        // ip.known: true when the client IP came from the connection peer
        // (or the gateway-minted XFF); false when the 0.0.0.0 sentinel was
        // used. Rules that distinguish "unknown client" from a real
        // address must gate on it: `ip.known and not ip.addr in {…}`.
        ip.known: Bool,
        client.port: Int,
        tls: Bool,
    }
    .build()
});

/// The shared scheme (exposed so a caller can build values with the
/// engine directly if it needs to evaluate an ad-hoc expression).
#[must_use]
pub fn scheme() -> &'static Scheme {
    &SCHEME
}

/// The field names the scheme registers, in order. Useful for config
/// validation / operator docs and for the health face.
pub const FIELDS: &[&str] = &[
    "http.method",
    "http.host",
    "http.path",
    "http.query",
    "http.ua",
    "http.referer",
    "http.content_type",
    "ip.addr",
    "ip.known",
    "client.port",
    "tls",
];

/// Cached field handles — looking a field up by name on every request
/// would hash a string ten times; these are `Copy` indices bound to the
/// static scheme.
struct Fields {
    method: wirefilter::FieldRef<'static>,
    host: wirefilter::FieldRef<'static>,
    path: wirefilter::FieldRef<'static>,
    query: wirefilter::FieldRef<'static>,
    ua: wirefilter::FieldRef<'static>,
    referer: wirefilter::FieldRef<'static>,
    content_type: wirefilter::FieldRef<'static>,
    ip: wirefilter::FieldRef<'static>,
    ip_known: wirefilter::FieldRef<'static>,
    port: wirefilter::FieldRef<'static>,
    tls: wirefilter::FieldRef<'static>,
}

// Field handles are looked up against a static, compile-time-declared
// scheme. A missing field here is a programmer error that must fail loudly
// at first use (LazyLock init) — not a request-time panic.
static FIELDS_HANDLES: LazyLock<Fields> = LazyLock::new(|| Fields {
    method: scheme()
        .get_field("http.method")
        .expect("static scheme field"),
    host: scheme()
        .get_field("http.host")
        .expect("static scheme field"),
    path: scheme()
        .get_field("http.path")
        .expect("static scheme field"),
    query: scheme()
        .get_field("http.query")
        .expect("static scheme field"),
    ua: scheme().get_field("http.ua").expect("static scheme field"),
    referer: scheme()
        .get_field("http.referer")
        .expect("static scheme field"),
    content_type: scheme()
        .get_field("http.content_type")
        .expect("static scheme field"),
    ip: scheme().get_field("ip.addr").expect("static scheme field"),
    ip_known: scheme().get_field("ip.known").expect("static scheme field"),
    port: scheme()
        .get_field("client.port")
        .expect("static scheme field"),
    tls: scheme().get_field("tls").expect("static scheme field"),
});

/// One compiled rule: the executable filter plus the operator's block
/// posture. Both are shared behind one `Arc` across all serving tasks.
struct CompiledRule {
    name: String,
    filter: Filter,
    status: u16,
    body: String,
    action: WafAction,
}

/// Compile one wirefilter expression against the shared scheme with the
/// gateway's bounded parser settings. Shared by the WAF ruleset and the
/// rate-limit selectors — one expression language, one set of caps.
pub fn compile_expression(expression: &str) -> Result<Filter, String> {
    let settings = wirefilter::ParserSettings {
        regex_compiled_size_limit: REGEX_COMPILED_SIZE_LIMIT,
        wildcard_star_limit: WILDCARD_STAR_LIMIT,
        max_nesting_depth: MAX_NESTING_DEPTH,
        ..Default::default()
    };
    scheme()
        .parser_with_settings(settings)
        .parse(expression)
        .map(wirefilter::FilterAst::compile)
        .map_err(|e| e.to_string())
}

/// Build an execution context from one request view. Shared by the WAF and
/// the rate-limit selectors so both evaluate the same compiled wirefilter
/// expressions against the same fields. `Err` means the scheme and the
/// literal field types disagree (a programmer error); the caller decides
/// whether to fail open or closed.
pub fn execution_context<'a>(request: &'a WafRequest<'a>) -> Result<ExecutionContext<'a>, String> {
    let fields = &*FIELDS_HANDLES;
    let mut ctx = ExecutionContext::new(scheme());
    let mut set_err: Option<String> = None;
    macro_rules! set {
        ($field:expr, $value:expr) => {
            if let Err(e) = ctx.set_field_value($field, $value) {
                set_err.get_or_insert_with(|| e.to_string());
            }
        };
    }
    set!(fields.method, request.method);
    set!(fields.host, request.host);
    set!(fields.path, request.path);
    set!(fields.query, request.query);
    set!(fields.ua, request.user_agent);
    set!(fields.referer, request.referer);
    set!(fields.content_type, request.content_type);
    let (ip, ip_known) = request.client_ip.map_or(
        (std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), false),
        |addr| (addr, true),
    );
    set!(fields.ip, ip);
    set!(fields.ip_known, ip_known);
    set!(fields.port, request.client_port);
    set!(fields.tls, request.tls);
    match set_err {
        None => Ok(ctx),
        Some(reason) => Err(reason),
    }
}

/// A compiled, shareable ruleset. Build once at boot with
/// [`WafRules::compile`], then call [`WafRules::evaluate`] per request.
/// `Clone` is cheap (Arc per rule) and the whole value is `Send + Sync`.
#[derive(Clone, Default)]
pub struct WafRules {
    rules: Arc<[Arc<CompiledRule>]>,
}

impl WafRules {
    /// Parse + compile every enabled rule against the scheme, ONCE.
    /// Disabled rules are skipped (a parked rule may carry a draft
    /// expression). A bad expression is a `WafRuleError` naming the rule.
    pub fn compile(rules: &[WafRule]) -> Result<Self, WafRuleError> {
        let enabled = rules.iter().filter(|r| r.enabled).count();
        if enabled > MAX_RULES {
            return Err(WafRuleError {
                rule: "<ruleset>".to_owned(),
                message: format!("{enabled} enabled rules exceed the {MAX_RULES} limit"),
            });
        }
        let mut compiled = Vec::with_capacity(enabled);
        for rule in rules.iter().filter(|r| r.enabled) {
            let filter = compile_expression(&rule.expression).map_err(|message| WafRuleError {
                rule: rule.name.clone(),
                message,
            })?;
            compiled.push(Arc::new(CompiledRule {
                name: rule.name.clone(),
                filter,
                status: rule.status,
                body: rule.body.clone(),
                action: rule.action,
            }));
        }
        Ok(Self {
            rules: compiled.into(),
        })
    }

    /// Whether this ruleset has any enabled rules (the WAF is inert
    /// when empty).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Evaluate the rules in order. The first match blocks; no match
    /// allows. A compile/execute failure is fail-closed: a rule that
    /// parses at boot but fails at request time is a scheme/type bug,
    /// and the client gets a denial rather than a free pass.
    #[must_use]
    pub fn evaluate(&self, request: &WafRequest<'_>) -> WafVerdict {
        // Reserved private/admin paths are dropped unconditionally, ahead
        // of the configurable ruleset — including when that ruleset is
        // empty. This is the edge half of the node's admin-channel law:
        // those faces are only ever reachable on the private listener.
        if is_private_path(request.path) {
            return WafVerdict::Block {
                rule: PRIVATE_PATH_RULE.to_owned(),
                status: 404,
                body: "not found\n".to_owned(),
                action: WafAction::Block,
            };
        }
        if self.rules.is_empty() {
            return WafVerdict::Allow;
        }
        let ctx = match execution_context(request) {
            Ok(ctx) => ctx,
            Err(reason) => {
                return WafVerdict::Block {
                    rule: "<field-setup>".to_owned(),
                    status: 403,
                    body: format!("waf field setup failed: {reason}\n"),
                    action: WafAction::Block,
                };
            }
        };

        for compiled in self.rules.iter() {
            let (matched, failure) = match compiled.filter.execute(&ctx) {
                Ok(v) => (v, None),
                // Fail closed on a scheme bug, and carry the reason in
                // the body so an operator can see why the client was
                // denied (this path means validator/compiler disagree).
                Err(e) => (true, Some(e.to_string())),
            };
            if matched {
                let status = match compiled.action {
                    WafAction::Block => compiled.status,
                    // A defaulted Challenge status signals "503"; an
                    // explicitly configured status is honoured verbatim.
                    WafAction::Challenge if compiled.status == default_block_status() => 503,
                    WafAction::Challenge => compiled.status,
                };
                let body = match failure {
                    Some(reason) => format!("{}waf evaluation failed: {reason}\n", compiled.body),
                    None => compiled.body.clone(),
                };
                return WafVerdict::Block {
                    rule: compiled.name.clone(),
                    status,
                    body,
                    action: compiled.action,
                };
            }
        }
        WafVerdict::Allow
    }
}

/// Validate every enabled rule's expression against the scheme at the
/// config boundary — a typo is a loud boot refusal, never a request-time
/// surprise. Disabled rules are skipped (a parked rule may carry a
/// draft expression).
pub fn validate(rules: &[WafRule]) -> Result<(), WafRuleError> {
    WafRules::compile(rules).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(method: &'static str, path: &'static str, ua: &'static str) -> WafRequest<'static> {
        WafRequest {
            method,
            host: "orders.example.com",
            path,
            query: "",
            user_agent: ua,
            content_type: "application/json",
            client_ip: Some("192.0.2.9".parse().unwrap()),
            client_port: 443,
            tls: true,
            ..Default::default()
        }
    }

    fn rule(name: &str, expression: &str) -> WafRule {
        WafRule {
            name: name.to_owned(),
            expression: expression.to_owned(),
            ..Default::default()
        }
    }

    #[test]
    fn private_paths_are_blocked_even_with_no_rules() {
        // The built-in deny runs ahead of the configurable ruleset — an
        // empty WAF must still drop the node's private/admin faces.
        let rules = WafRules::compile(&[]).unwrap();
        for path in [
            "/__private/mint-token",
            "/__private",
            "/__internal/debug",
            "/__internal",
        ] {
            let verdict = rules.evaluate(&request("GET", path, "curl/8"));
            let WafVerdict::Block {
                rule, status, body, ..
            } = verdict
            else {
                panic!("{path} should be blocked, got allow");
            };
            assert_eq!(rule, PRIVATE_PATH_RULE);
            assert_eq!(status, 404);
            assert_eq!(body, "not found\n");
        }
    }

    #[test]
    fn private_paths_are_blocked_before_a_configured_rule() {
        // Even an explicitly allow-ish ruleset cannot open a private path:
        // the built-in check precedes rule evaluation and stamps its own
        // rule name in x-gateway-waf.
        let rules = WafRules::compile(&[rule("allow-all", "http.path != \"\"")]).unwrap();
        let verdict = rules.evaluate(&request("GET", "/__private/anything", "curl/8"));
        assert_eq!(verdict.rule(), Some(PRIVATE_PATH_RULE));
        assert!(verdict.is_blocked());
    }

    #[test]
    fn ordinary_paths_are_unaffected() {
        assert!(!is_private_path("/"));
        assert!(!is_private_path("/api/inbox"));
        assert!(!is_private_path("/__privateish/thing"));
        assert!(!is_private_path("/environment")); // not `env.*`
        assert!(!is_private_path("/api/envelope")); // not `env.*`
        let rules = WafRules::compile(&[]).unwrap();
        assert_eq!(rules.evaluate(&request("GET", "/api/inbox", "curl/8")), WafVerdict::Allow);
    }

    #[test]
    fn env_and_secret_files_are_blocked_at_any_depth() {
        // The explicit shapes the operator asked for, plus deeper paths:
        // one-level-only matching would miss /a/b/.env.
        for path in [
            "/.env",                  // root
            "/app/.env",              // /*/.env
            "/a/b/.env",              // deeper
            "/config/app.env",        // /*/*.env
            "/a/b/service.env",       // deeper *.env
            "/env.local",             // /*/env.* (root)
            "/foo/env.production",    // /*/env.*
            "/foo/bar/env.json",      // deeper env.*
            "/app/id_rsa",            // private key
            "/static/server.pem",     // key-bearing cert
            "/secrets.yaml",          // secret config
            "/.git/config",           // VCS metadata dir
            "/a/.aws/credentials",    // cloud credentials dir
            "/x/.ssh/id_ed25519",     // ssh key
        ] {
            assert!(is_private_path(path), "{path} should be blocked");
        }
    }

    #[test]
    fn secret_paths_are_blocked_in_the_waf_verdict() {
        let rules = WafRules::compile(&[]).unwrap();
        for path in ["/.env", "/app/.env", "/config/.env.local", "/a/.git/config"] {
            let verdict = rules.evaluate(&request("GET", path, "curl/8"));
            assert_eq!(verdict.rule(), Some(PRIVATE_PATH_RULE), "{path}");
            assert!(verdict.is_blocked());
        }
    }

    #[test]
    fn a_matching_expression_blocks() {
        let rules =
            WafRules::compile(&[rule("no-scanners", r#"http.ua contains "sqlmap""#)]).unwrap();
        let verdict = rules.evaluate(&request("GET", "/", "sqlmap/1.2"));
        let WafVerdict::Block { rule, status, .. } = verdict else {
            panic!("expected a block");
        };
        assert_eq!(rule, "no-scanners");
        assert_eq!(status, 403);
    }

    #[test]
    fn a_non_matching_expression_allows() {
        let rules =
            WafRules::compile(&[rule("no-scanners", r#"http.ua contains "sqlmap""#)]).unwrap();
        assert_eq!(
            rules.evaluate(&request("GET", "/", "Mozilla/5.0")),
            WafVerdict::Allow
        );
    }

    #[test]
    fn the_first_matching_rule_wins() {
        let rules = WafRules::compile(&[
            rule("first", r#"http.method == "GET""#),
            rule("second", r#"http.path == "/""#),
        ])
        .unwrap();
        assert_eq!(
            rules.evaluate(&request("GET", "/", "ua")).rule(),
            Some("first")
        );
    }

    #[test]
    fn a_disabled_rule_never_runs() {
        let mut parked = rule("parked", r#"http.method == "GET""#);
        parked.enabled = false;
        let rules = WafRules::compile(&[parked]).unwrap();
        assert!(rules.is_empty());
        assert_eq!(
            rules.evaluate(&request("GET", "/", "ua")),
            WafVerdict::Allow
        );
    }

    #[test]
    fn ip_query_port_and_tls_are_filterable() {
        let rules = WafRules::compile(&[
            rule("private-source", r#"ip.addr in {10.0.0.0/8 192.0.2.0/24}"#),
            rule("query-string", r#"http.query contains "id=""#),
            rule("cleartext", r#"not tls"#),
        ])
        .unwrap();
        let mut req = request("GET", "/", "ua");
        req.query = "id=42";
        assert_eq!(rules.evaluate(&req).rule(), Some("private-source"));
        req.client_ip = Some("198.51.100.7".parse().unwrap());
        assert_eq!(rules.evaluate(&req).rule(), Some("query-string"));
        req.query = "";
        req.tls = false;
        assert_eq!(rules.evaluate(&req).rule(), Some("cleartext"));
    }

    #[test]
    fn an_unknown_client_ip_never_panics_a_rule_that_reads_it() {
        let mut req = request("GET", "/", "ua");
        req.client_ip = None;
        let rules =
            WafRules::compile(&[rule("private-source", r#"ip.addr in {10.0.0.0/8}"#)]).unwrap();
        assert_eq!(rules.evaluate(&req), WafVerdict::Allow);
    }

    #[test]
    fn ip_known_distinguishes_the_unknown_client_sentinel() {
        // An inverted rule (`not ip.addr in {…}`) would let an unknown
        // client through on the 0.0.0.0 sentinel unless it gates on
        // `ip.known`. This is the documented safe spelling.
        let rules =
            WafRules::compile(&[rule("unknown-ip", r#"not ip.known and ip.addr == 0.0.0.0"#)])
                .unwrap();
        let mut req = request("GET", "/", "ua");
        req.client_ip = None;
        assert_eq!(rules.evaluate(&req).rule(), Some("unknown-ip"));
        req.client_ip = Some("192.0.2.9".parse().unwrap());
        assert_eq!(rules.evaluate(&req), WafVerdict::Allow);
    }

    #[test]
    fn a_ruleset_beyond_the_cap_is_refused() {
        let rules: Vec<_> = (0..MAX_RULES + 1)
            .map(|i| rule(&format!("r{i}"), r#"http.method == "GET""#))
            .collect();
        let err = match WafRules::compile(&rules) {
            Ok(_) => panic!("an oversized ruleset must be refused"),
            Err(err) => err,
        };
        assert!(err.message.contains("exceed"), "{err:?}");
    }

    #[test]
    fn an_unbounded_wildcard_is_refused_at_compile_time() {
        let many_stars = "*".repeat(WILDCARD_STAR_LIMIT + 1);
        let expr = format!(r#"http.ua wildcard "{}""#, many_stars);
        assert!(validate(&[rule("wild", &expr)]).is_err());
    }

    #[test]
    fn challenge_uses_503_and_custom_status_is_respected() {
        let mut challenge = rule("challenge", r#"http.method == "POST""#);
        challenge.action = WafAction::Challenge;
        let rules = WafRules::compile(&[challenge]).unwrap();
        assert_eq!(
            rules.evaluate(&request("POST", "/", "ua")),
            WafVerdict::Block {
                rule: "challenge".to_owned(),
                status: 503,
                body: default_block_body(),
                action: WafAction::Challenge,
            }
        );
        let mut custom = rule("teapot", r#"http.method == "POST""#);
        custom.status = 418;
        let rules = WafRules::compile(&[custom]).unwrap();
        assert_eq!(
            rules.evaluate(&request("POST", "/", "ua")),
            WafVerdict::Block {
                rule: "teapot".to_owned(),
                status: 418,
                body: default_block_body(),
                action: WafAction::Block,
            }
        );
    }

    #[test]
    fn validate_rejects_bad_expressions_and_skips_disabled_rules() {
        assert!(validate(&[rule("bad", "http.method ===")]).is_err());
        assert!(validate(&[rule("unknown-field", "nope == 1")]).is_err());
        let mut parked = rule("parked", "nonsense !!!");
        parked.enabled = false;
        assert!(validate(&[parked]).is_ok());
    }

    #[test]
    fn every_scheme_field_is_set_on_every_evaluation() {
        let rules = WafRules::compile(&[rule("ok", r#"tls and client.port == 443"#)]).unwrap();
        assert_eq!(
            rules.evaluate(&request("GET", "/", "ua")).rule(),
            Some("ok")
        );
    }

    #[test]
    fn defaults_are_operator_friendly() {
        let r: WafRule = serde_json::from_str(r#"{"name":"x","expression":"tls"}"#).unwrap();
        assert_eq!(r.status, 403);
        assert_eq!(r.body, "blocked by the WAF\n");
        assert!(r.enabled);
        assert_eq!(r.action, WafAction::Block);
    }

    #[test]
    fn compiled_rules_are_send_and_sync_for_sharing_across_tasks() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<WafRules>();
    }
}
