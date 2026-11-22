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
    /// The client IP, parsed from the connection / `x-forwarded-for`.
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
    port: wirefilter::FieldRef<'static>,
    tls: wirefilter::FieldRef<'static>,
}

static FIELDS_HANDLES: LazyLock<Fields> = LazyLock::new(|| Fields {
    method: scheme().get_field("http.method").expect("field"),
    host: scheme().get_field("http.host").expect("field"),
    path: scheme().get_field("http.path").expect("field"),
    query: scheme().get_field("http.query").expect("field"),
    ua: scheme().get_field("http.ua").expect("field"),
    referer: scheme().get_field("http.referer").expect("field"),
    content_type: scheme().get_field("http.content_type").expect("field"),
    ip: scheme().get_field("ip.addr").expect("field"),
    port: scheme().get_field("client.port").expect("field"),
    tls: scheme().get_field("tls").expect("field"),
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
        let mut compiled = Vec::new();
        for rule in rules.iter().filter(|r| r.enabled) {
            let filter = scheme()
                .parse(&rule.expression)
                .map_err(|e| WafRuleError {
                    rule: rule.name.clone(),
                    message: e.to_string(),
                })?
                .compile();
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
        if self.rules.is_empty() {
            return WafVerdict::Allow;
        }
        let fields = &*FIELDS_HANDLES;
        let mut ctx = ExecutionContext::new(scheme());
        // Always set every field, even when a value is absent: an unset
        // field makes the engine panic. 0.0.0.0 is the honest sentinel
        // for "unknown client" — no real route owns it, so an
        // `ip.addr in {…}` rule simply does not match.
        ctx.set_field_value(fields.method, request.method)
            .expect("checked: Bytes field");
        let _ = ctx.set_field_value(fields.host, request.host);
        let _ = ctx.set_field_value(fields.path, request.path);
        let _ = ctx.set_field_value(fields.query, request.query);
        let _ = ctx.set_field_value(fields.ua, request.user_agent);
        let _ = ctx.set_field_value(fields.referer, request.referer);
        let _ = ctx.set_field_value(fields.content_type, request.content_type);
        ctx.set_field_value(
            fields.ip,
            request
                .client_ip
                .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
        )
        .expect("checked: Ip field");
        ctx.set_field_value(fields.port, request.client_port)
            .expect("checked: Int field");
        ctx.set_field_value(fields.tls, request.tls)
            .expect("checked: Bool field");

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
