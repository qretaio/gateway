//! The live rate-limit ruleset: static TOML rules (global) plus the
//! namespace-local rules watched from `RateLimit` CRs, folded into one
//! compiled set. Selectors are wirefilter expressions sharing the WAF's
//! scheme and parser; they compile once off the request path and are
//! shared as `Arc<Filter>` across serving tasks. A watch delta recompiles
//! the whole set behind a generation gate with a last-good fallback.
//!
//! Namespace-local means a CR in namespace `acme` only applies to requests
//! whose resolved route belongs to `acme`. Static rules have no namespace
//! and apply everywhere.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use gateway_core::crd::{RateLimitEntry, RateLimitKeySource};
use gateway_core::ratelimit::{RateLimitRule as StaticRateRule, build_key};
use wirefilter::Filter;

/// One compiled rule: the selector plus the counter posture and key
/// sources. `namespace: None` means the static/global set.
#[derive(Debug, Clone)]
pub struct CompiledRateRule {
    pub name: String,
    /// `None` = empty selector (matches every request). Held behind Arc so
    /// the rule stays Clone and the compiled filter is shared across tasks.
    pub filter: Option<Arc<Filter>>,
    pub limit: u32,
    pub window: Duration,
    pub key_sources: Vec<RateLimitKeySource>,
    /// Static-rule legacy shape: key on IP + method + host + path.
    pub per_route: bool,
    pub namespace: Option<String>,
}

impl CompiledRateRule {
    /// Whether this rule applies to a request in `namespace`. Static rules
    /// (no namespace) apply everywhere; CR rules only in their namespace.
    #[must_use]
    pub fn applies_to(&self, namespace: Option<&str>) -> bool {
        match &self.namespace {
            None => true,
            Some(rule_ns) => namespace == Some(rule_ns.as_str()),
        }
    }

    /// Build the counter bucket for this rule. The IP is always the
    /// leading component; a static `per_route` rule appends the route, a
    /// CR rule appends its dynamic header values via the pure law.
    #[must_use]
    pub fn bucket(
        &self,
        ip: std::net::IpAddr,
        headers: &std::collections::BTreeMap<String, String>,
        method: &str,
        host: &str,
        path: &str,
    ) -> String {
        let mut key = if self.per_route {
            format!("{ip}|{method} {host}{path}")
        } else {
            build_key(ip, headers, &self.key_sources)
        };
        // Namespace + rule name keep identically named rules in different
        // namespaces from sharing a counter.
        if let Some(ns) = &self.namespace {
            key = format!("{ns}|{}|{key}", self.name);
        } else {
            key = format!("static|{}|{key}", self.name);
        }
        key
    }

    /// Evaluate the compiled selector. An empty selector (`None`) matches
    /// everything; a field-set failure fails CLOSED (treat as a match so a
    /// scheme bug cannot silently skip a limit).
    #[must_use]
    pub fn matches(&self, request: &gateway_core::waf::WafRequest<'_>) -> bool {
        let Some(filter) = &self.filter else {
            return true;
        };
        match gateway_core::waf::execution_context(request) {
            Ok(ctx) => filter.execute(&ctx).unwrap_or(true),
            Err(_) => true,
        }
    }
}

/// A compiled, shareable ruleset. `Clone` is cheap (Arc per rule).
#[derive(Clone, Default)]
pub struct CompiledRateRules {
    rules: Arc<[Arc<CompiledRateRule>]>,
}

impl CompiledRateRules {
    /// The rules that apply in `namespace`, in compile order (static first,
    /// then watched CRs in namespace/name order).
    #[must_use]
    pub fn for_namespace(&self, namespace: Option<&str>) -> Vec<Arc<CompiledRateRule>> {
        self.rules
            .iter()
            .filter(|r| r.applies_to(namespace))
            .cloned()
            .collect()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

/// The state: static rules seeded at boot; the watched CR half folds in on
/// a generation change. Reads clone the current `Arc` cheaply.
pub struct RateLimitState {
    static_rules: Arc<[StaticRateRule]>,
    compiled: std::sync::RwLock<Arc<CompiledRateRules>>,
    generation: AtomicU64,
    attempted: AtomicU64,
}

impl RateLimitState {
    /// Seed from static TOML rules. An empty set is valid (the CR half may
    /// still populate it on the first request after the watch lands).
    #[must_use]
    pub fn new(static_rules: &[StaticRateRule]) -> Self {
        let compiled =
            compile_all(static_rules, &[]).expect("static rate limits validated at load");
        Self {
            static_rules: static_rules.to_vec().into(),
            compiled: std::sync::RwLock::new(Arc::new(compiled)),
            generation: AtomicU64::new(0),
            attempted: AtomicU64::new(0),
        }
    }

    /// The compiled ruleset for the current watched generation. `watched`
    /// is the namespace-keyed set from the table. A compile failure keeps
    /// the last-good ruleset (the offending CR is skipped/logged).
    #[must_use]
    pub fn rules(
        &self,
        watched: &[(String, Vec<RateLimitEntry>)],
        watched_generation: u64,
    ) -> Arc<CompiledRateRules> {
        if watched_generation != self.generation.load(Ordering::Acquire)
            && watched_generation != self.attempted.load(Ordering::Acquire)
        {
            self.attempted.store(watched_generation, Ordering::Release);
            match compile_all(&self.static_rules, watched) {
                Ok(next) => {
                    let next = Arc::new(next);
                    *self.compiled.write().expect("rate compiled lock") = Arc::clone(&next);
                    self.generation.store(watched_generation, Ordering::Release);
                    return next;
                }
                Err(err) => {
                    eprintln!("[gateway] RateLimit CR set refused: {err}");
                }
            }
        }
        Arc::clone(&self.compiled.read().expect("rate compiled lock"))
    }
}

/// Compile static rules (global) plus watched CR rules (namespace-scoped)
/// into one shared set. An enabled rule with a bad selector is a hard error
/// for the whole fold — the caller keeps the last-good set; a bad CR is
/// skipped by the table's row parser before it reaches here.
fn compile_all(
    static_rules: &[StaticRateRule],
    watched: &[(String, Vec<RateLimitEntry>)],
) -> Result<CompiledRateRules, String> {
    let mut rules: Vec<Arc<CompiledRateRule>> = Vec::new();
    for rule in static_rules {
        rules.push(Arc::new(CompiledRateRule {
            name: rule.name.clone(),
            // Static rules keep the legacy per-route key shape via an
            // empty selector and no dynamic sources; the bucket key is
            // built by the caller from IP + route facts.
            filter: None,
            limit: rule.limit,
            window: Duration::from_secs(rule.window_secs),
            key_sources: Vec::new(),
            per_route: rule.per_route,
            namespace: None,
        }));
    }
    for (namespace, entries) in watched {
        for entry in entries.iter().filter(|e| e.enabled) {
            let filter = if entry.filter.trim().is_empty() {
                None
            } else {
                Some(Arc::new(
                    gateway_core::waf::compile_expression(&entry.filter)
                        .map_err(|e| format!("rate limit {}: {e}", entry.name))?,
                ))
            };
            rules.push(Arc::new(CompiledRateRule {
                name: entry.name.clone(),
                filter,
                limit: entry.limit,
                window: Duration::from_secs(entry.window_secs),
                key_sources: entry.key.clone(),
                per_route: false,
                namespace: Some(namespace.clone()),
            }));
        }
    }
    Ok(CompiledRateRules {
        rules: rules.into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespace_scoping_selects_only_matching_rules() {
        let rules = CompiledRateRules {
            rules: vec![
                Arc::new(CompiledRateRule {
                    name: "global".into(),
                    filter: None,
                    limit: 10,
                    window: Duration::from_secs(60),
                    key_sources: Vec::new(),
                    per_route: false,
                    namespace: None,
                }),
                Arc::new(CompiledRateRule {
                    name: "acme-only".into(),
                    filter: None,
                    limit: 5,
                    window: Duration::from_secs(60),
                    key_sources: Vec::new(),
                    per_route: false,
                    namespace: Some("acme".into()),
                }),
            ]
            .into(),
        };
        let acme: Vec<_> = rules
            .for_namespace(Some("acme"))
            .iter()
            .map(|r| r.name.clone())
            .collect();
        assert_eq!(acme, ["global", "acme-only"]);
        let other: Vec<_> = rules
            .for_namespace(Some("other"))
            .iter()
            .map(|r| r.name.clone())
            .collect();
        assert_eq!(other, ["global"]);
        // An unresolved request (no namespace) only sees global rules.
        let none: Vec<_> = rules
            .for_namespace(None)
            .iter()
            .map(|r| r.name.clone())
            .collect();
        assert_eq!(none, ["global"]);
    }

    #[test]
    fn bucket_includes_dynamic_header_values() {
        let mut headers = std::collections::BTreeMap::new();
        headers.insert("x-api-key".to_owned(), "tenant-a".to_owned());
        let rule = CompiledRateRule {
            name: "per-tenant".into(),
            filter: None,
            limit: 1,
            window: Duration::from_secs(60),
            key_sources: vec![RateLimitKeySource::Header("x-api-key".to_owned())],
            per_route: false,
            namespace: Some("acme".into()),
        };
        let ip = "192.0.2.1".parse().unwrap();
        let a = rule.bucket(ip, &headers, "GET", "h", "/");
        headers.insert("x-api-key".to_owned(), "tenant-b".to_owned());
        let b = rule.bucket(ip, &headers, "GET", "h", "/");
        assert_ne!(a, b, "{a} vs {b}");
        assert!(a.contains("tenant-a"), "{a}");
    }

    #[test]
    fn an_empty_selector_matches_everything() {
        let rule = CompiledRateRule {
            name: "all".into(),
            filter: None,
            limit: 1,
            window: Duration::from_secs(60),
            key_sources: Vec::new(),
            per_route: false,
            namespace: None,
        };
        let req = gateway_core::waf::WafRequest::default();
        assert!(rule.matches(&req));
    }

    #[test]
    fn a_generation_delta_folds_watched_rules_in() {
        let state = RateLimitState::new(&[]);
        let watched = [(
            "acme".to_owned(),
            vec![RateLimitEntry {
                name: "cr".into(),
                limit: 3,
                window_secs: 30,
                ..Default::default()
            }],
        )];
        let rules = state.rules(&watched, 1);
        assert_eq!(rules.for_namespace(Some("acme")).len(), 1);
        assert_eq!(state.generation.load(Ordering::Acquire), 1);
    }
}
