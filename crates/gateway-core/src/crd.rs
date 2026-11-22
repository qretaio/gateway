//! Wire types for the gateway's typed custom resources. Pure serde over
//! plain data — no I/O, no clock, no `unsafe` (the crate-wide wall).
//!
//! The gateway watches its OWN CRDs from kapi under the
//! `gateway.qreta.io/v1alpha1` group (native k8s model: the group names
//! the serving surface that owns the kind). The CRD derive itself lives
//! in the consumer that owns `kube` (wisolate's crdgen); the gateway and
//! the kapi controller parse/emit these types over the generic CR
//! surface, exactly as they do for `PublicAssets`.

use serde::{Deserialize, Serialize};

use crate::waf::WafAction;

/// The API group/version every gateway-owned CR rides.
pub const GROUP_VERSION: &str = "gateway.qreta.io/v1alpha1";

/// The plural path segment of the `WafRule` kind (the kapi watch/list
/// path is `{GROUP_VERSION}/{PLURAL}`).
pub const WAF_RULE_PLURAL: &str = "wafrules";

/// One rule in a `WafRule` CR's `spec.rules`. The wire spelling is
/// camelCase (`blockStatus`, `blockBody`) so a CR reads like every other
/// k8s resource; `Default` keeps the operator surface friendly. This is
/// the CRD's shape, deliberately distinct from the law's [`crate::waf::WafRule`]
/// (TOML snake_case) — the gateway folds both into one compiled ruleset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WafRuleEntry {
    /// The rule's identity — stamped on a block (`x-gateway-waf`) so an
    /// operator can see which rule fired.
    pub name: String,
    /// The Wireshark-like wirefilter expression. Compiled once when the
    /// CR set changes; a bad expression is rejected at the watch seam.
    pub expression: String,
    /// What to do when the expression matches (default `block`).
    #[serde(default)]
    pub action: WafAction,
    /// The HTTP status a block returns (default 403).
    #[serde(default = "default_block_status")]
    pub status: u16,
    /// The body a block returns (default "blocked by the WAF\n").
    #[serde(default = "default_block_body")]
    pub body: String,
    /// A parked rule never runs (default true).
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

impl Default for WafRuleEntry {
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

/// The `WafRule` CR spec: an ordered set of wirefilter rules. Order is
/// significant — the first matching rule blocks. No `enabled` at the
/// spec level; an empty ruleset is an inert WAF layer.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WafRuleSpec {
    /// The ordered rules. The first match blocks; no match allows.
    #[serde(default)]
    pub rules: Vec<WafRuleEntry>,
}

/// The CR's `status`: operator-facing diagnostics. The gateway is
/// read-only on these; the controller stamps validation outcomes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WafRuleStatus {
    /// A controller note when a rule set could not be compiled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_cr_spec_is_an_inert_ruleset() {
        let spec: WafRuleSpec = serde_json::from_str("{}").unwrap();
        assert!(spec.rules.is_empty());
    }

    #[test]
    fn a_rule_entry_parses_with_operator_friendly_defaults() {
        let entry: WafRuleEntry = serde_json::from_str(
            r#"{"name":"no-scanners","expression":"http.ua contains \"sqlmap\""}"#,
        )
        .unwrap();
        assert_eq!(entry.status, 403);
        assert_eq!(entry.body, "blocked by the WAF\n");
        assert!(entry.enabled);
        assert_eq!(entry.action, WafAction::Block);
    }
}
