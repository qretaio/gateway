//! Response hardening law: the security headers the public edge stamps
//! on every response. Pure over config + a response-builder-ish view —
//! the gateway applies these to its own responses and to proxied ones.
//!
//! Everything is opt-in via [`HardeningConfig`] so an operator can tune
//! per deployment; defaults are sane for a public HTTPS edge. The law
//! never removes an existing upstream header of the same name (the
//! caller decides precedence) — it only produces the values to set.

use serde::{Deserialize, Serialize};

/// Response hardening configuration (`[hardening]`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardeningConfig {
    /// Emit Strict-Transport-Security (seconds; 0 = off).
    #[serde(default = "default_hsts")]
    pub hsts_max_age: u64,
    /// Include subdomains in HSTS.
    #[serde(default = "yes")]
    pub hsts_include_subdomains: bool,
    /// Emit X-Content-Type-Options: nosniff.
    #[serde(default = "yes")]
    pub nosniff: bool,
    /// Emit Referrer-Policy.
    #[serde(default = "default_referrer_policy")]
    pub referrer_policy: String,
    /// Emit X-Frame-Options.
    #[serde(default = "default_frame_options")]
    pub frame_options: String,
    /// Emit Permissions-Policy.
    #[serde(default = "default_permissions_policy")]
    pub permissions_policy: String,
    /// Emit a default CSP on responses that lack one.
    #[serde(default = "default_csp")]
    pub content_security_policy: String,
    /// Emit X-XSS-Protection (legacy; modern CSP supersedes it).
    #[serde(default)]
    pub xss_protection: bool,
}

fn yes() -> bool { true }
fn default_hsts() -> u64 { 31_536_000 } // 1 year
fn default_referrer_policy() -> String { "strict-origin-when-cross-origin".to_owned() }
fn default_frame_options() -> String { "DENY".to_owned() }
fn default_permissions_policy() -> String {
    "camera=(), microphone=(), geolocation=(), payment=()".to_owned()
}
fn default_csp() -> String { "default-src 'self'; base-uri 'none'; frame-ancestors 'none'".to_owned() }

impl Default for HardeningConfig {
    fn default() -> Self {
        Self {
            hsts_max_age: default_hsts(),
            hsts_include_subdomains: true,
            nosniff: true,
            referrer_policy: default_referrer_policy(),
            frame_options: default_frame_options(),
            permissions_policy: default_permissions_policy(),
            content_security_policy: default_csp(),
            xss_protection: false,
        }
    }
}

impl HardeningConfig {
    /// Off = every emission disabled (hardening face inert).
    pub fn disabled() -> Self {
        Self {
            hsts_max_age: 0,
            hsts_include_subdomains: false,
            nosniff: false,
            referrer_policy: String::new(),
            frame_options: String::new(),
            permissions_policy: String::new(),
            content_security_policy: String::new(),
            xss_protection: false,
        }
    }

    /// The `(name, value)` pairs to stamp, in a stable order. Empty values
    /// mean "don't emit". Callers apply them to the response builder.
    #[must_use]
    pub fn headers(&self) -> Vec<(&'static str, String)> {
        let mut out = Vec::new();
        if self.hsts_max_age > 0 {
            let mut v = format!("max-age={}", self.hsts_max_age);
            if self.hsts_include_subdomains {
                v.push_str("; includeSubDomains");
            }
            out.push(("strict-transport-security", v));
        }
        if self.nosniff {
            out.push(("x-content-type-options", "nosniff".to_owned()));
        }
        if !self.referrer_policy.is_empty() {
            out.push(("referrer-policy", self.referrer_policy.clone()));
        }
        if !self.frame_options.is_empty() {
            out.push(("x-frame-options", self.frame_options.clone()));
        }
        if !self.permissions_policy.is_empty() {
            out.push(("permissions-policy", self.permissions_policy.clone()));
        }
        if !self.content_security_policy.is_empty() {
            out.push(("content-security-policy", self.content_security_policy.clone()));
        }
        if self.xss_protection {
            out.push(("x-xss-protection", "0".to_owned()));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_emit_the_expected_headers() {
        let h = HardeningConfig::default().headers();
        let names: Vec<_> = h.iter().map(|(n, _)| *n).collect();
        assert_eq!(
            names,
            vec![
                "strict-transport-security",
                "x-content-type-options",
                "referrer-policy",
                "x-frame-options",
                "permissions-policy",
                "content-security-policy",
            ]
        );
        assert_eq!(h[0].1, "max-age=31536000; includeSubDomains");
    }

    #[test]
    fn disabled_emits_nothing() {
        assert!(HardeningConfig::disabled().headers().is_empty());
    }

    #[test]
    fn tuning_works() {
        let c = HardeningConfig {
            hsts_max_age: 0,
            content_security_policy: String::new(),
            ..Default::default()
        };
        let h = c.headers();
        assert!(!h.iter().any(|(n, _)| *n == "strict-transport-security"));
        assert!(!h.iter().any(|(n, _)| *n == "content-security-policy"));
        assert!(h.iter().any(|(n, _)| *n == "x-content-type-options"));
    }
}
