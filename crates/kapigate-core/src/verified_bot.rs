//! The verified-bot law: forward-confirmed reverse DNS (FCrDNS). A peer IP
//! is a verified crawler only when its PTR hostname ends with an allowed
//! suffix AND that hostname resolves forward back to the same IP. A bare
//! PTR suffix match is NOT enough — anyone with control of a PTR record
//! can claim `*.googlebot.com`; the forward confirmation closes that hole.
//!
//! Pure over plain data: the DNS I/O and the bounded, TTL'd cache live in
//! the gateway crate ([`kapigate::bot_state`]). This module answers only
//! "do these three facts constitute a verified bot", so the rule is
//! testable with a hostname and an IP list and no resolver.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

/// The verified-bot config (`[verified_bots]`). Off by default: this is an
/// allowlist exemption from the WAF and rate limiter, so enabling it is an
/// explicit operator choice.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VerifiedBotConfig {
    /// Apply the exemption at all.
    #[serde(default)]
    pub enabled: bool,
    /// PTR hostnames must end with one of these suffixes, on a label
    /// boundary (e.g. `.googlebot.com`, `.bing.com`). Leading dot is
    /// optional in config and normalized by [`Self::normalized_suffixes`].
    #[serde(default)]
    pub allowed_suffixes: Vec<String>,
    /// How long a positive or negative verification is cached, seconds.
    #[serde(default = "default_cache_ttl_secs")]
    pub cache_ttl_secs: u64,
    /// Per-lookup DNS timeout, milliseconds. A timeout fails CLOSED for
    /// the exemption (the client is treated as a normal request).
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    /// Bound on cached IPs. Beyond it the cache evicts the oldest entry —
    /// otherwise a hostile stream of source IPs grows it without limit.
    #[serde(default = "default_cache_max_entries")]
    pub cache_max_entries: usize,
}

fn default_cache_ttl_secs() -> u64 {
    600
}
fn default_timeout_ms() -> u64 {
    1500
}
fn default_cache_max_entries() -> usize {
    4096
}

impl Default for VerifiedBotConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            allowed_suffixes: Vec::new(),
            cache_ttl_secs: default_cache_ttl_secs(),
            timeout_ms: default_timeout_ms(),
            cache_max_entries: default_cache_max_entries(),
        }
    }
}

impl VerifiedBotConfig {
    /// Normalize config suffixes: lowercase, strip a trailing dot (DNS
    /// absolute form), and ensure a leading dot so matching is on a label
    /// boundary (`notgooglebot.com` must never match `.googlebot.com`).
    #[must_use]
    pub fn normalized_suffixes(&self) -> Vec<String> {
        self.allowed_suffixes
            .iter()
            .map(|s| {
                let s = s.trim().trim_end_matches('.').to_ascii_lowercase();
                if s.starts_with('.') {
                    s
                } else {
                    format!(".{s}")
                }
            })
            .collect()
    }

    /// Validate the config at the config boundary. An enabled allowlist
    /// with no suffixes can never verify anything — refuse it so an
    /// operator does not ship a silent no-op.
    pub fn validate(&self) -> Result<(), String> {
        if self.enabled && self.allowed_suffixes.iter().all(|s| s.trim().is_empty()) {
            return Err("verified_bots.enabled needs at least one allowed_suffix".to_owned());
        }
        if self.cache_ttl_secs == 0 {
            return Err("verified_bots.cache_ttl_secs must be > 0".to_owned());
        }
        if self.timeout_ms == 0 {
            return Err("verified_bots.timeout_ms must be > 0".to_owned());
        }
        if self.cache_max_entries == 0 {
            return Err("verified_bots.cache_max_entries must be > 0".to_owned());
        }
        Ok(())
    }
}

/// Forward-confirm a reverse hostname against a peer IP. The hostname is
/// lowercased and its trailing dot (DNS absolute form) is ignored. Returns
/// true only when both proofs hold:
///   1. the hostname ends with an allowed suffix on a label boundary;
///   2. the hostname's forward A/AAAA set contains the peer IP.
#[must_use]
pub fn verify_fcrdns(
    reverse_host: &str,
    forward_ips: &[IpAddr],
    peer: IpAddr,
    allowed_suffixes: &[String],
) -> bool {
    let host = reverse_host
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    let suffix_ok = allowed_suffixes
        .iter()
        .any(|suffix| host.ends_with(suffix.as_str()));
    suffix_ok && forward_ips.contains(&peer)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn fcrdns_requires_both_the_suffix_and_the_forward_match() {
        let suffixes = [".googlebot.com".to_owned()];
        // Both proofs hold.
        assert!(verify_fcrdns(
            "crawl-1.googlebot.com.",
            &[ip("66.249.66.1")],
            ip("66.249.66.1"),
            &suffixes
        ));
        // PTR suffix is right but the IP does not forward-confirm.
        assert!(!verify_fcrdns(
            "crawl-1.googlebot.com.",
            &[ip("66.249.66.2")],
            ip("66.249.66.99"),
            &suffixes
        ));
        // Forward confirms but the suffix is not allowlisted.
        assert!(!verify_fcrdns(
            "evil.example.com.",
            &[ip("66.249.66.1")],
            ip("66.249.66.1"),
            &suffixes
        ));
    }

    #[test]
    fn suffix_match_is_on_a_label_boundary() {
        let suffixes = [".googlebot.com".to_owned()];
        assert!(!verify_fcrdns(
            "notgooglebot.com.",
            &[ip("66.249.66.1")],
            ip("66.249.66.1"),
            &suffixes
        ));
        assert!(verify_fcrdns(
            "foo.bar.googlebot.com.",
            &[ip("66.249.66.1")],
            ip("66.249.66.1"),
            &suffixes
        ));
    }

    #[test]
    fn config_normalizes_and_validates_suffixes() {
        let cfg = VerifiedBotConfig {
            enabled: true,
            allowed_suffixes: vec!["GoogleBot.COM.".to_owned(), ".bing.com".to_owned()],
            ..Default::default()
        };
        assert_eq!(
            cfg.normalized_suffixes(),
            vec![".googlebot.com".to_owned(), ".bing.com".to_owned()]
        );
        assert!(cfg.validate().is_ok());

        let bad = VerifiedBotConfig {
            enabled: true,
            allowed_suffixes: vec!["   ".to_owned()],
            ..Default::default()
        };
        assert!(bad.validate().is_err());
    }
}
