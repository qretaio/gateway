//! The rate-limit law: a bounded sliding-window counter over request
//! timestamps. Pure over plain data — the stateful, bounded store lives in
//! the gateway crate ([`gateway::rate_state`]); this module owns only the
//! decision function and the config/verdict types, so the rule can be
//! tested without a clock, a map, or a network.
//!
//! The law is a FIXED window that slides with the request: a hit at time
//! `t` counts every prior hit in `[t - window, t)` (the window is
//! half-open, so a hit exactly `window` old has expired). When the count
//! reaches the rule's limit the request is blocked with a `Retry-After`
//! equal to the time until the oldest counted hit expires. A blocked hit
//! is NOT recorded — a client hammering a limited route does not push its
//! own release time further out (that would be a self-sustaining ban).

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::crd::RateLimitKeySource;

/// One rate-limit rule. Rules are evaluated in order; the first that
/// blocks wins. `per_route` keys the counter by (client IP, method, host,
/// path) instead of just client IP — use it for expensive routes like
/// `/login` while the default bounds the client overall.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateLimitRule {
    /// The rule's identity — stamped on a block (`x-qreta-rate`) so an
    /// operator can see which limit fired.
    pub name: String,
    /// Maximum requests in the window before blocking.
    pub limit: u32,
    /// The window length in whole seconds.
    pub window_secs: u64,
    /// Key by route as well as client IP (default false = per client).
    #[serde(default)]
    pub per_route: bool,
}

impl RateLimitRule {
    /// Validate the rule at the config boundary. A zero limit or window
    /// would either block everything or divide by zero; refuse both.
    pub fn validate(&self) -> Result<(), String> {
        if self.limit == 0 {
            return Err(format!("rate limit {}: limit must be > 0", self.name));
        }
        if self.window_secs == 0 {
            return Err(format!("rate limit {}: window_secs must be > 0", self.name));
        }
        Ok(())
    }
}

/// The rate-limit config (`[ratelimit]` / `[[ratelimit.rules]]`). Empty
/// rules = the limiter is inert.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct RateLimitConfig {
    #[serde(default)]
    pub rules: Vec<RateLimitRule>,
}

impl RateLimitConfig {
    /// Validate every configured rule at the config boundary.
    pub fn validate(&self) -> Result<(), String> {
        for rule in &self.rules {
            rule.validate()?;
        }
        Ok(())
    }
}

/// The decision for one request against one rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RateDecision {
    /// Allowed: carry the pruned hit list (with this hit appended) back to
    /// the caller so it can update the bounded store.
    Allow { hits: Vec<std::time::Instant> },
    /// Blocked: the rule that fired and how long until a retry is allowed.
    Block { rule: String, retry_after: Duration },
}

/// Decide one request against one rule. `hits` are the timestamps of
/// earlier allowed requests for the same key; `now` is the monotonic
/// instant supplied by the caller (the law never reads the clock itself).
/// Expired hits (older than `window`) are dropped; if the remaining count
/// is already `limit`, block with the time until the oldest expires.
#[must_use]
pub fn decide(
    hits: &[std::time::Instant],
    now: std::time::Instant,
    limit: u32,
    window: Duration,
) -> RateDecision {
    let mut live: Vec<_> = hits.iter().copied().filter(|t| *t + window > now).collect();
    // usize::try_from is infallible for u32 on every target we build, but
    // spelling it as a cast would trip the repo's numeric-cast pack.
    let limit = usize::try_from(limit).unwrap_or(usize::MAX);
    if live.len() >= limit {
        let retry_after = live.first().map_or(Duration::ZERO, |oldest| {
            (*oldest + window).saturating_duration_since(now)
        });
        return RateDecision::Block {
            rule: String::new(),
            retry_after,
        };
    }
    live.push(now);
    RateDecision::Allow { hits: live }
}

/// Build the counter bucket key: the client IP is ALWAYS the first
/// component (from the connection peer, never a header), followed by the
/// runtime value of each configured `key` source in order. A missing
/// header contributes an empty component so all such requests share one
/// bucket — deterministic, never a silently skipped limit. The namespace
/// and rule identity are prefixed by the caller so identical rule names in
/// different namespaces cannot collide.
#[must_use]
pub fn build_key(
    ip: IpAddr,
    headers: &BTreeMap<String, String>,
    sources: &[RateLimitKeySource],
) -> String {
    let mut key = ip.to_string();
    for source in sources {
        key.push('|');
        match source {
            RateLimitKeySource::Header(name) => {
                if let Some(value) = headers.get(&name.to_ascii_lowercase()) {
                    key.push_str(value);
                }
            }
        }
    }
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::LazyLock;

    static BASE: LazyLock<std::time::Instant> = LazyLock::new(std::time::Instant::now);

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn t(secs: u64) -> std::time::Instant {
        *BASE + Duration::from_secs(secs)
    }

    #[test]
    fn a_request_under_the_limit_is_allowed_and_recorded() {
        let d = decide(&[], t(0), 3, Duration::from_secs(60));
        let RateDecision::Allow { hits } = d else {
            panic!("expected allow");
        };
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn the_limit_blocks_and_reports_the_retry_delay() {
        let hits = [t(10), t(20), t(30)];
        let d = decide(&hits, t(35), 3, Duration::from_secs(60));
        let RateDecision::Block { retry_after, .. } = d else {
            panic!("expected block");
        };
        // The oldest hit at t=10 expires at t=70 → 35s from now.
        assert_eq!(retry_after, Duration::from_secs(35));
    }

    #[test]
    fn an_expired_hit_falls_out_of_the_window() {
        let hits = [t(0), t(20), t(30)];
        let d = decide(&hits, t(61), 3, Duration::from_secs(60));
        assert!(matches!(d, RateDecision::Allow { .. }));
    }

    #[test]
    fn a_blocked_request_does_not_extend_its_own_ban() {
        // Three hits fill the window; a fourth is blocked and must not be
        // appended — otherwise the client pushes its release time out.
        let hits = [t(10), t(20), t(30)];
        assert!(matches!(
            decide(&hits, t(35), 3, Duration::from_secs(60)),
            RateDecision::Block { .. }
        ));
        // At t=70 only the t=20 and t=30 hits remain; allowed again.
        assert!(matches!(
            decide(&hits, t(70), 3, Duration::from_secs(60)),
            RateDecision::Allow { .. }
        ));
    }

    #[test]
    fn build_key_is_per_ip_plus_dynamic_header_values() {
        use crate::crd::RateLimitKeySource;
        let mut headers = BTreeMap::new();
        headers.insert("x-api-key".to_owned(), "tenant-a".to_owned());
        let addr = ip("192.0.2.1");
        assert_eq!(build_key(addr, &headers, &[]), "192.0.2.1");
        assert_eq!(
            build_key(
                addr,
                &headers,
                &[RateLimitKeySource::Header("x-api-key".to_owned())]
            ),
            "192.0.2.1|tenant-a"
        );
        // Header names are matched case-insensitively; a missing header
        // yields an empty component (shared bucket), never a skipped limit.
        assert_eq!(
            build_key(
                addr,
                &headers,
                &[RateLimitKeySource::Header("X-Api-Key".to_owned())]
            ),
            "192.0.2.1|tenant-a"
        );
        assert_eq!(
            build_key(
                addr,
                &headers,
                &[RateLimitKeySource::Header("x-tenant".to_owned())]
            ),
            "192.0.2.1|"
        );
        // Different IPs stay in different buckets even with the same key.
        assert_ne!(
            build_key(
                ip("192.0.2.2"),
                &headers,
                &[RateLimitKeySource::Header("x-api-key".to_owned())]
            ),
            "192.0.2.1|tenant-a"
        );
    }

    #[test]
    fn zero_limit_and_zero_window_are_refused() {
        assert!(
            RateLimitRule {
                name: "bad".into(),
                limit: 0,
                window_secs: 60,
                per_route: false
            }
            .validate()
            .is_err()
        );
        assert!(
            RateLimitRule {
                name: "bad".into(),
                limit: 3,
                window_secs: 0,
                per_route: false
            }
            .validate()
            .is_err()
        );
    }
}
