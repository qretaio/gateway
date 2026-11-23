//! The stateful rate-limit store: bounded per-key sliding-window counters
//! over the pure [`gateway_core::ratelimit`] law. Lives in the gateway (not
//! the pure-law crate) because it owns a clock, a mutable map, and a
//! resource cap. A single process-wide store means every replica enforces
//! only 1/N of a configured limit — documented, with the shared-counter
//! upgrade path noted at the config boundary.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use gateway_core::ratelimit::RateDecision;

/// Upper bound on tracked keys. A client that sprays source IPs must not
/// grow this map without limit; past the cap the least-recently-used key
/// is evicted (its counter resets, which favors availability over perfect
/// accounting under abuse — the honest trade for a bounded store).
pub const MAX_TRACKED_KEYS: usize = 65_536;

struct Entry {
    /// The rule's window hits (allowed requests only).
    hits: Vec<Instant>,
    /// Last time this entry was touched, for LRU eviction.
    last: Instant,
}

/// The live rate limiter. `Clone` shares the same store behind an `Arc`,
/// so the serving tasks all count into one bounded map.
#[derive(Clone)]
pub struct RateLimiter {
    inner: std::sync::Arc<Inner>,
}

struct Inner {
    /// bucket key -> counter.
    map: Mutex<HashMap<String, Entry>>,
}

impl RateLimiter {
    /// Build the bounded counter store. Rules themselves live in
    /// [`crate::rate_limit_state::RateLimitState`]; this type only counts.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: std::sync::Arc::new(Inner {
                map: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// Check one bucket against a limit. `Some(retry_after)` means the
    /// bucket is over budget. A blocked hit is not recorded, so it cannot
    /// extend its own ban window. The namespace + rule name are already
    /// part of `bucket` (built by the compiled rule).
    #[must_use]
    pub fn check(&self, bucket: &str, limit: u32, window: Duration) -> Option<Duration> {
        let now = Instant::now();
        // A poisoned mutex means a panic while holding it; treating the
        // limiter as inert (fail-open) is the availability-preserving
        // choice here — a rate limiter is a mitigation, not a gate.
        let Ok(mut map) = self.inner.map.lock() else {
            return None;
        };
        let hits = map
            .get(bucket)
            .map_or(&[][..], |e| e.hits.as_slice())
            .to_vec();
        let result = match gateway_core::ratelimit::decide(&hits, now, limit, window) {
            RateDecision::Allow { hits } => {
                map.insert(bucket.to_owned(), Entry { hits, last: now });
                None
            }
            RateDecision::Block { retry_after, .. } => Some(retry_after),
        };
        self.evict_if_needed(&mut map);
        result
    }

    /// Penalty bucket prefix for IPs that probed a reserved private/admin
    /// path (`/__private/`, `/__internal/`). Kept in the SAME bounded map
    /// as ordinary rate buckets — a scanner spraying IPs cannot grow it
    /// past [`MAX_TRACKED_KEYS`].
    pub const PRIVATE_PATH_PENALTY_PREFIX: &str = "private-path-penalty|";

    /// Record that `ip` probed a reserved private/admin path. Called on
    /// EVERY private-path hit (the request is blocked regardless), so a
    /// scanner that keeps hammering the door only deepens its own penalty.
    /// One hit is enough to flag the IP: [`Self::is_private_path_penalized`]
    /// then refuses its every subsequent request (to any path) until the
    /// window expires. One minute is enough to make automated probing
    /// expensive without stranding a human who mistyped a URL.
    pub fn penalize_private_path(&self, ip: std::net::IpAddr) {
        let bucket = format!("{}{ip}", Self::PRIVATE_PATH_PENALTY_PREFIX);
        // `check` with a generous limit just records the hit and returns
        // None; the penalty is enforced by `is_private_path_penalized`,
        // which reads the recorded hit. Using `check` keeps the store
        // bounded and the hit pruning identical to ordinary rate buckets.
        let _ = self.check(&bucket, u32::MAX, Duration::from_secs(60));
    }

    /// Whether `ip` is currently over the private-path penalty budget.
    /// The WAF calls this on every request so an IP that probed a private
    /// path is refused (429) on all subsequent requests until the window
    /// expires. Reading does not add a hit, so a blocked client cannot push
    /// its own release time out.
    #[must_use]
    pub fn is_private_path_penalized(&self, ip: std::net::IpAddr) -> bool {
        let bucket = format!("{}{ip}", Self::PRIVATE_PATH_PENALTY_PREFIX);
        let Ok(map) = self.inner.map.lock() else {
            return false; // poisoned lock: fail open (mitigation, not a gate)
        };
        let window = Duration::from_secs(60);
        let now = Instant::now();
        map.get(&bucket)
            .is_some_and(|e| e.hits.iter().any(|t| *t + window > now))
    }

    /// Keep the map bounded: when it exceeds the cap, drop the
    /// least-recently-touched entries until it fits.
    fn evict_if_needed(&self, map: &mut HashMap<String, Entry>) {
        if map.len() <= MAX_TRACKED_KEYS {
            return;
        }
        let excess = map.len() - MAX_TRACKED_KEYS;
        let mut victims: Vec<_> = map.iter().map(|(k, e)| (k.clone(), e.last)).collect();
        victims.sort_by_key(|(_, last)| *last);
        for (key, _) in victims.into_iter().take(excess) {
            map.remove(&key);
        }
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn window() -> Duration {
        Duration::from_secs(60)
    }

    #[test]
    fn the_counter_blocks_after_the_configured_number_of_hits() {
        let limiter = RateLimiter::new();
        assert_eq!(limiter.check("bucket", 3, window()), None);
        assert_eq!(limiter.check("bucket", 3, window()), None);
        assert_eq!(limiter.check("bucket", 3, window()), None);
        let blocked = limiter.check("bucket", 3, window());
        assert!(blocked.is_some());
    }

    #[test]
    fn different_buckets_are_counted_independently() {
        let limiter = RateLimiter::new();
        assert_eq!(limiter.check("client-a", 1, window()), None);
        // Same bucket is blocked...
        assert!(limiter.check("client-a", 1, window()).is_some());
        // ...another bucket still has its own budget.
        assert_eq!(limiter.check("client-b", 1, window()), None);
    }

    #[test]
    fn a_private_path_probe_penalizes_the_ip_but_not_others() {
        let limiter = RateLimiter::new();
        let bot = "192.0.2.10".parse().unwrap();
        let innocent = "192.0.2.11".parse().unwrap();
        assert!(!limiter.is_private_path_penalized(bot));
        limiter.penalize_private_path(bot);
        assert!(limiter.is_private_path_penalized(bot));
        // A different source IP is untouched.
        assert!(!limiter.is_private_path_penalized(innocent));
        // Penalizing twice does not deepen the hit list beyond the window
        // (the check law prunes old hits and the map stays bounded).
        limiter.penalize_private_path(bot);
        assert!(limiter.is_private_path_penalized(bot));
    }

    #[test]
    fn a_namespace_prefix_keeps_same_named_rules_apart() {
        let limiter = RateLimiter::new();
        assert_eq!(limiter.check("acme|login|1.2.3.4", 1, window()), None);
        assert!(limiter.check("acme|login|1.2.3.4", 1, window()).is_some());
        // A different namespace's "login" rule has its own counter.
        assert_eq!(limiter.check("mgmt|login|1.2.3.4", 1, window()), None);
    }
}
