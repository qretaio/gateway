//! The verified-bot exemption: forward-confirmed reverse DNS (FCrDNS)
//! against an operator allowlist, with a bounded, TTL'd per-IP cache.
//!
//! This is the stateful half; the decision law is
//! [`kapigate_core::verified_bot::verify_fcrdns`]. DNS I/O lives here because
//! gateway-core forbids it. Failures, timeouts, and a disabled/unbuildable
//! resolver all FAIL OPEN for the exemption (the client is treated as a
//! regular request and still faces WAF + rate limits) — an allowlist that
//! breaks must never become a deny.
//!
//! A request's peer IP comes from `ConnectInfo`, not a client header, so a
//! client cannot point this lookup at an arbitrary address. The cache is
//! bounded and LRU-evicted: a stream of source IPs cannot grow it without
//! limit.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use kapigate_core::verified_bot::VerifiedBotConfig;
use hickory_resolver::TokioResolver;
use hickory_resolver::proto::rr::{RData, RecordType};

struct CacheEntry {
    verified: bool,
    stored: Instant,
}

/// The live verified-bot checker. `Clone` shares the resolver, cache, and
/// config behind an `Arc`.
#[derive(Clone)]
pub struct VerifiedBots {
    inner: std::sync::Arc<Inner>,
}

struct Inner {
    config: VerifiedBotConfig,
    suffixes: Vec<String>,
    resolver: TokioResolver,
    cache: Mutex<HashMap<IpAddr, CacheEntry>>,
}

impl VerifiedBots {
    /// Build the checker from validated config. Returns `None` when the
    /// feature is disabled or the system resolver cannot be built — in
    /// both cases the caller simply skips the exemption (fail-open).
    #[must_use]
    pub fn new(config: VerifiedBotConfig) -> Option<Self> {
        if !config.enabled {
            return None;
        }
        let resolver = match TokioResolver::builder_tokio().and_then(|b| b.build()) {
            Ok(resolver) => resolver,
            Err(e) => {
                eprintln!("[gateway] verified_bots: resolver unavailable: {e}");
                return None;
            }
        };
        Some(Self {
            inner: std::sync::Arc::new(Inner {
                suffixes: config.normalized_suffixes(),
                config,
                resolver,
                cache: Mutex::new(HashMap::new()),
            }),
        })
    }

    /// True when `ip` forward-confirms to an allowlisted crawler hostname.
    /// Cached answers (positive and negative) are reused for the config's
    /// TTL; a miss performs PTR + forward A/AAAA lookups under a timeout.
    #[must_use]
    pub async fn is_verified(&self, ip: IpAddr) -> bool {
        let ttl = Duration::from_secs(self.inner.config.cache_ttl_secs);
        let now = Instant::now();
        if let Ok(cache) = self.inner.cache.lock()
            && let Some(entry) = cache.get(&ip)
            && now.duration_since(entry.stored) < ttl
        {
            return entry.verified;
        }
        let verified = self.resolve(ip).await;
        if let Ok(mut cache) = self.inner.cache.lock() {
            // Bound the cache: evict the oldest before inserting a new key.
            if cache.len() >= self.inner.config.cache_max_entries && !cache.contains_key(&ip) {
                let oldest = cache.iter().min_by_key(|(_, e)| e.stored).map(|(k, _)| *k);
                if let Some(k) = oldest {
                    cache.remove(&k);
                }
            }
            cache.insert(
                ip,
                CacheEntry {
                    verified,
                    stored: Instant::now(),
                },
            );
        }
        verified
    }

    /// Do the bounded DNS work for one IP: PTR → hostname, then forward
    /// A/AAAA → IPs, then the pure FCrDNS law. Any error/timeout is false.
    async fn resolve(&self, ip: IpAddr) -> bool {
        let timeout = Duration::from_millis(self.inner.config.timeout_ms);
        let check = async {
            let ptr = self.inner.resolver.lookup(ip, RecordType::PTR).await.ok()?;
            let host = ptr.answers().iter().find_map(|record| match &record.data {
                RData::PTR(name) => Some(name.0.to_string()),
                _ => None,
            })?;
            let fwd = self.inner.resolver.lookup_ip(&host).await.ok()?;
            let forward_ips: Vec<IpAddr> = fwd.iter().collect();
            Some(kapigate_core::verified_bot::verify_fcrdns(
                &host,
                &forward_ips,
                ip,
                &self.inner.suffixes,
            ))
        };
        tokio::time::timeout(timeout, check)
            .await
            .unwrap_or(None)
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_disabled_config_has_no_checker() {
        let cfg = VerifiedBotConfig::default();
        assert!(cfg.validate().is_ok());
        // `new` returning None means the serving path skips the exemption.
        assert!(VerifiedBots::new(cfg).is_none());
    }

    #[test]
    fn an_enabled_config_normalizes_its_suffixes() {
        let cfg = VerifiedBotConfig {
            enabled: true,
            allowed_suffixes: vec!["GoogleBot.COM.".to_owned()],
            ..Default::default()
        };
        assert!(cfg.validate().is_ok());
        // The pure law is exercised in gateway-core; here we only assert
        // the config shape the stateful checker would carry.
        assert_eq!(cfg.normalized_suffixes(), vec![".googlebot.com".to_owned()]);
    }
}
