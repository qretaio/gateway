//! The edge cache store (edge.spec FR-006). An app chooses what to
//! cache (`caches.default.put(request, response)` — the jwks endpoint
//! is the motivating shape) and the edge SERVES the stored value
//! itself, after the assets check and before any backend materializes:
//! a cache hit never spins the app.
//!
//! THE SEAL: the store is PARTITIONED by app scope — each scope owns a
//! private map and no operation can address another scope's entries
//! (the scope is baked host-side at instantiation; it is not a
//! guest-controllable parameter). Owner directive 2026-11-06: "an app
//! only can push caches to its own cache and not pollute other app's
//! cache ... splitting is easier option."
//!
//! THE VOLATILITY LAW (the point of the feature): the store is the
//! edge's MEMORY and every entry is scoped to the app's serving
//! fingerprint — so a restart empties it, and a new version (or a
//! spec/env change) of the app never sees the old version's entries.
//! Freshness is the stored response's own TTL (the `cache-control`
//! `s-maxage`/`max-age` directives, a default when neither is present);
//! an expired entry is a miss and the app runs. The app pushes updates
//! by putting again — a `put` overwrites the key, the next edge lookup
//! serves the new bytes.
//!
//! The engine crosses through [`CacheDispatch`] (the queue-dispatch
//! shape: the serving layer bakes the caller's app scope at
//! instantiation); the implementation is [`EdgeCache`], one per edge.

/// One entry's body cap. A jwks document is kilobytes; 5 MiB leaves
/// every honest JSON/binary response room while an accidental
/// `put(the-whole-object-store)` bounces at the door.
pub const EDGE_CACHE_BODY_MAX: usize = 5 * 1024 * 1024;

/// The per-node entry cap (all apps). Past it the store evicts: expired
/// entries first, then the oldest-stored — a cache is a cache, not a
/// database (the durable faces are KV and the object storage).
pub const EDGE_CACHE_MAX_ENTRIES: usize = 4096;

/// The TTL when the stored response carries neither `s-maxage` nor
/// `max-age`: five minutes — the Workers-defaults ballpark, short
/// enough that an app that forgot the header self-heals quickly.
pub const EDGE_CACHE_TTL_DEFAULT_SECS: u64 = 300;

/// The TTL ceiling: one day. A longer freshness law is the app's own
/// business (it can re-put on a schedule or a version bump).
pub const EDGE_CACHE_TTL_MAX_SECS: u64 = 86_400;

/// One stored HTTP response — status line, header pairs (lowercased
/// names, the `http` crate's shape), and the body bytes.
#[derive(Debug, Clone)]
pub struct CachedResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl CachedResponse {
    /// One header's combined value (the repeated names joined `, ` —
    /// the Headers.get shape), lowercased for directive parsing.
    fn header(&self, name: &str) -> Option<String> {
        let vs: Vec<&str> = self
            .headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
            .collect();
        if vs.is_empty() {
            None
        } else {
            Some(vs.join(", "))
        }
    }

    /// The freshness law (the WIT doc's): `no-store` / `no-cache` /
    /// `private` refuse the put; `s-maxage` wins over `max-age`; neither
    /// present takes the default. Clamped to [1, TTL_MAX].
    pub fn ttl_secs(&self) -> Result<u64, String> {
        // A CDN-only directive (CDN-Cache-Control / Surrogate-Control)
        // overrides Cache-Control for a shared cache — Cloudflare's own
        // precedence, so the edge store honors what the CDN will honor.
        // Either header may forbid caching outright.
        // Lowest priority first: a later (higher-priority) header's
        // max-age overwrites the earlier one's for the same directive.
        let headers = [
            self.header("cache-control").unwrap_or_default(),
            self.header("surrogate-control").unwrap_or_default(),
            self.header("cdn-cache-control").unwrap_or_default(),
        ];
        let mut shared: Option<u64> = None; // s-maxage (any header)
        let mut freshness: Option<u64> = None; // max-age (any header)
        for cc in &headers {
            for directive in cc.split(',') {
                let directive = directive.trim();
                let lower = directive.to_ascii_lowercase();
                if lower == "no-store" || lower == "no-cache" || lower == "private" {
                    return Err(format!("the response forbids caching ({directive})"));
                }
                if let Some(v) = lower.strip_prefix("s-maxage=")
                    && let Ok(secs) = v.trim().parse::<u64>()
                {
                    shared = Some(secs);
                }
                if let Some(v) = lower.strip_prefix("max-age=")
                    && let Ok(secs) = v.trim().parse::<u64>()
                {
                    freshness = Some(secs);
                }
            }
        }
        // s-maxage ALWAYS wins over max-age, independent of the order
        // the directives appeared in (the old `.max()` law let a later
        // max-age override an earlier s-maxage — a real bug).
        Ok(shared
            .or(freshness)
            .unwrap_or(EDGE_CACHE_TTL_DEFAULT_SECS)
            .clamp(1, EDGE_CACHE_TTL_MAX_SECS))
    }
}

/// The engine half of the edge cache (the WIT face's backing): what
/// the cache-push face get/put/delete crosses through. The
/// implementor knows WHICH app's cache scope it carries (baked at
/// instantiation — the queue-dispatch shape).
#[async_trait::async_trait]
pub trait CacheDispatch: Send + Sync {
    async fn get(&self, key: &str) -> Result<Option<CachedResponse>, String>;
    async fn put(&self, key: &str, response: CachedResponse) -> Result<(), String>;
    async fn delete(&self, key: &str) -> Result<bool, String>;
}

struct Entry {
    response: CachedResponse,
    expires_at: std::time::Instant,
    stored_at: std::time::Instant,
}

/// The edge cache: one PRIVATE store per app scope — the split
/// is the seal (owner directive 2026-11-06: an app cannot pollute
/// another app's cache, and the split is the structural answer — there
/// is no key shape that crosses stores). Volatile BY LAW — the field
/// dies with the process (a restart empties the cache) and the
/// scope string dies with the app version (a redeploy orphans the old
/// store outright).
#[derive(Default)]
pub struct EdgeCache {
    scopes: std::sync::Mutex<
        std::collections::HashMap<String, std::collections::HashMap<String, Entry>>,
    >,
}

impl EdgeCache {
    /// The edge lookup: the stored response for `key` in `scope`'s own
    /// store, when one is present AND inside its TTL (an expired entry
    /// is removed — a miss — and the caller runs the request path).
    pub fn get(&self, scope: &str, key: &str) -> Option<CachedResponse> {
        self.get_with_age(scope, key).map(|(response, _)| response)
    }

    /// The edge lookup plus the entry's age in seconds. The age rides
    /// back to the response path so a cache hit can emit `Age:` — the
    /// standard shared-cache freshness signal an upstream CDN (e.g.
    /// Cloudflare) and clients both understand.
    pub fn get_with_age(&self, scope: &str, key: &str) -> Option<(CachedResponse, u64)> {
        let mut scopes = self.scopes.lock().unwrap();
        let store = scopes.get_mut(scope)?;
        match store.get(key) {
            Some(e) if e.expires_at > std::time::Instant::now() => {
                let age = e.stored_at.elapsed().as_secs();
                Some((e.response.clone(), age))
            }
            Some(_) => {
                store.remove(key);
                None
            }
            None => None,
        }
    }

    /// Store (or overwrite) a response under the app's scope. The TTL
    /// rides the response's own cache-control; a forbidding header or
    /// an oversized body refuses with the reason. The entry cap is the
    /// NODE's (all scopes counted together) — a crowded node makes
    /// room, the crowded app's neighbors are never read.
    pub fn put(&self, scope: &str, key: &str, response: CachedResponse) -> Result<(), String> {
        if response.body.len() > EDGE_CACHE_BODY_MAX {
            return Err(format!(
                "the response body exceeds the edge cache's {} MiB cap",
                EDGE_CACHE_BODY_MAX / (1024 * 1024)
            ));
        }
        let ttl = response.ttl_secs()?;
        let mut scopes = self.scopes.lock().unwrap();
        let total: usize = scopes.values().map(|s| s.len()).sum();
        let overwritten = scopes.get(scope).is_some_and(|s| s.contains_key(key));
        if total >= EDGE_CACHE_MAX_ENTRIES && !overwritten {
            Self::evict(&mut scopes);
        }
        let now = std::time::Instant::now();
        scopes.entry(scope.to_owned()).or_default().insert(
            key.to_owned(),
            Entry {
                response,
                expires_at: now + std::time::Duration::from_secs(ttl),
                stored_at: now,
            },
        );
        Ok(())
    }

    /// Drop the entry under the app's scope; answers whether one was.
    pub fn delete(&self, scope: &str, key: &str) -> bool {
        self.scopes
            .lock()
            .unwrap()
            .get_mut(scope)
            .is_some_and(|s| s.remove(key).is_some())
    }

    /// The node-wide entry count (the cap's measure).
    #[cfg(test)]
    fn total_entries(&self) -> usize {
        self.scopes.lock().unwrap().values().map(|s| s.len()).sum()
    }

    /// Make room for one more entry: the expired entries all go, then
    /// the oldest-stored survivor (a cache is a cache). The sweep is
    /// node-wide — every scope's expired crowd is fair game — but it
    /// only ever REMOVES: no entry moves between stores. Best-effort —
    /// an all-fresh store at the cap still yields its oldest.
    fn evict(
        scopes: &mut std::collections::HashMap<String, std::collections::HashMap<String, Entry>>,
    ) {
        let now = std::time::Instant::now();
        let expired: Vec<(String, String)> = scopes
            .iter()
            .flat_map(|(scope, store)| {
                store
                    .iter()
                    .filter(|(_, e)| e.expires_at <= now)
                    .map(|(k, _)| (scope.clone(), k.clone()))
            })
            .collect();
        if !expired.is_empty() {
            for (scope, k) in &expired {
                if let Some(store) = scopes.get_mut(scope) {
                    store.remove(k);
                }
            }
            return;
        }
        let mut oldest: Option<(String, String)> = None;
        let mut oldest_at = std::time::Instant::now();
        for (scope, store) in scopes.iter() {
            for (k, e) in store.iter() {
                if oldest.is_none() || e.stored_at < oldest_at {
                    oldest = Some((scope.clone(), k.clone()));
                    oldest_at = e.stored_at;
                }
            }
        }
        if let Some((scope, k)) = oldest
            && let Some(store) = scopes.get_mut(&scope)
        {
            store.remove(&k);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resp(status: u16, headers: Vec<(&str, &str)>, body: &[u8]) -> CachedResponse {
        CachedResponse {
            status,
            headers: headers
                .into_iter()
                .map(|(k, v)| (k.to_owned(), v.to_owned()))
                .collect(),
            body: body.to_vec(),
        }
    }

    #[test]
    fn ttl_rides_the_response_cache_control() {
        // The plain response takes the default; max-age wins; s-maxage
        // wins over max-age; the forbidding directives refuse; the
        // ceiling clamps.
        assert_eq!(resp(200, vec![], b"").ttl_secs().unwrap(), 300);
        assert_eq!(
            resp(200, vec![("cache-control", "max-age=60")], b"")
                .ttl_secs()
                .unwrap(),
            60
        );
        assert_eq!(
            resp(
                200,
                vec![("cache-control", "max-age=60, s-maxage=120")],
                b""
            )
            .ttl_secs()
            .unwrap(),
            120
        );
        // s-maxage wins regardless of directive order (the old bug:
        // a later max-age overrode an earlier s-maxage via `.max()`).
        assert_eq!(
            resp(200, vec![("cache-control", "s-maxage=10, max-age=60")], b"")
                .ttl_secs()
                .unwrap(),
            10
        );
        // CDN-only directives override Cache-Control for a shared cache:
        // a CDN-Cache-Control s-maxage wins, and a forbid refuses.
        assert_eq!(
            resp(
                200,
                vec![
                    ("cache-control", "max-age=600"),
                    ("cdn-cache-control", "s-maxage=60")
                ],
                b""
            )
            .ttl_secs()
            .unwrap(),
            60
        );
        assert!(
            resp(
                200,
                vec![
                    ("cache-control", "max-age=600"),
                    ("cdn-cache-control", "no-store")
                ],
                b""
            )
            .ttl_secs()
            .is_err()
        );
        assert_eq!(
            resp(
                200,
                vec![
                    ("surrogate-control", "max-age=30"),
                    ("cache-control", "max-age=600")
                ],
                b""
            )
            .ttl_secs()
            .unwrap(),
            30
        );
        assert_eq!(
            resp(200, vec![("cache-control", "max-age=99999999")], b"")
                .ttl_secs()
                .unwrap(),
            EDGE_CACHE_TTL_MAX_SECS
        );
        for forbidding in ["no-store", "no-cache", "private, max-age=60"] {
            assert!(
                resp(200, vec![("cache-control", forbidding)], b"")
                    .ttl_secs()
                    .is_err()
            );
        }
        // Repeated names combine (the Headers.get shape) — both count.
        assert_eq!(
            resp(
                200,
                vec![
                    ("Cache-Control", "max-age=10"),
                    ("cache-control", "s-maxage=20")
                ],
                b""
            )
            .ttl_secs()
            .unwrap(),
            20
        );
    }

    #[test]
    fn a_store_is_scoped_and_volatile() {
        let cache = EdgeCache::default();
        cache
            .put("org/app/v1", "GET /jwks", resp(200, vec![], b"one"))
            .unwrap();
        // The same key under another scope is a miss — a new version's
        // entries start empty (the version invalidation).
        assert!(cache.get("org/app/v2", "GET /jwks").is_none());
        assert_eq!(cache.get("org/app/v1", "GET /jwks").unwrap().body, b"one");
        // The age accessor returns the stored response plus a fresh age
        // (0 immediately after the put) — the server path stamps Age:
        // from this, never from a client/app-supplied Age header.
        let (fresh, age) = cache.get_with_age("org/app/v1", "GET /jwks").unwrap();
        assert_eq!(fresh.body, b"one");
        assert_eq!(age, 0);
        // A put overwrites: the next lookup serves the new bytes (the
        // app's update push).
        cache
            .put("org/app/v1", "GET /jwks", resp(200, vec![], b"two"))
            .unwrap();
        assert_eq!(cache.get("org/app/v1", "GET /jwks").unwrap().body, b"two");
        // Delete drops exactly the scoped key.
        assert!(cache.delete("org/app/v1", "GET /jwks"));
        assert!(!cache.delete("org/app/v1", "GET /jwks"));
        assert!(cache.get("org/app/v1", "GET /jwks").is_none());
    }

    #[test]
    fn scopes_are_private_stores_the_seal() {
        // FR-081's law: one app cannot touch another app's cache — the
        // split store makes it structural (no key crosses stores, a
        // scope's own operations are the ONLY doors).
        let cache = EdgeCache::default();
        cache
            .put("org/a/fp1", "GET /jwks", resp(200, vec![], b"a's"))
            .unwrap();
        // B's match on A's exact key: a miss.
        assert!(cache.get("org/b/fp1", "GET /jwks").is_none());
        // B's put under A's exact key: B's own store, A's bytes intact.
        cache
            .put("org/b/fp1", "GET /jwks", resp(200, vec![], b"b's"))
            .unwrap();
        assert_eq!(cache.get("org/a/fp1", "GET /jwks").unwrap().body, b"a's");
        assert_eq!(cache.get("org/b/fp1", "GET /jwks").unwrap().body, b"b's");
        // B's delete on A's exact key: it can only ever drop B's own
        // entry — A's bytes survive.
        assert!(cache.delete("org/b/fp1", "GET /jwks"));
        assert_eq!(cache.get("org/a/fp1", "GET /jwks").unwrap().body, b"a's");
        assert!(cache.get("org/b/fp1", "GET /jwks").is_none());
        // Even a hostile key with the scope separator inside stays in
        // B's own store (the flat prefix it used to impersonate is gone).
        cache
            .put(
                "org/b/fp1",
                "org/a/fp1\u{1}GET /jwks",
                resp(200, vec![], b"impersonation"),
            )
            .unwrap();
        assert_eq!(cache.get("org/a/fp1", "GET /jwks").unwrap().body, b"a's");
        assert_eq!(cache.total_entries(), 2);
    }

    #[test]
    fn an_expired_entry_is_a_miss() {
        let cache = EdgeCache::default();
        cache
            .put(
                "org/app/v1",
                "GET /jwks",
                resp(200, vec![("cache-control", "max-age=1")], b"x"),
            )
            .unwrap();
        assert!(cache.get("org/app/v1", "GET /jwks").is_some());
        std::thread::sleep(std::time::Duration::from_millis(1100));
        assert!(cache.get("org/app/v1", "GET /jwks").is_none());
    }

    #[test]
    fn the_caps_refuse_and_evict() {
        let cache = EdgeCache::default();
        // The body cap refuses.
        let big = vec![0u8; EDGE_CACHE_BODY_MAX + 1];
        assert!(cache.put("s", "GET /big", resp(200, vec![], &big)).is_err());
        // The entry cap evicts: fill to the cap with max-age=1 entries,
        // let them expire, store one more — the sweep takes the expired
        // crowd before touching a fresh one. The cap is the NODE's: the
        // fill spreads across two scopes and the third scope's put
        // still evicts the same expired crowd.
        for i in 0..EDGE_CACHE_MAX_ENTRIES / 2 {
            cache
                .put(
                    "s1",
                    &format!("GET /k{i}"),
                    resp(200, vec![("cache-control", "max-age=1")], b"x"),
                )
                .unwrap();
            cache
                .put(
                    "s2",
                    &format!("GET /k{i}"),
                    resp(200, vec![("cache-control", "max-age=1")], b"x"),
                )
                .unwrap();
        }
        assert_eq!(cache.total_entries(), EDGE_CACHE_MAX_ENTRIES);
        // Overwriting an existing key never evicts.
        cache
            .put(
                "s1",
                "GET /k0",
                resp(200, vec![("cache-control", "max-age=3600")], b"fresh"),
            )
            .unwrap();
        assert_eq!(cache.total_entries(), EDGE_CACHE_MAX_ENTRIES);
        std::thread::sleep(std::time::Duration::from_millis(1100));
        cache
            .put(
                "s3",
                "GET /new",
                resp(200, vec![("cache-control", "max-age=3600")], b"n"),
            )
            .unwrap();
        assert!(cache.total_entries() <= EDGE_CACHE_MAX_ENTRIES);
        assert!(cache.get("s3", "GET /new").is_some());
        assert!(cache.get("s1", "GET /k1").is_none(), "expired crowd swept");
        assert!(
            cache.get("s1", "GET /k0").is_some(),
            "the fresh overwrite survives"
        );
    }
}
