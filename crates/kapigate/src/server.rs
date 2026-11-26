//! The serving face (kapi.spec EDGE-FR-001/003/004/006/008/009): every
//! request walks the same pipeline — decompose, trim the inbound
//! `x-qreta-*` (FR-008, gateway-core), consult the edge cache before
//! anything else (FR-006, a hit never reaches a node), resolve the
//! route (FR-001's matcher over the kapi-fed table), forward to the
//! node's private listener with the original Host preserved (FR-003/
//! 004 — the node instantiates through its kubelet arm). The gateway's
//! own faces live under the reserved `/__gateway/` prefix and never
//! route. `/admin` and `/v2` are node-private and never served here
//! (kapi.spec DEC-004): the routing law's 404 answers them.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::Request;
use axum::response::Response;
use bytes::Bytes;
use kapigate_core::cache::{CachedResponse, EdgeCache};
use kapigate_core::trim::trim_qreta;
use tokio::sync::watch;
use uniflight::Merger;

use crate::bot_state::VerifiedBots;
use crate::config::GatewayConfig;
use crate::kapi::Informer;
use crate::rate_limit_state::RateLimitState;
use crate::rate_state::RateLimiter;
use crate::waf_state::WafState;

/// The gateway's reserved prefix (its own faces; the routing law never
/// sees these paths). The owner dropped the edge-flavored vocabulary
/// 2026-11-16: the faces ride /__gateway/* now.
const RESERVED_PREFIX: &str = "/__gateway/";

/// The hop-by-hop headers a proxy never forwards (RFC 9110 7.6.1).
const HOP_BY_HOP: [&str; 8] = [
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

pub struct Gateway {
    pub config: GatewayConfig,
    pub informer: Informer,
    pub cache: EdgeCache,
    pub assets: std::sync::Arc<crate::assets_store::AssetStore>,
    /// The drain machinery (kapi.spec EDGE-FR-010's first land): every
    /// in-flight request holds a guard; the barrier waits them out.
    pub drain: graceful_handover::GracefulShutdown,
    /// Uniflight coalescer for cacheable GET/HEAD forwards: concurrent
    /// misses for the same key collapse into one upstream fetch; followers
    /// receive a clone of the leader's buffered response. Non-idempotent
    /// methods never enter this map.
    coalescer: Merger<String, Arc<CoalescedForward>>,
    http: reqwest::Client,
    /// The compiled WAF ruleset: static TOML rules plus the `WafRule`
    /// CRs watched from kapi, folded into one shared ruleset. The request
    /// path only builds an ExecutionContext and runs the closure trees;
    /// a watch delta recompiles off the hot path. Config validation at
    /// load guarantees the static half compiles.
    pub waf: WafState,
    /// The compiled rate-limit ruleset (static TOML + watched namespace-
    /// local CRs). The counter store is `limiter`; this owns the selectors
    /// and the namespace scoping.
    pub rate_rules: RateLimitState,
    /// Per-bucket sliding-window counters. Ahead of the WAF so a limited
    /// client never reaches an expensive rule or the backend.
    pub limiter: RateLimiter,
    /// Verified-bot allowlist checker (FCrDNS + bounded TTL cache). `None`
    /// when disabled or the resolver cannot be built (fail-open).
    pub bots: Option<VerifiedBots>,
}

/// The buffered result of one upstream forward. `Clone` is cheap (`Bytes`
/// is refcounted) and `Send + Sync` — the shape uniflight's `Merger`
/// requires so every follower receives the leader's answer.
#[derive(Debug, Clone)]
struct CoalescedForward {
    status: u16,
    headers: Vec<(String, String)>,
    body: Bytes,
}

impl Gateway {
    pub fn new(config: GatewayConfig, data_root: Option<std::path::PathBuf>) -> Self {
        // The registry token ladder: the config's [registry.<host>] map
        // first, then the standard env names for ghcr.io.
        let mut registry: std::collections::BTreeMap<String, crate::table::RegistryAuth> = config
            .registry
            .clone()
            .into_iter()
            .map(|(host, token)| (host, crate::table::RegistryAuth::Bearer(token)))
            .collect();
        if !registry.contains_key("ghcr.io") {
            if let Ok(token) = std::env::var("GHCR_TOKEN") {
                registry.insert(
                    "ghcr.io".to_owned(),
                    crate::table::RegistryAuth::Bearer(token),
                );
            } else if let Ok(token) = std::env::var("GITHUB_TOKEN") {
                registry.insert(
                    "ghcr.io".to_owned(),
                    crate::table::RegistryAuth::Bearer(token),
                );
            }
        }
        let _ = data_root; // reserved for the CRI deploy supervisor
        let waf = WafState::new(&config.waf.rules);
        let rate_rules = RateLimitState::new(&config.ratelimit.rules);
        let limiter = RateLimiter::new();
        // Building the resolver needs a Tokio runtime handle; `Gateway::new`
        // is called inside one (boot/serve), but tests may construct it
        // outside a runtime — treat that as "no checker" (fail-open).
        let bots = match tokio::runtime::Handle::try_current() {
            Ok(_) => VerifiedBots::new(config.verified_bots.clone()),
            Err(_) => None,
        };
        // The kapi URL rides the config's [kapi] section — the
        // embedded arm injects the in-process server's URL there
        // before this runs; the standalone subcommand refuses a
        // config without it.
        let kapi_url = config
            .kapi
            .as_ref()
            .map(|k| k.url.clone())
            .unwrap_or_default();
        Self {
            informer: Informer::new(&kapi_url),
            cache: EdgeCache::default(),
            assets: std::sync::Arc::new(crate::assets_store::AssetStore::new(registry)),
            drain: graceful_handover::GracefulShutdown::new(),
            coalescer: Merger::new(),
            // The forward client NEVER follows redirects: the node's
            // 302 is the caller's answer (their browser follows it
            // against the PUBLIC domain — a server-side follow would
            // chase absolute https locations this client cannot dial
            // and 502 the user).
            http: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("the forward client builds"),
            waf,
            rate_rules,
            limiter,
            bots,
            config,
        }
    }

    /// Install the deploy arm (EDGE-FR-017): called by the composing
    /// process after constructing the async CRI engine, before the
    /// gateway is wrapped in an Arc and served.
    /// The axum app: one fallback — every path walks the pipeline.
    pub fn router(self: &Arc<Self>) -> axum::Router {
        let this = Arc::clone(self);
        axum::Router::new().fallback(move |req: Request| {
            let this = Arc::clone(&this);
            async move {
                // The request IS the drain unit: the guard drops when
                // the response completes, and the shutdown barrier
                // resolves exactly then (the receiver count).
                let _guard = this.drain.subscribe();
                this.handle(req).await
            }
        })
    }

    /// Run the informer loops until the shutdown signal flips.
    pub async fn run_informer(&self, shutdown: watch::Receiver<bool>) {
        self.informer.run(shutdown).await;
    }

    /// Apply hardening headers to every response — including blocks,
    /// cached answers, and proxied streams — then hand it back. Central
    /// so no early-return path in `handle_inner` can skip hardening.
    /// An upstream header of the same name wins: apps own their own
    /// security posture (resonate's CSP permits its inline theme/SW
    /// scripts), and the hardening law never removes an upstream header.
    /// Defaults only fill gaps.
    async fn handle(&self, req: Request) -> Response {
        let mut overrides: Option<Vec<(String, String)>> = None;
        let mut resp = self.handle_inner(req, &mut overrides).await;
        for (name, value) in self.config.hardening.headers() {
            if let Ok(v) = http::HeaderValue::from_str(&value) {
                use http::header::HeaderName;
                if let Ok(hname) = HeaderName::from_bytes(name.as_bytes())
                    && let http::header::Entry::Vacant(e) = resp.headers_mut().entry(hname)
                {
                    e.insert(v);
                }
            }
        }
        // A matched WafRule with action: hardening applies its response-header
        // overrides AFTER the global defaults: an empty value suppresses the
        // header entirely (lets an app be framed), a non-empty value replaces
        // the default for this request only.
        if let Some(headers) = overrides {
            for (name, value) in headers {
                if let Ok(hname) = http::header::HeaderName::from_bytes(name.as_bytes()) {
                    if value.is_empty() {
                        resp.headers_mut().remove(&hname);
                    } else if let Ok(v) = http::HeaderValue::from_str(&value) {
                        resp.headers_mut().insert(hname, v);
                    }
                }
            }
        }
        resp
    }

    async fn handle_inner(
        &self,
        req: Request,
        overrides: &mut Option<Vec<(String, String)>>,
    ) -> Response {
        let (parts, body) = req.into_parts();
        let method = parts.method.as_str().to_owned();
        let host = parts
            .headers
            .get(http::header::HOST)
            .and_then(|h| h.to_str().ok())
            .map(|h| h.split(':').next().unwrap_or(h).to_ascii_lowercase())
            .unwrap_or_default();
        let path = parts.uri.path().to_owned();
        // One canonical bare query string; the `?`-prefixed wire/cache
        // form is derived once here and reused at every site that needs it.
        let query = parts.uri.query().unwrap_or_default().to_owned();
        let query_wire = if query.is_empty() {
            String::new()
        } else {
            format!("?{query}")
        };

        // The gateway's own faces (health, cache push) answer before the
        // routing law sees anything.
        if path.starts_with(RESERVED_PREFIX) {
            let body = axum::body::to_bytes(body, 8 * 1024 * 1024)
                .await
                .unwrap_or_default();
            return self
                .gateway_face(&method, &path, &parts.headers, &body)
                .await;
        }

        // FR-008 first: the inbound namespace belongs to the host.
        let mut headers: std::collections::BTreeMap<String, String> = parts
            .headers
            .iter()
            .filter_map(|(k, v)| {
                v.to_str()
                    .ok()
                    .map(|v| (k.as_str().to_ascii_lowercase(), v.to_owned()))
            })
            .collect();
        trim_qreta(&mut headers);
        // The client IP is always the CONNECTION PEER, never a client
        // header. x-forwarded-for is the gateway's own mint (the client's
        // copy is not a host fact — overwrite, never append).
        let peer = parts
            .extensions
            .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
            .map(|c| c.0);
        let peer_ip = peer.map(|s| s.ip());
        if let Some(ip) = peer_ip {
            headers.insert("x-forwarded-for".to_owned(), ip.to_string());
        }
        // Behind a Cloudflare Tunnel the TCP peer is the tunnel's loopback
        // origin (127.0.0.1) for EVERY visitor. Penalizing that IP would
        // ban all users after one probe. Prefer the real visitor IP that
        // Cloudflare supplies; fall back to the peer on direct dials.
        let client_ip: Option<std::net::IpAddr> = headers
            .get("cf-connecting-ip")
            .and_then(|v| v.parse().ok())
            .or(peer_ip);

        // Verified-bot exemption FIRST: a peer that forward-confirms to an
        // allowlisted crawler skips both the rate limiter and the WAF and
        // goes straight to routing. The lookup is cached and bounded; a
        // failure/timeout fails open (no exemption), so a broken resolver
        // never lets traffic bypass the WAF.
        let verified_bot = match (&self.bots, peer_ip) {
            (Some(bots), Some(ip)) => bots.is_verified(ip).await,
            _ => false,
        };

        // A client that carries a VALID, unexpired solved PoW cookie is
        // treated like a verified bot for the configurable WAF: the
        // built-in private/secret-path deny still applies (it is in every
        // compiled set), but Challenge rules are skipped. The cookie is
        // HMAC-signed and carries the work proof, so it cannot be forged
        // by a scraper without doing the SHA-256 work.
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .min(i64::MAX as u128) as i64;
        let pow_solved = self.config.pow.enabled()
            && headers.get("cookie").is_some_and(|cookies| {
                cookies
                    .split(';')
                    .filter_map(|kv| kv.trim().split_once('='))
                    .any(|(k, v)| {
                        k == self.config.pow.cookie
                            && kapigate_core::pow::verify(&self.config.pow, v, now_ms)
                    })
            });

        // One request view, shared by the WAF and every rate-limit
        // selector. The peer is authoritative; the XFF header was just
        // minted from it, so no client-supplied fallback is needed.
        let waf_request = kapigate_core::waf::WafRequest {
            method: &method,
            host: &host,
            path: &path,
            query: &query,
            user_agent: headers.get("user-agent").map_or("", String::as_str),
            referer: headers.get("referer").map_or("", String::as_str),
            content_type: headers.get("content-type").map_or("", String::as_str),
            client_ip,
            client_port: peer.map_or(0, |s| i64::from(s.port())),
            tls: parts
                .uri
                .scheme()
                .is_some_and(|s| s == &http::uri::Scheme::HTTPS),
        };

        // One table read: resolve the route FIRST (a namespace-local rate
        // limit needs the served app's namespace), then snapshot the two
        // watched sets. Everything expensive (compiling selectors/rules)
        // happens AFTER the guard drops.
        let (resolved, watched_waf, watched_waf_gen, watched_rates, watched_rates_gen) = {
            let table = self.informer.table.read().await;
            let resolved = table.resolve(
                &host,
                &path,
                |node, row| self.config.node_addr(node, row),
                self.config.defaults.node.as_deref(),
            );
            (
                resolved,
                table.waf_rules(),
                table.waf_rules_generation(),
                if verified_bot {
                    Vec::new()
                } else {
                    table.rate_limits()
                },
                table.rate_limits_generation(),
            )
        };
        let namespace = resolved.as_ref().map(|(r, _)| r.org.as_str());

        // A client that previously probed a reserved private/admin path is
        // refused (429) on ALL requests until its penalty window expires —
        // before any rate rule, WAF rule, cache, or backend work. The
        // penalty is recorded by the private-path block below; this is its
        // enforcement half. Verified bots are exempt from the penalty (the
        // WAF's built-in private-path drop still applies to them).
        if !verified_bot
            && let Some(ip) = client_ip
            && self.limiter.is_private_path_penalized(ip)
        {
            // Incident: a previously-penalized IP attempted to reach the
            // gateway again. Captured by the incident tracing layer.
            tracing::warn!(
                target: "incident",
                client_ip = %ip,
                host = %host,
                path = %path,
                rule = "private-path-penalty",
                action = "rate-limit",
                "penalized client request refused"
            );
            return Response::builder()
                .status(429)
                .header("retry-after", "60")
                .header("x-qreta-rate", "private-path-penalty")
                .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
                .body(Body::from("rate limit exceeded\n"))
                .unwrap();
        }

        // Rate limiting runs ahead of the WAF so a client past its budget
        // never reaches an expensive rule or a backend. Namespace-local CR
        // rules apply only to the resolved route's namespace; static TOML
        // rules are global. Verified bots are exempt.
        if !verified_bot && let Some(ip) = client_ip {
            let rate_rules = self
                .rate_rules
                .rules(&watched_rates, watched_rates_gen)
                .for_namespace(namespace);
            for rule in rate_rules {
                if !rule.matches(&waf_request) {
                    continue;
                }
                let bucket = rule.bucket(ip, &headers, &method, &host, &path);
                if let Some(retry_after) = self.limiter.check(&bucket, rule.limit, rule.window) {
                    let secs = retry_after.as_secs().max(1);
                    tracing::warn!(
                        target: "incident",
                        client_ip = %ip,
                        host = %host,
                        path = %path,
                        rule = %rule.name,
                        action = "rate-limit",
                        "configured rate limit exceeded"
                    );
                    return Response::builder()
                        .status(429)
                        .header("retry-after", secs.to_string())
                        .header("x-qreta-rate", sanitize_header_value(&rule.name))
                        .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
                        .body(Body::from("rate limit exceeded\n"))
                        .unwrap();
                }
            }
        }

        // The WAF (wirefilter) walks the SAME trimmed, host-minted view
        // the route law sees: a client cannot spoof a reserved header
        // or its own client IP, and a match blocks before any cache or
        // backend work. The watched `WafRule` CRs are folded in on a
        // generation change (off the hot path); the last good ruleset
        // stays live if a CR's rules fail to compile.
        // The WAF ALWAYS evaluates, even with no configured rules and even
        // for verified bots: the built-in private-path deny lives in
        // `WafRules::evaluate` and must never be skipped by an `is_empty`
        // fast path at this layer. Verified bots simply get an empty
        // configurable ruleset (the built-in deny still runs).
        // Verified bots keep their exemption from CONFIGURABLE rules
        // (empty watched set here); the built-in private-path deny still
        // runs inside `evaluate` either way.
        let verdict = if verified_bot || pow_solved {
            if let Some(headers) = self
                .waf
                .rules(&watched_waf, watched_waf_gen)
                .hardening_only(&waf_request)
            {
                *overrides = Some(headers);
            }
            self.waf.builtin_only().evaluate(&waf_request)
        } else {
            self.waf
                .rules(&watched_waf, watched_waf_gen)
                .evaluate(&waf_request)
        };
        if let kapigate_core::waf::WafVerdict::Hardening { headers, .. } = &verdict {
            *overrides = Some(headers.clone());
        }
        if let kapigate_core::waf::WafVerdict::Block {
            ref rule, action, ..
        } = verdict
            && action == kapigate_core::waf::WafAction::Challenge
            && self.config.pow.enabled()
        {
            // Issue a PoW puzzle: an HMAC-signed challenge plus a tiny
            // HTML page whose JS finds a nonce with the configured number
            // of leading zero bits, sets the solution cookie, and reloads.
            // A scraper that will not run JS never gets past this page.
            let nonce = {
                let mut b = [0u8; 16];
                let _ = getrandom::fill(&mut b);
                b
            };
            let challenge = kapigate_core::pow::issue(&self.config.pow, &nonce, now_ms);
            let cookie = &self.config.pow.cookie;
            let page = pow_challenge_page(&challenge, cookie, self.config.pow.difficulty);
            return Response::builder()
                .status(200)
                .header("content-type", "text/html; charset=utf-8")
                .header("x-qreta-waf", sanitize_header_value(rule))
                .header("cache-control", "no-store")
                .body(Body::from(page))
                .unwrap();
        }
        if let kapigate_core::waf::WafVerdict::Block {
            rule, status, body, ..
        } = verdict
        {
            // Probing a reserved private/admin path marks the source IP:
            // its every subsequent request is rate-limited (429) for the
            // penalty window. This is the recording half; enforcement is
            // the check at the top of the pipeline. The block itself is
            // returned regardless of the penalty.
            if rule == kapigate_core::waf::PRIVATE_PATH_RULE
                && let Some(ip) = client_ip
            {
                self.limiter.penalize_private_path(ip);
                tracing::warn!(
                    target: "incident",
                    client_ip = %ip,
                    host = %host,
                    path = %path,
                    rule = %rule,
                    action = "block",
                    "private/admin path probe blocked"
                );
            }
            // A rule name is operator-supplied config (except our built-in
            // literal); sanitize control characters and cap length so an
            // odd name cannot turn a block into a serving failure — while
            // keeping the name as the audit hint an operator needs.
            let rule_header = http::HeaderValue::from_str(&sanitize_header_value(&rule))
                .unwrap_or_else(|_| http::HeaderValue::from_static("invalid-rule-name"));
            return Response::builder()
                .status(status)
                .header("x-qreta-waf", rule_header)
                .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
                .body(Body::from(body))
                .unwrap();
        }
        if let Some((resolved, _addr)) = &resolved
            && let Some(scope) = resolved.cache_scope()
        {
            let key = format!("{method} {path}{query_wire}");
            if let Some((cached, age)) = self.cache.get_with_age(&scope, &key) {
                return cached_response(cached, age);
            }
        }
        // FR-007's store half: the artifact tree answers static GETs
        // before the forward (a miss falls through; the worker may own
        // the path). The tree rides the row's spec.image + spec.assets.
        // A fresh read guard supplies the namespace's pull credential to
        // the asset store (only on a tree miss, where an OCI pull may run).
        let table = self.informer.table.read().await;
        if let Some((resolved, _addr)) = &resolved
            && let Some(answer) = self
                .assets
                .serve(
                    resolved,
                    &method,
                    &path,
                    &query_wire,
                    &headers,
                    &|namespace, registry| table.registry_auth(namespace, registry),
                )
                .await
        {
            let (parts, body) = answer.into_parts();
            let mut builder = Response::builder().status(parts.status);
            for (k, v) in parts.headers.iter() {
                builder = builder.header(k, v);
            }
            return builder
                .header("x-qreta-cache", "asset")
                .body(Body::from(body))
                .unwrap();
        }
        let Some((resolved, addr)) = resolved else {
            return plain(404, "not found\n");
        };
        // A AssetsOnlyApp CR with NO httpRouteRef has no backend: a path
        // that missed public/ is a 404, not a worker forward. With a
        // route ref, the matched route's backend (addr) handles it — the
        // asset-first, worker-fallback law.
        if resolved
            .assets_only_apps
            .as_ref()
            .is_some_and(|b| b.http_route_ref.is_none())
        {
            return plain(404, "not found\n");
        }
        drop(table);
        let Some(addr) = addr else {
            // The route matches but no node answers (no Running pod,
            // no default node, no address): 503, the node never wakes.
            return plain(503, "no node answers this route\n");
        };

        // FR-003/FR-004: forward to the node's private listener with
        // the ORIGINAL Host preserved — the node's own table resolves
        // the app and instantiates it through the kubelet arm.
        let url = format!("http://{addr}{path}{query_wire}");
        let method = parts.method.clone();
        let coalescible = method == http::Method::GET || method == http::Method::HEAD;
        let mut out = self.http.request(
            reqwest::Method::from_bytes(method.as_str().as_bytes()).unwrap_or(reqwest::Method::GET),
            &url,
        );
        for (name, value) in &headers {
            if HOP_BY_HOP.contains(&name.as_str()) || name == "host" {
                continue;
            }
            out = out.header(name.as_str(), value.as_str());
        }
        out = out.header(http::header::HOST, &host);
        // The cap is honest: over the 64 MiB limit is a 413 — never a
        // silently emptied request forwarded downstream.
        let body = match axum::body::to_bytes(body, 64 * 1024 * 1024).await {
            Ok(body) => body,
            Err(_) => {
                return plain(413, "the request body exceeds the gateway's 64 MiB cap\n");
            }
        };
        out = out.body(body);

        if coalescible {
            // The coalescing key names the answer, not the caller: same
            // method + host + path + query + backend. Two clients racing
            // the same cold cache entry collapse into ONE upstream fetch.
            // The resolved backend addr is in the key so a route change
            // mid-flight cannot hand a follower another node's response.
            let key = format!("{method} {host}{path}{query_wire} -> {addr}");
            return self.coalesced_forward(&key, out).await;
        }
        match out.send().await {
            Ok(resp) => proxy_response(resp).await,
            Err(e) => forward_error(&e, &path, &query_wire),
        }
    }

    /// One upstream fetch per key, shared by all concurrent callers.
    /// Uniflight elects the first caller leader; followers await it and
    /// receive a clone of the buffered response. A leader panic is
    /// surfaced as `LeaderPanicked` — we retry the forward unguarded so
    /// a panic in one caller never takes the others down with it.
    async fn coalesced_forward(&self, key: &str, out: reqwest::RequestBuilder) -> Response {
        // A GET/HEAD builder carries no streaming body, so try_clone is
        // always Some here; a None would mean a body that cannot be
        // duplicated — fall back to an unguarded forward in that case.
        let Some(attempt) = out.try_clone() else {
            return match out.send().await {
                Ok(resp) => proxy_response(resp).await,
                Err(e) => forward_error(&e, key, ""),
            };
        };
        match self
            .coalescer
            .execute(
                key,
                || async move { Arc::new(forward_buffer(attempt).await) },
            )
            .await
        {
            Ok(coalesced) => buffered_response(&coalesced, true),
            Err(panicked) => {
                // The leader panicked inside its forward; retry honestly
                // rather than handing followers a synthetic failure.
                eprintln!(
                    "[gateway] coalescing leader panicked for {key}: {}; retrying unguarded",
                    panicked.message()
                );
                buffered_response(&Arc::new(forward_buffer(out).await), false)
            }
        }
    }

    /// The gateway's own faces: `/__gateway/health`, `/__gateway/cache` (the
    /// node's push road, bearer-gated).
    async fn gateway_face(
        &self,
        method: &str,
        path: &str,
        headers: &http::HeaderMap,
        body: &[u8],
    ) -> Response {
        match (method, path) {
            ("POST", "/__gateway/pow") => {
                // The PoW challenge page POSTs its solved solution here.
                // Verify it server-side, then set an HTTPOnly cookie and
                // redirect back to the original page (the Referer).
                let form = String::from_utf8_lossy(body);
                // The solution is base64url — no percent-encoding needed.
                let solution = form
                    .split('&')
                    .find_map(|kv| kv.strip_prefix("solution="))
                    .unwrap_or_default()
                    .to_owned();
                let now_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis()
                    .min(i64::MAX as u128) as i64;
                if !self.config.pow.enabled()
                    || !kapigate_core::pow::verify(&self.config.pow, &solution, now_ms)
                {
                    return plain(403, "invalid proof of work\n");
                }
                let redirect = headers
                    .get(http::header::REFERER)
                    .and_then(|v| v.to_str().ok())
                    .filter(|s| s.starts_with('/') || s.contains("://"))
                    .unwrap_or("/");
                Response::builder()
                    .status(303)
                    .header("location", redirect)
                    .header(
                        "set-cookie",
                        format!(
                            "{}={}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}",
                            self.config.pow.cookie, solution, self.config.pow.verify_ttl_secs
                        ),
                    )
                    .header("cache-control", "no-store")
                    .body(Body::empty())
                    .unwrap()
            }
            ("GET", "/__gateway/health") => {
                let (apps, served, nodes) = self.informer.table.read().await.counts();
                let watches = self
                    .informer
                    .health()
                    .into_iter()
                    .map(|(plural, connected, rv)| {
                        format!(
                            "{{\"plural\":\"{plural}\",\"connected\":{connected},\"rv\":\"{rv}\"}}"
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(",");
                // The roll handshake's comparable version (FR-012):
                // the largest family rv as a number, null before the
                // seed LIST lands; `ready` is the table fact itself.
                let max_rv = self
                    .informer
                    .max_rv()
                    .map(|rv| rv.to_string())
                    .unwrap_or_else(|| "null".to_owned());
                let ready = self.informer.is_seeded();
                let body = format!(
                    "{{\"apps\":{apps},\"served\":{served},\"nodes\":{nodes},\"ready\":{ready},\"max_rv\":{max_rv},\"watches\":[{watches}]}}\n"
                );
                json_response(200, &body)
            }
            ("POST", "/__gateway/cache") => {
                // FR-006's push road: the node forwards app puts here
                // (bearer-gated; the scope rides the body, baked
                // host-side at instantiation — the seal gateway-core
                // already enforces). The WAF does NOT filter this face
                // (reserved-prefix short-circuit above), so DEPLOYMENT
                // MUST bind this listener to a private address or place
                // it behind an access-control boundary: a leaked token
                // lets a caller seed arbitrary cache entries for any app.
                let Some(expected) = self.config.cache_push.as_ref() else {
                    return plain(403, "the cache push face is not configured\n");
                };
                let presented = headers
                    .get(http::header::AUTHORIZATION)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.strip_prefix("Bearer "))
                    .unwrap_or("");
                if !constant_time_eq(presented.as_bytes(), expected.token.as_bytes()) {
                    return plain(403, "the cache push token does not answer\n");
                }
                let Ok(push) = serde_json::from_slice::<CachePushBody>(body) else {
                    return plain(422, "the cache push body does not parse\n");
                };
                use base64::Engine as _;
                let body = base64::engine::general_purpose::STANDARD
                    .decode(&push.response.body)
                    .map_err(|e| format!("the push body is not base64: {e}"));
                let Ok(body) = body else {
                    return plain(422, "the push body is not base64\n");
                };
                let stored = CachedResponse {
                    status: push.response.status,
                    headers: push.response.headers,
                    body,
                };
                match self.cache.put(&push.scope, &push.key, stored) {
                    Ok(()) => plain(200, "ok\n"),
                    Err(reason) => plain(422, &format!("{reason}\n")),
                }
            }
            _ => plain(404, "not found\n"),
        }
    }
}

/// The cache push body: the node forwards one app put verbatim (the
/// scope the app's instantiation baked, the canonical
/// `{METHOD} {path}{query}` key, the stored response).
#[derive(serde::Deserialize)]
struct CachePushBody {
    scope: String,
    key: String,
    response: CachePushResponse,
}

#[derive(serde::Deserialize)]
struct CachePushResponse {
    status: u16,
    #[serde(default)]
    headers: Vec<(String, String)>,
    /// Base64 (the wire shape the node forwards — 5 MiB bodies stay
    /// compact JSON).
    #[serde(default)]
    body: String,
}

/// A cache hit as a wire response (the stored status, headers, body).
fn cached_response(cached: CachedResponse, age_secs: u64) -> Response {
    let mut builder = Response::builder().status(cached.status);
    for (name, value) in &cached.headers {
        // A stored Age would be stale — the edge recomputes it from the
        // entry's own stored_at (the cache is the authority, not the
        // app that pushed the response).
        if name.eq_ignore_ascii_case("age") {
            continue;
        }
        builder = builder.header(name.as_str(), value.as_str());
    }
    builder
        .header("age", age_secs.to_string())
        .header("x-qreta-cache", "hit")
        .body(Body::from(cached.body))
        .unwrap()
}

/// The node's answer, streamed back minus the hop-by-hop set. Every
/// non-hop-by-hop header the node set — including `Cache-Control` and
/// `CDN-Cache-Control` — passes through verbatim: the node owns its
/// caching policy, the gateway only stamps the miss status.
async fn proxy_response(resp: reqwest::Response) -> Response {
    let mut builder = Response::builder().status(resp.status().as_u16());
    for (k, v) in resp.headers().iter() {
        if HOP_BY_HOP.contains(&k.as_str()) {
            continue;
        }
        builder = builder.header(k, v);
    }
    let stream = resp.bytes_stream();
    builder
        .header("x-qreta-cache", "miss")
        .body(Body::from_stream(stream))
        .unwrap()
}

/// The leader's forward: buffer the node's answer into a cloneable
/// value so uniflight followers can each receive the same response.
/// GET/HEAD answers are the coalescing domain — small enough (app
/// pages, API reads) that buffering is an honest trade for deduping
/// a thundering herd at cold cache entries.
async fn forward_buffer(out: reqwest::RequestBuilder) -> CoalescedForward {
    match out.send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let headers = resp
                .headers()
                .iter()
                .filter(|(k, _)| !HOP_BY_HOP.contains(&k.as_str()))
                .map(|(k, v)| {
                    (
                        k.as_str().to_owned(),
                        v.to_str().unwrap_or_default().to_owned(),
                    )
                })
                .collect();
            match resp.bytes().await {
                Ok(body) => CoalescedForward {
                    status,
                    headers,
                    body,
                },
                Err(e) => error_forward(format!("the node dropped the body: {}", error_chain(&e))),
            }
        }
        Err(e) => error_forward(error_chain(&e)),
    }
}

/// A forward failure as a buffered 502 (the leader's answer is shared
/// with its followers — they see the same honest failure, not a retry
/// storm against a node that is already down).
fn error_forward(chain: String) -> CoalescedForward {
    eprintln!("[gateway] coalesced forward: {chain}");
    CoalescedForward {
        status: 502,
        headers: Vec::new(),
        body: Bytes::from(format!("the node is unreachable: {chain}\n")),
    }
}

/// A buffered forward as a wire response. `coalesced` stamps the
/// operator's datum — "hit" means this answer came through the
/// coalescer (one upstream fetch shared by all concurrent callers).
fn buffered_response(buffered: &CoalescedForward, coalesced: bool) -> Response {
    let mut builder = Response::builder().status(buffered.status);
    for (name, value) in &buffered.headers {
        builder = builder.header(name.as_str(), value.as_str());
    }
    builder = builder.header("x-qreta-cache", "miss");
    if coalesced {
        builder = builder.header("x-qreta-coalesced", "hit");
    }
    builder.body(Body::from(buffered.body.clone())).unwrap()
}

fn error_chain(e: &reqwest::Error) -> String {
    let mut chain = format!("{e}");
    let mut src = std::error::Error::source(e);
    while let Some(cause) = src {
        chain.push_str(&format!(" <- {cause}"));
        src = std::error::Error::source(cause);
    }
    chain
}

fn forward_error(e: &reqwest::Error, path: &str, query: &str) -> Response {
    let chain = error_chain(e);
    eprintln!("[gateway] forward {path}{query}: {chain}");
    plain(502, &format!("the node is unreachable: {chain}\n"))
}

fn json_response(status: u16, body: &str) -> Response {
    Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_owned()))
        .unwrap()
}

fn plain(status: u16, body: &str) -> Response {
    Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Body::from(body.to_owned()))
        .unwrap()
}

/// The PoW challenge page. Its inline JS decodes the base64url challenge,
/// brute-forces a `work` nonce with Web Crypto SHA-256 until the digest
/// has `difficulty` leading zero bits, then POSTs the solution back to a
/// tiny same-origin endpoint that sets the cookie and redirects. We do
/// the cookie-setting via a form POST to `/__gateway/pow` (a gateway face)
/// so the cookie is `HttpOnly` and not readable by JS.
fn pow_challenge_page(challenge: &str, cookie: &str, difficulty: u8) -> String {
    format!(
        r#"<!doctype html><html><head><meta charset="utf-8"><title>Verifying…</title></head>
<body><p>Verifying your browser…</p>
<form id="f" method="post" action="/__gateway/pow">
<input type="hidden" name="solution" id="s"><input type="hidden" name="cookie" id="c" value="{cookie}">
</form>
<script>
const b64 = (s) => atob(s.replace(/-/g,'+').replace(/_/g,'/') + '==='.slice((s.length+3)%4));
async function sha(s) {{
  const d = new TextEncoder().encode(s);
  const h = await crypto.subtle.digest('SHA-256', d);
  return new Uint8Array(h);
}}
function zeros(bytes) {{ let n=0; for (const b of bytes) {{ if (b===0) {{ n+=8; continue; }} n += Math.clz32(b)-24; break; }} return n; }}
(async () => {{
  const ch = b64({challenge:?});
  const parts = ch.split(':');
  const payload = parts.slice(0,3).join(':');
  for (let i=0; i<2000000; i++) {{
    const digest = await sha(payload + ':' + i);
    if (zeros(digest) >= {difficulty}) {{
      const solution = btoa(payload + ':' + i + ':' + parts[3]).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
      document.getElementById('s').value = solution;
      document.getElementById('f').submit();
      return;
    }}
  }}
  document.body.textContent = 'Verification failed — please reload.';
}})();
</script></body></html>"#
    )
}

/// Compare two byte strings without early exit on the first difference.
/// Used for the cache-push bearer: a plain `==` leaks the token's length
/// and prefix through timing, and this face can write arbitrary cache
/// entries for any app scope.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = u8::from(a.len() != b.len());
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Make an operator-supplied rule name safe for an HTTP header value:
/// drop control characters (which `HeaderValue` rejects) and cap the
/// length, keeping the audit hint intact.
fn sanitize_header_value(s: &str) -> String {
    const MAX: usize = 128;
    s.chars().filter(|c| !c.is_control()).take(MAX).collect()
}

/// The serving loop under the drain discipline (graceful-handover's
/// law, kapi.spec EDGE-FR-010's first land): the trigger is a future, the
/// stop-accept is STRUCTURAL — the select drops the serve future (and
/// its listener with it) before the barrier is ever awaited — and the
/// barrier then waits the in-flight requests out (the receiver count;
/// no atomics, no lost wakeup). The timeout is the config's; `None`
/// waits forever, `Some(n)` forces after n seconds naming the units
/// still live.
pub async fn serve_until(
    gateway: Arc<Gateway>,
    listener: tokio::net::TcpListener,
    signal: impl std::future::Future<Output = ()>,
    timeout: Option<std::time::Duration>,
) -> graceful_handover::DrainOutcome {
    let router = gateway.router();
    let serve = axum::serve(
        listener,
        router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    );
    tokio::select! {
        result = serve => {
            if let Err(e) = result {
                eprintln!("gateway: serve: {e}");
            }
        }
        _ = signal => {}
    }
    gateway.drain.trigger();
    gateway.drain.shutdown(timeout).await
}

#[cfg(test)]
mod header_tests {
    use super::*;

    #[test]
    fn bearer_compare_is_exact_and_length_safe() {
        assert!(constant_time_eq(b"secret", b"secret"));
        assert!(!constant_time_eq(b"secret", b"secreT"));
        assert!(!constant_time_eq(b"secret", b"secret-extra"));
        assert!(!constant_time_eq(b"", b"x"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn rule_names_are_sanitized_without_losing_their_identity() {
        assert_eq!(sanitize_header_value("no-scanners"), "no-scanners");
        assert_eq!(sanitize_header_value("bad\r\nname\u{7}"), "badname");
        assert_eq!(sanitize_header_value(&"x".repeat(300)).len(), 128);
    }
}
