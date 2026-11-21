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
use gateway_core::cache::{CachedResponse, EdgeCache};
use gateway_core::trim::trim_qreta;
use tokio::sync::watch;
use uniflight::Merger;

use crate::config::GatewayConfig;
use crate::kapi::Informer;

/// The gateway's reserved prefix (its own faces; the routing law never
/// sees these paths).
/// The gateway's reserved prefix (its own faces; the routing law
/// never sees these paths). The owner dropped the edge-flavored
/// vocabulary 2026-11-16: the faces ride /__gateway/* now.
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
    pub assets: crate::assets_store::AssetStore,
    /// The drain machinery (kapi.spec EDGE-FR-010's first land): every
    /// in-flight request holds a guard; the barrier waits them out.
    pub drain: graceful_handover::GracefulShutdown,
    /// Uniflight coalescer for cacheable GET/HEAD forwards: concurrent
    /// misses for the same key collapse into one upstream fetch; followers
    /// receive a clone of the leader's buffered response. Non-idempotent
    /// methods never enter this map.
    coalescer: Merger<String, Arc<CoalescedForward>>,
    http: reqwest::Client,
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
            assets: crate::assets_store::AssetStore::new(registry),
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

    async fn handle(&self, req: Request) -> Response {
        let (parts, body) = req.into_parts();
        let method = parts.method.as_str().to_owned();
        let host = parts
            .headers
            .get(http::header::HOST)
            .and_then(|h| h.to_str().ok())
            .map(|h| h.split(':').next().unwrap_or(h).to_ascii_lowercase())
            .unwrap_or_default();
        let path = parts.uri.path().to_owned();
        let query = parts
            .uri
            .query()
            .map(|q| format!("?{q}"))
            .unwrap_or_default();

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
        // x-forwarded-for is the gateway's own mint (the client's copy is
        // not a host fact — overwrite, never append).
        if let Some(ip) = parts
            .extensions
            .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        {
            headers.insert("x-forwarded-for".to_owned(), ip.0.ip().to_string());
        }

        // FR-006: the cache consult rides the app's sealed scope; the
        // scope goes live when the kubelet stamps the fingerprint on
        // the row (the push face already accepts puts under it).
        let table = self.informer.table.read().await;
        let resolved = table.resolve(
            &host,
            &path,
            |node, row| {
                // The static map, then the rows' own stamps. The old
                // spawn-arm child addresses are gone: the kubelet runs
                // workloads through CRI-O, whose addresses the deploy
                // supervisor resolves separately (`deploy.address`).
                self.config.node_addr(node, row)
            },
            self.config.defaults.node.as_deref(),
        );
        if let Some((resolved, _addr)) = &resolved
            && let Some(scope) = resolved.cache_scope()
        {
            let key = format!("{method} {path}{query}");
            if let Some((cached, age)) = self.cache.get_with_age(&scope, &key) {
                return cached_response(cached, age);
            }
        }
        // FR-007's store half: the artifact tree answers static GETs
        // before the forward (a miss falls through; the worker may own
        // the path). The tree rides the row's spec.image + spec.assets.
        if let Some((resolved, _addr)) = &resolved
            && let Some(answer) = self
                .assets
                .serve(
                    resolved,
                    &method,
                    &path,
                    &query,
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
                .header("x-gateway-cache", "asset")
                .body(Body::from(body))
                .unwrap();
        }
        let Some((resolved, addr)) = resolved else {
            return plain(404, "not found\n");
        };
        // A PublicAssets CR with NO httpRouteRef has no backend: a path
        // that missed public/ is a 404, not a worker forward. With a
        // route ref, the matched route's backend (addr) handles it — the
        // asset-first, worker-fallback law.
        if resolved
            .public_assets
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
        let url = format!("http://{addr}{path}{query}");
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
            let key = format!("{method} {host}{path}{query} -> {addr}");
            return self.coalesced_forward(&key, out).await;
        }
        match out.send().await {
            Ok(resp) => proxy_response(resp).await,
            Err(e) => forward_error(&e, &path, &query),
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
                // already enforces).
                let Some(expected) = self.config.cache_push.as_ref() else {
                    return plain(403, "the cache push face is not configured\n");
                };
                let presented = headers
                    .get(http::header::AUTHORIZATION)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.strip_prefix("Bearer "))
                    .unwrap_or("");
                if presented != expected.token {
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
        .header("x-gateway-cache", "hit")
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
        .header("x-gateway-cache", "miss")
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
    builder = builder.header("x-gateway-cache", "miss");
    if coalesced {
        builder = builder.header("x-gateway-coalesced", "hit");
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
