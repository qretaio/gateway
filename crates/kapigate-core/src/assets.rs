//! The static-asset response law (edge.spec FR-007): the extension
//! content-type map, the strong ETag
//! (the file's content hash, truncated), the revalidate-by-default
//! Cache-Control, the `_headers` rules, and the RFC 9110 conditional
//! GET. Total and pure: the caller fetches the bytes, these functions
//! shape the response. [`resolve_asset`] is the request-path to
//! shipped-file resolver the caller feeds the tree with.

use std::collections::BTreeMap;

use serde::Deserialize;

/// The asset posture a row declares — the fields the edge's asset
/// store consumes (the response law reads [`AssetSpec::hashes`] +
/// [`AssetSpec::header_rules`] as borrowed params; this type is the
/// row's parse vocabulary). The row's JSON parses straight into this
/// (the format is in flux by design; unknown fields ride through on
/// the kapi side and this type takes what it knows).
#[derive(Debug, Clone, Deserialize, Default)]
pub struct AssetSpec {
    /// The Cloudflare `run_worker_first` semantic: when true, every
    /// request invokes the worker and assets are NOT served directly.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub run_worker_first: bool,
    /// Url path (no leading slash) -> sha256 hex of the bytes. Feeds
    /// the per-file ETag; absent on rows written before this existed.
    #[serde(default)]
    pub hashes: BTreeMap<String, String>,
    /// `_headers` rules (Cloudflare Workers/Pages semantic): all
    /// matching rules apply to a response, later rules override
    /// earlier ones.
    #[serde(default)]
    pub header_rules: Vec<HeaderRule>,
}

/// One `_headers` rule: a url pattern with `*` (the rest of the path)
/// and `:name` (one segment) placeholders, and the headers it sets.
#[derive(Debug, Clone, Deserialize)]
pub struct HeaderRule {
    /// Url pattern, e.g. `/static/*`.
    pub pattern: String,
    /// Header name -> value, in file order.
    pub headers: BTreeMap<String, String>,
}

/// Content-Type for a served asset, by extension. Workers' map, trimmed
/// to what a static site actually ships.
fn content_type(path: &str) -> &'static str {
    let ext = path.rsplit_once('.').map(|(_, e)| e).unwrap_or("");
    match ext {
        "html" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "json" | "map" => "application/json",
        "webmanifest" => "application/manifest+json",
        "txt" => "text/plain; charset=utf-8",
        "xml" => "application/xml",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "avif" => "image/avif",
        "ico" => "image/x-icon",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "otf" => "font/otf",
        "wasm" => "application/wasm",
        "pdf" => "application/pdf",
        _ => "application/octet-stream",
    }
}

/// Build one asset response: content type, a strong ETag (the file's
/// content hash), the revalidate-by-default Cache-Control, then
/// the `_headers` rules for the path (later rules override earlier
/// ones). `200`s are served as `304` when the request's
/// `If-None-Match` still matches.
///
/// The two spec fields the law reads ride as borrowed params (the
/// `resolve_asset` idiom): the caller holds whatever spec shape its
/// layer parsed — the edge's row spec, the node's manifest spec —
/// and nothing materializes per request.
pub fn asset_response(
    hashes: &BTreeMap<String, String>,
    header_rules: &[HeaderRule],
    rel: &str,
    status: u16,
    body: Vec<u8>,
    req_headers: &BTreeMap<String, String>,
) -> http::Response<Vec<u8>> {
    let etag = hashes.get(rel).map(|h| short_etag(h));
    if status == 200 && not_modified(etag, req_headers) {
        return response_with_headers(304, &validators(header_rules, rel, etag), Vec::new());
    }
    let mut headers = validators(header_rules, rel, etag);
    headers.insert(CONTENT_TYPE.to_owned(), content_type(rel).to_owned());
    response_with_headers(status, &headers, body)
}

/// ETag + Cache-Control + `_headers` rules, in override order: defaults,
/// then rules, then the ETag (content-addressed truth can't be
/// redefined by the file).
fn validators(
    header_rules: &[HeaderRule],
    rel: &str,
    etag: Option<&str>,
) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    out.insert(
        CACHE_CONTROL.to_owned(),
        "public, max-age=0, must-revalidate".to_owned(),
    );
    out.insert(
        CDN_CACHE_CONTROL.to_owned(),
        CDN_CACHE_CONTROL_DEFAULT.to_owned(),
    );
    for rule in header_rules {
        if header_rule_matches(&rule.pattern, rel) {
            for (name, value) in &rule.headers {
                out.insert(name.to_ascii_lowercase(), value.clone());
            }
        }
    }
    if let Some(etag) = etag {
        out.insert(ETAG.to_owned(), format!("\"{etag}\""));
    }
    out
}

/// RFC 9110 `If-None-Match`: strong compare, weak candidates tolerated,
/// `*` matches any known validator. Without an ETag there is nothing to
/// compare and the condition serves 200.
fn not_modified(etag: Option<&str>, req_headers: &BTreeMap<String, String>) -> bool {
    let Some(inm) = req_headers.get("if-none-match") else {
        return false;
    };
    let Some(current) = etag else {
        return false;
    };
    inm.split(',').any(|candidate| {
        let candidate = candidate.trim();
        let candidate = candidate
            .strip_prefix("W/")
            .unwrap_or(candidate)
            .trim_matches('"');
        candidate == "*" || candidate == current
    })
}

/// Short strong ETag: the deploy's full sha256 hex, truncated the same
/// way versions are.
pub fn short_etag(sha256_hex: &str) -> &str {
    &sha256_hex[..16.min(sha256_hex.len())]
}

/// Cloudflare `_headers` matching: `*` matches the rest of the path,
/// `:name` matches one segment, anything else is literal. Compared
/// against the resolved asset path (so `/` and directory URLs match
/// their `index.html` rules).
pub fn header_rule_matches(pattern: &str, rel: &str) -> bool {
    fn segments(s: &str) -> Vec<&str> {
        s.trim_matches('/')
            .split('/')
            .filter(|s| !s.is_empty())
            .collect()
    }
    let pattern = segments(pattern);
    let path = segments(rel);
    let mut i = 0;
    while i < pattern.len() {
        match pattern[i] {
            "*" => return i < path.len() || pattern.len() == 1,
            seg if seg.starts_with(':') => {
                if i >= path.len() {
                    return false;
                }
            }
            seg => {
                if i >= path.len() || path[i] != seg {
                    return false;
                }
            }
        }
        i += 1;
    }
    pattern.len() == path.len()
}

/// Map a request path to a shipped asset path (no leading slash), or
/// `None`. Workers `auto-trailing-slash`, simplified: `/` and directory
/// URLs resolve to their `index.html`; an extensionless path resolves to
/// its directory index; an exact file wins outright.
pub fn resolve_asset(files: &BTreeMap<String, u64>, path: &str) -> Option<String> {
    let p = path.split(['?', '#']).next().unwrap_or(path);
    let rel = p.trim_start_matches('/');
    if rel.split('/').any(|seg| seg == "..") {
        return None;
    }
    if rel.is_empty() {
        return files
            .contains_key("index.html")
            .then(|| "index.html".into());
    }
    if p.ends_with('/') {
        let candidate = format!("{rel}index.html");
        return files.contains_key(&candidate).then_some(candidate);
    }
    if files.contains_key(rel) {
        return Some(rel.to_owned());
    }
    let candidate = format!("{rel}/index.html");
    files.contains_key(&candidate).then_some(candidate)
}

fn response_with_headers(
    status: u16,
    headers: &BTreeMap<String, String>,
    body: Vec<u8>,
) -> http::Response<Vec<u8>> {
    let mut builder = http::Response::builder().status(status);
    for (name, value) in headers {
        builder = builder.header(name.as_str(), value.as_str());
    }
    builder.body(body).unwrap()
}

const CONTENT_TYPE: &str = "content-type";
const CACHE_CONTROL: &str = "cache-control";
/// A CDN-only directive (Cloudflare's `CDN-Cache-Control` overrides
/// `Cache-Control` for the shared cache only). Assets are content-
/// addressed — the ETag changes on every deploy — so the CDN may hold
/// them for a year while browsers revalidate each time.
const CDN_CACHE_CONTROL: &str = "cdn-cache-control";
const CDN_CACHE_CONTROL_DEFAULT: &str = "public, max-age=31536000, immutable";
const ETAG: &str = "etag";

#[cfg(test)]
mod tests {
    use super::HeaderRule;
    use super::*;

    fn spec(rules: &[(&str, &str)]) -> AssetSpec {
        AssetSpec {
            run_worker_first: false,
            hashes: BTreeMap::from([("index.html".to_owned(), "a".repeat(64))]),
            header_rules: rules
                .iter()
                .map(|(p, n)| HeaderRule {
                    pattern: p.to_string(),
                    headers: BTreeMap::from([(n.to_string(), "v".to_owned())]),
                })
                .collect(),
        }
    }

    fn h_from(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn header_rules_match_segments_and_splats() {
        assert!(header_rule_matches("/*", "index.html"));
        assert!(header_rule_matches("/*", "a/b/c.js"));
        assert!(header_rule_matches("/static/*", "static/app.js"));
        assert!(header_rule_matches("/static/*", "static/app.js.map"));
        assert!(!header_rule_matches("/static/*", "src/app.js"));
        assert!(header_rule_matches("/:org/index.html", "acme/index.html"));
        assert!(!header_rule_matches(
            "/:org/index.html",
            "acme/about/index.html"
        ));
        assert!(!header_rule_matches("/index.html", "about/index.html"));
        assert!(!header_rule_matches("/a/*", "a")); // splat needs a remainder
        assert!(header_rule_matches("/a/*", "a/b"));
        assert!(header_rule_matches("/*", "a")); // bare splat matches everything
    }

    #[test]
    fn etag_conditionals() {
        let sha = "a".repeat(64);
        let etag = short_etag(&sha);
        // Strong match -> 304; weak prefix tolerated; list tolerated.
        assert!(not_modified(
            Some(etag),
            &h_from(&[("if-none-match", "\"aaaaaaaaaaaaaaaa\"")])
        ));
        assert!(not_modified(
            Some(etag),
            &h_from(&[("if-none-match", "W/\"aaaaaaaaaaaaaaaa\", \"b\"")])
        ));
        assert!(not_modified(Some(etag), &h_from(&[("if-none-match", "*")])));
        // Miss -> 200.
        assert!(!not_modified(
            Some(etag),
            &h_from(&[("if-none-match", "\"bbbbbbbbbbbbbbbb\"")])
        ));
        // No validator at all -> 200 even with INM: *.
        assert!(!not_modified(None, &h_from(&[("if-none-match", "*")])));
    }

    #[test]
    fn asset_responses_carry_validators_and_rule_headers() {
        let s = spec(&[("/index.html", "x-test")]);
        let req = BTreeMap::new();
        let resp = asset_response(
            &s.hashes,
            &s.header_rules,
            "index.html",
            200,
            b"hi".to_vec(),
            &req,
        );
        assert_eq!(resp.status(), 200);
        assert_eq!(
            resp.headers()["cache-control"],
            "public, max-age=0, must-revalidate"
        );
        // A CDN-only directive lets Cloudflare cache content-addressed
        // assets long-term while browsers revalidate each request.
        assert_eq!(
            resp.headers()["cdn-cache-control"],
            "public, max-age=31536000, immutable"
        );
        assert_eq!(resp.headers()["x-test"], "v");
        assert_eq!(resp.headers()["etag"], "\"aaaaaaaaaaaaaaaa\"");
        assert_eq!(resp.headers()["content-type"], "text/html; charset=utf-8");

        // Conditional round-trip: send the etag back -> 304 without a body.
        let etag = resp.headers()["etag"].to_str().unwrap().to_owned();
        let resp304 = asset_response(
            &s.hashes,
            &s.header_rules,
            "index.html",
            200,
            b"hi".to_vec(),
            &h_from(&[("if-none-match", &etag)]),
        );
        assert_eq!(resp304.status(), 304);
        assert!(resp304.body().is_empty());
        assert_eq!(resp304.headers()["x-test"], "v");
        assert_eq!(
            resp304.headers()["cdn-cache-control"],
            "public, max-age=31536000, immutable"
        );
        assert!(resp304.headers().get("content-type").is_none());
    }

    #[test]
    fn no_validator_means_no_304() {
        let mut s = spec(&[]);
        s.hashes.clear();
        let resp = asset_response(
            &s.hashes,
            &s.header_rules,
            "index.html",
            200,
            b"hi".to_vec(),
            &h_from(&[("if-none-match", "*")]),
        );
        assert_eq!(resp.status(), 200);
        assert!(resp.headers().get("etag").is_none());
    }

    fn tree(pairs: &[(&str, u64)]) -> BTreeMap<String, u64> {
        pairs.iter().map(|(k, v)| (k.to_string(), *v)).collect()
    }

    #[test]
    fn resolve_walks_index_and_trailing_slashes() {
        let files = tree(&[
            ("index.html", 1),
            ("about/index.html", 2),
            ("app.js", 3),
            ("docs/readme", 4),
        ]);
        // The root and any directory URL land on their index.html.
        assert_eq!(resolve_asset(&files, "/").as_deref(), Some("index.html"));
        assert_eq!(resolve_asset(&files, "").as_deref(), Some("index.html"));
        assert_eq!(
            resolve_asset(&files, "/about/").as_deref(),
            Some("about/index.html")
        );
        assert_eq!(
            resolve_asset(&files, "/about").as_deref(),
            Some("about/index.html")
        );
        // An exact file wins outright; an extensionless path takes the
        // directory index only when it exists.
        assert_eq!(resolve_asset(&files, "/app.js").as_deref(), Some("app.js"));
        assert_eq!(
            resolve_asset(&files, "/about/").as_deref(),
            Some("about/index.html")
        );
        assert_eq!(
            resolve_asset(&files, "/docs/readme").as_deref(),
            Some("docs/readme")
        );
        assert_eq!(resolve_asset(&files, "/missing"), None);
        // Query strings and fragments never reach the lookup.
        assert_eq!(
            resolve_asset(&files, "/app.js?v=2#top").as_deref(),
            Some("app.js")
        );
    }

    #[test]
    fn resolve_never_climbs_out() {
        // The `..` refusal is total, wherever it appears.
        let files = tree(&[("index.html", 1), ("../secret", 2)]);
        assert_eq!(resolve_asset(&files, "/../etc/passwd"), None);
        assert_eq!(resolve_asset(&files, "/a/../b"), None);
        assert_eq!(resolve_asset(&files, "/.."), None);
    }
}
