# gateway

The qreta fleet's public serving face, extracted from the `kapi`
monorepo into its own project and binary (2026-11-21).

```sh
cargo run --bin gateway -- /etc/kapi/gateway.toml
cargo test
cargo clippy --all-targets
```

## What it does

- Reads the route table from a kapi watch (`[kapi] url` in the TOML).
- Resolves `Host` + path against typed `HTTPRoute` resources, serves
  static assets from OCI image layers, and forwards everything else to
  the node's private listener.
- Consults the edge cache before any backend; the node's push face
  (`POST /__gateway/cache`, bearer-gated) fills it.
- **Coalesces concurrent cacheable GET/HEAD forwards** with
  [`uniflight::Merger`](https://github.com/microsoft/oxidizer/tree/main/crates/uniflight):
  N clients racing the same cold route collapse into one upstream fetch;
  followers receive a clone of the leader's buffered response. The
  `x-gateway-coalesced: hit` header marks those answers. Non-idempotent
  methods (POST/PUT/DELETE/…) are never coalesced.
- **WAF filters** with [Cloudflare wirefilter](https://github.com/cloudflare/wirefilter)
  (unreleased 0.7 master, pinned — its compiled `Filter` is `Send + Sync`):
  ordered `[[waf.rules]]` expressions over the request (method, host,
  path, query, user-agent, referer, content-type, client IP/port, TLS)
  run after the reserved-header trim and before the cache/resolve/forward.
  Rules are parsed and compiled ONCE at boot into a shared `WafRules`
  (`Arc<Filter>` per rule); the request path only builds an execution
  context and runs the closure trees (~134 ns for four rules). First
  match blocks (the node never sees it) and stamps `x-gateway-waf: <rule>`.
  Bad expressions are a boot refusal. No rules = the configurable layer is inert, **but** the reserved private/admin paths `/__private/` and `/__internal/` (and their bare roots) are dropped unconditionally by a built-in check — these are the node's admin-channel faces and must never be reachable at the public edge. The deny runs before the ruleset, returns 404, and stamps `x-gateway-waf: reserved-private-path`.
 - **Incident logging (plain tracing)**: private/admin path probes and
   rate-limit penalties emit structured `tracing::warn!` events with
   `target: "incident"` and named fields (`client_ip`, `host`, `path`,
   `rule`, `action`). `main.rs` installs `tracing_subscriber::fmt().json()`
   so these land as JSON lines on stdout for the platform's collector.
   No producer-side sync, channels, or parquet code in this binary — that
   keeps the gateway small; the node owns the parquet log store.
 - **Proof-of-work bot challenges**: a WAF rule with `action = "challenge"`
   issues an HMAC-signed SHA-256 puzzle (HSSL, `gateway-core::pow`) when
   `[pow] secret` is set. A tiny inline JS page solves it in the browser,
   POSTs the solution to `/__gateway/pow`, and receives an HTTPOnly cookie;
   subsequent requests carrying a valid solution skip configurable WAF
   rules (built-in private/secret-path denies still apply). With no secret,
   challenge rules answer 503 (honest "not served").
 - **Response hardening**: `[hardening]` stamps HSTS, `X-Content-Type-Options:
   nosniff`, `Referrer-Policy`, `X-Frame-Options`, `Permissions-Policy`, and
   a default CSP on **every** response (including blocks, cached answers,
   and proxied streams) — applied centrally so no early-return path skips it.
 - **Rate limits** with bounded sliding-window counters ahead of the WAF:
  `[[ratelimit.rules]]` bound a client (optionally per route). The first
  rule past its budget answers 429 with `Retry-After` and
  `x-gateway-rate: <rule>`; a blocked hit is not recorded, so it cannot
  extend its own ban. The counter map is capped and LRU-evicted, so a
  spray of source IPs cannot grow it without limit. No rules = inert.
  Limits also arrive as watched, namespace-local `RateLimit` CRs whose
  wirefilter selectors pick the requests and whose keys may include a
  header value (split one client's budget by tenant).
- **Verified bots**: with `[verified_bots] enabled = true`, a peer that
  forward-confirms (FCrDNS) to a hostname ending in `allowed_suffixes`
  (e.g. `.googlebot.com`) is exempt from both WAF and rate limits and goes
  straight to routing. PTR + forward A/AAAA lookups run under a timeout
  with a bounded, TTL'd per-IP cache; failures time out OPEN (no
  exemption). The peer IP comes from the TCP connection, never a header.
- Boots under the drain discipline (graceful-handover): converge the
  table, bind under SO_REUSEPORT, drain in-flight requests on SIGTERM.
- Self-confines with seatlock when `[sandbox] enabled = true`.

## WAF config example

```toml
[[waf.rules]]
name = "no-scanners"
expression = 'http.ua contains "sqlmap"'
# action = "block"     # default
# status = 403         # default
# body = "blocked\n"   # default

[[waf.rules]]
name = "no-admin-from-public"
expression = 'http.path contains "/admin" and not ip.addr in {10.0.0.0/8}'

[[waf.rules]]
name = "parked"
expression = "draft !!!"
enabled = false
```

Fields: `http.method`, `http.host`, `http.path`, `http.query`,
`http.ua`, `http.referer`, `http.content_type`, `ip.addr`,
`ip.known` (false for the 0.0.0.0 unknown-client sentinel — gate inverted
IP rules on it, e.g. `ip.known and not ip.addr in {…}`), `client.port`,
`tls`. Operators (wirefilter 0.7): `==`, `!=`, ordering, `contains`,
`matches`, `in {…}`, `&`, boolean `and`/`or`/`not`, and `wildcard`.
An enabled ruleset is capped (512 rules); regex and wildcard expressions
carry explicit compile-size/star caps.

## Rate limit + verified bot config example

```toml
[[ratelimit.rules]]
name = "global"
limit = 120
window_secs = 60

[[ratelimit.rules]]
name = "login"
limit = 5
window_secs = 60
per_route = true          # key on client IP + method + host + path

[verified_bots]
enabled = true
allowed_suffixes = [".googlebot.com", ".google.com", ".bing.com"]
cache_ttl_secs = 600      # per-IP verification cache
timeout_ms = 1500         # DNS lookup timeout (fail-open)
cache_max_entries = 4096
```

A rate-limited client never reaches a rule or the backend; a verified bot
skips both layers. Both are validated at config load — a zero
limit/window or an enabled bot list with no suffixes is a boot refusal.

## PoW + hardening config example

```toml
[pow]
secret = "replace-with-a-random-secret"   # empty = challenges inert (503)
difficulty = 16        # leading zero bits of SHA256 (1..=32)
ttl_secs = 60          # puzzle lifetime
verify_ttl_secs = 3600 # solved-cookie trust window
cookie = "__gateway_pow"

[hardening]
hsts_max_age = 31536000
hsts_include_subdomains = true
nosniff = true
referrer_policy = "strict-origin-when-cross-origin"
frame_options = "DENY"
permissions_policy = "camera=(), microphone=(), geolocation=(), payment=()"
content_security_policy = "default-src 'self'; style-src 'self' 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'"
# xss_protection = false   # legacy; modern CSP supersedes it
```

To issue challenges, pair a `challenge` WAF rule with `[pow]`:

```toml
[[waf.rules]]
name = "bot-check"
expression = 'http.ua contains "bot"'
action = "challenge"
```

## WafRule CRD (watched, dynamic rules)

Rules can also be delivered as typed `WafRule` custom resources in the
`gateway.qreta.io/v1alpha1` group. The gateway watches `/apis/gateway.qreta.io/v1alpha1/wafrules`
from kapi and folds every CR's `spec.rules` into the compiled ruleset
(static TOML rules first, then CRs in namespace/name order — the first
match blocks). A CR delta recompiles off the request path; a CR whose
expression fails to compile is skipped and the last good ruleset stays
live.

```yaml
apiVersion: gateway.qreta.io/v1alpha1
kind: WafRule
metadata:
  name: scanners
  namespace: acme
spec:
  rules:
    - name: no-scanners           # stamped on x-gateway-waf
      expression: 'http.ua contains "sqlmap"'
      # action: block            # default; "challenge" answers 503
      # status: 403              # default
      # body: "blocked by the WAF\n"
      # enabled: true            # default
```

A CR with no `spec.rules` is inert. The wire types live in
`gateway-core::crd` (`WafRuleSpec`, `WafRuleEntry`, `WafRuleStatus`);
the gateway's `WafRule` family in `table.rs` parses and tracks them.

## RateLimit CRD (watched, namespace-local rules)

Rate limits can also be delivered as typed `RateLimit` custom resources in
the `gateway.qreta.io/v1alpha1` group (watched like `WafRule`). A CR is
**namespace-local**: its rules only apply to requests whose resolved route
belongs to the CR's namespace, so teams own their own budgets. One CR may
carry multiple independent rules; each has three stages:

1. **`match`** — a wirefilter selector (same fields/scheme as the WAF)
   deciding whether the rule applies to a request. Empty = all requests.
2. **`key`** — dynamic group sources. The client IP (TCP peer, never a
   header) is always the first bucket component; each `header` adds that
   header's runtime value, splitting one client's budget by tenant/API key.
   Missing headers contribute an empty component.
3. **`limit` / `windowSecs`** — the bounded sliding-window counter, per
   bucket. The first rule over budget answers 429 with `Retry-After` and
   `x-gateway-rate: <rule>`.

```yaml
apiVersion: gateway.qreta.io/v1alpha1
kind: RateLimit
metadata:
  name: api-budgets
  namespace: acme        # only acme's routes
spec:
  rules:
    - name: per-tenant-api
      match: 'http.path contains "/api"'
      limit: 60
      windowSecs: 60
      key:
        - header: x-api-key
    - name: logins
      match: 'http.method == "POST" and http.path contains "/login"'
      limit: 5
      windowSecs: 60
```

Selectors are compiled once off the request path (sharing the WAF's
wirefilter parser and caps) and generation-gated with a last-good fallback.
Static `[[ratelimit.rules]]` from TOML remain global and apply to every
namespace. Bad selectors/numbers are rejected at the watch seam.

Deployment prerequisite: the `WafRule` and `RateLimit` CRDs must be registered in kapi
before the gateway boots. It is a watched family, so its seed LIST is
part of boot convergence — an unregistered CRD holds the boot open until
`[roll] converge_secs` and refuses it (FR-013), like any other family.

## WAF engine benchmark

`cargo bench -p gateway-core --bench waf_engines` compares the wirefilter
WAF law against CEL (`cel-interpreter`) on equivalent rules — the gateway's
real precompiled regime, compile + evaluate per request (the old 0.6
cost), and an ordered-rule chain. Both engines are checked for equivalent
answers before measuring. Current results: precompiled wirefilter ~134 ns
vs CEL ~2.8 µs for four rules (~20x); single rule ~120 ns vs ~2.3 µs.

## Layout

| Path | Crate | Purpose |
| --- | --- | --- |
| `crates/gateway` | `gateway` | The I/O arm: kapi informer, route table, cache, asset store, serving pipeline, OCI pull, sandbox. |
| `crates/gateway-core` | `gateway-core` | Pure laws: route matcher, asset response law, cache store, inbound trim. |
| `crates/graceful-handover` | `graceful-handover` | Drain discipline + cutover state machines over local IPC. |
| `src/main.rs` | `gateway-bin` | The standalone `gateway` binary. |

The deploy arm (CRI-O supervisor) path-depends on `controller` and
`cri-client` from the sibling kapi checkout; the sandbox path-depends on
`seatlock`, and the handover crate on `fsm`.
