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
  Bad expressions are a boot refusal. No rules = the layer is inert.
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
`http.ua`, `http.referer`, `http.content_type`, `ip.addr`, `client.port`,
`tls`. Operators (wirefilter 0.6): `==`, `!=`, ordering, `contains`,
`matches`, `in {…}`, `&`, and boolean `and`/`or`/`not`.

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

Deployment prerequisite: the `WafRule` CRD must be registered in kapi
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
