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
- Boots under the drain discipline (graceful-handover): converge the
  table, bind under SO_REUSEPORT, drain in-flight requests on SIGTERM.
- Self-confines with seatlock when `[sandbox] enabled = true`.

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
