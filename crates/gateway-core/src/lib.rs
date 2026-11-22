//! The edge layer's pure laws.
//! 0.2.90, DEC-020: the edge leaves the node; the law text lives in
//! `specs/edge.spec` 0.1.0 draft). Three families, all total functions
//! over plain data: no I/O, no clock reads beyond the cache's monotonic
//! TTLs, `forbid(unsafe)`. The node re-exports every law in place (the
//! DEC-018 one-home pattern — `src/cache.rs` and `src/edge_routing.rs`
//! are the stable faces), and the edge repo (`~/src/qretaio/edge`)
//! depends on this crate rather than copying code.
//!
//! * [`routes`] — the host route matcher (edge.spec FR-001): exact Host, longest path prefix, 404 on miss.
//! * [`assets`] — the static-asset response law (edge.spec FR-007) and
//!   the shipped-file resolver.
//! * [`cache`] — the edge cache store (edge.spec FR-006): per-app sealed scopes, volatile, TTL-led.
//! * [`trim`] — the inbound trim law (edge.spec FR-008): client `x-qreta-*` stripped first.
//! * [`waf`] — the WAF filter law: Cloudflare wirefilter expressions over a request snapshot, first match blocks.
//! * [`crd`] — the wire types for the gateway's own typed custom resources (`gateway.qreta.io/v1alpha1`).

#![forbid(unsafe_code)]

pub mod assets;
pub mod cache;
pub mod crd;
pub mod public_assets;
pub mod routes;
pub mod trim;
pub mod waf;
