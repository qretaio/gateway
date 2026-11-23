//! The gateway layer's I/O arm: the kapi watch informer feeds the route
//! table, the serving face walks trim -> cache consult -> resolve ->
//! forward, the cache push face takes the fleet's puts. The laws live
//! in gateway-core (this workspace) — nothing is imported from any
//! runtime workspace. The crate moved home into the kapi workspace
//! 2026-11-16 (the wisolate-agnostic carve completed: the edge is now
//! kapi.s gateway; the wire faces keep their names — `/__gateway/*` and
//! `x-gateway-cache` are contracts with the node, not this crate's name).
//! The spawn arm (the kubelet) moved into the controller crate the same
//! day (owner directive: the gateway's controller belongs with the k8s
//! controllers) — `controller::spawn::Kubelet`, composed here unchanged.

pub mod assets_store;
pub use gateway_core::assets::AssetSpec;

pub mod boot;
pub mod bot_state;
pub mod config;
pub mod entry;
pub mod kapi;
pub mod oci;
pub mod rate_limit_state;
pub mod rate_state;
pub mod sandbox;
pub mod server;
pub mod table;
pub mod waf_state;
