//! The standalone `gateway` binary — the fleet's public serving face as
//! its own process (extracted from the `kapi` monorepo 2026-11-21).
//!
//! One subcommand, one config: load the TOML, CONFINE (the seatlock
//! policy precedes every thread — a refusal is fatal), then serve under
//! the drain discipline. The route table rides the kapi watch client
//! named in `[kapi]`; a config without it is a boot refusal.

use clap::Parser;
use gateway::config::GatewayConfig;

#[derive(Parser)]
#[command(
    name = "gateway",
    version,
    about = "the qreta fleet gateway: host routing, edge cache, and coalesced forwards"
)]
struct Cli {
    /// The gateway config (TOML: `[listen]`, `[kapi]`, `[nodes]`, ...).
    config: String,
}

fn main() -> anyhow::Result<()> {
    // Structured logging only. Incident sites emit `tracing::warn!` with
    // `target: "incident"` and named fields (client_ip, host, path, rule,
    // action); `fmt().json()` writes them to stdout as JSON lines for the
    // platform's log collector. No producer-side sync, channels, or
    // parquet in this binary — the node owns the parquet log store.
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    let config = GatewayConfig::load(&cli.config).map_err(|e| anyhow::anyhow!("{e}"))?;
    if config.kapi.is_none() {
        anyhow::bail!(
            "the standalone gateway needs [kapi] url in its config (the route table's source of truth)"
        );
    }
    if config.sandbox.enabled {
        gateway::sandbox::apply(&config);
    }
    // Bound memory: the default blocking pool (512 × 2 MiB stacks) is far
    // larger than the gateway needs.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(8)
        .thread_stack_size(256 * 1024)
        .enable_all()
        .build()?;
    rt.block_on(gateway::entry::run(config, None))
}
