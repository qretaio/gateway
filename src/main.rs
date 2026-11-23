//! The standalone `gateway` binary — the fleet's public serving face as
//! its own process (extracted from the `kapi` monorepo 2026-11-21).
//!
//! One subcommand, one config: load the TOML, CONFINE (the seatlock
//! policy precedes every thread — a refusal is fatal), then serve under
//! the drain discipline. The route table rides the kapi watch client
//! named in `[kapi]`; a config without it is a boot refusal.

use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use gateway::config::GatewayConfig;
use incident_log::{
    DiscardSink, HttpSink, IncidentLayer, IncidentSink, LocalDirSink, WriterConfig, run_writer,
};
use tokio::sync::mpsc;
use tracing_subscriber::Layer as _;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

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

    rt.block_on(async move {
        // Incident logging as a tracing layer. The sink is configured by
        // env: GATEWAY_INCIDENT_DIR writes parquet locally; otherwise
        // GATEWAY_INCIDENT_URL (+ bearer) POSTs JSON to the node's
        // private log-write face. Best-effort: a missing config simply
        // leaves the layer capturing into an unread channel — no boot
        // failure, no request-path cost beyond a try_send.
        let (tx, rx) = mpsc::channel(4096);
        let instance =
            std::env::var("GATEWAY_INSTANCE").unwrap_or_else(|_| "gateway-local".to_owned());
        let (sink, http_json): (Arc<dyn IncidentSink>, bool) =
            match std::env::var("GATEWAY_INCIDENT_DIR") {
                Ok(dir) => (Arc::new(LocalDirSink::new(dir)), false),
                Err(_) => match std::env::var("GATEWAY_INCIDENT_URL") {
                    Ok(url) => {
                        let bearer = std::env::var("GATEWAY_INCIDENT_BEARER").unwrap_or_default();
                        (Arc::new(HttpSink::new(url, bearer)), true)
                    }
                    Err(_) => {
                        // No sink configured: drop incidents quietly.
                        (Arc::new(DiscardSink), false)
                    }
                },
            };

        tracing_subscriber::registry()
            .with(
                tracing_subscriber::fmt::layer().with_filter(
                    tracing_subscriber::EnvFilter::try_from_default_env()
                        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
                ),
            )
            .with(IncidentLayer::new(tx, instance))
            .init();

        let writer_cfg = WriterConfig {
            batch_size: 64,
            flush_every: Duration::from_secs(5),
            http_json,
        };
        tokio::spawn(run_writer(rx, sink, writer_cfg));

        gateway::entry::run(config, None).await
    })
}
