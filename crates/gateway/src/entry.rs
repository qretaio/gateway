//! The gateway's run entry, shared by BOTH faces: the standalone
//! `kapi gateway <config>` subcommand and the in-process
//! `kapi server --with-gateway <config>` arm. Informer on, converge
//! the table (kapi.spec EDGE-FR-010's converge-then-bind), bind under
//! SO_REUSEPORT, serve under the drain discipline until SIGTERM or
//! SIGINT. A boot that cannot converge refuses (nothing was bound, so
//! nothing was dropped) — the caller decides what a refusal means
//! (the subcommand exits 1; the embedded arm fails the process, the
//! fail-closed law is one law).

use std::sync::Arc;

use tokio::sync::watch;

use crate::boot::boot_listener;
use crate::config::GatewayConfig;
use crate::server::{Gateway, serve_until};

/// Run the gateway to its drain outcome. `data_root`: the parent's
/// data dir (the kapi dir) — the kubelet reserves each child's data
/// beneath it by manifest kind + name; `None` keeps the children on
/// their platform default.
///
/// # Errors
/// The boot refused (the table did not converge inside the roll
/// budget) — nothing was bound.
pub async fn run(
    config: GatewayConfig,
    data_root: Option<std::path::PathBuf>,
) -> anyhow::Result<()> {
    let _ = data_root; // reserved for the host-side deploy arm (not in-cluster)
    // The WAF expressions must compile before the gate binds — a typo
    // is a boot refusal, not a request-time surprise. The TOML path
    // already validated at load; this closes the embedded/in-process
    // path that composes a config struct directly.
    config
        .validate_waf()
        .map_err(|e| anyhow::anyhow!("gateway WAF config refused: {e}"))?;
    let this = Arc::new(Gateway::new(config, None));
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let informer_this = Arc::clone(&this);
    let informer_shutdown = shutdown_rx.clone();
    tokio::spawn(async move { informer_this.run_informer(informer_shutdown).await });

    // FR-010's order: converge the table FIRST (the seed LISTs), ride
    // out the predecessor handshake where one answers, and only then
    // bind under SO_REUSEPORT.
    let listener = boot_listener(&this.config, &this.informer)
        .await
        .map_err(|e| anyhow::anyhow!("gateway boot refused: {e}"))?;
    let addr = this.config.listen.addr.clone();
    eprintln!(
        "gateway: table converged (rv {:?}), serving on {addr}, kapi at {}",
        this.informer.max_rv(),
        this.config
            .kapi
            .as_ref()
            .map(|k| k.url.as_str())
            .unwrap_or("<none>")
    );

    // The trigger as a future: SIGTERM (the deploy signal) or SIGINT
    // (the operator's) — whichever lands first.
    let signal = async {
        #[cfg(unix)]
        {
            let mut term =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("install SIGTERM handler");
            tokio::select! {
                _ = term.recv() => {}
                _ = tokio::signal::ctrl_c() => {}
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
        }
    };
    let timeout = this
        .config
        .drain
        .timeout_secs
        .map(std::time::Duration::from_secs);
    let outcome = serve_until(Arc::clone(&this), listener, signal, timeout).await;
    let _ = shutdown_tx.send(true);
    // Workloads are CRI-O pods now; their lifecycle belongs to the
    // deploy supervisor / kubelet, not the gateway process.
    eprintln!("gateway: stopped ({outcome:?})");
    Ok(())
}
