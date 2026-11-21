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
use crate::config::{CriConfig, GatewayConfig};
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
    let this = {
        let mut gateway = Gateway::new(config, data_root.clone());
        // The deploy arm (EDGE-FR-017): configured by the node's own
        // native files — CRI-O drop-ins + RuntimeClass YAML. Built in
        // async context (the CRI socket connect), then installed on the
        // gateway before it is shared.
        let deploy_cfg = gateway.config.deploy.as_ref().and_then(|d| d.cri.clone());
        let kapi_url = gateway
            .config
            .kapi
            .as_ref()
            .map(|k| k.url.clone())
            .unwrap_or_default();
        if let (Some(cri), true) = (deploy_cfg, !kapi_url.is_empty()) {
            match build_deploy_supervisor(&cri, &kapi_url, data_root.clone()).await {
                Ok(supervisor) => gateway = gateway.with_deploy(Arc::new(supervisor)),
                Err(e) => eprintln!("gateway: the CRI deploy arm is unavailable: {e}"),
            }
        }
        Arc::new(gateway)
    };
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    if let Some(deploy) = &this.deploy {
        let supervisor = Arc::clone(deploy);
        let shutdown = shutdown_rx.clone();
        tokio::spawn(async move { supervisor.run(shutdown).await });
        eprintln!("gateway: CRI deploy arm on (handler {})", deploy.handler());
    }
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

/// Build the deploy supervisor from the node's native CRI config. The
/// API-server seam is kube-rs (the same client the rest of kapi uses),
/// so the Deployment watch, pod status patch and Secret reads cannot
/// drift from the k8s wire shapes.
async fn build_deploy_supervisor(
    cri: &CriConfig,
    kapi_url: &str,
    data_root: Option<std::path::PathBuf>,
) -> anyhow::Result<cri_client::DeploySupervisor> {
    let config = cri_client::load_crio_config(&cri.conf_dir);
    let classes = cri_client::load_runtime_classes(&cri.runtime_class_dir);
    let handler = classes
        .values()
        .next()
        .map_or_else(|| config.runtime_handler.clone(), |c| c.handler.clone());
    let binding = controller::cri::Binding {
        endpoint: config.endpoint.clone(),
        node_name: cri.node_name.clone(),
    };
    let engine = cri_client::GrpcCriEngine::from_config(&config).await?;
    let client = cri_client::KubeKapiClient::connect(kapi_url, None, &cri.node_name)?;
    let supervisor =
        cri_client::DeploySupervisor::new(Arc::new(engine), Arc::new(client), binding, handler);
    // The generated Service-DNS hosts fragment lives under the node
    // data root (the only path the Landlock-confined process may write).
    // Pods mount it read-only at /etc/hosts via the CRI hostPath seam.
    let with_hosts = match data_root {
        None => supervisor.clone(),
        Some(root) => {
            let path = root.join("etc-hosts");
            match std::fs::create_dir_all(&root).and_then(|()| {
                std::fs::write(
                    &path,
                    "# generated by kapi Service controller\n127.0.0.1 localhost\n",
                )
            }) {
                Ok(()) => supervisor.with_hosts_path(path),
                Err(e) => {
                    eprintln!("gateway: Service hosts fragment unavailable: {e}");
                    supervisor.clone()
                }
            }
        }
    };
    Ok(with_hosts)
}
