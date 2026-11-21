//! The boot sequence (kapi.spec EDGE-FR-010..FR-013): CONVERGE, THEN BIND —
//! the kernel gives the new instance connections only once it is
//! ready, so a cold start can never answer a request from a half-built
//! table. The order is the law:
//!
//! 1. the informer's seed LISTs apply (the `seeded` table fact, FR-012
//!    — never a sleep),
//! 2. where a predecessor answers on the same port (the overlap
//!    window), its `max_rv` is fetched and the boot waits until its own
//!    table's version reaches it; a predecessor that stays ahead at the
//!    budget REFUSES the boot (fail-closed, FR-013 — the old instance
//!    keeps serving, zero packets dropped),
//! 3. only then the public port binds — under SO_REUSEPORT, so the
//!    overlap is one kernel decision (new connections shared), and the
//!    predecessor's stop-accept (closing its listener) leaves the set
//!    without dropping anything it already owns.

use std::time::Duration;

use crate::config::GatewayConfig;
use crate::kapi::Informer;

/// Bind the public listener with SO_REUSEPORT (FR-010): two gateway
/// instances share one port while the overlap window runs; solo, the
/// flag changes nothing observable.
pub fn bind_reuseport(addr: &str) -> std::io::Result<tokio::net::TcpListener> {
    use socket2::{Domain, Protocol, Socket, Type};
    let socket_addr: std::net::SocketAddr = addr
        .parse()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let domain = if socket_addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_port(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&socket_addr.into())?;
    socket.listen(1024)?;
    tokio::net::TcpListener::from_std(socket.into())
}

/// The boot's converged-then-bound outcome. `Err` is the FR-013
/// refusal: nothing was ever bound, a predecessor (if any) keeps
/// serving untouched.
pub async fn boot_listener(
    config: &GatewayConfig,
    informer: &Informer,
) -> Result<tokio::net::TcpListener, String> {
    let budget = Duration::from_secs(config.roll.converge_secs);
    let deadline = tokio::time::Instant::now() + budget;

    // 1. The table fact (FR-012): every family's LIST applied. The
    // family loops are already running and keep retrying with their
    // own capped backoff — the boot holds the informer's seeded watch
    // (every state update fires it) and the timeout bounds the budget,
    // so the deadline is always honored.
    let mut seeded = informer.subscribe_seeded();
    match tokio::time::timeout(budget, async {
        loop {
            if *seeded.borrow_and_update() {
                break;
            }
            seeded
                .changed()
                .await
                .map_err(|_| "the informer's seeded watch dropped".to_owned())?;
        }
        Ok::<(), String>(())
    })
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(e),
        Err(_) => {
            return Err(format!(
                "the seed LIST never converged inside {}s (FR-013: refusing the boot)",
                config.roll.converge_secs
            ));
        }
    }

    // 2. The handshake (FR-012's "where reachable"): a predecessor on
    // this port names its max rv; the boot waits until its own table
    // reaches it. Unreachable port = no predecessor (a cold boot) —
    // the own fact suffices. A predecessor that stays ahead at the
    // budget is a refused boot: a table behind its predecessor's may
    // 404 a route that exists, and fail-closed beats that.
    let (bind_host, listen_port) = match config.listen.addr.rsplit_once(':') {
        Some((host, port)) => (host.to_owned(), port.parse::<u16>().unwrap_or(80)),
        None => (config.listen.addr.clone(), 80),
    };
    // The probe dials the host a predecessor would SERVE, not the
    // bind wildcard: 0.0.0.0 / [::] / * / empty name every interface,
    // so the reachable one is loopback; a specific bind host IS the
    // reachable one (a hardcoded 127.0.0.1 there dials a face nobody
    // serves and the fail-closed gate silently dies).
    let dial_host = match bind_host.as_str() {
        "0.0.0.0" | "[::]" | "::" | "*" | "" => "127.0.0.1".to_owned(),
        other => other.to_owned(),
    };
    let predecessor_url = format!("http://{dial_host}:{listen_port}/__gateway/health");
    // The probe is bounded: a hung predecessor reads as cold boot
    // (fail-safe). A refused connect is the normal no-predecessor
    // fact; any other error is the operator's datum.
    let predecessor_rv: Option<u64> =
        match tokio::time::timeout(Duration::from_secs(5), reqwest::get(&predecessor_url)).await {
            Ok(Ok(resp)) if resp.status().is_success() => resp
                .json::<serde_json::Value>()
                .await
                .ok()
                .and_then(|v| v.get("max_rv").and_then(|r| r.as_u64())),
            Ok(Ok(_)) => None,
            Ok(Err(e)) => {
                if !e.is_connect() {
                    eprintln!("[gateway] predecessor probe {predecessor_url}: {e}");
                }
                None
            }
            Err(_) => {
                eprintln!("[gateway] predecessor probe {predecessor_url}: timed out at 5s");
                None
            }
        };
    if let Some(target) = predecessor_rv {
        // The catch-up wait rides the same seeded watch (every state
        // update fires it): wake, re-read max_rv, wait again — no
        // polling, the shared deadline honored.
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let mut seeded = informer.subscribe_seeded();
        match tokio::time::timeout(remaining, async {
            loop {
                if informer.max_rv().is_some_and(|own| own >= target) {
                    break;
                }
                seeded
                    .changed()
                    .await
                    .map_err(|_| "the informer's seeded watch dropped".to_owned())?;
            }
            Ok::<(), String>(())
        })
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                return Err(format!(
                    "the predecessor's table is ahead (rv {target}) and this boot never \
                     reached it inside {}s (FR-013: refusing the boot)",
                    config.roll.converge_secs
                ));
            }
        }
    }

    // 3. The bind (FR-010): reuseport, so the overlap is shared new
    // connections and nothing else.
    let listener = bind_reuseport(&config.listen.addr)
        .map_err(|e| format!("bind {}: {e}", config.listen.addr))?;
    Ok(listener)
}
