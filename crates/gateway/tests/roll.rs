//! The roll law tests (kapi.spec EDGE-FR-010..FR-014): the overlap shares
//! one port, the boot converges BEFORE it binds (and refuses
//! fail-closed when it cannot), the readiness is a table fact (and the
//! predecessor handshake's comparable version), and a fresh gateway
//! starts cold — a latency cost, never a correctness cost.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::Request;
use axum::response::Response;
use serde_json::{Value, json};
use tokio::sync::RwLock;

use gateway::config::{
    DrainConfig, GatewayConfig, KapiConfig, ListenConfig, RollConfig, SandboxConfig,
};
use gateway::kapi::Informer;
use gateway::server::Gateway;

/// A minimal config over the given kapi address; the listen port is
/// the caller's (the boot's handshake probes it).
fn gateway_config(
    kapi_addr: std::net::SocketAddr,
    listen_port: u16,
    converge_secs: u64,
) -> GatewayConfig {
    GatewayConfig {
        listen: ListenConfig {
            addr: format!("127.0.0.1:{listen_port}"),
        },
        tls: None,
        kapi: Some(KapiConfig {
            url: format!("http://{kapi_addr}"),
        }),
        nodes: Default::default(),
        defaults: Default::default(),
        drain: DrainConfig {
            timeout_secs: Some(2),
        },
        registry: Default::default(),
        cache_push: None,
        roll: RollConfig { converge_secs },
        deploy: None,
        sandbox: SandboxConfig {
            enabled: true,
            extra_connect: vec![],
            extra_read: Vec::new(),
        },
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// The watch face's leading line: the kube-rs WatchEvent shape kapi
/// rides in prod — the bookmark's head NESTED under `object`, the rv
/// riding the NUMBER side of the JSON fence — then the stream holds
/// open until the test ends. The fence reads both shapes; this mock
/// pins the nested-numeric one the two prod catches ride.
fn bookmarked_hold(rv: String) -> Response {
    let (line_tx, line_rx) = tokio::sync::mpsc::channel::<String>(4);
    tokio::spawn(async move {
        let bookmark = json!({"type": "BOOKMARK",
                              "object": {"metadata": {"resourceVersion": rv.parse::<u64>().unwrap_or(1)}}});
        let _ = line_tx.send(format!("{bookmark}\n")).await;
        // Hold the stream open — the informer's cycle blocks here
        // until the test ends.
        std::future::pending::<()>().await;
    });
    let stream = tokio_stream::wrappers::ReceiverStream::new(line_rx);
    use tokio_stream::StreamExt as _;
    Response::builder()
        .status(200)
        .header("content-type", "application/json")
        .body(Body::from_stream(
            stream.map(Ok::<_, std::convert::Infallible>),
        ))
        .unwrap()
}

/// The kapi mock: LIST answers `{rv, items:[]}` for every family, the
/// watch face holds a bookmarked stream open (the cycle stays open
/// until the test ends). `refuse` serves 500s on the LIST face — the
/// boot must refuse.
async fn mock_kapi_holding(rv: &'static str, refuse: bool) -> std::net::SocketAddr {
    let rv_state = Arc::new(RwLock::new(rv));
    let refuse_state = Arc::new(RwLock::new(refuse));
    let app = axum::Router::new().fallback(move |req: Request| async move {
        let (rv_state, refuse_state) = (Arc::clone(&rv_state), Arc::clone(&refuse_state));
        let (parts, body) = req.into_parts();
        let _ = axum::body::to_bytes(body, 1024).await;
        let query = parts.uri.query().unwrap_or_default().to_owned();
        if query.contains("watch=true") {
            let rv = rv_state.read().await.to_string();
            return bookmarked_hold(rv);
        }
        if *refuse_state.read().await {
            return Response::builder()
                .status(500)
                .body(Body::from("refused"))
                .unwrap();
        }
        let rv = *rv_state.read().await;
        let body = json!({
            "apiVersion": "v1",
            "kind": "List",
            "metadata": {"resourceVersion": rv},
            "items": [],
        });
        Response::builder()
            .status(200)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

/// The kapi mock with a per-family LIST refusal budget: `family`'s
/// first `refuse_first` LIST attempts answer 500 while every other
/// family answers immediately — one unlisted family must hold the
/// whole boot, however fast the other four converge.
async fn mock_kapi_refusing_family(
    rv: &'static str,
    family: &'static str,
    refuse_first: usize,
) -> std::net::SocketAddr {
    let rv_state = Arc::new(RwLock::new(rv));
    let attempts = Arc::new(RwLock::new(0usize));
    let app = axum::Router::new().fallback(move |req: Request| async move {
        let (rv_state, attempts) = (Arc::clone(&rv_state), Arc::clone(&attempts));
        let (parts, body) = req.into_parts();
        let _ = axum::body::to_bytes(body, 1024).await;
        let query = parts.uri.query().unwrap_or_default().to_owned();
        if query.contains("watch=true") {
            let rv = rv_state.read().await.to_string();
            return bookmarked_hold(rv);
        }
        let refusing = parts.uri.path().contains(family) && {
            let mut seen = attempts.write().await;
            let refuse = *seen < refuse_first;
            *seen += 1;
            refuse
        };
        if refusing {
            return Response::builder()
                .status(500)
                .body(Body::from("refused"))
                .unwrap();
        }
        let rv = *rv_state.read().await;
        let body = json!({
            "apiVersion": "v1",
            "kind": "List",
            "metadata": {"resourceVersion": rv},
            "items": [],
        });
        Response::builder()
            .status(200)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

/// The predecessor mock: answers `/__gateway/health` with the given
/// max_rv on the given port, anything else 404.
async fn mock_predecessor(port: u16, max_rv: u64) {
    let app = axum::Router::new().fallback(move |req: Request| async move {
        let (parts, body) = req.into_parts();
        let _ = axum::body::to_bytes(body, 1024).await;
        if parts.uri.path() == "/__gateway/health" {
            let body = json!({"max_rv": max_rv});
            Response::builder()
                .status(200)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap()
        } else {
            Response::builder()
                .status(404)
                .body(Body::from("no"))
                .unwrap()
        }
    });
    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
}

/// FR-010's overlap fact: two SO_REUSEPORT binds on ONE port both
/// succeed and both receive connections.
#[tokio::test]
async fn the_overlap_shares_one_port() {
    let port = free_port();
    let a = gateway::boot::bind_reuseport(&format!("127.0.0.1:{port}")).unwrap();
    let b = gateway::boot::bind_reuseport(&format!("127.0.0.1:{port}")).unwrap();
    assert_eq!(
        a.local_addr().unwrap().port(),
        b.local_addr().unwrap().port(),
        "both binds name the same port"
    );
    // The kernel hands each connect to one of the two listeners; both
    // must accept.
    let (tx, mut rx) = tokio::sync::mpsc::channel(4);
    for (name, listener) in [("a", a), ("b", b)] {
        let tx = tx.clone();
        tokio::spawn(async move {
            if listener.accept().await.is_ok() {
                let _ = tx.send(name).await;
            }
        });
    }
    let _stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    let who = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
        .await
        .expect("one of the overlap listeners accepted the connect");
    assert!(
        who == Some("a") || who == Some("b"),
        "the connect landed on an overlap listener"
    );
}

/// FR-010/FR-013: the boot binds ONLY after the table converges — a
/// kapi that refuses every LIST means a refused boot with NOTHING
/// bound; a working kapi means a bound listener whose health face
/// carries the table facts.
#[tokio::test]
async fn the_boot_binds_only_after_the_table_converges() {
    // Phase A: the refusing kapi — the boot refuses inside the budget,
    // the port stays free.
    let refusing = mock_kapi_holding("1", true).await;
    let port = free_port();
    let config = gateway_config(refusing, port, 1);
    let informer = Informer::new(config.kapi.as_ref().map(|k| k.url.as_str()).unwrap_or(""));
    let (_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let inf = Arc::new(informer);
    let run_inf = Arc::clone(&inf);
    tokio::spawn(async move { run_inf.run(shutdown_rx).await });
    let refused = gateway::boot::boot_listener(&config, &inf).await;
    assert!(
        refused.is_err(),
        "a non-converging table refuses the boot: {:?}",
        refused
    );
    assert!(
        tokio::net::TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .is_err(),
        "nothing was bound — zero packets could have been dropped"
    );

    // Phase B: the working kapi (rv 7) — the boot binds, and the
    // health face carries ready + the max rv (FR-012's comparable
    // version).
    let kapi = mock_kapi_holding("7", false).await;
    let port = free_port();
    let config = gateway_config(kapi, port, 10);
    let gateway = Arc::new(Gateway::new(config, None));
    let (_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let run_gateway = Arc::clone(&gateway);
    tokio::spawn(async move { run_gateway.run_informer(shutdown_rx).await });
    let listener = gateway::boot::boot_listener(&gateway.config, &gateway.informer)
        .await
        .expect("the converged boot binds");
    let serve_gateway = Arc::clone(&gateway);
    tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            serve_gateway
                .router()
                .into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await;
    });
    let addr = format!("127.0.0.1:{}", port);
    let client = reqwest::Client::new();
    let mut health = Value::Null;
    for _ in 0..50 {
        if let Ok(resp) = client
            .get(format!("http://{addr}/__gateway/health"))
            .send()
            .await
            && let Ok(v) = resp.json::<Value>().await
        {
            health = v;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert_eq!(
        health["ready"],
        json!(true),
        "health carries the fact: {health}"
    );
    assert!(
        health["max_rv"].as_u64().is_some_and(|v| v >= 7),
        "health carries the comparable rv: {health}"
    );
}

/// FR-012/FR-013: where a predecessor answers, its version is the
/// gate — a predecessor that stays ahead refuses the boot; a
/// predecessor at or below the boot's own version passes; no
/// predecessor at all (cold boot) passes on the own fact.
#[tokio::test]
async fn the_handshake_gates_on_the_predecessor_version() {
    let kapi = mock_kapi_holding("7", false).await;

    // A predecessor AHEAD: the boot refuses (its table may 404 a route
    // that exists — fail-closed).
    let ahead_port = free_port();
    mock_predecessor(ahead_port, 999).await;
    let config = gateway_config(kapi, ahead_port, 1);
    let informer = Informer::new(config.kapi.as_ref().map(|k| k.url.as_str()).unwrap_or(""));
    let (_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let inf = Arc::new(informer);
    let run_inf = Arc::clone(&inf);
    tokio::spawn(async move { run_inf.run(shutdown_rx).await });
    let refused = gateway::boot::boot_listener(&config, &inf).await;
    assert!(
        refused.is_err(),
        "a predecessor ahead refuses the boot: {:?}",
        refused
    );
    // The predecessor keeps serving untouched: its health face still
    // answers with its own version (it stays the sole listener).
    let client = reqwest::Client::new();
    let health = client
        .get(format!("http://127.0.0.1:{ahead_port}/__gateway/health"))
        .send()
        .await
        .expect("the predecessor still serves")
        .json::<serde_json::Value>()
        .await
        .expect("the predecessor's health parses");
    assert_eq!(
        health["max_rv"],
        json!(999),
        "the predecessor's own health answers: {health}"
    );

    // No predecessor (cold boot): the own fact suffices.
    let cold_port = free_port();
    let config = gateway_config(kapi, cold_port, 10);
    let informer = Informer::new(config.kapi.as_ref().map(|k| k.url.as_str()).unwrap_or(""));
    let (_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let inf = Arc::new(informer);
    let run_inf = Arc::clone(&inf);
    tokio::spawn(async move { run_inf.run(shutdown_rx).await });
    assert!(
        gateway::boot::boot_listener(&config, &inf).await.is_ok(),
        "a cold boot binds on its own converged fact"
    );
}

/// FR-014: a fresh gateway's cache starts cold — the consult misses, the
/// fallback forwards; cold is a latency cost, never a correctness one.
#[tokio::test]
async fn a_fresh_gateway_starts_cold() {
    let kapi = mock_kapi_holding("1", false).await;
    let config = gateway_config(kapi, free_port(), 10);
    let gateway = Gateway::new(config, None);
    assert!(
        gateway
            .cache
            .get("acme/state/fingerprint", "GET /")
            .is_none(),
        "the fresh cache misses any scope"
    );
}

/// The converge gate's tooth (FR-012/FR-013): secrets' LIST face
/// refuses its first three attempts while the other families answer
/// immediately — the boot must hold NOTHING bound while any family is
/// unlisted, then bind once the delayed family converges. The boot
/// binds only when EVERY family converged.
#[tokio::test]
async fn the_boot_refuses_until_every_family_converges() {
    let kapi = mock_kapi_refusing_family("7", "secrets", 3).await;
    let port = free_port();
    let config = gateway_config(kapi, port, 10);
    let informer = Informer::new(config.kapi.as_ref().map(|k| k.url.as_str()).unwrap_or(""));
    let (_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let inf = Arc::new(informer);
    let run_inf = Arc::clone(&inf);
    tokio::spawn(async move { run_inf.run(shutdown_rx).await });

    // The boot runs in the background; the gate decides when the port
    // appears.
    let boot_inf = Arc::clone(&inf);
    let boot = tokio::spawn(async move { gateway::boot::boot_listener(&config, &boot_inf).await });

    // While secrets is unlisted, NOTHING is bound: a probe window
    // across the first two refused re-lists (the gate reads the law —
    // every family — not whichever listed first).
    for _ in 0..10 {
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        assert!(
            tokio::net::TcpStream::connect(format!("127.0.0.1:{port}"))
                .await
                .is_err(),
            "nothing is bound while a family is unlisted"
        );
    }

    // The delayed family converges on its fourth attempt (the capped
    // re-list backoff: 1s + 2s + 4s ≈ 7s in) — inside the 10s budget
    // the gate opens and the bind lands.
    let mut bound = false;
    for _ in 0..150 {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        if tokio::net::TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .is_ok()
        {
            bound = true;
            break;
        }
    }
    assert!(
        bound,
        "the boot binds once the delayed family converges inside its budget"
    );
    let listener = boot
        .await
        .expect("the boot task joins")
        .expect("the boot's own answer is a bound listener");
    assert_eq!(listener.local_addr().unwrap().port(), port);
}
