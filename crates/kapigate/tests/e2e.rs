//! The end-to-end seam: a mock kapi (list + a live watch feed), a mock
//! node (echoes what it received), and the real gateway pipeline between
//! them. Proves the slice: the watch feeds the table, the trim runs
//! first, the forward preserves the Host, the cache push face is
//! bearer-gated, an unknown host 404s without touching a node.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::Request;
use axum::response::Response;
use serde_json::{Value, json};
use tokio::sync::broadcast;
use tokio_stream::StreamExt;

use kapigate::config::{CachePushConfig, GatewayConfig, KapiConfig, ListenConfig};
use kapigate::server::Gateway;

/// An app-shaped route seed as a typed HttpRoute body.
fn hr(name: &str, routes: &[&str]) -> Value {
    let mut hostnames = Vec::new();
    let mut paths = Vec::new();
    for r in routes {
        let (host, path) = match r.split_once('/') {
            Some((h, p)) => (h, format!("/{}", p)),
            None => (*r, "/".to_owned()),
        };
        if !hostnames.contains(&host.to_owned()) {
            hostnames.push(host.to_owned());
        }
        if !paths.contains(&path) {
            paths.push(path);
        }
    }
    let matches: Vec<Value> = paths
        .iter()
        .map(|p| json!({"path": {"type": "PathPrefix", "value": p}}))
        .collect();
    json!({
        "apiVersion": "gateway.networking.k8s.io/v1", "kind": "HTTPRoute",
        "metadata": {"name": name, "namespace": "acme"},
        "spec": {"hostnames": hostnames,
                 "rules": [{"matches": matches, "backendRefs": [{"name": name, "port": 80}]}]}
    })
}

/// The mock kapi: fixed seed rows per plural plus a broadcast channel
/// the tests inject events through. The watch face is a real JSON-line
/// stream: the leading BOOKMARK, then every matching injected event.
async fn mock_kapi(
    seed_rows: Vec<(String, Value)>,
) -> (
    std::net::SocketAddr,
    broadcast::Sender<(String, String, Value)>,
) {
    let (event_tx, _) = broadcast::channel::<(String, String, Value)>(64);
    let rows: Arc<std::sync::Mutex<Vec<(String, Value)>>> =
        Arc::new(std::sync::Mutex::new(seed_rows));
    let rows_for_handler = Arc::clone(&rows);
    let tx_for_handler = event_tx.clone();
    let app = axum::Router::new().fallback(move |req: Request| {
        let rows = Arc::clone(&rows_for_handler);
        let event_tx = tx_for_handler.clone();
        async move {
            let (parts, body) = req.into_parts();
            let path = parts.uri.path().to_owned();
            let query = parts.uri.query().unwrap_or_default().to_owned();

            if path == "/__test/event" {
                let body = axum::body::to_bytes(body, 1024 * 1024).await.unwrap();
                let event: Value = serde_json::from_slice(&body).unwrap();
                let family = event["family"].as_str().unwrap().to_owned();
                let event_type = event["type"].as_str().unwrap().to_owned();
                let object = event["object"].clone();
                let _ = event_tx.send((family, event_type, object));
                return Response::builder()
                    .status(200)
                    .body(Body::from("ok"))
                    .unwrap();
            }

            let plural = path.rsplit('/').next().unwrap_or("").to_owned();
            if query.contains("watch=true") {
                // The watch face: the bookmark, then the injected
                // events matching this plural, as a JSON-line stream.
                let (line_tx, line_rx) = tokio::sync::mpsc::channel::<String>(16);
                let mut rx = event_tx.subscribe();
                let plural_for_feed = plural.clone();
                tokio::spawn(async move {
                    let _ = line_tx
                        .send(format!(
                            "{}\n",
                            json!({"type": "BOOKMARK",
                                   "metadata": {"resourceVersion": "42"}})
                        ))
                        .await;
                    loop {
                        match rx.recv().await {
                            Ok((family, event_type, object)) => {
                                if family != plural_for_feed {
                                    continue;
                                }
                                let line = json!({"type": event_type, "object": object});
                                if line_tx.send(format!("{line}\n")).await.is_err() {
                                    return;
                                }
                            }
                            Err(broadcast::error::RecvError::Lagged(_)) => continue,
                            Err(broadcast::error::RecvError::Closed) => return,
                        }
                    }
                });
                let stream = tokio_stream::wrappers::ReceiverStream::new(line_rx);
                let body = Body::from_stream(stream.map(Ok::<_, std::convert::Infallible>));
                return Response::builder()
                    .status(200)
                    .header("content-type", "application/json")
                    .body(body)
                    .unwrap();
            }

            // The list face.
            let items: Vec<Value> = rows
                .lock()
                .unwrap()
                .iter()
                .filter(|(family_row, _)| *family_row == plural)
                .map(|(_, row)| row.clone())
                .collect();
            let body = json!({
                "apiVersion": "v1",
                "kind": "List",
                "metadata": {"resourceVersion": "42"},
                "items": items,
            });
            Response::builder()
                .status(200)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap()
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (addr, event_tx)
}

#[tokio::test]
async fn the_mock_kapi_list_face_answers_rows() {
    let app_row = hr("orders", &["orders.example.com"]);
    let (kapi_addr, _events) = mock_kapi(vec![("httproutes".to_owned(), app_row)]).await;
    let client = reqwest::Client::new();
    let resp = client
        .get(format!(
            "http://{kapi_addr}/apis/gateway.networking.k8s.io/v1/httproutes"
        ))
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    eprintln!("LIST BODY: {body}");
    assert_eq!(body["items"].as_array().unwrap().len(), 1);
}

/// The mock node: echoes what it received as JSON and counts requests.
async fn mock_node(hits: Arc<std::sync::atomic::AtomicUsize>) -> std::net::SocketAddr {
    let app = axum::Router::new().fallback(move |req: Request| {
        let hits = Arc::clone(&hits);
        async move {
            hits.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let (parts, body) = req.into_parts();
            let host = parts
                .headers
                .get("host")
                .and_then(|h| h.to_str().ok())
                .unwrap_or("")
                .to_owned();
            let spoofed = parts
                .headers
                .get("x-qreta-sub")
                .and_then(|h| h.to_str().ok())
                .map(str::to_owned)
                .unwrap_or_else(|| "absent".to_owned());
            let fwd = parts
                .headers
                .get("x-forwarded-for")
                .and_then(|h| h.to_str().ok())
                .unwrap_or("absent")
                .to_owned();
            let payload = axum::body::to_bytes(body, 1024).await.unwrap_or_default();
            let answer = json!({
                "host": host,
                "path": parts.uri.path(),
                "spoofed_x_qreta_sub": spoofed,
                "x_forwarded_for": fwd,
                "body_len": payload.len(),
            });
            Response::builder()
                .status(200)
                .header("content-type", "application/json")
                .body(Body::from(answer.to_string()))
                .unwrap()
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

fn gateway_config(kapi: std::net::SocketAddr, node: std::net::SocketAddr) -> GatewayConfig {
    GatewayConfig {
        listen: ListenConfig {
            addr: "127.0.0.1:0".to_owned(),
        },
        tls: None,
        drain: Default::default(),
        kapi: Some(KapiConfig {
            url: format!("http://{kapi}"),
        }),
        nodes: [("node-a".to_owned(), format!("{node}"))]
            .into_iter()
            .collect(),
        defaults: Default::default(),
        registry: Default::default(),
        cache_push: Some(CachePushConfig {
            token: "push-secret".to_owned(),
        }),
        roll: Default::default(),
        deploy: None,
        sandbox: Default::default(),
        waf: Default::default(),
        ratelimit: Default::default(),
        verified_bots: Default::default(),
        pow: Default::default(),
        hardening: Default::default(),
    }
}

/// Boot the real gateway (informer + router) on an ephemeral port.
async fn boot_gateway(config: GatewayConfig) -> std::net::SocketAddr {
    let gateway = Arc::new(Gateway::new(config, None));
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let serve_gateway = Arc::clone(&gateway);
    tokio::spawn(async move { serve_gateway.run_informer(shutdown_rx).await });
    let router = gateway.router();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap();
    });
    addr
}

#[tokio::test]
async fn the_gateway_serves_the_full_seam() {
    // The seed: one app with one route, one Running pod, no node row
    // (the address comes from the config map).
    let node_hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let node_addr = mock_node(Arc::clone(&node_hits)).await;
    let app_row = hr("orders", &["orders.example.com"]);
    let pod_row = json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "acme-orders", "namespace": "acme",
                     "labels": {"app": "orders", "org": "acme"}},
        "spec": {"nodeName": "node-a"},
        "status": {"phase": "Running"}
    });
    let (kapi_addr, _events) = mock_kapi(vec![
        ("httproutes".to_owned(), app_row),
        ("pods".to_owned(), pod_row),
    ])
    .await;
    let config = gateway_config(kapi_addr, node_addr);
    let gateway_addr = boot_gateway(config).await;
    let client = reqwest::Client::new();

    // The informer converges: the health face reports the app and the
    // pod once the lists seed the table.
    let mut health_ok = false;
    let mut last_health = String::new();
    for _ in 0..100 {
        if let Ok(resp) = client
            .get(format!("http://{gateway_addr}/__gateway/health"))
            .send()
            .await
            && let Ok(health) = resp.json::<Value>().await
        {
            last_health = health.to_string();
            if health["apps"] == 1 && health["served"] == 1 {
                health_ok = true;
                break;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(health_ok, "the informer never converged: {last_health}");

    // The request walks the pipeline: the node sees the ORIGINAL Host,
    // no client x-qreta-* (trimmed), the gateway's x-forwarded-for mint.
    let resp = client
        .get(format!("http://{gateway_addr}/cart/1"))
        .header("host", "orders.example.com")
        .header("X-QRETA-Sub", "spoofed")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let echo: Value = resp.json().await.unwrap();
    assert_eq!(echo["host"], "orders.example.com");
    assert_eq!(echo["path"], "/cart/1");
    assert_eq!(echo["spoofed_x_qreta_sub"], "absent");
    assert_ne!(echo["x_forwarded_for"], "absent");
    assert_eq!(node_hits.load(std::sync::atomic::Ordering::SeqCst), 1);

    // A host the table does not know 404s at the gateway — the node is
    // never touched.
    let resp = client
        .get(format!("http://{gateway_addr}/"))
        .header("host", "unknown.example.com")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 404);
    assert_eq!(node_hits.load(std::sync::atomic::Ordering::SeqCst), 1);

    // The cache push face is bearer-gated: the wrong token 403s.
    let resp = client
        .post(format!("http://{gateway_addr}/__gateway/cache"))
        .header("authorization", "Bearer wrong")
        .body(r#"{"scope":"s","key":"k","response":{"status":200,"headers":[],"body":[]}}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 403);

    // The right token pushes an entry under the app's sealed scope;
    // the store accepts it (the seal + TTL laws ride gateway-core).
    let resp = client
        .post(format!("http://{gateway_addr}/__gateway/cache"))
        .header("authorization", "Bearer push-secret")
        .header("content-type", "application/json")
        .body(
            json!({
                "scope": "acme/orders/fp-1",
                "key": "GET /cart/1",
                "response": {"status": 200,
                             "headers": [["content-type", "text/plain"]],
                             "body": "aGk="}
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    // The node's hit count did not move: the push never touches it.
    assert_eq!(node_hits.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_route_without_a_pod_503s_honestly() {
    let node_hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let node_addr = mock_node(node_hits).await;
    let app_row = hr("cold", &["cold.example.com"]);
    let (kapi_addr, _events) = mock_kapi(vec![("httproutes".to_owned(), app_row)]).await;
    let config = gateway_config(kapi_addr, node_addr);
    let gateway_addr = boot_gateway(config).await;
    let client = reqwest::Client::new();

    // The informer converged (the app row landed; no default node is
    // configured, so the cold route has nothing to answer with).
    let mut converged = false;
    for _ in 0..100 {
        if let Ok(resp) = client
            .get(format!("http://{gateway_addr}/__gateway/health"))
            .send()
            .await
            && let Ok(health) = resp.json::<Value>().await
            && health["apps"] == 1
            && health["served"] == 0
        {
            converged = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(converged, "the informer never converged");

    let resp = client
        .get(format!("http://{gateway_addr}/"))
        .header("host", "cold.example.com")
        .send()
        .await
        .unwrap();
    // No pods and no default node: the gateway answers honestly — 503,
    // the node never wakes (the kubelet-arm instantiation is slice 3).
    assert_eq!(resp.status().as_u16(), 503);
}

/// The full WAF seam over the real watch: a `WafRule` CR seeded in the
/// kapi LIST is compiled by the informer and blocks a request before the
/// node sees it; a CR injected later on the live watch stream takes
/// effect on the next request; allowed traffic still reaches the node.
#[tokio::test]
async fn wafrule_crs_from_the_watch_validate_real_requests() {
    use kapigate::table::Family;

    let node_hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let node_addr = mock_node(Arc::clone(&node_hits)).await;
    let app_row = hr("orders", &["orders.example.com"]);
    let pod_row = json!({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "acme-orders", "namespace": "acme",
                     "labels": {"app": "orders", "org": "acme"}},
        "spec": {"nodeName": "node-a"}, "status": {"phase": "Running"}
    });
    let scanner_cr = json!({
        "apiVersion": "gateway.qreta.io/v1alpha1", "kind": "WafRule",
        "metadata": {"name": "scanners", "namespace": "acme"},
        "spec": {"rules": [
            {"name": "cr-no-scanners", "expression": r#"http.ua contains "sqlmap""#}
        ]}
    });
    let (kapi_addr, events) = mock_kapi(vec![
        ("httproutes".to_owned(), app_row),
        ("pods".to_owned(), pod_row),
        ("wafrules".to_owned(), scanner_cr.clone()),
    ])
    .await;
    let gateway_addr = boot_gateway(gateway_config(kapi_addr, node_addr)).await;
    let client = reqwest::Client::new();

    // Wait for informer convergence: the health face reports the app once
    // every family's LIST (including wafrules) has landed.
    let mut converged = false;
    for _ in 0..100 {
        if let Ok(resp) = client
            .get(format!("http://{gateway_addr}/__gateway/health"))
            .send()
            .await
            && let Ok(health) = resp.json::<Value>().await
            && health["apps"] == 1
            && health["served"] == 1
        {
            converged = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(
        converged,
        "the informer never converged (wafrules LIST included)"
    );

    // The seeded CR blocks a scanner before the node sees the request.
    let blocked = client
        .get(format!("http://{gateway_addr}/cart/1"))
        .header("host", "orders.example.com")
        .header("user-agent", "sqlmap/1.2")
        .send()
        .await
        .unwrap();
    assert_eq!(blocked.status().as_u16(), 403);
    assert_eq!(blocked.headers()["x-qreta-waf"], "cr-no-scanners");
    assert_eq!(node_hits.load(std::sync::atomic::Ordering::SeqCst), 0);

    // A normal request passes through to the node.
    let allowed = client
        .get(format!("http://{gateway_addr}/cart/1"))
        .header("host", "orders.example.com")
        .header("user-agent", "Mozilla/5.0")
        .send()
        .await
        .unwrap();
    assert_eq!(allowed.status().as_u16(), 200);
    assert_eq!(node_hits.load(std::sync::atomic::Ordering::SeqCst), 1);

    // Inject a second CR on the live watch stream: it must take effect
    // on the NEXT request without a restart.
    let admin_cr = json!({
        "apiVersion": "gateway.qreta.io/v1alpha1", "kind": "WafRule",
        "metadata": {"name": "admin", "namespace": "acme"},
        "spec": {"rules": [
            {"name": "cr-no-admin", "expression": r#"http.path contains "/admin""#}
        ]}
    });
    let _ = events.send((
        Family::WafRules.plural().to_owned(),
        "ADDED".to_owned(),
        admin_cr,
    ));
    // Let the watch deliver and the table apply the delta.
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    let blocked_again = client
        .get(format!("http://{gateway_addr}/admin"))
        .header("host", "orders.example.com")
        .header("user-agent", "Mozilla/5.0")
        .send()
        .await
        .unwrap();
    assert_eq!(blocked_again.status().as_u16(), 403);
    assert_eq!(blocked_again.headers()["x-qreta-waf"], "cr-no-admin");
    assert_eq!(node_hits.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[test]
fn the_table_takes_a_seeded_row() {
    use kapigate::table::{Family, Table};
    let app_row = hr("orders", &["orders.example.com"]);
    let items = vec![app_row];
    let mut t = Table::default();
    t.replace(Family::Httproutes, &items);
    eprintln!("ROUTES: {:?}", t.counts());
    assert_eq!(t.counts().0, 1);
}

/// The asset store's road: a mock registry serving a real gzip-tar
/// artifact; the pull extracts the tree, the asset law shapes the
/// answer, the digest verifies, a new ref re-pulls.
#[tokio::test]
async fn the_asset_store_pulls_and_serves_the_tree() {
    use kapigate::assets_store::AssetStore;
    use std::io::Write as _;

    // The artifact: one gzip-tar layer carrying assets/index.html.
    let mut tar_buf = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_buf);
        let mut header = tar::Header::new_gnu();
        let content = b"<html>hi</html>";
        header.set_size(content.len() as u64);
        header.set_cksum();
        builder
            .append_data(&mut header, "assets/index.html", &content[..])
            .unwrap();
        builder.finish().unwrap();
    }
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    gz.write_all(&tar_buf).unwrap();
    let layer = gz.finish().unwrap();
    let digest = format!("sha256:{}", kapigate::oci::sha256_hex(&layer));
    let manifest = json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {"mediaType": "application/vnd.wisolate.wasm.assets.config.v1+json",
                   "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                   "size": 2},
        "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                    "digest": digest, "size": layer.len()}]
    });
    let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
    let manifest_digest = format!("sha256:{}", kapigate::oci::sha256_hex(&manifest_bytes));

    // The mock registry: the manifest face + the blob face.
    let app = axum::Router::new().fallback(move |req: Request| {
        let manifest_bytes = manifest_bytes.clone();
        let manifest_digest = manifest_digest.clone();
        let layer = layer.clone();
        async move {
            let path = req.uri().path().to_owned();
            if path.ends_with("/manifests/latest") {
                return Response::builder()
                    .status(200)
                    .header("content-type", "application/vnd.oci.image.manifest.v1+json")
                    .body(Body::from(manifest_bytes))
                    .unwrap();
            }
            if path.contains("/blobs/") {
                let wanted = path.rsplit('/').next().unwrap().to_owned();
                if wanted == manifest_digest {
                    return Response::builder()
                        .status(200)
                        .body(Body::from(manifest_bytes))
                        .unwrap();
                }
                return Response::builder()
                    .status(200)
                    .body(Body::from(layer))
                    .unwrap();
            }
            Response::builder()
                .status(404)
                .body(Body::from("no"))
                .unwrap()
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let registry_addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let store = std::sync::Arc::new(AssetStore::new(Default::default()));
    let spec = json!({
        "not_found_handling": "none",
        "files": {"index.html": 15},
        "hashes": {"index.html": "aaaaaaaaaaaaaaaa"},
        "header_rules": []
    });
    let spec: kapigate::AssetSpec = serde_json::from_value(spec).unwrap();

    // The pull + the law-shaped answer.
    let image = format!("{registry_addr}/acme/site:latest");
    let resolved = kapigate::table::Resolved {
        node: Some("node-a".into()),
        org: "acme".into(),
        app: "site".into(),
        fingerprint: None,
        image: Some(image.clone()),
        assets: Some(spec.clone()),
        assets_only_app: None,
    };
    let resp = store
        .serve(
            &resolved,
            "GET",
            "/index.html",
            "",
            &Default::default(),
            &|_, _| None,
        )
        .await
        .expect("the tree answers");
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(resp.headers()["content-type"], "text/html; charset=utf-8");
    assert_eq!(resp.headers()["etag"], "\"aaaaaaaaaaaaaaaa\"");
    // The store answers http::Response<Vec<u8>> directly (the law's
    // own shape); the body came back with the asset bytes.
    assert_eq!(&resp.body()[..], b"<html>hi</html>");

    // A POST never touches the store (the worker owns writes).
    let none = store
        .serve(&resolved, "POST", "/", "", &Default::default(), &|_, _| {
            None
        })
        .await;
    assert!(none.is_none());

    // run_worker_first bypasses the store by design.
    let mut worker_first_resolved = resolved.clone();
    let mut wf_spec = spec.clone();
    wf_spec.run_worker_first = true;
    worker_first_resolved.assets = Some(wf_spec);
    let none = store
        .serve(
            &worker_first_resolved,
            "GET",
            "/",
            "",
            &Default::default(),
            &|_, _| None,
        )
        .await;
    assert!(none.is_none());
}

/// The drain discipline (kapi.spec EDGE-FR-010's first land): an in-flight
/// request survives a triggered shutdown — the barrier waits it out,
/// the response completes, the outcome names Drained, and the listener
/// is gone by then (a new connection refuses).
#[tokio::test]
async fn the_drain_waits_in_flight_requests_out() {
    // The mock node parks the request on oneshots the test controls
    // (the unit of work the drain must wait out). The axum handler
    // must be Fn, so the oneshots ride Mutex-guarded slots the
    // handler takes once.
    let (received_tx, received_rx) = tokio::sync::oneshot::channel::<()>();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
    let cells = Arc::new(std::sync::Mutex::new((Some(received_tx), Some(release_rx))));
    let app = axum::Router::new().fallback(move |_req: Request| {
        let (received_tx, release_rx) = {
            let mut slots = cells.lock().unwrap();
            (
                slots.0.take().expect("one unit drives through"),
                slots.1.take().expect("one unit drives through"),
            )
        };
        async move {
            let _ = received_tx.send(());
            let _ = release_rx.await; // the test holds the unit open
            Response::builder()
                .status(200)
                .body(Body::from("the unit finished"))
                .unwrap()
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let node_addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let (kapi_addr, _events) = mock_kapi(vec![
        (
            "httproutes".to_owned(),
            hr("orders", &["orders.example.com"]),
        ),
        (
            "pods".to_owned(),
            json!({
                "metadata": {"name": "acme-orders", "namespace": "acme",
                             "labels": {"app": "orders", "org": "acme"}},
                "spec": {"nodeName": "node-a"},
                "status": {"phase": "Running"}
            }),
        ),
    ])
    .await;
    let mut config = gateway_config(kapi_addr, node_addr);
    config.drain = Default::default();
    let gateway = Arc::new(Gateway::new(config, None));
    let (_inform_tx, inform_rx) = tokio::sync::watch::channel(false);
    let inform_gateway = Arc::clone(&gateway);
    tokio::spawn(async move { inform_gateway.run_informer(inform_rx).await });
    let (signal_tx, signal_rx) = tokio::sync::oneshot::channel::<()>();
    let gateway_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gateway_addr = gateway_listener.local_addr().unwrap();
    let server = tokio::spawn(kapigate::server::serve_until(
        Arc::clone(&gateway),
        gateway_listener,
        async move {
            let _ = signal_rx.await;
        },
        None, // wait forever — the test releases the unit itself
    ));

    // The request is in flight when the drain fires — but only after
    // the informer converged (a slow box must not turn this into a
    // 404-then-hang).
    let client = reqwest::Client::new();
    let mut converged = false;
    for _ in 0..200 {
        if let Ok(resp) = client
            .get(format!("http://{gateway_addr}/__gateway/health"))
            .send()
            .await
            && let Ok(health) = resp.json::<serde_json::Value>().await
            && health["served"] == 1
        {
            converged = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(converged, "the informer never converged");

    let in_flight = tokio::spawn(async move {
        client
            .get(format!("http://{gateway_addr}/cart"))
            .header("host", "orders.example.com")
            .send()
            .await
            .unwrap()
    });
    let _ = received_rx.await; // the gateway is processing the unit

    // The trigger latches; the barrier waits (the unit is still open).
    signal_tx.send(()).unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    assert!(!server.is_finished(), "the drain waited the unit out");

    // The unit completes; the barrier resolves Drained right after.
    release_tx.send(()).unwrap();
    let resp = in_flight.await.unwrap();
    assert_eq!(resp.status().as_u16(), 200, "no request drops");
    let body = resp.text().await.unwrap();
    assert_eq!(body, "the unit finished");
    let outcome = server.await.unwrap();
    assert!(matches!(outcome, graceful_handover::DrainOutcome::Drained));

    // Stop-accept happened structurally: a new connection refuses.
    let refused = reqwest::Client::new()
        .get(format!("http://{gateway_addr}/"))
        .header("host", "orders.example.com")
        .send()
        .await;
    assert!(refused.is_err(), "the listener is gone after the drain");
}
