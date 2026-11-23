//! The watched RateLimit CR in the serving pipeline: namespace-local
//! scoping, wirefilter selectors, multiple rules, and dynamic header keys.

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use axum::body::Body;
use axum::extract::Request;
use axum::http::StatusCode;
use axum::response::Response;
use gateway::config::{GatewayConfig, KapiConfig, ListenConfig, WafConfig};
use gateway::server::Gateway;
use gateway::table::Family;
use serde_json::json;

async fn mock_node(hits: Arc<AtomicUsize>) -> std::net::SocketAddr {
    let app = axum::Router::new().fallback(move |_req: Request| {
        hits.fetch_add(1, Ordering::SeqCst);
        async {
            Response::builder()
                .status(200)
                .body(Body::from("from node\n"))
                .unwrap()
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

fn config(node: std::net::SocketAddr) -> GatewayConfig {
    GatewayConfig {
        listen: ListenConfig {
            addr: "127.0.0.1:0".to_owned(),
        },
        tls: None,
        kapi: Some(KapiConfig {
            url: "http://127.0.0.1:1".to_owned(),
        }),
        nodes: [("node-a".to_owned(), node.to_string())]
            .into_iter()
            .collect(),
        defaults: Default::default(),
        drain: Default::default(),
        registry: Default::default(),
        cache_push: None,
        roll: Default::default(),
        deploy: None,
        sandbox: Default::default(),
        waf: WafConfig::default(),
        ratelimit: Default::default(),
        verified_bots: Default::default(),
        pow: Default::default(),
        hardening: Default::default(),
    }
}

fn route(namespace: &str, host: &str) -> serde_json::Value {
    json!({
        "apiVersion": "gateway.networking.k8s.io/v1", "kind": "HTTPRoute",
        "metadata": {"name": "orders", "namespace": namespace},
        "spec": {"hostnames": [host],
                 "rules": [{"matches": [{"path": {"type": "PathPrefix", "value": "/"}}],
                            "backendRefs": [{"name": "orders", "port": 80}]}]}
    })
}

fn pod(namespace: &str) -> serde_json::Value {
    json!({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "orders", "namespace": namespace,
                     "labels": {"app": "orders", "org": namespace}},
        "spec": {"nodeName": "node-a"}, "status": {"phase": "Running"}
    })
}

fn rate_cr(namespace: &str, rules: serde_json::Value) -> serde_json::Value {
    json!({
        "apiVersion": "gateway.qreta.io/v1alpha1", "kind": "RateLimit",
        "metadata": {"name": "limits", "namespace": namespace},
        "spec": {"rules": rules}
    })
}

async fn boot_with_cr(cr: serde_json::Value) -> std::net::SocketAddr {
    let hits = Arc::new(AtomicUsize::new(0));
    let node = mock_node(hits).await;
    let gateway = Arc::new(Gateway::new(config(node), None));
    {
        let mut table = gateway.informer.table.write().await;
        table.apply(
            Family::Httproutes,
            "ADDED",
            &route("acme", "acme.example.com"),
        );
        table.apply(
            Family::Httproutes,
            "ADDED",
            &route("mgmt", "mgmt.example.com"),
        );
        table.apply(Family::Pods, "ADDED", &pod("acme"));
        table.apply(Family::Pods, "ADDED", &pod("mgmt"));
        table.apply(Family::RateLimits, "ADDED", &cr);
    }
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
async fn a_cr_rule_only_limits_its_own_namespace() {
    let cr = rate_cr(
        "acme",
        json!([{"name": "acme-limit", "match": "", "limit": 1, "windowSecs": 60}]),
    );
    let addr = boot_with_cr(cr).await;
    let client = reqwest::Client::new();

    // acme's first request passes, the second is blocked.
    let acme = format!("http://{addr}/");
    assert_eq!(
        client
            .get(&acme)
            .header("host", "acme.example.com")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    let blocked = client
        .get(&acme)
        .header("host", "acme.example.com")
        .send()
        .await
        .unwrap();
    assert_eq!(blocked.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(blocked.headers()["x-gateway-rate"], "acme-limit");

    // mgmt has no matching CR, so its requests keep passing.
    let mgmt = format!("http://{addr}/");
    for _ in 0..3 {
        assert_eq!(
            client
                .get(&mgmt)
                .header("host", "mgmt.example.com")
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
    }
}

#[tokio::test]
async fn multiple_rules_in_one_cr_are_independent() {
    let cr = rate_cr(
        "acme",
        json!([
            {"name": "api", "match": r#"http.path contains "/api""#, "limit": 1, "windowSecs": 60},
            {"name": "other", "match": r#"http.path contains "/other""#, "limit": 1, "windowSecs": 60}
        ]),
    );
    let addr = boot_with_cr(cr).await;
    let client = reqwest::Client::new();

    let api = format!("http://{addr}/api");
    assert_eq!(
        client
            .get(&api)
            .header("host", "acme.example.com")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        client
            .get(&api)
            .header("host", "acme.example.com")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    // The other rule has its own counter.
    let other = format!("http://{addr}/other");
    assert_eq!(
        client
            .get(&other)
            .header("host", "acme.example.com")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn a_header_key_splits_one_clients_budget() {
    let cr = rate_cr(
        "acme",
        json!([{
            "name": "per-tenant", "match": "", "limit": 2, "windowSecs": 60,
            "key": [{"header": "x-api-key"}]
        }]),
    );
    let addr = boot_with_cr(cr).await;
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/");

    // Same client IP, two different header values → two separate buckets,
    // each with its own budget of 2.
    for _ in 0..2 {
        let resp = client
            .get(&url)
            .header("host", "acme.example.com")
            .header("x-api-key", "tenant-a")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "request for tenant-a");
    }
    let resp = client
        .get(&url)
        .header("host", "acme.example.com")
        .header("x-api-key", "tenant-b")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "first request for tenant-b");
    // tenant-a is now exhausted...
    let blocked = client
        .get(&url)
        .header("host", "acme.example.com")
        .header("x-api-key", "tenant-a")
        .send()
        .await
        .unwrap();
    assert_eq!(blocked.status(), StatusCode::TOO_MANY_REQUESTS);
    // ...while tenant-b still has one request left in its own bucket.
    assert_eq!(
        client
            .get(&url)
            .header("host", "acme.example.com")
            .header("x-api-key", "tenant-b")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
}
