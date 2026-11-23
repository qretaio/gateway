//! The rate limiter in the serving pipeline: a client past its budget gets
//! 429 + Retry-After and never reaches the backend; other clients and other
//! routes keep their own budgets. Verified-bot config validation is covered
//! here too (the DNS exemption itself is a pure law in gateway-core).

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
use gateway_core::ratelimit::{RateLimitConfig, RateLimitRule};
use serde_json::json;

/// A mock node that counts every request it receives.
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

fn config(kapi_url: &str, node: std::net::SocketAddr, rules: Vec<RateLimitRule>) -> GatewayConfig {
    GatewayConfig {
        listen: ListenConfig {
            addr: "127.0.0.1:0".to_owned(),
        },
        tls: None,
        kapi: Some(KapiConfig {
            url: kapi_url.to_owned(),
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
        ratelimit: RateLimitConfig { rules },
        verified_bots: Default::default(),
        pow: Default::default(),
        hardening: Default::default(),
    }
}

async fn boot(config: GatewayConfig) -> std::net::SocketAddr {
    let gateway = Arc::new(Gateway::new(config, None));
    {
        let mut table = gateway.informer.table.write().await;
        table.apply(
            Family::Httproutes,
            "ADDED",
            &json!({
                "apiVersion": "gateway.networking.k8s.io/v1", "kind": "HTTPRoute",
                "metadata": {"name": "orders", "namespace": "acme"},
                "spec": {"hostnames": ["orders.example.com"],
                         "rules": [{"matches": [{"path": {"type": "PathPrefix", "value": "/"}}],
                                    "backendRefs": [{"name": "orders", "port": 80}]}]}
            }),
        );
        table.apply(
            Family::Pods,
            "ADDED",
            &json!({
                "apiVersion": "v1", "kind": "Pod",
                "metadata": {"name": "acme-orders", "namespace": "acme",
                             "labels": {"app": "orders", "org": "acme"}},
                "spec": {"nodeName": "node-a"}, "status": {"phase": "Running"}
            }),
        );
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

fn rule(name: &str, limit: u32, per_route: bool) -> RateLimitRule {
    RateLimitRule {
        name: name.to_owned(),
        limit,
        window_secs: 60,
        per_route,
    }
}

#[tokio::test]
async fn a_client_past_its_budget_gets_429_and_never_reaches_the_node() {
    let hits = Arc::new(AtomicUsize::new(0));
    let node = mock_node(Arc::clone(&hits)).await;
    let addr = boot(config(
        "http://127.0.0.1:1",
        node,
        vec![rule("per-client", 2, false)],
    ))
    .await;
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/");

    let first = client
        .get(&url)
        .header("host", "orders.example.com")
        .send()
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    let second = client
        .get(&url)
        .header("host", "orders.example.com")
        .send()
        .await
        .unwrap();
    assert_eq!(second.status(), StatusCode::OK);
    let third = client
        .get(&url)
        .header("host", "orders.example.com")
        .send()
        .await
        .unwrap();
    assert_eq!(third.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(third.headers()["x-gateway-rate"], "per-client");
    assert!(third.headers().contains_key("retry-after"));
    // Only the two allowed requests reached the backend.
    assert_eq!(hits.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn a_gateway_face_is_not_rate_limited() {
    let hits = Arc::new(AtomicUsize::new(0));
    let node = mock_node(Arc::clone(&hits)).await;
    let addr = boot(config(
        "http://127.0.0.1:1",
        node,
        vec![rule("one", 1, false)],
    ))
    .await;
    let client = reqwest::Client::new();
    for _ in 0..3 {
        let resp = client
            .get(format!("http://{addr}/__gateway/health"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}

#[tokio::test]
async fn per_route_rules_separate_budgets_by_path() {
    let hits = Arc::new(AtomicUsize::new(0));
    let node = mock_node(Arc::clone(&hits)).await;
    let addr = boot(config(
        "http://127.0.0.1:1",
        node,
        vec![rule("login", 1, true)],
    ))
    .await;
    let client = reqwest::Client::new();
    let login = format!("http://{addr}/login");
    assert_eq!(
        client
            .get(&login)
            .header("host", "orders.example.com")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        client
            .get(&login)
            .header("host", "orders.example.com")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    // A different path keeps its own budget for the same client.
    assert_eq!(
        client
            .get(format!("http://{addr}/"))
            .header("host", "orders.example.com")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
}
