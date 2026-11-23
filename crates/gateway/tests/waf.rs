//! The WAF seam: real wirefilter rules in the gateway's serving
//! pipeline, ahead of the cache and the node forward. A blocked request
//! never reaches the backend; an allowed one does. The reserved gateway
//! faces (health) are NOT WAF-filtered — they are the operator's own
//! surface.

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use axum::body::Body;
use axum::extract::Request;
use axum::http::StatusCode;
use gateway::config::{
    GatewayConfig, HardeningConfig, KapiConfig, ListenConfig, PowConfig, WafAction, WafConfig,
    WafRule,
};
use gateway::server::Gateway;
use gateway::table::Family;
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

use axum::response::Response;

fn rule(name: &str, expression: &str) -> WafRule {
    WafRule {
        name: name.to_owned(),
        expression: expression.to_owned(),
        ..Default::default()
    }
}

fn config(kapi: &str, node: std::net::SocketAddr, rules: Vec<WafRule>) -> GatewayConfig {
    GatewayConfig {
        listen: ListenConfig {
            addr: "127.0.0.1:0".to_owned(),
        },
        tls: None,
        kapi: Some(KapiConfig {
            url: kapi.to_owned(),
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
        waf: WafConfig { rules },
        ratelimit: Default::default(),
        verified_bots: Default::default(),
        pow: Default::default(),
        hardening: Default::default(),
    }
}

/// Boot a gateway whose table is seeded directly (no watch loop needed
/// for the WAF seam — the router reads the table on every request).
async fn boot(config: GatewayConfig) -> (std::net::SocketAddr, Arc<Gateway>) {
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
    (addr, gateway)
}

#[tokio::test]
async fn a_matching_rule_blocks_before_the_backend_sees_the_request() {
    let hits = Arc::new(AtomicUsize::new(0));
    let node = mock_node(Arc::clone(&hits)).await;
    let rules = vec![rule("no-scanners", r#"http.ua contains "sqlmap""#)];
    let (addr, _gw) = boot(config("http://127.0.0.1:1", node, rules)).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{addr}/"))
        .header("host", "orders.example.com")
        .header("user-agent", "sqlmap/1.2")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(resp.headers()["x-gateway-waf"], "no-scanners");
    assert_eq!(resp.text().await.unwrap(), "blocked by the WAF\n");
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "blocked requests never reach the node"
    );
}

#[tokio::test]
async fn a_non_matching_rule_forwards_normally() {
    let hits = Arc::new(AtomicUsize::new(0));
    let node = mock_node(Arc::clone(&hits)).await;
    let rules = vec![rule("no-scanners", r#"http.ua contains "sqlmap""#)];
    let (addr, _gw) = boot(config("http://127.0.0.1:1", node, rules)).await;

    let resp = reqwest::Client::new()
        .get(format!("http://{addr}/products"))
        .header("host", "orders.example.com")
        .header("user-agent", "Mozilla/5.0")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.text().await.unwrap(), "from node\n");
    assert_eq!(hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn method_path_query_and_ip_rules_all_fire() {
    let hits = Arc::new(AtomicUsize::new(0));
    let node = mock_node(Arc::clone(&hits)).await;
    let rules = vec![
        rule("no-post", r#"http.method == "POST""#),
        rule("admin-path", r#"http.path contains "/admin""#),
        rule("query-token", r#"http.query contains "token=""#),
        rule("bad-source", r#"ip.addr in {192.0.2.0/24}"#),
    ];
    let (addr, _gw) = boot(config("http://127.0.0.1:1", node, rules)).await;
    let client = reqwest::Client::new();

    // The loopback client IP doesn't match `bad-source`, so a plain GET
    // passes.
    let allowed = client
        .get(format!("http://{addr}/"))
        .header("host", "orders.example.com")
        .send()
        .await
        .unwrap();
    assert_eq!(allowed.status(), StatusCode::OK);

    let method = client
        .post(format!("http://{addr}/"))
        .header("host", "orders.example.com")
        .send()
        .await
        .unwrap();
    assert_eq!(method.status(), StatusCode::FORBIDDEN);
    assert_eq!(method.headers()["x-gateway-waf"], "no-post");

    let path = client
        .get(format!("http://{addr}/admin"))
        .header("host", "orders.example.com")
        .send()
        .await
        .unwrap();
    assert_eq!(path.headers()["x-gateway-waf"], "admin-path");

    let query = client
        .get(format!("http://{addr}/?token=abc"))
        .header("host", "orders.example.com")
        .send()
        .await
        .unwrap();
    assert_eq!(query.headers()["x-gateway-waf"], "query-token");
}

#[tokio::test]
async fn the_gateway_faces_are_not_waf_filtered() {
    let hits = Arc::new(AtomicUsize::new(0));
    let node = mock_node(Arc::clone(&hits)).await;
    // An expression that blocks EVERYTHING — even this must not block
    // the operator's own health face.
    let rules = vec![rule("block-all", "tls or not tls")];
    let (addr, _gw) = boot(config("http://127.0.0.1:1", node, rules)).await;

    let resp = reqwest::Client::new()
        .get(format!("http://{addr}/__gateway/health"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = resp.json().await.unwrap();
    // The health face answers from the table, not the WAF; `ready` is
    // the informer's seed fact (absent in this direct-seed harness).
    assert_eq!(body["apps"], 1);
}

#[tokio::test]
async fn a_challenge_action_answers_503() {
    let hits = Arc::new(AtomicUsize::new(0));
    let node = mock_node(Arc::clone(&hits)).await;
    let mut challenge = rule("bot-check", r#"http.ua contains "curl""#);
    challenge.action = WafAction::Challenge;
    let (addr, _gw) = boot(config("http://127.0.0.1:1", node, vec![challenge])).await;

    let resp = reqwest::Client::new()
        .get(format!("http://{addr}/"))
        .header("host", "orders.example.com")
        .header("user-agent", "curl/8")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(resp.headers()["x-gateway-waf"], "bot-check");
}

/// A `WafRule` CR (gateway.qreta.io/v1alpha1) watched from kapi is
/// compiled into the live ruleset and blocks a request — no static TOML
/// rule needed. The `x-gateway-waf` header names the CR's rule.
#[tokio::test]
async fn a_watched_wafrule_cr_blocks_a_request() {
    let hits = Arc::new(AtomicUsize::new(0));
    let node = mock_node(Arc::clone(&hits)).await;
    let (addr, gw) = boot(config("http://127.0.0.1:1", node, vec![])).await;
    {
        let mut table = gw.informer.table.write().await;
        table.apply(
            Family::WafRules,
            "ADDED",
            &json!({
                "apiVersion": "gateway.qreta.io/v1alpha1", "kind": "WafRule",
                "metadata": {"name": "scanners", "namespace": "acme"},
                "spec": {"rules": [
                    {"name": "cr-no-scanners", "expression": r#"http.ua contains "sqlmap""#}
                ]}
            }),
        );
    }

    let resp = reqwest::Client::new()
        .get(format!("http://{addr}/"))
        .header("host", "orders.example.com")
        .header("user-agent", "sqlmap/1.2")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(resp.headers()["x-gateway-waf"], "cr-no-scanners");
    assert_eq!(hits.load(Ordering::SeqCst), 0);
}

/// A CR delta that lands AFTER the router is serving is picked up on the
/// next request — the generation bump recompiles off the hot path.
#[tokio::test]
async fn a_wafrule_cr_added_after_boot_is_picked_up_live() {
    let hits = Arc::new(AtomicUsize::new(0));
    let node = mock_node(Arc::clone(&hits)).await;
    let (addr, gw) = boot(config("http://127.0.0.1:1", node, vec![])).await;
    let client = reqwest::Client::new();

    // Before the CR lands the request is allowed.
    let before = client
        .get(format!("http://{addr}/admin"))
        .header("host", "orders.example.com")
        .send()
        .await
        .unwrap();
    assert_eq!(before.status(), StatusCode::OK);

    {
        let mut table = gw.informer.table.write().await;
        table.apply(
            Family::WafRules,
            "ADDED",
            &json!({
                "apiVersion": "gateway.qreta.io/v1alpha1", "kind": "WafRule",
                "metadata": {"name": "admin", "namespace": "acme"},
                "spec": {"rules": [
                    {"name": "cr-no-admin", "expression": r#"http.path contains "/admin""#}
                ]}
            }),
        );
    }

    let after = client
        .get(format!("http://{addr}/admin"))
        .header("host", "orders.example.com")
        .send()
        .await
        .unwrap();
    assert_eq!(after.status(), StatusCode::FORBIDDEN);
    assert_eq!(after.headers()["x-gateway-waf"], "cr-no-admin");
}

/// A CR whose expression is invalid cannot poison the ruleset: the last
/// good compiled rules stay live, so a request matching the static rule
/// is still blocked.
#[tokio::test]
async fn a_bad_wafrule_cr_keeps_the_last_good_ruleset() {
    let node = mock_node(Arc::new(AtomicUsize::new(0))).await;
    let rules = vec![rule("static-block", r#"http.ua contains "curl""#)];
    let (addr, gw) = boot(config("http://127.0.0.1:1", node, rules)).await;
    {
        let mut table = gw.informer.table.write().await;
        table.apply(
            Family::WafRules,
            "ADDED",
            &json!({
                "apiVersion": "gateway.qreta.io/v1alpha1", "kind": "WafRule",
                "metadata": {"name": "broken", "namespace": "acme"},
                "spec": {"rules": [
                    {"name": "bad", "expression": "http.method ==="}
                ]}
            }),
        );
    }
    let resp = reqwest::Client::new()
        .get(format!("http://{addr}/"))
        .header("host", "orders.example.com")
        .header("user-agent", "curl/8")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.headers()["x-gateway-waf"], "static-block");
}

/// Reserved private/admin paths are dropped unconditionally (even with no
/// configured rules) and the probing IP is immediately rate-limited on all
/// subsequent requests. This is the edge half of the node's admin-channel
/// law: `/__private/` and `/__internal/` only exist on the private listener.
#[tokio::test]
async fn private_paths_are_blocked_and_the_ip_is_immediately_penalized() {
    let hits = Arc::new(AtomicUsize::new(0));
    let node = mock_node(Arc::clone(&hits)).await;
    // NO configured WAF rules — the built-in deny must still fire.
    let (addr, _gw) = boot(config("http://127.0.0.1:1", node, vec![])).await;
    let client = reqwest::Client::new();

    // 1. A private-path probe is blocked with 404, stamped with the
    //    built-in rule name, and never reaches the backend.
    let probe = client
        .get(format!("http://{addr}/__private/mint-provision-token"))
        .header("host", "orders.example.com")
        .send()
        .await
        .unwrap();
    assert_eq!(probe.status(), StatusCode::NOT_FOUND);
    assert_eq!(probe.headers()["x-gateway-waf"], "reserved-private-path");
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "a private-path probe never reaches the backend"
    );

    // 2. The SAME source IP is now rate-limited on an ordinary path —
    //    429 with the penalty rule name, before any WAF rule/backend.
    let after = client
        .get(format!("http://{addr}/products"))
        .header("host", "orders.example.com")
        .send()
        .await
        .unwrap();
    assert_eq!(after.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(after.headers()["x-gateway-rate"], "private-path-penalty");
    assert_eq!(hits.load(Ordering::SeqCst), 0);
}

/// A `Challenge` WAF rule with PoW configured issues an HTML puzzle page
/// (not a flat block), and a solved cookie bypasses the challenge.
#[tokio::test]
async fn pow_challenge_is_issued_and_a_solution_bypasses_it() {
    let hits = Arc::new(AtomicUsize::new(0));
    let node = mock_node(Arc::clone(&hits)).await;
    let mut cfg = config("http://127.0.0.1:1", node, vec![]);
    cfg.waf.rules = vec![WafRule {
        name: "bot-check".into(),
        expression: r#"http.ua contains "bot""#.into(),
        action: WafAction::Challenge,
        ..Default::default()
    }];
    cfg.pow = PowConfig {
        secret: "test-secret".into(),
        difficulty: 4,
        ..Default::default()
    };
    let pow_cfg = cfg.pow.clone();
    let cookie_name = cfg.pow.cookie.clone();
    let (addr, _gw) = boot(cfg).await;
    let client = reqwest::Client::new();

    // 1. A bot gets the challenge page (200 HTML with JS), not a block.
    let challenged = client
        .get(format!("http://{addr}/"))
        .header("host", "orders.example.com")
        .header("user-agent", "evilbot/1.0")
        .send()
        .await
        .unwrap();
    assert_eq!(challenged.status(), StatusCode::OK);
    let html = challenged.text().await.unwrap();
    assert!(html.contains("Verifying"));
    assert!(html.contains("crypto.subtle.digest"));
    assert_eq!(hits.load(Ordering::SeqCst), 0);

    // 2. A solved PoW cookie bypasses the challenge rule and reaches the
    //    node. We solve with the pure law (same algorithm as the JS).
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let nonce = [7u8; 16];
    let challenge = gateway_core::pow::issue(&pow_cfg, &nonce, now);
    let solution = gateway_core::pow::solve(&pow_cfg, &challenge, 1_000_000).unwrap();
    let passed = client
        .get(format!("http://{addr}/"))
        .header("host", "orders.example.com")
        .header("user-agent", "evilbot/1.0")
        .header("cookie", format!("{cookie_name}={solution}"))
        .send()
        .await
        .unwrap();
    assert_eq!(passed.status(), StatusCode::OK);
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "solved bot reached the node"
    );
}

/// Hardening headers are stamped on every response, including simple
/// ones (404s, health, proxied answers).
#[tokio::test]
async fn hardening_headers_are_stamped_on_every_response() {
    let node = mock_node(Arc::new(AtomicUsize::new(0))).await;
    let mut cfg = config("http://127.0.0.1:1", node, vec![]);
    cfg.hardening = HardeningConfig::default();
    let (addr, _gw) = boot(cfg).await;
    let resp = reqwest::Client::new()
        .get(format!("http://{addr}/no-such-route"))
        .header("host", "unknown.example.com")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.headers()["x-content-type-options"], "nosniff");
    assert_eq!(
        resp.headers()["referrer-policy"],
        "strict-origin-when-cross-origin"
    );
    assert_eq!(resp.headers()["x-frame-options"], "DENY");
    assert!(resp.headers().contains_key("strict-transport-security"));
    assert!(resp.headers().contains_key("content-security-policy"));
}
