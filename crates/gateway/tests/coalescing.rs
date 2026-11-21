//! Uniflight coalescing, end to end: N clients racing the same cold
//! route collapse into ONE upstream fetch; followers see
//! `x-gateway-coalesced: hit`. Non-coalescible methods are proven to
//! stay unguarded (each POST reaches the node).

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use axum::{body::Body, extract::Request, response::Response};
use serde_json::{Value, json};
use tokio_stream::StreamExt;

use gateway::config::{GatewayConfig, KapiConfig, ListenConfig};
use gateway::server::Gateway;

fn hr(name: &str, host: &str) -> Value {
    json!({
        "apiVersion": "gateway.networking.k8s.io/v1", "kind": "HTTPRoute",
        "metadata": {"name": name, "namespace": "acme"},
        "spec": {"hostnames": [host],
                 "rules": [{"matches": [{"path": {"type": "PathPrefix", "value": "/"}}],
                            "backendRefs": [{"name": name, "port": 80}]}]}
    })
}

fn pod(name: &str) -> Value {
    json!({
        "metadata": {"name": name, "namespace": "acme",
                     "labels": {"app": name, "org": "acme"}},
        "spec": {"nodeName": "node-a"},
        "status": {"phase": "Running"}
    })
}

async fn mock_kapi(seed_rows: Vec<(String, Value)>) -> std::net::SocketAddr {
    let rows: Arc<std::sync::Mutex<Vec<(String, Value)>>> = Arc::new(std::sync::Mutex::new(seed_rows));
    let rows_for_handler = Arc::clone(&rows);
    let app = axum::Router::new().fallback(move |req: Request| {
        let rows = Arc::clone(&rows_for_handler);
        async move {
            let path = req.uri().path().to_owned();
            let query = req.uri().query().unwrap_or_default().to_owned();
            let plural = path.rsplit('/').next().unwrap_or("").to_owned();
            if query.contains("watch=true") {
                let (line_tx, line_rx) = tokio::sync::mpsc::channel::<String>(16);
                let _ = line_tx
                    .send(format!(
                        "{}\n",
                        json!({"type": "BOOKMARK", "metadata": {"resourceVersion": "42"}})
                    ))
                    .await;
                let stream = tokio_stream::wrappers::ReceiverStream::new(line_rx);
                return Response::builder()
                    .status(200)
                    .header("content-type", "application/json")
                    .body(Body::from_stream(stream.map(Ok::<_, std::convert::Infallible>)))
                    .unwrap();
            }
            let items: Vec<Value> = rows
                .lock()
                .unwrap()
                .iter()
                .filter(|(family, _)| *family == plural)
                .map(|(_, row)| row.clone())
                .collect();
            let body = json!({
                "apiVersion": "v1", "kind": "List",
                "metadata": {"resourceVersion": "42"}, "items": items,
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
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
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
        cache_push: None,
        roll: Default::default(),
        deploy: None,
        sandbox: Default::default(),
    }
}

async fn boot_gateway(config: GatewayConfig) -> std::net::SocketAddr {
    let gateway = Arc::new(Gateway::new(config, None));
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let informer = Arc::clone(&gateway);
    tokio::spawn(async move { informer.run_informer(shutdown_rx).await });
    let router = gateway.router();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    addr
}

#[tokio::test]
async fn concurrent_gets_coalesce_into_one_upstream_fetch() {
    let calls = Arc::new(AtomicUsize::new(0));
    let node_calls = Arc::clone(&calls);
    let node_app = axum::Router::new().fallback(move |_req: Request| {
        let calls = Arc::clone(&node_calls);
        async move {
            calls.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(std::time::Duration::from_millis(120)).await;
            Response::builder()
                .status(200)
                .header("content-type", "text/plain")
                .body(Body::from("one answer"))
                .unwrap()
        }
    });
    let node_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let node_addr = node_listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(node_listener, node_app).await.unwrap() });

    let kapi_addr = mock_kapi(vec![
        ("httproutes".to_owned(), hr("orders", "orders.example.com")),
        ("pods".to_owned(), pod("orders")),
    ])
    .await;
    let gateway_addr = boot_gateway(gateway_config(kapi_addr, node_addr)).await;
    let client = reqwest::Client::new();
    // Converge the table (the informer's seed LIST) before racing.
    for _ in 0..200 {
        if let Ok(resp) = client
            .get(format!("http://{gateway_addr}/__gateway/health"))
            .send()
            .await
            && let Ok(health) = resp.json::<Value>().await
            && health["served"] == 1
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    let mut handles = Vec::new();
    for _ in 0..8 {
        let client = client.clone();
        handles.push(tokio::spawn(async move {
            client
                .get(format!("http://{gateway_addr}/cart"))
                .header("host", "orders.example.com")
                .send()
                .await
                .unwrap()
        }));
    }
    let mut hits = 0;
    for handle in handles {
        let resp = handle.await.unwrap();
        assert_eq!(resp.status(), 200);
        if resp.headers().get("x-gateway-coalesced").is_some() {
            hits += 1;
        }
        assert_eq!(resp.text().await.unwrap(), "one answer");
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "eight concurrent GETs must collapse into one upstream fetch"
    );
    assert_eq!(hits, 8, "every caller (leader included) gets the coalesced stamp");
}

#[tokio::test]
async fn posts_are_never_coalesced() {
    let calls = Arc::new(AtomicUsize::new(0));
    let node_calls = Arc::clone(&calls);
    let node_app = axum::Router::new().fallback(move |_req: Request| {
        let calls = Arc::clone(&node_calls);
        async move {
            calls.fetch_add(1, Ordering::SeqCst);
            Response::builder()
                .status(200)
                .body(Body::from("ok"))
                .unwrap()
        }
    });
    let node_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let node_addr = node_listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(node_listener, node_app).await.unwrap() });

    let kapi_addr = mock_kapi(vec![
        ("httproutes".to_owned(), hr("orders", "orders.example.com")),
        ("pods".to_owned(), pod("orders")),
    ])
    .await;
    let gateway_addr = boot_gateway(gateway_config(kapi_addr, node_addr)).await;
    let client = reqwest::Client::new();
    for _ in 0..200 {
        if let Ok(resp) = client
            .get(format!("http://{gateway_addr}/__gateway/health"))
            .send()
            .await
            && let Ok(health) = resp.json::<Value>().await
            && health["served"] == 1
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    let mut handles = Vec::new();
    for _ in 0..4 {
        let client = client.clone();
        handles.push(tokio::spawn(async move {
            client
                .post(format!("http://{gateway_addr}/cart"))
                .header("host", "orders.example.com")
                .body("x")
                .send()
                .await
                .unwrap()
        }));
    }
    for handle in handles {
        let resp = handle.await.unwrap();
        assert_eq!(resp.status(), 200);
        assert!(resp.headers().get("x-gateway-coalesced").is_none());
    }
    assert_eq!(calls.load(Ordering::SeqCst), 4);
}
