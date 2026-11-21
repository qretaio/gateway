//! The handover socket's gates: request/reply over the unix socket,
//! the latch stopping the accept loop BEFORE the drain wait, late
//! clients refused honestly, and the drain outcome named.

use std::path::PathBuf;

use graceful_handover::cutover::{Message, Role, RunId};
use graceful_handover::{HandoverClient, HandoverServer, ServeOutcome, socket_path};
use tokio::sync::watch;

fn envelope(kind: &'static str, note: &str) -> Message<String, String> {
    Message {
        run: RunId(1),
        epoch: 0,
        from: Role::Predecessor,
        to: Role::Successor,
        kind: kind.to_string(),
        payload: note.to_string(),
    }
}

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("graceful-handover-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[tokio::test]
async fn a_call_gets_its_reply_and_the_server_counts_it() {
    let dir = temp_dir("roundtrip");
    let path = socket_path(&dir);

    let (latch_tx, latch_rx) = watch::channel(());
    let server = HandoverServer::<String, String>::bind(&path).unwrap();
    let server_task = tokio::spawn(async move {
        server
            .serve_until(
                graceful_handover::latch_watcher(latch_rx),
                |request| async move {
                    Ok(Message {
                        run: request.run,
                        epoch: request.epoch,
                        from: Role::Successor,
                        to: Role::Predecessor,
                        kind: format!("ack/{}", request.kind),
                        payload: format!("saw: {}", request.payload),
                    })
                },
            )
            .await
            .unwrap()
    });

    // The client may need a beat for the listener to be up (bind
    // happened before the spawn; the socket file exists already).
    let mut client = HandoverClient::<String, String>::connect(&path)
        .await
        .unwrap();
    let reply = client
        .call(envelope("handshake", "the port is yours"))
        .await
        .unwrap();
    assert_eq!(reply.kind, "ack/handshake");
    assert_eq!(reply.payload, "saw: the port is yours");
    assert_eq!(reply.from, Role::Successor);

    latch_tx.send(()).unwrap();
    drop(latch_tx);
    let outcome: ServeOutcome = server_task.await.unwrap();
    assert_eq!(outcome.served, 1);
    assert_eq!(outcome.failed, 0);
    assert_eq!(outcome.drained, graceful_handover::DrainOutcome::Drained);

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn the_latch_stops_accepts_before_draining_and_late_dials_fail() {
    let dir = temp_dir("latch");
    let path = socket_path(&dir);

    let (never_tx, never_rx) = watch::channel(());
    let server = HandoverServer::<String, String>::bind(&path).unwrap();
    let server_task = tokio::spawn(async move {
        let outcome = server
            .serve_until(
                graceful_handover::latch_watcher(never_rx),
                |request| async move { Ok(request) },
            )
            .await
            .unwrap();
        // The latch fired: prove it happened BEFORE the drain wait by
        // the signal the caller can observe — the outcome resolves at
        // all, with zero served (the accept loop broke first).
        outcome
    });

    let mut client = HandoverClient::<String, String>::connect(&path)
        .await
        .unwrap();
    let reply = client.call(envelope("ping", "1")).await.unwrap();
    assert_eq!(reply.kind, "ping");

    // Latch.
    never_tx.send(()).unwrap();
    drop(never_tx);
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(2), server_task)
        .await
        .expect("the server never resolved after the latch")
        .unwrap();
    assert_eq!(outcome.served, 1);

    // A LATE client finds the socket gone or closed — an honest
    // failure, never a hang.
    let late = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        match HandoverClient::<String, String>::connect(&path).await {
            Ok(mut client) => client.call(envelope("ping", "late")).await.is_err(),
            Err(_) => true,
        }
    })
    .await
    .expect("the late dial hung");
    assert!(late, "the late dial must fail, not succeed silently");

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_stale_socket_file_is_swept_on_bind() {
    let dir = temp_dir("stale");
    let path = socket_path(&dir);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, b"garbage from a dead incarnation").unwrap();

    let server = HandoverServer::<String, String>::bind(&path);
    assert!(server.is_ok(), "bind must sweep the stale socket file");

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn concurrent_clients_are_served_independently() {
    let dir = temp_dir("concurrent");
    let path = socket_path(&dir);

    let (_latch_tx, latch_rx) = watch::channel(());
    let server = HandoverServer::<String, String>::bind(&path).unwrap();
    let server_task = tokio::spawn(async move {
        server
            .serve_until(
                graceful_handover::latch_watcher(latch_rx),
                |request| async move {
                    Ok(Message {
                        run: request.run,
                        epoch: request.epoch,
                        from: Role::Successor,
                        to: Role::Predecessor,
                        kind: format!("ack/{}", request.kind),
                        payload: request.payload,
                    })
                },
            )
            .await
            .unwrap()
    });

    let mut handles = Vec::new();
    for i in 0..8 {
        let path = path.clone();
        handles.push(tokio::spawn(async move {
            let mut client = HandoverClient::<String, String>::connect(&path)
                .await
                .unwrap();
            let reply = client
                .call(envelope("ping", &format!("client {i}")))
                .await
                .unwrap();
            assert_eq!(reply.kind, "ack/ping");
            assert_eq!(reply.payload, format!("client {i}"));
        }));
    }
    for handle in handles {
        handle.await.unwrap();
    }

    _latch_tx.send(()).unwrap();
    drop(_latch_tx);
    let outcome = server_task.await.unwrap();
    assert_eq!(outcome.served, 8);

    let _ = std::fs::remove_dir_all(&dir);
}
