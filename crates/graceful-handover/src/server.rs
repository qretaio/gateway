//! The handover socket: a predecessor and a successor signalling
//! each other over a local unix socket with generic messages.
//!
//! Shape (the axum lessons, applied):
//! - The trigger for `serve_until` is a FUTURE, never a callback.
//! - Stop-accept happens BEFORE the drain wait, structurally: the
//!   accept loop breaks on the latch and only then does the server
//!   wait for the connection units.
//! - Every accepted connection is a unit: it holds a `UnitGuard` in
//!   the barrier and a `Signal` subscription; on the latch it
//!   finishes the request in flight and stops reading new ones (a
//!   control socket drains by finishing the current exchange — the
//!   unit decides, the crate signals).
//! - Completion is `serve_until` resolving with the outcome.

use std::path::Path;
use std::sync::Arc;

use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::watch;

use crate::cutover::Message;
use crate::drain::{DrainOutcome, GracefulShutdown};
use crate::frame::{FrameError, decode_frame, encode_frame};

/// What one `serve_until` delivered.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ServeOutcome {
    /// Request frames fully served (request received, reply sent).
    pub served: usize,
    /// Requests that arrived but errored before a reply.
    pub failed: usize,
    /// How the connection units drained after the latch.
    pub drained: DrainOutcome,
}

/// The server side: the role that OWNS the socket (the successor in
/// the blue-green handover; whoever hosts the control plane).
pub struct HandoverServer<K, P> {
    listener: UnixListener,
    marker: std::marker::PhantomData<fn() -> (K, P)>,
}

impl<K, P> HandoverServer<K, P>
where
    K: Serialize + DeserializeOwned + Clone + Eq + std::fmt::Debug + Send + Sync + 'static,
    P: Serialize + DeserializeOwned + Clone + Eq + std::fmt::Debug + Send + Sync + 'static,
{
    /// Bind the socket at `path`, sweeping a stale socket file left
    /// by a dead predecessor. The local trust boundary is the
    /// handover dir; the socket is `0600`.
    pub fn bind(path: &Path) -> std::io::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // A stale socket (the previous incarnation died without
        // unlink) makes `bind` fail with AddrInUse; sweep it. A LIVE
        // server on the same path is a caller bug the bind would
        // mask — the caller owns the one-server-per-path law.
        let _ = std::fs::remove_file(path);
        let listener = UnixListener::bind(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(Self {
            listener,
            marker: std::marker::PhantomData,
        })
    }

    /// Serve until `signal` resolves, then drain. The handler is
    /// every request's answer: one frame in, one reply frame out.
    pub async fn serve_until<F, H, Fut>(
        self,
        signal: F,
        handler: H,
    ) -> std::io::Result<ServeOutcome>
    where
        F: std::future::Future<Output = ()> + Send + 'static,
        H: Fn(Message<K, P>) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<Message<K, P>, String>> + Send,
    {
        let shutdown = Arc::new(GracefulShutdown::new());
        // Lesson 1: the signal future is converted to the latch by
        // THIS plumbing, so the caller never wires callbacks.
        {
            let shutdown = shutdown.clone();
            tokio::spawn(async move {
                signal.await;
                shutdown.trigger();
            });
        }

        let handler = Arc::new(handler);
        let mut served = 0usize;
        let mut failed = 0usize;
        let mut units = Vec::new();

        // Lesson 2, structural: the accept loop is the FIRST select
        // arm; a latched signal breaks it BEFORE any drain wait.
        loop {
            let latch = shutdown.signal();
            let accepted;
            tokio::select! {
                biased;
                _ = async {
                    let mut latch = latch;
                    latch.next().await;
                } => break,
                item = self.listener.accept() => {
                    accepted = item;
                }
            }
            let (stream, _addr) = match accepted {
                Ok(pair) => pair,
                // Transient accept errors (a wedged peer, a fd spike
                // under the adoption): sleep a beat, keep serving —
                // axum's posture, and the ingress serve's lesson
                // (0.2.73 ladder #4): the face never goes dark
                // silently on one accept error.
                Err(_) => {
                    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                    continue;
                }
            };
            let guard = shutdown.subscribe();
            let handler = handler.clone();
            let shutdown_for_unit = shutdown.clone();
            units.push(tokio::spawn(async move {
                serve_connection(stream, handler, guard, shutdown_for_unit).await
            }));
        }

        // Only now the drain barrier (lesson 2's second half).
        let drained = shutdown.shutdown(None).await;
        for unit in units {
            match unit.await {
                Ok(Ok(count)) => served += count,
                Ok(Err(_failures)) => failed += 1,
                Err(_) => failed += 1,
            }
        }
        Ok(ServeOutcome {
            served,
            failed,
            drained,
        })
    }
}

/// One connection's loop: frames in, replies out, until the latch
/// fires between requests or the peer closes. Returns the count of
/// served requests, or the failures.
async fn serve_connection<K, P, H, Fut>(
    mut stream: UnixStream,
    handler: Arc<H>,
    guard: crate::drain::UnitGuard,
    shutdown: Arc<GracefulShutdown>,
) -> Result<usize, usize>
where
    K: Serialize + DeserializeOwned + Clone + Eq + std::fmt::Debug + Send + Sync + 'static,
    P: Serialize + DeserializeOwned + Clone + Eq + std::fmt::Debug + Send + Sync + 'static,
    H: Fn(Message<K, P>) -> Fut,
    Fut: std::future::Future<Output = Result<Message<K, P>, String>> + Send,
{
    let mut served = 0usize;
    let mut failures = 0usize;
    // The barrier entry lives exactly as long as this connection.
    let _guard = guard;
    loop {
        let mut latch = shutdown.signal();
        let incoming;
        tokio::select! {
            biased;
            _ = latch.next() => break,
            frame = decode_frame::<_, Message<K, P>>(&mut stream) => {
                incoming = frame;
            }
        }
        match incoming {
            Ok(request) => match (*handler)(request).await {
                Ok(reply) => {
                    if encode_frame(&mut stream, &reply).await.is_ok() {
                        served += 1;
                    } else {
                        failures += 1;
                        break;
                    }
                }
                // The handler refused: the connection closes and the
                // peer reports the failure honestly. The error
                // vocabulary is the host's, not this crate's.
                Err(_) => {
                    failures += 1;
                    break;
                }
            },
            Err(FrameError::Closed) => break,
            Err(_) => {
                failures += 1;
                break;
            }
        }
    }
    if failures > 0 {
        Err(failures)
    } else {
        Ok(served)
    }
}

/// The client side: dials the socket, exchanges one request for one
/// reply. Cheap to hold; each `call` is one frame pair.
pub struct HandoverClient<K, P> {
    stream: UnixStream,
    marker: std::marker::PhantomData<fn() -> (K, P)>,
}

impl<K, P> HandoverClient<K, P>
where
    K: Serialize + DeserializeOwned + Clone + Eq + std::fmt::Debug + Send + Sync + 'static,
    P: Serialize + DeserializeOwned + Clone + Eq + std::fmt::Debug + Send + Sync + 'static,
{
    pub async fn connect(path: &Path) -> std::io::Result<Self> {
        let stream = UnixStream::connect(path).await?;
        Ok(Self {
            stream,
            marker: std::marker::PhantomData,
        })
    }

    /// One request, one reply.
    pub async fn call(&mut self, request: Message<K, P>) -> Result<Message<K, P>, FrameError> {
        encode_frame(&mut self.stream, &request).await?;
        decode_frame(&mut self.stream).await
    }
}

/// The latch broadcaster for tests and for hosts that trigger the
/// server from an IPC message or a oneshot instead of a signal
/// future: this future resolves when the watch fires.
pub fn latch_watcher(latch: watch::Receiver<()>) -> impl std::future::Future<Output = ()> {
    let mut latch = latch;
    async move {
        let _ = latch.changed().await;
    }
}
