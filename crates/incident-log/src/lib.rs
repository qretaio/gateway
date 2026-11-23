//! Structured security-incident logging for the edge gateway, as a
//! `tracing` layer.
//!
//! Instead of ad-hoc `eprintln!` at each block site, the gateway emits a
//! single structured event:
//!
//! ```ignore
//! tracing::warn!(
//!     target: "incident",
//!     client_ip = %ip,
//!     host = %host,
//!     path = %path,
//!     rule = "reserved-private-path",
//!     action = "block",
//!     "private path probe"
//! );
//! ```
//!
//! [`IncidentLayer`] captures those events, turns each into an org-audit
//! [`LogRecord`] under the `host.incidents` kind, and batches them into
//! parquet segments via the shared `parquet-log` codec. A background
//! [`IncidentWriter`] flushes segments to a pluggable [`IncidentSink`]:
//! a local directory (dev / local agg) or the node's private log-write
//! face (production — lands in `org/<org>/logs/host.incidents/`).
//!
//! Logging is best-effort by law: a sink failure is counted and dropped,
//! never propagated to the request path. The layer sends to a bounded
//! channel; a full channel drops the newest incident rather than blocking
//! a request.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tracing::field::{Field, Visit};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context as LayerContext;

pub use parquet_log::{LogRecord, encode};

/// The tracing target the layer listens for. Emit incidents with
/// `target: "incident"` (or use [`incident!`]).
pub const INCIDENT_TARGET: &str = "incident";
/// The audit-stream kind incidents are written under. `host.` so only the
/// host (gateway/node) can write it — guests are refused by the node.
pub const INCIDENTS_KIND: &str = "host.incidents";
/// The org/app identity stamped on every gateway incident record.
pub const INCIDENT_ORG: &str = "qreta";
pub const INCIDENT_APP: &str = "gateway";

/// Metadata keys (kept in sync with wisolate's `incident_meta`).
pub mod field {
    pub const CLIENT_IP: &str = "client_ip";
    pub const HOST: &str = "host";
    pub const PATH: &str = "path";
    pub const RULE: &str = "rule";
    pub const ACTION: &str = "action";
    pub const GATEWAY_INSTANCE: &str = "gateway_instance";
}

/// The wire shape the HTTP sink POSTs to the node's private write face.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IncidentWire {
    pub org: String,
    pub app: String,
    pub kind: String,
    pub level: String,
    pub message: String,
    pub metadata: BTreeMap<String, String>,
}

impl From<LogRecord> for IncidentWire {
    fn from(r: LogRecord) -> Self {
        Self {
            org: r.org,
            app: r.app,
            kind: r.kind,
            level: r.level,
            message: r.message,
            metadata: r.metadata,
        }
    }
}

/// Where flushed incident parquet segments go.
pub trait IncidentSink: Send + Sync + 'static {
    /// Persist one segment. `first_ts` is the segment's first record's
    /// epoch-ms (the sort key the node's log store uses).
    fn write<'a>(
        &'a self,
        org: &'a str,
        kind: &'a str,
        first_ts: i64,
        bytes: &'a [u8],
    ) -> BoxFuture<'a, Result<()>>;
}

/// A sink that writes parquet segments into a local directory —
/// `<dir>/<kind>/<first_ts>-gateway-<seq>.parquet`. Useful for local dev
/// and for shipping via an external collector; mirrors the node's flat
/// segment layout so DuckDB reads it unchanged.
pub struct LocalDirSink {
    root: PathBuf,
    seq: std::sync::atomic::AtomicU64,
}

impl LocalDirSink {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            seq: std::sync::atomic::AtomicU64::new(0),
        }
    }
}

impl IncidentSink for LocalDirSink {
    fn write<'a>(
        &'a self,
        _org: &'a str,
        kind: &'a str,
        first_ts: i64,
        bytes: &'a [u8],
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let dir = self.root.join(kind);
            tokio::fs::create_dir_all(&dir)
                .await
                .context("incident dir")?;
            let seq = self.seq.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let path = dir.join(format!("{first_ts:020}-gateway-{seq}.parquet"));
            tokio::fs::write(&path, bytes)
                .await
                .context("incident segment write")?;
            Ok(())
        })
    }
}

/// A no-op sink for when no destination is configured. Logging stays
/// best-effort: incidents are dropped without a boot failure or a noisy
/// "not a directory" error on every flush.
pub struct DiscardSink;

impl IncidentSink for DiscardSink {
    fn write<'a>(
        &'a self,
        _org: &'a str,
        _kind: &'a str,
        _first_ts: i64,
        _bytes: &'a [u8],
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

/// A sink that POSTs each incident as JSON to the node's private
/// log-write face. The node validates the bearer and appends to the
/// `host.incidents` kind via its existing `LogDispatch::write_host`.
pub struct HttpSink {
    client: reqwest::Client,
    url: String,
    bearer: String,
}

impl HttpSink {
    pub fn new(url: impl Into<String>, bearer: impl Into<String>) -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(3))
                .build()
                .expect("incident http client"),
            url: url.into(),
            bearer: bearer.into(),
        }
    }
}

impl IncidentSink for HttpSink {
    fn write<'a>(
        &'a self,
        _org: &'a str,
        _kind: &'a str,
        _first_ts: i64,
        bytes: &'a [u8],
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            // The writer encoded `bytes` as a JSON array of IncidentWire
            // (config.http_json = true for this sink). The node's private
            // write face accepts that shape and appends via write_host.
            self.client
                .post(&self.url)
                .bearer_auth(&self.bearer)
                .header("content-type", "application/json")
                .body(bytes.to_vec())
                .send()
                .await
                .context("incident post")?
                .error_for_status()
                .context("incident post status")?;
            Ok(())
        })
    }
}

/// A tracing layer that captures `target: "incident"` events into the
/// incident channel. Clone-cheap; register it alongside the fmt layer.
#[derive(Clone)]
pub struct IncidentLayer {
    tx: mpsc::Sender<LogRecord>,
    gateway_instance: Arc<str>,
}

impl IncidentLayer {
    pub fn new(tx: mpsc::Sender<LogRecord>, gateway_instance: impl Into<Arc<str>>) -> Self {
        Self {
            tx,
            gateway_instance: gateway_instance.into(),
        }
    }
}

/// Capture the named fields of an incident event.
#[derive(Default)]
struct Fields {
    client_ip: String,
    host: String,
    path: String,
    rule: String,
    action: String,
}

impl Visit for Fields {
    fn record_str(&mut self, field: &Field, value: &str) {
        match field.name() {
            field::CLIENT_IP => self.client_ip = value.to_owned(),
            field::HOST => self.host = value.to_owned(),
            field::PATH => self.path = value.to_owned(),
            field::RULE => self.rule = value.to_owned(),
            field::ACTION => self.action = value.to_owned(),
            _ => {}
        }
    }
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        // `%value` (Display) lands in record_str; `?value` lands here.
        self.record_str(field, &format!("{value:?}"));
    }
}

impl<S: tracing::Subscriber> Layer<S> for IncidentLayer {
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: LayerContext<'_, S>) {
        if event.metadata().target() != INCIDENT_TARGET {
            return;
        }
        let mut f = Fields::default();
        event.record(&mut f);
        let mut metadata = BTreeMap::new();
        metadata.insert(field::CLIENT_IP.to_owned(), f.client_ip);
        metadata.insert(field::HOST.to_owned(), f.host);
        metadata.insert(field::PATH.to_owned(), f.path);
        metadata.insert(field::RULE.to_owned(), f.rule);
        metadata.insert(field::ACTION.to_owned(), f.action);
        metadata.insert(
            field::GATEWAY_INSTANCE.to_owned(),
            self.gateway_instance.to_string(),
        );
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .min(i64::MAX as u128) as i64;
        let level = match *event.metadata().level() {
            tracing::Level::ERROR => "error",
            tracing::Level::WARN => "warn",
            tracing::Level::INFO => "info",
            tracing::Level::DEBUG => "debug",
            tracing::Level::TRACE => "trace",
        };
        let record = LogRecord {
            ts,
            org: INCIDENT_ORG.to_owned(),
            app: INCIDENT_APP.to_owned(),
            kind: INCIDENTS_KIND.to_owned(),
            level: level.to_owned(),
            message: event.metadata().name().to_owned(),
            metadata,
        };
        // Bounded channel: a full buffer drops the newest incident rather
        // than blocking the request path — logging is best-effort.
        let _ = self.tx.try_send(record);
    }
}

/// Configuration for the background writer.
pub struct WriterConfig {
    pub batch_size: usize,
    pub flush_every: Duration,
    /// When true, the HTTP sink receives JSON records instead of parquet
    /// bytes (the node's log-write face accepts JSON).
    pub http_json: bool,
}

impl Default for WriterConfig {
    fn default() -> Self {
        Self {
            batch_size: 64,
            flush_every: Duration::from_secs(5),
            http_json: false,
        }
    }
}

/// Drain the incident channel and flush batches to a sink. Spawn this on
/// the gateway's tokio runtime. On sink failure the batch is dropped and
/// the error is reported via eprintln — never to the request path.
pub async fn run_writer(
    mut rx: mpsc::Receiver<LogRecord>,
    sink: Arc<dyn IncidentSink>,
    config: WriterConfig,
) {
    let mut batch: Vec<LogRecord> = Vec::with_capacity(config.batch_size);
    let mut tick = tokio::time::interval(config.flush_every);
    loop {
        tokio::select! {
            maybe = rx.recv() => match maybe {
                Some(record) => {
                    batch.push(record);
                    if batch.len() >= config.batch_size {
                        flush(&mut batch, &sink, config.http_json).await;
                    }
                }
                None => {
                    flush(&mut batch, &sink, config.http_json).await;
                    break;
                }
            },
            _ = tick.tick() => {
                flush(&mut batch, &sink, config.http_json).await;
            }
        }
    }
}

async fn flush(batch: &mut Vec<LogRecord>, sink: &Arc<dyn IncidentSink>, http_json: bool) {
    if batch.is_empty() {
        return;
    }
    let first_ts = batch[0].ts;
    let payload = if http_json {
        let wires: Vec<IncidentWire> = batch.iter().cloned().map(Into::into).collect();
        serde_json::to_vec(&wires).unwrap_or_default()
    } else {
        match encode(batch) {
            Ok(bytes) => bytes,
            Err(e) => {
                eprintln!("[incident] parquet encode failed: {e:#}");
                batch.clear();
                return;
            }
        }
    };
    if let Err(e) = sink
        .write(INCIDENT_ORG, INCIDENTS_KIND, first_ts, &payload)
        .await
    {
        eprintln!("[incident] sink write failed: {e:#}");
    }
    batch.clear();
}
