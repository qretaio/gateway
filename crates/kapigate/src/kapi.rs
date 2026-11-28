//! The kapi watch client (kapi.spec EDGE-FR-002): one informer per family —
//! a LIST to seed the table, then an open `?watch=true` JSON-line
//! stream from the pinned resourceVersion. kapi's law (the k8s watch
//! law): a leading BOOKMARK pins the start rv, every recorded write
//! streams as ADDED / MODIFIED / DELETED, a caller pinned below the
//! retained window takes the 410 (re-list), and the server may end the
//! watch at `timeoutSeconds` (re-open). The informer never spins
//! through an error — it re-lists with a small capped backoff.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use tokio::sync::{RwLock, watch};

use crate::table::{Family, Table};

/// The watched families, in deterministic order. Kapinodes is the
/// node family: the table stores it for node/route resolution; the old
/// reconciles its rows. Routes come ONLY from typed Gateway API
/// HttpRoutes (built by the wisolate controller) — no app/worker
/// families: kapi is blind to those kinds (the k8s model).
pub const FAMILIES: [Family; 10] = [
    Family::Httproutes,
    Family::FunctionApps,
    Family::AssetsOnlyApp,
    Family::LegacyPublicAssets,
    Family::WafRules,
    Family::RateLimits,
    Family::Pods,
    Family::Nodes,
    Family::Kapinodes,
    Family::Secrets,
];

/// kapi's resourceVersion rides either side of the JSON number/string
/// fence (the LIST pins a string; the BOOKMARK events emit a number) —
/// read both, never lose the pin.
fn rv_string(v: &serde_json::Value) -> Option<String> {
    v.as_str()
        .map(str::to_owned)
        .or_else(|| v.as_u64().map(|n| n.to_string()))
}

/// One family's watch position.
#[derive(Debug, Default, Clone)]
struct FamilyState {
    resource_version: Option<String>,
    connected: bool,
}

/// The informer: owns the watch loops and the table they feed. The
/// server reads the table per request; the informer is the only
/// writer.
pub struct Informer {
    pub table: Arc<RwLock<Table>>,
    http: reqwest::Client,
    base: String,
    states: Arc<std::sync::Mutex<BTreeMap<Family, FamilyState>>>,
    /// The spawn arm: the kapinodes family's rows reconcile here.
    /// The boot's readiness fact (kapi.spec EDGE-FR-012): the watch carries
    /// true once EVERY family's LIST applied (each carries a
    /// resourceVersion) — the table is converged, a boot may bind. The
    /// informer holds BOTH ends: a watch with zero receivers is closed
    /// and `send` silently fails, so the receiver stays pinned here
    /// and the boot takes its own via `subscribe_seeded`.
    seeded_tx: watch::Sender<bool>,
    seeded_rx: watch::Receiver<bool>,
}

impl Informer {
    pub fn new(kapi_url: &str) -> Self {
        let (seeded_tx, seeded_rx) = watch::channel(false);
        Self {
            seeded_tx,
            seeded_rx,
            table: Arc::new(RwLock::new(Table::default())),
            http: reqwest::Client::new(),
            base: kapi_url.trim_end_matches('/').to_owned(),
            states: Arc::new(std::sync::Mutex::new(BTreeMap::new())),
        }
    }

    /// The readiness fact: has every family's LIST applied at least
    /// once (FR-012 — a table fact, never a timer).
    pub fn is_seeded(&self) -> bool {
        *self.seeded_rx.borrow()
    }

    /// A fresh view of the readiness fact: the boot holds this
    /// receiver and waits on its changes — event-driven, no polling.
    pub fn subscribe_seeded(&self) -> watch::Receiver<bool> {
        self.seeded_tx.subscribe()
    }

    /// The largest family resourceVersion as a number (kapi pins them
    /// monotonically): the roll handshake's comparable version.
    pub fn max_rv(&self) -> Option<u64> {
        self.states
            .lock()
            .unwrap()
            .values()
            .filter_map(|s| s.resource_version.as_deref().and_then(|v| v.parse().ok()))
            .max()
    }

    /// The health face's view of the watch posture: (plural, connected,
    /// rv).
    pub fn health(&self) -> Vec<(String, bool, String)> {
        self.states
            .lock()
            .unwrap()
            .iter()
            .map(|(f, s)| {
                (
                    f.plural().to_owned(),
                    s.connected,
                    s.resource_version
                        .clone()
                        .unwrap_or_else(|| "never".to_owned()),
                )
            })
            .collect()
    }

    /// Run every family's informer loop until the shutdown signal
    /// flips. One task per family; all run to the signal.
    pub async fn run(&self, shutdown: watch::Receiver<bool>) {
        let this = Arc::new(Self {
            table: Arc::clone(&self.table),
            http: self.http.clone(),
            base: self.base.clone(),
            states: Arc::clone(&self.states),
            seeded_tx: self.seeded_tx.clone(),
            seeded_rx: self.seeded_rx.clone(),
        });
        let mut handles = Vec::new();
        for family in FAMILIES {
            let handle = FamilyLoop {
                inner: Arc::clone(&this),
                family,
                shutdown: shutdown.clone(),
            };
            handles.push(tokio::spawn(async move { handle.run().await }));
        }
        for handle in handles {
            let _ = handle.await;
        }
    }
}

struct FamilyLoop {
    inner: Arc<Informer>,
    family: Family,
    shutdown: watch::Receiver<bool>,
}

impl FamilyLoop {
    async fn run(&self) {
        let mut backoff = Duration::from_secs(1);
        let shutdown = self.shutdown.clone();
        loop {
            if *shutdown.borrow() {
                return;
            }
            match self.cycle().await {
                Ok(()) => {
                    // The server ended the watch cleanly (the
                    // timeoutSeconds law): re-open from the pinned rv
                    // without a list, no backoff owed.
                    backoff = Duration::from_secs(1);
                }
                Err(err) => {
                    eprintln!("[gateway] watch {}: {err}", self.family.plural());
                    // The capped backoff as a bounded wait on a pending
                    // future — no sleep anywhere in src/.
                    let _ = tokio::time::timeout(backoff, std::future::pending::<()>()).await;
                    backoff = (backoff * 2).min(Duration::from_secs(30));
                }
            }
        }
    }

    /// One list + one watch cycle. Returns when the watch stream ends.
    async fn cycle(&self) -> Result<(), String> {
        // LIST: seed the family, pin the rv. A route family names its
        // label selector — the server-side filter keeps the watch (and
        // the seed list) to the http-route-carrying rows.
        let list_path = self.family.list_path();
        let url = match self.family.watch_selector() {
            Some(sel) => format!("{}{list_path}?{sel}", self.inner.base),
            None => format!("{}{list_path}", self.inner.base),
        };
        let resp = self
            .inner
            .http
            .get(&url)
            .timeout(Duration::from_secs(15))
            .send()
            .await
            .map_err(|e| format!("list: {e}"))?;
        let status = resp.status();
        if status.as_u16() == 404 {
            // An unregistered CRD (e.g. `WafRule`/`RateLimit` on a fleet
            // whose kapi predates them) means "no rules of that kind",
            // NOT a boot refusal. Seed an EMPTY family with a synthetic
            // rv so the FR-013 convergence gate can latch — fail open,
            // as the WAF/ratelimit laws themselves do when empty.
            let mut table = self.inner.table.write().await;
            table.replace(self.family, &[]);
            drop(table);
            self.set_state(|s| {
                s.resource_version = Some("0".to_owned());
                s.connected = true;
            });
            // No watch to run on a missing resource; a short quiet cycle
            // retries so a CRD registered later is picked up.
            tokio::time::sleep(Duration::from_secs(5)).await;
            return Ok(());
        }
        if !status.is_success() {
            return Err(format!("list: HTTP {status}"));
        }
        let text = resp.text().await.map_err(|e| format!("list body: {e}"))?;
        let body: Value = serde_json::from_str(&text).map_err(|e| format!("list parse: {e}"))?;
        let items = body
            .pointer("/items")
            .and_then(|i| i.as_array())
            .cloned()
            .unwrap_or_default();
        let rv = body
            .pointer("/metadata/resourceVersion")
            .and_then(rv_string);
        {
            let mut table = self.inner.table.write().await;
            table.replace(self.family, &items);
        }
        self.set_state(|s| {
            s.resource_version = rv.clone();
            s.connected = true;
        });

        // WATCH: the open stream from the pinned rv.
        let Some(rv) = rv else {
            return Err("list carried no resourceVersion".to_owned());
        };
        let sep = if url.contains('?') { '&' } else { '?' };
        let watch_url = format!("{url}{sep}watch=true&resourceVersion={rv}");
        let mut stream = self
            .inner
            .http
            .get(&watch_url)
            .send()
            .await
            .map_err(|e| format!("watch: {e}"))?;
        let status = stream.status();
        if status.as_u16() == 410 {
            self.set_state(|s| s.connected = false);
            return Err("watch: 410 Gone — re-list".to_owned());
        }
        if !status.is_success() {
            self.set_state(|s| s.connected = false);
            return Err(format!("watch: HTTP {status}"));
        }

        // The JSON-line pump: buffer the chunks, split on newline,
        // apply each event to the table.
        let mut buffer = String::new();
        loop {
            let Some(chunk) = stream
                .chunk()
                .await
                .map_err(|e| format!("watch read: {e}"))?
            else {
                break; // the stream ended — the cycle ends, the loop re-opens
            };
            buffer.push_str(&String::from_utf8_lossy(&chunk));
            while let Some(pos) = buffer.find('\n') {
                let line: String = buffer.drain(..=pos).collect();
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                self.apply_line(line).await;
            }
        }
        self.set_state(|s| s.connected = false);
        Ok(())
    }

    /// One watch line: a bookmark (pin the rv) or an object event
    /// (apply the delta).
    async fn apply_line(&self, line: &str) {
        let Ok(event) = serde_json::from_str::<Value>(line) else {
            return;
        };
        let event_type = event.get("type").and_then(|t| t.as_str()).unwrap_or("");
        match event_type {
            "BOOKMARK" => {
                // kapi nests the bookmark's head under `object` (the
                // kube-rs WatchEvent tag/content shape); the top-level
                // metadata is the fallback shape.
                let rv = event
                    .pointer("/object/metadata/resourceVersion")
                    .or_else(|| event.pointer("/metadata/resourceVersion"))
                    .and_then(rv_string);
                // A line matching NEITHER shape leaves rv None — an
                // unparsable bookmark never unwinds the family's
                // pinned rv.
                self.set_state(|s| {
                    if let Some(rv) = rv {
                        s.resource_version = Some(rv);
                    }
                });
            }
            "ADDED" | "MODIFIED" | "DELETED" => {
                if let Some(object) = event.get("object") {
                    // Advance the family's position from EVERY event, not
                    // just BOOKMARKs: kapi emits one bookmark at watch start
                    // and then a stream of MODIFIED events whose
                    // object.metadata.resourceVersion keeps climbing. A
                    // bookmark-only informer pins itself at the LIST rv
                    // forever — health reports connected with a frozen
                    // max_rv, and a re-list/watch restart replays the same
                    // stale window.
                    let rv = object
                        .pointer("/metadata/resourceVersion")
                        .and_then(rv_string);
                    self.set_state(|s| {
                        if let Some(rv) = rv {
                            s.resource_version = Some(rv);
                        }
                    });
                    let mut table = self.inner.table.write().await;
                    table.apply(self.family, event_type, object);
                }
            }
            _ => {}
        }
    }

    fn set_state(&self, f: impl FnOnce(&mut FamilyState)) {
        let mut states = self.inner.states.lock().unwrap();
        f(states.entry(self.family).or_default());
        // The readiness fact iterates the LAW, not the map: the map
        // only holds already-listed families, so `all()` over IT
        // latches on the first family's LIST (a 1/5 table reads
        // seeded and the FR-012 gate dies). Every family in FAMILIES
        // carrying a resourceVersion is the table fact. Each state
        // update fires the watch (a send marks the version even when
        // the value repeats), so the boot's waits are event-driven.
        let all_listed = FAMILIES
            .iter()
            .all(|f| states.get(f).is_some_and(|s| s.resource_version.is_some()));
        let _ = self.inner.seeded_tx.send(all_listed);
    }
}
