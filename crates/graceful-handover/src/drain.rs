//! The drain discipline, learned from axum's graceful shutdown.
//!
//! Two primitives with distinct roles (never one multiplexed
//! channel): the SIGNAL is a latching watch whose closure is the only
//! event — a unit that subscribes after the trigger still observes
//! it; the BARRIER counts in-flight units by receiver count — every
//! unit holds a cloned `watch::Receiver` and drops it on completion,
//! so awaiting `Sender::closed()` resolves exactly at zero. No
//! atomics, no lost-wakeup race, no RAII guard to get wrong.

use tokio::sync::watch;

/// How a drain wait ended.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DrainOutcome {
    /// Every unit completed before the wait resolved.
    Drained,
    /// The deadline passed with units still live. The crate stopped
    /// WAITING; it never aborts the units (they are the host's
    /// futures). `abandoned` names how many were still in flight —
    /// the host applies its own force.
    Forced { abandoned: usize },
}

/// The drain discipline for one handover: trigger, signal, barrier.
/// The latch sits in a mutex because the handle is shared (Arc) —
/// the lock guards a one-way Option take; contention is nil.
#[derive(Debug)]
pub struct GracefulShutdown {
    /// Latching stop channel. `trigger()` drops the sender; every
    /// subscriber's `changed()` resolves from then on, whenever it
    /// subscribed.
    signal_tx: std::sync::Mutex<Option<watch::Sender<()>>>,
    /// The drain barrier: its receiver count IS the in-flight count.
    close_tx: watch::Sender<()>,
}

impl Default for GracefulShutdown {
    fn default() -> Self {
        Self::new()
    }
}

impl GracefulShutdown {
    pub fn new() -> Self {
        let (signal_tx, _) = watch::channel(());
        let (close_tx, _) = watch::channel(());
        Self {
            signal_tx: std::sync::Mutex::new(Some(signal_tx)),
            close_tx,
        }
    }

    /// Latch the stop signal. Idempotent; the first call wins (the
    /// latch). Every live unit's signal subscription resolves.
    pub fn trigger(&self) {
        self.signal_tx.lock().unwrap().take();
    }

    /// Has the stop signal latched?
    pub fn is_triggered(&self) -> bool {
        self.signal_tx.lock().unwrap().is_none()
    }

    /// Subscribe one unit of work: hold the returned guard while the
    /// unit is in flight, drop it when done. The guard's receiver is
    /// the unit's entry in the barrier count.
    pub fn subscribe(&self) -> UnitGuard {
        UnitGuard(self.close_tx.subscribe())
    }

    /// The per-unit stop subscription (lesson 5: the crate signals,
    /// the unit decides how to drain). Await `Signal::next` inside a
    /// `tokio::select!` with the unit's own work.
    pub fn signal(&self) -> Signal {
        Signal(
            self.signal_tx
                .lock()
                .unwrap()
                .as_ref()
                .map(|tx| tx.subscribe()),
        )
    }

    /// How many units are still in flight.
    pub fn in_flight(&self) -> usize {
        self.close_tx.receiver_count()
    }

    /// Wait for every unit to complete. `timeout: None` waits
    /// forever (axum's default posture: a graceful shutdown never
    /// silently aborts in-flight work); `Some(deadline)` resolves as
    /// [`DrainOutcome::Forced`] naming the abandoned count.
    pub async fn shutdown(&self, timeout: Option<std::time::Duration>) -> DrainOutcome {
        let wait = self.close_tx.closed();
        match timeout {
            None => {
                let _ = wait.await;
                DrainOutcome::Drained
            }
            Some(deadline) => match tokio::time::timeout(deadline, wait).await {
                Ok(()) => DrainOutcome::Drained,
                Err(_) => DrainOutcome::Forced {
                    abandoned: self.close_tx.receiver_count(),
                },
            },
        }
    }
}

/// A unit's entry in the drain barrier. Hold it while the unit is in
/// flight; the drop IS the completion signal. The receiver is never
/// read — its LIFETIME is the count.
#[derive(Debug)]
pub struct UnitGuard(#[allow(dead_code)] watch::Receiver<()>);

/// The stop signal's per-unit subscription. `changed()` resolves
/// when [`GracefulShutdown::trigger`] latched — before or after this
/// subscription was taken (the latch is closure, not a message).
#[derive(Debug)]
pub struct Signal(Option<watch::Receiver<()>>);

impl Signal {
    /// Resolve when the stop signal latched (or immediately, if it
    /// latched before this call).
    pub async fn next(&mut self) {
        // The channel carries no values; closure is the only event,
        // so `changed()` resolving IS the trigger. A None means the
        // sender was already gone: the latch fired before this
        // subscription existed.
        if let Some(rx) = &mut self.0 {
            let _ = rx.changed().await;
        }
    }

    /// Has the latch already fired?
    pub fn fired(&self) -> bool {
        self.0.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn a_drain_resolves_when_the_last_guard_drops() {
        let shutdown = std::sync::Arc::new(GracefulShutdown::new());
        let guard_a = shutdown.subscribe();
        let guard_b = shutdown.subscribe();
        assert_eq!(shutdown.in_flight(), 2);

        let waiter = {
            let shutdown = shutdown.clone();
            tokio::spawn(async move { shutdown.shutdown(None).await })
        };

        // While both guards live, the wait holds.
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(!waiter.is_finished(), "the drain resolved while units live");

        drop(guard_a);
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(!waiter.is_finished(), "one unit is still live");

        drop(guard_b);
        let outcome = waiter.await.unwrap();
        assert_eq!(outcome, DrainOutcome::Drained);
    }

    #[tokio::test]
    async fn a_deadline_forces_with_the_abandoned_count() {
        let shutdown = GracefulShutdown::new();
        let _guard = shutdown.subscribe();
        let outcome = shutdown.shutdown(Some(Duration::from_millis(20))).await;
        assert_eq!(outcome, DrainOutcome::Forced { abandoned: 1 });
        // The unit is NOT aborted — the crate stopped waiting.
        assert_eq!(shutdown.in_flight(), 1);
    }

    #[tokio::test]
    async fn the_signal_latches_for_late_subscribers() {
        let shutdown = GracefulShutdown::new();
        // Latch BEFORE anyone subscribes.
        shutdown.trigger();
        assert!(shutdown.is_triggered());

        let mut late = shutdown.signal();
        assert!(late.fired(), "a late subscriber observes the latch at once");
        // `next` resolves immediately, not never.
        tokio::time::timeout(Duration::from_millis(20), late.next())
            .await
            .expect("the latch was lost on a late subscriber");
    }

    #[tokio::test]
    async fn an_untriggered_signal_holds() {
        let shutdown = GracefulShutdown::new();
        let mut signal = shutdown.signal();
        assert!(!signal.fired());
        let result = tokio::time::timeout(Duration::from_millis(30), signal.next()).await;
        assert!(result.is_err(), "an untriggered latch must hold");
    }
}
