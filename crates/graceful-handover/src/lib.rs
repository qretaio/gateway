//! Local handover transport: unix-socket IPC with generic messages
//! and graceful-drain signalling.
//!
//! This is the I/O ADAPTER layer for the sans-I/O [`cutover`]
//! machines (owner directive 2026-11-07; the machines merged into
//! this crate as the `cutover` module 2026-11-16). The machines decide WHAT
//! the flow does; the transport side carries the messages and the drain
//! discipline their hosts need while doing it. The design lessons are
//! axum's (the graceful-shutdown study, 2026-11-07):
//!
//! 1. The trigger is a FUTURE, never a callback — the crate owns the
//!    plumbing that turns its resolution into a latching broadcast,
//!    so a SIGTERM wrapper, an IPC message, or a oneshot in a test
//!    all work unchanged.
//! 2. Stop-accept happens BEFORE draining, structurally: the accept
//!    loop exits and the listener drops before the drain barrier is
//!    awaited. The ordering cannot be violated because it is the only
//!    order the code has.
//! 3. Two primitives with distinct roles: a latching signal channel
//!    (watch closure) and a drain barrier (receiver count). No value
//!    ever rides either channel, so signal and data never conflate.
//! 4. The in-flight count is the receiver count: every unit of work
//!    clones a `watch::Receiver` and drops it when done; awaiting
//!    `Sender::closed()` resolves exactly at zero. No atomics, no
//!    RAII guard bugs, no lost-wakeup race.
//! 5. Live units are signalled through per-unit subscriptions; each
//!    unit decides HOW to drain. The crate signals; it never reaches
//!    into unit internals.
//! 6. Timeouts are explicit and opt-in. A deadline's meaning is
//!    defined: the wait resolves as [`DrainOutcome::Forced`] naming
//!    how many units were still live — the host applies its own
//!    force. The default is wait-forever, never a silent abort.
//! 7. Completion is the awaited future resolving (drained), plus an
//!    explicit waiter for external triggers.

pub mod cutover;
pub mod drain;
pub mod frame;
pub mod server;

pub use cutover::Message;
pub use drain::{DrainOutcome, GracefulShutdown, UnitGuard};
pub use frame::{FrameError, decode_frame, encode_frame};
pub use server::{HandoverClient, HandoverServer, ServeOutcome, latch_watcher};

/// The default socket path inside a handover directory. The path is
/// the run's rendezvous: both sides derive it from the handover dir
/// the predecessor already names (no flag, no port, no env).
pub fn socket_path(handover_dir: &std::path::Path) -> std::path::PathBuf {
    handover_dir.join("handover.sock")
}
