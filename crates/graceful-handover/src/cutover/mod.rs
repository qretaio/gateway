//! Sans-I/O control machines for the failover flows.
//!
//! This module is JUST the control logic (owner directive 2026-11-07).
//! The flow law is DEFINED with [`statig`](https://crates.io/crates/statig)
//! (owner directive 2026-11-07: "Let's use
//! <https://crates.io/crates/statig> for defining the cutover state
//! machine"): each machine is one `#[state]` handler per state, the
//! transition in the arm, the owed actions pushed in the arm. The
//! handlers stay pure — they read and write only the machine's own
//! storage (run, epoch, owed, refusals) and touch no tokio, no
//! socket, no clock, no process. The host maps its concrete world
//! onto the event alphabet, performs the actions the machine
//! delivers, and drives `Tick`-style events itself.
//!
//! **The host owns every wire.** Nothing here opens, reads, or waits
//! on anything: no file, no socket, no clock, no supervisor, no
//! child process. A test drives a machine with plain enum values and
//! asserts on the plain enum values that come back — that is the
//! whole interface, and the dependency list is the proof (no
//! runtime, no io).
//!
//! The module's own contract rides on top of statig and is what the
//! hosts and tests rely on:
//!
//! - TOTAL: every (state, event) pair answers a defined outcome. A
//!   pair the law names applies: the state moves, the owed actions
//!   come back in order. An illegal pair is a recorded [`Refusal`] —
//!   no actions, no move — never a panic, never a silently dropped
//!   event. A terminal state refuses as [`RefusalReason::Terminal`];
//!   everything else as [`RefusalReason::IllegalTransition`].
//! - FENCED: every machine instance is bound to ONE run's [`RunId`],
//!   and the epoch is the run's generation. [`StateMachine::on_run_event`]
//!   refuses anything carrying an epoch the machine has superseded
//!   ([`RefusalReason::StaleEpoch`]); [`StateMachine::on_message`]
//!   additionally refuses anything carrying another run's id
//!   ([`RefusalReason::ForeignRun`]) or addressed to another role.
//!   A rollback that restarts the ladder bumps the epoch itself, so
//!   the dead generation's ghosts are refused.
//! - PLUGGABLE: the [`Message`] envelope rides any transport (`K`
//!   the machine-facing kind, `P` the host's payload); nothing here
//!   knows a socket.
//!
//! Three machines ride the fleet failover today:
//!
//! - [`predecessor::PredecessorMachine`] — the serving node that
//!   adopts a staged release and hands the port over (the blue-green
//!   releaser; the rollback law 0.2.38 and the blue-green soak road
//!   live in its handlers).
//! - [`successor::SuccessorMachine`] — the cutover twin that takes
//!   the movable apps, announces MAINPID at CUTOVER READY (0.2.73)
//!   and lands the ingress.
//! - [`holdout::HoldoutMachine`] — the fork-marked scoped worker:
//!   holdouts over the mesh, the ride-home armed at the flag's
//!   successor (0.2.74), the reclaim when the successor goes stale.
//!
//! Future machines slot into the same harness — a new machine is a
//! statig impl block plus a [`harness!`] row, not a rewrite.

mod holdout;
mod predecessor;
mod successor;

pub use holdout::{HoldoutAction, HoldoutEvent, HoldoutMachine, HoldoutState};
pub use predecessor::{PredecessorAction, PredecessorEvent, PredecessorMachine, PredecessorState};
pub use successor::{SuccessorAction, SuccessorEvent, SuccessorMachine, SuccessorState};

// The harness, the trait, and the plain contract types live in the
// `fsm` workspace (~/src/fsm; extracted from this crate 2026-11-07,
// carved out of the runtime 2026-11-10 once the k8s plane became a citizen). Every consumer path — `cutover::RunId`,
// `cutover::StateMachine`, `harness!` — stays exactly as it was.
pub(crate) use fsm::harness;
pub use fsm::{
    REFUSAL_BOOK_CAP, Refusal, RefusalReason, RunEvent, RunId, StateMachine, fuzz, reachable_states,
};

/// Who speaks on the fleet's message plane. THE ROLE VOCABULARY IS
/// THE FLEET'S, NOT THE HARNESS'S (owner directive 2026-11-07: a
/// role enum in fsm proves the harness not generic — the
/// vocabulary lives here, and every machine crate stamps its role
/// from this one place). The envelope's addressing: a machine only
/// accepts the messages addressed to its own role (the transport may
/// route, the machine verifies).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, serde::Serialize, serde::Deserialize)]
pub enum Role {
    /// The serving node handing over (the blue-green releaser).
    Predecessor,
    /// The cutover twin taking over.
    Successor,
    /// The fork-marked scoped worker holding the holdouts.
    Holdout,
    /// The process supervisor (systemd) — the MAINPID channel.
    Supervisor,
    /// The scheduler machine (FR-087): the scheduled-work loops
    /// (queue, cron, alarms) and their gate — the machine that parks
    /// and releases them for handover.
    Scheduler,
}

/// The fleet's message envelope: the harness's pluggable message
/// stamped with THIS crate's role vocabulary. The wire format rides
/// unchanged — a `Message` here is a `fsm::Message<Role, K, P>`.
pub type Message<K, P> = fsm::Message<Role, K, P>;
