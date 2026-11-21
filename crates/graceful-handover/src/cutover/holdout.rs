//! The holdout machine: the fork-marked scoped worker.
//!
//! The law is statig-defined, encoding the worker road as prod-proven
//! (ladders 6 through 12, SPEC 0.2.48/0.2.73/0.2.74):
//!
//! - the mark or a standing flag scopes the boot; the mesh attaches
//!   after the fork-parent is waited out; the watch arms the
//!   ride-home at the flag's successor, re-arms on successor change
//!   and at the 23 h chain refresh.
//! - a `BindingProviderMiss` rides home ONLY once armed — before
//!   that the host answers the miss honestly (a genuine not-live;
//!   riding early would loop, the 0.2.74 loop law). A FAILED arm is
//!   honest too: the machine stays armed and the host retries at the
//!   next tick, it never fakes the arm.
//! - the boot-time stale road: a flag naming a DEAD successor tears
//!   immediately and boots full — the same reclaim law, entered from
//!   `Born` before the mesh even attaches.
//! - the reclaim law: the successor's presence went stale — tear the
//!   flag, boot full (the re-exec without the mark). The holdouts
//!   come home through the failover ladder.
//! - a flag that vanished means the holdouts came HOME: the worker
//!   retires (`FlagGone`) — and fork-once means the operator's kill
//!   retires it too (`WorkerKilled`), from any live state.
//!
//! The handlers are pure: they read and write only this machine's
//! own storage — no tokio, no socket, no clock.

use super::{Refusal, RefusalReason, Role, RunId, StateMachine, harness};
use statig::prelude::*;

/// Where the worker stands.
#[derive(Clone, Copy, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize)]
pub enum HoldoutState {
    /// The mark was inherited (the fork child) or a standing flag was
    /// found (the supervisor-restart road); nothing loaded yet.
    Born,
    /// The scoped reload finished: holdout apps only, no deploy
    /// watch, no public port.
    Scoped,
    /// The mesh endpoint is up (`mesh on as <id>`).
    MeshAttached,
    /// The ride-home is armed at the flag's successor; a provider
    /// miss rides.
    Armed,
    /// The successor's presence went stale (or the boot found a dead
    /// successor's flag): the flag is being torn up and this boot
    /// returns full.
    Reclaiming,
    /// Terminal: the reclaim landed, this node is full again.
    Full,
    /// Terminal: the flag vanished (the holdouts came home) or the
    /// operator killed this worker (fork-once retirement).
    Retired,
}

impl HoldoutState {
    pub const fn born() -> Self {
        Self::Born
    }
    pub const fn scoped() -> Self {
        Self::Scoped
    }
    pub const fn mesh_attached() -> Self {
        Self::MeshAttached
    }
    pub const fn armed() -> Self {
        Self::Armed
    }
    pub const fn reclaiming() -> Self {
        Self::Reclaiming
    }
    pub const fn full() -> Self {
        Self::Full
    }
    pub const fn retired() -> Self {
        Self::Retired
    }
}

/// What the world told the worker.
#[derive(Clone, Copy, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize)]
pub enum HoldoutEvent {
    /// The fork's child inherited `WISOLATE_HOLDOUT_WORKER=1` (the
    /// mark rides the ENV, 0.2.73 — not the argv).
    MarkInherited,
    /// The boot found a standing flag (the supervisor-restart road:
    /// the plain boot becomes the scoped worker).
    FlagFound,
    /// The scoped reload finished (holdout apps only).
    ScopedLoadDone,
    /// The mesh endpoint attached (`mesh on as <id>`).
    MeshOn,
    /// The watch's tick read the flag's successor (first arm).
    FlagSuccessorKnown,
    /// The flag names a NEW successor (re-arm at the new home).
    FlagSuccessorChanged,
    /// The ride-home chain is 23 h into its 24 h mint (refresh).
    ChainRefreshDue,
    /// The arm attempt FAILED (the endpoint key did not read, the
    /// successor's spec did not parse): honest — the machine stays,
    /// the host retries at the next tick.
    ArmRideHomeFailed,
    /// A binding's provider is not live HERE (env.AI on the worker).
    BindingProviderMiss,
    /// The successor's presence went stale (it died without handing
    /// over) — the reclaim trigger. Also lawful at `Born`: a flag
    /// naming a dead successor tears at boot, before the mesh even
    /// attaches.
    SuccessorPresenceStale,
    /// The flag is torn up (the tear landed).
    FlagTorn,
    /// The re-exec boots full (the reclaim's second half).
    BootFullComplete,
    /// The flag vanished — the holdouts came home (a release whose
    /// ladder moved everything); the worker retires.
    FlagGone,
    /// This worker lost its job — the operator killed the process
    /// (fork-once retirement), or the flag's worker_pid moved to a
    /// newer boot (the re-exec claimed the identity; ONE worker per
    /// identity serves the holdouts).
    WorkerKilled,
}

/// What the host owes when an arm fires.
#[derive(Clone, Copy, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize)]
pub enum HoldoutAction {
    /// Arm the ride-home at the flag's successor: name the home,
    /// self-mint the one-hop chain from this node's endpoint key
    /// (the fork shares the releaser's key — identity continuity).
    ArmRideHome,
    /// Ride the binding home: carry the exchange over the mesh to
    /// the armed home and return the reply bytes (0.2.74).
    RideHome,
    /// Tear the flag up (the reclaim's first half).
    TearFlag,
    /// Boot full (the reclaim's second half: the re-exec without the
    /// mark).
    BootFull,
}

/// The machine's own storage. FLAT — no state carries state-local
/// data.
#[derive(Debug)]
pub struct Holdout {
    run: RunId,
    epoch: u64,
    /// The actions the host owes from the LAST dispatch; `step`
    /// drains it.
    owed: Vec<HoldoutAction>,
    /// The refusal this machine's law last handed down, stamped with
    /// a monotonic counter. The machine REPORTS here (its own plain
    /// storage write — no statig accessor); the wrapper BOOKS: after
    /// every dispatch it copies the report out when the counter
    /// advances and files it in its own bounded book. The monotonic
    /// stamp means a stale report can never replay.
    report_seq: u64,
    report: Option<Refusal<HoldoutState, HoldoutEvent>>,
}

impl Holdout {
    fn fresh(run: RunId) -> Self {
        Self {
            run,
            epoch: 0,
            owed: Vec::new(),
            report_seq: 0,
            report: None,
        }
    }

    /// Why this pair was refused: a terminal state refuses as
    /// Terminal, everything else as IllegalTransition.
    fn refuse(&mut self, state: HoldoutState, event: &HoldoutEvent) -> Outcome<HoldoutState> {
        let reason = if Self::terminal(state) {
            RefusalReason::Terminal
        } else {
            RefusalReason::IllegalTransition
        };
        self.report_seq += 1;
        self.report = Some(Refusal {
            state,
            event: *event,
            epoch: self.epoch,
            reason,
        });
        Handled
    }

    const fn terminal(state: HoldoutState) -> bool {
        matches!(state, HoldoutState::Full | HoldoutState::Retired)
    }

    /// The reclaim: the successor cannot serve its holdouts any
    /// more — tear the flag and boot full. The boot-time road (the
    /// flag named a dead successor before anything attached) rides
    /// the same law.
    fn reclaim(&mut self) -> Outcome<HoldoutState> {
        self.owed.push(HoldoutAction::TearFlag);
        Transition(HoldoutState::reclaiming())
    }
}

#[state_machine(initial = "HoldoutState::born()", state(custom, name = "HoldoutState"))]
impl Holdout {
    #[state]
    fn born(&mut self, event: &HoldoutEvent) -> Outcome<HoldoutState> {
        match event {
            // The mark and the flag are boot facts: recorded by
            // staying put, owed nothing.
            HoldoutEvent::MarkInherited | HoldoutEvent::FlagFound => Handled,
            HoldoutEvent::ScopedLoadDone => Transition(HoldoutState::scoped()),
            // Boot-time stale: the flag names a DEAD successor — the
            // reclaim starts before the mesh even attaches.
            HoldoutEvent::SuccessorPresenceStale => self.reclaim(),
            HoldoutEvent::WorkerKilled => Transition(HoldoutState::retired()),
            _ => self.refuse(HoldoutState::Born, event),
        }
    }

    #[state]
    fn scoped(&mut self, event: &HoldoutEvent) -> Outcome<HoldoutState> {
        match event {
            HoldoutEvent::MeshOn => Transition(HoldoutState::mesh_attached()),
            HoldoutEvent::SuccessorPresenceStale => self.reclaim(),
            HoldoutEvent::FlagGone => Transition(HoldoutState::retired()),
            HoldoutEvent::WorkerKilled => Transition(HoldoutState::retired()),
            _ => self.refuse(HoldoutState::Scoped, event),
        }
    }

    #[state]
    fn mesh_attached(&mut self, event: &HoldoutEvent) -> Outcome<HoldoutState> {
        match event {
            HoldoutEvent::FlagSuccessorKnown => {
                self.owed.push(HoldoutAction::ArmRideHome);
                Transition(HoldoutState::armed())
            }
            // The loop law (0.2.74): NOT armed yet — the host answers
            // the miss honestly, a genuine not-live. Riding early
            // would loop.
            HoldoutEvent::BindingProviderMiss => Handled,
            HoldoutEvent::SuccessorPresenceStale => self.reclaim(),
            HoldoutEvent::FlagGone => Transition(HoldoutState::retired()),
            HoldoutEvent::WorkerKilled => Transition(HoldoutState::retired()),
            _ => self.refuse(HoldoutState::MeshAttached, event),
        }
    }

    #[state]
    fn armed(&mut self, event: &HoldoutEvent) -> Outcome<HoldoutState> {
        match event {
            HoldoutEvent::FlagSuccessorChanged => {
                self.owed.push(HoldoutAction::ArmRideHome);
                Handled
            }
            HoldoutEvent::ChainRefreshDue => {
                self.owed.push(HoldoutAction::ArmRideHome);
                Handled
            }
            HoldoutEvent::BindingProviderMiss => {
                self.owed.push(HoldoutAction::RideHome);
                Handled
            }
            // The arm failed honestly: stay armed, the host retries
            // at the next tick — never fake the arm.
            HoldoutEvent::ArmRideHomeFailed => Handled,
            HoldoutEvent::SuccessorPresenceStale => self.reclaim(),
            HoldoutEvent::FlagGone => Transition(HoldoutState::retired()),
            HoldoutEvent::WorkerKilled => Transition(HoldoutState::retired()),
            _ => self.refuse(HoldoutState::Armed, event),
        }
    }

    #[state]
    fn reclaiming(&mut self, event: &HoldoutEvent) -> Outcome<HoldoutState> {
        match event {
            HoldoutEvent::FlagTorn => {
                self.owed.push(HoldoutAction::BootFull);
                Handled
            }
            HoldoutEvent::BootFullComplete => Transition(HoldoutState::full()),
            _ => self.refuse(HoldoutState::Reclaiming, event),
        }
    }

    #[state]
    fn full(&mut self, event: &HoldoutEvent) -> Outcome<HoldoutState> {
        // Terminal: the harness's gate refuses first; this arm is
        // the law's own answer if an event ever reaches it.
        self.refuse(HoldoutState::Full, event)
    }

    #[state]
    fn retired(&mut self, event: &HoldoutEvent) -> Outcome<HoldoutState> {
        self.refuse(HoldoutState::Retired, event)
    }
}

harness! {
    HoldoutMachine, Holdout,
    state = HoldoutState, event = HoldoutEvent, action = HoldoutAction,
    terminal = Holdout::terminal, role: Role = Role::Holdout,
    events = [
        HoldoutEvent::MarkInherited,
        HoldoutEvent::FlagFound,
        HoldoutEvent::ScopedLoadDone,
        HoldoutEvent::MeshOn,
        HoldoutEvent::FlagSuccessorKnown,
        HoldoutEvent::FlagSuccessorChanged,
        HoldoutEvent::ChainRefreshDue,
        HoldoutEvent::ArmRideHomeFailed,
        HoldoutEvent::BindingProviderMiss,
        HoldoutEvent::SuccessorPresenceStale,
        HoldoutEvent::FlagTorn,
        HoldoutEvent::BootFullComplete,
        HoldoutEvent::FlagGone,
        HoldoutEvent::WorkerKilled,
    ],
}
