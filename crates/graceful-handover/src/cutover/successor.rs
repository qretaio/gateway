//! The successor machine: the cutover twin that takes the movable
//! apps, announces MAINPID at CUTOVER READY, and lands the ingress.
//!
//! The law is statig-defined, encoding the prod take EXACTLY as prod
//! runs it (ladders 5 through 12, SPEC 0.2.36/0.2.73): the bootstrap
//! names the twin, the exchange mints the ladder credential to this
//! node's own key, the take loop moves leases and apps one by one,
//! and at ALL-MOVABLE-MOVED the twin announces CUTOVER READY and
//! moves the supervisor's anchor TOGETHER (0.2.73, prod ladder #9:
//! announcing at the port landing lost a race — the release with
//! every lease already taken finishes in milliseconds, the
//! predecessor's exit beat the take loop, systemd read the MAINPID
//! death as a service death and SIGTERMed this twin). A refused
//! MAINPID anchor is guidance, not a state change: the supervisor's
//! restart road (the reclaim) still serves.
//!
//! The handlers are pure: they read and write only this machine's
//! own storage — no tokio, no socket, no clock.

use super::{Refusal, RefusalReason, Role, RunId, StateMachine, harness};
use statig::prelude::*;

/// Where the taker stands.
#[derive(Clone, Copy, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize)]
pub enum SuccessorState {
    /// Spawned; not yet named itself at bootstrap.
    Pending,
    /// The bootstrap exchange completed: the ladder credential is
    /// minted to this node's own key.
    Exchanged,
    /// The ladder runs: leases and movable apps moving here.
    Taking,
    /// CUTOVER READY: every movable app runs here, the predecessor
    /// holds only the holdout set. MAINPID was announced (0.2.73).
    CutoverReady,
    /// Terminal: the port handover landed — this node is the ingress,
    /// the fleet is one node again.
    Full,
}

impl SuccessorState {
    pub const fn pending() -> Self {
        Self::Pending
    }
    pub const fn exchanged() -> Self {
        Self::Exchanged
    }
    pub const fn taking() -> Self {
        Self::Taking
    }
    pub const fn cutover_ready() -> Self {
        Self::CutoverReady
    }
    pub const fn full() -> Self {
        Self::Full
    }
}

/// What the world told the taker.
#[derive(Clone, Copy, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize)]
pub enum SuccessorEvent {
    /// This node named itself at bootstrap (the twin announces its
    /// identity before the exchange).
    NamedItself,
    /// The bootstrap exchange completed (grant traded for the ladder
    /// credential).
    BootstrapExchangeComplete,
    /// The take loop armed (leases, apps, wheels).
    LadderStarted,
    /// One lease moved (progress; no actions owed).
    LeaseTaken,
    /// One app moved (progress; no actions owed).
    AppMoved,
    /// Every movable app runs here (CUTOVER READY).
    AllMovableMoved,
    /// The supervisor accepted the MAINPID anchor.
    MainPidAccepted,
    /// The port handover landed on the public address.
    PortLanded,
}

/// What the host owes when an arm fires.
#[derive(Clone, Copy, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize)]
pub enum SuccessorAction {
    /// Announce CUTOVER READY (the marker the predecessor watches).
    AnnounceCutoverReady,
    /// Announce MAINPID to the supervisor AT READY — the anchor
    /// moves while this node holds every movable app, so the
    /// predecessor's exit can never read as a service death
    /// (0.2.73).
    AnnounceMainPid,
}

/// The machine's own storage. FLAT — no state carries state-local
/// data, so the wrapper's before-init placement is exact and the
/// crate carries NO unsafe.
#[derive(Debug)]
pub struct Successor {
    run: RunId,
    epoch: u64,
    /// The actions the host owes from the LAST dispatch; `step`
    /// drains it.
    owed: Vec<SuccessorAction>,
    /// The refusal this machine's law last handed down, stamped with
    /// a monotonic counter. The machine REPORTS here (its own plain
    /// storage write — no statig accessor); the wrapper BOOKS: after
    /// every dispatch it copies the report out when the counter
    /// advances and files it in its own bounded book. The monotonic
    /// stamp means a stale report can never replay.
    report_seq: u64,
    report: Option<Refusal<SuccessorState, SuccessorEvent>>,
}

impl Successor {
    fn fresh(run: RunId) -> Self {
        Self {
            run,
            epoch: 0,
            owed: Vec::new(),
            report_seq: 0,
            report: None,
        }
    }

    fn refuse(&mut self, state: SuccessorState, event: &SuccessorEvent) -> Outcome<SuccessorState> {
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

    const fn terminal(state: SuccessorState) -> bool {
        matches!(state, SuccessorState::Full)
    }
}

#[state_machine(
    initial = "SuccessorState::pending()",
    state(custom, name = "SuccessorState")
)]
impl Successor {
    #[state]
    fn pending(&mut self, event: &SuccessorEvent) -> Outcome<SuccessorState> {
        match event {
            SuccessorEvent::NamedItself => Handled,
            SuccessorEvent::BootstrapExchangeComplete => Transition(SuccessorState::exchanged()),
            _ => self.refuse(SuccessorState::Pending, event),
        }
    }

    #[state]
    fn exchanged(&mut self, event: &SuccessorEvent) -> Outcome<SuccessorState> {
        match event {
            SuccessorEvent::LadderStarted => Transition(SuccessorState::taking()),
            _ => self.refuse(SuccessorState::Exchanged, event),
        }
    }

    #[state]
    fn taking(&mut self, event: &SuccessorEvent) -> Outcome<SuccessorState> {
        match event {
            // Progress events: the take loop advances, the law owes
            // nothing for them.
            SuccessorEvent::LeaseTaken | SuccessorEvent::AppMoved => Handled,
            SuccessorEvent::AllMovableMoved => {
                // CUTOVER READY: the two announcements of 0.2.73 in
                // order — the marker first, MAINPID right behind it.
                self.owed.push(SuccessorAction::AnnounceCutoverReady);
                self.owed.push(SuccessorAction::AnnounceMainPid);
                Transition(SuccessorState::cutover_ready())
            }
            _ => self.refuse(SuccessorState::Taking, event),
        }
    }

    #[state]
    fn cutover_ready(&mut self, event: &SuccessorEvent) -> Outcome<SuccessorState> {
        match event {
            // A refused MAINPID anchor is guidance: the supervisor's
            // restart road still serves, the ladder keeps walking.
            SuccessorEvent::MainPidAccepted => Handled,
            SuccessorEvent::PortLanded => Transition(SuccessorState::full()),
            _ => self.refuse(SuccessorState::CutoverReady, event),
        }
    }

    #[state]
    fn full(&mut self, event: &SuccessorEvent) -> Outcome<SuccessorState> {
        // Terminal: the harness's gate refuses first; this arm is
        // the law's own answer if an event ever reaches it.
        self.refuse(SuccessorState::Full, event)
    }
}

harness! {
    SuccessorMachine, Successor,
    state = SuccessorState, event = SuccessorEvent, action = SuccessorAction,
    terminal = Successor::terminal, role: Role = Role::Successor,
    events = [
        SuccessorEvent::NamedItself,
        SuccessorEvent::BootstrapExchangeComplete,
        SuccessorEvent::LadderStarted,
        SuccessorEvent::LeaseTaken,
        SuccessorEvent::AppMoved,
        SuccessorEvent::AllMovableMoved,
        SuccessorEvent::MainPidAccepted,
        SuccessorEvent::PortLanded,
    ],
}
