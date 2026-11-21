//! The predecessor machine: the serving node that adopts a staged
//! release and hands the port over.
//!
//! The law is statig-defined, encoding the prod ladder EXACTLY as
//! prod runs it (ladders 5 through 12, SPEC 0.2.38/0.2.48/0.2.73):
//!
//! - the drain posture starts WHEN THE PIPELINE DOES (owner
//!   directive): [`StartDrain`] is owed at launch, not at the marker;
//!   the fleet is told at once and idle apps shed while the twin
//!   takes. The blue-green soak (`SoakLaunched`) does NOT drain — the
//!   predecessor keeps the port and serves beside the twin.
//! - a twin that dies BEFORE the port leaves this node never takes
//!   the apps with it: [`SuccessorDied`] is a rollback (0.2.38) from
//!   every holding state — pipeline, cutover-confirmed, draining,
//!   control-kept — and the epoch bumps, so the dead generation's
//!   ghosts (a late marker, a stale launch notice) are REFUSED, not
//!   applied.
//! - a death INSIDE the release grace is a rollback, not a promotion
//!   onto a corpse: [`GraceElapsed`] moves to draining owed
//!   [`VerifySuccessorAlive`] FIRST, and only [`SuccessorHealthy`]
//!   opens the settle.
//! - the settle (fork fresh workers vs follow a live one — fork-once,
//!   0.2.73) is the HOST's policy; the machine demands only that the
//!   holdout question is answered before the port is released, and
//!   the answer names the road: [`HoldoutsReleased`] pays
//!   [`ReleasePort`] then [`RequestWantsShutdown`] in order;
//!   [`ControlKept`] owes [`SuperviseSuccessor`] — control stayed
//!   here, so the twin's death is still this node's problem.
//!
//! The handlers are pure: they read and write only this machine's
//! storage (run, epoch, owed, refusals) — no tokio, no socket, no
//! clock, no process.

use super::{Refusal, RefusalReason, Role, RunId, StateMachine, harness};
use statig::prelude::*;

/// Where the releaser stands.
#[derive(Clone, Copy, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize)]
pub enum PredecessorState {
    /// Steady: holding the public port, watching the staged path.
    Serving,
    /// The staged bytes were adopted; the twin is launched and the
    /// cutover marker is watched. Draining (the posture began at
    /// launch).
    PipelineStarted,
    /// The blue-green soak: the twin runs for compute only — no
    /// marker is coming, the port stays here. NOT draining.
    Soaking,
    /// The twin's marker is in (CUTOVER CONFIRMED); the grace runs.
    CutoverConfirmed,
    /// Grace elapsed: the twin is verified alive, the holdout
    /// question is settled, then the port is released.
    Draining,
    /// The port is released and `wants_shutdown` is requested; the
    /// process is on its way out.
    Released,
    /// Terminal: the exit landed. Nothing moves this machine.
    Done,
}

impl PredecessorState {
    pub const fn serving() -> Self {
        Self::Serving
    }
    pub const fn pipeline_started() -> Self {
        Self::PipelineStarted
    }
    pub const fn soaking() -> Self {
        Self::Soaking
    }
    pub const fn cutover_confirmed() -> Self {
        Self::CutoverConfirmed
    }
    pub const fn draining() -> Self {
        Self::Draining
    }
    pub const fn released() -> Self {
        Self::Released
    }
    pub const fn done() -> Self {
        Self::Done
    }
}

/// What the world told the releaser. Every variant is a FACT — fed
/// only after the thing already happened (the rename landed, the
/// spawn landed, the marker exists); the machine's actions are what
/// the host still owes BECAUSE of the fact.
#[derive(Clone, Copy, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize)]
pub enum PredecessorEvent {
    /// The staged bytes were adopted: renamed over this binary (the
    /// running inode is unaffected; the spawn and every later plain
    /// start resolve the NEW bytes).
    StagedReleaseAdopted,
    /// The twin launched for a blue-green soak (compute_only): it
    /// supervises forwarded compute, no marker is coming.
    SoakLaunched,
    /// The twin launched for the ladder: it will name itself at
    /// bootstrap and write the cutover marker when the read-back
    /// confirms this node holds nothing.
    SuccessorLaunched,
    /// The twin's cutover marker is in (CUTOVER CONFIRMED).
    CutoverMarkerIn,
    /// The drain grace ended.
    GraceElapsed,
    /// The twin answered the alive probe after the grace.
    SuccessorHealthy,
    /// The twin exited while this node still held control — before
    /// the marker, inside the grace, or after a control-kept settle.
    /// The rollback trigger (0.2.38).
    SuccessorDied,
    /// The holdout question was settled with the port leaving:
    /// holdouts released (forked or followed) or there were none and
    /// retire was accepted. The release decision is the HOST's
    /// (fork-once policy, retire request); the machine only demands
    /// the question is settled.
    HoldoutsReleased,
    /// The settle kept control here: the flag write failed, no data
    /// dir, or retire was declined — promote the successor by hand.
    /// The twin's death is still this node's problem.
    ControlKept,
    /// `wants_shutdown` was honored; the process is exiting.
    Exited,
}

/// What the host owes when an arm fires.
#[derive(Clone, Copy, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize)]
pub enum PredecessorAction {
    /// Arm the cutover-marker watch (the release trigger).
    WatchCutoverMarker,
    /// Open the drain posture NOW (launch-time, not marker-time):
    /// no new admissions, the fleet is told at once, idle apps shed.
    /// A rollback un-drains.
    StartDrain,
    /// Supervise the twin without a ladder (the soak road: its death
    /// rolls the forwarded compute back here).
    SuperviseSuccessor,
    /// Run the drain grace (the successor's final announcements and
    /// its take_port bind get a window before the release).
    StartGrace,
    /// Probe the twin before settling: a death inside the grace is a
    /// rollback, not a promotion onto a corpse.
    VerifySuccessorAlive,
    /// Settle the holdout question: fork fresh workers for the
    /// holdout set, follow a live worker (fork-once), or tear a
    /// standing flag when no holdouts ride this ladder. The HOST
    /// decides which road; the machine demands the answer before the
    /// port is released.
    SettleHoldouts,
    /// Drop the public listener; the successor's retry-bind catches
    /// the port (new connections flow with no listener gap).
    ReleasePort,
    /// Ask the supervisor for shutdown (`wants_shutdown`); MAINPID
    /// already moved (0.2.73), the exit is a non-event for systemd.
    RequestWantsShutdown,
    /// Tear the pipeline down and roll back: the drain posture is
    /// undone (the apps come home), every forward at the dead twin
    /// is un-forwarded, the placement is re-announced, the pipeline
    /// latch opens so a retry can run. The failure is REPORTED.
    TearUpPipeline,
    /// Roll the soak back: the forwarded compute returns, the drain
    /// posture never changed (a soak never drained).
    RollbackSoak,
}

/// The machine's own storage: everything the law needs. FLAT — no
/// state carries state-local storage, so placement (the wrapper
/// rebuilding the machine before statig's initialization window
/// closes) is exact and the crate carries NO unsafe.
#[derive(Debug)]
pub struct Predecessor {
    run: RunId,
    epoch: u64,
    /// The actions the host owes from the LAST dispatch; `step`
    /// drains it.
    owed: Vec<PredecessorAction>,
    /// The refusal this machine's law last handed down, stamped with
    /// a monotonic counter. The machine REPORTS here (its own plain
    /// storage write — no statig accessor); the wrapper BOOKS: after
    /// every dispatch it copies the report out when the counter
    /// advances and files it in its own bounded book. The monotonic
    /// stamp means a stale report can never replay.
    report_seq: u64,
    report: Option<Refusal<PredecessorState, PredecessorEvent>>,
}

impl Predecessor {
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
    fn refuse(
        &mut self,
        state: PredecessorState,
        event: &PredecessorEvent,
    ) -> Outcome<PredecessorState> {
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
        statig::Outcome::Handled
    }

    const fn terminal(state: PredecessorState) -> bool {
        matches!(state, PredecessorState::Done)
    }

    /// The rollback (0.2.38): a twin that died while this node held
    /// control takes NOTHING with it. The pipeline tears up, the node
    /// serves on — and the epoch bumps, so the dead generation's
    /// ghosts are refused from here on.
    fn rollback(&mut self) -> statig::Outcome<PredecessorState> {
        self.epoch += 1;
        self.owed.push(PredecessorAction::TearUpPipeline);
        statig::Outcome::Transition(PredecessorState::serving())
    }
}

#[state_machine(
    initial = "PredecessorState::serving()",
    state(custom, name = "PredecessorState")
)]
impl Predecessor {
    #[state]
    fn serving(&mut self, event: &PredecessorEvent) -> Outcome<PredecessorState> {
        match event {
            PredecessorEvent::StagedReleaseAdopted => {
                Transition(PredecessorState::pipeline_started())
            }
            PredecessorEvent::SoakLaunched => {
                // Blue-green soak: supervise the twin's compute, no
                // marker watch, NO drain — the port stays here.
                self.owed.push(PredecessorAction::SuperviseSuccessor);
                Transition(PredecessorState::soaking())
            }
            PredecessorEvent::SuccessorLaunched => {
                // The straight ladder: the launch itself starts the
                // pipeline — watch for the twin's marker and drain at
                // once (idle apps shed while the twin takes). The same
                // posture `pipeline_started` holds; this arm is its
                // ENTRY from a plain serving predecessor.
                self.owed.push(PredecessorAction::WatchCutoverMarker);
                self.owed.push(PredecessorAction::StartDrain);
                Transition(PredecessorState::pipeline_started())
            }
            _ => self.refuse(PredecessorState::Serving, event),
        }
    }

    #[state]
    fn pipeline_started(&mut self, event: &PredecessorEvent) -> Outcome<PredecessorState> {
        match event {
            // The adoption landed and the host picked the blue-green
            // soak road instead of the ladder: supervise the twin's
            // compute. A soak NEVER drains, wherever it starts from.
            PredecessorEvent::SoakLaunched => {
                self.owed.push(PredecessorAction::SuperviseSuccessor);
                Transition(PredecessorState::soaking())
            }
            PredecessorEvent::SuccessorLaunched => {
                // The ladder posture: the marker is the release
                // trigger, and the drain began AT LAUNCH — the fleet
                // is told at once, idle apps shed while the twin
                // takes.
                self.owed.push(PredecessorAction::WatchCutoverMarker);
                self.owed.push(PredecessorAction::StartDrain);
                statig::Outcome::Handled
            }
            PredecessorEvent::CutoverMarkerIn => {
                self.owed.push(PredecessorAction::StartGrace);
                Transition(PredecessorState::cutover_confirmed())
            }
            PredecessorEvent::SuccessorDied => self.rollback(),
            _ => self.refuse(PredecessorState::PipelineStarted, event),
        }
    }

    #[state]
    fn soaking(&mut self, event: &PredecessorEvent) -> Outcome<PredecessorState> {
        match event {
            // The soak never drained: the compute rolls back and the
            // posture never changed.
            PredecessorEvent::SuccessorDied => {
                self.epoch += 1;
                self.owed.push(PredecessorAction::RollbackSoak);
                Transition(PredecessorState::serving())
            }
            _ => self.refuse(PredecessorState::Soaking, event),
        }
    }

    #[state]
    fn cutover_confirmed(&mut self, event: &PredecessorEvent) -> Outcome<PredecessorState> {
        match event {
            PredecessorEvent::GraceElapsed => {
                // The grace ran; before ANY settle the twin must prove
                // it still lives — the alive probe moves BEFORE the
                // settle, the promotion-on-a-corpse edge the old
                // engine guarded inline.
                self.owed.push(PredecessorAction::VerifySuccessorAlive);
                Transition(PredecessorState::draining())
            }
            PredecessorEvent::SuccessorDied => self.rollback(),
            _ => self.refuse(PredecessorState::CutoverConfirmed, event),
        }
    }

    #[state]
    fn draining(&mut self, event: &PredecessorEvent) -> Outcome<PredecessorState> {
        match event {
            PredecessorEvent::SuccessorHealthy => {
                // Alive: settle the holdout question. The host picks
                // the road (fork fresh, follow live, or none); the
                // machine waits for the ANSWER.
                self.owed.push(PredecessorAction::SettleHoldouts);
                statig::Outcome::Handled
            }
            // A death at ANY point before the port leaves — the
            // probe's answer, or a fall after a control-kept settle —
            // is a rollback.
            PredecessorEvent::SuccessorDied => self.rollback(),
            PredecessorEvent::HoldoutsReleased => {
                // The port leaves THIS node: the release
                // announcement, then the shutdown ask — MAINPID
                // already moved (0.2.73), the exit is a non-event.
                self.owed.push(PredecessorAction::ReleasePort);
                self.owed.push(PredecessorAction::RequestWantsShutdown);
                Transition(PredecessorState::released())
            }
            PredecessorEvent::ControlKept => {
                // Control stayed here (flag write failed, no data
                // dir, retire declined): promote by hand — and keep
                // supervising, the twin's death is still ours.
                self.owed.push(PredecessorAction::SuperviseSuccessor);
                statig::Outcome::Handled
            }
            _ => self.refuse(PredecessorState::Draining, event),
        }
    }

    #[state]
    fn released(&mut self, event: &PredecessorEvent) -> Outcome<PredecessorState> {
        match event {
            PredecessorEvent::Exited => Transition(PredecessorState::done()),
            _ => self.refuse(PredecessorState::Released, event),
        }
    }

    #[state]
    fn done(&mut self, event: &PredecessorEvent) -> Outcome<PredecessorState> {
        // Terminal: the harness's gate refuses first; this arm is
        // the law's own answer if an event ever reaches it.
        self.refuse(PredecessorState::Done, event)
    }
}

harness! {
    PredecessorMachine, Predecessor,
    state = PredecessorState, event = PredecessorEvent, action = PredecessorAction,
    terminal = Predecessor::terminal, role: Role = Role::Predecessor,
    events = [
        PredecessorEvent::StagedReleaseAdopted,
        PredecessorEvent::SoakLaunched,
        PredecessorEvent::SuccessorLaunched,
        PredecessorEvent::CutoverMarkerIn,
        PredecessorEvent::GraceElapsed,
        PredecessorEvent::SuccessorHealthy,
        PredecessorEvent::SuccessorDied,
        PredecessorEvent::HoldoutsReleased,
        PredecessorEvent::ControlKept,
        PredecessorEvent::Exited,
    ],
}
