//! The sans-I/O harness every control machine in the fleet hangs on.
//!
//! Lineage: extracted from wisolate's cutover crate (owner directive
//! 2026-11-07: "carve out reusable piece ... The crate should be a
//! sans Io state machine"), lived as wisolate's `crates/sansio`, and
//! moved to this standalone workspace (`~/src/fsm`) once the k8s
//! plane stamped its first machine — three citizens is where a
//! cross-repo law needs its own roof. The contract is unchanged:
//! TOTAL on every (state, event) pair, PURE handlers, FENCED runs,
//! the bounded refusal book, and the no-unsafe report/book wrapper
//! the [`harness!`] macro generates.
//!
//! Citizens: cutover (the failover machines, `~/src/qretaio/wisolate`),
//! scheduler (the scheduled loops, same workspace), and the k8s
//! coordinator's sweep (`~/src/q8s`) — its conformance battery is the
//! scheduler's law ported. More machines are expected: this is where
//! the next one stamps.
//!
//! A machine crate defines its state/event/action enums plus the
//! statig `#[state]` handlers, then stamps the host-facing harness
//! with one [`harness!`] row. The host feeds events, performs owed
//! actions, and reads no machine internals beyond the trait doors.

// The `expr` matcher in `harness!` keeps its 2021 breadth on purpose:
// machine crates stamp roles as plain paths
// (`role: Role = Role::Coordinator`).
#![allow(rust_2024_compatibility)]

use std::fmt;

// The wrapper the [`harness!`] macro stamps carries statig's
// initialized machine, so this crate owns the statig integration: the
// macro's `$crate::statig` path resolves HERE (one version, one
// source), and the consumer needs statig only for its own
// `#[state_machine]` storage definitions.
pub use statig;

/// One failover run's identity. Ladders overlap in practice (a
/// successor booting while a predecessor still drains, a fork while a
/// release is mid-flight); every machine instance is fenced to ONE
/// run: events carrying another run's id are refused, not applied.
/// The refusal book's cap (see [`StateMachine::MAX_REFUSALS`]): the
/// last entries are kept, the oldest dropped, the dropped count
/// honest.
pub const REFUSAL_BOOK_CAP: usize = 256;

#[derive(
    Clone, Copy, PartialEq, Eq, Hash, Debug, Default, serde::Serialize, serde::Deserialize,
)]
pub struct RunId(pub u64);

/// The pluggable message: any transport carries these. `R` is the
/// addressing vocabulary — THE CRATE NAMES NO ROLES: the fleet does
/// (owner directive 2026-11-07: a role enum here would prove the
/// harness not generic). `K` is the machine's event alphabet, `P`
/// the host's own payload — the crate never looks inside `P`. An old
/// peer that cannot decode a `K` fails that ONE message honestly;
/// nothing about the envelope is fixed except the fields named here.
#[derive(Clone, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize)]
pub struct Message<R, K, P> {
    pub run: RunId,
    pub epoch: u64,
    pub from: R,
    pub to: R,
    /// The machine-facing kind: which event this delivery carries.
    pub kind: K,
    /// The transport-facing payload: bytes, a fd, a path — host's
    /// choice.
    pub payload: P,
}

impl<R: fmt::Debug, K: fmt::Display, P> fmt::Display for Message<R, K, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "run {:?} epoch {} {:?} to {:?}: {}",
            self.run, self.epoch, self.from, self.to, self.kind
        )
    }
}

/// An event arriving under its run's fence. The epoch is the run's
/// generation: a machine bumps it when its flow explicitly re-bases
/// (a reclaim, a rollback that restarts the ladder); anything carrying
/// an older epoch is a ghost from a superseded generation and is
/// refused.
#[derive(Clone, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize)]
pub struct RunEvent<E> {
    pub epoch: u64,
    pub event: E,
}

impl<E> RunEvent<E> {
    pub fn new(epoch: u64, event: E) -> Self {
        Self { epoch, event }
    }
}

/// Why an event was refused. Recorded, never swallowed: the host can
/// log, count, and alert on refusals — a rising refusal rate IS the
/// signal that the world disagrees with the law.
#[derive(Clone, Copy, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize)]
pub enum RefusalReason {
    /// No arm of the current state's handler names this event. The
    /// pair is illegal; state is unchanged, no actions are owed.
    IllegalTransition,
    /// The event carried an epoch the machine has superseded.
    StaleEpoch,
    /// The event carried another run's id — a ghost from a pipeline
    /// this machine instance does not fence.
    ForeignRun,
    /// The machine is in a terminal state; nothing moves it.
    Terminal,
}

/// A refused (state, event) pair, kept for the host's inspection.
#[derive(Clone, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize)]
pub struct Refusal<S, E> {
    pub state: S,
    pub event: E,
    pub epoch: u64,
    pub reason: RefusalReason,
}

/// The harness every machine hangs on — the contract layer on top of
/// the statig-defined flow. The contract:
///
/// - TOTAL: [`StateMachine::on_event`] answers a defined outcome on
///   every pair. A terminal machine refuses everything (no actions, no
///   move, one [`Refusal`] with [`RefusalReason::Terminal`]); a legal
///   pair applies its arm (state moves, actions owed in order); an
///   illegal pair records [`RefusalReason::IllegalTransition`] and
///   changes nothing.
/// - PURE: the handlers behind [`StateMachine::step`] perform no I/O
///   and read nothing but the machine's own storage.
/// - FENCED: [`StateMachine::on_run_event`] refuses stale epochs
///   (the fence is EXACT: an event carries this machine's epoch
///   or it is refused — older AND newer are both ghosts)
///   before the law is consulted; [`StateMachine::on_message`] adds
///   the run fence and the role check.
pub trait StateMachine: fmt::Debug + Sized {
    type State: Clone + Copy + PartialEq + Eq + fmt::Debug + 'static;
    type Event: Clone + PartialEq + Eq + fmt::Debug + 'static;
    type Action: Clone + PartialEq + Eq + fmt::Debug + 'static;

    /// Every event the vocabulary names, once each. The completeness
    /// gate: the tests match this list EXHAUSTIVELY (no `_` arm), so
    /// a new variant cannot slip past — the compiler forces the list
    /// to grow with the enum.
    const ALL_EVENTS: &'static [Self::Event];

    /// The role this machine speaks as — the crate's own addressing
    /// type (the harness names none). The [`StateMachine::on_message`]
    /// door drops anything addressed elsewhere; the transport may
    /// route, the machine verifies.
    type Role: Copy + PartialEq + Eq + std::hash::Hash + fmt::Debug;
    const ROLE: Self::Role;

    /// A machine for one run, at its initial epoch and state. The
    /// generic door — a concrete machine's inherent `new` has the
    /// same name and takes precedence at concrete call sites; this
    /// one exists so generic code (the probes, the fuzz) can build
    /// any machine.
    fn for_run(run: RunId) -> Self;

    fn run(&self) -> RunId;
    fn state(&self) -> Self::State;
    fn epoch(&self) -> u64;
    fn refusals(&self) -> &[Refusal<Self::State, Self::Event>];

    /// The refusal book is BOUNDED (a machine lives as long as its
    /// host process — the holdout worker's run is weeks long): the
    /// last [`StateMachine::MAX_REFUSALS`] entries are kept, the
    /// oldest is dropped, and the count of the dropped stays honest.
    /// A rising [`StateMachine::refusals_dropped`] against a capped
    /// book is the same alarm as a growing one.
    const MAX_REFUSALS: usize = REFUSAL_BOOK_CAP;

    /// How many refusals the book has dropped to stay bounded.
    fn refusals_dropped(&self) -> u64;
    fn is_terminal(&self) -> bool;

    /// Test-and-probe door: place the machine in `state` without
    /// paying for the path there.
    fn set_state(&mut self, state: Self::State);

    /// The refusal book: exactly one entry per refused pair.
    fn record(&mut self, refusal: Refusal<Self::State, Self::Event>);

    /// The statig-backed step: dispatch one event through the law,
    /// return the actions the host owes in order. The terminal and
    /// epoch gates live ABOVE this — `step` itself answers only for
    /// non-terminal machines at the current epoch.
    fn step(&mut self, event: Self::Event) -> Vec<Self::Action>;

    /// Reset to the machine's initial state for its run, clearing
    /// refusals (a fresh incarnation of the same run: the re-exec
    /// worker boot, the post-rollback watch).
    fn reset(&mut self);

    /// One event in, the actions the host owes out. Total on every
    /// pair: a terminal machine refuses as [`RefusalReason::Terminal`];
    /// an unlawed pair is recorded inside the machine's handlers as
    /// [`RefusalReason::IllegalTransition`] (no actions, no move).
    fn on_event(&mut self, event: Self::Event) -> Vec<Self::Action> {
        if self.is_terminal() {
            let state = self.state();
            self.record(Refusal {
                state,
                event,
                epoch: self.epoch(),
                reason: RefusalReason::Terminal,
            });
            return Vec::new();
        }
        self.step(event)
    }

    /// The epoch-fenced door: a stale epoch is refused before the
    /// law is consulted.
    fn on_run_event(&mut self, run: RunEvent<Self::Event>) -> Vec<Self::Action> {
        if run.epoch != self.epoch() {
            let state = self.state();
            self.record(Refusal {
                state,
                event: run.event,
                epoch: run.epoch,
                reason: RefusalReason::StaleEpoch,
            });
            return Vec::new();
        }
        self.on_event(run.event)
    }

    /// The transport door: one [`Message`] in, the owed actions out —
    /// or [`None`] when the envelope is not this machine's to judge.
    /// - addressed to another role: [`None`] (routing, not law — the
    ///   machine never saw the event).
    /// - another run's id: recorded [`RefusalReason::ForeignRun`],
    ///   no actions, no move.
    /// - a superseded epoch: recorded [`RefusalReason::StaleEpoch`]
    ///   (the run's own ghosts).
    /// - anything else: the law answers, actions owed in order.
    fn on_message<P>(
        &mut self,
        message: Message<Self::Role, Self::Event, P>,
    ) -> Option<Vec<Self::Action>> {
        if message.to != Self::ROLE {
            return None;
        }
        if message.run != self.run() {
            let state = self.state();
            self.record(Refusal {
                state,
                event: message.kind,
                epoch: message.epoch,
                reason: RefusalReason::ForeignRun,
            });
            return Some(Vec::new());
        }
        Some(self.on_run_event(RunEvent::new(message.epoch, message.kind)))
    }
}

/// The wrapper every machine's host-facing harness needs, generated
/// once instead of hand-rolled three times: the struct around the
/// statig machine, the inherent constructor, the run accessor, the
/// manual `Debug` (statig's wrapper carries none), `Default`, and the
/// [`StateMachine`] impl. NO unsafe: the machine REPORTS, the wrapper
/// BOOKS. statig's initialized machine keeps its storage read-only
/// from outside a dispatch (writes there would threaten state-local
/// storage coherence — exactly why `inner_mut`/`state_mut` are unsafe
/// on that type), so every product of a dispatch rides out as a copy:
/// the owed actions off the queue — emptied after every dispatch, so
/// handlers always push onto an empty queue — and the last refusal,
/// stamped by the storage's monotonic report counter so no stale
/// report can replay. Placement ([`StateMachine::set_state`]) rebuilds
/// the machine in the one window statig opens safely — before
/// initialization — at the placed state: flat machines carry no entry
/// actions, so the entry walk into it is empty and placement is exact.
///
/// - `$name` the wrapper struct; `$storage` the statig storage type
///   (private, same module — it must expose `fn fresh(RunId) -> Self`
///   and `const fn terminal($state) -> bool`);
/// - `$state`/`$event`/`$action` the crate-facing enums;
/// - `$role` this machine's role value (its type names `Self::Role`);
/// - the event list is `ALL_EVENTS`, in vocabulary order — each entry
///   is an EXPRESSION (a bare variant path is one; a payload variant
///   may carry a representative sample value, const-constructible).
#[macro_export]
macro_rules! harness {
    (
        $name:ident, $storage:ty,
        state = $state:ty, event = $event:ty, action = $action:ty,
        terminal = $terminal:path, role: $role_ty:ty = $role:expr,
        events = [$($event_sample:expr),+ $(,)?] $(,)?
    ) => {
        pub struct $name {
            /// The initialized machine (the machine's law and its own
            /// storage). Initialized once at construction — from there
            /// statig keeps the storage read-only from outside the
            /// dispatch, and this wrapper never writes it.
            sm: $crate::statig::blocking::InitializedStateMachine<$storage>,
            /// The refusal book: wrapper-owned (the machine reports,
            /// the wrapper books — the machine's storage is read-only
            /// from outside a dispatch). Bounded: the last
            /// [`StateMachine::MAX_REFUSALS`] entries are kept.
            refusals: Vec<Refusal<$state, $event>>,
            refusals_dropped: u64,
            /// The report watermark: the storage's `report_seq` as of
            /// the last copy-out. A stale report cannot replay — the
            /// storage counter is monotonic.
            report_seen: u64,
            /// The owed watermark: how many queue entries the wrapper
            /// has already copied out. The machines' queue is
            /// APPEND-ONLY (an action is minted once per discrete law
            /// event, never per tick, so the queue stays tiny and
            /// finite by construction); the wrapper slices out exactly
            /// what each dispatch added. Rebuilt storage (set_state,
            /// reset) empties the queue, and this zeroes with it.
            owed_drained: usize,
        }

        impl $name {
            /// A machine for one run, at its initial epoch.
            pub fn new(run: RunId) -> Self {
                // Initialized ONCE, on the one road statig opens
                // safely: the machine is configured (storage, state)
                // before initialization and then init() walks the
                // entry actions into the initial state — for the flat
                // machines, an empty walk.
                let sm = <$storage>::fresh(run).uninitialized_state_machine().init();
                Self {
                    sm,
                    refusals: Vec::new(),
                    refusals_dropped: 0,
                    report_seen: 0,
                    owed_drained: 0,
                }
            }

            /// The run this machine fences.
            pub fn run(&self) -> RunId {
                self.sm.inner().run
            }
        }

        impl ::std::fmt::Debug for $name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                f.debug_struct(stringify!($name))
                    .field("run", &self.sm.inner().run)
                    .field("epoch", &self.sm.inner().epoch)
                    .field("state", self.sm.state())
                    .field("refusals", &self.refusals)
                    .field("refusals_dropped", &self.refusals_dropped)
                    .finish()
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new(RunId::default())
            }
        }

        impl StateMachine for $name {
            type State = $state;
            type Event = $event;
            type Action = $action;
            type Role = $role_ty;

            const ROLE: Self::Role = $role;

            const ALL_EVENTS: &'static [Self::Event] = &[$($event_sample),+];

            fn for_run(run: RunId) -> Self {
                Self::new(run)
            }

            fn run(&self) -> RunId {
                self.sm.inner().run
            }

            fn state(&self) -> Self::State {
                *self.sm.state()
            }

            fn epoch(&self) -> u64 {
                self.sm.inner().epoch
            }

            fn refusals(&self) -> &[Refusal<Self::State, Self::Event>] {
                &self.refusals
            }

            fn is_terminal(&self) -> bool {
                $terminal(*self.sm.state())
            }

            fn set_state(&mut self, state: Self::State) {
                // Placement WITHOUT unsafe: statig opens the storage
                // and the state to mutation only BEFORE initialization
                // (the initialized machine keeps them coherent against
                // state-local storage — the reason its own mutators are
                // unsafe). The machine is rebuilt at the placed state;
                // flat machines carry no entry actions, so the entry
                // walk into it is empty and placement is exact. Run,
                // epoch, and the report bookkeeping ride along:
                // placement moves the state, not the history. The owed
                // queue does NOT ride — a rebuilt machine owes nothing
                // — and the wrapper's watermark zeroes to match.
                let (run, epoch) = {
                    let inner = self.sm.inner();
                    (inner.run, inner.epoch)
                };
                let (report_seq, report) = {
                    let inner = self.sm.inner();
                    (inner.report_seq, inner.report.clone())
                };
                let mut placed = <$storage>::fresh(run).uninitialized_state_machine();
                placed.inner_mut().epoch = epoch;
                placed.inner_mut().report_seq = report_seq;
                placed.inner_mut().report = report;
                *placed.state_mut() = state;
                self.sm = placed.init();
                self.owed_drained = 0;
            }

            fn record(&mut self, refusal: Refusal<Self::State, Self::Event>) {
                // The cap rides as a fully qualified path: the macro
                // is invoked in the machines' own modules, and a bare
                // name would resolve at the USE site's scope, not the
                // crate root's.
                if self.refusals.len() >= $crate::REFUSAL_BOOK_CAP {
                    self.refusals.remove(0);
                    self.refusals_dropped += 1;
                }
                self.refusals.push(refusal);
            }

            fn refusals_dropped(&self) -> u64 {
                self.refusals_dropped
            }

            fn step(&mut self, event: Self::Event) -> Vec<Self::Action> {
                self.sm.handle(&event);
                // The initialized machine's storage is read-only from
                // outside the dispatch (statig gates mutation there to
                // protect state-local storage coherence), so the two
                // products of a dispatch ride out as COPIES:
                // - the owed actions off the queue. The wrapper copies
                //   the WHOLE queue after every dispatch and handlers
                //   always push onto an empty queue (it is emptied
                //   after every dispatch; the gates that skip a
                //   dispatch never push). A copy that were ever longer
                //   than one dispatch's actions would surface at once
                //   as duplicated action lists in the tests.
                // - the refusal the handler reported, stamped with the
                //   storage's monotonic report counter so no stale
                //   report can replay.
                // The initialized machine's storage is read-only from
                // outside the dispatch (statig gates mutation there to
                // protect state-local storage coherence), so the two
                // products of a dispatch ride out as COPIES:
                // - the owed actions, sliced off the append-only queue
                //   by the wrapper's watermark. The queue is never
                //   cleared — an action is minted once per discrete
                //   law event, never per tick, so it stays tiny and
                //   finite by construction — and the slice is exactly
                //   what THIS dispatch added. (The old `mem::take`
                //   emptied the queue mechanically; the watermark
                //   preserves its observable behavior without any
                //   write from outside the dispatch. A rebuilt machine
                //   owes nothing — set_state and reset zero the
                //   watermark with their fresh storage.)
                // - the refusal the handler reported, stamped with the
                //   storage's monotonic report counter so no stale
                //   report can replay.
                let from = self.owed_drained.min(self.sm.inner().owed.len());
                let owed = self.sm.inner().owed[from..].to_vec();
                self.owed_drained = self.sm.inner().owed.len();
                let report_seq = self.sm.inner().report_seq;
                if report_seq != self.report_seen {
                    self.report_seen = report_seq;
                    if let Some(refusal) = self.sm.inner().report.clone() {
                        self.record(refusal);
                    }
                }
                owed
            }

            fn reset(&mut self) {
                let run = self.sm.inner().run;
                *self = Self::new(run);
            }
        }
    };
}

/// The reachability walk, run empirically: from `initial`, probe
/// every (reached state, named event) pair on a THROWAWAY machine and
/// follow the pairs that do not refuse. The tests cross-check the
/// result against the law, so a handler edge that the law does not
/// name (or a law row no handler implements) cannot hide — one of the
/// two sets will not match. No state is orphaned, no edge dangles.
pub fn reachable_states<M: StateMachine>(initial: M::State) -> Vec<M::State> {
    let mut seen = vec![initial];
    let mut queue = vec![initial];
    while let Some(state) = queue.pop() {
        for event in M::ALL_EVENTS {
            let mut probe = M::for_run(RunId::default());
            probe.set_state(state);
            let refusals_before = probe.refusals().len();
            probe.on_event(event.clone());
            if probe.refusals().len() != refusals_before {
                continue; // the pair refused: not an edge of the law
            }
            let to = probe.state();
            if !seen.contains(&to) {
                seen.push(to);
                queue.push(to);
            }
        }
    }
    seen
}

/// A deterministic no-panic fuzz harness: walk 4096 events chosen by
/// an in-crate LCG (no external rng dep), asserting the invariants
/// that matter under adversarial input — the machine never panics,
/// never emits an action while terminal, and only ever sits in a
/// state the law can reach. Returns (actions emitted, refusals
/// recorded).
///
/// # Panics
///
/// A terminal machine emitting an action, or a walk leaving the
/// reachable set — the invariants are asserted, not trusted.
pub fn fuzz<M: StateMachine>(mut machine: M, events: &[M::Event], seed: u64) -> (usize, usize) {
    if events.is_empty() {
        return (0, machine.refusals().len());
    }
    let mut state = seed;
    let mut lcg = move || {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (state >> 33) as usize
    };
    let reachable = reachable_states::<M>(machine.state());
    let mut actions = 0usize;
    for _ in 0..4096 {
        let event = match events.get(lcg() % events.len()) {
            Some(e) => e.clone(),
            // unreachable: the alphabet was gated non-empty above
            None => return (actions, machine.refusals().len()),
        };
        let was_terminal = machine.is_terminal();
        let owed = machine.on_event(event);
        if was_terminal {
            assert!(owed.is_empty(), "a terminal machine minted actions");
        }
        assert!(
            reachable.contains(&machine.state()),
            "the walk left the reachable set"
        );
        actions += owed.len();
    }
    (actions, machine.refusals().len())
}
