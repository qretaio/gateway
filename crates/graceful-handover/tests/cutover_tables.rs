//! The correctness gates for the cutover machines. The flow law is
//! statig-defined; these tests hold it to the ORACLE — an independent
//! statement of the same law, written here as plain rows — and walk
//! the sweeps, the reach, the fences, and the fuzz against it. The
//! oracle and the handlers are two descriptions of one law: if they
//! ever disagree, these tests fail. Nothing here performs I/O — the
//! machines cannot, and neither can their tests.
//!
//! Oracle note: the rollback rows (the ones landing back on
//! `Serving`) also BUMP THE EPOCH in the handlers; the row shape
//! carries (from, on, to, owed) and the epoch law is asserted
//! separately (section 5).

use graceful_handover::cutover::{
    HoldoutAction, HoldoutEvent, HoldoutMachine, HoldoutState, Message, PredecessorAction,
    PredecessorEvent, PredecessorMachine, PredecessorState, RefusalReason, Role, RunEvent, RunId,
    StateMachine, SuccessorAction, SuccessorEvent, SuccessorMachine, SuccessorState, fuzz,
    reachable_states,
};

// ----------------------------------------------------------------
// 0. THE EVENT VOCABULARY, compiler-enforced. Each witness matches
//    its enum with NO catch-all arm: a new variant fails this file
//    at compile time, so the sweeps below can never silently skip a
//    legal pair.
// ----------------------------------------------------------------

fn predecessor_events() -> Vec<PredecessorEvent> {
    let all = |e: PredecessorEvent| match e {
        PredecessorEvent::StagedReleaseAdopted => e,
        PredecessorEvent::SoakLaunched => e,
        PredecessorEvent::SuccessorLaunched => e,
        PredecessorEvent::CutoverMarkerIn => e,
        PredecessorEvent::GraceElapsed => e,
        PredecessorEvent::SuccessorHealthy => e,
        PredecessorEvent::SuccessorDied => e,
        PredecessorEvent::HoldoutsReleased => e,
        PredecessorEvent::ControlKept => e,
        PredecessorEvent::Exited => e,
    };
    [
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
    ]
    .into_iter()
    .map(all)
    .collect()
}

fn successor_events() -> Vec<SuccessorEvent> {
    let all = |e: SuccessorEvent| match e {
        SuccessorEvent::NamedItself => e,
        SuccessorEvent::BootstrapExchangeComplete => e,
        SuccessorEvent::LadderStarted => e,
        SuccessorEvent::LeaseTaken => e,
        SuccessorEvent::AppMoved => e,
        SuccessorEvent::AllMovableMoved => e,
        SuccessorEvent::MainPidAccepted => e,
        SuccessorEvent::PortLanded => e,
    };
    [
        SuccessorEvent::NamedItself,
        SuccessorEvent::BootstrapExchangeComplete,
        SuccessorEvent::LadderStarted,
        SuccessorEvent::LeaseTaken,
        SuccessorEvent::AppMoved,
        SuccessorEvent::AllMovableMoved,
        SuccessorEvent::MainPidAccepted,
        SuccessorEvent::PortLanded,
    ]
    .into_iter()
    .map(all)
    .collect()
}

fn holdout_events() -> Vec<HoldoutEvent> {
    let all = |e: HoldoutEvent| match e {
        HoldoutEvent::MarkInherited => e,
        HoldoutEvent::FlagFound => e,
        HoldoutEvent::ScopedLoadDone => e,
        HoldoutEvent::MeshOn => e,
        HoldoutEvent::FlagSuccessorKnown => e,
        HoldoutEvent::FlagSuccessorChanged => e,
        HoldoutEvent::ChainRefreshDue => e,
        HoldoutEvent::ArmRideHomeFailed => e,
        HoldoutEvent::BindingProviderMiss => e,
        HoldoutEvent::SuccessorPresenceStale => e,
        HoldoutEvent::FlagTorn => e,
        HoldoutEvent::BootFullComplete => e,
        HoldoutEvent::FlagGone => e,
        HoldoutEvent::WorkerKilled => e,
    };
    [
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
    ]
    .into_iter()
    .map(all)
    .collect()
}

/// The crate's own vocabulary consts must agree with the
/// compiler-enforced lists above.
#[test]
fn all_events_consts_match_the_enums() {
    assert_eq!(PredecessorMachine::ALL_EVENTS, predecessor_events());
    assert_eq!(SuccessorMachine::ALL_EVENTS, successor_events());
    assert_eq!(HoldoutMachine::ALL_EVENTS, holdout_events());
}

/// Every machine speaks under its own role.
#[test]
fn the_machines_speak_under_their_roles() {
    assert_eq!(PredecessorMachine::ROLE, Role::Predecessor);
    assert_eq!(SuccessorMachine::ROLE, Role::Successor);
    assert_eq!(HoldoutMachine::ROLE, Role::Holdout);
}

// ----------------------------------------------------------------
// 1. THE ORACLE: the law as plain rows, independent of the handlers.
//    One tuple = (from, on, to, owed actions in order).
// ----------------------------------------------------------------

type Row<S, E, A> = (S, E, S, &'static [A]);

const PREDECESSOR_LAW: &[Row<PredecessorState, PredecessorEvent, PredecessorAction>] = &[
    // The adopt is a FACT (the rename landed): the machine moves and
    // owes nothing.
    (
        PredecessorState::Serving,
        PredecessorEvent::StagedReleaseAdopted,
        PredecessorState::PipelineStarted,
        &[],
    ),
    // The blue-green soak: supervise the twin's compute, NO drain.
    (
        PredecessorState::Serving,
        PredecessorEvent::SoakLaunched,
        PredecessorState::Soaking,
        &[PredecessorAction::SuperviseSuccessor],
    ),
    // The straight ladder ENTERS the pipeline from plain serving:
    // the launch itself arms the marker watch and starts the drain.
    (
        PredecessorState::Serving,
        PredecessorEvent::SuccessorLaunched,
        PredecessorState::PipelineStarted,
        &[
            PredecessorAction::WatchCutoverMarker,
            PredecessorAction::StartDrain,
        ],
    ),
    // The soak may also start FROM the adoption (the rename landed,
    // the host picked compute_only): still no drain.
    (
        PredecessorState::PipelineStarted,
        PredecessorEvent::SoakLaunched,
        PredecessorState::Soaking,
        &[PredecessorAction::SuperviseSuccessor],
    ),
    // The ladder posture: the marker is the release trigger, the
    // drain began AT LAUNCH — in this order.
    (
        PredecessorState::PipelineStarted,
        PredecessorEvent::SuccessorLaunched,
        PredecessorState::PipelineStarted,
        &[
            PredecessorAction::WatchCutoverMarker,
            PredecessorAction::StartDrain,
        ],
    ),
    (
        PredecessorState::PipelineStarted,
        PredecessorEvent::CutoverMarkerIn,
        PredecessorState::CutoverConfirmed,
        &[PredecessorAction::StartGrace],
    ),
    // The rollback (0.2.38): a death while this node held control
    // takes NOTHING with it. These rows also bump the epoch.
    (
        PredecessorState::PipelineStarted,
        PredecessorEvent::SuccessorDied,
        PredecessorState::Serving,
        &[PredecessorAction::TearUpPipeline],
    ),
    (
        PredecessorState::Soaking,
        PredecessorEvent::SuccessorDied,
        PredecessorState::Serving,
        &[PredecessorAction::RollbackSoak],
    ),
    // The grace ran; the twin must PROVE it lives before any settle.
    (
        PredecessorState::CutoverConfirmed,
        PredecessorEvent::GraceElapsed,
        PredecessorState::Draining,
        &[PredecessorAction::VerifySuccessorAlive],
    ),
    (
        PredecessorState::CutoverConfirmed,
        PredecessorEvent::SuccessorDied,
        PredecessorState::Serving,
        &[PredecessorAction::TearUpPipeline],
    ),
    // The settle roads: alive opens the settle; the ANSWER names the
    // road.
    (
        PredecessorState::Draining,
        PredecessorEvent::SuccessorHealthy,
        PredecessorState::Draining,
        &[PredecessorAction::SettleHoldouts],
    ),
    (
        PredecessorState::Draining,
        PredecessorEvent::SuccessorDied,
        PredecessorState::Serving,
        &[PredecessorAction::TearUpPipeline],
    ),
    // The release law: the port leaves, THEN the shutdown ask —
    // MAINPID already moved (0.2.73), the exit is a non-event.
    (
        PredecessorState::Draining,
        PredecessorEvent::HoldoutsReleased,
        PredecessorState::Released,
        &[
            PredecessorAction::ReleasePort,
            PredecessorAction::RequestWantsShutdown,
        ],
    ),
    (
        PredecessorState::Draining,
        PredecessorEvent::ControlKept,
        PredecessorState::Draining,
        &[PredecessorAction::SuperviseSuccessor],
    ),
    (
        PredecessorState::Released,
        PredecessorEvent::Exited,
        PredecessorState::Done,
        &[],
    ),
];

const SUCCESSOR_LAW: &[Row<SuccessorState, SuccessorEvent, SuccessorAction>] = &[
    (
        SuccessorState::Pending,
        SuccessorEvent::NamedItself,
        SuccessorState::Pending,
        &[],
    ),
    (
        SuccessorState::Pending,
        SuccessorEvent::BootstrapExchangeComplete,
        SuccessorState::Exchanged,
        &[],
    ),
    (
        SuccessorState::Exchanged,
        SuccessorEvent::LadderStarted,
        SuccessorState::Taking,
        &[],
    ),
    (
        SuccessorState::Taking,
        SuccessorEvent::LeaseTaken,
        SuccessorState::Taking,
        &[],
    ),
    (
        SuccessorState::Taking,
        SuccessorEvent::AppMoved,
        SuccessorState::Taking,
        &[],
    ),
    // CUTOVER READY: the two announcements of 0.2.73 in order.
    (
        SuccessorState::Taking,
        SuccessorEvent::AllMovableMoved,
        SuccessorState::CutoverReady,
        &[
            SuccessorAction::AnnounceCutoverReady,
            SuccessorAction::AnnounceMainPid,
        ],
    ),
    (
        SuccessorState::CutoverReady,
        SuccessorEvent::MainPidAccepted,
        SuccessorState::CutoverReady,
        &[],
    ),
    (
        SuccessorState::CutoverReady,
        SuccessorEvent::PortLanded,
        SuccessorState::Full,
        &[],
    ),
];

const HOLDOUT_LAW: &[Row<HoldoutState, HoldoutEvent, HoldoutAction>] = &[
    // Boot facts and the scoped load.
    (
        HoldoutState::Born,
        HoldoutEvent::MarkInherited,
        HoldoutState::Born,
        &[],
    ),
    (
        HoldoutState::Born,
        HoldoutEvent::FlagFound,
        HoldoutState::Born,
        &[],
    ),
    (
        HoldoutState::Born,
        HoldoutEvent::ScopedLoadDone,
        HoldoutState::Scoped,
        &[],
    ),
    // Boot-time stale: the flag named a DEAD successor — the reclaim
    // starts before the mesh even attaches.
    (
        HoldoutState::Born,
        HoldoutEvent::SuccessorPresenceStale,
        HoldoutState::Reclaiming,
        &[HoldoutAction::TearFlag],
    ),
    (
        HoldoutState::Born,
        HoldoutEvent::WorkerKilled,
        HoldoutState::Retired,
        &[],
    ),
    (
        HoldoutState::Scoped,
        HoldoutEvent::MeshOn,
        HoldoutState::MeshAttached,
        &[],
    ),
    (
        HoldoutState::Scoped,
        HoldoutEvent::SuccessorPresenceStale,
        HoldoutState::Reclaiming,
        &[HoldoutAction::TearFlag],
    ),
    (
        HoldoutState::Scoped,
        HoldoutEvent::FlagGone,
        HoldoutState::Retired,
        &[],
    ),
    (
        HoldoutState::Scoped,
        HoldoutEvent::WorkerKilled,
        HoldoutState::Retired,
        &[],
    ),
    // The arm; and the loop law (0.2.74): an UNARMED miss answers
    // honestly — the row exists so the pair is LEGAL (no refusal)
    // and owes nothing.
    (
        HoldoutState::MeshAttached,
        HoldoutEvent::FlagSuccessorKnown,
        HoldoutState::Armed,
        &[HoldoutAction::ArmRideHome],
    ),
    (
        HoldoutState::MeshAttached,
        HoldoutEvent::BindingProviderMiss,
        HoldoutState::MeshAttached,
        &[],
    ),
    (
        HoldoutState::MeshAttached,
        HoldoutEvent::SuccessorPresenceStale,
        HoldoutState::Reclaiming,
        &[HoldoutAction::TearFlag],
    ),
    (
        HoldoutState::MeshAttached,
        HoldoutEvent::FlagGone,
        HoldoutState::Retired,
        &[],
    ),
    (
        HoldoutState::MeshAttached,
        HoldoutEvent::WorkerKilled,
        HoldoutState::Retired,
        &[],
    ),
    // Armed: re-arms on change and refresh; a miss rides home; a
    // FAILED arm is honest and retried (stays put, owes nothing).
    (
        HoldoutState::Armed,
        HoldoutEvent::FlagSuccessorChanged,
        HoldoutState::Armed,
        &[HoldoutAction::ArmRideHome],
    ),
    (
        HoldoutState::Armed,
        HoldoutEvent::ChainRefreshDue,
        HoldoutState::Armed,
        &[HoldoutAction::ArmRideHome],
    ),
    (
        HoldoutState::Armed,
        HoldoutEvent::BindingProviderMiss,
        HoldoutState::Armed,
        &[HoldoutAction::RideHome],
    ),
    (
        HoldoutState::Armed,
        HoldoutEvent::ArmRideHomeFailed,
        HoldoutState::Armed,
        &[],
    ),
    (
        HoldoutState::Armed,
        HoldoutEvent::SuccessorPresenceStale,
        HoldoutState::Reclaiming,
        &[HoldoutAction::TearFlag],
    ),
    (
        HoldoutState::Armed,
        HoldoutEvent::FlagGone,
        HoldoutState::Retired,
        &[],
    ),
    (
        HoldoutState::Armed,
        HoldoutEvent::WorkerKilled,
        HoldoutState::Retired,
        &[],
    ),
    // The reclaim: the tear, then boot full.
    (
        HoldoutState::Reclaiming,
        HoldoutEvent::FlagTorn,
        HoldoutState::Reclaiming,
        &[HoldoutAction::BootFull],
    ),
    (
        HoldoutState::Reclaiming,
        HoldoutEvent::BootFullComplete,
        HoldoutState::Full,
        &[],
    ),
];

fn is_lawful<S: PartialEq, E: PartialEq, A: PartialEq>(
    law: &[Row<S, E, A>],
    state: &S,
    event: &E,
) -> bool {
    law.iter()
        .any(|(from, on, _, _)| from == state && on == event)
}

// ----------------------------------------------------------------
// 2. THE ORACLE AGREES WITH THE MACHINES: every lawful row fires
//    exactly as the oracle names it.
// ----------------------------------------------------------------

#[test]
fn every_law_row_fires_exactly_as_named() {
    for (from, on, to, actions) in PREDECESSOR_LAW.iter() {
        let mut machine = PredecessorMachine::new(RunId(7));
        machine.set_state(*from);
        let owed = machine.on_event(*on);
        assert_eq!(
            machine.state(),
            *to,
            "predecessor row ({from:?}, {on:?}) landed in the wrong state"
        );
        assert_eq!(
            &owed, actions,
            "predecessor row ({from:?}, {on:?}) owed the wrong actions"
        );
        assert!(
            machine.refusals().is_empty(),
            "a LAWFUL predecessor row recorded a refusal: ({from:?}, {on:?})"
        );
    }
    for (from, on, to, actions) in SUCCESSOR_LAW.iter() {
        let mut machine = SuccessorMachine::new(RunId(7));
        machine.set_state(*from);
        let owed = machine.on_event(*on);
        assert_eq!(
            machine.state(),
            *to,
            "successor row ({from:?}, {on:?}) landed in the wrong state"
        );
        assert_eq!(
            &owed, actions,
            "successor row ({from:?}, {on:?}) owed wrong"
        );
        assert!(
            machine.refusals().is_empty(),
            "lawful successor row refused"
        );
    }
    for (from, on, to, actions) in HOLDOUT_LAW.iter() {
        let mut machine = HoldoutMachine::new(RunId(7));
        machine.set_state(*from);
        let owed = machine.on_event(*on);
        assert_eq!(
            machine.state(),
            *to,
            "holdout row ({from:?}, {on:?}) landed in the wrong state"
        );
        assert_eq!(&owed, actions, "holdout row ({from:?}, {on:?}) owed wrong");
        assert!(machine.refusals().is_empty(), "lawful holdout row refused");
    }
}

// ----------------------------------------------------------------
// 3. TOTALITY: every (state, event) pair — lawful pairs behave, all
//    others refuse exactly once and never move.
// ----------------------------------------------------------------

#[test]
fn predecessor_pairs_are_total() {
    let states = [
        PredecessorState::Serving,
        PredecessorState::PipelineStarted,
        PredecessorState::Soaking,
        PredecessorState::CutoverConfirmed,
        PredecessorState::Draining,
        PredecessorState::Released,
        PredecessorState::Done,
    ];
    for state in states {
        for event in predecessor_events() {
            let mut machine = PredecessorMachine::new(RunId(1));
            machine.set_state(state);
            let refusals_before = machine.refusals().len();
            let lawful = is_lawful(PREDECESSOR_LAW, &state, &event);
            let owed = machine.on_event(event);
            if lawful {
                assert!(
                    machine.refusals().len() == refusals_before,
                    "{state:?} + {event:?}: a LAWFUL pair recorded a refusal"
                );
            } else {
                assert!(owed.is_empty(), "{state:?} + {event:?} owed actions");
                assert_eq!(machine.state(), state, "a refusal MOVED the machine");
                assert_eq!(machine.refusals().len(), refusals_before + 1);
                assert!(matches!(
                    machine.refusals().last().unwrap().reason,
                    RefusalReason::IllegalTransition | RefusalReason::Terminal
                ));
            }
        }
    }
}

#[test]
fn successor_pairs_are_total() {
    let states = [
        SuccessorState::Pending,
        SuccessorState::Exchanged,
        SuccessorState::Taking,
        SuccessorState::CutoverReady,
        SuccessorState::Full,
    ];
    for state in states {
        for event in successor_events() {
            let mut machine = SuccessorMachine::new(RunId(1));
            machine.set_state(state);
            let refusals_before = machine.refusals().len();
            let lawful = is_lawful(SUCCESSOR_LAW, &state, &event);
            let owed = machine.on_event(event);
            if lawful {
                assert!(
                    machine.refusals().len() == refusals_before,
                    "{state:?} + {event:?}: a LAWFUL pair recorded a refusal"
                );
            } else {
                assert!(owed.is_empty(), "{state:?} + {event:?} owed actions");
                assert_eq!(machine.state(), state, "a refusal MOVED the machine");
                assert_eq!(machine.refusals().len(), refusals_before + 1);
            }
        }
    }
}

#[test]
fn holdout_pairs_are_total() {
    let states = [
        HoldoutState::Born,
        HoldoutState::Scoped,
        HoldoutState::MeshAttached,
        HoldoutState::Armed,
        HoldoutState::Reclaiming,
        HoldoutState::Full,
        HoldoutState::Retired,
    ];
    for state in states {
        for event in holdout_events() {
            let mut machine = HoldoutMachine::new(RunId(1));
            machine.set_state(state);
            let refusals_before = machine.refusals().len();
            let lawful = is_lawful(HOLDOUT_LAW, &state, &event);
            let owed = machine.on_event(event);
            if lawful {
                assert!(
                    machine.refusals().len() == refusals_before,
                    "{state:?} + {event:?}: a LAWFUL pair recorded a refusal"
                );
            } else {
                assert!(owed.is_empty(), "{state:?} + {event:?} owed actions");
                assert_eq!(machine.state(), state, "a refusal MOVED the machine");
                assert_eq!(machine.refusals().len(), refusals_before + 1);
            }
        }
    }
}

// ----------------------------------------------------------------
// 3b. THE FAIL ROADS. The question the owner put: does the API fail
//     HONESTLY — not only on the happy path and the rollback? These
//     drives feed the failure events from EVERY state, put wrong-run
//     envelopes to every door, refuse a pair twice, and overfill the
//     refusal book. A lawful fail-row owes exactly its road; anything
//     else refuses with no actions and no move.
// ----------------------------------------------------------------

fn row_actions<'a, S: PartialEq, E: PartialEq, A: PartialEq>(
    law: &'a [(S, E, S, &'static [A])],
    state: &S,
    event: &E,
) -> Option<&'a [A]> {
    law.iter()
        .find(|(from, on, _, _)| from == state && on == event)
        .map(|(_, _, _, owed)| *owed)
}

#[test]
fn the_fail_roads_drive_honestly_from_every_state() {
    // The PREDECESSOR's fail event is a successor death. Every
    // lawful (state, death) row owes its road exactly; any other
    // state refuses with nothing owed and nothing moved.
    for state in [
        PredecessorState::Serving,
        PredecessorState::PipelineStarted,
        PredecessorState::Soaking,
        PredecessorState::CutoverConfirmed,
        PredecessorState::Draining,
        PredecessorState::Released,
        PredecessorState::Done,
    ] {
        let mut machine = PredecessorMachine::new(RunId(1));
        machine.set_state(state);
        let owed = machine.on_event(PredecessorEvent::SuccessorDied);
        match row_actions(PREDECESSOR_LAW, &state, &PredecessorEvent::SuccessorDied) {
            Some(road) => {
                assert_eq!(owed, road, "{state:?} + SuccessorDied owes its road");
            }
            None => {
                assert!(owed.is_empty(), "{state:?} + SuccessorDied owed something");
                assert_eq!(machine.state(), state, "a death refusal MOVED the machine");
                assert_eq!(machine.refusals().len(), 1);
            }
        }
    }

    // The SUCCESSOR has no death vocabulary — its fail roads are the
    // premature claims: READY before the ladder, a ghost acceptance
    // from Pending. Both refuse from every state the law does not
    // name.
    for state in [
        SuccessorState::Pending,
        SuccessorState::Exchanged,
        SuccessorState::Taking,
        SuccessorState::CutoverReady,
        SuccessorState::Full,
    ] {
        for event in [
            SuccessorEvent::AllMovableMoved,
            SuccessorEvent::MainPidAccepted,
        ] {
            let mut machine = SuccessorMachine::new(RunId(1));
            machine.set_state(state);
            let owed = machine.on_event(event);
            match row_actions(SUCCESSOR_LAW, &state, &event) {
                Some(road) => {
                    assert_eq!(owed, road, "{state:?} + {event:?} owes its road");
                }
                None => {
                    assert!(owed.is_empty(), "{state:?} + {event:?} owed something");
                    assert_eq!(
                        machine.state(),
                        state,
                        "a premature claim MOVED the machine"
                    );
                    assert_eq!(machine.refusals().len(), 1);
                }
            }
        }
    }

    // The HOLDOUT's fail events: the successor's presence went
    // stale, the flag vanished, the operator killed this worker.
    // Each drive from every state.
    for state in [
        HoldoutState::Born,
        HoldoutState::Scoped,
        HoldoutState::MeshAttached,
        HoldoutState::Armed,
        HoldoutState::Reclaiming,
        HoldoutState::Full,
        HoldoutState::Retired,
    ] {
        for event in [
            HoldoutEvent::SuccessorPresenceStale,
            HoldoutEvent::FlagGone,
            HoldoutEvent::WorkerKilled,
        ] {
            let mut machine = HoldoutMachine::new(RunId(1));
            machine.set_state(state);
            let owed = machine.on_event(event);
            match row_actions(HOLDOUT_LAW, &state, &event) {
                Some(road) => {
                    assert_eq!(owed, road, "{state:?} + {event:?} owes its road");
                }
                None => {
                    assert!(owed.is_empty(), "{state:?} + {event:?} owed something");
                    assert_eq!(
                        machine.state(),
                        state,
                        "a fail-road refusal MOVED the machine"
                    );
                    assert_eq!(machine.refusals().len(), 1);
                }
            }
        }
    }
}

#[test]
fn foreign_runs_refuse_at_every_door() {
    // A wrong-run envelope: ONE ForeignRun refusal, no move, no
    // actions — at every machine's door. A wrong-role envelope is
    // routing SILENCE: None, no refusal recorded (routing is not
    // the law's business).
    let mut predecessor = PredecessorMachine::new(RunId(1));
    let ghost = Message {
        run: RunId(999),
        epoch: predecessor.epoch(),
        from: Role::Successor,
        to: Role::Predecessor,
        kind: PredecessorEvent::SuccessorLaunched,
        payload: (),
    };
    assert_eq!(predecessor.on_message(ghost), Some(Vec::new()));
    assert_eq!(predecessor.refusals().len(), 1);
    assert_eq!(predecessor.refusals()[0].reason, RefusalReason::ForeignRun);
    assert_eq!(predecessor.state(), PredecessorState::Serving);

    let mut successor = SuccessorMachine::new(RunId(1));
    let ghost = Message {
        run: RunId(999),
        epoch: successor.epoch(),
        from: Role::Predecessor,
        to: Role::Successor,
        kind: SuccessorEvent::NamedItself,
        payload: (),
    };
    assert_eq!(successor.on_message(ghost), Some(Vec::new()));
    assert_eq!(successor.refusals().len(), 1);
    assert_eq!(successor.refusals()[0].reason, RefusalReason::ForeignRun);
    assert_eq!(successor.state(), SuccessorState::Pending);

    let mut holdout = HoldoutMachine::new(RunId(1));
    let ghost = Message {
        run: RunId(999),
        epoch: holdout.epoch(),
        from: Role::Successor,
        to: Role::Holdout,
        kind: HoldoutEvent::FlagFound,
        payload: (),
    };
    assert_eq!(holdout.on_message(ghost), Some(Vec::new()));
    assert_eq!(holdout.refusals().len(), 1);
    assert_eq!(holdout.refusals()[0].reason, RefusalReason::ForeignRun);
    assert_eq!(holdout.state(), HoldoutState::Born);

    // Misdelivered: silence, and the book did not grow.
    let misdelivered = Message {
        run: RunId(1),
        epoch: 0,
        from: Role::Successor,
        to: Role::Supervisor,
        kind: PredecessorEvent::SuccessorLaunched,
        payload: (),
    };
    assert_eq!(predecessor.on_message(misdelivered), None);
    assert_eq!(
        predecessor.refusals().len(),
        1,
        "routing silence recorded a refusal"
    );
}

#[test]
fn a_refused_pair_refuses_again_without_moving() {
    // Honesty is idempotent: feed the SAME illegal pair twice —
    // two refusals, still unmoved, nothing owed either time.
    let mut machine = PredecessorMachine::new(RunId(1));
    machine.set_state(PredecessorState::Serving);
    let ghost = PredecessorEvent::HoldoutsReleased;
    assert!(!is_lawful(
        PREDECESSOR_LAW,
        &PredecessorState::Serving,
        &ghost
    ));
    assert!(machine.on_event(ghost).is_empty());
    let after_first = machine.state();
    assert!(machine.on_event(ghost).is_empty());
    assert_eq!(machine.state(), after_first);
    assert_eq!(machine.refusals().len(), 2);
}

#[test]
fn the_refusal_book_is_bounded_and_honest() {
    // A machine lives as long as its host (the holdout worker's run
    // is weeks long): the book caps at MAX_REFUSALS, drops the
    // OLDEST entries, and the dropped count stays honest. Every
    // kept entry is the same refused pair — the book only forgets,
    // it never rewrites.
    let mut machine = PredecessorMachine::new(RunId(1));
    machine.set_state(PredecessorState::Serving);
    let ghost = PredecessorEvent::HoldoutsReleased;
    for _ in 0..300 {
        assert!(machine.on_event(ghost).is_empty());
    }
    assert_eq!(machine.state(), PredecessorState::Serving);
    assert_eq!(machine.refusals().len(), PredecessorMachine::MAX_REFUSALS);
    assert_eq!(
        machine.refusals_dropped(),
        (300 - PredecessorMachine::MAX_REFUSALS) as u64
    );
    assert!(
        machine
            .refusals()
            .iter()
            .all(|r| r.event == ghost && r.reason == RefusalReason::IllegalTransition)
    );

    // The long-lived machine's book behaves the same.
    let mut worker = HoldoutMachine::new(RunId(1));
    worker.set_state(HoldoutState::Armed);
    let stray = HoldoutEvent::ScopedLoadDone;
    assert!(!is_lawful(HOLDOUT_LAW, &HoldoutState::Armed, &stray));
    for _ in 0..257 {
        assert!(worker.on_event(stray).is_empty());
    }
    assert_eq!(worker.refusals().len(), HoldoutMachine::MAX_REFUSALS);
    assert_eq!(worker.refusals_dropped(), 1);
}

// ----------------------------------------------------------------
// 4. REACHABILITY: the reach walk agrees with the oracle — no
//    orphan states, no oracle row on or into an unreachable state.
// ----------------------------------------------------------------

#[test]
fn every_state_is_reachable_and_the_oracle_lives_on_the_reach() {
    macro_rules! reach {
        ($m:ty, $init:expr, $law:expr) => {{
            let reachable = reachable_states::<$m>($init);
            let mut law_states: Vec<_> = Vec::new();
            for (from, _, to, _) in $law.iter() {
                if !law_states.contains(from) {
                    law_states.push(*from);
                }
                if !law_states.contains(to) {
                    law_states.push(*to);
                }
            }
            for row in $law.iter() {
                assert!(
                    reachable.contains(&row.0),
                    "oracle row fires from an unreachable state: {row:?}"
                );
                assert!(
                    reachable.contains(&row.2),
                    "oracle row lands in an unreachable state: {row:?}"
                );
            }
            assert_eq!(
                law_states.len(),
                reachable.len(),
                "the oracle's states and the machine's reach disagree"
            );
            for state in &law_states {
                assert!(
                    reachable.contains(state),
                    "the oracle names {state:?}, the machine cannot reach it"
                );
            }
            reachable
        }};
    }
    let pred = reach!(
        PredecessorMachine,
        PredecessorState::Serving,
        PREDECESSOR_LAW
    );
    assert_eq!(pred.len(), 7, "every predecessor state reachable");
    let succ = reach!(SuccessorMachine, SuccessorState::Pending, SUCCESSOR_LAW);
    assert_eq!(succ.len(), 5);
    let hold = reach!(HoldoutMachine, HoldoutState::Born, HOLDOUT_LAW);
    assert_eq!(hold.len(), 7);
}

// ----------------------------------------------------------------
// 5. THE ROLLBACK LAW (0.2.38): successor death tears the pipeline
//    from every pre-port state, rebases the epoch, and ghosts are
//    refused afterwards. A fresh generation ladders again on the
//    same machine.
// ----------------------------------------------------------------

#[test]
fn rollback_rebases_and_ghosts_are_refused() {
    let mut machine = PredecessorMachine::new(RunId(42));
    assert_eq!(machine.epoch(), 0);

    // The rename landed: the machine moves, nothing owed.
    let owed = machine.on_event(PredecessorEvent::StagedReleaseAdopted);
    assert!(owed.is_empty());
    assert_eq!(machine.state(), PredecessorState::PipelineStarted);

    // The twin launched: watch + drain, in that order.
    let owed = machine.on_event(PredecessorEvent::SuccessorLaunched);
    assert_eq!(
        owed,
        vec![
            PredecessorAction::WatchCutoverMarker,
            PredecessorAction::StartDrain
        ]
    );

    let owed = machine.on_event(PredecessorEvent::CutoverMarkerIn);
    assert_eq!(owed, vec![PredecessorAction::StartGrace]);
    assert_eq!(machine.state(), PredecessorState::CutoverConfirmed);

    // The successor dies AFTER the marker: still a rollback (the port
    // never left us).
    let owed = machine.on_event(PredecessorEvent::SuccessorDied);
    assert_eq!(owed, vec![PredecessorAction::TearUpPipeline]);
    assert_eq!(machine.state(), PredecessorState::Serving);
    assert_eq!(machine.epoch(), 1, "the rollback rebased the run");

    // A ghost from the dead generation: the stale marker arrives
    // again, carrying the OLD epoch — refused, recorded, no move.
    let owed = machine.on_run_event(RunEvent::new(0, PredecessorEvent::CutoverMarkerIn));
    assert!(owed.is_empty());
    assert_eq!(machine.state(), PredecessorState::Serving);
    assert_eq!(machine.refusals().len(), 1);
    assert_eq!(machine.refusals()[0].reason, RefusalReason::StaleEpoch);

    // The fresh generation ladders again from the same machine.
    let owed = machine.on_run_event(RunEvent::new(1, PredecessorEvent::StagedReleaseAdopted));
    assert!(owed.is_empty());
    assert_eq!(machine.state(), PredecessorState::PipelineStarted);
}

// ----------------------------------------------------------------
// 6. TERMINAL ABSORPTION.
// ----------------------------------------------------------------

#[test]
fn terminal_states_absorb_everything() {
    let mut predecessor = PredecessorMachine::new(RunId(1));
    predecessor.set_state(PredecessorState::Done);
    let owed = predecessor.on_event(PredecessorEvent::SuccessorLaunched);
    assert!(owed.is_empty());
    assert_eq!(predecessor.refusals()[0].reason, RefusalReason::Terminal);
    assert_eq!(predecessor.state(), PredecessorState::Done);

    let mut successor = SuccessorMachine::new(RunId(1));
    successor.set_state(SuccessorState::Full);
    let owed = successor.on_event(SuccessorEvent::PortLanded);
    assert!(owed.is_empty());
    assert_eq!(successor.refusals()[0].reason, RefusalReason::Terminal);

    let mut holdout = HoldoutMachine::new(RunId(1));
    holdout.set_state(HoldoutState::Retired);
    let owed = holdout.on_event(HoldoutEvent::MeshOn);
    assert!(owed.is_empty());
    assert_eq!(holdout.refusals()[0].reason, RefusalReason::Terminal);
}

// ----------------------------------------------------------------
// 7. THE FULL LADDER AS A SCENARIO: two machines hand a run over,
//    matching the prod ladder's event order event by event.
// ----------------------------------------------------------------

#[test]
fn the_ladder_walks_both_sides_in_prod_order() {
    let mut predecessor = PredecessorMachine::new(RunId(11));
    let mut successor = SuccessorMachine::new(RunId(11));

    // The watch sees staged bytes; the rename lands first, THEN the
    // machine hears about it.
    let owed = predecessor.on_event(PredecessorEvent::StagedReleaseAdopted);
    assert!(owed.is_empty());
    assert_eq!(predecessor.state(), PredecessorState::PipelineStarted);

    // The successor spawned and names itself; the exchange completes;
    // the ladder starts moving apps. The predecessor arms the marker
    // watch and opens the drain posture AT LAUNCH.
    assert_eq!(
        predecessor.on_event(PredecessorEvent::SuccessorLaunched),
        vec![
            PredecessorAction::WatchCutoverMarker,
            PredecessorAction::StartDrain
        ]
    );
    assert_eq!(
        successor.on_event(SuccessorEvent::NamedItself),
        Vec::<SuccessorAction>::new()
    );
    assert_eq!(
        successor.on_event(SuccessorEvent::BootstrapExchangeComplete),
        vec![]
    );
    assert_eq!(successor.on_event(SuccessorEvent::LadderStarted), vec![]);
    for _ in 0..12 {
        assert_eq!(successor.on_event(SuccessorEvent::AppMoved), vec![]);
        assert_eq!(successor.on_event(SuccessorEvent::LeaseTaken), vec![]);
    }

    // CUTOVER READY: the two announcements of 0.2.73 in order.
    let owed = successor.on_event(SuccessorEvent::AllMovableMoved);
    assert_eq!(
        owed,
        vec![
            SuccessorAction::AnnounceCutoverReady,
            SuccessorAction::AnnounceMainPid
        ]
    );
    assert_eq!(successor.state(), SuccessorState::CutoverReady);
    assert_eq!(successor.on_event(SuccessorEvent::MainPidAccepted), vec![]);

    // The predecessor sees the marker, runs the grace, verifies the
    // twin alive, settles the holdouts, releases the port; the
    // successor lands it.
    assert_eq!(
        predecessor.on_event(PredecessorEvent::CutoverMarkerIn),
        vec![PredecessorAction::StartGrace]
    );
    assert_eq!(
        predecessor.on_event(PredecessorEvent::GraceElapsed),
        vec![PredecessorAction::VerifySuccessorAlive]
    );
    assert_eq!(
        predecessor.on_event(PredecessorEvent::SuccessorHealthy),
        vec![PredecessorAction::SettleHoldouts]
    );
    assert_eq!(
        predecessor.on_event(PredecessorEvent::HoldoutsReleased),
        vec![
            PredecessorAction::ReleasePort,
            PredecessorAction::RequestWantsShutdown
        ]
    );
    assert_eq!(successor.on_event(SuccessorEvent::PortLanded), vec![]);
    assert_eq!(successor.state(), SuccessorState::Full);
    assert!(successor.is_terminal());
    assert_eq!(predecessor.on_event(PredecessorEvent::Exited), vec![]);
    assert!(predecessor.is_terminal());
    assert!(predecessor.refusals().is_empty());
    assert!(successor.refusals().is_empty());
}

// ----------------------------------------------------------------
// 8. THE HOLDOUT SCENARIO: born scoped, armed, the ride, the
//    reclaim, full — with the honest-arm and loop laws on the road.
// ----------------------------------------------------------------

#[test]
fn the_holdout_walks_the_worker_road() {
    let mut worker = HoldoutMachine::new(RunId(12));

    // The mark rode the ENV; the scoped load finished.
    assert_eq!(worker.on_event(HoldoutEvent::MarkInherited), vec![]);
    assert_eq!(worker.on_event(HoldoutEvent::ScopedLoadDone), vec![]);
    assert_eq!(worker.state(), HoldoutState::Scoped);

    // The mesh attaches; a provider miss BEFORE arming answers
    // honestly (no ride: the loop law).
    assert_eq!(worker.on_event(HoldoutEvent::MeshOn), vec![]);
    let owed = worker.on_event(HoldoutEvent::BindingProviderMiss);
    assert_eq!(owed, vec![], "an unarmed worker must not ride home");
    assert_eq!(worker.state(), HoldoutState::MeshAttached);
    assert!(
        worker.refusals().is_empty(),
        "the honest miss is LAWFUL, not a refusal"
    );

    // The watch arms on its first tick.
    let owed = worker.on_event(HoldoutEvent::FlagSuccessorKnown);
    assert_eq!(owed, vec![HoldoutAction::ArmRideHome]);
    assert_eq!(worker.state(), HoldoutState::Armed);

    // A FAILED arm is honest: stay put, owe nothing, retry lawful.
    assert_eq!(worker.on_event(HoldoutEvent::ArmRideHomeFailed), vec![]);
    assert_eq!(worker.state(), HoldoutState::Armed);
    assert!(
        worker.refusals().is_empty(),
        "an honest arm failure refused"
    );

    // Now every provider miss rides home; the state holds.
    for _ in 0..3 {
        assert_eq!(
            worker.on_event(HoldoutEvent::BindingProviderMiss),
            vec![HoldoutAction::RideHome]
        );
    }

    // The flag names a new successor: re-arm. The chain hits 23 h:
    // refresh.
    assert_eq!(
        worker.on_event(HoldoutEvent::FlagSuccessorChanged),
        vec![HoldoutAction::ArmRideHome]
    );
    assert_eq!(
        worker.on_event(HoldoutEvent::ChainRefreshDue),
        vec![HoldoutAction::ArmRideHome]
    );

    // The successor goes stale: the reclaim tears the flag and boots
    // full.
    assert_eq!(
        worker.on_event(HoldoutEvent::SuccessorPresenceStale),
        vec![HoldoutAction::TearFlag]
    );
    assert_eq!(worker.state(), HoldoutState::Reclaiming);
    assert_eq!(
        worker.on_event(HoldoutEvent::FlagTorn),
        vec![HoldoutAction::BootFull]
    );
    assert_eq!(worker.on_event(HoldoutEvent::BootFullComplete), vec![]);
    assert_eq!(worker.state(), HoldoutState::Full);
    assert!(worker.is_terminal());
}

// ----------------------------------------------------------------
// 9. FUZZ: 4096 adversarial events per seed per machine, no panic,
//    every landing state reachable.
// ----------------------------------------------------------------

#[test]
fn fuzz_never_panics_and_never_leaves_the_reachable_set() {
    let predecessor_events = predecessor_events();
    let successor_events = successor_events();
    let holdout_events = holdout_events();
    for seed in 1..=16u64 {
        let (actions, refusals) = fuzz(
            PredecessorMachine::new(RunId(seed)),
            &predecessor_events,
            seed,
        );
        assert!(actions + refusals > 0, "a fuzz run emitted nothing");
        let (actions, refusals) = fuzz(SuccessorMachine::new(RunId(seed)), &successor_events, seed);
        assert!(actions + refusals > 0);
        let (actions, refusals) = fuzz(HoldoutMachine::new(RunId(seed)), &holdout_events, seed);
        assert!(actions + refusals > 0);
    }
}

// ----------------------------------------------------------------
// 10. RESET: a fresh incarnation clears state and refusals, keeps
//     the run id.
// ----------------------------------------------------------------

#[test]
fn reset_gives_a_fresh_incarnation() {
    let mut worker = HoldoutMachine::new(RunId(9));
    worker.on_event(HoldoutEvent::MarkInherited);
    worker.on_event(HoldoutEvent::FlagTorn); // refused: unlawful in Born
    assert_eq!(worker.refusals().len(), 1);
    worker.reset();
    assert_eq!(worker.state(), HoldoutState::Born);
    assert!(worker.refusals().is_empty());
    assert_eq!(worker.run(), RunId(9));
}

// ----------------------------------------------------------------
// 11. THE ENVELOPE: generic message carries any kind + payload.
// ----------------------------------------------------------------

#[test]
fn the_message_envelope_is_transport_agnostic() {
    let message: Message<&'static str, Vec<u8>> = Message {
        run: RunId(11),
        epoch: 2,
        from: Role::Successor,
        to: Role::Predecessor,
        kind: "cutover-ready",
        payload: b"main-pid 320460".to_vec(),
    };
    assert_eq!(message.from, Role::Successor);
    assert_eq!(message.to, Role::Predecessor);
    // Display never renders the payload (it may be bytes).
    let rendered = format!("{message}");
    assert!(rendered.contains("cutover-ready"));
    assert!(!rendered.contains("main-pid"));
}

// ----------------------------------------------------------------
// 12. THE MESSAGE DOOR: role routing, the run fence, the epoch
//     fence — one entry point answers all three.
// ----------------------------------------------------------------

#[test]
fn the_message_door_routes_by_role_and_fences_the_run() {
    // Addressed to another role: the machine never saw the event.
    let mut predecessor = PredecessorMachine::new(RunId(5));
    let not_mine = Message {
        run: RunId(5),
        epoch: 0,
        from: Role::Supervisor,
        to: Role::Successor,
        kind: PredecessorEvent::SuccessorLaunched,
        payload: (),
    };
    assert!(predecessor.on_message(not_mine).is_none());
    assert!(
        predecessor.refusals().is_empty(),
        "a message for another role touched this machine"
    );

    // Another run's id: recorded ForeignRun, no move, no actions.
    let foreign = Message {
        run: RunId(999),
        epoch: 0,
        from: Role::Successor,
        to: Role::Predecessor,
        kind: PredecessorEvent::CutoverMarkerIn,
        payload: (),
    };
    assert_eq!(predecessor.on_message(foreign), Some(Vec::new()));
    assert_eq!(predecessor.state(), PredecessorState::Serving);
    assert_eq!(
        predecessor.refusals().last().unwrap().reason,
        RefusalReason::ForeignRun
    );

    // This run, a lawful event: the law answers with owed actions.
    let mine = Message {
        run: RunId(5),
        epoch: 0,
        from: Role::Successor,
        to: Role::Predecessor,
        kind: PredecessorEvent::StagedReleaseAdopted,
        payload: (),
    };
    assert_eq!(predecessor.on_message(mine), Some(Vec::new()));
    assert_eq!(predecessor.state(), PredecessorState::PipelineStarted);

    // A superseded epoch: StaleEpoch, refused before the law.
    let ghost = Message {
        run: RunId(5),
        epoch: 7,
        from: Role::Successor,
        to: Role::Predecessor,
        kind: PredecessorEvent::SuccessorDied,
        payload: (),
    };
    assert_eq!(predecessor.on_message(ghost), Some(Vec::new()));
    assert_eq!(
        predecessor.refusals().last().unwrap().reason,
        RefusalReason::StaleEpoch
    );
    assert_eq!(predecessor.state(), PredecessorState::PipelineStarted);
}
