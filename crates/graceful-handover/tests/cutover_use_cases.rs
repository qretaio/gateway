//! The defensive use-case suite: every production road the wisolate
//! host drives, scripted END TO END through the machines with the
//! owed actions performed into a plain world-state struct. These are
//! the scenarios prod actually runs (ladders 5 through 12): the
//! happy ladder, the rollback at every point a twin can die, the
//! blue-green soak, every settle road (fork, follow, none, kept),
//! the holdout worker's boot/arm/ride/reclaim/retire roads, and the
//! full two-machine conversation over the message door. The host
//! here is a struct of booleans — the REAL host is tokio, sockets,
//! and children; the machines cannot tell the difference, and that
//! is the point.

use graceful_handover::cutover::{
    HoldoutAction, HoldoutEvent, HoldoutMachine, HoldoutState, Message, PredecessorAction,
    PredecessorEvent, PredecessorMachine, PredecessorState, RefusalReason, Role, RunEvent, RunId,
    StateMachine, SuccessorAction, SuccessorEvent, SuccessorMachine, SuccessorState,
};

/// The predecessor's world: the flags the REAL host sets when it
/// performs each owed action.
#[derive(Default, Debug, PartialEq, Eq)]
struct PredecessorWorld {
    marker_watch_armed: bool,
    drained: bool,
    grace_ran: bool,
    alive_probe_done: bool,
    holdouts_settled: bool,
    port_released: bool,
    wants_shutdown_asked: bool,
    pipeline_torn: bool,
    soak_rolled_back: bool,
    supervising: bool,
    exited: bool,
}

/// Perform the owed actions like the host does: each action's side
/// effects, in the order the machine owed them.
fn perform(world: &mut PredecessorWorld, owed: &[PredecessorAction]) {
    for action in owed {
        match action {
            PredecessorAction::WatchCutoverMarker => world.marker_watch_armed = true,
            PredecessorAction::StartDrain => world.drained = true,
            PredecessorAction::SuperviseSuccessor => world.supervising = true,
            PredecessorAction::StartGrace => world.grace_ran = true,
            PredecessorAction::VerifySuccessorAlive => world.alive_probe_done = true,
            PredecessorAction::SettleHoldouts => world.holdouts_settled = true,
            PredecessorAction::ReleasePort => world.port_released = true,
            PredecessorAction::RequestWantsShutdown => world.wants_shutdown_asked = true,
            PredecessorAction::TearUpPipeline => {
                // The rollback undoes the drain posture — the apps
                // come home — and re-opens the pipeline latch.
                world.drained = false;
                world.pipeline_torn = true;
                world.marker_watch_armed = false;
            }
            PredecessorAction::RollbackSoak => {
                // A soak never drained; the compute returns, the
                // posture never moved.
                world.soak_rolled_back = true;
                world.supervising = false;
            }
        }
    }
}

fn drive(world: &mut PredecessorWorld, machine: &mut PredecessorMachine, event: PredecessorEvent) {
    let owed = machine.on_event(event);
    perform(world, &owed);
}

// ----------------------------------------------------------------
// USE CASE 1: the prod ladder, happy path, end to end.
// ----------------------------------------------------------------

#[test]
fn the_prod_ladder_lands_every_posture_in_order() {
    let mut machine = PredecessorMachine::new(RunId(100));
    let mut world = PredecessorWorld::default();

    // The deploy watch's probe saw staged bytes differing; the host
    // renames them over this binary FIRST, then tells the machine.
    drive(
        &mut world,
        &mut machine,
        PredecessorEvent::StagedReleaseAdopted,
    );
    assert_eq!(machine.state(), PredecessorState::PipelineStarted);

    // The twin launched: the marker watch arms AND the drain opens,
    // both owed at launch.
    drive(
        &mut world,
        &mut machine,
        PredecessorEvent::SuccessorLaunched,
    );
    assert!(world.marker_watch_armed, "the marker watch armed at LAUNCH");
    assert!(world.drained, "the drain posture opened at LAUNCH");

    // The twin's marker lands: grace first.
    drive(&mut world, &mut machine, PredecessorEvent::CutoverMarkerIn);
    assert!(world.grace_ran);

    // The grace ends: the twin must prove it lives BEFORE the
    // settle.
    drive(&mut world, &mut machine, PredecessorEvent::GraceElapsed);
    assert!(world.alive_probe_done);
    assert!(
        !world.holdouts_settled,
        "the settle waits for the alive answer"
    );

    // The probe came back alive: settle.
    drive(&mut world, &mut machine, PredecessorEvent::SuccessorHealthy);
    assert!(world.holdouts_settled);

    // The holdout question answered with the port leaving: the port
    // drops, then the shutdown ask — in this order, MAINPID already
    // moved.
    drive(&mut world, &mut machine, PredecessorEvent::HoldoutsReleased);
    assert!(world.port_released);
    assert!(world.wants_shutdown_asked);
    assert_eq!(machine.state(), PredecessorState::Released);

    // The exit lands: Done.
    drive(&mut world, &mut machine, PredecessorEvent::Exited);
    assert_eq!(machine.state(), PredecessorState::Done);
    assert!(machine.is_terminal());
    assert!(
        machine.refusals().is_empty(),
        "the whole prod ladder lawfired without one refusal"
    );
}

// ----------------------------------------------------------------
// USE CASE 2: the twin dies mid-pipeline — the 0.2.38 rollback, the
// ghost refusals, and the SECOND ladder on the same machine.
// ----------------------------------------------------------------

#[test]
fn a_mid_pipeline_death_rolls_back_and_the_re_ladder_completes() {
    let mut machine = PredecessorMachine::new(RunId(101));
    let mut world = PredecessorWorld::default();

    drive(
        &mut world,
        &mut machine,
        PredecessorEvent::StagedReleaseAdopted,
    );
    drive(
        &mut world,
        &mut machine,
        PredecessorEvent::SuccessorLaunched,
    );
    assert!(world.drained, "the ladder drained at launch");

    // The twin died before the marker.
    drive(&mut world, &mut machine, PredecessorEvent::SuccessorDied);
    assert_eq!(machine.state(), PredecessorState::Serving);
    assert_eq!(machine.epoch(), 1, "the rollback rebased the run");
    assert!(
        world.pipeline_torn,
        "the pipeline tore up: forwards returned, latch reopened"
    );
    assert!(
        !world.drained,
        "the drain posture UNDRAINED — the apps come home"
    );
    assert!(!world.marker_watch_armed, "the dead watch disarmed");

    // A ghost from the dead generation: the late marker — refused.
    let owed = machine.on_run_event(RunEvent::new(0, PredecessorEvent::CutoverMarkerIn));
    assert!(owed.is_empty());
    assert_eq!(machine.refusals()[0].reason, RefusalReason::StaleEpoch);

    // The SECOND ladder runs on the same machine, at epoch 1.
    drive(
        &mut world,
        &mut machine,
        PredecessorEvent::StagedReleaseAdopted,
    );
    drive(
        &mut world,
        &mut machine,
        PredecessorEvent::SuccessorLaunched,
    );
    assert!(world.drained, "the re-ladder drains again");
    drive(&mut world, &mut machine, PredecessorEvent::CutoverMarkerIn);
    drive(&mut world, &mut machine, PredecessorEvent::GraceElapsed);
    drive(&mut world, &mut machine, PredecessorEvent::SuccessorHealthy);
    drive(&mut world, &mut machine, PredecessorEvent::HoldoutsReleased);
    drive(&mut world, &mut machine, PredecessorEvent::Exited);
    assert_eq!(machine.state(), PredecessorState::Done);
    assert_eq!(machine.epoch(), 1, "the happy re-ladder never bumped again");
    assert!(world.port_released && world.wants_shutdown_asked);
}

// ----------------------------------------------------------------
// USE CASE 3: the twin dies after CUTOVER CONFIRMED but inside the
// grace — still a rollback; the alive gate NEVER opens onto a
// corpse.
// ----------------------------------------------------------------

#[test]
fn a_death_at_any_holding_point_is_a_rollback() {
    for (stage, setup) in [
        (
            "mid-pipeline",
            0usize, // death right after the launch
        ),
        (
            "post-marker",
            1usize, // death after the marker, before the grace ended
        ),
        (
            "inside the grace",
            2usize, // death after GraceElapsed, before the probe answered
        ),
        (
            "after control-kept",
            3usize, // the settle kept control; the twin died while supervised
        ),
    ] {
        let mut machine = PredecessorMachine::new(RunId(102));
        let mut world = PredecessorWorld::default();
        drive(
            &mut world,
            &mut machine,
            PredecessorEvent::StagedReleaseAdopted,
        );
        drive(
            &mut world,
            &mut machine,
            PredecessorEvent::SuccessorLaunched,
        );
        if setup >= 1 {
            drive(&mut world, &mut machine, PredecessorEvent::CutoverMarkerIn);
        }
        if setup >= 2 {
            drive(&mut world, &mut machine, PredecessorEvent::GraceElapsed);
        }
        if setup >= 3 {
            drive(&mut world, &mut machine, PredecessorEvent::SuccessorHealthy);
            drive(&mut world, &mut machine, PredecessorEvent::ControlKept);
            assert!(
                world.supervising,
                "control-kept owes supervision (stage: {stage})"
            );
        }
        drive(&mut world, &mut machine, PredecessorEvent::SuccessorDied);
        assert_eq!(
            machine.state(),
            PredecessorState::Serving,
            "a death at {stage} rolls back to Serving"
        );
        assert_eq!(machine.epoch(), 1, "a death at {stage} rebases the run");
        assert!(
            world.pipeline_torn,
            "a death at {stage} tears the pipeline up"
        );
        assert!(
            !world.drained,
            "a death at {stage} undrains — nothing the twin took stays taken"
        );
    }
}

// ----------------------------------------------------------------
// USE CASE 4: the blue-green soak — no drain, no marker, and the
// compute rolls back on death WITHOUT ever touching the posture.
// ----------------------------------------------------------------

#[test]
fn the_soak_never_drains_and_rolls_back_compute() {
    let mut machine = PredecessorMachine::new(RunId(103));
    let mut world = PredecessorWorld::default();

    drive(
        &mut world,
        &mut machine,
        PredecessorEvent::StagedReleaseAdopted,
    );
    drive(&mut world, &mut machine, PredecessorEvent::SoakLaunched);
    assert_eq!(machine.state(), PredecessorState::Soaking);
    assert!(
        world.supervising,
        "the soak road supervises the twin's compute"
    );
    assert!(
        !world.drained,
        "the soak NEVER drained — the predecessor keeps the port and serves beside the twin"
    );
    assert!(
        !world.marker_watch_armed,
        "no marker is coming; no watch is armed"
    );

    // A marker would be nonsense mid-soak — refused honestly.
    let owed = machine.on_event(PredecessorEvent::CutoverMarkerIn);
    assert!(owed.is_empty());
    assert_eq!(machine.state(), PredecessorState::Soaking);
    assert_eq!(
        machine.refusals().last().unwrap().reason,
        RefusalReason::IllegalTransition
    );

    // The soak twin dies: compute returns, posture untouched.
    drive(&mut world, &mut machine, PredecessorEvent::SuccessorDied);
    assert_eq!(machine.state(), PredecessorState::Serving);
    assert_eq!(machine.epoch(), 1);
    assert!(world.soak_rolled_back);
    assert!(
        !world.pipeline_torn,
        "the soak rollback is not a pipeline tear"
    );
    assert!(
        !world.drained,
        "the posture never moved, so nothing to undrain"
    );
}

// ----------------------------------------------------------------
// USE CASE 5: the settle roads. The fork-once decision and the
// retire request are the HOST's; the machine answers whichever road
// the host reports.
// ----------------------------------------------------------------

#[test]
fn the_settle_roads_answer_as_the_host_reports_them() {
    // Road A: holdouts forked fresh, release accepted.
    {
        let mut machine = PredecessorMachine::new(RunId(104));
        let mut world = PredecessorWorld::default();
        drive(
            &mut world,
            &mut machine,
            PredecessorEvent::StagedReleaseAdopted,
        );
        drive(
            &mut world,
            &mut machine,
            PredecessorEvent::SuccessorLaunched,
        );
        drive(&mut world, &mut machine, PredecessorEvent::CutoverMarkerIn);
        drive(&mut world, &mut machine, PredecessorEvent::GraceElapsed);
        drive(&mut world, &mut machine, PredecessorEvent::SuccessorHealthy);
        drive(&mut world, &mut machine, PredecessorEvent::HoldoutsReleased);
        assert_eq!(machine.state(), PredecessorState::Released);
        assert!(world.port_released && world.wants_shutdown_asked);
    }
    // Road B: no holdouts this ladder + retire declined → control
    // stays; the twin's death is still this node's problem.
    {
        let mut machine = PredecessorMachine::new(RunId(105));
        let mut world = PredecessorWorld::default();
        drive(
            &mut world,
            &mut machine,
            PredecessorEvent::StagedReleaseAdopted,
        );
        drive(
            &mut world,
            &mut machine,
            PredecessorEvent::SuccessorLaunched,
        );
        drive(&mut world, &mut machine, PredecessorEvent::CutoverMarkerIn);
        drive(&mut world, &mut machine, PredecessorEvent::GraceElapsed);
        drive(&mut world, &mut machine, PredecessorEvent::SuccessorHealthy);
        drive(&mut world, &mut machine, PredecessorEvent::ControlKept);
        assert_eq!(machine.state(), PredecessorState::Draining);
        assert!(
            world.supervising,
            "control-kept keeps supervising the promoted twin"
        );
        assert!(
            !world.port_released && !world.wants_shutdown_asked,
            "control-kept NEVER releases"
        );
        // The promoted twin dies later: rollback, control was ours.
        drive(&mut world, &mut machine, PredecessorEvent::SuccessorDied);
        assert_eq!(machine.state(), PredecessorState::Serving);
        assert!(world.pipeline_torn);
    }
    // Road C: settle refused honestly (no data dir for the flag) —
    // the host reports ControlKept too; same law.
    {
        let mut machine = PredecessorMachine::new(RunId(106));
        let mut world = PredecessorWorld::default();
        drive(
            &mut world,
            &mut machine,
            PredecessorEvent::StagedReleaseAdopted,
        );
        drive(
            &mut world,
            &mut machine,
            PredecessorEvent::SuccessorLaunched,
        );
        drive(&mut world, &mut machine, PredecessorEvent::CutoverMarkerIn);
        drive(&mut world, &mut machine, PredecessorEvent::GraceElapsed);
        drive(&mut world, &mut machine, PredecessorEvent::SuccessorHealthy);
        drive(&mut world, &mut machine, PredecessorEvent::ControlKept);
        assert_eq!(machine.state(), PredecessorState::Draining);
        assert!(machine.refusals().is_empty(), "the kept road is LAWFUL");
    }
}

// ----------------------------------------------------------------
// USE CASE 6: the full two-machine PROD CONVERSATION driven ONLY
// through the message door — role routing, the run fence, and the
// epoch fence all green, zero refusals.
// ----------------------------------------------------------------

#[test]
fn the_prod_conversation_rides_the_message_door() {
    let run = RunId(200);
    let mut predecessor = PredecessorMachine::new(run);
    let mut successor = SuccessorMachine::new(run);
    let mut world = PredecessorWorld::default();

    // (the closure soup above is deliberate noise; the real walk
    // starts here) — the twin names itself and exchanges.
    let named = Message {
        run,
        epoch: 0,
        from: Role::Successor,
        to: Role::Successor,
        kind: SuccessorEvent::NamedItself,
        payload: (),
    };
    assert_eq!(successor.on_message(named), Some(Vec::new()));
    let exchanged = Message {
        run,
        epoch: 0,
        from: Role::Predecessor,
        to: Role::Successor,
        kind: SuccessorEvent::BootstrapExchangeComplete,
        payload: (),
    };
    assert_eq!(successor.on_message(exchanged), Some(Vec::new()));
    let ladder = Message {
        run,
        epoch: 0,
        from: Role::Predecessor,
        to: Role::Successor,
        kind: SuccessorEvent::LadderStarted,
        payload: (),
    };
    assert_eq!(successor.on_message(ladder), Some(Vec::new()));

    // The rename lands first (the deploy watch adopted the staged
    // bytes), THEN the predecessor hears the launch through the
    // door: watch + drain owed.
    let adopted = Message {
        run,
        epoch: 0,
        from: Role::Predecessor,
        to: Role::Predecessor,
        kind: PredecessorEvent::StagedReleaseAdopted,
        payload: (),
    };
    assert_eq!(predecessor.on_message(adopted), Some(Vec::new()));
    assert_eq!(predecessor.state(), PredecessorState::PipelineStarted);
    let launched = Message {
        run,
        epoch: 0,
        from: Role::Successor,
        to: Role::Predecessor,
        kind: PredecessorEvent::SuccessorLaunched,
        payload: (),
    };
    let owed = predecessor.on_message(launched).expect("addressed to us");
    perform(&mut world, &owed);
    assert!(world.drained && world.marker_watch_armed);

    // CUTOVER READY rides to the predecessor; the grace runs.
    let ready = Message {
        run,
        epoch: 0,
        from: Role::Successor,
        to: Role::Predecessor,
        kind: PredecessorEvent::CutoverMarkerIn,
        payload: (),
    };
    let owed = predecessor.on_message(ready).expect("addressed to us");
    perform(&mut world, &owed);
    assert!(world.grace_ran);

    // Grace elapsed + alive + settled + released — all through the
    // door.
    for event in [
        PredecessorEvent::GraceElapsed,
        PredecessorEvent::SuccessorHealthy,
        PredecessorEvent::HoldoutsReleased,
    ] {
        let message = Message {
            run,
            epoch: 0,
            from: Role::Successor,
            to: Role::Predecessor,
            kind: event,
            payload: (),
        };
        let owed = predecessor.on_message(message).expect("addressed to us");
        perform(&mut world, &owed);
    }
    assert_eq!(predecessor.state(), PredecessorState::Released);

    // Meanwhile the take ladder finished on the twin's side: every
    // movable app moved, CUTOVER READY announced, MAINPID accepted.
    let ready = Message {
        run,
        epoch: 0,
        from: Role::Successor,
        to: Role::Successor,
        kind: SuccessorEvent::AllMovableMoved,
        payload: (),
    };
    assert_eq!(
        successor.on_message(ready),
        Some(vec![
            SuccessorAction::AnnounceCutoverReady,
            SuccessorAction::AnnounceMainPid
        ])
    );
    let accepted = Message {
        run,
        epoch: 0,
        from: Role::Supervisor,
        to: Role::Successor,
        kind: SuccessorEvent::MainPidAccepted,
        payload: (),
    };
    assert_eq!(successor.on_message(accepted), Some(Vec::new()));

    // The successor lands the port: Full.
    let landed = Message {
        run,
        epoch: 0,
        from: Role::Predecessor,
        to: Role::Successor,
        kind: SuccessorEvent::PortLanded,
        payload: (),
    };
    assert_eq!(successor.on_message(landed), Some(Vec::new()));
    assert_eq!(successor.state(), SuccessorState::Full);

    let exited = Message {
        run,
        epoch: 0,
        from: Role::Successor,
        to: Role::Predecessor,
        kind: PredecessorEvent::Exited,
        payload: (),
    };
    assert_eq!(predecessor.on_message(exited), Some(Vec::new()));
    assert_eq!(predecessor.state(), PredecessorState::Done);
    assert!(predecessor.refusals().is_empty());
    assert!(successor.refusals().is_empty());
}

// ----------------------------------------------------------------
// USE CASE 7: the successor's take ladder — announce order, the
// refused-MAINPID road, and progress lawfulness.
// ----------------------------------------------------------------

#[test]
fn the_take_ladder_announces_ready_then_mainpid() {
    let mut machine = SuccessorMachine::new(RunId(300));

    assert_eq!(machine.on_event(SuccessorEvent::NamedItself), vec![]);
    assert_eq!(
        machine.on_event(SuccessorEvent::BootstrapExchangeComplete),
        vec![]
    );
    assert_eq!(machine.state(), SuccessorState::Exchanged);
    assert_eq!(machine.on_event(SuccessorEvent::LadderStarted), vec![]);
    assert_eq!(machine.state(), SuccessorState::Taking);

    // Progress is lawful, owes nothing.
    for _ in 0..5 {
        assert_eq!(machine.on_event(SuccessorEvent::LeaseTaken), vec![]);
        assert_eq!(machine.on_event(SuccessorEvent::AppMoved), vec![]);
    }

    // ALL MOVABLE MOVED: CUTOVER READY, then MAINPID — the 0.2.73
    // order that keeps the supervisor from reading the release as a
    // service death.
    assert_eq!(
        machine.on_event(SuccessorEvent::AllMovableMoved),
        vec![
            SuccessorAction::AnnounceCutoverReady,
            SuccessorAction::AnnounceMainPid
        ]
    );
    assert_eq!(machine.state(), SuccessorState::CutoverReady);

    // A refused MAINPID anchor is guidance, not a state change: the
    // supervisor's restart road still serves, the take keeps
    // walking — PortLanded ends the ladder WITHOUT the accept.
    assert_eq!(machine.on_event(SuccessorEvent::PortLanded), vec![]);
    assert_eq!(machine.state(), SuccessorState::Full);
    assert!(machine.is_terminal());
    assert!(machine.refusals().is_empty());
}

// ----------------------------------------------------------------
// USE CASE 8: the holdout worker's roads — fork-child, flag-found,
// boot-stale, flag-gone, and the kill sweep.
// ----------------------------------------------------------------

#[test]
fn the_worker_roads_end_where_prod_puts_them() {
    // Road 1: the fork child (the mark rode the ENV).
    {
        let mut worker = HoldoutMachine::new(RunId(400));
        assert_eq!(worker.on_event(HoldoutEvent::MarkInherited), vec![]);
        assert_eq!(worker.on_event(HoldoutEvent::ScopedLoadDone), vec![]);
        assert_eq!(worker.state(), HoldoutState::Scoped);
        assert_eq!(worker.on_event(HoldoutEvent::MeshOn), vec![]);
        let owed = worker.on_event(HoldoutEvent::FlagSuccessorKnown);
        assert_eq!(owed, vec![HoldoutAction::ArmRideHome]);
        assert_eq!(worker.state(), HoldoutState::Armed);
        assert_eq!(
            worker.on_event(HoldoutEvent::BindingProviderMiss),
            vec![HoldoutAction::RideHome]
        );
    }
    // Road 2: the flag found on a plain boot (the supervisor-restart
    // road) — the same law from the other boot fact.
    {
        let mut worker = HoldoutMachine::new(RunId(401));
        assert_eq!(worker.on_event(HoldoutEvent::FlagFound), vec![]);
        assert_eq!(worker.on_event(HoldoutEvent::ScopedLoadDone), vec![]);
        assert_eq!(worker.on_event(HoldoutEvent::MeshOn), vec![]);
        assert_eq!(
            worker.on_event(HoldoutEvent::FlagSuccessorKnown),
            vec![HoldoutAction::ArmRideHome]
        );
    }
    // Road 3: boot-time stale — the flag names a DEAD successor; the
    // reclaim starts before the mesh attaches.
    {
        let mut worker = HoldoutMachine::new(RunId(402));
        assert_eq!(worker.on_event(HoldoutEvent::FlagFound), vec![]);
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
    }
    // Road 4: the flag vanished — the holdouts came home; retire.
    for state in [
        HoldoutState::Scoped,
        HoldoutState::MeshAttached,
        HoldoutState::Armed,
    ] {
        let mut worker = HoldoutMachine::new(RunId(403));
        worker.set_state(state);
        assert_eq!(
            worker.on_event(HoldoutEvent::FlagGone),
            vec![],
            "retiring on a gone flag owes nothing ({state:?})"
        );
        assert_eq!(worker.state(), HoldoutState::Retired);
        assert!(worker.is_terminal());
    }
    // Road 5: the operator kills the worker (fork-once retirement) —
    // from every live state.
    for state in [
        HoldoutState::Born,
        HoldoutState::Scoped,
        HoldoutState::MeshAttached,
        HoldoutState::Armed,
    ] {
        let mut worker = HoldoutMachine::new(RunId(404));
        worker.set_state(state);
        assert_eq!(worker.on_event(HoldoutEvent::WorkerKilled), vec![]);
        assert_eq!(worker.state(), HoldoutState::Retired);
        assert!(worker.is_terminal());
    }
}

// ----------------------------------------------------------------
// USE CASE 9: the worker survives a chaotic tick stream (the watch
// loop's adversarial orderings) — re-arms, retries failed arms,
// and never fake-rides before armed.
// ----------------------------------------------------------------

#[test]
fn the_watch_loop_survives_chaotic_orderings() {
    let mut worker = HoldoutMachine::new(RunId(500));
    worker.on_event(HoldoutEvent::FlagFound);
    worker.on_event(HoldoutEvent::ScopedLoadDone);
    worker.on_event(HoldoutEvent::MeshOn);

    // Misses before the flag's successor is known: honest answers.
    assert_eq!(worker.on_event(HoldoutEvent::BindingProviderMiss), vec![]);
    assert_eq!(worker.on_event(HoldoutEvent::BindingProviderMiss), vec![]);
    assert_eq!(worker.state(), HoldoutState::MeshAttached);
    assert!(worker.refusals().is_empty());

    // Armed; the arm fails once — stay armed, retry at the next tick
    // (ChainRefreshDue stands in for the tick): the retry is lawful.
    assert_eq!(
        worker.on_event(HoldoutEvent::FlagSuccessorKnown),
        vec![HoldoutAction::ArmRideHome]
    );
    assert_eq!(worker.on_event(HoldoutEvent::ArmRideHomeFailed), vec![]);
    assert_eq!(
        worker.on_event(HoldoutEvent::ChainRefreshDue),
        vec![HoldoutAction::ArmRideHome]
    );
    assert_eq!(worker.state(), HoldoutState::Armed);

    // The flag flips to a new successor twice: every change re-arms.
    for _ in 0..2 {
        assert_eq!(
            worker.on_event(HoldoutEvent::FlagSuccessorChanged),
            vec![HoldoutAction::ArmRideHome]
        );
    }
    assert!(
        worker.refusals().is_empty(),
        "the whole chaotic watch rode without one refusal"
    );
}
