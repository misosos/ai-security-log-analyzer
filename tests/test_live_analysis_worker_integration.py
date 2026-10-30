"""Queue acknowledgement is the irreversible boundary for internal analysis."""

import pytest
from dataclasses import replace
import asyncio

from app.analyzer.pipeline import assess_risk_with_metadata, correlate_attacks, detect_attacks
from app.live_monitoring import (
    LiveDetectionAccumulator, LiveMonitorConfig, LiveProcessingWorker,
    open_live_tail_session,
)
from app.live_monitoring.analysis_accumulator import LiveAnalysisAccumulator
from app.live_monitoring import analysis_accumulator as analysis_module
from app.live_monitoring.publication import LivePublicationBuffer
from app.live_monitoring.worker import LiveWorkerError, LiveWorkerState
from app.live_monitoring import worker as worker_module
from app.live_monitoring.core import LiveTailSession
from app.live_monitoring.detection_accumulator import LiveDetectionAccumulator as DetectionType
from app.live_monitoring.runner import LiveMonitoringRunner, LiveRunnerState
from app.live_monitoring.service import LiveMonitoringService


def line(second, kind="login_failed"):
    return f"2026-01-02 03:04:{second:02d} INFO {kind} user=synthetic ip=192.0.2.11"


def setup(tmp_path, role="application", *, analysis=None):
    path = tmp_path / "synthetic.log"
    path.write_bytes(b"old line\n")
    session = open_live_tail_session(LiveMonitorConfig(role, path.resolve()))
    detector = LiveDetectionAccumulator(role, 256, 256 * 1024)
    if analysis is None and role == "application":
        analysis = LiveAnalysisAccumulator(detector, ())
    worker = LiveProcessingWorker(session, detector, 16, 4096,
                                  analysis_accumulator=analysis)
    if role == "ssh":
        analysis = worker._analysis
    return path, session, detector, analysis, worker


def append(path, *lines):
    with path.open("ab") as stream:
        stream.write(("\n".join(lines) + "\n").encode())


def fail(*_):
    raise RuntimeError("PRIVATE_INTERNAL_EXCEPTION")


def test_application_prefix_matches_batch_and_preserves_sse_shape(tmp_path):
    path, session, detection, analysis, worker = setup(tmp_path)
    try:
        assert worker.step().status == "NO_DATA"
        for index, entry in enumerate((line(1), line(2), line(3), line(4), line(5),
                                        line(6, "user_login")), 1):
            append(path, entry)
            result = worker.step()
            assert result.status == "PROCESSED"
            assert result.accumulator_revision == result.analysis_revision == index
            assert worker.snapshot().last_committed_revision == index
            assert worker.publication_buffer.snapshot().latest_committed_detection_revision == index
            assert detection._detection == detect_attacks(list(detection._history))
            from app.main import _analyze_normalized_logs_with_context

            oracle, _, _ = _analyze_normalized_logs_with_context(
                list(detection._history))
            assert analysis._state._results == oracle["results"]
            assert not session.snapshot().active_lease
            assert not analysis.snapshot().active_proposal
            assert worker.publication_buffer._active is None
        assert analysis.snapshot().relation_count >= 1
        assert analysis.snapshot().case_count >= 1
        published = worker.publication_buffer.replay_after(None).events
        assert all(event.event_type in {"DETECTION_CHANGE", "ANALYSIS_CHANGE"} for event in published)
        assert any(event.event_type == "ANALYSIS_CHANGE" for event in published)
        assert "192.0.2." not in repr(published)
    finally:
        worker.close()
    assert session._fd == -1
    assert analysis.snapshot().closed


def test_ignored_and_rejected_only_commit_empty_analysis_change(tmp_path):
    path, _, _, analysis, worker = setup(tmp_path)
    try:
        append(path, "   ", "malformed")
        result = worker.step()
        assert (result.ignored_count, result.rejected_count) == (1, 1)
        assert result.analysis_revision == 1
        assert analysis.latest_change_set().changes == ()
        assert worker.publication_buffer.snapshot().published_total == 0
    finally:
        worker.close()


def test_access_remains_detection_only(tmp_path):
    path, _, _, analysis, worker = setup(tmp_path, "access")
    try:
        assert analysis is None
        append(path, '192.0.2.11 - - [02/Jan/2026:03:04:05 +0900] "GET / HTTP/1.1" 200 1')
        result = worker.step()
        assert result.analysis_revision is None
        assert worker.snapshot().analysis is None
    finally:
        worker.close()


def test_wrong_binding_and_shared_analysis_rejected(tmp_path):
    path = tmp_path / "source.log"
    path.write_bytes(b"")
    session = open_live_tail_session(LiveMonitorConfig("application", path.resolve()))
    other = LiveDetectionAccumulator("application", 256, 256 * 1024)
    analysis = LiveAnalysisAccumulator(other, ())
    try:
        with pytest.raises(LiveWorkerError) as caught:
            LiveProcessingWorker(session, LiveDetectionAccumulator("application", 256, 256 * 1024),
                                 16, 4096, analysis_accumulator=analysis)
        assert caught.value.code == "INVALID_ANALYSIS_ACCUMULATOR"
    finally:
        session.close()
        analysis.close()


def test_same_analysis_cannot_bind_second_worker(tmp_path):
    path, _, detection, analysis, worker = setup(tmp_path)
    other = tmp_path / "other.log"
    other.write_bytes(b"")
    second = open_live_tail_session(LiveMonitorConfig("application", other.resolve()))
    try:
        with pytest.raises(LiveWorkerError) as caught:
            LiveProcessingWorker(second, detection, 16, 4096,
                                 analysis_accumulator=analysis)
        assert caught.value.code == "ACCUMULATOR_ALREADY_OWNED"
    finally:
        second.close()
        worker.close()


def test_non_application_rejects_analysis_binding(tmp_path):
    path = tmp_path / "ssh.log"
    path.write_bytes(b"")
    session = open_live_tail_session(LiveMonitorConfig("ssh", path.resolve()))
    application = LiveDetectionAccumulator("application", 256, 256 * 1024)
    analysis = LiveAnalysisAccumulator(application, ())
    try:
        with pytest.raises(LiveWorkerError) as caught:
            LiveProcessingWorker(session, LiveDetectionAccumulator("ssh", 256, 256 * 1024),
                                 16, 4096, analysis_accumulator=analysis)
        assert caught.value.code == "INVALID_ANALYSIS_ACCUMULATOR"
    finally:
        session.close()
        analysis.close()


def test_cross_proposal_mismatch_releases_before_ack(tmp_path, monkeypatch):
    path, session, detection, analysis, worker = setup(tmp_path)
    append(path, line(1))
    original = LivePublicationBuffer.prepare_batch

    def mismatched(instance, proposal, analysis_proposal):
        prepared = original(instance, proposal, analysis_proposal)
        from dataclasses import replace
        wrong = replace(prepared, revision=prepared.revision + 1)
        instance._active = wrong
        return wrong

    monkeypatch.setattr(LivePublicationBuffer, "prepare_batch", mismatched)
    try:
        with pytest.raises(LiveWorkerError):
            worker.step()
        assert session.snapshot().acknowledged_record_count == 0
        assert session.snapshot().available_item_count == 1
        assert detection.snapshot().revision == analysis.snapshot().revision == 0
    finally:
        worker.close()


def test_worker_safe_projection_excludes_trusted_canaries(tmp_path):
    path, _, _, _, worker = setup(tmp_path)
    account = "ACCOUNT_PRIVATE_CANARY"
    ip = "192.0.2.123"
    append(path, f"2026-01-02 03:04:01 INFO login_failed user={account} ip={ip}")
    try:
        result = worker.step()
        safe = repr(worker) + repr(result) + repr(worker.snapshot())
        assert account not in safe and ip not in safe
        assert "synthetic.log" not in safe
    finally:
        worker.close()


@pytest.mark.parametrize("stage,expected", (
    ("analysis", "ANALYSIS_PREPARE_FAILED"),
    ("publication", "PUBLICATION_PREPARE_FAILED"),
))
def test_pre_ack_failure_aborts_and_releases(tmp_path, monkeypatch, stage, expected):
    path, session, detection, analysis, worker = setup(tmp_path)
    append(path, line(1))
    target = LiveAnalysisAccumulator if stage == "analysis" else LivePublicationBuffer
    monkeypatch.setattr(target, "prepare" if stage == "analysis" else "prepare_batch", fail)
    try:
        with pytest.raises(LiveWorkerError) as caught:
            worker.step()
        assert caught.value.code == expected
        assert worker.snapshot().state is LiveWorkerState.DEGRADED
        assert session.snapshot().available_item_count == 1
        assert session.snapshot().acknowledged_record_count == 0
        assert detection.snapshot().revision == analysis.snapshot().revision == 0
        assert not detection.snapshot().active_proposal
        assert not analysis.snapshot().active_proposal
    finally:
        worker.close()


@pytest.mark.parametrize("name", (
    "group_logs_by_ip", "assess_risk_with_metadata",
    "assemble_incident_cases", "build_investigation_case_projection",
))
def test_each_analysis_compute_failure_is_pre_ack(tmp_path, monkeypatch, name):
    path, session, detection, analysis, worker = setup(tmp_path)
    append(path, line(1))
    monkeypatch.setattr(analysis_module, name, fail)
    try:
        with pytest.raises(LiveWorkerError) as caught:
            worker.step()
        assert caught.value.code == "ANALYSIS_PREPARE_FAILED"
        assert session.snapshot().available_item_count == 1
        assert session.snapshot().acknowledged_record_count == 0
        assert detection.snapshot().revision == analysis.snapshot().revision == 0
        assert "PRIVATE_INTERNAL_EXCEPTION" not in repr(caught.value)
    finally:
        worker.close()


@pytest.mark.parametrize("target", ("analysis", "publication"))
def test_prepare_return_boundary_does_not_leave_active_proposal(tmp_path, monkeypatch, target):
    path, session, detection, analysis, worker = setup(tmp_path)
    append(path, line(1))
    klass = LiveAnalysisAccumulator if target == "analysis" else LivePublicationBuffer
    method = "prepare" if target == "analysis" else "prepare_batch"
    original = getattr(klass, method)

    def installed_then_failed(instance, candidate, *extra):
        original(instance, candidate, *extra)
        fail()

    monkeypatch.setattr(klass, method, installed_then_failed)
    try:
        with pytest.raises(LiveWorkerError):
            worker.step()
        assert worker.snapshot().state is LiveWorkerState.DEGRADED
        assert session.snapshot().available_item_count == 1
        assert not detection.snapshot().active_proposal
        assert not analysis.snapshot().active_proposal
        assert worker.publication_buffer._active is None
    finally:
        worker.close()


def test_analysis_commit_failure_is_terminal_without_publication(tmp_path, monkeypatch):
    path, session, detection, analysis, worker = setup(tmp_path)
    append(path, line(1))
    monkeypatch.setattr(LiveAnalysisAccumulator, "_install_candidate", fail)
    try:
        with pytest.raises(LiveWorkerError) as caught:
            worker.step()
        assert caught.value.code == "ANALYSIS_COMMIT_FAILED_AFTER_DETECTION_COMMIT"
        assert "PRIVATE_INTERNAL_EXCEPTION" not in repr(caught.value)
        assert worker.snapshot().state is LiveWorkerState.FAILED
        assert detection.snapshot().revision == 1
        assert analysis.snapshot().revision == 0
        assert worker.snapshot().potentially_uncommitted_analysis_revision_count == 1
        assert worker.publication_buffer.snapshot().published_total == 0
        assert session.snapshot().acknowledged_record_count == 1
        assert session.snapshot().released_lease_count == 0
    finally:
        worker.close()


def test_publication_commit_failure_preserves_both_commits(tmp_path, monkeypatch):
    path, session, detection, analysis, worker = setup(tmp_path)
    append(path, *(line(index) for index in range(1, 6)))
    monkeypatch.setattr(LivePublicationBuffer, "commit_prepared", fail)
    try:
        with pytest.raises(LiveWorkerError) as caught:
            worker.step()
        assert caught.value.code == "PUBLICATION_FAILED_AFTER_ANALYSIS_COMMIT"
        assert detection.snapshot().revision == analysis.snapshot().revision == 1
        assert worker.snapshot().potentially_unpublished_revision_count == 1
        assert session.snapshot().acknowledged_record_count == 5
        assert session.snapshot().released_lease_count == 0
    finally:
        worker.close()


def test_ack_failure_aborts_analysis_without_guessing_release(tmp_path, monkeypatch):
    path, session, detection, analysis, worker = setup(tmp_path)
    append(path, line(1))
    monkeypatch.setattr(type(session), "acknowledge_lease", fail)
    try:
        with pytest.raises(LiveWorkerError) as caught:
            worker.step()
        assert caught.value.code == "ACK_FAILURE"
        assert worker.snapshot().state is LiveWorkerState.FAILED
        assert detection.snapshot().revision == analysis.snapshot().revision == 0
        assert not detection.snapshot().active_proposal
        assert not analysis.snapshot().active_proposal
        assert worker.publication_buffer._active is None
        assert session.snapshot().released_lease_count == 0
    finally:
        worker.close()


def test_analysis_abort_failure_is_terminal_and_does_not_ack(tmp_path, monkeypatch):
    path, session, detection, analysis, worker = setup(tmp_path)
    append(path, line(1))
    monkeypatch.setattr(LivePublicationBuffer, "prepare_batch", fail)
    monkeypatch.setattr(LiveAnalysisAccumulator, "abort", fail)
    try:
        with pytest.raises(LiveWorkerError) as caught:
            worker.step()
        assert caught.value.code == "ANALYSIS_ABORT_FAILED"
        assert worker.snapshot().state is LiveWorkerState.FAILED
        assert session.snapshot().acknowledged_record_count == 0
        assert detection.snapshot().revision == analysis.snapshot().revision == 0
    finally:
        worker.close()


def test_detection_commit_failure_does_not_commit_analysis(tmp_path, monkeypatch):
    path, session, detection, analysis, worker = setup(tmp_path)
    append(path, line(1))
    monkeypatch.setattr(LiveDetectionAccumulator, "commit_prepared", fail)
    try:
        with pytest.raises(LiveWorkerError) as caught:
            worker.step()
        assert caught.value.code == "DETECTION_COMMIT_FAILED_AFTER_ACK"
        assert worker.snapshot().state is LiveWorkerState.FAILED
        assert detection.snapshot().revision == analysis.snapshot().revision == 0
        assert session.snapshot().acknowledged_record_count == 1
        assert worker.publication_buffer.snapshot().published_total == 0
    finally:
        worker.close()


# Each ID is a distinct reachable boundary. The matrix deliberately checks the
# settled state, not just that an exception was raised.
_FAULT_POINTS = (
    "01_poll", "02_lease", "03_parse", "04_parse_batch_validation",
    "05_detection_prepare", "06_analysis_correlation_prepare",
    "07_analysis_risk_prepare", "08_analysis_case_prepare",
    "09_analysis_safe_projection", "10_publication_prepare",
    "11_cross_proposal_validation", "12_detection_abort",
    "13_analysis_abort", "14_lease_release", "15_queue_ack",
    "16_after_queue_ack", "17_detection_state_swap",
    "18_after_detection_commit", "19_analysis_state_swap",
    "20_after_analysis_commit", "21_publication_state_swap",
    "22_after_publication_commit", "23_worker_summary",
)


@pytest.mark.parametrize("role", ("application", "ssh"))
@pytest.mark.parametrize("point", _FAULT_POINTS, ids=_FAULT_POINTS)
def test_individual_fault_boundary(tmp_path, monkeypatch, point, role):
    path, session, detection, analysis, worker = setup(tmp_path, role)
    entries = (line(index) for index in range(1, 6)) if role == "application" else (
        f"2026-01-02 03:04:{index:02d} sshd: Failed password for synthetic "
        "from 192.0.2.11 port 5001 ssh2" for index in range(1, 6))
    append(path, *entries)
    calls = {"ack": 0, "release": 0}
    original_ack = LiveTailSession.acknowledge_lease
    original_release = LiveTailSession.release_lease

    def ack(instance, lease):
        calls["ack"] += 1
        if point == "15_queue_ack":
            fail()
        value = original_ack(instance, lease)
        if point == "16_after_queue_ack":
            fail()
        return value

    def release(instance, lease):
        calls["release"] += 1
        if point == "14_lease_release":
            fail()
        return original_release(instance, lease)

    monkeypatch.setattr(LiveTailSession, "acknowledge_lease", ack)
    monkeypatch.setattr(LiveTailSession, "release_lease", release)

    if point == "01_poll":
        monkeypatch.setattr(LiveTailSession, "poll_once", fail)
    elif point == "02_lease":
        monkeypatch.setattr(LiveTailSession, "lease_records", fail)
    elif point in ("03_parse", "14_lease_release"):
        monkeypatch.setattr(worker_module, "parse_live_records", fail)
    elif point == "04_parse_batch_validation":
        monkeypatch.setattr(worker_module, "_validate_batch", fail)
    elif point == "05_detection_prepare":
        monkeypatch.setattr(DetectionType, "prepare", fail)
    elif point == "06_analysis_correlation_prepare":
        monkeypatch.setattr(analysis_module, "group_logs_by_ip", fail)
    elif point == "07_analysis_risk_prepare":
        monkeypatch.setattr(analysis_module, "assess_risk_with_metadata", fail)
    elif point == "08_analysis_case_prepare":
        monkeypatch.setattr(analysis_module, "assemble_incident_cases", fail)
    elif point == "09_analysis_safe_projection":
        monkeypatch.setattr(analysis_module, "build_investigation_case_projection", fail)
    elif point in ("10_publication_prepare", "12_detection_abort", "13_analysis_abort"):
        monkeypatch.setattr(LivePublicationBuffer, "prepare_batch", fail)
        if point == "12_detection_abort":
            monkeypatch.setattr(DetectionType, "abort", fail)
        if point == "13_analysis_abort":
            monkeypatch.setattr(LiveAnalysisAccumulator, "abort", fail)
    elif point == "11_cross_proposal_validation":
        original = LivePublicationBuffer.prepare_batch

        def mismatch(instance, proposal, analysis_proposal):
            prepared = original(instance, proposal, analysis_proposal)
            wrong = replace(prepared, revision=prepared.revision + 1)
            instance._active = wrong
            return wrong

        monkeypatch.setattr(LivePublicationBuffer, "prepare_batch", mismatch)
    elif point in ("17_detection_state_swap", "18_after_detection_commit"):
        original = DetectionType.commit_prepared

        def detection_commit(instance, proposal):
            if point == "17_detection_state_swap":
                fail()
            result = original(instance, proposal)
            fail()
            return result

        monkeypatch.setattr(DetectionType, "commit_prepared", detection_commit)
    elif point == "19_analysis_state_swap":
        monkeypatch.setattr(LiveAnalysisAccumulator, "_install_candidate", fail)
    elif point == "20_after_analysis_commit":
        original = LiveAnalysisAccumulator.commit

        def analysis_commit(instance, proposal):
            original(instance, proposal)
            fail()

        monkeypatch.setattr(LiveAnalysisAccumulator, "commit", analysis_commit)
    elif point in ("21_publication_state_swap", "22_after_publication_commit"):
        original = LivePublicationBuffer.commit_prepared

        def publication_commit(instance, proposal):
            if point == "21_publication_state_swap":
                fail()
            result = original(instance, proposal)
            fail()
            return result

        monkeypatch.setattr(LivePublicationBuffer, "commit_prepared", publication_commit)
    elif point == "23_worker_summary":
        original = LiveProcessingWorker._transition

        def transition(instance, state):
            if state is LiveWorkerState.READY and instance._state is LiveWorkerState.RUNNING_STEP:
                fail()
            return original(instance, state)

        monkeypatch.setattr(LiveProcessingWorker, "_transition", transition)

    # Fault patches above are scoped to the test; cleanup below needs the
    # real close path, so undo after the assertions.
    try:
            with pytest.raises(LiveWorkerError) as caught:
                worker.step()
            snapshot = worker.snapshot()
            queue = session.snapshot()
            detection_revision = detection.snapshot().revision
            analysis_revision = analysis.snapshot().revision
            # The safe snapshot mirrors detection's committed revision even
            # before publication settles; inspect the trusted buffer cursor.
            publication_revision = worker.publication_buffer._state.latest_revision
            stage = int(point[:2])
            expected_code = (
                "POLL_FAILURE" if stage == 1 else
                "LEASE_FAILURE" if stage == 2 else
                "PROCESSING_FAILURE" if stage <= 5 else
                "ANALYSIS_PREPARE_FAILED" if stage <= 9 else
                "PUBLICATION_PREPARE_FAILED" if stage == 10 else
                "ANALYSIS_PROPOSAL_MISMATCH" if stage == 11 else
                "PROPOSAL_ABORT_FAILURE" if stage == 12 else
                "ANALYSIS_ABORT_FAILED" if stage == 13 else
                "OWNERSHIP_FAILURE" if stage == 14 else
                "ACK_FAILURE" if stage == 15 else
                "DETECTION_COMMIT_FAILED_AFTER_ACK" if stage <= 18 else
                "ANALYSIS_COMMIT_FAILED_AFTER_DETECTION_COMMIT" if stage <= 20 else
                "PUBLICATION_FAILED_AFTER_ANALYSIS_COMMIT" if stage <= 22 else
                "WORKER_AGGREGATE_FAILED_AFTER_PUBLICATION"
            )
            assert caught.value.code == expected_code
            assert snapshot.fixed_error_code == expected_code
            if stage == 1:
                assert (calls["ack"], calls["release"], queue.queue_item_count) == (0, 0, 0)
                assert snapshot.state is LiveWorkerState.FAILED
                assert queue.state == "RUNNING" and not queue.active_lease
            elif stage == 2:
                assert (calls["ack"], calls["release"], queue.available_item_count) == (0, 0, 5)
                assert snapshot.state is LiveWorkerState.FAILED
                assert queue.state == "RUNNING" and not queue.active_lease
            elif stage <= 11:
                assert (calls["ack"], calls["release"], queue.available_item_count) == (0, 1, 5)
                assert not queue.active_lease
                assert queue.state == "RUNNING" and queue.leased_item_count == 0
                assert snapshot.state is LiveWorkerState.DEGRADED
                assert not detection.snapshot().active_proposal
                assert not analysis.snapshot().active_proposal
                assert worker.publication_buffer._active is None
                with pytest.raises(LiveWorkerError):
                    worker.step()
                worker.resume_after_degraded()
                assert worker.snapshot().state is LiveWorkerState.READY
            elif stage <= 14:
                assert calls == {"ack": 0, "release": 0 if stage < 14 else 1}
                assert snapshot.state is LiveWorkerState.FAILED
                assert queue.queue_item_count == 5
                assert queue.active_lease and queue.leased_item_count == 5
                assert queue.state == ("FAILED" if stage == 14 else "RUNNING")
            elif stage == 15:
                assert calls == {"ack": 1, "release": 0}
                assert snapshot.state is LiveWorkerState.FAILED
                assert queue.queue_item_count == 5
                assert queue.state == "FAILED" and queue.active_lease
            else:
                assert calls == {"ack": 1, "release": 0}
                assert snapshot.state is LiveWorkerState.FAILED
                assert queue.queue_item_count == 0
                assert queue.state == "RUNNING" and not queue.active_lease
            expected = ((0, 0, 0) if stage <= 18 else
                        (1, 0, 0) if stage == 19 else
                        (1, 1, 0) if stage <= 21 else (1, 1, 1))
            assert (detection_revision, analysis_revision, publication_revision) == expected
            if snapshot.state is LiveWorkerState.FAILED:
                with pytest.raises(LiveWorkerError):
                    worker.step()
                with pytest.raises(LiveWorkerError):
                    worker.resume_after_degraded()
            safe = repr(caught.value) + str(caught.value) + repr(snapshot)
            assert "PRIVATE_INTERNAL_EXCEPTION" not in safe
            assert "synthetic.log" not in safe and "192.0.2.11" not in safe
    finally:
        monkeypatch.undo()
        worker.close()
        assert session._fd == -1


def test_fault_point_24_runner_notify_change_is_terminal_without_reprocessing(tmp_path, monkeypatch):
    path, session, detection, analysis, worker = setup(tmp_path)
    service = LiveMonitoringService(worker)
    runner = LiveMonitoringRunner(service)
    append(path, *(line(index) for index in range(1, 6)))
    notifications = []

    async def notify(_self):
        notifications.append(1)
        fail()

    monkeypatch.setattr(LiveMonitoringService, "notify_change", notify)

    async def scenario():
        await runner.run()
        assert runner.state is LiveRunnerState.FAILED
        assert runner.error_code == "LIVE_RUNNER_FAILED"
        # Service state notifications share this method; the runner still
        # performs only one processing step before its terminal transition.
        assert len(notifications) >= 1
        assert worker.snapshot().state is LiveWorkerState.READY
        assert detection.snapshot().revision == analysis.snapshot().revision == 1
        assert worker.publication_buffer._state.latest_revision == 1
        assert session.snapshot().acknowledged_record_count == 5
        assert session.snapshot().released_lease_count == 0
        assert not session.snapshot().active_lease
        assert not detection.snapshot().active_proposal
        assert not analysis.snapshot().active_proposal
        assert worker.publication_buffer._active is None
        assert worker.snapshot().step_revision == 1
        await runner.shutdown()

    asyncio.run(scenario())
    assert session._fd == -1


def test_fault_point_25_close_fails_bounded_then_can_retry_cleanup(tmp_path, monkeypatch):
    _, session, detection, analysis, worker = setup(tmp_path)
    with monkeypatch.context() as patch:
        patch.setattr(LiveAnalysisAccumulator, "close", fail)
        with pytest.raises(LiveWorkerError) as caught:
            worker.close()
        assert caught.value.code == "CLOSE_FAILURE"
        assert "PRIVATE_INTERNAL_EXCEPTION" not in repr(caught.value)
        assert worker.snapshot().state is LiveWorkerState.FAILED
        assert session.snapshot().state == "RUNNING"
        assert session.snapshot().queue_item_count == 0
        assert detection.snapshot().revision == analysis.snapshot().revision == 0
        assert worker.publication_buffer._state.latest_revision == 0
        assert not detection.snapshot().active_proposal
        assert not analysis.snapshot().active_proposal
        assert worker.publication_buffer._active is None
    worker.close()
    assert worker.snapshot().state is LiveWorkerState.STOPPED
    assert session._fd == -1
