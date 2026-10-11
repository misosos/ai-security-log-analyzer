"""Acknowledgement is the point of no return, not a database transaction."""

import pytest

from app.live_monitoring import (
    LiveDetectionAccumulator, LiveMonitorConfig, LiveProcessingWorker,
    LiveWorkerError, LiveWorkerState, open_live_tail_session,
)
from app.live_monitoring import worker as module
from app.live_monitoring import detection_accumulator as detection_module
from app.live_monitoring import LiveTailRecord, parse_live_records


LINE = "2026-01-02 03:04:05 INFO login_failed user=synthetic ip=192.0.2.1"


def setup(tmp_path, *, limit=10):
    path = tmp_path / "synthetic.log"
    path.write_bytes(b"")
    session = open_live_tail_session(LiveMonitorConfig("application", path.resolve()))
    accumulator = LiveDetectionAccumulator("application", limit, 10000)
    worker = LiveProcessingWorker(session, accumulator, 10, 4096)
    with path.open("ab") as stream:
        stream.write((LINE + "\n").encode())
    return session, accumulator, worker


def failure(message="private-secret-diagnostic"):
    raise RuntimeError(message)


@pytest.mark.parametrize("stage", ("parse_live_records", "prevalidate", "prepare"))
def test_pre_ack_failure_aborts_then_releases_and_resumes(tmp_path, monkeypatch, stage):
    session, accumulator, worker = setup(tmp_path)
    if stage == "parse_live_records":
        target, name = module, stage
    else:
        target, name = LiveDetectionAccumulator, stage
    original = getattr(target, name)
    monkeypatch.setattr(target, name, lambda *_: failure())
    try:
        with pytest.raises(LiveWorkerError) as raised:
            worker.step()
        assert raised.value.code == "PROCESSING_FAILURE"
        assert worker.snapshot().state is LiveWorkerState.DEGRADED
        assert session.snapshot().available_item_count == 1
        assert session.snapshot().acknowledged_record_count == 0
        assert accumulator.snapshot().revision == 0
        assert worker.snapshot().successful_step_count == 0
        monkeypatch.setattr(target, name, original)
        worker.resume_after_degraded()
        assert worker.step().parsed_count == 1
        assert accumulator.snapshot().revision == 1
    finally:
        worker.close()


def test_history_overflow_is_pre_ack_and_keeps_fifo(tmp_path):
    session, accumulator, worker = setup(tmp_path, limit=1)
    try:
        assert worker.step().parsed_count == 1
        with (tmp_path / "synthetic.log").open("ab") as stream:
            stream.write((LINE + "\n").encode())
        with pytest.raises(LiveWorkerError) as raised:
            worker.step()
        assert raised.value.code == "PROCESSING_FAILURE"
        assert accumulator.snapshot().revision == 1
        assert session.snapshot().available_item_count == 1
        assert session.snapshot().acknowledged_record_count == 1
    finally:
        worker.close()


def test_ack_failure_aborts_proposal_without_guessing_release(tmp_path, monkeypatch):
    session, accumulator, worker = setup(tmp_path)
    monkeypatch.setattr(type(session), "acknowledge_lease", lambda *_: failure())
    try:
        with pytest.raises(LiveWorkerError) as raised:
            worker.step()
        assert raised.value.code == "ACK_FAILURE"
        assert worker.snapshot().state is LiveWorkerState.FAILED
        assert accumulator.snapshot().revision == 0
        assert not accumulator.snapshot().active_proposal
        assert session.snapshot().acknowledged_record_count == 0
        assert worker.snapshot().total_released == 0
        with pytest.raises(LiveWorkerError):
            worker.resume_after_degraded()
    finally:
        worker.close()


def test_post_ack_commit_failure_is_terminal_and_not_released(tmp_path, monkeypatch):
    session, accumulator, worker = setup(tmp_path)
    monkeypatch.setattr(LiveDetectionAccumulator, "commit_prepared", lambda *_: failure())
    try:
        with pytest.raises(LiveWorkerError) as raised:
            worker.step()
        assert raised.value.code == "DETECTION_COMMIT_FAILED_AFTER_ACK"
        assert worker.snapshot().state is LiveWorkerState.FAILED
        assert session.snapshot().acknowledged_record_count == 1
        assert session.snapshot().queue_item_count == 0
        assert accumulator.snapshot().revision == 0
        assert worker.snapshot().post_ack_commit_failure_count == 1
        assert worker.snapshot().uncommitted_after_ack_record_count == 1
        assert worker.snapshot().successful_step_count == 0
        assert worker.snapshot().total_released == 0
        with pytest.raises(LiveWorkerError):
            worker.step()
    finally:
        worker.close()


def test_ack_settled_then_exception_is_terminal_post_ack_gap(tmp_path, monkeypatch):
    session, accumulator, worker = setup(tmp_path)
    original = type(session).acknowledge_lease

    def settled_then_broken(instance, lease):
        original(instance, lease)
        failure()

    monkeypatch.setattr(type(session), "acknowledge_lease", settled_then_broken)
    try:
        with pytest.raises(LiveWorkerError) as raised:
            worker.step()
        assert raised.value.code == "DETECTION_COMMIT_FAILED_AFTER_ACK"
        assert session.snapshot().acknowledged_record_count == 1
        assert worker.snapshot().post_ack_commit_failure_count == 1
        assert accumulator.snapshot().revision == 0
        assert worker.snapshot().total_released == 0
    finally:
        worker.close()


def test_state_swap_then_exception_does_not_claim_commit_success(tmp_path, monkeypatch):
    session, accumulator, worker = setup(tmp_path)
    original = LiveDetectionAccumulator.commit_prepared

    def swapped_then_broken(instance, proposal):
        original(instance, proposal)
        failure()

    monkeypatch.setattr(LiveDetectionAccumulator, "commit_prepared", swapped_then_broken)
    try:
        with pytest.raises(LiveWorkerError) as raised:
            worker.step()
        assert raised.value.code == "DETECTION_COMMIT_FAILED_AFTER_ACK"
        assert session.snapshot().acknowledged_record_count == 1
        assert accumulator.snapshot().revision == 0
        assert accumulator.snapshot().closed
        assert worker.snapshot().successful_step_count == 0
        assert worker.snapshot().post_ack_commit_failure_count == 1
    finally:
        worker.close()


def test_post_commit_worker_aggregate_failure_is_terminal(tmp_path, monkeypatch):
    session, accumulator, worker = setup(tmp_path)
    original = LiveProcessingWorker._transition

    def fail_ready_after_commit(instance, state):
        if state is LiveWorkerState.READY and instance._state is LiveWorkerState.RUNNING_STEP:
            failure()
        return original(instance, state)

    monkeypatch.setattr(LiveProcessingWorker, "_transition", fail_ready_after_commit)
    try:
        with pytest.raises(LiveWorkerError) as raised:
            worker.step()
        assert raised.value.code == "WORKER_AGGREGATE_FAILED_AFTER_PUBLICATION"
        assert session.snapshot().acknowledged_record_count == 1
        assert accumulator.snapshot().revision == 1
        assert worker.snapshot().successful_step_count == 0
        assert worker.snapshot().total_acknowledged == 0
        assert worker.snapshot().uncommitted_after_ack_record_count == 0
        assert worker.snapshot().post_publication_aggregate_failure_count == 1
    finally:
        worker.close()


def test_abort_failure_and_release_failure_are_terminal(tmp_path, monkeypatch):
    for failed_stage in ("abort", "release"):
        folder = tmp_path / failed_stage
        folder.mkdir()
        session, accumulator, worker = setup(folder)
        if failed_stage == "release":
            monkeypatch.setattr(module, "parse_live_records", lambda *_: failure())
            monkeypatch.setattr(type(session), "release_lease", lambda *_: failure())
        else:
            # Prepare succeeded, but validation fails and abort itself fails.
            monkeypatch.setattr(LiveDetectionAccumulator, "prevalidate", lambda *_: failure())
            monkeypatch.setattr(LiveDetectionAccumulator, "abort", lambda *_: failure())
        try:
            with pytest.raises(LiveWorkerError):
                worker.step()
            assert worker.snapshot().state is LiveWorkerState.FAILED
            assert accumulator.snapshot().revision == 0
        finally:
            worker.close()
            monkeypatch.undo()


def test_worker_rejects_role_mismatch_and_shared_accumulator(tmp_path):
    first = tmp_path / "first.log"
    second = tmp_path / "second.log"
    first.write_bytes(b"")
    second.write_bytes(b"")
    s1 = open_live_tail_session(LiveMonitorConfig("application", first.resolve()))
    s2 = open_live_tail_session(LiveMonitorConfig("application", second.resolve()))
    accumulator = LiveDetectionAccumulator("application", 10, 10000)
    worker = LiveProcessingWorker(s1, accumulator, 1, 4096)
    try:
        with pytest.raises(LiveWorkerError) as raised:
            LiveProcessingWorker(s2, accumulator, 1, 4096)
        assert raised.value.code == "ACCUMULATOR_ALREADY_OWNED"
        with pytest.raises(LiveWorkerError):
            LiveProcessingWorker(s2, LiveDetectionAccumulator("ssh", 10, 10000), 1, 4096)
    finally:
        worker.close()
        s2.close()


def test_prevalidated_commit_does_not_run_detector_diff_or_validation(monkeypatch):
    accumulator = LiveDetectionAccumulator("application", 4, 4096)
    record = LiveTailRecord("application", 1, LINE, len(LINE.encode()))
    proposal = accumulator.prepare(parse_live_records("application", (record,)))
    accumulator.prevalidate(proposal)

    def forbidden(*_args):
        failure()

    monkeypatch.setattr(detection_module, "detect_attacks", forbidden)
    monkeypatch.setattr(detection_module, "_prepare_observations", forbidden)
    monkeypatch.setattr(detection_module, "_safe_detection_counts", forbidden)
    monkeypatch.setattr(LiveDetectionAccumulator, "_validate_proposal", forbidden)
    snapshot = accumulator.commit_prepared(proposal)
    assert snapshot.revision == 1
    assert snapshot.history_record_count == 1


def test_change_set_generation_failure_is_pre_ack_and_private(tmp_path, monkeypatch):
    session, accumulator, worker = setup(tmp_path)
    monkeypatch.setattr(detection_module, "_prepare_observations", lambda *_: failure())
    try:
        with pytest.raises(LiveWorkerError) as raised:
            worker.step()
        assert raised.value.code == "PROCESSING_FAILURE"
        assert "private-secret" not in str(raised.value)
        assert session.snapshot().available_item_count == 1
        assert session.snapshot().acknowledged_record_count == 0
        assert accumulator.snapshot().revision == 0
    finally:
        worker.close()
