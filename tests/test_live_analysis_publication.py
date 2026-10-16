"""Application analysis is published as one bounded, ordered batch."""

import json
from dataclasses import asdict

import pytest

from app.live_monitoring import (
    LiveDetectionAccumulator, LiveMonitorConfig, LiveProcessingWorker,
    open_live_tail_session,
)
from app.live_monitoring import publication as publication_module
from app.live_monitoring.publication import (
    LivePublicationBuffer, LivePublicationError,
    serialize_live_analysis_publication_event, serialize_live_publication_event,
    serialize_live_publication_snapshot,
)
from app.live_monitoring.worker import LiveWorkerError


def _worker(tmp_path):
    path = tmp_path / "source.log"
    path.write_bytes(b"existing line\n")
    session = open_live_tail_session(LiveMonitorConfig("application", path.resolve()))
    detection = LiveDetectionAccumulator("application", 256, 262144)
    worker = LiveProcessingWorker(session, detection, 16, 4096)
    return path, session, detection, worker


def _append(path, *lines):
    with path.open("ab") as output:
        output.write(("\n".join(lines) + "\n").encode())


def _failure(second):
    return (f"2026-01-02 03:04:{second:02d} INFO login_failed "
            "user=ACCOUNT_PRIVATE_CANARY ip=192.0.2.123")


def _success():
    return ("2026-01-02 03:04:06 INFO user_login "
            "user=ACCOUNT_PRIVATE_CANARY ip=192.0.2.123")


def test_batch_event_order_replay_and_private_values(tmp_path):
    path, session, detection, worker = _worker(tmp_path)
    try:
        _append(path, *(_failure(index) for index in range(5)))
        first = worker.step()
        assert first.publication_event_id is not None
        _append(path, _success())
        second = worker.step()
        assert second.accumulator_revision == second.analysis_revision == 2
        replay = worker.publication_buffer.replay_after(None)
        assert [(event.revision, event.event_type) for event in replay.events] == [
            (1, "DETECTION_CHANGE"), (1, "ANALYSIS_CHANGE"),
            (2, "ANALYSIS_CHANGE"),
        ]
        assert [int(event.event_id.rsplit("-", 1)[1]) for event in replay.events] == [1, 2, 3]
        assert worker.publication_buffer.replay_after(replay.events[0].event_id).events == replay.events[1:]
        assert detection.snapshot().revision == worker._analysis.snapshot().revision == 2
        snapshot = worker.publication_buffer.snapshot()
        payload = json.loads(serialize_live_publication_snapshot(snapshot))
        assert payload["analysis"]["analysis_available"] is True
        assert payload["analysis"]["relation_count"] >= 1
        assert payload["analysis"]["case_count"] >= 1
        assert snapshot.byte_count == sum(
            len(serialize_live_publication_event(event)) if event.event_type == "DETECTION_CHANGE"
            else len(serialize_live_analysis_publication_event(event))
            for event in replay.events)
        wire = b"".join(
            serialize_live_publication_event(event) if event.event_type == "DETECTION_CHANGE"
            else serialize_live_analysis_publication_event(event)
            for event in replay.events) + serialize_live_publication_snapshot(snapshot)
        assert b"CASE-BRUTE-SUCCESS-01" in wire
        for secret in (b"ACCOUNT_PRIVATE_CANARY", b"192.0.2.123", b"source.log"):
            assert secret not in wire
        safe_tree = json.dumps(asdict(snapshot), default=str).encode()
        safe_tree += repr(snapshot).encode()
        safe_tree += repr(replay.events).encode()
        for secret in (b"ACCOUNT_PRIVATE_CANARY", b"192.0.2.123", b"source.log"):
            assert secret not in safe_tree
    finally:
        worker.close()
    assert session._fd == -1


def test_two_event_batch_rejects_item_cap_before_ack(tmp_path):
    path, session, detection, worker = _worker(tmp_path)
    worker.publication_buffer._max_items = 1
    _append(path, *(_failure(index) for index in range(5)))
    try:
        with pytest.raises(LiveWorkerError) as raised:
            worker.step()
        assert raised.value.code == "PUBLICATION_PREPARE_FAILED"
        assert session.snapshot().acknowledged_record_count == 0
        assert session.snapshot().released_lease_count == 1
        assert detection.snapshot().revision == worker._analysis.snapshot().revision == 0
        assert worker.publication_buffer.snapshot().published_total == 0
        assert worker.publication_buffer._active is None
    finally:
        worker.close()


def test_snapshot_size_failure_is_pre_ack(tmp_path, monkeypatch):
    path, session, detection, worker = _worker(tmp_path)
    monkeypatch.setattr(publication_module, "MAX_ANALYSIS_SNAPSHOT_BYTES", 1)
    _append(path, _failure(0))
    try:
        with pytest.raises(LiveWorkerError) as raised:
            worker.step()
        assert raised.value.code == "PUBLICATION_PREPARE_FAILED"
        assert session.snapshot().acknowledged_record_count == 0
        assert detection.snapshot().revision == worker._analysis.snapshot().revision == 0
    finally:
        worker.close()


def test_snapshot_item_limit_is_pre_ack_without_truncation(tmp_path, monkeypatch):
    path, session, detection, worker = _worker(tmp_path)
    monkeypatch.setattr(publication_module, "MAX_ANALYSIS_SNAPSHOT_ITEMS", 1)
    _append(path, _failure(0), _failure(1).replace("192.0.2.123", "192.0.2.124"))
    try:
        with pytest.raises(LiveWorkerError) as raised:
            worker.step()
        assert raised.value.code == "PUBLICATION_PREPARE_FAILED"
        assert session.snapshot().acknowledged_record_count == 0
        assert session.snapshot().available_item_count == 2
        assert detection.snapshot().revision == worker._analysis.snapshot().revision == 0
        assert worker.publication_buffer.snapshot().published_total == 0
    finally:
        worker.close()


def test_batch_commit_swap_failure_has_no_partial_publication(tmp_path, monkeypatch):
    path, session, detection, worker = _worker(tmp_path)
    _append(path, *(_failure(index) for index in range(5)))

    def fail_before_swap(_self, _proposal):
        raise RuntimeError("DETECTOR_PRIVATE_EXCEPTION_CANARY")

    monkeypatch.setattr(LivePublicationBuffer, "commit_prepared", fail_before_swap)
    try:
        with pytest.raises(LiveWorkerError) as raised:
            worker.step()
        assert raised.value.code == "PUBLICATION_FAILED_AFTER_ANALYSIS_COMMIT"
        assert session.snapshot().acknowledged_record_count == 5
        assert detection.snapshot().revision == worker._analysis.snapshot().revision == 1
        assert worker.publication_buffer.snapshot().published_total == 0
        assert worker.snapshot().state.value == "FAILED"
        assert "DETECTOR_PRIVATE_EXCEPTION_CANARY" not in repr(raised.value)
    finally:
        worker.close()


@pytest.mark.parametrize("boundary", [
    "observation_serialization", "analysis_serialization", "snapshot_projection",
])
def test_batch_prepare_faults_release_without_partial_publication(tmp_path, monkeypatch, boundary):
    path, session, detection, worker = _worker(tmp_path)
    _append(path, *(_failure(index) for index in range(5)))

    def fail(*_args, **_kwargs):
        raise RuntimeError("PRIVATE_EXCEPTION_CANARY")

    target = {
        "observation_serialization": "serialize_live_publication_event",
        "analysis_serialization": "serialize_live_analysis_publication_event",
        "snapshot_projection": "analysis_snapshot_data",
    }[boundary]
    monkeypatch.setattr(publication_module, target, fail)
    try:
        with pytest.raises(LiveWorkerError) as raised:
            worker.step()
        assert raised.value.code == "PUBLICATION_PREPARE_FAILED"
        assert "PRIVATE_EXCEPTION_CANARY" not in repr(raised.value)
        queue = session.snapshot()
        assert queue.acknowledged_record_count == 0
        assert queue.released_lease_count == 1
        assert queue.available_item_count == 5
        assert detection.snapshot().revision == worker._analysis.snapshot().revision == 0
        assert worker.publication_buffer.snapshot().published_total == 0
        assert worker.publication_buffer._active is None
    finally:
        worker.close()


def test_two_event_combined_byte_cap_rejects_before_ack(tmp_path):
    path, session, detection, worker = _worker(tmp_path)
    # Each safe event fits independently, but their combined batch does not.
    worker.publication_buffer._max_bytes = 600
    _append(path, *(_failure(index) for index in range(5)))
    try:
        with pytest.raises(LiveWorkerError) as raised:
            worker.step()
        assert raised.value.code == "PUBLICATION_PREPARE_FAILED"
        assert session.snapshot().acknowledged_record_count == 0
        assert session.snapshot().available_item_count == 5
        assert detection.snapshot().revision == worker._analysis.snapshot().revision == 0
        assert worker.publication_buffer.snapshot().published_total == 0
    finally:
        worker.close()


def test_fault_after_batch_swap_keeps_both_events_and_never_retries(tmp_path, monkeypatch):
    path, session, detection, worker = _worker(tmp_path)
    _append(path, *(_failure(index) for index in range(5)))
    original_commit = LivePublicationBuffer.commit_prepared

    def fail_after_swap(instance, proposal):
        original_commit(instance, proposal)
        raise RuntimeError("PRIVATE_EXCEPTION_CANARY")

    monkeypatch.setattr(LivePublicationBuffer, "commit_prepared", fail_after_swap)
    try:
        with pytest.raises(LiveWorkerError) as raised:
            worker.step()
        assert raised.value.code == "PUBLICATION_FAILED_AFTER_ANALYSIS_COMMIT"
        assert session.snapshot().acknowledged_record_count == 5
        assert detection.snapshot().revision == worker._analysis.snapshot().revision == 1
        replay = worker.publication_buffer.replay_after(None)
        assert [event.event_type for event in replay.events] == [
            "DETECTION_CHANGE", "ANALYSIS_CHANGE",
        ]
        assert worker.snapshot().state.value == "FAILED"
        with pytest.raises(LiveWorkerError):
            worker.step()
        assert worker.publication_buffer.snapshot().published_total == 2
        assert "PRIVATE_EXCEPTION_CANARY" not in repr(raised.value)
    finally:
        worker.close()


def test_analysis_serializer_rejects_raw_inputs():
    for value in ({}, [], object()):
        with pytest.raises(LivePublicationError):
            serialize_live_analysis_publication_event(value)


def test_empty_revision_updates_analysis_snapshot_without_event(tmp_path):
    path, _, detection, worker = _worker(tmp_path)
    try:
        _append(path, " ")
        result = worker.step()
        assert result.status == "PROCESSED"
        assert result.accumulator_revision == result.analysis_revision == 1
        assert worker.publication_buffer.snapshot().published_total == 0
        assert worker.publication_buffer.replay_after(None).events == ()
        payload = json.loads(serialize_live_publication_snapshot(worker.publication_buffer.snapshot()))
        assert payload["analysis"]["revision"] == 1
        assert detection.snapshot().revision == 1
    finally:
        worker.close()


@pytest.mark.parametrize("role,available", [("ssh", True), ("access", False)])
def test_source_snapshot_marks_analysis_availability(tmp_path, role, available):
    path = tmp_path / "source.log"
    path.write_bytes(b"")
    session = open_live_tail_session(LiveMonitorConfig(role, path.resolve()))
    detection = LiveDetectionAccumulator(role, 8, 8192)
    worker = LiveProcessingWorker(session, detection, 8, 4096)
    try:
        payload = json.loads(serialize_live_publication_snapshot(worker.publication_buffer.snapshot()))
        assert payload["analysis"]["analysis_available"] is available
        assert payload["analysis"]["revision"] == (0 if available else None)
        assert worker.step().status == "NO_DATA"
    finally:
        worker.close()
