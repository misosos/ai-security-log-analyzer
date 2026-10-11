"""Worker publishes only after queue ack and detection commit."""

import pytest

from app.live_monitoring import (
    LiveDetectionAccumulator, LiveMonitorConfig, LiveProcessingWorker,
    open_live_tail_session,
)
from app.live_monitoring.publication import LivePublicationBuffer
from app.live_monitoring.worker import LiveWorkerError


def auth(second):
    return f"2026-01-02 03:04:{second:02d} INFO login_failed user=synthetic ip=192.0.2.1"


def make_worker(tmp_path):
    path = tmp_path / "synthetic.log"
    path.write_bytes(b"old line\n")
    session = open_live_tail_session(LiveMonitorConfig("application", path.resolve()))
    accumulator = LiveDetectionAccumulator("application", 64, 65536)
    worker = LiveProcessingWorker(session, accumulator, 16, 4096)
    return path, session, accumulator, worker


def append(path, *lines):
    with path.open("ab") as stream:
        stream.write(("\n".join(lines) + "\n").encode())


def test_worker_publishes_after_detection_commit_and_skips_empty_changes(tmp_path):
    path, session, accumulator, worker = make_worker(tmp_path)
    try:
        assert worker.step().status == "NO_DATA"
        append(path, *(auth(index) for index in range(4)))
        below = worker.step()
        assert below.publication_event_id is None
        assert worker.publication_buffer.snapshot().latest_committed_detection_revision == 1
        append(path, auth(4))
        created = worker.step()
        assert created.created_count == 1
        assert created.publication_event_id is not None
        assert session.snapshot().acknowledged_record_count == 5
        replay = worker.publication_buffer.replay_after(None)
        assert replay.status == "INITIAL" and len(replay.events) == 1
        assert replay.events[0].revision == accumulator.snapshot().revision == 2
        assert replay.events[0].created_count == 1
        assert worker.snapshot().publication.published_total == 1
        assert worker.snapshot().potentially_unpublished_revision_count == 0
    finally:
        worker.close()
    assert session._fd == -1
    assert worker.publication_buffer.snapshot().state == "CLOSED"


def test_publication_failure_after_commit_is_terminal_without_release(tmp_path, monkeypatch):
    path, session, accumulator, worker = make_worker(tmp_path)
    append(path, *(auth(index) for index in range(5)))

    def fail_publish(_self, _change_set):
        raise RuntimeError("SECRET_EXCEPTION_CANARY")

    monkeypatch.setattr(LivePublicationBuffer, "publish", fail_publish)
    try:
        with pytest.raises(LiveWorkerError) as raised:
            worker.step()
        assert raised.value.code == "PUBLICATION_FAILED_AFTER_DETECTION_COMMIT"
        assert "SECRET_EXCEPTION_CANARY" not in str(raised.value)
        assert session.snapshot().acknowledged_record_count == 5
        assert session.snapshot().released_lease_count == 0
        assert accumulator.snapshot().revision == 1
        snap = worker.snapshot()
        assert snap.potentially_unpublished_revision_count == 1
        assert snap.successful_step_count == 0
        assert snap.total_acknowledged == 0
        with pytest.raises(LiveWorkerError):
            worker.step()
        with pytest.raises(LiveWorkerError):
            worker.resume_after_degraded()
    finally:
        worker.close()


def test_parse_failure_before_commit_never_publishes(tmp_path, monkeypatch):
    from app.live_monitoring import worker as module
    path, session, accumulator, worker = make_worker(tmp_path)
    append(path, auth(0))
    monkeypatch.setattr(module, "parse_live_records", lambda *_: (_ for _ in ()).throw(RuntimeError("secret")))
    try:
        with pytest.raises(LiveWorkerError) as raised:
            worker.step()
        assert raised.value.code == "PROCESSING_FAILURE"
        assert accumulator.snapshot().revision == 0
        assert worker.publication_buffer.snapshot().published_total == 0
        assert session.snapshot().acknowledged_record_count == 0
        assert session.snapshot().released_lease_count == 1
    finally:
        worker.close()


def test_publication_commit_then_exception_is_not_retried(tmp_path, monkeypatch):
    path, session, accumulator, worker = make_worker(tmp_path)
    append(path, *(auth(index) for index in range(5)))
    original = LivePublicationBuffer.publish

    def applied_then_failed(instance, change_set):
        original(instance, change_set)
        raise RuntimeError("PRIVATE_POST_PUBLISH_EXCEPTION")

    monkeypatch.setattr(LivePublicationBuffer, "publish", applied_then_failed)
    try:
        with pytest.raises(LiveWorkerError) as raised:
            worker.step()
        assert raised.value.code == "PUBLICATION_FAILED_AFTER_DETECTION_COMMIT"
        assert worker.publication_buffer.snapshot().published_total == 1
        assert accumulator.snapshot().revision == 1
        assert session.snapshot().acknowledged_record_count == 5
        assert worker.snapshot().potentially_unpublished_revision_count == 1
        assert worker.snapshot().successful_step_count == 0
    finally:
        worker.close()
