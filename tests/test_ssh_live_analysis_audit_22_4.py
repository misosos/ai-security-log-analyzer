"""Independent SSH publication and privacy boundaries for the acceptance audit."""

from dataclasses import asdict
import json

import pytest

from app.live_monitoring import (
    LiveDetectionAccumulator, LiveMonitorConfig, LiveProcessingWorker,
    open_live_tail_session,
)
from app.live_monitoring import publication as publication_module
from app.live_monitoring.worker import LiveWorkerError, LiveWorkerState


def _setup(tmp_path):
    source = tmp_path / "PATH_AUDIT_CANARY.log"
    source.write_bytes(b"preexisting private line\n")
    session = open_live_tail_session(LiveMonitorConfig("ssh", source.resolve()))
    detection = LiveDetectionAccumulator("ssh", 256, 256 * 1024)
    worker = LiveProcessingWorker(session, detection, 16, 4096)
    return source, session, detection, worker


def _append(source):
    with source.open("ab") as stream:
        for second in range(1, 6):
            stream.write((
                f"2026-01-02 03:04:{second:02d} sshd: Failed password for "
                "ACCOUNT_AUDIT_CANARY from 198.51.100.87 port 5001 ssh2\n"
            ).encode())


@pytest.mark.parametrize("fault", (
    "observation_serialization", "analysis_serialization", "snapshot_projection",
    "item_cap", "byte_cap", "snapshot_byte_cap",
))
def test_ssh_publication_prepare_fault_is_pre_ack_and_private(tmp_path, monkeypatch, fault):
    source, session, detection, worker = _setup(tmp_path)
    _append(source)

    def fail(*_args, **_kwargs):
        raise RuntimeError("EXCEPTION_AUDIT_CANARY")

    if fault == "observation_serialization":
        monkeypatch.setattr(publication_module, "serialize_live_publication_event", fail)
    elif fault == "analysis_serialization":
        monkeypatch.setattr(publication_module, "serialize_live_analysis_publication_event", fail)
    elif fault == "snapshot_projection":
        monkeypatch.setattr(publication_module, "analysis_snapshot_data", fail)
    elif fault == "item_cap":
        worker.publication_buffer._max_items = 1
    elif fault == "byte_cap":
        worker.publication_buffer._max_bytes = 600
    else:
        monkeypatch.setattr(publication_module, "MAX_ANALYSIS_SNAPSHOT_BYTES", 1)
    try:
        with pytest.raises(LiveWorkerError) as caught:
            worker.step()
        assert caught.value.code == "PUBLICATION_PREPARE_FAILED"
        assert worker.snapshot().state is LiveWorkerState.DEGRADED
        queue = session.snapshot()
        assert queue.acknowledged_record_count == 0
        assert queue.released_lease_count == 1
        assert queue.available_item_count == 5
        assert not queue.active_lease
        assert detection.snapshot().revision == worker._analysis.snapshot().revision == 0
        assert not detection.snapshot().active_proposal
        assert not worker._analysis.snapshot().active_proposal
        assert worker.publication_buffer._active is None
        assert worker.publication_buffer.snapshot().published_total == 0
        safe = repr(caught.value) + repr(worker.snapshot())
        for secret in ("PATH_AUDIT_CANARY", "ACCOUNT_AUDIT_CANARY",
                       "198.51.100.87", "EXCEPTION_AUDIT_CANARY"):
            assert secret not in safe
    finally:
        worker.close()
    assert session._fd == -1


def test_ssh_safe_snapshots_and_errors_have_no_trusted_values(tmp_path):
    source, session, detection, worker = _setup(tmp_path)
    _append(source)
    try:
        assert worker.step().status == "PROCESSED"
        payload = json.dumps(asdict(worker.snapshot()), default=str, ensure_ascii=False)
        payload += repr(worker.snapshot()) + repr(worker.publication_buffer.snapshot())
        assert worker._analysis.snapshot().case_count == 0  # No successful login yet.
        for secret in ("PATH_AUDIT_CANARY", "ACCOUNT_AUDIT_CANARY", "198.51.100.87"):
            assert secret not in payload
        assert detection.snapshot().revision == worker._analysis.snapshot().revision == 1
    finally:
        worker.close()
    assert session._fd == -1


def test_ssh_history_257th_event_fails_closed_without_eviction(tmp_path):
    source, session, detection, worker = _setup(tmp_path)
    raw = (b"2026-01-02 03:04:01 sshd: Failed password for synthetic "
           b"from 198.51.100.87 port 5001 ssh2\n")
    try:
        for _ in range(16):
            with source.open("ab") as stream:
                stream.write(raw * 16)
            assert worker.step().parsed_count == 16
        assert detection.snapshot().history_record_count == 256
        assert detection.snapshot().revision == worker._analysis.snapshot().revision == 16
        with source.open("ab") as stream:
            stream.write(raw)
        with pytest.raises(LiveWorkerError) as caught:
            worker.step()
        assert caught.value.code == "PROCESSING_FAILURE"
        assert worker.snapshot().state is LiveWorkerState.DEGRADED
        assert session.snapshot().available_item_count == 1
        assert not session.snapshot().active_lease
        assert detection.snapshot().history_record_count == 256
        assert detection.snapshot().revision == worker._analysis.snapshot().revision == 16
    finally:
        worker.close()
    assert session._fd == -1
