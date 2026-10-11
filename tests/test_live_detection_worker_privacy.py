"""Only count-only worker results and safe observation IDs leave trusted state."""

from dataclasses import asdict
import logging

import pytest

from app.live_monitoring import (
    LiveDetectionAccumulator, LiveMonitorConfig, LiveProcessingWorker,
    LiveWorkerError, open_live_tail_session,
)


def test_account_path_query_and_evidence_canaries_not_in_safe_boundary(tmp_path, capsys, caplog):
    canaries = (
        "account_azalea_703", "private-path_cedar_704", "query_elm_705",
        "credential-maple_706", "agent-birch_707", "source-oak_708",
    )
    folder = tmp_path / canaries[-1]
    folder.mkdir()
    path = folder / "filename-pine_709.log"
    path.write_bytes(b"")
    session = open_live_tail_session(LiveMonitorConfig("access", path.resolve()))
    accumulator = LiveDetectionAccumulator("access", 8, 10000)
    worker = LiveProcessingWorker(session, accumulator, 8, 4096)
    raw = (f'198.51.100.231 - - [02/Jan/2026:03:04:05 +0900] '
           f'"GET /{canaries[1]}?q=%27%20or%201%3D1&token={canaries[2]} HTTP/1.1" 404 1')
    with path.open("ab") as stream:
        stream.write((raw + "\n").encode())
    caplog.set_level(logging.DEBUG)
    try:
        result = worker.step()
        change = accumulator.latest_change_set()
        visible = (repr(worker) + repr(result) + repr(worker.snapshot())
                   + repr(accumulator) + repr(accumulator.snapshot())
                   + repr(change) + repr(asdict(worker.snapshot()))
                   + str(LiveWorkerError("DETECTION_COMMIT_FAILED_AFTER_ACK")))
        output = capsys.readouterr()
        visible += output.out + output.err + caplog.text
        for canary in (*canaries, path.name, raw, "198.51.100.231"):
            assert canary not in visible
        assert result.created_count == 1
        assert change.changes[0].observation_id == "LIVE-OBS-000001"
        assert "198.51.100" not in change.changes[0].observation_id
    finally:
        worker.close()


def test_post_ack_exception_text_is_not_exposed(tmp_path, monkeypatch, capsys, caplog):
    path = tmp_path / "source.log"
    path.write_bytes(b"")
    session = open_live_tail_session(LiveMonitorConfig("application", path.resolve()))
    accumulator = LiveDetectionAccumulator("application", 8, 10000)
    worker = LiveProcessingWorker(session, accumulator, 8, 4096)
    with path.open("ab") as stream:
        stream.write(b"2026-01-02 03:04:05 INFO login_failed user=canary_user_901 ip=198.51.100.221\n")

    def private_failure(*_args):
        raise RuntimeError("private_exception_canary_902")

    monkeypatch.setattr(LiveDetectionAccumulator, "commit_prepared", private_failure)
    caplog.set_level(logging.DEBUG)
    try:
        with pytest.raises(LiveWorkerError) as raised:
            worker.step()
        output = capsys.readouterr()
        visible = (str(raised.value) + repr(raised.value) + repr(worker.snapshot())
                   + repr(accumulator.snapshot()) + output.out + output.err + caplog.text)
        for canary in ("canary_user_901", "198.51.100.221", "private_exception_canary_902"):
            assert canary not in visible
        assert raised.value.__cause__ is None
    finally:
        worker.close()
