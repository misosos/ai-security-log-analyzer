"""Worker output, errors, and logging never expose trusted parser input."""

from dataclasses import asdict
import logging

import pytest

from app.live_monitoring import (
    LiveMonitorConfig, LiveProcessingWorker, LiveWorkerError, open_live_tail_session,
)
from app.live_monitoring import worker as worker_module


def test_canaries_absent_from_result_snapshot_errors_and_logs(tmp_path, monkeypatch, capsys, caplog):
    canaries = (
        "acct_zephyr_491", "198.51.100.243", "/private-path-cedar-82",
        "query=opaque_violet_57", "secret-honeydew-39", "private-source-cobalt-63",
    )
    folder = tmp_path / canaries[-1]
    folder.mkdir()
    path = folder / "private-file-amber-21.log"
    path.write_bytes(b"")
    session = open_live_tail_session(LiveMonitorConfig("application", path.resolve()))
    worker = LiveProcessingWorker(session, 1, 4096)
    raw = f"2026-01-02 03:04:05 INFO user_login user={canaries[0]} ip={canaries[1]} detail={canaries[2]}?{canaries[3]} {canaries[4]}"
    with path.open("ab") as stream:
        stream.write((raw + "\n").encode())
    caplog.set_level(logging.DEBUG)
    try:
        result = worker.step()
        visible = repr(worker) + str(result) + repr(worker.snapshot()) + str(asdict(worker.snapshot()))
        error = LiveWorkerError("PROCESSING_FAILURE")
        visible += str(error) + repr(error)
        visible += capsys.readouterr().out + capsys.readouterr().err + caplog.text
        for canary in (*canaries, path.name):
            assert canary not in visible
    finally:
        worker.close()


def test_private_internal_exception_is_not_chained(tmp_path, monkeypatch):
    path = tmp_path / "source.log"
    path.write_bytes(b"")
    session = open_live_tail_session(LiveMonitorConfig("application", path.resolve()))
    worker = LiveProcessingWorker(session, 1, 4096)
    with path.open("ab") as stream:
        stream.write(b"malformed private-canary-725\n")
    monkeypatch.setattr(worker_module, "parse_live_records", lambda *_: (_ for _ in ()).throw(RuntimeError("private-canary-725")))
    try:
        with pytest.raises(LiveWorkerError) as raised:
            worker.step()
        assert raised.value.__cause__ is None
        assert "private-canary-725" not in str(raised.value)
        assert "private-canary-725" not in repr(worker.snapshot())
    finally:
        worker.close()
