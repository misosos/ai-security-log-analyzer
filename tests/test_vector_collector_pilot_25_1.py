"""Test-only receiver boundary; no Vector binary is needed in project CI."""

import socket
from pathlib import Path
from tempfile import TemporaryDirectory
import sys
import time

from vector_collector_pilot_25_1 import (
    BoundedReceiver,
    MAX_FRAME,
    MAX_RECORDS,
    PROJECT_MAX_LINE,
    classify,
    synthetic_line,
)


def test_receiver_waits_for_lf_and_exposes_only_safe_summary():
    with TemporaryDirectory(prefix="v251-", dir="/tmp") as directory:
        _check_lf_boundary(Path(directory) / "capture.sock")


def _check_lf_boundary(path):
    receiver = BoundedReceiver(path)
    line = synthetic_line(1, suffix=b"ACCOUNT_PRIVATE_CANARY")
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
            peer.connect(str(receiver.path))
            peer.sendall(line[:-1])
            time.sleep(0.1)
            assert receiver.safe_summary()["count"] == 0
            peer.sendall(b"\n")
            assert receiver.wait_count(1, 2)
        summary = receiver.safe_summary()
        assert summary["sequence"] == [1]
        assert summary["bytes"] == len(line)
        assert summary["peer_uid_verified"] is sys.platform.startswith("linux")
        assert "ACCOUNT_PRIVATE_CANARY" not in repr(summary)
        assert classify([line], receiver.snapshot())["byte_equal"]
    finally:
        receiver.close()
        receiver.close()
    assert not receiver.path.exists()


def test_receiver_rejects_oversized_frame_without_silent_eviction():
    with TemporaryDirectory(prefix="v251-", dir="/tmp") as directory:
        _check_oversized_frame(Path(directory) / "capture.sock")


def _check_oversized_frame(path):
    receiver = BoundedReceiver(path)
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
            peer.connect(str(receiver.path))
            peer.sendall(b"X" * (MAX_FRAME + 1) + b"\n")
            deadline = time.monotonic() + 2
            while receiver.error is None and time.monotonic() < deadline:
                time.sleep(0.01)
        assert receiver.error == "FRAME_TOO_LARGE"
        assert receiver.safe_summary()["count"] == 0
    finally:
        receiver.close()


def test_receiver_rejects_invalid_utf8_without_echoing_payload():
    with TemporaryDirectory(prefix="v251-", dir="/tmp") as directory:
        receiver = BoundedReceiver(Path(directory) / "capture.sock")
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
                peer.connect(str(receiver.path))
                peer.sendall(b"PRIVATE_RAW_CANARY\xff\n")
                deadline = time.monotonic() + 2
                while receiver.error is None and time.monotonic() < deadline:
                    time.sleep(0.01)
            assert receiver.error == "FRAME_NOT_UTF8"
            assert "PRIVATE_RAW_CANARY" not in repr(receiver.safe_summary())
        finally:
            receiver.close()


def test_classifier_preserves_duplicate_gap_and_order_evidence():
    expected = [synthetic_line(1), synthetic_line(2), synthetic_line(3)]
    from vector_collector_pilot_25_1 import classify

    result = classify(expected, (expected[1], expected[1], expected[0]))
    assert result["received_sequence"] == [2, 2, 1]
    assert result["gap"] == [3]
    assert result["duplicate"] == 1
    assert not result["order_equal"] and not result["byte_equal"]


def test_receiver_history_limit_is_explicit_and_safe_summary_has_no_canaries():
    with TemporaryDirectory(prefix="v251-", dir="/tmp") as directory:
        receiver = BoundedReceiver(Path(directory) / "capture.sock")
        private = (b"ACCOUNT_PRIVATE IP_PRIVATE FILE_PRIVATE QUERY_PRIVATE "
                   b"RAW_PRIVATE EXCEPTION_PRIVATE")
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
                peer.connect(str(receiver.path))
                peer.sendall((private + b"\n") * (MAX_RECORDS + 1))
                deadline = time.monotonic() + 3
                while receiver.error is None and time.monotonic() < deadline:
                    time.sleep(0.01)
            summary = receiver.safe_summary()
            assert summary["count"] == MAX_RECORDS
            assert summary["error"] == "HISTORY_FULL"
            assert all(canary not in repr(summary) for canary in private.decode().split())
        finally:
            receiver.close()


def test_synthetic_long_line_boundary_tracks_internal_tailer_contract():
    from app.live_monitoring.core import MAX_LINE_BYTES

    assert PROJECT_MAX_LINE == MAX_LINE_BYTES
    base = synthetic_line(1)
    assert len(synthetic_line(1, suffix=b"X" * (PROJECT_MAX_LINE - 1 - len(base)))) == 2047
    assert len(synthetic_line(2, suffix=b"Y" * (PROJECT_MAX_LINE + 2 - len(base)))) == 2050
