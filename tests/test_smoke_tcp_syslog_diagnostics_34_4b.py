"""Safe stage diagnostics for the synthetic TCP subprocess smoke."""

import signal
from pathlib import Path

import pytest

import tests.smoke_tcp_syslog_34_2 as smoke


def test_child_start_failure_reports_fixed_stage_without_exception_text(monkeypatch, capsys):
    def fail_to_start(*_args, **_kwargs):
        raise OSError("PRIVATE_PATH_CANARY PRIVATE_HOST_CANARY")

    monkeypatch.setattr(smoke.subprocess, "Popen", fail_to_start)
    with pytest.raises(smoke.SmokeFailure):
        smoke._parent_run("application", signal.SIGTERM)

    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == (
        "TCP_SYSLOG_SMOKE_FAILURE role=application signal=SIGTERM "
        "stage=CHILD_START category=CHILD_START_FAILED\n"
    )
    assert "PRIVATE_PATH_CANARY" not in output.err
    assert "PRIVATE_HOST_CANARY" not in output.err


def test_failure_diagnostic_vocabulary_is_closed():
    assert smoke._FAILURE_STAGES == {
        "CHILD_START", "LISTENER_READY", "FRAME_SENT", "ANALYSIS_CONFIRMED",
        "SIGNAL_SENT", "PROCESS_EXIT", "LISTENER_RELEASED", "PORT_REUSED",
        "TEMP_CLEANUP",
    }
    assert "PRIVATE_BIND_CANARY" not in repr(smoke.SmokeFailure("bad", "bad"))


def test_ready_marker_publication_is_atomic_and_private(tmp_path, monkeypatch):
    target = tmp_path / "ready"
    original_replace = smoke.os.replace
    observed = []

    def inspect_before_publish(source, destination):
        source_path, destination_path = Path(source), Path(destination)
        observed.append((source_path.read_text(encoding="ascii"), source_path.stat().st_mode & 0o777,
                         destination_path.exists()))
        return original_replace(source, destination)

    monkeypatch.setattr(smoke.os, "replace", inspect_before_publish)
    smoke._write_private_marker(target, "43127")

    assert observed == [("43127", 0o600, False)]
    assert target.read_text(encoding="ascii") == "43127"
    assert target.stat().st_mode & 0o777 == 0o600


def test_empty_readiness_marker_is_a_fixed_failure_without_value_leak(tmp_path):
    marker = tmp_path / "ready"
    marker.touch(mode=0o600)
    with pytest.raises(smoke.SmokeFailure) as raised:
        smoke._read_ready_port(marker)
    assert raised.value.stage == "LISTENER_READY"
    assert raised.value.category == "READINESS_MARKER_INVALID"
    assert str(raised.value) == "READINESS_MARKER_INVALID"
