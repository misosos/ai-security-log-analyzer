"""CLI config reuse, startup/port failure cleanup, and lifespan integration."""

import asyncio
import errno
import json
import os
from pathlib import Path

from fastapi.testclient import TestClient
import pytest

from app import local_web
from app.api import create_app
from app.live_monitoring.runner import LiveMonitoringRunner


def _config(tmp_path: Path):
    source = tmp_path / "synthetic.log"
    source.write_bytes(b"old line\n")
    config = tmp_path / "live.json"
    config.write_text(json.dumps({
        "schema_version": "1", "start_policy": "FROM_END",
        "source": {"role": "application", "path": str(source.resolve())},
    }), encoding="utf-8")
    config.chmod(0o600)
    return config, source


def test_cli_option_help_combinations_and_invalid_path_are_private(tmp_path, capsys):
    arguments = local_web._arguments([
        "--monitor-config", "/absolute/path/to/live-monitor.json",
        "--no-browser", "--port", "8123",
    ])
    assert arguments.port == 8123 and arguments.no_browser
    assert arguments.monitor_config == "/absolute/path/to/live-monitor.json"
    with pytest.raises(local_web._ArgumentFailure):
        local_web._arguments(["--monitor-config", "a", "--monitor-config", "b"])
    with pytest.raises(SystemExit) as caught:
        local_web._arguments(["--help"])
    assert caught.value.code == 0
    assert "/absolute/path/to/live-monitor.json" in capsys.readouterr().out
    assert local_web.run_local_web(monitor_config=Path("relative.json"),
                                   listener_factory=lambda *_: pytest.fail("bound socket")) == 4
    assert "relative.json" not in capsys.readouterr().err


def test_valid_runtime_once_and_port_failure_closes_fd(tmp_path, capsys):
    config, _ = _config(tmp_path)
    made = []

    def runtime(path):
        assert path == config
        value = local_web._live_runtime(path)
        made.append(value)
        return value

    def occupied(_port):
        raise OSError(errno.EADDRINUSE, "PRIVATE_SOCKET_EXCEPTION")

    assert local_web.run_local_web(monitor_config=config, runtime_factory=runtime,
                                   listener_factory=occupied, open_browser=False) == 3
    assert len(made) == 1
    assert made[0][0]._worker._session._fd == -1
    assert "PRIVATE_SOCKET_EXCEPTION" not in capsys.readouterr().err


def test_closed_config_and_source_policies_are_reused(tmp_path, capsys):
    config, source = _config(tmp_path)
    payload = json.loads(config.read_text(encoding="utf-8"))
    payload["unknown"] = True
    config.write_text(json.dumps(payload), encoding="utf-8")
    assert local_web.run_local_web(monitor_config=config,
                                   listener_factory=lambda *_: pytest.fail("bound socket")) == 4
    assert "LIVE_CONFIG_INVALID" in capsys.readouterr().err
    config.unlink()
    config.symlink_to(source)
    assert local_web.run_local_web(monitor_config=config,
                                   listener_factory=lambda *_: pytest.fail("bound socket")) == 4
    assert str(source) not in capsys.readouterr().err


def test_lifespan_starts_one_runner_and_preserves_other_api(tmp_path, monkeypatch):
    config, source = _config(tmp_path)
    service, runner = local_web._live_runtime(config)
    gate = asyncio.Event()

    async def wait_next(_self):
        gate_task = asyncio.create_task(gate.wait())
        stop_task = asyncio.create_task(_self._stop.wait())
        _, pending = await asyncio.wait((gate_task, stop_task), return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        gate.clear()

    monkeypatch.setattr(LiveMonitoringRunner, "_wait_next", wait_next)
    app = create_app(live_monitoring_service=service, live_monitoring_runner=runner)
    with TestClient(app, base_url="http://127.0.0.1:8000", client=("127.0.0.1", 50000)) as client:
        status = client.get("/api/v1/live/status").json()
        assert status["service_state"] == "RUNNING"
        assert status["available_event_count"] == 0
        assert client.get("/api/health").json() == {"status": "ok"}
        assert client.post("/api/v1/investigations/sample").status_code == 200
        assert "LiveStatusResponse" in client.get("/openapi.json").text
        with source.open("ab") as output:
            for number in range(5):
                output.write((f"2026-01-02 03:04:{number:02d} INFO login_failed "
                              "user=synthetic ip=192.0.2.1\n").encode())
        client.portal.call(gate.set)
        for _ in range(100):
            if service.status().published_total == 1:
                break
            client.portal.call(asyncio.sleep, 0)
        assert service.status().published_total == 1
    assert service.status().service_state == "STOPPED"
    assert service._worker._session._fd == -1
    assert runner._task.done()


def test_no_config_keeps_live_disabled_and_existing_cli_contract():
    assert local_web._arguments([]).monitor_config is None
    assert create_app().openapi()["paths"].get("/api/v1/live/status") is None


def test_application_runtime_commits_analysis_without_exposing_it(tmp_path):
    config, source = _config(tmp_path)
    service, runner = local_web._live_runtime(config)
    worker = service._worker
    assert worker._analysis is not None
    try:
        with source.open("ab") as output:
            for number in range(5):
                output.write((f"2026-01-02 03:04:{number:02d} INFO login_failed "
                              "user=synthetic ip=192.0.2.1\n").encode())
        first = worker.step()
        assert first.analysis_revision == first.accumulator_revision == 1
        with source.open("ab") as output:
            output.write(b"2026-01-02 03:04:06 INFO user_login user=synthetic ip=192.0.2.1\n")
        second = worker.step()
        assert second.analysis_revision == second.accumulator_revision == 2
        assert worker._analysis.snapshot().relation_count >= 1
        assert worker._analysis.snapshot().case_count >= 1
        with TestClient(create_app(live_monitoring_service=service),
                        base_url="http://127.0.0.1:8000",
                        client=("127.0.0.1", 50000)) as client:
            status = client.get("/api/v1/live/status")
            assert status.status_code == 200
            assert "analysis" not in status.text
            assert "192.0.2.1" not in status.text
            for event in worker.publication_buffer.replay_after(None).events:
                assert event.event_type == "DETECTION_CHANGE"
    finally:
        asyncio.run(service.close())
    assert worker._session._fd == -1


def test_same_running_runtime_commits_cases_but_transmits_only_observations(tmp_path, monkeypatch):
    config, source = _config(tmp_path)
    service, runner = local_web._live_runtime(config)
    worker = service._worker
    gate = asyncio.Event()

    async def wait_next(_self):
        gate_task = asyncio.create_task(gate.wait())
        stop_task = asyncio.create_task(_self._stop.wait())
        _, pending = await asyncio.wait((gate_task, stop_task), return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        gate.clear()

    monkeypatch.setattr(LiveMonitoringRunner, "_wait_next", wait_next)
    app = create_app(live_monitoring_service=service, live_monitoring_runner=runner)
    with TestClient(app, base_url="http://127.0.0.1:8000",
                    client=("127.0.0.1", 50000)) as client:
        assert worker._session.snapshot().acknowledged_record_count == 0
        assert client.get("/api/v1/live/status").status_code == 200
        with source.open("ab") as output:
            for number in range(5):
                output.write((f"2026-01-02 03:04:{number:02d} INFO login_failed "
                              "user=ACCOUNT_PRIVATE_CANARY ip=192.0.2.123\n").encode())
        client.portal.call(gate.set)
        for _ in range(200):
            if worker._analysis.snapshot().revision >= 1:
                break
            client.portal.call(asyncio.sleep, 0)
        assert worker._analysis.snapshot().revision == 1
        with source.open("ab") as output:
            output.write(b"2026-01-02 03:04:06 INFO user_login "
                         b"user=ACCOUNT_PRIVATE_CANARY ip=192.0.2.123\n")
        client.portal.call(gate.set)
        for _ in range(200):
            if worker._analysis.snapshot().revision >= 2:
                break
            client.portal.call(asyncio.sleep, 0)
        analysis = worker._analysis.snapshot()
        detection = worker._accumulator.snapshot()
        assert analysis.revision == detection.revision == 2
        assert {item.relation_type for item in analysis.relations if item.state == "ACTIVE"} >= {
            "failed_to_successful_login", "brute_force_to_successful_login"}
        assert analysis.risk_count >= 1
        assert any(item.rule_id == "CASE-BRUTE-SUCCESS-01"
                   and item.supporting_relation_count == 1
                   for item in analysis.cases if item.state == "CURRENT")
        queue = worker._session.snapshot()
        assert queue.queue_item_count == 0 and not queue.active_lease
        assert not worker._accumulator.snapshot().active_proposal
        assert not analysis.active_proposal
        assert worker.publication_buffer._active is None
        status = client.get("/api/v1/live/status")
        assert status.status_code == 200
        assert set(status.json()).isdisjoint({"analysis", "relations", "risks", "cases"})
        assert "LiveAnalysisSnapshot" not in client.get("/openapi.json").text

        async def retained_frames():
            stream = service.open_connection(None).stream()
            try:
                frames = [await anext(stream)]
                for _ in service.publication_buffer.replay_after(None).events:
                    frames.append(await anext(stream))
                return b"".join(frames)
            finally:
                await stream.aclose()

        wire = client.portal.call(retained_frames)
        assert b"event: observation_changes" in wire
        for value in (b"ACCOUNT_PRIVATE_CANARY", b"192.0.2.123", b"synthetic.log",
                      b"CASE-BRUTE-SUCCESS-01", b"failed_to_successful_login"):
            assert value not in wire + status.content
    assert runner._task.done()
    assert worker._session._fd == -1
