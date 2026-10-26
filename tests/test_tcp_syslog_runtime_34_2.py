"""Synthetic loopback-only runtime contracts; no user HOME or log inputs."""

import asyncio
from dataclasses import FrozenInstanceError
import errno
import json
import os
from pathlib import Path
import re
import socket
import time

import pytest

from app.log_collection.models import CollectionCoreError, CollectionErrorCode
from app.log_collection.runtime import (
    TcpRuntimeConfig,
    TcpRuntimeError,
    TcpRuntimeErrorCode,
    TcpRuntimeState,
    TcpSyslogRuntime,
)


def _config(role="application", **overrides):
    values = {
        "schema_version": "tcp-syslog-runtime/v1",
        "source_role": role,
        "bind_family": "ipv4",
        "port": 0,
        "connection_limit": 2,
        "idle_timeout_seconds": 1.0,
        "read_timeout_seconds": 0.5,
        "parser_timezone": "Asia/Seoul",
        "startup_mode": "synthetic_pilot",
        "test_only_ephemeral_port": True,
    }
    values.update(overrides)
    return TcpRuntimeConfig(**values)


def _line(role, second, event, account="synthetic_user", ip="192.0.2.19"):
    if role == "application":
        return (f"2026-01-02 03:04:{second:02d} INFO {event} "
                f"user={account} ip={ip} service=ssh")
    status = "Accepted" if event == "user_login" else "Failed"
    return (f"2026-01-02 03:04:{second:02d} sshd: {status} password "
            f"for {account} from {ip} port 45001 ssh2")


def _wire(line):
    payload = line.encode("utf-8")
    return str(len(payload)).encode("ascii") + b" " + payload


def _run(coro):
    return asyncio.run(coro)


def test_runtime_config_is_closed_and_rejects_unsafe_bind_and_ports():
    config = _config()
    with pytest.raises(FrozenInstanceError):
        config.port = 514
    with pytest.raises(TcpRuntimeError) as raised:
        _config(bind_family="0.0.0.0")
    assert raised.value.code == TcpRuntimeErrorCode.INVALID_CONFIG
    with pytest.raises(TcpRuntimeError):
        _config(port=514, test_only_ephemeral_port=True)
    with pytest.raises(TcpRuntimeError):
        _config(port=514, bind_family="wildcard")
    with pytest.raises(TcpRuntimeError):
        _config(connection_limit=True)
    mapping = config.to_dict()
    mapping["user_path"] = "/PRIVATE/PATH/CANARY"
    with pytest.raises(TcpRuntimeError) as raised:
        TcpRuntimeConfig.from_mapping(mapping)
    assert "/PRIVATE/PATH/CANARY" not in str(raised.value) + repr(raised.value)


def test_runtime_starts_only_on_fixed_loopback_and_safe_status_hides_endpoint():
    async def scenario():
        runtime = TcpSyslogRuntime(_config())
        await runtime.start()
        try:
            assert runtime.snapshot().state == TcpRuntimeState.LISTENING
            wire = json.dumps(runtime.snapshot().to_dict(), sort_keys=True)
            assert "127.0.0.1" not in wire and "::1" not in wire
            assert "\"port\":" not in wire and "socket" not in wire
            assert "127.0.0.1" not in repr(runtime) and "port" not in repr(runtime)
            assert runtime._server is not None and runtime._server.is_serving()
        finally:
            await runtime.stop()
        assert runtime.snapshot().state == TcpRuntimeState.STOPPED
        assert runtime._server is None
        assert not runtime._connection_tasks
        assert not runtime._processor_task or runtime._processor_task.done()
    _run(scenario())


def test_ipv6_family_uses_only_fixed_loopback_literal():
    async def scenario():
        runtime = TcpSyslogRuntime(_config(bind_family="ipv6"))
        await runtime.start()
        try:
            assert all(sock.family == socket.AF_INET6 for sock in runtime._server.sockets)
            assert all(sock.getsockname()[0] == "::1" for sock in runtime._server.sockets)
            port = runtime._server.sockets[0].getsockname()[1]
            _reader, writer = await asyncio.open_connection("::1", port, family=socket.AF_INET6)
            writer.close()
            await writer.wait_closed()
        finally:
            await runtime.stop()
    _run(scenario())


@pytest.mark.parametrize("role", ["application", "ssh"])
def test_role_pipeline_accepts_single_partial_and_batched_frames_without_publication(role):
    async def scenario():
        runtime = TcpSyslogRuntime(_config(role))
        await runtime.start()
        port = runtime._server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            failures = [_wire(_line(role, i, "login_failed")) for i in range(1, 6)]
            success = _wire(_line(role, 6, "user_login"))
            writer.write(failures[0][:5])
            await writer.drain()
            writer.write(failures[0][5:] + b"".join(failures[1:]) + success)
            await writer.drain()
            await runtime.wait_until_processed(6, timeout=3.0)
            status = runtime.snapshot()
            summary = runtime.internal_analysis_summary()
            assert status.accepted_frames == 6
            assert status.parsed_events == 6
            assert status.analyzed_events == 6
            assert status.parser_rejected_events == 0
            assert summary.revision == 6
            assert summary.case_count >= 1
            assert runtime._detection._history
            assert all(not event.raw.strip() for event in runtime._detection._history)
            assert runtime._publication is None
            assert "192.0.2.19" not in json.dumps(status.to_dict())
        finally:
            writer.close()
            await writer.wait_closed()
            await runtime.stop()
    _run(scenario())


@pytest.mark.parametrize("role", ["application", "ssh"])
def test_parser_rejections_and_malformed_frames_are_fixed_and_do_not_leak(role):
    async def scenario():
        runtime = TcpSyslogRuntime(_config(role))
        await runtime.start()
        port = runtime._server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            writer.write(_wire("malformed parser input ACCOUNT_CANARY 198.51.100.29") + b"+1 secret")
            await writer.drain()
            await runtime.wait_until_processed(1, timeout=1.0)
            status = runtime.snapshot()
            assert status.accepted_frames == 1
            assert status.parser_rejected_events == 1
            assert status.rejected_frames >= 1
            safe = json.dumps(status.to_dict(), sort_keys=True) + repr(status)
            for secret in ("ACCOUNT_CANARY", "198.51.100.29", "secret"):
                assert secret not in safe
            assert status.error_category in {"NONE", "FRAME_REJECTED"}
        finally:
            writer.close()
            await writer.wait_closed()
            await runtime.stop()
    _run(scenario())


def test_connection_cap_rejects_third_client_without_reading_payload():
    async def scenario():
        runtime = TcpSyslogRuntime(_config(connection_limit=2))
        await runtime.start()
        port = runtime._server.sockets[0].getsockname()[1]
        clients = [await asyncio.open_connection("127.0.0.1", port) for _ in range(3)]
        try:
            clients[2][1].write(b"PRIVATE_UNREAD_PAYLOAD")
            await clients[2][1].drain()
            try:
                response = await asyncio.wait_for(clients[2][0].read(1), timeout=0.5)
            except ConnectionResetError:
                response = b""
            assert response == b""
            await asyncio.sleep(0.05)
            status = runtime.snapshot()
            assert status.active_connections == 2
            assert status.rejected_connections == 1
            assert status.accepted_frames == 0
        finally:
            for _reader, writer in clients:
                writer.close()
            await runtime.stop()
    _run(scenario())


def test_bind_conflict_fails_without_listening_or_endpoint_disclosure():
    async def scenario():
        blocker = await asyncio.start_server(lambda _r, _w: None, "127.0.0.1", 0)
        port = blocker.sockets[0].getsockname()[1]
        runtime = TcpSyslogRuntime(_config(port=port, test_only_ephemeral_port=False))
        try:
            with pytest.raises(TcpRuntimeError) as raised:
                await runtime.start()
            assert raised.value.code == TcpRuntimeErrorCode.PORT_IN_USE
            assert str(port) not in str(raised.value) + repr(raised.value)
            assert runtime.snapshot().state == TcpRuntimeState.FAILED
            assert runtime._server is None and not runtime._connection_tasks
        finally:
            await runtime.stop()
            blocker.close()
            await blocker.wait_closed()
    _run(scenario())


def test_idle_timeout_closes_partial_frame_and_does_not_reuse_decoder():
    async def scenario():
        runtime = TcpSyslogRuntime(_config(idle_timeout_seconds=0.1, read_timeout_seconds=0.5))
        await runtime.start()
        port = runtime._server.sockets[0].getsockname()[1]
        _reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"20 partial")
        await writer.drain()
        await asyncio.sleep(0.25)
        assert runtime.snapshot().rejected_frames == 1
        assert runtime.snapshot().error_category == TcpRuntimeErrorCode.IDLE_TIMEOUT.value
        writer.close()
        await writer.wait_closed()
        await runtime.stop()
    _run(scenario())


def test_read_timeout_is_separate_from_connection_idle_timeout():
    async def scenario():
        runtime = TcpSyslogRuntime(_config(idle_timeout_seconds=1.0, read_timeout_seconds=0.05))
        await runtime.start()
        port = runtime._server.sockets[0].getsockname()[1]
        _reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"10 partial")
        await writer.drain()
        await asyncio.sleep(0.1)
        assert runtime.snapshot().rejected_frames == 1
        assert runtime.snapshot().error_category == TcpRuntimeErrorCode.READ_TIMEOUT.value
        writer.close()
        await writer.wait_closed()
        await runtime.stop()
    _run(scenario())


def test_stop_is_idempotent_releases_listener_and_all_tasks():
    async def scenario():
        runtime = TcpSyslogRuntime(_config())
        await runtime.start()
        port = runtime._server.sockets[0].getsockname()[1]
        await runtime.stop()
        await runtime.stop()
        replacement = await asyncio.start_server(lambda _r, _w: None, "127.0.0.1", port)
        replacement.close()
        await replacement.wait_closed()
        assert runtime.snapshot().state == TcpRuntimeState.STOPPED
        assert not runtime._connection_tasks
        assert not runtime._connections
    _run(scenario())


def test_epoch_is_ephemeral_and_never_in_safe_snapshot():
    async def scenario():
        first, second = TcpSyslogRuntime(_config()), TcpSyslogRuntime(_config())
        await first.start()
        await second.start()
        try:
            assert first.epoch_id != second.epoch_id
            safe = json.dumps(first.snapshot().to_dict())
            assert first.epoch_id not in safe
        finally:
            await first.stop()
            await second.stop()
    _run(scenario())


def test_pipeline_fault_is_sanitized_and_cleanup_continues(monkeypatch):
    async def parser_failure():
        runtime = TcpSyslogRuntime(_config())
        import app.log_collection.runtime as runtime_module
        monkeypatch.setattr(runtime_module, "parse_live_records",
                            lambda *_args: (_ for _ in ()).throw(RuntimeError("PRIVATE_ANALYSIS_CANARY")))
        await runtime.start()
        port = runtime._server.sockets[0].getsockname()[1]
        _reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            wire = _wire(_line("application", 1, "login_failed"))
            writer.write(wire)
            await writer.drain()
            await asyncio.sleep(0.05)
            assert runtime.snapshot().state == TcpRuntimeState.FAILED
            safe = json.dumps(runtime.snapshot().to_dict()) + repr(runtime.snapshot())
            assert "PRIVATE_ANALYSIS_CANARY" not in safe
            assert runtime.snapshot().dropped_frames >= 1
        finally:
            writer.close()
            await writer.wait_closed()
            await runtime.stop()
    _run(parser_failure())


def _assert_bind_failure_is_sanitized(failure, expected, monkeypatch, caplog, capsys):
    async def scenario():
        runtime = TcpSyslogRuntime(_config())

        async def fail_bind(_host, _port):
            raise failure

        monkeypatch.setattr(runtime, "_create_server", fail_bind)
        with pytest.raises(TcpRuntimeError) as raised:
            await runtime.start()

        assert raised.value.code == expected
        assert runtime.snapshot().state == TcpRuntimeState.FAILED
        assert runtime.snapshot().error_category == expected.value
        exposed = str(raised.value) + repr(raised.value)
        exposed += json.dumps(runtime.snapshot().to_dict(), sort_keys=True)
        captured = capsys.readouterr()
        exposed += caplog.text + captured.out + captured.err
        assert "PRIVATE_" not in exposed

        await runtime.stop()
        assert runtime.snapshot().state == TcpRuntimeState.STOPPED

    _run(scenario())


def test_eaddrinuse_is_classified_as_port_in_use(monkeypatch, caplog, capsys):
    _assert_bind_failure_is_sanitized(
        OSError(errno.EADDRINUSE, "PRIVATE_PORT_CANARY"),
        TcpRuntimeErrorCode.PORT_IN_USE,
        monkeypatch,
        caplog,
        capsys,
    )


@pytest.mark.parametrize(
    "failure",
    [
        OSError(errno.EACCES, "PRIVATE_BIND_CANARY"),
        OSError(max(errno.errorcode, default=0) + 1, "PRIVATE_UNKNOWN_ERRNO_CANARY"),
        OSError("PRIVATE_MISSING_ERRNO_CANARY"),
    ],
    ids=["access-denied", "unknown-errno", "missing-errno"],
)
def test_non_eaddrinuse_bind_errors_are_fixed_bind_failed(failure, monkeypatch, caplog, capsys):
    _assert_bind_failure_is_sanitized(
        failure,
        TcpRuntimeErrorCode.BIND_FAILED,
        monkeypatch,
        caplog,
        capsys,
    )


def test_tcp_bind_fault_tests_use_platform_independent_errno_names():
    tests_root = Path(__file__).parent
    runtime_source = (tests_root.parent / "app/log_collection/runtime.py").read_text(encoding="utf-8")
    assert "errno.EADDRINUSE" in runtime_source
    numeric_errno = re.compile(r"OSError\(\s*(?:98|48)\s*,")
    assert all(numeric_errno.search(path.read_text(encoding="utf-8")) is None
               for path in tests_root.rglob("*.py"))
    source = Path(__file__).read_text(encoding="utf-8")
    assert "errno.EADDRINUSE" in source


def test_queue_overload_is_visible_and_never_exceeds_configured_caps():
    async def scenario():
        runtime = TcpSyslogRuntime(_config(max_queue_events=1, max_queue_bytes=8192))
        await runtime.start()
        port = runtime._server.sockets[0].getsockname()[1]
        _reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            writer.write(_wire(_line("application", 1, "login_failed"))
                         + _wire(_line("application", 2, "login_failed"))
                         + _wire(_line("application", 3, "login_failed")))
            await writer.drain()
            await asyncio.sleep(0.1)
            snapshot = runtime.snapshot()
            assert snapshot.queued_events <= snapshot.queue_event_limit == 1
            assert snapshot.queued_bytes <= snapshot.queue_byte_limit
            assert snapshot.accepted_frames == 1
            assert snapshot.rejected_frames == 2
            assert snapshot.error_category == TcpRuntimeErrorCode.QUEUE_OVERLOAD.value
            assert snapshot.state == TcpRuntimeState.DEGRADED
        finally:
            writer.close()
            await writer.wait_closed()
            await runtime.stop()
    _run(scenario())


def test_runtime_analysis_summary_is_deterministic_for_same_synthetic_sequence():
    async def execute_once():
        runtime = TcpSyslogRuntime(_config())
        await runtime.start()
        port = runtime._server.sockets[0].getsockname()[1]
        _reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            writer.write(b"".join(_wire(_line("application", second, "login_failed"))
                                  for second in range(1, 6))
                         + _wire(_line("application", 6, "user_login")))
            await writer.drain()
            await runtime.wait_until_processed(6, timeout=3.0)
            return runtime.internal_analysis_summary()
        finally:
            writer.close()
            await writer.wait_closed()
            await runtime.stop()
    previous_tz = os.environ.get("TZ")
    try:
        os.environ["TZ"] = "UTC"
        time.tzset()
        first = _run(execute_once())
        os.environ["TZ"] = "Asia/Seoul"
        time.tzset()
        second = _run(execute_once())
    finally:
        if previous_tz is None:
            os.environ.pop("TZ", None)
        else:
            os.environ["TZ"] = previous_tz
        time.tzset()
    assert first == second


def test_queue_admission_fault_is_fixed_and_stops_the_listener(monkeypatch):
    async def scenario():
        runtime = TcpSyslogRuntime(_config())
        await runtime.start()
        port = runtime._server.sockets[0].getsockname()[1]
        from app.log_collection.queue import BoundedEventQueue
        monkeypatch.setattr(BoundedEventQueue, "enqueue",
                            lambda _self, _frame: (_ for _ in ()).throw(
                                CollectionCoreError(CollectionErrorCode.QUEUE_FULL)))
        _reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            writer.write(_wire(_line("application", 1, "login_failed")))
            await writer.drain()
            await asyncio.sleep(0.05)
            snapshot = runtime.snapshot()
            assert snapshot.accepted_frames == 0
            assert snapshot.rejected_frames == 1
            assert snapshot.error_category == TcpRuntimeErrorCode.QUEUE_OVERLOAD.value
            assert snapshot.state == TcpRuntimeState.DEGRADED
            assert runtime._server is not None and not runtime._server.is_serving()
        finally:
            writer.close()
            await writer.wait_closed()
            await runtime.stop()
    _run(scenario())


def test_connection_task_creation_and_read_faults_fail_closed_without_exception_text():
    async def task_creation_fault():
        runtime = TcpSyslogRuntime(_config())
        await runtime.start()
        port = runtime._server.sockets[0].getsockname()[1]
        runtime._spawn_connection_task = lambda *_args: (_ for _ in ()).throw(
            RuntimeError("PRIVATE_TASK_CANARY"))
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            await asyncio.sleep(0.05)
            assert runtime.snapshot().state == TcpRuntimeState.FAILED
            assert runtime.snapshot().rejected_connections == 1
            assert runtime.snapshot().error_category == TcpRuntimeErrorCode.INTERNAL_FAILURE.value
            assert "PRIVATE_TASK_CANARY" not in json.dumps(runtime.snapshot().to_dict())
        finally:
            writer.close()
            await runtime.stop()
    _run(task_creation_fault())

    async def read_fault():
        runtime = TcpSyslogRuntime(_config())
        runtime._read_chunk = lambda *_args: (_ for _ in ()).throw(
            RuntimeError("PRIVATE_READ_CANARY"))
        await runtime.start()
        port = runtime._server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            await asyncio.sleep(0.05)
            safe = json.dumps(runtime.snapshot().to_dict()) + repr(runtime.snapshot())
            assert runtime.snapshot().state == TcpRuntimeState.FAILED
            assert runtime.snapshot().error_category == TcpRuntimeErrorCode.INTERNAL_FAILURE.value
            assert "PRIVATE_READ_CANARY" not in safe
        finally:
            writer.close()
            await runtime.stop()
    _run(read_fault())


def test_cleanup_attempts_every_owned_resource_after_independent_failures(monkeypatch):
    async def scenario():
        runtime = TcpSyslogRuntime(_config())
        await runtime.start()
        calls = []
        from app.live_monitoring.analysis_accumulator import LiveAnalysisAccumulator
        from app.live_monitoring.detection_accumulator import LiveDetectionAccumulator
        from app.log_collection.queue import BoundedEventQueue
        monkeypatch.setattr(BoundedEventQueue, "close",
                            lambda _self: (_ for _ in ()).throw(RuntimeError("PRIVATE_CLEANUP_CANARY")))
        monkeypatch.setattr(LiveAnalysisAccumulator, "close",
                            lambda _self: (calls.append("analysis"), (_ for _ in ()).throw(
                                RuntimeError("PRIVATE_ANALYSIS_CLEANUP_CANARY")))[1])
        monkeypatch.setattr(LiveDetectionAccumulator, "close", lambda _self: calls.append("detection"))
        await runtime.stop()
        assert calls == ["analysis", "detection"]
        snapshot = runtime.snapshot()
        assert snapshot.state == TcpRuntimeState.STOPPED
        assert snapshot.error_category == TcpRuntimeErrorCode.SHUTDOWN_FAILED.value
        safe = json.dumps(snapshot.to_dict()) + repr(snapshot)
        assert "PRIVATE_CLEANUP_CANARY" not in safe
        assert "PRIVATE_ANALYSIS_CLEANUP_CANARY" not in safe
        await runtime.stop()
    _run(scenario())


def test_slow_partial_connection_does_not_starve_second_connection_and_eof_rejects():
    async def scenario():
        runtime = TcpSyslogRuntime(_config(idle_timeout_seconds=2.0, read_timeout_seconds=0.5))
        await runtime.start()
        port = runtime._server.sockets[0].getsockname()[1]
        slow_reader, slow_writer = await asyncio.open_connection("127.0.0.1", port)
        fast_reader, fast_writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            slow_writer.write(b"100 partial")
            await slow_writer.drain()
            fast_writer.write(_wire(_line("application", 1, "login_failed")))
            await fast_writer.drain()
            await runtime.wait_until_processed(1, timeout=2.0)
            assert runtime.snapshot().active_connections == 2
            assert runtime.snapshot().analyzed_events == 1
            slow_writer.close()
            await slow_writer.wait_closed()
            await asyncio.sleep(0.05)
            assert runtime.snapshot().rejected_frames == 1
            assert runtime.snapshot().active_connections <= 1
        finally:
            fast_writer.close()
            await fast_writer.wait_closed()
            await runtime.stop()
    _run(scenario())


def test_rapid_connect_disconnect_and_malformed_reconnect_use_fresh_decoders():
    async def scenario():
        runtime = TcpSyslogRuntime(_config())
        await runtime.start()
        port = runtime._server.sockets[0].getsockname()[1]
        try:
            for _ in range(20):
                _reader, writer = await asyncio.open_connection("127.0.0.1", port)
                writer.write(b"+1 forbidden")
                await writer.drain()
                writer.close()
                await writer.wait_closed()
            await asyncio.sleep(0.1)
            snapshot = runtime.snapshot()
            assert snapshot.active_connections == 0
            assert snapshot.accepted_frames == 0
            assert snapshot.rejected_frames == 20
            assert snapshot.error_category == TcpRuntimeErrorCode.FRAME_REJECTED.value
            assert runtime._queue.snapshot().queued_events == 0
        finally:
            await runtime.stop()
    _run(scenario())
