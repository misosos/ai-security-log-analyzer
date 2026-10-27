"""Contract tests for the synthetic-only JSONL collector runtime."""

import asyncio
import errno
import json
import subprocess
import sys
from pathlib import Path
import socket

import pytest

from app.log_collection.jsonl_runtime import (
    JsonlRuntimeConfig, JsonlRuntimeError, JsonlRuntimeErrorCode,
    JsonlRuntimeState, JsonlCollectorRuntime,
)
from app.log_collection.jsonl_adapter import AdapterErrorCode, JsonlAdapterError
from app.live_monitoring.analysis_accumulator import LiveAnalysisAccumulator
from app.live_monitoring.core import LiveTailRecord
from app.live_monitoring.detection_accumulator import LiveDetectionAccumulator
from app.live_monitoring.parser_adapter import parse_live_records


def _config(role="application", **changes):
    values = dict(source_role=role, host="127.0.0.1", port=0,
                  test_only_ephemeral_port=True)
    values.update(changes)
    return JsonlRuntimeConfig(**values)


def test_config_is_closed_loopback_only_and_repr_is_safe():
    config = _config()
    assert "127.0.0.1" not in repr(config)
    with pytest.raises(JsonlRuntimeError) as error:
        _config(host="0.0.0.0")
    assert error.value.code is JsonlRuntimeErrorCode.CONFIG_INVALID
    for host in ("localhost", "::", "::ffff:127.0.0.1", "192.168.1.2", "169.254.1.2"):
        with pytest.raises(JsonlRuntimeError):
            _config(host=host)
    with pytest.raises(JsonlRuntimeError):
        JsonlRuntimeConfig.from_mapping({**config.to_dict(), "surprise": "CANARY"})
    with pytest.raises(JsonlRuntimeError):
        _config(port=True)


def test_runtime_binds_loopback_validates_jsonl_and_exposes_safe_status():
    async def scenario():
        runtime = JsonlCollectorRuntime(_config())
        await runtime.start()
        try:
            assert runtime.snapshot().state is JsonlRuntimeState.RUNNING
            port = runtime._server.sockets[0].getsockname()[1]
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            payload = "synthetic app event"
            envelope = {"schema_version": 1, "source_role": "application",
                        "payload": payload, "collector_instance_alias": "collector-1",
                        "sequence_hint": None, "retry_hint": False}
            writer.write(json.dumps(envelope).encode() + b"\n")
            await writer.drain()
            await runtime.wait_until_processed(1)
            status = runtime.snapshot().to_dict()
            assert status["queue_accepted"] == 1
            assert status["analysis_completed"] == 1
            _assert_absent(json.dumps(status), (payload,))
            writer.close()
            await writer.wait_closed()
        finally:
            await runtime.stop()
        assert runtime.snapshot().state is JsonlRuntimeState.STOPPED

    asyncio.run(scenario())


def test_runtime_rejects_non_loopback_and_sanitizes_internal_failure():
    async def scenario():
        runtime = JsonlCollectorRuntime(_config("ssh"))
        runtime._create_server = lambda *_args: _raise(OSError("PRIVATE_CANARY"))
        with pytest.raises(JsonlRuntimeError) as error:
            await runtime.start()
        assert error.value.code is JsonlRuntimeErrorCode.BIND_FAILED
        _assert_absent(str(error.value) + repr(error.value), ("PRIVATE_CANARY",))
        await runtime.stop()
    asyncio.run(scenario())


@pytest.mark.parametrize(("failure", "expected"), [
    (OSError(errno.EADDRINUSE, "PRIVATE_CANARY"), JsonlRuntimeErrorCode.PORT_IN_USE),
    (OSError(errno.EACCES, "PRIVATE_CANARY"), JsonlRuntimeErrorCode.BIND_FAILED),
    (OSError("PRIVATE_CANARY"), JsonlRuntimeErrorCode.BIND_FAILED),
])
def test_bind_errno_categories_are_portable_and_safe(failure, expected):
    async def scenario():
        runtime = JsonlCollectorRuntime(_config())
        runtime._create_server = lambda: _raise(failure)
        with pytest.raises(JsonlRuntimeError) as error:
            await runtime.start()
        assert error.value.code is expected
        _assert_absent(str(error.value) + repr(error.value), ("PRIVATE_CANARY",))
        await runtime.stop()
        assert runtime._worker is None and runtime._server is None
    asyncio.run(scenario())


def test_partial_start_worker_failure_cleans_all_prepared_resources():
    async def scenario():
        runtime = JsonlCollectorRuntime(_config())
        runtime._spawn_worker_task = lambda: _raise(RuntimeError("INTERNAL_CANARY"))
        with pytest.raises(JsonlRuntimeError) as error:
            await runtime.start()
        assert error.value.code is JsonlRuntimeErrorCode.INTERNAL_FAILURE
        _assert_absent(str(error.value) + repr(error.value), ("INTERNAL_CANARY",))
        assert runtime._server is None and runtime._worker is None
        await runtime.stop()
    asyncio.run(scenario())


def test_decoder_creation_and_analysis_faults_are_terminal_and_sanitized(monkeypatch):
    async def scenario():
        runtime = JsonlCollectorRuntime(_config())
        runtime._new_decoder = lambda: _raise(RuntimeError("DECODER_PRIVATE_CANARY"))
        await runtime.start()
        port = runtime._server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"x"); await writer.drain()
        try:
            await asyncio.wait_for(reader.read(), 2)
        except ConnectionResetError:
            pass
        assert runtime.snapshot().state is JsonlRuntimeState.FAILED
        assert runtime.snapshot().error_category == JsonlRuntimeErrorCode.INTERNAL_FAILURE.value
        safe = repr(runtime) + repr(runtime.snapshot()) + json.dumps(runtime.snapshot().to_dict())
        _assert_absent(safe, ("DECODER_PRIVATE_CANARY",))
        writer.close()
        try:
            await writer.wait_closed()
        except ConnectionResetError:
            pass
        await runtime.stop()

        runtime = JsonlCollectorRuntime(_config())
        monkeypatch.setattr("app.log_collection.jsonl_runtime.parse_live_records",
                            lambda *_args: _raise(RuntimeError("ANALYSIS_PRIVATE_CANARY")))
        await runtime.start()
        port = runtime._server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        envelope = {"schema_version": 1, "source_role": "application", "payload": "synthetic",
                    "collector_instance_alias": "collector-1", "sequence_hint": None,
                    "retry_hint": False}
        writer.write(json.dumps(envelope).encode() + b"\n"); await writer.drain()
        async def failed():
            while runtime.snapshot().state is not JsonlRuntimeState.FAILED:
                await asyncio.sleep(0)
        await asyncio.wait_for(failed(), 2)
        snap = runtime.snapshot()
        assert snap.queue_accepted == 1 and snap.processing_dropped == 1
        assert snap.analysis_completed == 0
        safe = repr(runtime) + repr(snap) + json.dumps(snap.to_dict())
        _assert_absent(safe, ("ANALYSIS_PRIVATE_CANARY",))
        writer.close()
        try:
            await writer.wait_closed()
        except ConnectionResetError:
            pass
        await runtime.stop()
    asyncio.run(scenario())


def test_status_snapshot_failure_is_sanitized_and_stop_is_repeatable(monkeypatch):
    async def scenario():
        runtime = JsonlCollectorRuntime(_config())
        await runtime.start()
        monkeypatch.setattr("app.live_monitoring.detection_accumulator.LiveDetectionAccumulator.snapshot",
                            lambda _self: _raise(RuntimeError("STATUS_PRIVATE_CANARY")))
        with pytest.raises(JsonlRuntimeError) as error:
            runtime.snapshot()
        assert error.value.code is JsonlRuntimeErrorCode.INTERNAL_FAILURE
        _assert_absent(str(error.value) + repr(error.value), ("STATUS_PRIVATE_CANARY",))
        monkeypatch.undo()
        await runtime.stop()
        await runtime.stop()
        assert runtime.snapshot().state is JsonlRuntimeState.STOPPED
    asyncio.run(scenario())


def test_analysis_failure_stops_collection_without_counting_completion(monkeypatch):
    async def scenario():
        runtime = JsonlCollectorRuntime(_config())
        monkeypatch.setattr("app.live_monitoring.analysis_accumulator.LiveAnalysisAccumulator.prepare",
                            lambda *_args: _raise(RuntimeError("PRIVATE_ANALYSIS_CANARY")))
        await runtime.start()
        port = runtime._server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        envelope = {"schema_version": 1, "source_role": "application", "payload": "synthetic",
                    "collector_instance_alias": "collector-1", "sequence_hint": None,
                    "retry_hint": False}
        writer.write(json.dumps(envelope).encode() + b"\n"); await writer.drain()
        async def failed():
            while runtime.snapshot().state is not JsonlRuntimeState.FAILED:
                await asyncio.sleep(0)
        await asyncio.wait_for(failed(), 2)
        snap = runtime.snapshot()
        assert snap.parser_unrecognized == 1
        assert snap.processing_dropped == 1 and snap.analysis_completed == 0
        _assert_absent(repr(snap) + json.dumps(snap.to_dict()), ("PRIVATE_ANALYSIS_CANARY",))
        writer.close()
        try:
            await writer.wait_closed()
        except ConnectionResetError:
            pass
        await runtime.stop()
    asyncio.run(scenario())


def test_listener_cleanup_failures_do_not_skip_other_cleanup(monkeypatch):
    async def scenario():
        runtime = JsonlCollectorRuntime(_config())
        await runtime.start()
        port = runtime._server.sockets[0].getsockname()[1]
        real = runtime._server
        calls = []

        class FaultyServer:
            sockets = real.sockets

            def close(self):
                calls.append("close")
                real.close()
                raise RuntimeError("PRIVATE_CLOSE_CANARY")

            async def wait_closed(self):
                calls.append("wait_closed")
                await real.wait_closed()
                raise RuntimeError("PRIVATE_WAIT_CANARY")

        runtime._server = FaultyServer()
        with pytest.raises(JsonlRuntimeError) as error:
            await runtime.stop()
        assert error.value.code is JsonlRuntimeErrorCode.CLEANUP_FAILED
        _assert_absent(str(error.value) + repr(error.value),
                       ("PRIVATE_CLOSE_CANARY", "PRIVATE_WAIT_CANARY"))
        assert calls == ["close", "wait_closed"]
        assert runtime._server is None and runtime._worker is None
        with socket.socket() as reuse:
            reuse.bind(("127.0.0.1", port))
        assert runtime.snapshot().state is JsonlRuntimeState.STOPPED
    asyncio.run(scenario())


def test_connection_task_creation_failure_closes_listener_and_client():
    async def scenario():
        runtime = JsonlCollectorRuntime(_config())
        runtime._spawn_connection_task = lambda *_args: _raise(RuntimeError("PRIVATE_TASK_CANARY"))
        await runtime.start()
        port = runtime._server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            await asyncio.wait_for(reader.read(), 1)
        except ConnectionResetError:
            pass
        assert runtime.snapshot().state is JsonlRuntimeState.FAILED
        safe = repr(runtime) + repr(runtime.snapshot()) + json.dumps(runtime.snapshot().to_dict())
        _assert_absent(safe, ("PRIVATE_TASK_CANARY",))
        await runtime.stop()
        assert runtime._server is None and not runtime._connections and not runtime._closing
        writer.close()
        try:
            await writer.wait_closed()
        except ConnectionResetError:
            pass
    asyncio.run(scenario())


def test_stop_cancels_partial_connection_and_is_repeatable():
    async def scenario():
        runtime = JsonlCollectorRuntime(_config())
        await runtime.start()
        port = runtime._server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b'{"schema_version":'); await writer.drain()
        async def accepted():
            while runtime.snapshot().active_connections != 1:
                await asyncio.sleep(0)
        await asyncio.wait_for(accepted(), 1)
        await runtime.stop()
        await runtime.stop()
        snap = runtime.snapshot()
        assert snap.state is JsonlRuntimeState.STOPPED
        assert snap.active_connections == 0
        assert runtime._server is None and runtime._worker is None
        writer.close()
        try:
            await writer.wait_closed()
        except ConnectionResetError:
            pass
    asyncio.run(scenario())


@pytest.mark.parametrize("role", ["application", "ssh"])
def test_runtime_malformed_connection_isolated_and_analysis_metadata_is_ignored(role):
    async def scenario():
        runtime = JsonlCollectorRuntime(_config(role))
        await runtime.start()
        port = runtime._server.sockets[0].getsockname()[1]
        bad_reader, bad_writer = await asyncio.open_connection("127.0.0.1", port)
        bad_writer.write(b'{"payload":"PRIVATE_CANARY"}\n')
        await bad_writer.drain()
        bad_writer.close()
        await bad_writer.wait_closed()
        good_reader, good_writer = await asyncio.open_connection("127.0.0.1", port)
        payload = ("2026-01-02 03:04:05 INFO user_login user=synthetic_user ip=192.0.2.41 service=ssh"
                   if role == "application" else
                   "2026-01-02 03:04:05 sshd: Accepted password for synthetic_user from 192.0.2.41 port 45001 ssh2")
        envelope = {"schema_version": 1, "source_role": role, "payload": payload,
                    "collector_instance_alias": "private-alias", "sequence_hint": "private-sequence",
                    "retry_hint": True}
        good_writer.write(json.dumps(envelope).encode() + b"\n")
        await good_writer.drain()
        await runtime.wait_until_processed(1)
        snap = runtime.snapshot()
        encoded = json.dumps(snap.to_dict(), sort_keys=True) + repr(snap) + repr(runtime)
        _assert_absent(encoded, (payload, "private-alias", "private-sequence", "PRIVATE_CANARY",
                                 "192.0.2.41", "45001"))
        assert snap.malformed == 1
        assert snap.queue_accepted == 1 and snap.analysis_completed == 1
        assert snap.processing_dropped == 0
        good_writer.close()
        await good_writer.wait_closed()
        await runtime.stop()
    asyncio.run(scenario())


def test_subprocess_smoke_runs_two_roles_with_both_shutdown_signals():
    script = Path("tests/smoke_collector_jsonl_runtime_35_3.py")
    result = subprocess.run([sys.executable, str(script)], capture_output=True, text=True, timeout=30)
    if result.returncode != 0:
        pytest.fail("synthetic subprocess smoke failed at a fixed stage")
    if result.stdout.strip() != "COLLECTOR_JSONL_RUNTIME_SMOKE_PASS roles=2 subprocesses=4 synthetic=1 leaks=0":
        pytest.fail("synthetic subprocess smoke omitted its safe completion marker")
    if result.stderr:
        pytest.fail("synthetic subprocess smoke wrote stderr")


@pytest.mark.parametrize("role", ["application", "ssh"])
def test_256_record_bounded_synthetic_soak(role):
    async def scenario():
        runtime = JsonlCollectorRuntime(_config(role))
        await runtime.start()
        port = runtime._server.sockets[0].getsockname()[1]
        payload = ("2026-01-02 03:04:05 INFO user_login user=synthetic_user ip=192.0.2.41 service=ssh"
                   if role == "application" else
                   "2026-01-02 03:04:05 sshd: Accepted password for synthetic_user from 192.0.2.41 port 45001 ssh2")
        envelope = {"schema_version": 1, "source_role": role, "payload": payload,
                    "collector_instance_alias": "collector-1", "sequence_hint": None,
                    "retry_hint": False}
        wire = json.dumps(envelope, separators=(",", ":")).encode() + b"\n"
        _reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            for _ in range(8):
                writer.write(wire * 32)
                await writer.drain()
                await runtime.wait_until_processed(runtime.snapshot().analysis_completed + 32,
                                                   timeout=5)
            await runtime.wait_until_processed(256, timeout=15)
            status = runtime.snapshot()
            assert status.received == status.envelope_validated == status.queue_accepted == 256
            assert status.parser_recognized == status.analysis_completed == 256
            assert status.parser_unrecognized == status.processing_dropped == status.malformed == 0
            assert status.peak_queued_events <= status.queue_event_limit
            assert status.peak_queued_bytes <= status.queue_byte_limit
            assert status.history_events <= status.history_event_limit
            assert status.history_bytes <= status.history_byte_limit
        finally:
            writer.close()
            await writer.wait_closed()
            await runtime.stop()
        assert runtime.snapshot().active_connections == 0
    asyncio.run(scenario())


def test_slow_partial_connection_does_not_block_another_connection():
    async def scenario():
        runtime = JsonlCollectorRuntime(_config())
        await runtime.start()
        port = runtime._server.sockets[0].getsockname()[1]
        slow_reader, slow = await asyncio.open_connection("127.0.0.1", port)
        slow.write(b'{"schema_version":')
        await slow.drain()
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        envelope = {"schema_version": 1, "source_role": "application",
                    "payload": "2026-01-02 03:04:05 INFO user_login user=synthetic_user ip=192.0.2.41 service=ssh",
                    "collector_instance_alias": "collector-1", "sequence_hint": None,
                    "retry_hint": False}
        writer.write(json.dumps(envelope).encode() + b"\n")
        await writer.drain()
        await runtime.wait_until_processed(1)
        third_reader, third = await asyncio.open_connection("127.0.0.1", port)
        await asyncio.wait_for(third_reader.read(), 1)
        assert runtime.snapshot().connection_rejected == 1
        slow.close(); writer.close(); third.close()
        await asyncio.gather(slow.wait_closed(), writer.wait_closed(), third.wait_closed())
        await runtime.stop()
        assert runtime.snapshot().active_connections == 0
    asyncio.run(scenario())


def test_utf8_split_and_multiple_jsonl_records_preserve_wire_order():
    async def scenario():
        runtime = JsonlCollectorRuntime(_config())
        await runtime.start()
        port = runtime._server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        payloads = [
            "2026-01-02 03:04:05 INFO user_login user=synthetic_user ip=192.0.2.41 service=ssh 주석=합성",
            "2026-01-02 03:04:06 INFO user_login user=synthetic_user ip=192.0.2.42 service=ssh 주석=두번째",
        ]
        wires = [json.dumps({"schema_version": 1, "source_role": "application", "payload": payload,
                             "collector_instance_alias": "collector-1", "sequence_hint": None,
                             "retry_hint": False}, ensure_ascii=False).encode() + b"\n"
                 for payload in payloads]
        joined = b"".join(wires)
        for byte in joined:
            writer.write(bytes((byte,)))
            await writer.drain()
        await runtime.wait_until_processed(2)
        status = runtime.snapshot()
        assert status.received == status.envelope_validated == status.queue_accepted == 2
        assert status.analysis_completed == 2
        assert status.queued_events == status.queued_bytes == 0
        writer.close(); await writer.wait_closed()
        await runtime.stop()
    asyncio.run(scenario())


def test_role_mismatch_and_read_timeout_reject_without_stopping_listener():
    async def scenario():
        runtime = JsonlCollectorRuntime(_config(read_timeout_seconds=0.05,
                                                idle_timeout_seconds=0.2))
        await runtime.start()
        port = runtime._server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        mismatch = {"schema_version": 1, "source_role": "ssh", "payload": "synthetic",
                    "collector_instance_alias": "collector-1", "sequence_hint": None,
                    "retry_hint": False}
        writer.write(json.dumps(mismatch).encode() + b"\n"); await writer.drain()
        try:
            await asyncio.wait_for(reader.read(), 1)
        except ConnectionResetError:
            pass
        assert runtime.snapshot().malformed == 1
        writer.close()
        try:
            await writer.wait_closed()
        except ConnectionResetError:
            pass

        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            await asyncio.wait_for(reader.read(), 1)
        except ConnectionResetError:
            pass
        assert runtime.snapshot().terminal_failures == 1
        assert runtime.snapshot().state is JsonlRuntimeState.RUNNING
        writer.close()
        try:
            await writer.wait_closed()
        except ConnectionResetError:
            pass
        await runtime.stop()
    asyncio.run(scenario())


def test_queue_full_degrades_without_silent_success(monkeypatch):
    async def scenario():
        runtime = JsonlCollectorRuntime(_config())
        monkeypatch.setattr("app.log_collection.jsonl_runtime.BoundedJsonLinesQueue.enqueue",
                            lambda _queue, _item: _raise_adapter(AdapterErrorCode.QUEUE_FULL))
        await runtime.start()
        port = runtime._server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        envelope = {"schema_version": 1, "source_role": "application", "payload": "synthetic",
                    "collector_instance_alias": "collector-1", "sequence_hint": None,
                    "retry_hint": False}
        writer.write(json.dumps(envelope).encode() + b"\n")
        await writer.drain()
        await reader.read()
        with pytest.raises(JsonlRuntimeError) as wait_error:
            await runtime.wait_until_processed(1)
        assert wait_error.value.code is JsonlRuntimeErrorCode.QUEUE_FULL
        assert runtime.snapshot().queue_rejected == 1
        assert runtime.snapshot().state is JsonlRuntimeState.DEGRADED
        assert runtime.snapshot().analysis_completed == 0
        writer.close(); await writer.wait_closed()
        await runtime.stop()
    asyncio.run(scenario())


def _raise_adapter(code):
    raise JsonlAdapterError(code)


def _assert_absent(text, values):
    if any(value in text for value in values):
        pytest.fail("privacy boundary invariant failed")


@pytest.mark.parametrize("role", ["application", "ssh"])
def test_internal_analysis_matches_direct_existing_pipeline(role):
    async def scenario():
        payload = ("2026-01-02 03:04:05 INFO user_login user=synthetic_user ip=192.0.2.41 service=ssh"
                   if role == "application" else
                   "2026-01-02 03:04:05 sshd: Accepted password for synthetic_user from 192.0.2.41 port 45001 ssh2")
        runtime = JsonlCollectorRuntime(_config(role))
        await runtime.start()
        port = runtime._server.sockets[0].getsockname()[1]
        envelope = {"schema_version": 1, "source_role": role, "payload": payload,
                    "collector_instance_alias": "ignored-alias", "sequence_hint": "ignored-sequence",
                    "retry_hint": True}
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(json.dumps(envelope).encode() + b"\n")
        await writer.drain()
        await runtime.wait_until_processed(1)

        detection = LiveDetectionAccumulator(role, 256, 262144)
        analysis = LiveAnalysisAccumulator(detection, ())
        batch = parse_live_records(role, (LiveTailRecord(role, 1, payload, len(payload.encode())),))
        proposal = detection.prepare(batch)
        analysis_proposal = analysis.prepare(proposal)
        detection.prevalidate(proposal)
        detection.commit_prepared(proposal)
        direct = analysis.commit(analysis_proposal)
        actual = runtime.internal_analysis_summary()
        assert (actual.relation_count, actual.risk_count, actual.case_count,
                actual.independent_observation_count) == (
                    direct.relation_count, direct.risk_count, direct.case_count,
                    direct.independent_observation_count)
        writer.close(); await writer.wait_closed()
        await runtime.stop()
        analysis.close(); detection.close()
    asyncio.run(scenario())


def _raise(error):
    raise error
