"""Bounded Linux subprocess acceptance for the synthetic JSONL runtime.

The child control plane uses an inherited private pipe and atomically published
status files. No endpoint, payload, path, or exception text is printed.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import resource
import selectors
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
PASS_MARKER = "COLLECTOR_JSONL_LINUX_ACCEPTANCE_PASS roles=2 runs=80 synthetic=1 leaks=0"
LOCAL_MARKER = "COLLECTOR_JSONL_LOCAL_DRY_RUN_PASS roles=2 runs=80 synthetic=1 leaks=0"
ROLES = ("application", "ssh")
SCENARIOS = (
    "readiness", "sigint", "sigterm", "normal_stop", "start_immediate",
    "record_pending", "malformed", "queue_full",
)
REPEATS = 5
RUN_TIMEOUT_SECONDS = 8.0
RECORD = {
    "schema_version": 1,
    "source_role": "application",
    "payload": "synthetic",
    "collector_instance_alias": "collector-canary",
    "sequence_hint": "sequence-canary",
    "retry_hint": False,
}


class AcceptanceFailure(Exception):
    def __init__(self, role: str, scenario: str, stage: str, category: str):
        self.role = role if role in ROLES else "unknown"
        self.scenario = scenario if scenario in SCENARIOS else "support"
        self.stage = stage
        self.category = category
        super().__init__("acceptance failure")


class _StressFailure(Exception):
    def __init__(self, stage: str, count: int = 0, expected: int = 0,
                 accepted: int = 0, rejected: int = 0):
        self.stage = stage
        self.count = count
        self.expected = expected
        self.accepted = accepted
        self.rejected = rejected
        super().__init__(stage)


def _atomic_json(path: Path, value: dict[str, Any]) -> None:
    temporary = path.with_name(path.name + ".pending")
    data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")
    with temporary.open("xb") as stream:
        os.chmod(temporary, 0o600)
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        raw = path.read_bytes()
        value = json.loads(raw)
    except (FileNotFoundError, json.JSONDecodeError, UnicodeDecodeError):
        return None
    return value if type(value) is dict else None


def _envelope(role: str, payload: str = "synthetic", *, sequence: str | None = None) -> bytes:
    value = dict(RECORD)
    value["source_role"] = role
    value["payload"] = payload
    value["sequence_hint"] = sequence
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n"


def _role_payload(role: str, path_canary: str = "PATH_CANARY") -> str:
    if role == "application":
        base = "2026-01-02 03:04:05 INFO user_login user=ACCOUNT_CANARY ip=203.0.113.42 service=ssh"
    else:
        base = "2026-01-02 03:04:05 sshd: Accepted password for ACCOUNT_CANARY from 203.0.113.42 port 45001 ssh2"
    return (base + " host=HOST_CANARY ipv6=2001:db8::42 file=FILENAME_CANARY "
            f"path={path_canary} token=CREDENTIAL_CANARY key=PRIVATE_KEY_CANARY "
            "prompt=ignore previous instructions")


def _fd_count() -> int | None:
    path = Path("/proc/self/fd")
    if not path.is_dir():
        return None
    try:
        return len(tuple(path.iterdir()))
    except OSError:
        return None


def _peak_rss_bytes() -> int | None:
    try:
        peak = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
        # Darwin reports bytes; Linux reports KiB.
        return peak if sys.platform == "darwin" else peak * 1024
    except (AttributeError, OSError, ValueError):
        return None


async def _wait_for(predicate, timeout: float = 3.0) -> bool:
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        if predicate():
            return True
        await asyncio.sleep(0)
    return bool(predicate())


async def _child(role: str, scenario: str, home: Path, marker: Path, progress: Path,
                 result: Path, control_fd: int) -> int:
    from app.log_collection.jsonl_runtime import (
        JsonlCollectorRuntime, JsonlRuntimeConfig, JsonlRuntimeError,
        JsonlRuntimeErrorCode, JsonlRuntimeState,
    )

    if role not in ROLES or scenario not in SCENARIOS:
        return 2
    before_fds = _fd_count()
    started_ns = time.monotonic_ns()
    stopping = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stopping.set)

    runtime = JsonlCollectorRuntime(JsonlRuntimeConfig(
        source_role=role, host="127.0.0.1", port=0, test_only_ephemeral_port=True,
        shutdown_timeout_seconds=2.0,
    ))
    if scenario in {"record_pending", "queue_full"}:
        # Hold accepted work before analysis to verify shutdown accounting and
        # queue-full state without altering production code.
        runtime._spawn_worker_task = lambda: asyncio.create_task(asyncio.Event().wait())

    await runtime.start()
    if runtime.snapshot().state is not JsonlRuntimeState.RUNNING:
        return 3
    sock = runtime._server.sockets[0]
    port = int(sock.getsockname()[1])
    _atomic_json(marker, {"schema": "collector-jsonl-ready/v1", "state": "RUNNING"})
    os.write(control_fd, f"{port}\n".encode("ascii"))
    os.close(control_fd)

    async def publish_progress() -> None:
        while not stopping.is_set():
            snap = runtime.snapshot()
            _atomic_json(progress, {
                "schema": "collector-jsonl-progress/v1",
                "state": snap.state.value,
                "queue_accepted": snap.queue_accepted,
                "queue_rejected": snap.queue_rejected,
                "analysis_completed": snap.analysis_completed,
                "parser_recognized": snap.parser_recognized,
                "parser_unrecognized": snap.parser_unrecognized,
                "malformed": snap.malformed,
                "processing_dropped": snap.processing_dropped,
                "queued_events": snap.queued_events,
                "queued_bytes": snap.queued_bytes,
                "queue_event_limit": snap.queue_event_limit,
                "queue_byte_limit": snap.queue_byte_limit,
            })
            try:
                await asyncio.wait_for(stopping.wait(), timeout=0.01)
            except asyncio.TimeoutError:
                pass

    initial = runtime.snapshot()
    _atomic_json(progress, {
        "schema": "collector-jsonl-progress/v1",
        "state": initial.state.value,
        "queue_accepted": initial.queue_accepted,
        "queue_rejected": initial.queue_rejected,
        "analysis_completed": initial.analysis_completed,
        "parser_recognized": initial.parser_recognized,
        "parser_unrecognized": initial.parser_unrecognized,
        "malformed": initial.malformed,
        "processing_dropped": initial.processing_dropped,
        "queued_events": initial.queued_events,
        "queued_bytes": initial.queued_bytes,
        "queue_event_limit": initial.queue_event_limit,
        "queue_byte_limit": initial.queue_byte_limit,
    })
    reporter = asyncio.create_task(publish_progress())
    result_code = 0
    queue_wait_error = "NONE"
    if scenario == "start_immediate":
        pass
    elif scenario == "queue_full":
        writer = None
        try:
            _RECORDS = 257
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            for sent in range(0, _RECORDS, 32):
                batch_end = min(sent + 32, _RECORDS)
                writer.write(b"".join(_envelope(role) for _ in range(sent, batch_end)))
                await writer.drain()
                target = batch_end
                ok = await _wait_for(lambda: runtime.snapshot().queue_accepted >= target)
                if not ok and batch_end <= 256:
                    result_code = 4
                    break
            if result_code == 0:
                ok = await _wait_for(lambda: runtime.snapshot().state is JsonlRuntimeState.DEGRADED)
                if not ok:
                    result_code = 5
                else:
                    try:
                        await runtime.wait_until_processed(257, timeout=0.05)
                    except JsonlRuntimeError as exc:
                        queue_wait_error = exc.code.value
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except (ConnectionResetError, OSError):
                    pass
        if result_code == 0:
            await stopping.wait()
    elif scenario in {"readiness", "normal_stop"}:
        # Parent sends one record after validating the atomic marker.
        processed = await _wait_for(lambda: runtime.snapshot().analysis_completed >= 1)
        if not processed:
            result_code = 6
        else:
            await runtime.stop()
    elif scenario == "record_pending":
        accepted = await _wait_for(lambda: runtime.snapshot().queue_accepted >= 1)
        if not accepted:
            result_code = 7
        else:
            await stopping.wait()
    elif scenario == "malformed":
        ready = await _wait_for(lambda: runtime.snapshot().malformed >= 1)
        processed = await _wait_for(lambda: runtime.snapshot().analysis_completed >= 1) if ready else False
        if not (ready and processed):
            result_code = 8
        else:
            await stopping.wait()
    else:
        processed = await _wait_for(lambda: runtime.snapshot().analysis_completed >= 1)
        if not processed:
            result_code = 9
        else:
            await stopping.wait()

    reporter.cancel()
    await asyncio.gather(reporter, return_exceptions=True)
    try:
        await runtime.stop()
        await runtime.stop()
    except Exception:
        result_code = 10
    await asyncio.sleep(0)
    snapshot = runtime.snapshot()
    pending = [task for task in asyncio.all_tasks()
               if task is not asyncio.current_task() and not task.done()]
    after_fds = _fd_count()
    summary = {
        "schema": "collector-jsonl-result/v1",
        "state": snapshot.state.value,
        "received": snapshot.received,
        "envelope_validated": snapshot.envelope_validated,
        "queue_accepted": snapshot.queue_accepted,
        "queue_rejected": snapshot.queue_rejected,
        "parser_recognized": snapshot.parser_recognized,
        "parser_unrecognized": snapshot.parser_unrecognized,
        "analysis_completed": snapshot.analysis_completed,
        "processing_dropped": snapshot.processing_dropped,
        "connection_rejected": snapshot.connection_rejected,
        "malformed": snapshot.malformed,
        "queued_events": snapshot.queued_events,
        "queued_bytes": snapshot.queued_bytes,
        "queue_event_limit": snapshot.queue_event_limit,
        "queue_byte_limit": snapshot.queue_byte_limit,
        "queue_wait_error": queue_wait_error,
        "active_connections": snapshot.active_connections,
        "history_events": snapshot.history_events,
        "history_bytes": snapshot.history_bytes,
        "history_event_limit": snapshot.history_event_limit,
        "history_byte_limit": snapshot.history_byte_limit,
        "peak_queued_events": snapshot.peak_queued_events,
        "peak_queued_bytes": snapshot.peak_queued_bytes,
        "fd_start": before_fds,
        "fd_end": after_fds,
        "server_closed": runtime._server is None,
        "worker_closed": runtime._worker is None,
        "connection_tasks": len(runtime._connections),
        "closing_tasks": len(runtime._closing),
        "pending_tasks": len(pending),
        "fd_delta": (after_fds - before_fds) if before_fds is not None and after_fds is not None else None,
        "peak_rss_bytes": _peak_rss_bytes(),
        "elapsed_ms": (time.monotonic_ns() - started_ns) / 1_000_000,
    }
    _atomic_json(result, summary)
    return result_code


def _child_main(args: list[str]) -> int:
    if len(args) != 7:
        return 2
    role, scenario, home, marker, progress, result, fd = args
    try:
        return asyncio.run(_child(role, scenario, Path(home), Path(marker), Path(progress),
                                  Path(result), int(fd)))
    except BaseException:
        # Never serialize or print exception text/tracebacks from this boundary.
        return 20


def _read_control_port(fd: int, timeout: float) -> int | None:
    selector = selectors.DefaultSelector()
    selector.register(fd, selectors.EVENT_READ)
    try:
        if not selector.select(timeout):
            return None
        raw = os.read(fd, 32)
        if not raw.endswith(b"\n") or len(raw) > 10:
            return None
        value = int(raw[:-1])
        return value if 1024 <= value <= 65535 else None
    except (OSError, ValueError):
        return None
    finally:
        selector.close()
        os.close(fd)


def _wait_file(path: Path, predicate, timeout: float) -> dict[str, Any] | None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = _read_json(path)
        if value is not None and predicate(value):
            return value
        time.sleep(0.005)
    return None


def _assert_absent(data: bytes, values: tuple[str, ...]) -> bool:
    text = data.decode("utf-8", errors="replace")
    return not any(value and value in text for value in values)


def _send_record(port: int, role: str, payload: str) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1.0) as connection:
            connection.sendall(_envelope(role, payload))
        return True
    except OSError:
        return False


def _reuse_port(port: int) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            # Match the runtime listener option; this is a local rebind probe,
            # not a claim that SO_REUSEADDR removes TIME_WAIT or guarantees
            # port availability across all operating systems.
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", port))
        return True
    except OSError:
        return False


def _run_one(role: str, scenario: str, repetition: int) -> None:
    from app.log_collection.jsonl_runtime import JsonlRuntimeErrorCode, JsonlRuntimeState

    with tempfile.TemporaryDirectory(prefix="jsonl-accept-") as temporary:
        private = Path(temporary)
        os.chmod(private, 0o700)
        home = private / "home"
        home.mkdir(mode=0o700)
        marker, progress, result = (private / "ready.json", private / "progress.json",
                                    private / "result.json")
        control_read, control_write = os.pipe()
        env = {
            "HOME": str(home), "TMPDIR": str(private), "PYTHONPATH": str(ROOT),
            "PYTHONNOUSERSITE": "1", "PYTHONHASHSEED": "0", "TZ": "UTC",
            "PATH": os.environ.get("PATH", ""),
        }
        command = [sys.executable, str(Path(__file__).resolve()), "--child", role,
                   scenario, str(home), str(marker), str(progress), str(result), str(control_write)]
        try:
            process = subprocess.Popen(
                command, cwd=ROOT, env=env, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True,
                pass_fds=(control_write,),
            )
        except OSError:
            os.close(control_read)
            os.close(control_write)
            raise AcceptanceFailure(role, scenario, "CHILD_START", "SPAWN_FAILED") from None
        os.close(control_write)
        port: int | None = None
        stage = "CHILD_START"
        try:
            marker_value = _wait_file(marker, lambda v: v == {
                "schema": "collector-jsonl-ready/v1", "state": "RUNNING",
            }, RUN_TIMEOUT_SECONDS)
            if marker_value is None:
                raise AcceptanceFailure(role, scenario, "LISTENER_READY", "READY_TIMEOUT")
            if (stat.S_IMODE(marker.stat().st_mode) != 0o600
                    or stat.S_IMODE(private.stat().st_mode) != 0o700
                    or stat.S_IMODE(home.stat().st_mode) != 0o700):
                raise AcceptanceFailure(role, scenario, "LISTENER_READY", "PRIVATE_MODE")
            port = _read_control_port(control_read, RUN_TIMEOUT_SECONDS)
            control_read = -1
            if port is None:
                raise AcceptanceFailure(role, scenario, "LISTENER_READY", "CONTROL_UNAVAILABLE")
            if scenario == "start_immediate":
                stage = "PROCESS_EXIT"
            elif scenario == "queue_full":
                stage = "QUEUE_FULL"
                state = _wait_file(progress, lambda v: v.get("state") == "DEGRADED", 4.0)
                if state is None:
                    raise AcceptanceFailure(role, scenario, stage, "DEGRADE_NOT_OBSERVED")
                if (state.get("queue_accepted") != 256 or state.get("queue_rejected", 0) < 1
                        or state.get("analysis_completed") != 0
                        or state.get("queued_events") > state.get("queue_event_limit")
                        or state.get("queued_bytes") > state.get("queue_byte_limit")):
                    raise AcceptanceFailure(role, scenario, stage, "QUEUE_BOUNDARY")
                stage = "SIGNAL_SENT"
                process.send_signal(signal.SIGTERM)
            elif scenario == "record_pending":
                stage = "FRAME_SENT"
                if not _send_record(port, role, _role_payload(role, str(private))):
                    raise AcceptanceFailure(role, scenario, stage, "SEND_FAILED")
                pending = _wait_file(progress, lambda v: v.get("queue_accepted") == 1, 2.0)
                if pending is None:
                    raise AcceptanceFailure(role, scenario, "ANALYSIS_CONFIRMED", "QUEUE_NOT_OBSERVED")
                stage = "SIGNAL_SENT"
                process.send_signal(signal.SIGTERM)
            elif scenario == "malformed":
                stage = "FRAME_SENT"
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=1.0) as connection:
                        connection.sendall(b'{"schema_version":\n')
                except OSError:
                    pass
                malformed = _wait_file(progress, lambda v: v.get("malformed", 0) >= 1, 2.0)
                if malformed is None:
                    raise AcceptanceFailure(role, scenario, "FRAME_SENT", "MALFORMED_NOT_REJECTED")
                if not _send_record(port, role, _role_payload(role, str(private))):
                    raise AcceptanceFailure(role, scenario, "FRAME_SENT", "RECOVERY_SEND_FAILED")
                processed = _wait_file(progress, lambda v: v.get("analysis_completed", 0) >= 1, 2.0)
                if processed is None:
                    raise AcceptanceFailure(role, scenario, "ANALYSIS_CONFIRMED", "RECOVERY_NOT_PROCESSED")
                stage = "SIGNAL_SENT"
                process.send_signal(signal.SIGINT)
            elif scenario in {"readiness", "normal_stop"}:
                stage = "FRAME_SENT"
                if not _send_record(port, role, _role_payload(role, str(private))):
                    raise AcceptanceFailure(role, scenario, stage, "SEND_FAILED")
                stage = "ANALYSIS_CONFIRMED"
            else:
                stage = "FRAME_SENT"
                if not _send_record(port, role, _role_payload(role, str(private))):
                    raise AcceptanceFailure(role, scenario, stage, "SEND_FAILED")
                analysis = _wait_file(progress, lambda v: v.get("analysis_completed", 0) >= 1, 2.0)
                if analysis is None:
                    raise AcceptanceFailure(role, scenario, "ANALYSIS_CONFIRMED", "ANALYSIS_NOT_OBSERVED")
                stage = "SIGNAL_SENT"
                process.send_signal(signal.SIGINT if scenario == "sigint" else signal.SIGTERM)

            stage = "PROCESS_EXIT"
            try:
                stdout, stderr = process.communicate(timeout=RUN_TIMEOUT_SECONDS)
            except subprocess.TimeoutExpired:
                raise AcceptanceFailure(role, scenario, "SHUTDOWN_WAIT", "EXIT_TIMEOUT") from None
            canaries = ("ACCOUNT_CANARY", "203.0.113.42", "2001:db8::42", "HOST_CANARY",
                        "FILENAME_CANARY", "CREDENTIAL_CANARY", "PRIVATE_KEY_CANARY",
                        "ignore previous instructions", str(private), str(ROOT))
            files = marker.read_bytes() + progress.read_bytes() + result.read_bytes()
            if not _assert_absent(stdout + stderr + files, canaries):
                raise AcceptanceFailure(role, scenario, "PROCESS_EXIT", "PRIVACY_LEAK")
            if process.returncode != 0:
                raise AcceptanceFailure(role, scenario, "PROCESS_EXIT", "CHILD_FAILED")
            summary = _read_json(result)
            if summary is None or summary.get("schema") != "collector-jsonl-result/v1":
                raise AcceptanceFailure(role, scenario, "PROCESS_EXIT", "RESULT_INVALID")
            if (summary.get("state") != JsonlRuntimeState.STOPPED.value
                    or not summary.get("server_closed") or not summary.get("worker_closed")
                    or summary.get("active_connections") != 0
                    or summary.get("connection_tasks") != 0
                    or summary.get("closing_tasks") != 0 or summary.get("pending_tasks") != 0
                    or summary.get("queued_events") != 0 or summary.get("queued_bytes") != 0
                    or summary.get("history_events", 0) > summary.get("history_event_limit", -1)
                    or summary.get("history_bytes", 0) > summary.get("history_byte_limit", -1)
                    or (summary.get("fd_delta") is not None and summary.get("fd_delta") > 0)):
                raise AcceptanceFailure(role, scenario, "CLEANUP", "RESOURCE_REMAINS")
            rss = summary.get("peak_rss_bytes")
            elapsed = summary.get("elapsed_ms")
            if ((rss is not None and (type(rss) is not int or rss <= 0))
                    or type(elapsed) not in (int, float) or elapsed <= 0):
                raise AcceptanceFailure(role, scenario, "PROCESS_EXIT", "METRIC_INVALID")
            if scenario == "queue_full" and not (
                summary.get("queue_accepted") == 256
                and summary.get("queue_rejected", 0) >= 1
                and summary.get("analysis_completed") == 0
                and summary.get("processing_dropped") == 256
                and summary.get("queue_wait_error") == JsonlRuntimeErrorCode.QUEUE_FULL.value
            ):
                raise AcceptanceFailure(role, scenario, "CLEANUP", "QUEUE_ACCOUNTING")
            if scenario == "record_pending" and not (
                summary.get("analysis_completed") == 0 and summary.get("processing_dropped") == 1
            ):
                raise AcceptanceFailure(role, scenario, "CLEANUP", "PENDING_ACCOUNTING")
            stage = "PORT_REUSED"
            if not _reuse_port(port):
                raise AcceptanceFailure(role, scenario, stage, "PORT_NOT_REUSABLE")
        except AcceptanceFailure:
            if process.poll() is None:
                process.terminate()
                try:
                    process.communicate(timeout=1.0)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.communicate()
            raise
        except Exception:
            if process.poll() is None:
                process.terminate()
                try:
                    process.communicate(timeout=1.0)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.communicate()
            raise AcceptanceFailure(role, scenario, stage, "HARNESS_FAILURE") from None
        finally:
            if control_read >= 0:
                os.close(control_read)
            if process.poll() is None:
                process.terminate()
                try:
                    process.communicate(timeout=1.0)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.communicate()


async def _runtime_stress(role: str) -> None:
    from app.log_collection.jsonl_runtime import (
        JsonlCollectorRuntime, JsonlRuntimeConfig, JsonlRuntimeState,
    )

    before_fds = _fd_count()
    runtime = JsonlCollectorRuntime(JsonlRuntimeConfig(
        source_role=role, host="127.0.0.1", port=0,
        test_only_ephemeral_port=True, max_connections=2,
    ))
    await runtime.start()
    port = int(runtime._server.sockets[0].getsockname()[1])
    writers: list[asyncio.StreamWriter] = []
    try:
        # One incomplete connection cannot prevent the other from being analyzed.
        first_reader, first_writer = await asyncio.open_connection("127.0.0.1", port)
        writers.append(first_writer)
        first_writer.write(b'{"schema_version":1,"source_role":')
        await first_writer.drain()
        second_reader, second_writer = await asyncio.open_connection("127.0.0.1", port)
        writers.append(second_writer)
        second_writer.write(_envelope(role, _role_payload(role)))
        await second_writer.drain()
        if not await _wait_for(lambda: runtime.snapshot().active_connections == 2):
            raise _StressFailure("TWO_CONNECTIONS")
        if not await _wait_for(lambda: runtime.snapshot().analysis_completed >= 1):
            raise _StressFailure("CONCURRENT_PROGRESS")
        # A third peer is rejected before reading its input.
        third_reader, third_writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            third_writer.write(b"unread")
            await third_writer.drain()
        except (ConnectionResetError, BrokenPipeError):
            pass
        try:
            third_data = await asyncio.wait_for(third_reader.read(), 1.0)
        except ConnectionResetError:
            third_data = b""
        except asyncio.TimeoutError:
            raise _StressFailure("THIRD_CONNECTION") from None
        if third_data:
            raise _StressFailure("THIRD_CONNECTION")
        third_writer.close()
        try:
            await third_writer.wait_closed()
        except (ConnectionResetError, OSError):
            pass
        first_writer.write(_envelope(role, _role_payload(role))[len(b'{"schema_version":1,"source_role":'):])
        await first_writer.drain()
        if not await _wait_for(lambda: runtime.snapshot().analysis_completed >= 2):
            raise _StressFailure("PARTIAL_CONNECTION_PROGRESS")
        first_writer.close()
        second_writer.close()
        await asyncio.gather(first_writer.wait_closed(), second_writer.wait_closed(),
                             return_exceptions=True)
        writers.clear()
        if not await _wait_for(lambda: runtime.snapshot().active_connections == 0):
            raise _StressFailure("CONCURRENT_CLEANUP")
        if runtime.snapshot().connection_rejected < 1:
            raise _StressFailure("CONNECTION_LIMIT_COUNT")

        # Split a multibyte UTF-8 code point across TCP writes.
        unicode_line = _envelope(role, "synthetic-é-🙂")
        marker = unicode_line.index("🙂".encode("utf-8")) + 1
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writers.append(writer)
        writer.write(unicode_line[:marker]); await writer.drain()
        writer.write(unicode_line[marker:]); await writer.drain()
        if not await _wait_for(lambda: runtime.snapshot().analysis_completed >= 3):
            raise _StressFailure("UTF8_SPLIT")
        writer.close(); await writer.wait_closed(); writers.clear()

        # Thirty short connections exercise repeated accept/close cleanup.
        for _ in range(30):
            _reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.close()
            await writer.wait_closed()
            if not await _wait_for(lambda: runtime.snapshot().active_connections == 0):
                raise _StressFailure("RAPID_RECONNECT")

        # A bounded single write exercises a 32-record runtime burst. TCP may
        # split it across reads; the pure decoder boundary is checked below.
        small = json.dumps({
            "schema_version": 1, "source_role": role, "payload": "x",
            "collector_instance_alias": "c", "sequence_hint": None, "retry_hint": False,
        }, separators=(",", ":")).encode() + b"\n"
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writers.append(writer)
        before_batch = runtime.snapshot().analysis_completed
        writer.write(small * 32); await writer.drain()
        if not await _wait_for(lambda: runtime.snapshot().analysis_completed >= before_batch + 32):
            raise _StressFailure("FEED_32_BATCH")
        writer.close(); await writer.wait_closed(); writers.clear()
        if not await _wait_for(lambda: runtime.snapshot().active_connections == 0):
            raise _StressFailure("FEED_32_CLEANUP")

        # Isolate the exact 256-record soak from preceding stress records so
        # the configured 256-event history limit is tested at its boundary.
        old_port = port
        await runtime.stop()
        if not _reuse_port(old_port):
            raise _StressFailure("PORT_REUSE_BEFORE_SOAK")
        runtime = JsonlCollectorRuntime(JsonlRuntimeConfig(
            source_role=role, host="127.0.0.1", port=0, test_only_ephemeral_port=True,
            max_connections=2,
        ))
        await runtime.start()
        port = int(runtime._server.sockets[0].getsockname()[1])

        # Bounded soak: exactly 256 records in 16-record chunks.
        start = runtime.snapshot().analysis_completed
        payload = _role_payload(role)
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writers.append(writer)
        for sent in range(0, 256, 16):
            # Repeated sequence hints are deliberately not deduplicated.
            writer.write(b"".join(_envelope(role, payload, sequence="repeated-hint")
                                   for i in range(16)))
            await writer.drain()
            target = start + sent + 16
            if not await _wait_for(lambda: runtime.snapshot().analysis_completed >= target):
                snap = runtime.snapshot()
                raise _StressFailure("SOAK_256", snap.analysis_completed, target,
                                     snap.queue_accepted, snap.queue_rejected)
        writer.close(); await writer.wait_closed(); writers.clear()
        snap = runtime.snapshot()
        if not (
            snap.received == 256 and snap.envelope_validated == 256
            and snap.queue_accepted == 256 and snap.queue_rejected == 0
            and snap.parser_recognized == 256 and snap.parser_unrecognized == 0
            and snap.analysis_completed == 256 and snap.malformed == 0
            and snap.processing_dropped == 0 and snap.peak_queued_events <= snap.queue_event_limit
            and snap.peak_queued_bytes <= snap.queue_byte_limit
            and snap.history_events <= snap.history_event_limit
            and snap.history_bytes <= snap.history_byte_limit
        ):
            raise _StressFailure("SOAK_ACCOUNTING")
    finally:
        for writer in writers:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionResetError, OSError):
                pass
        await runtime.stop()
        await runtime.stop()
    if runtime.snapshot().state is not JsonlRuntimeState.STOPPED:
        raise _StressFailure("STOP")
    if before_fds is not None:
        after_fds = _fd_count()
        if after_fds is not None and after_fds > before_fds:
            raise _StressFailure("FD_CLEANUP")
    if not _reuse_port(port):
        raise _StressFailure("PORT_REUSE")


def _support_checks() -> None:
    from app.log_collection.jsonl_adapter import AdapterErrorCode, JsonLinesDecoder, JsonlAdapterConfig

    for role in ROLES:
        decoder = JsonLinesDecoder(JsonlAdapterConfig(source_role=role))
        frame = _envelope(role, "é🙂")
        for byte in frame:
            result = decoder.feed(bytes((byte,)))
            if result.error_category is not None:
                raise RuntimeError
        if decoder.validated_records != 1:
            raise RuntimeError
        decoder.close()
        batch = JsonLinesDecoder(JsonlAdapterConfig(source_role=role))
        result = batch.feed(_envelope(role, "x") * 32)
        if result.error_category is not None or len(result.records) != 32:
            raise RuntimeError
        batch.close()
        full = JsonLinesDecoder(JsonlAdapterConfig(source_role=role))
        result = full.feed(_envelope(role, "x") * 33)
        if result.error_category is not AdapterErrorCode.FEED_EVENT_LIMIT or result.records:
            raise RuntimeError
        full.close()


def main() -> int:
    if len(sys.argv) >= 2 and sys.argv[1] == "--child":
        return _child_main(sys.argv[2:])
    local = sys.argv[1:] == ["--local-dry-run"]
    if not local and sys.platform != "linux":
        print("COLLECTOR_JSONL_LINUX_ACCEPTANCE_FAIL role=unknown scenario=support stage=PLATFORM category=LINUX_REQUIRED runs=0")
        return 1
    if local and sys.platform == "linux":
        pass
    runs = 0
    role = "unknown"
    scenario = "support"
    stage = "CORE_BOUNDARIES"
    try:
        _support_checks()
        for role in ROLES:
            for scenario in SCENARIOS:
                for repetition in range(REPEATS):
                    runs += 1
                    stage = "SUBPROCESS"
                    _run_one(role, scenario, repetition)
            scenario = "stress"
            stage = "RUNTIME_STRESS"
            asyncio.run(_runtime_stress(role))
    except AcceptanceFailure as failure:
        marker = "COLLECTOR_JSONL_LOCAL_DRY_RUN_FAIL" if local else "COLLECTOR_JSONL_LINUX_ACCEPTANCE_FAIL"
        print(f"{marker} role={failure.role} scenario={failure.scenario} stage={failure.stage} category={failure.category} runs={runs}")
        return 1
    except _StressFailure as failure:
        marker = "COLLECTOR_JSONL_LOCAL_DRY_RUN_FAIL" if local else "COLLECTOR_JSONL_LINUX_ACCEPTANCE_FAIL"
        print(f"{marker} role={role} scenario=stress stage={failure.stage} category=ASSERTION count={failure.count} expected={failure.expected} accepted={failure.accepted} rejected={failure.rejected} runs={runs}")
        return 1
    except Exception:
        marker = "COLLECTOR_JSONL_LOCAL_DRY_RUN_FAIL" if local else "COLLECTOR_JSONL_LINUX_ACCEPTANCE_FAIL"
        print(f"{marker} role={role} scenario={scenario} stage={stage} category=INTERNAL_FAILURE runs={runs}")
        return 1
    print(LOCAL_MARKER if local else PASS_MARKER)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
