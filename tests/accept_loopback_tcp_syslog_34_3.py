"""Manual, synthetic-only Phase 34.3 lifecycle and resource acceptance."""

from __future__ import annotations

import asyncio
import json
import math
import os
from pathlib import Path
import platform
import resource
import signal
import socket
import statistics
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
_TEMP_CLEANUP_FAILURES = 0
_TEMP_CLEANUP_DETAILS: list[str] = []
_RESOURCE_CLEANUP_DETAILS: list[str] = []


def _line(role: str, second: int) -> bytes:
    if role == "application":
        text = (f"2026-01-02 03:04:{second:02d} INFO login_failed "
                "user=synthetic_user ip=192.0.2.19 service=ssh")
    else:
        text = (f"2026-01-02 03:04:{second:02d} sshd: Failed password for synthetic_user "
                "from 198.51.100.29 port 45001 ssh2")
    return text.encode("utf-8")


def _write_private(path: Path, value: str) -> None:
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("x", encoding="utf-8") as handle:
        handle.write(value)
        handle.flush()
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def _fd_count() -> int:
    descriptor_dir = Path("/proc/self/fd") if Path("/proc/self/fd").is_dir() else Path("/dev/fd")
    if not descriptor_dir.is_dir():
        return -1
    return len(tuple(descriptor_dir.iterdir()))


async def _child(role: str, mode: str, ready_path: Path, connected_path: Path,
                 processing_path: Path, settled_path: Path, stop_path: Path,
                 result_path: Path) -> int:
    from app.log_collection.runtime import TcpRuntimeConfig, TcpSyslogRuntime
    import app.log_collection.runtime as runtime_module

    if mode == "processing":
        original_parser = runtime_module.parse_live_records

        def delayed_parser(*args, **kwargs):
            _write_private(processing_path, "started")
            time.sleep(0.04)
            return original_parser(*args, **kwargs)

        runtime_module.parse_live_records = delayed_parser

    runtime = TcpSyslogRuntime(TcpRuntimeConfig(
        schema_version="tcp-syslog-runtime/v1", source_role=role, bind_family="ipv4",
        port=0, connection_limit=2, idle_timeout_seconds=2.0,
        read_timeout_seconds=1.0, parser_timezone="Asia/Seoul",
        startup_mode="synthetic_pilot", test_only_ephemeral_port=True,
    ))
    loop = asyncio.get_running_loop()
    stopping = asyncio.Event()
    for signum in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(signum, stopping.set)
    descriptors_before = _fd_count()
    await runtime.start()
    port = runtime._server.sockets[0].getsockname()[1]
    _write_private(ready_path, f"{port} {descriptors_before}")

    try:
        if mode in {"sigint", "sigterm"}:
            deadline = loop.time() + 2
            while runtime.snapshot().active_connections == 0 and loop.time() < deadline:
                await asyncio.sleep(0.002)
            if runtime.snapshot().active_connections:
                _write_private(connected_path, "connected")
            else:
                _write_private(settled_path, "connection-not-observed")
        elif mode == "processing":
            deadline = loop.time() + 3
            while not processing_path.exists() and loop.time() < deadline:
                await asyncio.sleep(0.001)
            if not processing_path.exists():
                _write_private(settled_path, "processing-not-observed")
        elif mode == "malformed":
            deadline = loop.time() + 3
            while runtime.snapshot().rejected_frames < 1 and loop.time() < deadline:
                await asyncio.sleep(0.002)
            if runtime.snapshot().rejected_frames:
                _write_private(settled_path, "rejected")
            else:
                _write_private(settled_path, "rejection-not-observed")
        elif mode in {"normal", "readiness"}:
            deadline = loop.time() + 5
            while not stop_path.exists() and loop.time() < deadline:
                await asyncio.sleep(0.002)
        elif mode != "startup":
            _write_private(settled_path, "invalid-test-mode")

        if mode in {"startup", "readiness", "normal"}:
            stopping.set()
        else:
            await stopping.wait()

        before_stop = runtime.snapshot()
        await runtime.stop()
        after_stop = runtime.snapshot()
        descriptors_after = _fd_count()
        result = {
            "state_stopped": after_stop.state.value == "STOPPED",
            "active_connections": after_stop.active_connections,
            "connection_tasks": len(runtime._connection_tasks),
            "closing_tasks": len(runtime._closing_tasks),
            "processor_done": runtime._processor_task is None or runtime._processor_task.done(),
            "listener_released": runtime._server is None,
            "queue_events": after_stop.queued_events,
            "accepted": before_stop.accepted_frames,
            "rejected": before_stop.rejected_frames,
            "fd_delta": (descriptors_after - descriptors_before
                         if descriptors_before >= 0 and descriptors_after >= 0 else None),
        }
        _write_private(result_path, json.dumps(result, sort_keys=True))
        if (not result["state_stopped"] or result["active_connections"] != 0
                or result["connection_tasks"] or result["closing_tasks"]
                or not result["processor_done"] or not result["listener_released"]
                or result["queue_events"] != 0
                or result["fd_delta"] is None or result["fd_delta"] != 0):
            return 3
        print(f"TCP_SYSLOG_CYCLE_COMPLETE role={role} mode={mode}")
        return 0
    finally:
        if runtime.snapshot().state.value != "STOPPED":
            await runtime.stop()


def _await_file(path: Path, process: subprocess.Popen[str], timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while not path.exists() and process.poll() is None and time.monotonic() < deadline:
        time.sleep(0.002)
    return path.exists()


def _cycle(role: str, mode: str, signum: int | None = None) -> tuple[str | None, float | None]:
    global _TEMP_CLEANUP_FAILURES
    temporary = tempfile.TemporaryDirectory(prefix="tcp34-3-")
    root = Path(temporary.name)
    os.chmod(root, 0o700)
    home = root / "home"
    home.mkdir(mode=0o700)
    ready, connected = root / "ready", root / "connected"
    processing, settled, stop_path, result_path = (
        root / "processing", root / "settled", root / "stop", root / "result")
    env = {"HOME": str(home), "PATH": os.environ.get("PATH", ""),
           "PYTHONPATH": os.getcwd(), "PYTHONNOUSERSITE": "1", "TZ": "UTC"}
    command = [sys.executable, __file__, "--child", role, mode, str(ready),
               str(connected), str(processing), str(settled), str(stop_path), str(result_path)]
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, env=env)
    stage = "listener_readiness"
    started = time.perf_counter()
    stop_started: float | None = None
    peer: socket.socket | None = None
    try:
        if not _await_file(ready, process, 5):
            return stage, None
        port_text, _fd_baseline = ready.read_text(encoding="ascii").split()
        port = int(port_text)
        if mode in {"sigint", "sigterm"}:
            peer = socket.create_connection(("127.0.0.1", port), timeout=2)
            if not _await_file(connected, process, 2):
                stage = "connection_close"
                return stage, None
        elif mode == "processing":
            with socket.create_connection(("127.0.0.1", port), timeout=2) as connection:
                connection.sendall(_wire_frame(_line(role, 1)))
                if not _await_file(processing, process, 3):
                    stage = "frame_processing"
                    return stage, None
        elif mode == "malformed":
            with socket.create_connection(("127.0.0.1", port), timeout=2) as connection:
                connection.sendall(b"+1 invalid")
            if not _await_file(settled, process, 3):
                stage = "frame_processing"
                return stage, None

        stage = "signal_delivery" if signum is not None else "shutdown_wait"
        stop_started = time.perf_counter()
        if signum is not None:
            process.send_signal(signum)
        elif mode in {"normal", "readiness"}:
            _write_private(stop_path, "stop")
        stdout, stderr = process.communicate(timeout=5)
        elapsed = (time.perf_counter() - stop_started) * 1000
        if process.returncode != 0:
            return ("subprocess_reap", elapsed)
        expected = f"TCP_SYSLOG_CYCLE_COMPLETE role={role} mode={mode}\n"
        if stdout != expected or stderr:
            return ("privacy_output", elapsed)
        if not result_path.exists():
            return ("shutdown_wait", elapsed)
        result = json.loads(result_path.read_text(encoding="utf-8"))
        if result["fd_delta"] not in (None, 0):
            return ("runtime_fd_close", elapsed)
        if result["active_connections"] or result["connection_tasks"] or result["closing_tasks"]:
            return ("task_or_connection_close", elapsed)
        if not result["listener_released"] or result["queue_events"]:
            return ("listener_close", elapsed)
        stage = "resource_reuse"
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            probe.bind(("127.0.0.1", port))
        stage = "temporary_cleanup"
        return None, elapsed
    except subprocess.TimeoutExpired:
        return "shutdown_wait", None
    except Exception:
        return stage, None
    finally:
        if peer is not None:
            try:
                peer.close()
            except Exception:
                _RESOURCE_CLEANUP_DETAILS.append(f"{role}:{mode}:connection_close")
        try:
            if process.poll() is None:
                process.kill()
        except Exception:
            _RESOURCE_CLEANUP_DETAILS.append(f"{role}:{mode}:subprocess_reap")
        try:
            process.communicate(timeout=2)
        except Exception:
            _RESOURCE_CLEANUP_DETAILS.append(f"{role}:{mode}:subprocess_reap")
        cleanup_failed = False
        try:
            temporary.cleanup()
        except Exception:
            cleanup_failed = True
        if cleanup_failed or Path(temporary.name).exists():
            _TEMP_CLEANUP_FAILURES += 1
            _TEMP_CLEANUP_DETAILS.append(f"{role}:{mode}:temporary_cleanup")


def _lifecycle_matrix(bounded: bool = False) -> dict[str, object]:
    counts = ({"readiness": 10, "sigint": 5, "sigterm": 5, "normal": 5,
               "startup": 5, "processing": 5, "malformed": 5}
              if bounded else
              {"sigint": 10, "sigterm": 20, "normal": 10,
               "startup": 10, "processing": 10, "malformed": 10})
    totals: dict[str, object] = {"attempts": 0, "first_attempt_passes": 0,
                                 "first_attempt_failures": {}, "shutdown_ms": {}}
    for role in ("application", "ssh"):
        for mode, count in counts.items():
            times: list[float] = []
            for index in range(count):
                if mode == "sigint":
                    signum = signal.SIGINT
                elif mode == "sigterm":
                    signum = signal.SIGTERM
                elif mode == "processing":
                    signum = signal.SIGINT if index % 2 == 0 else signal.SIGTERM
                elif mode == "malformed":
                    signum = signal.SIGTERM
                else:
                    signum = None
                failure, elapsed = _cycle(role, mode, signum)
                totals["attempts"] += 1
                if failure is None:
                    totals["first_attempt_passes"] += 1
                else:
                    failures = totals["first_attempt_failures"]
                    failures[f"{role}:{mode}:{failure}"] = failures.get(f"{role}:{mode}:{failure}", 0) + 1
                if elapsed is not None:
                    times.append(elapsed)
            if times:
                ordered = sorted(times)
                totals["shutdown_ms"][f"{role}:{mode}"] = {
                    "samples": len(times),
                    "median": round(statistics.median(times), 3),
                    "p95": round(ordered[max(0, math.ceil(len(ordered) * 0.95) - 1)], 3),
                    "max": round(max(times), 3),
                }
    return totals


def _wire_frame(payload: bytes) -> bytes:
    return str(len(payload)).encode("ascii") + b" " + payload


async def _concurrency_and_soak(role: str, bounded: bool = False) -> dict[str, object]:
    from app.log_collection.runtime import TcpRuntimeConfig, TcpSyslogRuntime

    runtime = TcpSyslogRuntime(TcpRuntimeConfig(
        schema_version="tcp-syslog-runtime/v1", source_role=role, bind_family="ipv4",
        port=0, connection_limit=2, idle_timeout_seconds=5.0,
        read_timeout_seconds=2.0, parser_timezone="Asia/Seoul",
        startup_mode="synthetic_pilot", test_only_ephemeral_port=True,
    ))
    fd_before = _fd_count()
    await runtime.start()
    port = runtime._server.sockets[0].getsockname()[1]
    listener_before = len(runtime._server.sockets)
    max_active = max_tasks = 0
    try:
        first_reader, first_writer = await asyncio.open_connection("127.0.0.1", port)
        second_reader, second_writer = await asyncio.open_connection("127.0.0.1", port)
        deadline = time.monotonic() + 2
        while runtime.snapshot().active_connections < 2 and time.monotonic() < deadline:
            await asyncio.sleep(0.002)
        if runtime.snapshot().active_connections != 2:
            raise RuntimeError("two-client readiness contract failed")
        await asyncio.sleep(0.01)
        third_reader, third_writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            await asyncio.wait_for(third_reader.read(1), timeout=2)
        except (ConnectionResetError, asyncio.IncompleteReadError):
            pass
        max_active = max(max_active, runtime.snapshot().active_connections)
        max_tasks = max(max_tasks, len(runtime._connection_tasks))

        slow = _wire_frame(_line(role, 1))
        first_writer.write(slow[:1])
        await first_writer.drain()
        burst_count = 16
        second_writer.write(b"".join(_wire_frame(_line(role, (i % 59) + 1))
                                     for i in range(burst_count)))
        await second_writer.drain()
        await runtime.wait_until_processed(burst_count, timeout=10)
        first_writer.write(slow[1:])
        await first_writer.drain()
        await runtime.wait_until_processed(burst_count + 1, timeout=10)
        first_writer.close()
        second_writer.close()
        third_writer.close()
        await asyncio.gather(first_writer.wait_closed(), second_writer.wait_closed(),
                             third_writer.wait_closed(), return_exceptions=True)
        deadline = time.monotonic() + 3
        while runtime.snapshot().active_connections and time.monotonic() < deadline:
            await asyncio.sleep(0.002)

        rapid_completed = 0
        for _ in range(30 if bounded else 100):
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.close()
            await writer.wait_closed()
            deadline = time.monotonic() + 1
            while runtime.snapshot().active_connections and time.monotonic() < deadline:
                await asyncio.sleep(0.001)
            if runtime.snapshot().active_connections:
                raise RuntimeError("bounded connection cycle did not settle")
            rapid_completed += 1

        malformed_inputs = (
            (b"+1 invalid", "frame"),
            (b"1234567 0", "frame"),
            (b"8193 ", "frame"),
            (b"10 short", "incomplete"),
            (_wire_frame(b"\xff"), "frame"),
            (_wire_frame(b"\x00"), "frame"),
            (_wire_frame(b"not a valid role record"), "parser"),
        )
        for invalid_wire, kind in malformed_inputs:
            before = runtime.snapshot()
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(invalid_wire)
            await writer.drain()
            if kind == "incomplete":
                writer.close()
                await writer.wait_closed()
            elif kind == "frame":
                try:
                    await asyncio.wait_for(reader.read(1), timeout=2)
                except (ConnectionResetError, asyncio.IncompleteReadError):
                    pass
                finally:
                    writer.close()
                    await writer.wait_closed()
            else:
                writer.close()
                await writer.wait_closed()

            deadline = time.monotonic() + 3
            if kind == "parser":
                target = before.parser_rejected_events + 1
                while runtime.snapshot().parser_rejected_events < target and time.monotonic() < deadline:
                    await asyncio.sleep(0.002)
                if runtime.snapshot().parser_rejected_events != target:
                    raise RuntimeError("parser rejection was not counted")
            else:
                target = before.rejected_frames + 1
                while runtime.snapshot().rejected_frames < target and time.monotonic() < deadline:
                    await asyncio.sleep(0.002)
                if runtime.snapshot().rejected_frames != target:
                    raise RuntimeError("malformed frame was not rejected")
            if runtime.snapshot().state.value != "LISTENING":
                raise RuntimeError("one malformed connection stopped the listener")

            analyzed_before = runtime.snapshot().analyzed_events
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(_wire_frame(_line(role, 20)))
            await writer.drain()
            await runtime.wait_until_processed(analyzed_before + 1, timeout=5)
            writer.close()
            await writer.wait_closed()

        # The zero-cap queue forces an observable overload using the real handler/admission path.
        overloaded = TcpSyslogRuntime(TcpRuntimeConfig(
            schema_version="tcp-syslog-runtime/v1", source_role=role, bind_family="ipv4",
            port=0, connection_limit=2, idle_timeout_seconds=5.0,
            read_timeout_seconds=2.0, parser_timezone="Asia/Seoul",
            startup_mode="synthetic_pilot", test_only_ephemeral_port=True,
            max_queue_events=1,
        ))
        release_processor = asyncio.Event()

        async def stalled_processor():
            await release_processor.wait()

        overloaded._process_queue = stalled_processor
        await overloaded.start()
        overload_port = overloaded._server.sockets[0].getsockname()[1]
        _r, w = await asyncio.open_connection("127.0.0.1", overload_port)
        w.write(_wire_frame(_line(role, 2)) + _wire_frame(_line(role, 3)))
        await w.drain()
        deadline = time.monotonic() + 3
        while overloaded.snapshot().state.value != "DEGRADED" and time.monotonic() < deadline:
            await asyncio.sleep(0.002)
        overload = overloaded.snapshot()
        if (overload.state.value != "DEGRADED" or overload.accepted_frames != 1
                or overload.rejected_frames != 1 or overload.queued_events > 1
                or overload.error_category != "QUEUE_OVERLOAD"):
            raise RuntimeError("queue overload contract failed")
        w.close()
        await w.wait_closed()
        release_processor.set()
        await overloaded.stop()

        # Bounded soak is 256 synthetic frames per role (within the 1,000-frame limit).
        count = 256
        soak_runtime = TcpSyslogRuntime(TcpRuntimeConfig(
            schema_version="tcp-syslog-runtime/v1", source_role=role, bind_family="ipv4",
            port=0, connection_limit=2, idle_timeout_seconds=5.0,
            read_timeout_seconds=2.0, parser_timezone="Asia/Seoul",
            startup_mode="synthetic_pilot", test_only_ephemeral_port=True,
        ))
        soak_fd_before = _fd_count()
        soak_started = time.perf_counter()
        await soak_runtime.start()
        soak_port = soak_runtime._server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", soak_port)
        deadline = time.monotonic() + 2
        while not soak_runtime.snapshot().active_connections and time.monotonic() < deadline:
            await asyncio.sleep(0.002)
        soak_connection_peak = soak_runtime.snapshot().active_connections
        soak_task_peak = len(soak_runtime._connection_tasks)
        writer.write(b"".join(_wire_frame(_line(role, (i % 59) + 1))
                               for i in range(count)))
        await writer.drain()
        await soak_runtime.wait_until_processed(count, timeout=60)
        before_stop = soak_runtime.snapshot()
        writer.close()
        await writer.wait_closed()
        await soak_runtime.stop()
        elapsed_ms = (time.perf_counter() - soak_started) * 1000
        soak_fd_after = _fd_count()
        after_soak_stop = soak_runtime.snapshot()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            probe.bind(("127.0.0.1", soak_port))
        usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        peak_rss = usage if platform.system() == "Darwin" else usage * 1024
        if before_stop.accepted_frames != count or before_stop.analyzed_events != count:
            raise RuntimeError("bounded synthetic soak count mismatch")
        if (after_soak_stop.active_connections or after_soak_stop.queued_events
                or len(soak_runtime._connection_tasks)):
            raise RuntimeError("soak runtime resources remained after stop")

        main_before_stop = runtime.snapshot()
        await runtime.stop()
        main_after_stop = runtime.snapshot()
        main_fd_after = _fd_count()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            probe.bind(("127.0.0.1", port))
        safe_status = json.dumps(main_after_stop.to_dict(), sort_keys=True) + repr(main_after_stop)
        if any(secret in safe_status for secret in (
            "synthetic_user", "192.0.2.19", "198.51.100.29",
        )):
            raise RuntimeError("synthetic identifier appeared in status")
        return {
            "role": role,
            "two_connection_progress": main_before_stop.accepted_frames >= burst_count + 1,
            "slow_partial_did_not_starve_peer": True,
            "third_connection_rejected": main_before_stop.rejected_connections == 1,
            "rapid_connect_disconnect": rapid_completed,
            "malformed_and_parser_recovery_cases": len(malformed_inputs),
            "active_connections_peak": max_active,
            "active_connection_tasks_peak": max_tasks,
            "main_runtime_cleanup": {
                "active_connections": main_after_stop.active_connections,
                "connection_tasks": len(runtime._connection_tasks),
                "closing_tasks": len(runtime._closing_tasks),
                "fd_before": fd_before,
                "fd_after": main_fd_after,
                "listener_released": runtime._server is None,
                "port_reused": True,
            },
            "queue_overload": {
                "state": overload.state.value,
                "accepted": overload.accepted_frames,
                "rejected": overload.rejected_frames,
                "queued_events": overload.queued_events,
                "event_limit": overload.queue_event_limit,
                "queued_bytes": overload.queued_bytes,
                "byte_limit": overload.queue_byte_limit,
            },
            "soak": {
                "sent": count,
                "accepted": before_stop.accepted_frames,
                "rejected": before_stop.rejected_frames,
                "parsed": before_stop.parsed_events,
                "parser_rejected": before_stop.parser_rejected_events,
                "analyzed": before_stop.analyzed_events,
                "dropped": before_stop.dropped_frames,
                "queue_peak_events": before_stop.peak_queued_events,
                "queue_peak_bytes": before_stop.peak_queued_bytes,
                "active_connections_peak": max_active,
                "active_tasks_peak": max_tasks,
                "fd_before": soak_fd_before,
                "fd_after": soak_fd_after,
                "listener_sockets_before_stop": listener_before,
                "listener_released_after_stop": soak_runtime._server is None,
                "port_reused_after_stop": True,
                "tasks_after_stop": len(soak_runtime._connection_tasks),
                "active_connections_peak": soak_connection_peak,
                "active_tasks_peak": soak_task_peak,
                "peak_rss_process_wide_bytes": peak_rss,
                "elapsed_ms": round(elapsed_ms, 3),
            },
        }
    finally:
        await runtime.stop()


async def _main(linux_bounded: bool = False, bounded: bool = False) -> int:
    if linux_bounded and not sys.platform.startswith("linux"):
        print("TCP_SYSLOG_LINUX_RELIABILITY_FAIL category=unsupported_platform", flush=True)
        return 2
    bounded = bounded or linux_bounded
    lifecycle = _lifecycle_matrix(bounded=bounded)
    failures = lifecycle["first_attempt_failures"]
    if bounded and (lifecycle["first_attempt_passes"] != 80 or failures
                    or _TEMP_CLEANUP_FAILURES or _RESOURCE_CLEANUP_DETAILS):
        failure_count = lifecycle["attempts"] - lifecycle["first_attempt_passes"]
        print(f"TCP_SYSLOG_LINUX_RELIABILITY_FAIL category=lifecycle runs={lifecycle['attempts']} failures={failure_count} "
              f"cleanup_failures={_TEMP_CLEANUP_FAILURES}", flush=True)
        for label, count in sorted(failures.items()):
            role, scenario, stage = label.split(":", 2)
            print(f"TCP_SYSLOG_LINUX_RELIABILITY_CASE role={role} scenario={scenario} "
                  f"stage={stage} category=cycle_failure count={count}", flush=True)
        for label in _TEMP_CLEANUP_DETAILS:
            role, scenario, stage = label.split(":", 2)
            print(f"TCP_SYSLOG_LINUX_RELIABILITY_CASE role={role} scenario={scenario} "
                  f"stage={stage} category=cleanup_failure count=1", flush=True)
        for label in _RESOURCE_CLEANUP_DETAILS:
            role, scenario, stage = label.split(":", 2)
            print(f"TCP_SYSLOG_LINUX_RELIABILITY_CASE role={role} scenario={scenario} "
                  f"stage={stage} category=cleanup_failure count=1", flush=True)
        return 1
    if not linux_bounded:
        print(json.dumps({"kind": "lifecycle_matrix_first_attempts", "platform": platform.platform(),
                          "python": platform.python_version(), "temp_cleanup_failures": _TEMP_CLEANUP_FAILURES,
                          "results": lifecycle}, sort_keys=True), flush=True)
    concurrency = []
    for role in ("application", "ssh"):
        try:
            concurrency.append(await _concurrency_and_soak(role, bounded=bounded))
        except Exception:
            if linux_bounded:
                print(f"TCP_SYSLOG_LINUX_RELIABILITY_FAIL role={role} scenario=concurrency "
                      "stage=runtime category=internal_failure count=1", flush=True)
                return 1
            raise
    result = {
        "kind": "synthetic_phase_34_3_acceptance_not_sla",
        "platform": platform.platform(),
        "python": platform.python_version(),
        "temp_cleanup_failures": _TEMP_CLEANUP_FAILURES,
        "lifecycle": lifecycle,
        "concurrency_and_soak": concurrency,
    }
    if linux_bounded:
        safe = all(
            item["two_connection_progress"] and item["third_connection_rejected"]
            and item["slow_partial_did_not_starve_peer"]
            and item["rapid_connect_disconnect"] == 30
            and item["malformed_and_parser_recovery_cases"] == 7
            and item["active_connections_peak"] == 2
            and item["active_connection_tasks_peak"] == 2
            and item["main_runtime_cleanup"]["active_connections"] == 0
            and item["main_runtime_cleanup"]["connection_tasks"] == 0
            and item["main_runtime_cleanup"]["closing_tasks"] == 0
            and item["main_runtime_cleanup"]["fd_before"] >= 0
            and item["main_runtime_cleanup"]["fd_before"] == item["main_runtime_cleanup"]["fd_after"]
            and item["main_runtime_cleanup"]["listener_released"]
            and item["main_runtime_cleanup"]["port_reused"]
            and item["queue_overload"]["state"] == "DEGRADED"
            and item["queue_overload"]["accepted"] == 1
            and item["queue_overload"]["rejected"] == 1
            and item["queue_overload"]["queued_events"] <= item["queue_overload"]["event_limit"]
            and item["queue_overload"]["queued_bytes"] <= item["queue_overload"]["byte_limit"]
            and item["soak"]["sent"] == item["soak"]["accepted"] == item["soak"]["parsed"]
                == item["soak"]["analyzed"] == 256
            and item["soak"]["rejected"] == item["soak"]["parser_rejected"]
                == item["soak"]["dropped"] == 0
            and item["soak"]["queue_peak_events"] <= 256
            and item["soak"]["queue_peak_bytes"] <= 1024 * 1024
            and item["soak"]["active_connections_peak"] <= 2
            and item["soak"]["active_tasks_peak"] <= 2
            and item["soak"]["fd_before"] >= 0
            and item["soak"]["fd_before"] == item["soak"]["fd_after"]
            and item["soak"]["listener_released_after_stop"]
            and item["soak"]["port_reused_after_stop"]
            and item["soak"]["tasks_after_stop"] == 0
            for item in concurrency
        )
        if not safe:
            print("TCP_SYSLOG_LINUX_RELIABILITY_FAIL category=resource_or_concurrency", flush=True)
            return 1
        print("TCP_SYSLOG_LINUX_RELIABILITY_PASS roles=2 runs=80 synthetic=1 leaks=0", flush=True)
        return 0

    print(json.dumps(result, sort_keys=True))
    return 0 if (lifecycle["first_attempt_passes"] == lifecycle["attempts"]
                 and not failures and _TEMP_CLEANUP_FAILURES == 0
                 and not _RESOURCE_CLEANUP_DETAILS) else 1


if __name__ == "__main__" and len(sys.argv) > 1 and sys.argv[1] == "--child":
    if len(sys.argv) != 10:
        raise SystemExit(2)
    raise SystemExit(asyncio.run(_child(
        sys.argv[2], sys.argv[3], *(Path(value) for value in sys.argv[4:10]))))
elif __name__ == "__main__" and len(sys.argv) == 2 and sys.argv[1] == "--linux-bounded":
    if not sys.platform.startswith("linux"):
        print("TCP_SYSLOG_LINUX_RELIABILITY_FAIL category=unsupported_platform", flush=True)
        raise SystemExit(2)
    try:
        result = asyncio.run(_main(linux_bounded=True))
    except Exception:
        print("TCP_SYSLOG_LINUX_RELIABILITY_FAIL category=internal_failure", flush=True)
        raise SystemExit(1)
    raise SystemExit(result)
elif __name__ == "__main__" and len(sys.argv) == 2 and sys.argv[1] == "--bounded":
    raise SystemExit(asyncio.run(_main(bounded=True)))
elif __name__ == "__main__":
    raise SystemExit(asyncio.run(_main()))
