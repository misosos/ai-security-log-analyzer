"""Manual short synthetic loopback soak; never reads user logs/settings."""

import asyncio
import json
import os
import platform
import resource
import time

from app.log_collection.runtime import TcpRuntimeConfig, TcpSyslogRuntime


def _wire(role, second):
    if role == "application":
        text = f"2026-01-02 03:04:{second:02d} INFO login_failed user=synthetic_user ip=192.0.2.19 service=ssh"
    else:
        text = (f"2026-01-02 03:04:{second:02d} sshd: Failed password for synthetic_user "
                "from 198.51.100.29 port 45001 ssh2")
    body = text.encode("utf-8")
    return str(len(body)).encode() + b" " + body


async def _role_soak(role):
    runtime = TcpSyslogRuntime(TcpRuntimeConfig(
        schema_version="tcp-syslog-runtime/v1", source_role=role, bind_family="ipv4",
        port=0, connection_limit=2, idle_timeout_seconds=10.0,
        read_timeout_seconds=2.0, parser_timezone="Asia/Seoul",
        startup_mode="synthetic_pilot", test_only_ephemeral_port=True,
    ))
    start_fd = len(os.listdir("/dev/fd")) if os.path.isdir("/dev/fd") else None
    started = time.perf_counter()
    await runtime.start()
    port = runtime._server.sockets[0].getsockname()[1]
    slow_reader, slow_writer = await asyncio.open_connection("127.0.0.1", port)
    slow_writer.write(b"100 partial")
    await slow_writer.drain()
    fast_reader, fast_writer = await asyncio.open_connection("127.0.0.1", port)
    fast_writer.write(b"".join(_wire(role, (i % 50) + 1) for i in range(1, 33)))
    await fast_writer.drain()
    fast_writer.close()
    await fast_writer.wait_closed()
    deadline = time.monotonic() + 5
    while runtime.snapshot().active_connections > 1 and time.monotonic() < deadline:
        await asyncio.sleep(0.005)
    slow_output = await asyncio.open_connection("127.0.0.1", port)
    _slow2_reader, slow2_writer = slow_output
    for second in range(1, 5):
        slow2_writer.write(_wire(role, second))
        await slow2_writer.drain()
        await asyncio.sleep(0.005)
    slow2_writer.close()
    await slow2_writer.wait_closed()
    await runtime.wait_until_processed(36, timeout=30.0)
    for index in range(20):
        deadline = time.monotonic() + 5
        while runtime.snapshot().active_connections > 1 and time.monotonic() < deadline:
            await asyncio.sleep(0.005)
        target = index + 1
        _reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"+1 malformed")
        await writer.drain()
        writer.close()
        await writer.wait_closed()
        while runtime.snapshot().rejected_frames < target and time.monotonic() < deadline:
            await asyncio.sleep(0.005)
    await asyncio.sleep(0.05)
    slow_writer.close()
    await slow_writer.wait_closed()
    await asyncio.sleep(0.05)
    before_stop = runtime.snapshot()
    elapsed_ms = (time.perf_counter() - started) * 1000
    await runtime.stop()
    end_fd = len(os.listdir("/dev/fd")) if os.path.isdir("/dev/fd") else None
    usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    peak_rss_bytes = usage if platform.system() == "Darwin" else usage * 1024
    result = {
        "role": role,
        "frames_received": before_stop.accepted_frames,
        "parsed": before_stop.parsed_events,
        "analyzed": before_stop.analyzed_events,
        "parser_rejected": before_stop.parser_rejected_events,
        "frame_rejected": before_stop.rejected_frames,
        "peak_queue_events": before_stop.peak_queued_events,
        "queue_event_cap": before_stop.queue_event_limit,
        "peak_queue_bytes": before_stop.peak_queued_bytes,
        "queue_byte_cap": before_stop.queue_byte_limit,
        "fd_count_before": start_fd,
        "fd_count_after": end_fd,
        "peak_rss_bytes_process_wide": peak_rss_bytes,
        "elapsed_ms": round(elapsed_ms, 3),
        "stopped": runtime.snapshot().state.value == "STOPPED",
        "listener_released": runtime._server is None,
        "connection_tasks_after": len(runtime._connection_tasks),
    }
    if (before_stop.accepted_frames != 36 or before_stop.analyzed_events != 36
            or before_stop.rejected_frames != 21 or not result["stopped"]
            or not result["listener_released"] or result["connection_tasks_after"] != 0
            or result["peak_queue_events"] > result["queue_event_cap"]
            or result["peak_queue_bytes"] > result["queue_byte_cap"]):
        raise RuntimeError("synthetic bounded soak invariant failed")
    return result


async def main():
    rows = [await _role_soak(role) for role in ("application", "ssh")]
    print(json.dumps({"kind": "synthetic_short_soak_not_sla", "results": rows}, sort_keys=True))


if __name__ == "__main__":
    asyncio.run(main())
