"""Manual bounded synthetic loopback benchmark; excluded from pytest/CI by default."""

import asyncio
import json
import math
import platform
import statistics
import sys
import time

from app.log_collection.runtime import TcpRuntimeConfig, TcpSyslogRuntime


def _line(role, second, failed=True):
    if role == "application":
        event = "login_failed" if failed else "user_login"
        value = f"2026-01-02 03:04:{second:02d} INFO {event} user=synthetic_user ip=192.0.2.19 service=ssh"
    else:
        action = "Failed" if failed else "Accepted"
        value = (f"2026-01-02 03:04:{second:02d} sshd: {action} password for synthetic_user "
                 "from 198.51.100.29 port 45001 ssh2")
    payload = value.encode("utf-8")
    return str(len(payload)).encode("ascii") + b" " + payload


def _percentile(values, fraction):
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, max(0, math.ceil(len(ordered) * fraction) - 1))]


async def _sample(role, count):
    runtime = TcpSyslogRuntime(TcpRuntimeConfig(
        schema_version="tcp-syslog-runtime/v1", source_role=role, bind_family="ipv4",
        port=0, connection_limit=2, idle_timeout_seconds=30.0,
        read_timeout_seconds=5.0, parser_timezone="Asia/Seoul",
        startup_mode="synthetic_pilot", test_only_ephemeral_port=True,
    ))
    started = time.perf_counter_ns()
    await runtime.start()
    start_ns = time.perf_counter_ns() - started
    port = runtime._server.sockets[0].getsockname()[1]
    connect_at = time.perf_counter_ns()
    _reader, writer = await asyncio.open_connection("127.0.0.1", port)
    connect_ns = time.perf_counter_ns() - connect_at
    wire = b"".join(_line(role, (index % 50) + 1, failed=index % 6 != 5)
                    for index in range(1, count + 1))
    send_at = time.perf_counter_ns()
    writer.write(wire)
    await writer.drain()
    while runtime.snapshot().accepted_frames < count:
        await asyncio.sleep(0)
    admission_ns = time.perf_counter_ns() - send_at
    analysis_at = time.perf_counter_ns()
    await runtime.wait_until_processed(count, timeout=60.0)
    analysis_ns = time.perf_counter_ns() - analysis_at
    status_at = time.perf_counter_ns()
    runtime.snapshot()
    status_ns = time.perf_counter_ns() - status_at
    writer.close()
    await writer.wait_closed()
    close_at = time.perf_counter_ns()
    await runtime.stop()
    close_ns = time.perf_counter_ns() - close_at
    return {"start_ns": start_ns, "connect_ns": connect_ns,
            "send_to_admission_ns": admission_ns, "parser_analysis_ns": analysis_ns,
            "status_ns": status_ns, "graceful_close_ns": close_ns,
            "payload_bytes": len(wire), "frames": count}


async def main():
    output = []
    for role in ("application", "ssh"):
        for count in (1, 32, 256):
            await _sample(role, count)  # one warm-up per role/size
            rows = [await _sample(role, count) for _ in range(3)]
            fields = {}
            for key in ("start_ns", "connect_ns", "send_to_admission_ns", "parser_analysis_ns",
                        "status_ns", "graceful_close_ns", "payload_bytes"):
                values = [row[key] for row in rows]
                fields[key] = {"median": int(statistics.median(values)),
                               "p95": int(_percentile(values, 0.95)), "max": max(values)}
            output.append({"role": role, "frames": count, "warmup": 1, "samples": 3,
                           "measurements": fields})
    print(json.dumps({"kind": "synthetic_development_measurement",
                      "python": platform.python_version(), "os": platform.platform(),
                      "architecture": platform.machine(), "operational_sla": False,
                      "results": output}, sort_keys=True))


if __name__ == "__main__":
    asyncio.run(main())
