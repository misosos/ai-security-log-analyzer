"""Opt-in synthetic runtime benchmark; measurements are not an operations SLA."""

import asyncio
import json
import platform
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.log_collection.jsonl_adapter import BoundedJsonLinesQueue, JsonlAdapterError, AdapterErrorCode
from app.log_collection.jsonl_runtime import JsonlCollectorRuntime, JsonlRuntimeConfig, JsonlRuntimeError


def _payload(role: str) -> str:
    return ("2026-01-02 03:04:05 INFO user_login user=synthetic_user ip=192.0.2.41 service=ssh"
            if role == "application" else
            "2026-01-02 03:04:05 sshd: Accepted password for synthetic_user from 192.0.2.41 port 45001 ssh2")


async def _once(role: str, count: int) -> float:
    runtime = JsonlCollectorRuntime(JsonlRuntimeConfig(
        role, port=0, test_only_ephemeral_port=True,
        history_records=256, history_bytes=262144,
    ))
    await runtime.start()
    port = runtime._server.sockets[0].getsockname()[1]
    envelope = {"schema_version": 1, "source_role": role, "payload": _payload(role),
                "collector_instance_alias": "synthetic-collector", "sequence_hint": None,
                "retry_hint": False}
    wire = (json.dumps(envelope, separators=(",", ":")) + "\n").encode()
    started = time.perf_counter()
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    for sent in range(0, count, 32):
        batch_count = min(32, count - sent)
        writer.write(wire * batch_count)
        await writer.drain()
        await runtime.wait_until_processed(sent + batch_count, timeout=10)
    elapsed = time.perf_counter() - started
    writer.close()
    await writer.wait_closed()
    await runtime.stop()
    return elapsed


async def _other(role: str, case: str) -> float:
    runtime = JsonlCollectorRuntime(JsonlRuntimeConfig(role, port=0, test_only_ephemeral_port=True))
    if case == "fault_cleanup":
        async def fail_bind():
            raise OSError("synthetic")
        runtime._create_server = fail_bind
        started = time.perf_counter()
        try:
            await runtime.start()
        except JsonlRuntimeError:
            pass
        await runtime.stop()
        return time.perf_counter() - started
    if case == "queue_full":
        original = BoundedJsonLinesQueue.enqueue
        def full(_queue, _envelope):
            raise JsonlAdapterError(AdapterErrorCode.QUEUE_FULL)
        BoundedJsonLinesQueue.enqueue = full
        try:
            return await _send_case(runtime, role, "queue_full")
        finally:
            BoundedJsonLinesQueue.enqueue = original
    return await _send_case(runtime, role, case)


async def _send_case(runtime: JsonlCollectorRuntime, role: str, case: str) -> float:
    started = time.perf_counter()
    if case == "start_stop":
        await runtime.start()
        await runtime.stop()
        return time.perf_counter() - started
    await runtime.start()
    port = runtime._server.sockets[0].getsockname()[1]
    payload = _payload(role)
    envelope = {"schema_version": 1, "source_role": role, "payload": payload,
                "collector_instance_alias": "synthetic-collector", "sequence_hint": None,
                "retry_hint": False}
    wire = (json.dumps(envelope, separators=(",", ":")) + "\n").encode()
    if case == "malformed_refusal":
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b'{"invalid":true}\n'); await writer.drain()
        await reader.read()
        writer.close(); await writer.wait_closed()
    elif case == "two_connection_fairness":
        clients = [await asyncio.open_connection("127.0.0.1", port) for _ in range(2)]
        for _reader, writer in clients:
            writer.write(wire); await writer.drain()
        await runtime.wait_until_processed(2)
        for _reader, writer in clients:
            writer.close(); await writer.wait_closed()
    elif case == "queue_full":
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(wire); await writer.drain(); await reader.read()
        writer.close(); await writer.wait_closed()
    await runtime.stop()
    return time.perf_counter() - started


def main() -> None:
    print(f"python={platform.python_version()} os={platform.system()} arch={platform.machine()} warmup=2 samples=9")
    for role in ("application", "ssh"):
        for count in (1, 32, 256):
            for _ in range(2):
                asyncio.run(_once(role, count))
            values = sorted(asyncio.run(_once(role, count)) * 1000 for _ in range(9))
            p95 = values[min(8, int(0.95 * len(values)))]
            print(f"role={role} records={count} median_ms={statistics.median(values):.3f} "
                  f"p95_ms={p95:.3f} max_ms={max(values):.3f} payload_bytes={len(_payload(role).encode())} "
                  "delivery=synthetic runtime and parser/analysis included")
        for case in ("start_stop", "malformed_refusal", "queue_full",
                     "two_connection_fairness", "fault_cleanup"):
            for _ in range(2):
                asyncio.run(_other(role, case))
            values = sorted(asyncio.run(_other(role, case)) * 1000 for _ in range(9))
            p95 = values[min(8, int(0.95 * len(values)))]
            print(f"role={role} case={case} median_ms={statistics.median(values):.3f} "
                  f"p95_ms={p95:.3f} max_ms={max(values):.3f} payload_bytes={len(_payload(role).encode())}")
    print("These development measurements are not an operational SLA.")


if __name__ == "__main__":
    main()
