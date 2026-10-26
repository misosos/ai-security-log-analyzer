"""Manual synthetic benchmark; run with `PYTHONPATH=. uv run python tests/benchmark_tcp_syslog_core_34_1.py`.

Development observations only, not an operating SLA. No sockets or files are used.
"""

from __future__ import annotations

import json
import platform
import statistics
import time

from app.log_collection.framing import OctetCountingDecoder
from app.log_collection.models import TcpCollectionConfig
from app.log_collection.queue import BoundedEventQueue


CONFIG = TcpCollectionConfig(
    schema_version="tcp-syslog-config/v1", source_role="application",
    transport="tcp_syslog_octet_counting", bind_scope="loopback_only",
    max_connections=2, max_prefix_digits=6, max_frame_bytes=8192,
    max_connection_buffer_bytes=8199, max_queue_events=256,
    max_queue_bytes=1024 * 1024, invalid_frame_action="close_connection",
    incomplete_frame_action="reject_on_close",
)


def _measure(name, operation, payload_size=0):
    for _ in range(2):
        operation()
    samples = []
    for _ in range(20):
        start = time.perf_counter_ns()
        operation()
        samples.append((time.perf_counter_ns() - start) / 1_000_000)
    ordered = sorted(samples)
    return {"name": name, "warmup": 2, "samples": len(samples), "payload_bytes": payload_size,
            "median_ms": round(statistics.median(samples), 4),
            "p95_ms": round(ordered[18], 4), "max_ms": round(max(samples), 4)}


def main():
    payload = b"x" * 512
    wire = str(len(payload)).encode() + b" " + payload
    batch = b"1 x" * 32
    cases = [
        _measure("decoder_create", lambda: OctetCountingDecoder(CONFIG)),
        _measure("single_frame", lambda: OctetCountingDecoder(CONFIG).feed(wire), len(payload)),
        _measure("byte_chunks", lambda: _byte_chunks(wire), len(payload)),
        _measure("batch_32", lambda: OctetCountingDecoder(CONFIG).feed(batch), 32),
        _measure("max_frame", lambda: OctetCountingDecoder(CONFIG).feed(b"8192 " + b"x" * 8192), 8192),
        _measure("queue_enqueue_dequeue", lambda: _queue_roundtrip(wire), len(payload)),
        _measure("malformed_prefix", lambda: OctetCountingDecoder(CONFIG).feed(b"+1 bad"), 0),
        _measure("close_cleanup", lambda: _closed_decoder(wire), len(payload)),
    ]
    print(json.dumps({"python": platform.python_version(), "os": platform.system(),
                      "architecture": platform.machine(), "payload_byte_budget": 8199 + 1024 * 1024,
                      "python_object_overhead_included": False,
                      "results": cases}, sort_keys=True))


def _queue_roundtrip(wire):
    queue = BoundedEventQueue(CONFIG)
    frame = OctetCountingDecoder(CONFIG).feed(wire).frames[0]
    queue.enqueue(frame)
    queue.dequeue()


def _byte_chunks(wire):
    decoder = OctetCountingDecoder(CONFIG)
    for byte in wire:
        decoder.feed(bytes((byte,)))


def _closed_decoder(wire):
    decoder = OctetCountingDecoder(CONFIG)
    decoder.feed(wire[:4])
    decoder.close()


if __name__ == "__main__":
    main()
