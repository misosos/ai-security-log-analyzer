"""Opt-in synthetic benchmark; not part of pytest and not an operational SLA."""

from __future__ import annotations

import json
import platform
import statistics
import sys
from time import perf_counter_ns
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.log_collection.jsonl_adapter import (
    BoundedJsonLinesQueue,
    JsonLinesDecoder,
    JsonlAdapterConfig,
    JsonlEnvelope,
)


WARMUP = 8
SAMPLES = 51
QUEUE_ACCOUNTED_BYTES = len("synthetic-queue".encode("utf-8")) + len("bench-synthetic".encode("utf-8"))


def _line(payload: str) -> bytes:
    value = {
        "schema_version": 1,
        "source_role": "application",
        "payload": payload,
        "collector_instance_alias": "bench-synthetic",
        "sequence_hint": None,
        "retry_hint": False,
    }
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"


def _maximum_line(config: JsonlAdapterConfig) -> bytes:
    raw = _line("x" * config.max_payload_bytes)
    pad = config.max_record_bytes - len(raw)
    if pad < 0:
        raise RuntimeError("fixed benchmark fixture exceeds configured limit")
    return raw[:-2] + b" " * pad + raw[-2:]


def _cases():
    config = JsonlAdapterConfig(source_role="application")
    ascii_line = _line("synthetic-ascii")
    korean_line = _line("합성한국어")
    byte_line = _line("🙂")
    batch = _line("batch-a") * 32
    maximum = _maximum_line(config)
    refusal = b"{}\n"
    queue_event = JsonlEnvelope("application", "synthetic-queue", 15,
                                "bench-synthetic", None, False)

    def decode(raw: bytes):
        result = JsonLinesDecoder(config).feed(raw)
        if result.error_category is not None:
            raise RuntimeError("fixed benchmark decode fixture rejected")

    def one_byte():
        decoder = JsonLinesDecoder(config)
        for byte in byte_line:
            result = decoder.feed(bytes((byte,)))
            if result.error_category is not None:
                raise RuntimeError("fixed benchmark byte fixture rejected")

    def refuse():
        result = JsonLinesDecoder(config).feed(refusal)
        if result.error_category is None:
            raise RuntimeError("fixed benchmark refusal fixture accepted")

    def queue_operation():
        queue = BoundedJsonLinesQueue(config)
        queue.enqueue(queue_event)
        queue.dequeue()
        queue.close()

    return (
        ("ASCII", lambda: decode(ascii_line), ascii_line, 15),
        ("Korean", lambda: decode(korean_line), korean_line, len("합성한국어".encode("utf-8"))),
        ("one_byte", one_byte, byte_line, len("🙂".encode("utf-8"))),
        ("batch_32", lambda: decode(batch), batch, 32 * len("batch-a")),
        ("maximum_line", lambda: decode(maximum), maximum, config.max_payload_bytes),
        ("refusal", refuse, refusal, 0),
        ("queue", queue_operation, b"", queue_event.payload_byte_count),
    )


def _percentile(values: list[float], percentile: float) -> float:
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, int((len(ordered) * percentile + 0.999999)) - 1))
    return ordered[index]


def main() -> int:
    results = []
    for name, operation, raw, payload_bytes in _cases():
        for _ in range(WARMUP):
            operation()
        timings = []
        for _ in range(SAMPLES):
            start = perf_counter_ns()
            operation()
            timings.append((perf_counter_ns() - start) / 1_000_000)
        results.append({
            "case": name,
            "warmup": WARMUP,
            "samples": SAMPLES,
            "payload_bytes": payload_bytes,
            "record_bytes": len(raw),
            "queue_accounted_bytes": QUEUE_ACCOUNTED_BYTES if name == "queue" else 0,
            "median_ms": round(statistics.median(timings), 4),
            "p95_ms": round(_percentile(timings, 0.95), 4),
            "max_ms": round(max(timings), 4),
        })
    print(json.dumps({
        "benchmark": "synthetic in-process JSON Lines adapter core",
        "python": platform.python_version(),
        "os": platform.system(),
        "architecture": platform.machine(),
        "operational_sla": False,
        "results": results,
    }, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
