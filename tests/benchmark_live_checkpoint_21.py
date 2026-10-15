"""Development-only bounded checkpoint timings; no operational SLA."""

import asyncio
import json
import math
from pathlib import Path
import platform
import statistics
import tempfile
import time
import tracemalloc

from fastapi.testclient import TestClient
from app.api import create_app
from app.local_web import _live_runtime
from app.monitor_setup import create_monitor_config
from app.live_monitoring.checkpoint import CHECKPOINT_NAME
from app.live_monitoring import checkpoint as checkpoint_module
from app.live_monitoring.detection_accumulator import LiveDetectionAccumulator
from app.live_monitoring.analysis_accumulator import LiveAnalysisAccumulator
from app.live_monitoring.runner import LiveMonitoringRunner
from app.live_monitoring.checkpoint import LiveCheckpointManager


def _summary(values: list[float]) -> dict[str, float]:
    ordered = sorted(values)
    return {"median_ms": round(statistics.median(values) * 1000, 3),
            "p95_ms": round(ordered[math.ceil(0.95 * len(values)) - 1] * 1000, 3),
            "max_ms": round(max(values) * 1000, 3)}


def _once(count: int) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="checkpoint-benchmark-",
                                     dir=Path(tempfile.gettempdir()).resolve()) as root:
        base = Path(root)
        source = base / "synthetic.log"
        source.write_text("2026-01-02 03:04:00 INFO login_failed user=old ip=192.0.2.1\n")
        config = base / "private" / "monitoring.json"
        create_monitor_config(source, config)
        started = time.perf_counter()
        service, _ = _live_runtime(config, checkpoint_default=True)
        initial_ms = time.perf_counter() - started
        worker = service._worker
        writes = []
        original_write = LiveCheckpointManager._write

        def timed_write(self, value):
            then = time.perf_counter()
            try:
                return original_write(self, value)
            finally:
                writes.append(time.perf_counter() - then)

        try:
            with source.open("a", encoding="utf-8") as stream:
                for index in range(count):
                    stream.write(f"2026-01-02 03:{(index // 60):02d}:{(index % 60):02d} "
                                 "INFO login_failed user=synthetic ip=192.0.2.1\n")
            steps = []
            LiveCheckpointManager._write = timed_write
            try:
                while worker._session.snapshot().acknowledged_record_count < count:
                    started = time.perf_counter()
                    worker.step()
                    steps.append(time.perf_counter() - started)
            finally:
                LiveCheckpointManager._write = original_write
            before = worker._accumulator.snapshot()
        finally:
            asyncio.run(service.close())
        size = (config.parent / CHECKPOINT_NAME).stat().st_size
        parts = {"parser": [], "detection": [], "analysis": [], "semantic": []}
        originals = (checkpoint_module.parse_live_records, LiveDetectionAccumulator.prepare,
                     LiveAnalysisAccumulator.prepare, checkpoint_module._semantic_digest)

        def measure(name, original):
            def wrapped(*args, **kwargs):
                then = time.perf_counter()
                try:
                    return original(*args, **kwargs)
                finally:
                    parts[name].append(time.perf_counter() - then)
            return wrapped

        checkpoint_module.parse_live_records = measure("parser", originals[0])
        LiveDetectionAccumulator.prepare = measure("detection", originals[1])
        LiveAnalysisAccumulator.prepare = measure("analysis", originals[2])
        checkpoint_module._semantic_digest = measure("semantic", originals[3])
        tracemalloc.start()
        try:
            started = time.perf_counter()
            service, runner = _live_runtime(config, checkpoint_default=True)
            replay_ms = time.perf_counter() - started
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
            checkpoint_module.parse_live_records = originals[0]
            LiveDetectionAccumulator.prepare = originals[1]
            LiveAnalysisAccumulator.prepare = originals[2]
            checkpoint_module._semantic_digest = originals[3]
        try:
            assert service._worker._accumulator.snapshot() == before
            assert service._worker.publication_buffer.snapshot().published_total == 0
            status = []
            app = create_app(live_monitoring_service=service,
                             live_monitoring_runner=runner)
            with TestClient(app, base_url="http://127.0.0.1:8000",
                            client=("127.0.0.1", 50000)) as client:
                for _ in range(30):
                    started = time.perf_counter()
                    response = client.get("/api/v1/live/status")
                    status.append(time.perf_counter() - started)
                    assert response.status_code == 200
                    assert response.json()["analysis_revision"] == before.revision
                shutdown_start = time.perf_counter()
            shutdown = time.perf_counter() - shutdown_start
        finally:
            asyncio.run(service.close())
        return {"events": count, "bytes": source.stat().st_size,
                "initial_seconds": initial_ms, "replay_seconds": replay_ms,
                "step_seconds": statistics.median(steps), "checkpoint_bytes": size,
                "peak_bytes": peak, "update_seconds": statistics.median(writes),
                "parts": {key: sum(value) for key, value in parts.items()},
                "status_seconds": statistics.median(status), "shutdown_seconds": shutdown}


def main() -> None:
    results = {}
    for count in (1, 16, 64, 128, 256):
        samples = [_once(count) for _ in range(4)]  # 1 warm-up, 3 reported.
        measured = samples[1:]
        results[count] = {
            "input_events": count, "input_bytes": measured[0]["bytes"],
            "checkpoint_bytes": measured[0]["checkpoint_bytes"],
            "peak_tracemalloc_bytes": max(item["peak_bytes"] for item in measured),
            "initial": _summary([item["initial_seconds"] for item in measured]),
            "replay": _summary([item["replay_seconds"] for item in measured]),
            "worker_step": _summary([item["step_seconds"] for item in measured]),
            "checkpoint_update": _summary([item["update_seconds"] for item in measured]),
            "parser_rebuild": _summary([item["parts"]["parser"] for item in measured]),
            "detection_rebuild": _summary([item["parts"]["detection"] for item in measured]),
            "analysis_rebuild": _summary([item["parts"]["analysis"] for item in measured]),
            "semantic_verification": _summary([item["parts"]["semantic"] for item in measured]),
            "status_http": _summary([item["status_seconds"] for item in measured]),
            "shutdown": _summary([item["shutdown_seconds"] for item in measured]),
        }
    print(json.dumps({"os": platform.system(), "python": platform.python_version(),
                      "samples": 3, "warmup": 1, "tracemalloc": "replay only",
                      "results": results}, sort_keys=True))


if __name__ == "__main__":
    main()
