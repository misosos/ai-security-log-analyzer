"""Opt-in development measurement; run directly, never an operational SLA."""

import json
import statistics
import tempfile
import threading
import time
import tracemalloc
from pathlib import Path

from app import local_web
from app.live_monitoring.analysis_accumulator import LiveAnalysisAccumulator
from app.live_monitoring.core import LiveTailSession
from app.live_monitoring.worker import LiveProcessingWorker
from app.api import create_app
from fastapi.testclient import TestClient


WARMUPS = 2
SAMPLES = 12


def _stats(samples):
    ordered = sorted(samples)
    return {
        "samples": len(ordered),
        "median_ms": round(statistics.median(ordered), 3),
        "p95_ms": round(ordered[min(len(ordered) - 1, int(len(ordered) * 0.95))], 3),
        "max_ms": round(ordered[-1], 3),
    }


def _run_one(*, trace=False):
    with tempfile.TemporaryDirectory(prefix="live-benchmark-") as root:
        source = Path(root) / "synthetic.log"
        source.write_bytes(b"old line\n")
        config = Path(root) / "live.json"
        config.write_text(json.dumps({
            "schema_version": "1", "start_policy": "FROM_END",
            "source": {"role": "application", "path": str(source.resolve())},
        }), encoding="utf-8")
        config.chmod(0o600)
        service, _ = local_web._live_runtime(config.resolve())
        worker = service._worker
        try:
            raw = b"2026-01-02 03:04:01 INFO login_failed user=synthetic ip=192.0.2.11\n"
            # 255 committed events; each actual step respects the 16-line poll
            # cap and the one-lease-per-step ownership contract.
            remaining = 255
            while remaining:
                count = min(16, remaining)
                with source.open("ab") as stream:
                    stream.write(raw * count)
                processed = worker.step().parsed_count
                assert processed == count
                remaining -= count
            assert worker._accumulator.snapshot().history_record_count == 255
            final = b"2026-01-02 03:04:06 INFO user_login user=synthetic ip=192.0.2.11\n"
            with source.open("ab") as stream:
                stream.write(final)
            prepare_span = []
            after_ack = []
            original_prepare = LiveAnalysisAccumulator.prepare
            original_ack = LiveTailSession.acknowledge_lease

            def prepare(instance, proposal):
                start = time.perf_counter_ns()
                try:
                    return original_prepare(instance, proposal)
                finally:
                    prepare_span.append((time.perf_counter_ns() - start) / 1e6)

            def ack(instance, lease):
                value = original_ack(instance, lease)
                after_ack.append(time.perf_counter_ns())
                return value

            LiveAnalysisAccumulator.prepare = prepare
            LiveTailSession.acknowledge_lease = ack
            if trace:
                tracemalloc.start()
            try:
                start = time.perf_counter_ns()
                result = worker.step()
                end = time.perf_counter_ns()
                peak = tracemalloc.get_traced_memory()[1] if trace else None
            finally:
                if trace:
                    tracemalloc.stop()
                LiveAnalysisAccumulator.prepare = original_prepare
                LiveTailSession.acknowledge_lease = original_ack
            assert result.status == "PROCESSED" and result.parsed_count == 1
            assert worker._analysis.snapshot().revision == worker._accumulator.snapshot().revision
            assert worker._accumulator.snapshot().history_record_count == 256
            analysis = worker._analysis.snapshot()
            return {
                "worker_ms": (end - start) / 1e6,
                "analysis_ms": prepare_span[0],
                "commit_ms": (end - after_ack[0]) / 1e6,
                "events": 256,
                "raw_bytes": len(raw) * 255 + len(final),
                "detections": worker._accumulator.snapshot().active_observation_count,
                "relations": analysis.relation_count,
                "risks": analysis.risk_count,
                "cases": analysis.case_count,
                "traced_peak_bytes": peak,
            }
        finally:
            worker.close()
            assert worker._session._fd == -1


def _status_while_runner_runs():
    with tempfile.TemporaryDirectory(prefix="live-status-benchmark-") as root:
        source = Path(root) / "synthetic.log"
        source.write_bytes(b"old line\n")
        config = Path(root) / "live.json"
        config.write_text(json.dumps({
            "schema_version": "1", "start_policy": "FROM_END",
            "source": {"role": "application", "path": str(source.resolve())},
        }), encoding="utf-8")
        config.chmod(0o600)
        service, runner = local_web._live_runtime(config.resolve())
        entered = threading.Event()
        spans = []
        original_step = LiveProcessingWorker.step

        def measured_step(instance):
            start = time.perf_counter_ns()
            entered.set()
            try:
                return original_step(instance)
            finally:
                spans.append((start, time.perf_counter_ns()))

        LiveProcessingWorker.step = measured_step
        intervals = []
        try:
            app = create_app(live_monitoring_service=service,
                             live_monitoring_runner=runner)
            with TestClient(app, base_url="http://127.0.0.1:8000",
                            client=("127.0.0.1", 50000)) as client:
                assert client.get("/api/v1/live/status").status_code == 200
                entered.clear()
                with source.open("ab") as stream:
                    stream.write(b"2026-01-02 03:04:01 INFO login_failed "
                                 b"user=synthetic ip=192.0.2.11\n" * 16)
                assert entered.wait(timeout=2.0)
                for _ in range(40):
                    start = time.perf_counter_ns()
                    response = client.get("/api/v1/live/status")
                    end = time.perf_counter_ns()
                    assert response.status_code == 200
                    data = response.json()
                    assert data["schema_version"] == "1"
                    assert data["source_role"] == "application"
                    intervals.append((start, end))
                    time.sleep(0.03)  # Measurement pacing, not production polling.
                assert service._worker._session.snapshot().acknowledged_record_count == 16
            assert runner._task.done()
            assert service._worker._session._fd == -1
        finally:
            LiveProcessingWorker.step = original_step
        overlap = sum(any(a < end and start < b for a, b in spans)
                      for start, end in intervals)
        return {"status": _stats([(end - start) / 1e6 for start, end in intervals]),
                "worker_steps": len(spans), "overlapping_requests": overlap}


if __name__ == "__main__":
    for _ in range(WARMUPS):
        _run_one()
    samples = [_run_one() for _ in range(SAMPLES)]
    traced = [_run_one(trace=True) for _ in range(SAMPLES)]
    print(json.dumps({
        "warmups": WARMUPS,
        "input": {key: samples[0][key] for key in
                  ("events", "raw_bytes", "detections", "relations", "risks", "cases")},
        "untraced": {key: _stats([item[key] for item in samples]) for key in
                     ("worker_ms", "analysis_ms", "commit_ms")},
        "traced_analysis": _stats([item["analysis_ms"] for item in traced]),
        "traced_peak_bytes_max": max(item["traced_peak_bytes"] for item in traced),
        "runner_status": _status_while_runner_runs(),
    }, sort_keys=True))
