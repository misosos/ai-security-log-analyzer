"""Opt-in SSH development measurement; results are not an operational SLA."""

import json
import statistics
import tempfile
import threading
import time
from pathlib import Path

from fastapi.testclient import TestClient

from app.api import create_app
from app.local_web import _live_runtime
from app.live_monitoring.analysis_accumulator import LiveAnalysisAccumulator
from app.live_monitoring.publication import LivePublicationBuffer
from app.live_monitoring.worker import LiveProcessingWorker


WARMUPS = 1
SAMPLES = 8


def _stats(values):
    ordered = sorted(values)
    return {"samples": len(values), "median_ms": round(statistics.median(ordered), 3),
            "p95_ms": round(ordered[min(len(ordered) - 1, int(len(ordered) * .95))], 3),
            "max_ms": round(ordered[-1], 3)}


def _runtime(root):
    source = Path(root) / "synthetic.log"
    source.write_bytes(b"old line\n")
    config = Path(root) / "monitor.json"
    config.write_text(json.dumps({"schema_version": "1", "start_policy": "FROM_END",
                                  "source": {"role": "ssh", "path": str(source.resolve())}}),
                      encoding="utf-8")
    config.chmod(0o600)
    service, runner = _live_runtime(config.resolve())
    return source, service, runner


def _run_one():
    with tempfile.TemporaryDirectory(prefix="ssh-live-bench-") as root:
        source, service, _runner = _runtime(root)
        worker = service._worker
        failed = (b"2026-01-02 03:04:01 sshd: Failed password for synthetic "
                  b"from 198.51.100.87 port 5001 ssh2\n")
        success = (b"2026-01-02 03:04:06 sshd: Accepted password for synthetic "
                   b"from 198.51.100.87 port 5001 ssh2\n")
        try:
            for first in range(0, 255, 16):
                amount = min(16, 255 - first)
                with source.open("ab") as stream:
                    stream.write(failed * amount)
                assert worker.step().parsed_count == amount
            with source.open("ab") as stream:
                stream.write(success)
            spans = {"analysis_prepare": [], "publication_prepare": [],
                     "publication_commit": []}
            original_analysis = LiveAnalysisAccumulator.prepare
            original_prepare = LivePublicationBuffer.prepare_batch
            original_commit = LivePublicationBuffer.commit_prepared

            def measured(name, original):
                def call(instance, *args):
                    start = time.perf_counter_ns()
                    try:
                        return original(instance, *args)
                    finally:
                        spans[name].append((time.perf_counter_ns() - start) / 1e6)
                return call

            LiveAnalysisAccumulator.prepare = measured("analysis_prepare", original_analysis)
            LivePublicationBuffer.prepare_batch = measured("publication_prepare", original_prepare)
            LivePublicationBuffer.commit_prepared = measured("publication_commit", original_commit)
            try:
                start = time.perf_counter_ns()
                result = worker.step()
                worker_ms = (time.perf_counter_ns() - start) / 1e6
            finally:
                LiveAnalysisAccumulator.prepare = original_analysis
                LivePublicationBuffer.prepare_batch = original_prepare
                LivePublicationBuffer.commit_prepared = original_commit
            assert result.status == "PROCESSED" and result.parsed_count == 1
            assert worker._accumulator.snapshot().history_record_count == 256
            analysis = worker._analysis.snapshot()
            return {"worker": worker_ms, **{key: value[0] for key, value in spans.items()},
                    "events": 256, "raw_bytes": 255 * len(failed) + len(success),
                    "detections": worker._accumulator.snapshot().active_observation_count,
                    "relations": analysis.relation_count, "risks": analysis.risk_count,
                    "cases": analysis.case_count}
        finally:
            worker.close()
            assert worker._session._fd == -1


def _status_while_runner_runs():
    with tempfile.TemporaryDirectory(prefix="ssh-status-bench-") as root:
        source, service, runner = _runtime(root)
        spans = []
        entered = threading.Event()
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
                    stream.write((b"2026-01-02 03:04:01 sshd: Failed password for synthetic "
                                  b"from 198.51.100.87 port 5001 ssh2\n") * 16)
                assert entered.wait(timeout=2)
                for _ in range(40):
                    start = time.perf_counter_ns()
                    response = client.get("/api/v1/live/status")
                    end = time.perf_counter_ns()
                    assert response.status_code == 200
                    assert response.json()["source_role"] == "ssh"
                    intervals.append((start, end))
                    time.sleep(.02)
                assert service._worker._session.snapshot().acknowledged_record_count == 16
            assert runner._task.done()
            assert service._worker._session._fd == -1
        finally:
            LiveProcessingWorker.step = original_step
        overlap = sum(any(a < end and start < b for a, b in spans)
                      for start, end in intervals)
        return {"http_status": _stats([(end - start) / 1e6 for start, end in intervals]),
                "worker_steps": len(spans), "overlapping_requests": overlap}


def main():
    for _ in range(WARMUPS):
        _run_one()
    samples = [_run_one() for _ in range(SAMPLES)]
    print(json.dumps({"warmups": WARMUPS, "samples": SAMPLES, "tracemalloc": False,
                      "input": {key: samples[0][key] for key in (
                          "events", "raw_bytes", "detections", "relations", "risks", "cases")},
                      "timings": {key: _stats([sample[key] for sample in samples])
                                  for key in ("worker", "analysis_prepare",
                                              "publication_prepare", "publication_commit")},
                      "status_while_runner_runs": _status_while_runner_runs()},
                     sort_keys=True))


if __name__ == "__main__":
    main()
