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
from app.live_monitoring.publication import (
    LivePublicationBuffer, serialize_live_analysis_publication_event,
    serialize_live_publication_event, serialize_live_publication_snapshot,
)
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
            publication_prepare_span = []
            publication_commit_span = []
            after_ack = []
            original_prepare = LiveAnalysisAccumulator.prepare
            original_ack = LiveTailSession.acknowledge_lease
            original_publication_prepare = LivePublicationBuffer.prepare_batch
            original_publication_commit = LivePublicationBuffer.commit_prepared

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

            def publication_prepare(instance, detection, analysis):
                start = time.perf_counter_ns()
                try:
                    return original_publication_prepare(instance, detection, analysis)
                finally:
                    publication_prepare_span.append((time.perf_counter_ns() - start) / 1e6)

            def publication_commit(instance, proposal):
                start = time.perf_counter_ns()
                try:
                    return original_publication_commit(instance, proposal)
                finally:
                    publication_commit_span.append((time.perf_counter_ns() - start) / 1e6)

            LiveAnalysisAccumulator.prepare = prepare
            LiveTailSession.acknowledge_lease = ack
            LivePublicationBuffer.prepare_batch = publication_prepare
            LivePublicationBuffer.commit_prepared = publication_commit
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
                LivePublicationBuffer.prepare_batch = original_publication_prepare
                LivePublicationBuffer.commit_prepared = original_publication_commit
            assert result.status == "PROCESSED" and result.parsed_count == 1
            assert worker._analysis.snapshot().revision == worker._accumulator.snapshot().revision
            assert worker._accumulator.snapshot().history_record_count == 256
            analysis = worker._analysis.snapshot()
            replay = worker.publication_buffer.replay_after(None)
            detection_event_bytes = [len(serialize_live_publication_event(item)) for item in replay.events
                                     if item.event_type == "DETECTION_CHANGE"]
            analysis_event_bytes = [len(serialize_live_analysis_publication_event(item)) for item in replay.events
                                    if item.event_type == "ANALYSIS_CHANGE"]
            latest_events = tuple(item for item in replay.events if item.revision == result.accumulator_revision)
            serialization_start = time.perf_counter_ns()
            for item in latest_events:
                if item.event_type == "DETECTION_CHANGE":
                    serialize_live_publication_event(item)
                else:
                    serialize_live_analysis_publication_event(item)
            serialization_ms = (time.perf_counter_ns() - serialization_start) / 1e6
            return {
                "worker_ms": (end - start) / 1e6,
                "analysis_ms": prepare_span[0],
                "commit_ms": (end - after_ack[0]) / 1e6,
                "publication_prepare_ms": publication_prepare_span[0],
                "publication_commit_ms": publication_commit_span[0],
                "detection_event_bytes": max(detection_event_bytes, default=0),
                "analysis_event_bytes": max(analysis_event_bytes, default=0),
                "snapshot_bytes": len(serialize_live_publication_snapshot(worker.publication_buffer.snapshot())),
                "latest_batch_bytes": sum(len(serialize_live_publication_event(item))
                                          if item.event_type == "DETECTION_CHANGE"
                                          else len(serialize_live_analysis_publication_event(item))
                                          for item in latest_events),
                "serialization_ms": serialization_ms,
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
                    assert data["schema_version"] == "2"
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


def _diverse_max_prefix_snapshot():
    """Synthetic 256-subject upper-prefix probe, not a worst-case proof."""
    with tempfile.TemporaryDirectory(prefix="live-diverse-benchmark-") as root:
        source = Path(root) / "synthetic.log"
        source.write_bytes(b"old line\n")
        config = Path(root) / "live.json"
        config.write_text(json.dumps({
            "schema_version": "1", "start_policy": "FROM_END",
            "source": {"role": "application", "path": str(source.resolve())},
        }), encoding="utf-8")
        config.chmod(0o600)
        service, _ = local_web._live_runtime(config.resolve())
        try:
            for first in range(0, 256, 16):
                with source.open("ab") as stream:
                    for number in range(first, first + 16):
                        stream.write(("2026-01-02 03:04:01 INFO login_failed "
                                      f"user=synthetic ip=10.0.0.{number}\n").encode())
                assert service._worker.step().parsed_count == 16
            snapshot = service.publication_buffer.snapshot()
            analysis = service._worker._analysis.snapshot()
            return {"safe_snapshot_bytes": len(serialize_live_publication_snapshot(snapshot)),
                    "relations": analysis.relation_count, "risks": analysis.risk_count,
                    "cases": analysis.case_count}
        finally:
            service._worker.close()


def _two_event_batch_bytes():
    with tempfile.TemporaryDirectory(prefix="live-two-event-benchmark-") as root:
        source = Path(root) / "synthetic.log"
        source.write_bytes(b"old line\n")
        config = Path(root) / "live.json"
        config.write_text(json.dumps({
            "schema_version": "1", "start_policy": "FROM_END",
            "source": {"role": "application", "path": str(source.resolve())},
        }), encoding="utf-8")
        config.chmod(0o600)
        service, _ = local_web._live_runtime(config.resolve())
        try:
            with source.open("ab") as stream:
                for second in range(5):
                    stream.write((f"2026-01-02 03:04:{second:02d} INFO login_failed "
                                  "user=synthetic ip=192.0.2.11\n").encode())
            assert service._worker.step().status == "PROCESSED"
            events = service.publication_buffer.replay_after(None).events
            assert [item.event_type for item in events] == ["DETECTION_CHANGE", "ANALYSIS_CHANGE"]
            sizes = [len(serialize_live_publication_event(events[0])),
                     len(serialize_live_analysis_publication_event(events[1]))]
            return {"detection_bytes": sizes[0], "analysis_bytes": sizes[1],
                    "batch_bytes": sum(sizes)}
        finally:
            service._worker.close()


if __name__ == "__main__":
    for _ in range(WARMUPS):
        _run_one()
    samples = [_run_one() for _ in range(SAMPLES)]
    traced = [_run_one(trace=True) for _ in range(SAMPLES)]
    print(json.dumps({
        "warmups": WARMUPS,
        "input": {key: samples[0][key] for key in
                  ("events", "raw_bytes", "detections", "relations", "risks", "cases",
                   "detection_event_bytes", "analysis_event_bytes", "snapshot_bytes",
                   "latest_batch_bytes")},
        "untraced": {key: _stats([item[key] for item in samples]) for key in
                     ("worker_ms", "analysis_ms", "commit_ms", "publication_prepare_ms",
                      "publication_commit_ms", "serialization_ms")},
        "traced_analysis": _stats([item["analysis_ms"] for item in traced]),
        "traced_peak_bytes_max": max(item["traced_peak_bytes"] for item in traced),
        "runner_status": _status_while_runner_runs(),
        "diverse_256_prefix": _diverse_max_prefix_snapshot(),
        "two_event_batch": _two_event_batch_bytes(),
    }, sort_keys=True))
