"""Re-runnable synthetic-only benchmark; emits aggregate timings, never report data."""

from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import resource
import statistics
import tempfile
import time

from app.restricted_report import (
    APPROVAL,
    _atomic_publish,
    _audit_append,
    _build_report,
    _canonical_json,
    _open_private_directory,
    _parse_lines,
    _read_private_input,
    export_report,
)


WARMUPS = 1
SAMPLES = 5


def _stats(values):
    ordered = sorted(values)
    p95 = ordered[min(len(ordered) - 1, int(0.95 * len(ordered)))]
    return {
        "median_ms": round(statistics.median(values) * 1000, 3),
        "p95_ms": round(p95 * 1000, 3),
        "max_ms": round(max(values) * 1000, 3),
        "samples": len(values),
    }


def _line(index):
    second = index % 60
    return f"2026-09-11 10:00:{second:02d} INFO login_failed user=synthetic-{index % 3} ip=192.0.2.{index % 200 + 1}"


def run_benchmark():
    results = {}
    with tempfile.TemporaryDirectory(
        prefix="restricted-report-bench-", dir=Path(tempfile.gettempdir()).resolve(),
    ) as temp:
        root = Path(temp)
        root.chmod(0o700)
        for count in (1, 32, 256):
            input_path = root / f"input-{count}.log"
            input_path.write_text("\n".join(_line(index) for index in range(count)) + "\n", encoding="utf-8")
            input_path.chmod(0o600)
            data, _ = _read_private_input(str(input_path))
            events = _parse_lines(data, "application")
            stages = {name: [] for name in ("analysis_preparation", "json_serialization", "file_fsync", "audit_write", "whole_export")}
            output_bytes = 0
            for iteration in range(WARMUPS + SAMPLES):
                start = time.perf_counter()
                report = _build_report("application", events)
                elapsed = time.perf_counter() - start
                if iteration >= WARMUPS:
                    stages["analysis_preparation"].append(elapsed)

                start = time.perf_counter()
                payload = _canonical_json(report) + b"\n"
                elapsed = time.perf_counter() - start
                output_bytes = len(payload)
                if iteration >= WARMUPS:
                    stages["json_serialization"].append(elapsed)

                publish_dir = root / f"publish-{count}-{iteration}"
                publish_dir.mkdir(mode=0o700)
                publish_dir.chmod(0o700)
                dir_fd = _open_private_directory(publish_dir)
                try:
                    start = time.perf_counter()
                    _atomic_publish(dir_fd, "report.json", payload)
                    elapsed = time.perf_counter() - start
                    if iteration >= WARMUPS:
                        stages["file_fsync"].append(elapsed)
                    start = time.perf_counter()
                    _audit_append(dir_fd, {
                        "status": "success", "occurred_at": "2026-01-01T00:00:00+00:00",
                        "schema_version": "restricted-investigation-report/v1",
                        "source_role": "application", "report_id": "0" * 32,
                        "identifier_counts": {"account": 0, "ipv4": 0, "ipv6": 0, "hostname": 0},
                        "case_count": 0, "relation_count": 0, "observation_count": count,
                    })
                    elapsed = time.perf_counter() - start
                    if iteration >= WARMUPS:
                        stages["audit_write"].append(elapsed)
                finally:
                    os.close(dir_fd)

                whole_dir = root / f"whole-{count}-{iteration}"
                whole_dir.mkdir(mode=0o700)
                whole_dir.chmod(0o700)
                whole_input = whole_dir / "input.log"
                whole_input.write_bytes(input_path.read_bytes())
                whole_input.chmod(0o600)
                with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    start = time.perf_counter()
                    _report, _size, _digest = export_report(
                        "application", str(whole_input), str(whole_dir / "result.json"),
                        approval_reader=lambda: APPROVAL,
                    )
                    elapsed = time.perf_counter() - start
                if iteration >= WARMUPS:
                    stages["whole_export"].append(elapsed)
            results[str(count)] = {
                "event_count": count,
                "output_bytes": output_bytes,
                "peak_rss_platform_units": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
                "stages": {name: _stats(values) for name, values in stages.items()},
            }
    return {
        "benchmark": "synthetic restricted analyst report",
        "warmups": WARMUPS,
        "samples": SAMPLES,
        "operational_sla": False,
        "peak_rss_platform_units_note": "ru_maxrss units vary by operating system; this is process high-water observation, not an isolated per-case peak.",
        "results": results,
    }


if __name__ == "__main__":
    print(json.dumps(run_benchmark(), sort_keys=True, separators=(",", ":")))
