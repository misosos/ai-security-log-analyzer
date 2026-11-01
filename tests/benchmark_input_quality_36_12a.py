"""Offline synthetic microbenchmark for Phase 36.12A input-quality summaries."""

import json
from pathlib import Path
import statistics
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.input_quality_36_12a import aggregate_input_quality, evaluate_source_text


APP = "2026-11-01 10:30:12 INFO login_failed user=synthetic"
SSH = "2026-11-01 10:30:12 sshd Failed password for u from 192.0.2.1 port 22 ssh2"
ACCESS = (
    '192.0.2.2 - - [01/Nov/2026:10:30:12 +0000] '
    '"GET / HTTP/1.1" 200 1 "-" "synthetic"'
)
SAMPLES = 25
WARMUPS = 3


def _measure(operation, input_bytes):
    for _ in range(WARMUPS):
        operation()
    values = []
    for _ in range(SAMPLES):
        start = time.perf_counter_ns()
        operation()
        values.append((time.perf_counter_ns() - start) / 1_000_000)
    ordered = sorted(values)
    p95 = ordered[min(len(ordered) - 1, int(0.95 * (len(ordered) - 1)))]
    return {
        "samples": SAMPLES,
        "input_bytes": input_bytes,
        "median_ms": round(statistics.median(values), 3),
        "p95_ms": round(p95, 3),
        "max_ms": round(max(values), 3),
    }


def main():
    accepted = (APP + "\n") * 511 + APP
    rejected = ("not-a-log\n") * 511 + "not-a-log"
    mixed = (APP + "\nnot-a-log\n") * 255 + APP
    three_sources = {
        "application": (APP + "\n") * 169 + APP,
        "ssh": (SSH + "\n") * 169 + SSH,
        "access": (ACCESS + "\n") * 169 + ACCESS,
    }

    def aggregate_all():
        summaries = {
            source: evaluate_source_text(source, text)
            for source, text in three_sources.items()
        }
        aggregate_input_quality(summaries)

    results = {
        "synthetic_only": True,
        "operational_sla": False,
        "warmups": WARMUPS,
        "scenarios": {
            "512_recognized": _measure(
                lambda: evaluate_source_text("application", accepted),
                len(accepted.encode("utf-8")),
            ),
            "512_unrecognized": _measure(
                lambda: evaluate_source_text("application", rejected),
                len(rejected.encode("utf-8")),
            ),
            "512_mixed": _measure(
                lambda: evaluate_source_text("application", mixed),
                len(mixed.encode("utf-8")),
            ),
            "three_source_aggregate": _measure(
                aggregate_all,
                sum(len(text.encode("utf-8")) for text in three_sources.values()),
            ),
        },
    }
    print(json.dumps(results, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
