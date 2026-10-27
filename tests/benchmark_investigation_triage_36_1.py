"""Small synthetic benchmark. Results are development observations, not an SLA."""

from __future__ import annotations

import json
import statistics
import time

from app.investigation_triage_36_1 import (
    CORPUS_DIGEST,
    SafeInvestigationDTO,
    _priority,
    _validate_verified_ids,
    build_investigation_assistance,
    create_safe_investigation_dto,
    validate_assistance_json,
)
from app.local_retrieval_33_1 import build_index, load_corpus


SAMPLES = 100
WARMUP = 10
BASE = {
    "schema_version": 1,
    "request_id": "r_0123456789abcdef01234567",
    "case_ref": "c_fedcba9876543210fedcba98",
    "source_role": "application",
    "observation_categories": ("authentication",),
    "detection_codes": ("brute_force",),
    "relation_codes": (),
    "risk_band": "LOW",
    "case_status": "open",
    "event_count_bucket": "2_5",
    "time_window_bucket": "5_60m",
    "evidence_completeness": "complete",
    "limitation_codes": ("DETECTION_IS_NOT_COMPROMISE",),
    "corpus_digest": CORPUS_DIGEST,
}


def _measure(fn):
    for _ in range(WARMUP):
        fn()
    values = []
    for _ in range(SAMPLES):
        start = time.perf_counter_ns()
        fn()
        values.append((time.perf_counter_ns() - start) / 1_000_000)
    ordered = sorted(values)
    return {
        "samples": len(values),
        "median_ms": round(statistics.median(values), 4),
        "p95_ms": round(ordered[94], 4),
        "max_ms": round(max(values), 4),
    }


def main() -> int:
    item = create_safe_investigation_dto(**BASE)
    output = build_investigation_assistance(item).to_json()
    corpus = load_corpus()
    index = build_index(corpus)
    scenarios = {
        "dto_validation": lambda: SafeInvestigationDTO.from_mapping(item.to_mapping()),
        "priority": lambda: _priority(item),
        "lexical_retrieval_and_dto": lambda: create_safe_investigation_dto(**BASE),
        "citation_validation": lambda: _validate_verified_ids(item.to_mapping()),
        "output_validation": lambda: validate_assistance_json(output, item),
        "full_triage": lambda: build_investigation_assistance(item),
    }
    result = {
        "synthetic_only": True,
        "model_used": False,
        "warmup": WARMUP,
        "input_bytes": len(json.dumps(BASE, ensure_ascii=False, separators=(",", ":")).encode("utf-8")),
        "output_bytes": len(output.encode("utf-8")),
        "corpus_index_resident_bytes": index.resident_bytes,
        "measurements": {name: _measure(fn) for name, fn in scenarios.items()},
        "interpretation": "small development measurements; not an operational SLA",
    }
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
