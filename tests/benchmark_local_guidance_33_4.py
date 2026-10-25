"""Synthetic-only microbenchmarks for Phase 33.4; not an operational SLA."""

from __future__ import annotations

import json
import hashlib
from pathlib import Path
import statistics
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient

import app.api as api
from app.local_guidance_33_4 import (
    GuidanceRequest, TRUSTED_CORPUS_DIGEST, _evidence,
    _query_for,
)
from app.local_retrieval_33_1 import (
    build_index, load_corpus,
    retrieve, validate_result,
)


SAMPLES = 30
WARMUP = 5


def stats(values: list[float]) -> dict[str, float | int]:
    ordered = sorted(values)
    return {
        "samples": len(values),
        "median_ms": round(statistics.median(values), 3),
        "p95_ms": round(ordered[max(0, int(len(ordered) * .95 + .999) - 1)], 3),
        "max_ms": round(max(values), 3),
    }


def measure(function, *, samples: int = SAMPLES) -> tuple[dict, object]:
    value = None
    for _ in range(WARMUP):
        value = function()
    values = []
    for _ in range(samples):
        started = time.perf_counter_ns()
        value = function()
        values.append((time.perf_counter_ns() - started) / 1_000_000)
    return stats(values), value


def main() -> None:
    safe_fields = {
        "review_order": 1,
        "supported_detections": ["Brute Force"],
        "supported_relations": ["Failed Login → Successful Login"],
        "risk_level": "MEDIUM",
        "confidence": "HIGH",
        "observation_count": 3,
        "supporting_relation_count": 1,
    }
    case_id = "c_" + hashlib.sha256(
        json.dumps(safe_fields, ensure_ascii=False, sort_keys=True,
                   separators=(",", ":")).encode("utf-8")
    ).hexdigest()[:24]
    case = {"case_id": case_id, **safe_fields}
    request = GuidanceRequest.model_validate({
        "schema_version": 1, "case": case, "category": "EXPLAIN_CASE",
        "corpus_digest": TRUSTED_CORPUS_DIGEST,
    })
    corpus_metrics, corpus = measure(load_corpus)
    index_metrics, index = measure(lambda: build_index(corpus))
    evidence = _evidence(request.case)
    query = _query_for(request.category, request.case)
    result_metrics, result = measure(lambda: retrieve(
        query, request.category, evidence, corpus=corpus, index=index,
    ))
    validation_metrics, _ = measure(lambda: validate_result(
        result, corpus, requested_top_k=3,
    ))
    client = TestClient(api.create_app(), base_url="http://127.0.0.1",
                        client=("127.0.0.1", 12345))
    body = {
        "schema_version": 1, "case": case, "category": "EXPLAIN_CASE",
        "corpus_digest": TRUSTED_CORPUS_DIGEST,
    }
    endpoint_metrics, response = measure(lambda: client.post(
        "/api/v1/investigations/guidance", json=body,
    ), samples=7)
    if response.status_code != 200:
        raise SystemExit("GUIDANCE_BENCHMARK_FAILED")
    response_body = response.json()
    print(json.dumps({
        "purpose": "synthetic development microbenchmark; not an operational SLA",
        "warmup": WARMUP,
        "corpus_sections": len(corpus.sections),
        "corpus_bytes": corpus.total_bytes,
        "lexical_index_resident_bytes": index.resident_bytes,
        "request_payload_bytes": len(json.dumps(body, ensure_ascii=False,
                                                 separators=(",", ":")).encode("utf-8")),
        "response_payload_bytes": len(response.content),
        "citation_count": len(response_body["citations"]),
        "stages": {
            "corpus_load": corpus_metrics,
            "index_build": index_metrics,
            "retrieval": result_metrics,
            "citation_verification": validation_metrics,
            "in_process_endpoint": endpoint_metrics,
        },
    }, ensure_ascii=False, sort_keys=True))
    client.close()


if __name__ == "__main__":
    main()
