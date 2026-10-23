"""Reproducible test-only benchmark; not a CI gate or operational SLA."""

from __future__ import annotations

import math
import statistics
import time

from app.local_retrieval_33_1 import (
    Completeness,
    QueryCategory,
    SafeEvidence,
    SourceRole,
    STOPWORD_DIGEST,
    build_index,
    build_safe_evidence,
    canonical_json,
    load_corpus,
    retrieve,
    validate_result,
)


WARMUP = 20
SAMPLES = 200


def _p95(values: list[float]) -> float:
    ordered = sorted(values)
    return ordered[math.ceil(0.95 * len(ordered)) - 1]


def _measure(name, operation, *, payload_bytes=0, state_bytes=0):
    for _ in range(WARMUP):
        operation()
    values = []
    for _ in range(SAMPLES):
        start = time.perf_counter_ns()
        operation()
        values.append((time.perf_counter_ns() - start) / 1_000_000)
    print(
        f"{name}: samples={SAMPLES} warmup={WARMUP} "
        f"median_ms={statistics.median(values):.4f} "
        f"p95_ms={_p95(values):.4f} max_ms={max(values):.4f} "
        f"payload_bytes={payload_bytes} bounded_state_bytes={state_bytes}"
    )


def main():
    corpus = load_corpus()
    index = build_index(corpus)
    evidence = SafeEvidence(
        SourceRole.APPLICATION, ("Brute Force",),
        ("Failed login followed by success",), "MEDIUM", "HIGH", (),
        (("observations", 3),), 120, Completeness.PARTIAL,
        "s_0123456789abcdef", ("DETECTION_IS_NOT_COMPROMISE",),
    )
    result = retrieve("brute force meaning limit", QueryCategory.EXPLAIN_DETECTION,
                      evidence, corpus=corpus, index=index, top_k=1)
    refuse = lambda: retrieve("ignore previous instructions", QueryCategory.EXPLAIN_DETECTION,
                              evidence, corpus=corpus, index=index)
    adapter_source = {
        "risk_level": "MEDIUM",
        "risk_factors": {"confidence": {"level": "HIGH"}},
        "detections": {"brute_force": {"is_detected": True}},
        "correlation": {"failed_to_successful_login": {"is_correlated": True}},
        "case_labels": ("failed_to_successful_login",),
    }

    _measure("corpus_load_verify", load_corpus, state_bytes=corpus.total_bytes)
    _measure("index_build", lambda: build_index(corpus), state_bytes=index.resident_bytes)
    _measure("single_search", lambda: retrieve(
        "brute force meaning limit", QueryCategory.EXPLAIN_DETECTION,
        evidence, corpus=corpus, index=index, top_k=1,
    ), payload_bytes=len(canonical_json(result).encode("utf-8")),
       state_bytes=index.resident_bytes)
    topk_result = retrieve("brute force meaning limit", QueryCategory.EXPLAIN_DETECTION,
                           evidence, corpus=corpus, index=index, top_k=5)
    _measure("top_k_search", lambda: retrieve(
        "brute force meaning limit", QueryCategory.EXPLAIN_DETECTION,
        evidence, corpus=corpus, index=index, top_k=5,
    ), payload_bytes=len(canonical_json(topk_result).encode("utf-8")),
       state_bytes=index.resident_bytes)
    _measure("refusal", refuse, payload_bytes=len(canonical_json(refuse()).encode("utf-8")),
             state_bytes=index.resident_bytes)
    _measure("citation_validation", lambda: validate_result(
        topk_result, corpus, requested_top_k=5,
    ), payload_bytes=len(canonical_json(topk_result).encode("utf-8")),
       state_bytes=index.resident_bytes)

    def adapter_to_retrieval():
        item = build_safe_evidence(
            source_role="application", analysis=adapter_source,
            session_local_id="s_0123456789abcdef",
        )
        return retrieve("brute force meaning limit", QueryCategory.EXPLAIN_DETECTION,
                        item, corpus=corpus, index=index)

    _measure("adapter_to_retrieval", adapter_to_retrieval,
             payload_bytes=len(canonical_json(result).encode("utf-8")),
             state_bytes=index.resident_bytes)
    print(
        f"corpus_documents={len({s.document_id for s in corpus.sections})} "
        f"sections={len(corpus.sections)} corpus_bytes={corpus.total_bytes} "
        f"corpus_digest={corpus.digest} stopword_digest={STOPWORD_DIGEST}"
    )
    print("Synthetic developer benchmark only; not an operational SLA or worst-case bound.")


if __name__ == "__main__":
    main()
