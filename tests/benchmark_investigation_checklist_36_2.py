"""Small synthetic microbenchmark; results are not an operational SLA."""

from __future__ import annotations

import json
import statistics
import time

from app.investigation_checklist_36_2 import (
    _categories,
    _verified_ids,
    build_investigation_checklist,
    validate_checklist_json,
)
from app.investigation_triage_36_1 import (
    _safe_evidence,
    build_investigation_assistance,
)
from app.local_retrieval_33_1 import (
    QueryCategory,
    build_index,
    load_corpus,
    retrieve,
    validate_result,
)
from tests.evaluate_investigation_checklist_36_2 import _dto


def _measure(operation, *, warmup: int = 10, samples: int = 100) -> dict:
    for _ in range(warmup):
        operation()
    values = []
    for _ in range(samples):
        start = time.perf_counter_ns()
        operation()
        values.append((time.perf_counter_ns() - start) / 1_000_000)
    ordered = sorted(values)
    return {
        "median_ms": round(statistics.median(values), 6),
        "p95_ms": round(ordered[int((len(ordered) - 1) * 0.95)], 6),
        "max_ms": round(max(values), 6),
        "samples": samples,
    }


def run() -> dict:
    item = _dto("brute_force")
    corpus = load_corpus()
    index = build_index(corpus)
    evidence = _safe_evidence(item.to_mapping())
    output = build_investigation_checklist(item)
    serialized = output.to_json()
    input_bytes = len(json.dumps(item.to_mapping(), separators=(",", ":")).encode("utf-8"))
    output_bytes = len(serialized.encode("utf-8"))
    queries = {
        "corpus_load_verify": load_corpus,
        "lexical_search": lambda: validate_result(
            retrieve("brute force meaning limit", QueryCategory.EXPLAIN_DETECTION,
                     evidence, corpus=corpus, index=index, top_k=5),
            corpus, requested_top_k=5,
        ),
        "semantic_checklist_selection": lambda: _categories(item),
        "citation_validation": lambda: _verified_ids(item, _categories(item), corpus),
        "output_validation": lambda: validate_checklist_json(serialized, item),
        "full_checklist": lambda: build_investigation_checklist(item),
    }
    return {
        "warmup": 10,
        "sample_count": 100,
        "input_bytes": input_bytes,
        "output_bytes": output_bytes,
        "corpus_sections": len(corpus.sections),
        "resident_index_estimate_bytes": index.resident_bytes,
        "operations": {name: _measure(operation) for name, operation in queries.items()},
        "sla": False,
    }


def main() -> None:
    print("INVESTIGATION_CHECKLIST_BENCHMARK " + json.dumps(run(), sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
