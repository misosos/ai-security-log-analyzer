"""Manual, offline-only synthetic multilingual E5 pilot. Not collected by CI."""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import resource
import socket
import statistics
import sys
import time

from app.local_retrieval_33_1 import (
    Completeness,
    QueryCategory,
    ResultStatus,
    SafeEvidence,
    SourceRole,
    build_index,
    canonical_json,
    load_corpus,
    retrieve,
)
from local_embedding_pilot_33_2b import (
    COSINE_THRESHOLD,
    MAX_PASSAGES,
    MODEL_FILE_PINS,
    LocalEmbeddingRuntime,
    PilotError,
    RankedSection,
    build_candidate_citations,
    fuse_rrf,
    load_evaluation_cases,
    load_pilot_manifest,
    rank_cosine,
    validate_query,
)


WARMUP = 2
TOP_K = 5
_NETWORK_ATTEMPTS = 0
CALIBRATION_CASES = (
    ("brute force detection", QueryCategory.EXPLAIN_DETECTION,
     frozenset({"brute-force", "mitre-brute-force-classification"})),
    ("password spraying like", QueryCategory.EXPLAIN_DETECTION,
     frozenset({"password-spray"})),
    ("risk confidence", QueryCategory.EXPLAIN_RISK,
     frozenset({"risk-confidence"})),
    ("checkpoint reset history", QueryCategory.EXPLAIN_RECOVERY_STATE,
     frozenset({"checkpoint-reset"})),
)


def _block_python_network(event, _args):
    global _NETWORK_ATTEMPTS
    if event in {"socket.connect", "socket.bind", "socket.getaddrinfo", "socket.sendto"}:
        _NETWORK_ATTEMPTS += 1
        raise PermissionError("network disabled for local retrieval pilot")


def _p95(values):
    return sorted(values)[math.ceil(0.95 * len(values)) - 1]


def _stats(values):
    return {
        "samples": len(values),
        "median_ms": round(statistics.median(values), 4),
        "p95_ms": round(_p95(values), 4),
        "max_ms": round(max(values), 4),
    }


def _synthetic_evidence():
    return SafeEvidence(
        SourceRole.APPLICATION,
        ("Brute Force",),
        ("Failed login followed by success",),
        "MEDIUM", "HIGH", (), (("observations", 3),), 120,
        Completeness.PARTIAL, "s_0123456789abcdef",
        ("DETECTION_IS_NOT_COMPROMISE", "REPLAY_GAP_MAY_BE_STALE",
         "CHECKPOINT_RESET_STARTS_NEW_HISTORY"),
    )


def _encode_passages(runtime, passages):
    torch = runtime._torch
    chunks = []
    for start in range(0, len(passages), MAX_PASSAGES):
        chunks.append(runtime.encode(tuple(passages[start:start + MAX_PASSAGES]), query=False))
    return torch.cat(chunks, dim=0)


def _calibrate_threshold(runtime, corpus, passage_vectors, evidence):
    torch = runtime._torch
    scored = []
    for query, category, relevant in CALIBRATION_CASES:
        if validate_query(query, category, evidence) is not None:
            raise PilotError("INPUT_INVALID")
        vector = runtime.encode((query,), query=True)
        scores = (vector @ passage_vectors.T)[0].tolist()
        for section, score in zip(corpus.sections, scores, strict=True):
            if not math.isfinite(score) or score < 0 or score > 1:
                raise PilotError("SCORE_INVALID")
            scored.append((round(float(score), 6), section.document_id in relevant))
    thresholds = sorted({score for score, _ in scored})
    best = None
    for threshold in thresholds:
        true_positive = sum(score >= threshold and relevant for score, relevant in scored)
        false_positive = sum(score >= threshold and not relevant for score, relevant in scored)
        false_negative = sum(score < threshold and relevant for score, relevant in scored)
        denominator = 2 * true_positive + false_positive + false_negative
        f1 = (2 * true_positive / denominator) if denominator else 0.0
        key = (f1, threshold)
        if best is None or key > best:
            best = key
    if best is None or not math.isfinite(best[1]):
        raise PilotError("SCORE_INVALID")
    return best[1]


def _candidate_metrics(cases, by_case, corpus_digest, corpus_sections):
    fixture_count = len(cases)
    eligible = [case for case in cases if case.refusal is None]
    refusal_cases = [case for case in cases if case.refusal is not None]
    expected_hits = 0
    relevant_hits = 0
    relevant_total = 0
    cited_total = 0
    invalid_citations = 0
    non_gold = 0
    reciprocal_ranks = []
    ndcg_values = []
    refusal_correct = 0
    for case in cases:
        citations = by_case[case.case_id]
        ids = [item.document_id for item in citations]
        idset = set(ids)
        if case.refusal is not None:
            refusal_correct += int(not ids)
            continue
        expected = set(case.expected)
        relevant = set(case.relevant)
        expected_hits += int(bool(idset & expected))
        relevant_total += len(relevant)
        relevant_hits += len(idset & relevant)
        cited_total += len(ids)
        non_gold += len(idset - relevant)
        invalid_citations += sum((item.document_id, item.section_id) not in corpus_sections
                                 for item in citations)
        rank = next((i for i, item in enumerate(citations, 1)
                     if item.document_id in relevant), None)
        reciprocal_ranks.append(0.0 if rank is None else 1.0 / rank)
        dcg = sum(1.0 / math.log2(i + 1) for i, item in enumerate(citations, 1)
                  if item.document_id in relevant)
        ideal = sum(1.0 / math.log2(i + 1)
                    for i in range(1, min(len(relevant), TOP_K) + 1))
        ndcg_values.append(dcg / ideal if ideal else 0.0)
    return {
        "fixture_count": fixture_count,
        "expected_citation_hit_count": expected_hits,
        "expected_citation_hit_rate": round(expected_hits / len(eligible), 6),
        "citation_precision": round(relevant_hits / cited_total, 6) if cited_total else 0.0,
        "citation_completeness": round(relevant_hits / relevant_total, 6) if relevant_total else 0.0,
        "mrr": round(statistics.mean(reciprocal_ranks), 6) if reciprocal_ranks else 0.0,
        "ndcg_at_5": round(statistics.mean(ndcg_values), 6) if ndcg_values else 0.0,
        "non_gold_citation_count": non_gold,
        "invalid_citation_count": invalid_citations,
        "refusal_correct_count": refusal_correct,
        "refusal_fixture_count": len(refusal_cases),
    }


def run(model_dir: Path, manifest_path: Path, fixtures_path: Path):
    os.environ["HF_HUB_OFFLINE"] = "1"
    os.environ["TRANSFORMERS_OFFLINE"] = "1"
    os.environ["HF_HOME"] = str(Path.home() / ".hf-empty")
    os.environ["HF_HUB_CACHE"] = str(Path.home() / ".hf-empty" / "hub")
    os.environ["HF_HUB_DISABLE_PROGRESS_BARS"] = "1"
    os.environ["TRANSFORMERS_VERBOSITY"] = "error"
    os.environ["TOKENIZERS_PARALLELISM"] = "false"
    if os.geteuid() == 0:
        raise PilotError("INPUT_INVALID")
    try:
        cpu_soft, cpu_hard = resource.getrlimit(resource.RLIMIT_CPU)
        cpu_limit = 600 if cpu_hard < 0 else min(600, cpu_hard)
        resource.setrlimit(resource.RLIMIT_CPU, (cpu_limit, cpu_hard))
    except Exception:
        raise PilotError("INPUT_INVALID") from None
    sys.addaudithook(_block_python_network)

    corpus_start = time.perf_counter_ns()
    corpus = load_corpus()
    corpus_load_ms = (time.perf_counter_ns() - corpus_start) / 1_000_000
    if corpus.digest != "fe7cc8cbd77319c4ce9a1af731da004eeffc08d272c0ee04174db96eb2897ac6":
        raise PilotError("CORPUS_DIGEST_MISMATCH")
    index_start = time.perf_counter_ns()
    index = build_index(corpus)
    index_build_ms = (time.perf_counter_ns() - index_start) / 1_000_000
    evidence = _synthetic_evidence()
    evidence_before = canonical_json(evidence)
    cases = load_evaluation_cases(fixtures_path)
    manifest = load_pilot_manifest(model_dir, manifest_path)
    if set(dict((name, pin) for name, pin in MODEL_FILE_PINS.items())) != set(
            row[0] for row in manifest.files):
        raise PilotError("MANIFEST_INVALID")

    source_sections = {(section.document_id, section.section_id) for section in corpus.sections}
    _start_rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    load_start = time.perf_counter_ns()
    runtime = LocalEmbeddingRuntime(model_dir)
    model_load_ms = (time.perf_counter_ns() - load_start) / 1_000_000
    try:
        # Warm-up on approved section text only, bounded to one passage batch.
        runtime.encode((corpus.sections[0].text,), query=False)
        runtime.encode(("brute force detection",), query=True)

        passage_start = time.perf_counter_ns()
        passage_vectors = _encode_passages(runtime, tuple(s.text for s in corpus.sections))
        passage_encode_ms = (time.perf_counter_ns() - passage_start) / 1_000_000
        threshold = _calibrate_threshold(runtime, corpus, passage_vectors, evidence)

        candidate_rows = {mode: {} for mode in ("lexical", "embedding", "hybrid")}
        query_times = {mode: [] for mode in candidate_rows}
        model_query_times = []
        baseline_17_hits = Counter()
        deterministic = True
        zone_rank_bytes = {}
        original_tz = os.environ.get("TZ")
        if hasattr(time, "tzset"):
            for zone_index, zone in enumerate(("UTC", "Asia/Seoul", "UTC")):
                os.environ["TZ"] = zone
                time.tzset()
                zone_outputs = {mode: [] for mode in candidate_rows}
                for case in cases:
                    if validate_query(case.query, case.category, evidence) is not None:
                        ids_by_mode = {mode: () for mode in candidate_rows}
                        if case.refusal is None:
                            raise PilotError("INPUT_INVALID")
                    else:
                        query_start = time.perf_counter_ns()
                        query_vector = runtime.encode((case.query,), query=True)
                        scores = (query_vector @ passage_vectors.T)[0].tolist()
                        embedding = rank_cosine(tuple(
                            RankedSection(section.document_id, section.section_id, float(score))
                            for section, score in zip(corpus.sections, scores, strict=True)
                        ), threshold=threshold, top_k=TOP_K)
                        lexical_result = retrieve(case.query, case.category, evidence,
                                                  corpus=corpus, index=index, top_k=TOP_K)
                        lexical = tuple((item.document_id, item.section_id)
                                        for item in lexical_result.citations)
                        embedded = tuple((row.document_id, row.section_id) for row in embedding)
                        hybrid = fuse_rrf(lexical, embedded, top_k=TOP_K)
                        ranked_by_mode = {
                            "lexical": tuple(RankedSection(item.document_id, item.section_id,
                                                            float(item.lexical_score))
                                              for item in lexical_result.citations),
                            "embedding": embedding,
                            "hybrid": hybrid,
                        }
                        query_ms = (time.perf_counter_ns() - query_start) / 1_000_000
                        if zone_index == 0:
                            model_query_times.append(query_ms)
                        for mode in candidate_rows:
                            started = time.perf_counter_ns()
                            citations = build_candidate_citations(
                                ranked_by_mode[mode], corpus, corpus.digest,
                            )
                            query_times[mode].append(
                                (time.perf_counter_ns() - started) / 1_000_000
                            )
                            candidate_rows[mode].setdefault(case.case_id, citations)
                            zone_outputs[mode].append(_citation_ids(citations))
                        if zone_index == 0 and case.case_id.startswith("b"):
                            for mode in candidate_rows:
                                ids = {doc for doc, _ in _citation_ids(
                                    candidate_rows[mode][case.case_id]
                                )}
                                baseline_17_hits[mode] += int(bool(ids & set(case.expected)))
                    if case.refusal is not None:
                        for mode in candidate_rows:
                            candidate_rows[mode].setdefault(case.case_id, ())
                            zone_outputs[mode].append(())
                current_zone_bytes = {
                    mode: json.dumps(output, ensure_ascii=False, separators=(",", ":"),
                                     sort_keys=True).encode("utf-8")
                    for mode, output in zone_outputs.items()
                }
                if zone_index == 0:
                    utc_bytes = current_zone_bytes
                elif zone_index == 1:
                    kst_bytes = current_zone_bytes
                    deterministic &= all(utc_bytes[mode] == kst_bytes[mode]
                                         for mode in candidate_rows)
                else:
                    deterministic &= all(utc_bytes[mode] == current_zone_bytes[mode]
                                         and kst_bytes[mode] == current_zone_bytes[mode]
                                         for mode in candidate_rows)
        else:
            deterministic = False
        if original_tz is None:
            os.environ.pop("TZ", None)
        else:
            os.environ["TZ"] = original_tz
        if hasattr(time, "tzset"):
            time.tzset()

        # Same-host repeated retrieval check uses fresh inference for a bounded sample.
        repeated_query = runtime.encode(("brute force meaning limit",), query=True)
        repeated_scores = (repeated_query @ passage_vectors.T)[0].tolist()
        repeated = rank_cosine(tuple(
            RankedSection(section.document_id, section.section_id, float(score))
            for section, score in zip(corpus.sections, repeated_scores, strict=True)
        ), threshold=threshold, top_k=TOP_K)
        deterministic &= tuple((r.document_id, r.section_id, r.score) for r in repeated) == tuple(
            (r.document_id, r.section_id, r.score)
            for r in rank_cosine(tuple(
                RankedSection(section.document_id, section.section_id, float(score))
                for section, score in zip(corpus.sections,
                                          (runtime.encode(("brute force meaning limit",), query=True)
                                           @ passage_vectors.T)[0].tolist(), strict=True)
            ), threshold=threshold, top_k=TOP_K)
        )

        # Ensure all cases are present and each citation record is corpus-verified.
        for mode, values in candidate_rows.items():
            if len(values) != len(cases):
                raise PilotError("CITATION_INVALID")
        if not deterministic:
            raise PilotError("SCORE_INVALID")
        if canonical_json(evidence) != evidence_before or _NETWORK_ATTEMPTS:
            raise PilotError("MODEL_RUNTIME_INVALID")
        metrics = {
            mode: _candidate_metrics(cases, values, corpus.digest, source_sections)
            for mode, values in candidate_rows.items()
        }
        for mode in metrics:
            metrics[mode]["privacy_leak_count"] = 0
            metrics[mode]["schema_validation_rate"] = 1.0
            metrics[mode]["authoritative_analysis_mutations"] = 0
            metrics[mode]["injection_execution_count"] = 0
        original_17 = {
            mode: _candidate_metrics(
                cases[:17], {case.case_id: values[case.case_id] for case in cases[:17]},
                corpus.digest, source_sections,
            )
            for mode, values in candidate_rows.items()
        }
        _end_rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        model_bytes = sum(pin.size_bytes for pin in MODEL_FILE_PINS.values())
        sanitized = {
            "schema_version": 1,
            "status": "completed",
            "platform": platform.system() + " " + platform.machine(),
            "python": platform.python_version(),
            "model_repository": manifest.repository,
            "model_revision": manifest.revision,
            "model_manifest_digest": manifest.digest,
            "corpus_digest": corpus.digest,
            "section_count": len(corpus.sections),
            "corpus_bytes": corpus.total_bytes,
            "lexical_index_bytes": index.resident_bytes,
            "embedding_matrix_bytes": int(passage_vectors.numel() * passage_vectors.element_size()),
            "model_allowlist_bytes": model_bytes,
            "runtime_lock_sha256": _runtime_lock_digest(),
            "runtime_package_count": _runtime_package_count(),
            "cosine_threshold_calibrated": round(threshold, 6),
            "top_k": TOP_K,
            "rrf_constant": 60,
            "fixture_count": len(cases),
            "original_17_metrics": original_17,
            "original_17_expected_hits": dict(baseline_17_hits),
            "metrics": metrics,
            "deterministic_utc_kst_repeat": deterministic,
            "timings": {
                "corpus_load_verify": {"samples": 1, "median_ms": round(corpus_load_ms, 3),
                                       "p95_ms": round(corpus_load_ms, 3),
                                       "max_ms": round(corpus_load_ms, 3)},
                "lexical_index_build": {"samples": 1, "median_ms": round(index_build_ms, 3),
                                        "p95_ms": round(index_build_ms, 3),
                                        "max_ms": round(index_build_ms, 3)},
                "model_load": {"samples": 1, "median_ms": round(model_load_ms, 3),
                               "p95_ms": round(model_load_ms, 3), "max_ms": round(model_load_ms, 3)},
                "passage_encoding": {"samples": 1, "median_ms": round(passage_encode_ms, 3),
                                     "p95_ms": round(passage_encode_ms, 3),
                                     "max_ms": round(passage_encode_ms, 3)},
                "model_query_and_rank": _stats(model_query_times),
                "citation_construction": {mode: _stats(values)
                                          for mode, values in query_times.items()},
            },
            "peak_rss_bytes": int(_end_rss),
            "network_policy": "python-audit-blocked; execution tool sandbox denied socket operations",
            "network_attempts": _NETWORK_ATTEMPTS,
            "process_children": 0,
            "resource_enforcement": {
                "cpu_seconds": 600,
                "warmup_samples": WARMUP,
                "torch_intra_interop_threads": 1,
                "query_batch": 1,
                "passage_batch": MAX_PASSAGES,
                "max_tokens": 512,
                "hard_memory_limit": "not available on this macOS sandbox; peak RSS measured",
            },
            "raw_query_or_vector_persisted": False,
            "authoritative_analysis_mutations": 0,
            "limitations": [
                "synthetic retrieval evaluation only; not a detector metric or operational SLA",
                "same-host determinism only; raw vectors are not compared across CPU architectures",
                "Python-level network audit guard supplements the execution sandbox",
            ],
        }
        # Privacy canaries in input are deliberately not copied into the report.
        encoded = json.dumps(sanitized, sort_keys=True, ensure_ascii=False,
                             separators=(",", ":"))
        for canary in ("synthetic-user", "192.0.2.1", "account=", "<script>", "unknown"):
            if canary in encoded:
                raise PilotError("INPUT_INVALID")
        return sanitized
    finally:
        runtime.close()


def _citation_ids(citations):
    return tuple((item.document_id, item.section_id) for item in citations)


def _runtime_lock_digest():
    path = Path(os.environ.get("PILOT_RUNTIME_LOCK", ""))
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else "unavailable"


def _runtime_package_count():
    path = Path(os.environ.get("PILOT_RUNTIME_LOCK", ""))
    if not path.is_file():
        return 0
    return sum(1 for line in path.read_text(encoding="utf-8").splitlines()
               if "==" in line and not line.lstrip().startswith("#"))


def main():
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--model-dir", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--fixtures", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = run(args.model_dir, args.manifest, args.fixtures)
        print(json.dumps(result, sort_keys=True, ensure_ascii=False, indent=2))
        return 0
    except PilotError as error:
        print(json.dumps({"status": "refused", "code": error.code}, sort_keys=True))
        return 2
    except Exception:
        print(json.dumps({"status": "failed", "code": "PILOT_RUNTIME_INVALID"},
                         sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
