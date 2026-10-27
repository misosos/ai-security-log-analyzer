"""Small local development benchmark; it is not an operational SLA."""

import hashlib
import json
import statistics
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient

import app.investigation_checklist_api_36_3 as checklist_api
from app.api import create_app
from app.investigation_checklist_36_2 import build_investigation_checklist, validate_checklist_json
from app.investigation_triage_36_1 import CORPUS_DIGEST, create_safe_investigation_dto
from app.local_retrieval_33_1 import load_corpus


def _summary(samples):
    ordered = sorted(samples)
    return {
        "samples": len(ordered),
        "median_ms": round(statistics.median(ordered), 3),
        "p95_ms": round(ordered[min(len(ordered) - 1, int(len(ordered) * .95))], 3),
        "max_ms": round(ordered[-1], 3),
    }


def main():
    checklist_api.GLOBAL_RATE_LIMIT = 512
    checklist_api.CASE_RATE_LIMIT = 512
    values = dict(
        schema_version=1, request_id="r_0123456789abcdef01234567",
        case_ref="c_1123456789abcdef01234567", source_role="unknown",
        observation_categories=("authentication",), detection_codes=("brute_force",),
        relation_codes=(), risk_band="HIGH", case_status="open", event_count_bucket="2_5",
        time_window_bucket="unknown", evidence_completeness="complete",
        limitation_codes=("DETECTION_IS_NOT_COMPROMISE",), corpus_digest=CORPUS_DIGEST,
    )
    item = create_safe_investigation_dto(**values)
    corpus = load_corpus()
    result = build_investigation_checklist(item)
    encoded = result.to_json()
    sizes = {"input_bytes": len(json.dumps({"schema_version": 1, "case_ref": values["case_ref"]}).encode()),
             "internal_output_bytes": len(encoded.encode()), "corpus_bytes": corpus.total_bytes}

    measures = {name: [] for name in ("corpus_load", "retrieval", "checklist", "validation", "endpoint")}
    for _ in range(10):
        load_corpus()
        create_safe_investigation_dto(**values)
        built = build_investigation_checklist(item)
        validate_checklist_json(built.to_json(), item)

    corpus_times = []
    retrieval_times = []
    checklist_times = []
    validation_times = []
    for _ in range(100):
        start = time.perf_counter(); load_corpus(); corpus_times.append((time.perf_counter() - start) * 1000)
        start = time.perf_counter(); create_safe_investigation_dto(**values); retrieval_times.append((time.perf_counter() - start) * 1000)
        start = time.perf_counter(); built = build_investigation_checklist(item); checklist_times.append((time.perf_counter() - start) * 1000)
        start = time.perf_counter(); validate_checklist_json(built.to_json(), item); validation_times.append((time.perf_counter() - start) * 1000)

    client = TestClient(create_app(), base_url="http://127.0.0.1", client=("127.0.0.1", 12345))
    initial = client.post("/api/v1/investigations/sample")
    case_ref = initial.json()["cases"][0]["checklist_ref"]
    request = json.dumps({"schema_version": 1, "case_ref": case_ref}, separators=(",", ":")).encode()
    output_bytes = None
    canonical = None
    for _ in range(10):
        response = client.post("/api/v1/investigations/checklist", content=request,
                               headers={"content-type": "application/json"})
        if response.status_code != 200:
            raise RuntimeError("benchmark endpoint did not return a bounded result")
    endpoint_times = []
    digests = []
    for _ in range(100):
        start = time.perf_counter()
        response = client.post("/api/v1/investigations/checklist", content=request,
                               headers={"content-type": "application/json"})
        endpoint_times.append((time.perf_counter() - start) * 1000)
        if response.status_code != 200:
            raise RuntimeError("benchmark endpoint did not return a bounded result")
        output_bytes = len(response.content)
        canonical = json.dumps(response.json(), ensure_ascii=False, sort_keys=True,
                               separators=(",", ":"), allow_nan=False).encode()
        digests.append(hashlib.sha256(canonical).hexdigest())
    if len(set(digests)) != 1:
        raise RuntimeError("canonical response changed across identical requests")
    sizes["request_bytes"] = len(request)
    sizes["response_bytes"] = output_bytes
    report = {
        "corpus_load": _summary(corpus_times), "lexical_retrieval_and_dto": _summary(retrieval_times),
        "checklist_generation": _summary(checklist_times), "output_validation": _summary(validation_times),
        "endpoint_total": _summary(endpoint_times), "bytes": sizes,
        "canonical_sha256": digests[0], "result_status": result.status,
        "measurement": "small synthetic development sample; not an operational SLA",
    }
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
