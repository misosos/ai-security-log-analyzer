"""Small synthetic timing probe for the verified-role checklist path; not an SLA."""

from __future__ import annotations

import hashlib
import json
import statistics
import time
from datetime import datetime, timezone

from fastapi import FastAPI
from fastapi.testclient import TestClient

import app.api as api_module
import app.investigation_checklist_api_36_3 as checklist_api
import app.investigation_triage_36_1 as triage
from app.analyzer.incident_case_adapter import project_investigation_cases_from_analysis
from app.investigation_checklist_36_2 import build_investigation_checklist
from app.investigation_checklist_api_36_3 import trusted_case_fields_from_projection
from app.investigation_role_snapshot_36_4 import AnalysisSourceRoleSnapshot
from app.main import analyze_with_source_role_snapshot
from app.models.schemas import NormalizedEvent


WARMUPS = 10
SAMPLES = 100


def _measure(function):
    for _ in range(WARMUPS):
        function()
    values = []
    for _ in range(SAMPLES):
        start = time.perf_counter_ns()
        function()
        values.append((time.perf_counter_ns() - start) / 1_000_000)
    ordered = sorted(values)
    return {
        "median_ms": statistics.median(values),
        "p95_ms": ordered[int((len(ordered) - 1) * 0.95)],
        "max_ms": max(values),
    }


def main():
    # Permit the fixed synthetic benchmark loop to exercise the same endpoint repeatedly.
    checklist_api.CASE_RATE_LIMIT = 1_000
    checklist_api.GLOBAL_RATE_LIMIT = 1_000

    captured = []
    base_registry = checklist_api.ChecklistRegistry

    class CapturingRegistry(base_registry):
        def __init__(self):
            super().__init__()
            captured.append(self)

    api_module.ChecklistRegistry = CapturingRegistry
    checklist_api.ChecklistRegistry = CapturingRegistry
    client = TestClient(api_module.create_app(), base_url="http://127.0.0.1",
                        client=("127.0.0.1", 12345))
    sample_response = client.post("/api/v1/investigations/sample")
    sample_response.raise_for_status()
    registry = captured[0]
    case_ref = sample_response.json()["cases"][0]["checklist_ref"]
    stored_values = registry.lookup(case_ref)
    if stored_values is None:
        raise RuntimeError("synthetic registry setup failed")

    analysis_run = analyze_with_source_role_snapshot()
    projection = project_investigation_cases_from_analysis(analysis_run.analysis)
    case = projection.cases[0]
    role_snapshot = analysis_run.source_roles
    bound_role = role_snapshot.bind_projection(projection, analysis_run.analysis)[0]
    role_fields = trusted_case_fields_from_projection(case, bound_role,
                                                      analysis_run.analysis, projection)
    citation_input = dict(stored_values)
    citation_input["request_id"] = "r_0123456789abcdef01234567"
    citation_input.pop("verified_citation_ids", None)
    source_name = {"application": "application", "ssh": "ssh", "access": "access_log"}.get(
        role_fields["source_role"], "application",
    )
    synthetic_events = tuple(NormalizedEvent(
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc), event_type="synthetic",
        source=source_name, user=None, src_ip=case.row.subject_ip, dst_ip=None,
        application=None, protocol=None, user_agent=None, raw="synthetic-only",
    ) for _ in range(64))

    lookup = lambda: registry.lookup(case_ref)
    snapshot_capture = lambda: AnalysisSourceRoleSnapshot.from_events(
        analysis_run.analysis, synthetic_events,
    )
    identity_check = lambda: bound_role.is_current(case, analysis_run.analysis, projection)
    role_adapter = lambda: trusted_case_fields_from_projection(
        case, bound_role, analysis_run.analysis, projection,
    )
    retrieval = lambda: triage._retrieve_citation_ids(citation_input)
    citations = triage._retrieve_citation_ids(citation_input)
    dto_values = {**citation_input, "verified_citation_ids": citations}
    dto_validation = lambda: triage.SafeInvestigationDTO.from_mapping(dto_values)
    dto = dto_validation()
    checklist = lambda: build_investigation_checklist(dto)
    result = checklist()
    output = lambda: checklist_api._response(dto, result)
    response_model = output()
    response_validation = lambda: checklist_api.ChecklistResponse.model_validate_json(
        response_model.model_dump_json(by_alias=True),
    )
    request = {"schema_version": 1, "case_ref": case_ref}
    def endpoint():
        response = client.post("/api/v1/investigations/checklist", json=request)
        response.raise_for_status()

    stages = {
        "case_lookup": _measure(lookup),
        "source_role_snapshot_capture_64_events": _measure(snapshot_capture),
        "snapshot_identity_check": _measure(identity_check),
        "role_validation_and_safe_adapter": _measure(role_adapter),
        "lexical_retrieval_and_verified_citations": _measure(retrieval),
        "safe_dto_validation": _measure(dto_validation),
        "checklist_generation": _measure(checklist),
        "response_validation": _measure(response_validation),
        "endpoint_total": _measure(endpoint),
    }
    final_response = client.post("/api/v1/investigations/checklist", json=request)
    final_response.raise_for_status()
    digest = hashlib.sha256(final_response.content).hexdigest()
    request_bytes = json.dumps(request, separators=(",", ":")).encode("utf-8")
    print(f"warmups={WARMUPS} samples={SAMPLES} request_bytes={len(request_bytes)}")
    print(f"response_bytes={len(final_response.content)} canonical_sha256={digest}")
    for name, result in stages.items():
        print(f"{name} median_ms={result['median_ms']:.4f} "
              f"p95_ms={result['p95_ms']:.4f} max_ms={result['max_ms']:.4f}")
    print("synthetic development observation only; not an operational SLA or worst-case guarantee")
    client.close()


if __name__ == "__main__":
    main()
