"""Verified source-role provenance contracts for the checklist boundary."""

from types import SimpleNamespace
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor

import pytest


def _case(subject="192.0.2.10"):
    return SimpleNamespace(row=SimpleNamespace(subject_ip=subject))


def _bound(snapshot, case, analysis):
    projection = SimpleNamespace(cases=(case,))
    return snapshot.bind_projection(projection, analysis)[0], projection


def _event(subject, source):
    from app.models.schemas import NormalizedEvent

    return NormalizedEvent(
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc), event_type="synthetic",
        source=source, user="ACCOUNT_CANARY", src_ip=subject, dst_ip=None,
        application="HOST_CANARY credential-like-CANARY", protocol=None,
        user_agent=None, raw="RAW_LINE_CANARY /synthetic/private.log",
    )


def test_one_explicit_role_from_the_same_analysis_snapshot_is_preserved():
    from app.investigation_role_snapshot_36_4 import AnalysisSourceRoleSnapshot

    analysis = {}
    snapshot = AnalysisSourceRoleSnapshot.from_events(
        analysis, (_event("192.0.2.10", "application"),)
    )
    case = _case()
    bound, projection = _bound(snapshot, case, analysis)

    assert bound.source_role == "application"
    assert bound.is_current(case, analysis, projection) is True
    assert bound.is_current(_case(), analysis, projection) is False


@pytest.mark.parametrize("events", [
    (),
    (_event("192.0.2.10", "application"), _event("192.0.2.10", "ssh")),
    (_event("192.0.2.10", "unrecognized-source"),),
])
def test_missing_mixed_or_invalid_role_metadata_falls_back_to_unknown(events):
    from app.investigation_role_snapshot_36_4 import AnalysisSourceRoleSnapshot

    analysis = {}
    snapshot = AnalysisSourceRoleSnapshot.from_events(analysis, events)
    assert _bound(snapshot, _case(), analysis)[0].source_role == "unknown"


def test_role_snapshot_rejects_replaced_analysis_and_unmatched_case_identity():
    from app.investigation_role_snapshot_36_4 import AnalysisSourceRoleSnapshot

    analysis = {}
    snapshot = AnalysisSourceRoleSnapshot.from_events(
        analysis, (_event("192.0.2.10", "ssh"),)
    )
    assert _bound(snapshot, _case(), {})[0].source_role == "unknown"
    assert _bound(snapshot, _case("192.0.2.11"), analysis)[0].source_role == "unknown"


def test_roles_from_other_case_observations_are_not_combined():
    from app.investigation_role_snapshot_36_4 import AnalysisSourceRoleSnapshot

    analysis = {}
    snapshot = AnalysisSourceRoleSnapshot.from_events(analysis, (
        _event("192.0.2.10", "application"),
        _event("192.0.2.11", "ssh"),
    ))
    assert _bound(snapshot, _case("192.0.2.10"), analysis)[0].source_role == "application"
    assert _bound(snapshot, _case("192.0.2.11"), analysis)[0].source_role == "ssh"


def test_repeated_same_role_is_accepted_but_role_conflict_is_unknown():
    from app.investigation_role_snapshot_36_4 import AnalysisSourceRoleSnapshot

    analysis = {}
    same = AnalysisSourceRoleSnapshot.from_events(analysis, (
        _event("192.0.2.10", "application"),
        _event("192.0.2.10", "application"),
    ))
    mixed = AnalysisSourceRoleSnapshot.from_events(analysis, (
        _event("192.0.2.10", "application"),
        _event("192.0.2.10", "access_log"),
    ))
    assert _bound(same, _case(), analysis)[0].source_role == "application"
    assert _bound(mixed, _case(), analysis)[0].source_role == "unknown"


def test_role_binding_is_case_and_analysis_object_scoped_and_redacted():
    from app.investigation_role_snapshot_36_4 import AnalysisSourceRoleSnapshot

    canary_ip = "2001:db8::7331"
    analysis = {}
    case = _case(canary_ip)
    snapshot = AnalysisSourceRoleSnapshot.from_events(
        analysis, (_event(canary_ip, "access_log"),)
    )
    bound, projection = _bound(snapshot, case, analysis)
    with pytest.raises(TypeError):
        snapshot._roles_by_subject["192.0.2.99"] = frozenset({"application"})
    assert bound.source_role == "access"
    assert bound.is_current(case, analysis, projection)
    assert not bound.is_current(_case(canary_ip), analysis, projection)
    assert not bound.is_current(case, {}, projection)
    assert not bound.is_current(case, analysis, SimpleNamespace(cases=(case,)))
    assert canary_ip not in repr(snapshot)
    assert canary_ip not in repr(bound)
    for canary in ("ACCOUNT_CANARY", "HOST_CANARY", "credential-like-CANARY",
                   "RAW_LINE_CANARY", "/synthetic/private.log"):
        assert canary not in repr(snapshot)
        assert canary not in repr(bound)


def test_parallel_case_binding_keeps_roles_isolated():
    from app.investigation_role_snapshot_36_4 import AnalysisSourceRoleSnapshot

    analysis = {}
    snapshot = AnalysisSourceRoleSnapshot.from_events(analysis, (
        _event("192.0.2.41", "application"), _event("192.0.2.42", "ssh"),
    ))
    cases = (_case("192.0.2.41"), _case("192.0.2.42"))

    def bind(case):
        return _bound(snapshot, case, analysis)[0].source_role

    with ThreadPoolExecutor(max_workers=2) as pool:
        roles = tuple(pool.map(bind, cases))
    assert roles == ("application", "ssh")


def test_dto_accepts_only_the_defined_source_role_enum():
    from app.investigation_triage_36_1 import CORPUS_DIGEST, create_safe_investigation_dto

    values = {
        "schema_version": 1, "request_id": "r_0123456789abcdef01234567",
        "case_ref": "c_1123456789abcdef01234567", "source_role": "access",
        "observation_categories": ("web_request",), "detection_codes": ("path_traversal",),
        "relation_codes": (), "risk_band": "UNKNOWN", "case_status": "open",
        "event_count_bucket": "1", "time_window_bucket": "unknown",
        "evidence_completeness": "complete", "limitation_codes": (),
        "corpus_digest": CORPUS_DIGEST,
    }
    assert create_safe_investigation_dto(**values).source_role == "access"


def test_role_snapshot_capture_failure_fails_closed_without_private_repr():
    from app.investigation_role_snapshot_36_4 import AnalysisSourceRoleSnapshot

    analysis = {}
    snapshot = AnalysisSourceRoleSnapshot.from_events(
        analysis, (_event("198.51.100.77", "application"), object())
    )
    assert _bound(snapshot, _case("198.51.100.77"), analysis)[0].source_role == "unknown"
    assert "198.51.100.77" not in repr(snapshot)


def test_bound_role_is_not_reused_for_a_replaced_case_snapshot():
    from app.analyzer.incident_case_projection import InvestigationCaseDetailProjection
    from app.investigation_checklist_api_36_3 import trusted_case_fields_from_projection
    from app.investigation_role_snapshot_36_4 import AnalysisSourceRoleSnapshot

    canary_ip = "198.51.100.88"

    def projection_case():
        case = object.__new__(InvestigationCaseDetailProjection)
        object.__setattr__(case, "timeline_entries", ())
        object.__setattr__(case, "timeline_entries_without_time", ())
        object.__setattr__(case, "row", SimpleNamespace(
            included_highest_risk="MEDIUM", observation_count=2, subject_ip=canary_ip,
        ))
        object.__setattr__(case, "limitations", ())
        return case

    analysis = {}
    original_case = projection_case()
    projection = SimpleNamespace(cases=(original_case,))
    snapshot = AnalysisSourceRoleSnapshot.from_events(
        analysis, (_event(canary_ip, "application"),)
    )
    bound = snapshot.bind_projection(projection, analysis)[0]
    original = trusted_case_fields_from_projection(original_case, bound, analysis, projection)
    replacement = projection_case()
    stale = trusted_case_fields_from_projection(replacement, bound, analysis, projection)

    assert original["source_role"] == "application"
    assert stale["source_role"] == "unknown"
    assert canary_ip not in repr(bound)
    assert canary_ip not in str(stale)


def test_invalid_bound_role_value_fails_closed_to_unknown():
    from app.analyzer.incident_case_projection import InvestigationCaseDetailProjection
    from app.investigation_checklist_api_36_3 import trusted_case_fields_from_projection
    from app.investigation_role_snapshot_36_4 import BoundCaseSourceRole

    case = object.__new__(InvestigationCaseDetailProjection)
    object.__setattr__(case, "timeline_entries", ())
    object.__setattr__(case, "timeline_entries_without_time", ())
    object.__setattr__(case, "row", SimpleNamespace(included_highest_risk="LOW", observation_count=1,
                                                     subject_ip="192.0.2.20"))
    object.__setattr__(case, "limitations", ())
    analysis = {}
    projection = SimpleNamespace(cases=(case,))
    forged = BoundCaseSourceRole("private-role-canary", case, analysis, projection)
    values = trusted_case_fields_from_projection(case, forged, analysis, projection)

    assert values["source_role"] == "unknown"
    assert "private-role-canary" not in repr(forged)


def test_source_role_analysis_wrapper_loads_once_and_preserves_analysis_result(monkeypatch):
    import app.main as main

    analysis = {"results": {}, "global_correlation": {}}
    from app.detector.brute_force import AnalysisRunOwner

    run_owner = AnalysisRunOwner()
    run_owner._bind_analysis(analysis)
    load_calls = []
    events = [_event("192.0.2.30", "ssh")]
    monkeypatch.setattr(main, "load_normalized_logs", lambda sources: load_calls.append(sources) or events)
    monkeypatch.setattr(
        main,
        "_analyze_normalized_logs_with_context",
        lambda loaded: (analysis, {}, run_owner),
    )

    snapshot = main.analyze_with_source_role_snapshot(({"source": "ssh", "path": "synthetic"},))

    assert load_calls == [({"source": "ssh", "path": "synthetic"},)]
    assert snapshot.analysis is analysis
    assert _bound(snapshot.source_roles, _case("192.0.2.30"), analysis)[0].source_role == "ssh"


def test_provenance_wrapper_keeps_deterministic_analysis_output_identical():
    from app.main import LOG_SOURCES, analyze, analyze_with_source_role_snapshot

    original = analyze(LOG_SOURCES)
    wrapped = analyze_with_source_role_snapshot(LOG_SOURCES)
    assert wrapped.analysis == original


def test_sample_checklist_exposes_only_the_verified_safe_role_contract():
    from fastapi.testclient import TestClient
    from app.api import create_app

    client = TestClient(create_app(), base_url="http://127.0.0.1", client=("127.0.0.1", 12345))
    sample = client.post("/api/v1/investigations/sample")
    assert sample.status_code == 200
    case_ref = sample.json()["cases"][0]["checklist_ref"]
    response = client.post("/api/v1/investigations/checklist", json={
        "schema_version": 1, "case_ref": case_ref,
    })

    assert response.status_code == 200
    assert response.json()["schema"] == "investigation-checklist/v2"
    assert response.json()["source_role"] == "ssh"
    assert response.json()["source_role_label"] == "SSH 인증 로그"
    roles = []
    for case_item in sample.json()["cases"]:
        role_response = client.post("/api/v1/investigations/checklist", json={
            "schema_version": 1, "case_ref": case_item["checklist_ref"],
        })
        assert role_response.status_code == 200
        roles.append(role_response.json()["source_role"])
    assert roles == ["ssh", "application"]


def test_local_upload_worker_carries_roles_from_its_same_parse_pass():
    from pathlib import Path
    from fastapi.testclient import TestClient
    from app.api import create_app

    root = Path(__file__).resolve().parents[1]
    files = [
        (field, ("synthetic.log", (root / "sample_logs" / name).read_bytes(), "text/plain"))
        for field, name in (
            ("application_file", "brute_force.log"),
            ("ssh_file", "ssh_auth.log"),
            ("access_file", "web_shell.log"),
        )
    ]
    client = TestClient(create_app(), base_url="http://127.0.0.1", client=("127.0.0.1", 12345))
    analysis = client.post("/api/v1/investigations", files=files)
    assert analysis.status_code == 200
    roles = []
    for case in analysis.json()["cases"]:
        result = client.post("/api/v1/investigations/checklist", json={
            "schema_version": 1, "case_ref": case["checklist_ref"],
        })
        assert result.status_code == 200
        roles.append(result.json()["source_role"])
    assert roles == ["ssh", "application"]


def test_verified_role_response_is_repeatable_across_timezones(monkeypatch):
    import hashlib
    import os
    import time
    from fastapi.testclient import TestClient
    from app.api import create_app

    client = TestClient(create_app(), base_url="http://127.0.0.1", client=("127.0.0.1", 12345))
    sample = client.post("/api/v1/investigations/sample").json()
    case_ref = sample["cases"][0]["checklist_ref"]
    original = os.environ.get("TZ")
    responses = []
    try:
        for zone in ("UTC", "Asia/Seoul", "UTC"):
            monkeypatch.setenv("TZ", zone)
            time.tzset()
            response = client.post("/api/v1/investigations/checklist", json={
                "schema_version": 1, "case_ref": case_ref,
            })
            assert response.status_code == 200
            responses.append(response.content)
    finally:
        if original is None:
            monkeypatch.delenv("TZ", raising=False)
        else:
            monkeypatch.setenv("TZ", original)
        time.tzset()
    assert len(set(responses)) == 1
    assert hashlib.sha256(responses[0]).hexdigest() == (
        "243b7e53e4c209952cf52ca4947b3b3068405eb7bf2bb9b39881df2087b6abb5"
    )
