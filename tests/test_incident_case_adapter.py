import builtins
from copy import deepcopy
from dataclasses import fields, is_dataclass
from datetime import datetime, timedelta, timezone
import math
import os
import random
import socket
import time

import pytest

import app.analyzer.incident_case_adapter as adapter_module
from app.analyzer.incident_case import (
    IncidentCaseAssemblyError,
    assemble_incident_cases,
)
from app.analyzer.incident_case_adapter import (
    IncidentCaseAdapterError,
    project_investigation_cases_from_analysis,
)
from app.analyzer.incident_case_projection import (
    InvestigationCaseProjectionError,
    build_investigation_case_projection,
)
from app.models.schemas import (
    AnalysisResponse,
    AnalysisSummary,
    DetectionResult,
    Evidence,
)


BASE = datetime(2026, 10, 8, 0, 0, tzinfo=timezone.utc)
PRIVATE = "PRIVATE-ACCOUNT-CREDENTIAL-TOKEN-COOKIE"
PRIVATE_PATH = "/private/operator/secret.log"


def _empty_detection():
    return DetectionResult(False, None, [])


def _brute_detection(
    *,
    failed_count=5,
    target_count=1,
    window=20.0,
    start=BASE,
):
    return DetectionResult(
        True,
        "brute_force",
        [
            Evidence(
                "multiple_login_failures",
                failed_count,
                "brute_force_detector",
                time_range=(start, start + timedelta(seconds=window)),
            ),
            Evidence(
                "single_target_user",
                target_count,
                "brute_force_detector",
            ),
            Evidence(
                "failures_within_short_window",
                window,
                "brute_force_detector",
            ),
        ],
    )


def _spray_detection(
    *,
    failed_count=5,
    target_count=3,
    window=20.0,
):
    return DetectionResult(
        True,
        "password_spraying_like",
        [
            Evidence(
                "multiple_login_failures",
                failed_count,
                "password_spray_detector",
                time_range=(BASE, BASE + timedelta(seconds=window)),
            ),
            Evidence(
                "multiple_target_users",
                target_count,
                "password_spray_detector",
            ),
            Evidence(
                "failures_within_short_window",
                window,
                "password_spray_detector",
            ),
        ],
    )


def _path_detection():
    return DetectionResult(
        True,
        "path_traversal",
        [
            Evidence(
                "url_decoded_path",
                f"{PRIVATE_PATH}/../../etc/passwd",
                "path_traversal_detector",
                timestamp=BASE,
            ),
            Evidence(
                "path_pattern",
                "../",
                "path_traversal_detector",
                timestamp=BASE,
            ),
            Evidence(
                "url_decoded_query",
                f"credential={PRIVATE}",
                "path_traversal_detector",
                timestamp=BASE,
            ),
            Evidence(
                "http_method",
                "GET",
                "path_traversal_detector",
                timestamp=BASE,
            ),
            Evidence(
                "http_status_code",
                200,
                "path_traversal_detector",
                timestamp=BASE,
            ),
            Evidence(
                "http_response_size",
                2048,
                "path_traversal_detector",
                timestamp=BASE,
            ),
        ],
    )


def _no_correlation():
    return {
        "is_correlated": False,
        "type": None,
        "user": None,
        "rationale": [],
    }


def _correlation(
    correlation_type="failed_to_successful_login",
    *,
    failure=BASE + timedelta(seconds=20),
    success=BASE + timedelta(seconds=40),
    account=PRIVATE,
):
    return {
        "is_correlated": True,
        "type": correlation_type,
        "user": account,
        "failure_timestamp": failure,
        "success_timestamp": success,
        "time_delta_seconds": (success - failure).total_seconds(),
        "rationale": [f"bounded rationale for {account}"],
    }


def _post_correlation():
    success = BASE + timedelta(seconds=40)
    access = BASE + timedelta(seconds=50)
    return {
        "is_correlated": True,
        "type": "successful_login_to_file_access",
        "user": PRIVATE,
        "success_timestamp": success,
        "file_access_timestamp": access,
        "time_delta_seconds": 10.0,
        "rationale": [f"bounded rationale for {PRIVATE}"],
    }


def _features(
    *,
    failed_count=0,
    accounts=(),
    window=0,
    within_window=False,
):
    return {
        "failure_count": failed_count,
        "target_users": list(accounts),
        "login_succeeded": False,
        "within_window": within_window,
        "window_seconds": window,
        "average_interval": 0,
        "interval_variability": 0,
        "unique_target_count": len(accounts),
    }


def _risk_factors(confidence="HIGH"):
    return {
        "likelihood": {"private": PRIVATE},
        "impact": {"private": PRIVATE},
        "confidence": {
            "level": confidence,
            "rationale": ["bounded confidence rationale"],
        },
        "evidence": [{"private": PRIVATE_PATH}],
        "account_context": {PRIVATE: {"credential": PRIVATE}},
    }


def _subject_result(
    *,
    features=None,
    brute=None,
    spray=None,
    path=None,
    authentication=None,
    post=None,
    brute_success=None,
    spray_success=None,
    risk="HIGH",
    confidence="HIGH",
):
    return {
        "features": features or _features(),
        "detections": {
            "brute_force": brute or _empty_detection(),
            "password_spray": spray or _empty_detection(),
            "path_traversal": path or _empty_detection(),
        },
        "correlation": {
            "authentication": authentication or _no_correlation(),
            "post_authentication": post or _no_correlation(),
            "brute_force_to_success": brute_success or _no_correlation(),
            "password_spray_to_success": spray_success or _no_correlation(),
        },
        "risk_factors": _risk_factors(confidence),
        "risk_level": risk,
    }


def _analysis(results=None, global_correlation=None):
    return {
        "results": {} if results is None else results,
        "global_correlation": (
            {"private": PRIVATE}
            if global_correlation is None
            else global_correlation
        ),
    }


def _brute_subject(*, include_path=False):
    return _subject_result(
        features=_features(
            failed_count=5,
            accounts=(PRIVATE,),
            window=20.0,
            within_window=True,
        ),
        brute=_brute_detection(),
        path=_path_detection() if include_path else None,
        authentication=_correlation(),
        brute_success=_correlation(
            "brute_force_to_successful_login"
        ),
    )


def _scalar_tree(value):
    if is_dataclass(value):
        return tuple(
            (item.name, _scalar_tree(getattr(value, item.name)))
            for item in fields(value)
        )
    if type(value) is tuple:
        return tuple(_scalar_tree(item) for item in value)
    if type(value) is datetime:
        return value.isoformat()
    if value is None or type(value) in {str, int, float, bool}:
        return value
    raise AssertionError("unexpected projection value")


def test_exact_analysis_boundary_rejects_models_strings_and_iterables():
    api_model = AnalysisResponse(
        analysis_id="bounded",
        status="completed",
        summary=AnalysisSummary(
            total_sources=0,
            total_ips=0,
            detected_ips=0,
            high_risk_ips=0,
        ),
        results=[],
        global_correlation={
            "multi_ip_authentication_count": 0,
            "distributed_authentication_to_success_count": 0,
            "linux_audit_session_lifecycle_count": 0,
            "linux_audit_login_start_co_observation_count": 0,
            "limitation": "fixed",
        },
    )

    for value in (
        api_model,
        "cli output",
        (),
        iter(()),
    ):
        with pytest.raises(IncidentCaseAdapterError) as error:
            project_investigation_cases_from_analysis(value)
        assert error.value.code == "invalid_input_type"


def test_exact_top_level_subject_and_feature_shapes_fail_closed():
    malformed = _analysis()
    malformed["unexpected"] = PRIVATE
    with pytest.raises(IncidentCaseAdapterError) as error:
        project_investigation_cases_from_analysis(malformed)
    assert error.value.code == "unsupported_result_shape"

    bad_subject = _brute_subject()
    bad_subject["unexpected"] = PRIVATE
    with pytest.raises(IncidentCaseAdapterError):
        project_investigation_cases_from_analysis(
            _analysis({"192.0.2.1": bad_subject})
        )

    bad_features = _brute_subject()
    bad_features["features"]["raw_log"] = PRIVATE
    with pytest.raises(IncidentCaseAdapterError):
        project_investigation_cases_from_analysis(
            _analysis({"192.0.2.1": bad_features})
        )


def test_input_is_not_mutated_or_retained():
    analysis = _analysis({"192.0.2.1": _brute_subject(include_path=True)})
    before = deepcopy(analysis)
    projection = project_investigation_cases_from_analysis(analysis)

    assert analysis == before
    rendered = repr(projection)
    assert "DetectionResult" not in rendered
    assert "Evidence(" not in rendered
    assert PRIVATE not in rendered
    assert PRIVATE_PATH not in rendered


def test_supported_mapping_builds_brute_case_and_absorbs_generic_relation():
    projection = project_investigation_cases_from_analysis(
        _analysis({"192.0.2.1": _brute_subject()})
    )
    case = projection.cases[0]

    assert projection.summary.case_count == 1
    assert projection.summary.independent_observation_count == 0
    assert case.rule_code == "CASE-BRUTE-SUCCESS-01"
    assert case.row.supporting_relation_count == 2
    assert tuple(entry.category for entry in case.timeline_entries) == (
        "DETECTION_OBSERVATION",
        "OBSERVED_FACT",
        "SUPPORTED_RELATION",
        "SUPPORTED_RELATION",
        "OBSERVED_FACT",
    )
    evidence = case.timeline_entries[0].evidence
    assert tuple((item.label, item.value, item.unit) for item in evidence) == (
        ("실패 횟수", 5, "회"),
        ("대상 계정 수", 1, "개"),
        ("시간 범위", 20.0, "초"),
    )


def test_generic_failed_to_success_mapping_builds_auth_transition_case():
    result = _subject_result(
        features=_features(
            failed_count=1,
            accounts=(PRIVATE,),
            within_window=True,
        ),
        authentication=_correlation(),
        risk="MEDIUM",
        confidence="MEDIUM",
    )
    projection = project_investigation_cases_from_analysis(
        _analysis({"192.0.2.2": result})
    )

    assert projection.cases[0].rule_code == "CASE-AUTH-TRANSITION-01"
    assert projection.cases[0].row.included_highest_risk == "MEDIUM"


def test_spray_mapping_stays_no_go_and_independent():
    spray_relation = _correlation(
        "password_spray_to_successful_login"
    )
    result = _subject_result(
        features=_features(
            failed_count=5,
            accounts=(PRIVATE, "operator", "reviewer"),
            window=20.0,
            within_window=True,
        ),
        spray=_spray_detection(),
        spray_success=spray_relation,
    )
    projection = project_investigation_cases_from_analysis(
        _analysis({"192.0.2.3": result})
    )

    assert projection.summary.case_count == 0
    assert projection.summary.spray_no_go_observation_count == 2
    assert {item.display_type for item in projection.independent_observations} == {
        "Password Spraying-like",
        "Password Spraying-like → Successful Login",
    }


def test_path_mapping_is_independent_and_drops_private_evidence():
    result = _subject_result(path=_path_detection(), risk="MEDIUM")
    projection = project_investigation_cases_from_analysis(
        _analysis({"192.0.2.4": result})
    )
    item = projection.independent_observations[0]

    assert item.display_type == "Path Traversal"
    assert item.evidence == ()
    assert item.timestamp_state == "TIMESTAMPED"
    assert item.start_time.canonical_utc == BASE
    assert PRIVATE not in repr(projection)
    assert PRIVATE_PATH not in repr(projection)


def test_post_authentication_mapping_is_preserved_as_independent():
    result = _subject_result(post=_post_correlation(), risk="LOW")
    projection = project_investigation_cases_from_analysis(
        _analysis({"192.0.2.5": result})
    )
    item = projection.independent_observations[0]

    assert item.display_type == "Successful Login → File Access"
    assert item.timestamp_state == "TIMESTAMPED"
    assert item.reason_id == "unsupported_for_case_assembly"


def test_unknown_detector_is_sanitized_and_preserved_independently():
    unknown = DetectionResult(
        True,
        f"future-{PRIVATE}",
        [Evidence("raw", PRIVATE_PATH, "future")],
    )
    result = _subject_result(brute=unknown, risk="LOW", confidence="LOW")
    projection = project_investigation_cases_from_analysis(
        _analysis({"192.0.2.6": result})
    )

    assert len(projection.independent_observations) == 1
    assert projection.independent_observations[0].display_type == (
        "지원되지 않는 탐지 관찰"
    )
    assert PRIVATE not in repr(projection)
    assert PRIVATE_PATH not in repr(projection)


def test_unknown_correlation_fails_closed_instead_of_being_discarded():
    result = _subject_result(
        authentication=_correlation("future_private_relation")
    )
    with pytest.raises(IncidentCaseAdapterError) as error:
        project_investigation_cases_from_analysis(
            _analysis({"192.0.2.7": result})
        )
    assert error.value.code == "invalid_correlation_contract"


def test_global_correlation_and_linux_audit_context_are_never_consumed():
    class PrivateGlobalValue:
        def __repr__(self):
            raise AssertionError("global correlation must not be rendered")

    global_correlation = {
        "multi_ip_authentication": PrivateGlobalValue(),
        "linux_audit_session_lifecycle": {
            "argv": PRIVATE,
            "PROCTITLE": PRIVATE,
            "CWD": PRIVATE_PATH,
            "PATH": PRIVATE_PATH,
        },
    }
    projection = project_investigation_cases_from_analysis(
        _analysis({}, global_correlation)
    )

    assert projection.summary.case_count == 0
    assert PRIVATE not in repr(projection)
    assert PRIVATE_PATH not in repr(projection)


def test_single_pass_calls_only_assembler_and_projection_once(monkeypatch):
    counts = {"assembly": 0, "projection": 0}
    real_assembler = assemble_incident_cases
    real_projection = build_investigation_case_projection

    def assembly_spy(subjects):
        counts["assembly"] += 1
        return real_assembler(subjects)

    def projection_spy(assembly):
        counts["projection"] += 1
        return real_projection(assembly)

    def forbidden(*args, **kwargs):
        raise AssertionError("analysis stage must not run")

    monkeypatch.setattr(adapter_module, "assemble_incident_cases", assembly_spy)
    monkeypatch.setattr(
        adapter_module,
        "build_investigation_case_projection",
        projection_spy,
    )
    monkeypatch.setattr("app.main.analyze", forbidden)
    monkeypatch.setattr("app.analyzer.pipeline.load_normalized_logs", forbidden)
    monkeypatch.setattr("app.analyzer.pipeline.detect_attacks", forbidden)
    monkeypatch.setattr("app.analyzer.pipeline.correlate_attacks", forbidden)
    monkeypatch.setattr("app.analyzer.pipeline.assess_risk", forbidden)
    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(os, "getenv", forbidden)
    monkeypatch.setattr(time, "time", forbidden)
    monkeypatch.setattr(random, "random", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)

    project_investigation_cases_from_analysis(
        _analysis({"192.0.2.1": _brute_subject()})
    )

    assert counts == {"assembly": 1, "projection": 1}


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("failed", True),
        ("failed", -1),
        ("failed", 1 << 63),
        ("target", True),
        ("window", -1.0),
        ("window", math.nan),
        ("window", math.inf),
        ("window", float(1 << 63)),
    ),
)
def test_invalid_detection_evidence_numbers_fail_closed(field, value):
    detection = _brute_detection()
    if field == "failed":
        detection.evidence[0].value = value
    elif field == "target":
        detection.evidence[1].value = value
    else:
        detection.evidence[2].value = value
    result = _brute_subject()
    result["detections"]["brute_force"] = detection

    with pytest.raises(IncidentCaseAdapterError) as error:
        project_investigation_cases_from_analysis(
            _analysis({"192.0.2.1": result})
        )
    assert error.value.code in {
        "invalid_detection_contract",
        "invalid_timestamp",
    }


def test_detection_evidence_requires_exact_types_sources_and_time_range():
    cases = []
    duplicate = _brute_subject()
    duplicate["detections"]["brute_force"].evidence[1].type = (
        "multiple_login_failures"
    )
    cases.append(duplicate)

    wrong_source = _brute_subject()
    wrong_source["detections"]["brute_force"].evidence[0].source = PRIVATE
    cases.append(wrong_source)

    mismatched_range = _brute_subject()
    mismatched_range["detections"]["brute_force"].evidence[0].time_range = (
        BASE,
        BASE + timedelta(seconds=19),
    )
    cases.append(mismatched_range)

    for result in cases:
        with pytest.raises(IncidentCaseAdapterError):
            project_investigation_cases_from_analysis(
                _analysis({"192.0.2.1": result})
            )


def test_invalid_detection_timestamp_is_preserved_as_independent_no_time():
    naive_start = datetime(2026, 10, 8, 0, 0)
    detection = _brute_detection(start=naive_start)
    result = _subject_result(
        features=_features(
            failed_count=5,
            accounts=(PRIVATE,),
            window=20.0,
            within_window=True,
        ),
        brute=detection,
    )
    projection = project_investigation_cases_from_analysis(
        _analysis({"192.0.2.1": result})
    )
    item = projection.independent_observations[0]

    assert projection.summary.case_count == 0
    assert item.display_type == "Brute Force 시간 미검증 관찰"
    assert item.timestamp_state == "NO_TIME"
    assert item.reason_id == "invalid_timestamp"


def test_path_invalid_timestamp_is_safely_preserved_without_time():
    detection = _path_detection()
    for evidence in detection.evidence:
        evidence.timestamp = datetime(2026, 10, 8, 0, 0)
    projection = project_investigation_cases_from_analysis(_analysis({
        "192.0.2.1": _subject_result(path=detection),
    }))

    item = projection.independent_observations[0]
    assert item.display_type == "Path Traversal"
    assert item.timestamp_state == "NO_TIME"


def test_adapter_preserves_canonical_microseconds_end_to_end():
    start = BASE + timedelta(microseconds=123456)
    failure = start + timedelta(seconds=20)
    success = start + timedelta(seconds=40)
    result = _subject_result(
        features=_features(
            failed_count=5,
            accounts=(PRIVATE,),
            window=20.0,
            within_window=True,
        ),
        brute=_brute_detection(start=start),
        authentication=_correlation(failure=failure, success=success),
        brute_success=_correlation(
            "brute_force_to_successful_login",
            failure=failure,
            success=success,
        ),
    )
    projection = project_investigation_cases_from_analysis(
        _analysis({"192.0.2.1": result})
    )

    assert projection.cases[0].row.start_time.canonical_utc == start
    assert projection.cases[0].row.start_time.display_utc == (
        "2026-10-08T00:00:00.123456Z"
    )


def test_correlation_endpoint_delta_account_and_timestamp_are_exact():
    malformed = []

    mismatch = _brute_subject()
    mismatch["correlation"]["authentication"]["time_delta_seconds"] = 19
    malformed.append(mismatch)

    missing_account = _brute_subject()
    missing_account["correlation"]["authentication"]["user"] = None
    malformed.append(missing_account)

    naive = _brute_subject()
    naive["correlation"]["authentication"]["failure_timestamp"] = (
        datetime(2026, 10, 8, 0, 0, 20)
    )
    malformed.append(naive)

    non_utc = _brute_subject()
    non_utc["correlation"]["authentication"]["failure_timestamp"] = (
        BASE.astimezone(timezone(timedelta(hours=9)))
    )
    malformed.append(non_utc)

    for result in malformed:
        with pytest.raises(IncidentCaseAdapterError) as error:
            project_investigation_cases_from_analysis(
                _analysis({"192.0.2.1": result})
            )
        assert error.value.code in {
            "invalid_correlation_contract",
            "invalid_timestamp",
        }


def test_invalid_risk_and_confidence_never_default_to_low():
    bad_risk = _brute_subject()
    bad_risk["risk_level"] = "UNKNOWN"
    bad_confidence = _brute_subject()
    bad_confidence["risk_factors"]["confidence"]["level"] = "UNKNOWN"

    for result in (bad_risk, bad_confidence):
        with pytest.raises(IncidentCaseAdapterError) as error:
            project_investigation_cases_from_analysis(
                _analysis({"192.0.2.1": result})
            )
        assert error.value.code == "invalid_risk"


def test_downstream_errors_are_wrapped_without_original_content(monkeypatch):
    def assembly_failure(subjects):
        raise IncidentCaseAssemblyError("invalid_input")

    monkeypatch.setattr(
        adapter_module,
        "assemble_incident_cases",
        assembly_failure,
    )
    with pytest.raises(IncidentCaseAdapterError) as assembly_error:
        project_investigation_cases_from_analysis(_analysis())
    assert assembly_error.value.code == "downstream_assembly_failure"

    monkeypatch.setattr(
        adapter_module,
        "assemble_incident_cases",
        assemble_incident_cases,
    )

    def projection_failure(assembly):
        raise InvestigationCaseProjectionError()

    monkeypatch.setattr(
        adapter_module,
        "build_investigation_case_projection",
        projection_failure,
    )
    with pytest.raises(IncidentCaseAdapterError) as projection_error:
        project_investigation_cases_from_analysis(_analysis())
    assert projection_error.value.code == "downstream_projection_failure"
    assert PRIVATE not in repr(assembly_error.value)
    assert PRIVATE not in repr(projection_error.value)


def test_end_to_end_is_deterministic_across_permutation_and_repetition():
    brute = _brute_subject(include_path=True)
    low = _subject_result(risk="LOW", confidence="LOW")
    first_input = _analysis({"2001:db8::1": low, "192.0.2.1": brute})
    second_input = _analysis({"192.0.2.1": brute, "2001:db8::1": low})

    first = project_investigation_cases_from_analysis(first_input)
    second = project_investigation_cases_from_analysis(second_input)
    third = project_investigation_cases_from_analysis(first_input)

    assert first == second == third
    assert _scalar_tree(first) == _scalar_tree(second)
    assert first.summary.case_count == 1
    assert first.summary.independent_observation_count == 1
    assert (
        first.summary.high_case_count,
        first.summary.medium_case_count,
        first.summary.low_case_count,
    ) == (1, 0, 0)
    assert first.cases[0].row.case_label == "조사 사례 1"
    assert first.cases[0].row.start_time.display_kst == (
        "2026-10-08 09:00:00 KST (UTC+09:00)"
    )
    assert first.cases[0].row.start_time.display_utc == (
        "2026-10-08T00:00:00Z"
    )


def test_privacy_canaries_are_absent_from_result_error_and_output(capsys):
    analysis = _analysis(
        {"192.0.2.1": _brute_subject(include_path=True)},
        {
            "raw_log": PRIVATE,
            "argv": PRIVATE,
            "PROCTITLE": PRIVATE,
            "CWD": PRIVATE_PATH,
            "PATH": PRIVATE_PATH,
            "filename": "secret.log",
        },
    )
    projection = project_investigation_cases_from_analysis(analysis)
    rendered = repr(projection) + repr(_scalar_tree(projection))
    canaries = (
        PRIVATE,
        PRIVATE_PATH,
        "credential=",
        "../../etc/passwd",
        "secret.log",
        "PROCTITLE",
        "CWD",
        "argv",
    )
    assert all(canary not in rendered for canary in canaries)
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""

    malformed = _brute_subject()
    malformed["correlation"]["authentication"]["user"] = None
    with pytest.raises(IncidentCaseAdapterError) as error:
        project_investigation_cases_from_analysis(
            _analysis({"192.0.2.1": malformed})
        )
    error_text = str(error.value) + repr(error.value)
    assert all(canary not in error_text for canary in canaries)


def test_bounded_structural_preview_contract(monkeypatch):
    calls = {"assembly": 0, "projection": 0}
    real_assembler = adapter_module.assemble_incident_cases
    real_projection = adapter_module.build_investigation_case_projection

    def assembly_spy(subjects):
        calls["assembly"] += 1
        return real_assembler(subjects)

    def projection_spy(assembly):
        calls["projection"] += 1
        return real_projection(assembly)

    monkeypatch.setattr(adapter_module, "assemble_incident_cases", assembly_spy)
    monkeypatch.setattr(
        adapter_module,
        "build_investigation_case_projection",
        projection_spy,
    )
    projection = project_investigation_cases_from_analysis(
        _analysis({"192.0.2.1": _brute_subject(include_path=True)})
    )
    preview = (
        1,
        2,
        2,
        projection.summary.case_count,
        projection.summary.independent_observation_count,
        (
            projection.summary.high_case_count,
            projection.summary.medium_case_count,
            projection.summary.low_case_count,
        ),
        tuple(
            entry.category for entry in projection.cases[0].timeline_entries
        ),
        calls["assembly"],
        calls["projection"],
    )

    assert preview == (
        1,
        2,
        2,
        1,
        1,
        (1, 0, 0),
        (
            "DETECTION_OBSERVATION",
            "OBSERVED_FACT",
            "SUPPORTED_RELATION",
            "SUPPORTED_RELATION",
            "OBSERVED_FACT",
        ),
        1,
        1,
    )
