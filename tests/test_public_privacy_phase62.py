"""Public projections must not expose trusted raw analysis fields."""

from copy import deepcopy
from urllib.parse import quote

from fastapi.testclient import TestClient
import pytest
from pydantic import ValidationError

import app.api as api_module
from app.analyzer.legacy_api_projection import LegacyAnalysisProjectionError
from app.api import build_analysis_response
from app.analyzer.html_report import render_investigation_report_html
from app.analyzer.llm import build_llm_input
from app.analyzer.report import print_analysis_result
from app.analyzer.report_projection import (
    InvestigationReportProjectionError,
    build_investigation_report_projection,
)
from app.main import analyze
from app.models.schemas import LegacyDetectionProjection


ACCOUNT = "synthetic-account-canary-62"
PASSWORD = "synthetic-password-like-canary-62"
COOKIE = "synthetic-cookie-canary-62"
TOKEN = "synthetic-token-canary-62"
PATH = "/synthetic-private-segment-62"
QUERY = "private_parameter=synthetic-query-canary-62"
FILENAME = "synthetic-filename-canary-62.log"
TEMP_PATH = "/synthetic-temp-segment-62/staged.log"
EXCEPTION = "synthetic-internal-exception-canary-62"
FORBIDDEN = (
    ACCOUNT, PASSWORD, COOKIE, TOKEN, PATH, "synthetic-private-segment-62",
    QUERY, "synthetic-query-canary-62", FILENAME, TEMP_PATH,
    "synthetic-temp-segment-62", EXCEPTION,
)


def _canary_analysis():
    result = deepcopy(analyze())
    for subject in result["results"].values():
        subject["features"]["target_users"] = [ACCOUNT]
        subject["features"]["raw_log"] = PASSWORD + COOKIE + TOKEN
        subject["features"]["source_filename"] = FILENAME
        subject["features"]["temporary_path"] = TEMP_PATH
        subject["risk_factors"]["account_context"] = {
            ACCOUNT: {"cookie": COOKIE, "token": TOKEN, "error": EXCEPTION},
        }
        for relation in subject["correlation"].values():
            if relation.get("is_correlated"):
                relation["user"] = ACCOUNT
                relation["rationale"] = [f"{ACCOUNT} synthetic relation"]
        traversal = subject["detections"]["path_traversal"]
        if traversal.is_detected:
            for evidence in traversal.evidence:
                if evidence.type == "url_decoded_path":
                    evidence.value = PATH
                elif evidence.type == "url_decoded_query":
                    evidence.value = QUERY
    for records in result["global_correlation"].values():
        for record in records:
            record["source_filename"] = FILENAME
            record["temporary_path"] = TEMP_PATH
            if "user" in record:
                record["user"] = ACCOUNT
            if "rationale" in record:
                record["rationale"] = [f"{ACCOUNT} synthetic relation"]
    return result


def test_legacy_api_nested_values_are_privacy_safe():
    response = build_analysis_response(_canary_analysis(), total_sources=3)
    rendered = response.model_dump_json()
    assert all(value not in rendered for value in FORBIDDEN)
    assert all(value not in repr(response) for value in FORBIDDEN)
    assert response.summary.total_sources == 3
    assert response.results
    assert response.global_correlation.multi_ip_authentication_count >= 0
    for row in response.results:
        assert set(row.detections) == {
            "brute_force", "password_spray", "path_traversal",
            "sql_injection_like", "xss_like", "sensitive_resource_probing_like",
            "web_scanning_like",
        }
        assert row.risk_factors.rationale_id == "existing_assessment"
        assert all(relation.account_reference_available is False for relation in row.correlation)


def test_legacy_route_is_deprecated_and_never_serializes_raw_nested_data(monkeypatch):
    monkeypatch.setattr(api_module, "analyze", lambda _: _canary_analysis())
    client = TestClient(api_module.app)
    response = client.post("/api/analyze", files={
        "application_file": ("a.log", b"sample\n", "text/plain"),
        "ssh_file": ("b.log", b"sample\n", "text/plain"),
        "access_file": ("c.log", b"sample\n", "text/plain"),
    })
    assert response.status_code == 200
    assert response.headers["Deprecation"] == "true"
    assert api_module.app.openapi()["paths"]["/api/analyze"]["post"]["deprecated"] is True
    assert all(value not in response.text for value in FORBIDDEN)
    assert all(value not in str(api_module.app.openapi()) for value in FORBIDDEN)


def test_malformed_legacy_route_returns_fixed_error_without_canary(monkeypatch, capsys):
    raw = _canary_analysis()
    raw["global_correlation"]["unknown"] = [{"user": ACCOUNT}]
    monkeypatch.setattr(api_module, "analyze", lambda _: raw)
    response = TestClient(api_module.app).post("/api/analyze", files={
        "application_file": ("a.log", b"sample\n", "text/plain"),
        "ssh_file": ("b.log", b"sample\n", "text/plain"),
        "access_file": ("c.log", b"sample\n", "text/plain"),
    })
    assert response.status_code == 500
    assert response.headers["Deprecation"] == "true"
    assert response.json() == {
        "error_code": "LEGACY_ANALYSIS_FAILED",
        "user_message": "분석 결과를 준비하지 못했습니다.",
        "recovery_action": "입력 형식을 확인한 뒤 로컬 분석을 다시 시도하세요.",
        "retryable": False,
    }
    captured = capsys.readouterr()
    rendered = response.text + captured.out + captured.err
    for value in FORBIDDEN:
        assert value not in rendered
        assert quote(value, safe="") not in rendered


def test_unknown_internal_types_and_malformed_shape_fail_closed():
    raw = _canary_analysis()
    raw["results"][next(iter(raw["results"]))]["detections"]["unknown"] = object()
    with pytest.raises(LegacyAnalysisProjectionError) as caught:
        build_analysis_response(raw, total_sources=3)
    assert all(value not in str(caught.value) + repr(caught.value) for value in FORBIDDEN)

    malformed = _canary_analysis()
    malformed["global_correlation"]["unknown"] = [{"user": ACCOUNT}]
    with pytest.raises(LegacyAnalysisProjectionError):
        build_analysis_response(malformed, total_sources=3)


def test_public_nested_model_rejects_raw_detection_and_extra_account_field():
    raw = next(iter(_canary_analysis()["results"].values()))
    with pytest.raises(ValidationError):
        LegacyDetectionProjection.model_validate(raw["detections"]["brute_force"])
    with pytest.raises(ValidationError):
        LegacyDetectionProjection.model_validate({
            "is_detected": False,
            "detection_type": None,
            "user": ACCOUNT,
        })


def test_legacy_projection_is_deterministic_for_identical_internal_result():
    raw = _canary_analysis()
    first = build_analysis_response(raw, total_sources=3).model_dump_json()
    second = build_analysis_response(raw, total_sources=3).model_dump_json()
    assert first == second


def test_html_report_never_contains_original_http_path_or_query():
    projection = build_investigation_report_projection(_canary_analysis())
    html = render_investigation_report_html(projection)
    assert all(value not in html for value in FORBIDDEN)
    assert all(value not in repr(projection) for value in FORBIDDEN)
    assert "개인정보 보호를 위해 표시하지 않습니다." in html
    assert "일치 패턴" in html


def test_unapproved_traversal_pattern_and_method_cannot_cross_public_boundary():
    for evidence_type, value in (
        ("path_pattern", QUERY),
        ("http_method", "GET-" + ACCOUNT),
    ):
        raw = _canary_analysis()
        for subject in raw["results"].values():
            detection = subject["detections"]["path_traversal"]
            if detection.is_detected:
                for evidence in detection.evidence:
                    if evidence.type == evidence_type:
                        evidence.value = value
        with pytest.raises(InvestigationReportProjectionError) as caught:
            build_investigation_report_projection(raw)
        assert all(item not in str(caught.value) + repr(caught.value) for item in FORBIDDEN)


def test_cli_and_llm_input_do_not_copy_private_fields(capsys):
    result = _canary_analysis()
    print_analysis_result(result)
    output = capsys.readouterr()
    assert all(value not in output.out + output.err for value in FORBIDDEN)
    subject_ip, subject = next(iter(result["results"].items()))
    llm_input = build_llm_input(subject_ip, subject)
    assert all(value not in repr(llm_input) for value in FORBIDDEN)
