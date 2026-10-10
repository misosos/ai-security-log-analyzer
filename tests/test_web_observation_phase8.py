"""Reviewed web-request observations; these do not assert attack success."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from itertools import permutations
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.api import create_app
from app.analyzer.risk import _web_types
from app.analyzer.html_report import _CONTENT_SECURITY_POLICY, render_investigation_report_html
from app.analyzer.report_projection import build_investigation_report_projection
from app.analyzer.report_projection import InvestigationReportProjectionError
from app.analyzer.incident_case_adapter import (
    IncidentCaseAdapterError, project_investigation_cases_from_analysis,
)
from app.analyzer.llm import build_llm_input
from app.analyzer.web_observation_projection import (
    WEB_LIMITATION, WEB_NEXT_STEP,
    WebObservationProjectionError,
    project_web_observation,
)
from app.detector.web_attack import _bounded_decode, detect_web_observations
from app.main import analyze
from app.models.schemas import DetectionResult, Evidence, HttpContext, NormalizedEvent


START = datetime(2026, 10, 8, tzinfo=timezone.utc)


def _event(target: str, seconds: int = 0, status: int = 200, *, micros: int = 0):
    path, _, query = target.partition("?")
    return NormalizedEvent(
        timestamp=START + timedelta(seconds=seconds, microseconds=micros),
        event_type="http_request", source="access_log", user=None,
        src_ip="198.51.100.10", dst_ip=None, application=None,
        protocol="HTTP/1.1", user_agent=None, raw="",
        http=HttpContext("GET", path, status, 16, query or None),
    )


@pytest.mark.parametrize(("target", "kind", "pattern"), [
    ("/search?q=%27OR%201%3D1", "sql_injection_like", "SQLI_BOOLEAN_EXPRESSION"),
    ("/search?q=UNION%20SELECT%201", "sql_injection_like", "SQLI_UNION_SELECT"),
    ("/search?q=%27SELECT%201--", "sql_injection_like", "SQLI_COMMENT_SEQUENCE"),
    ("/search?q=%3Cscript%3E", "xss_like", "XSS_SCRIPT_ELEMENT"),
    ("/search?q=%3Cimg%20onerror%3D1%3E", "xss_like", "XSS_EVENT_HANDLER"),
    ("/search?q=javascript%3Aalert(1)", "xss_like", "XSS_SCRIPT_SCHEME"),
    ("/.env", "sensitive_resource_probing_like", "SENSITIVE_ENV_FILE"),
    ("/.git/config", "sensitive_resource_probing_like", "SENSITIVE_VCS_METADATA"),
    ("/config.bak", "sensitive_resource_probing_like", "SENSITIVE_CONFIG_FILE"),
])
def test_approved_patterns_are_typed_and_private(target, kind, pattern):
    result = detect_web_observations([_event(target)])[kind]
    safe = project_web_observation(kind, result)
    assert safe.pattern_id == pattern
    assert safe.request_count == 1
    assert safe.start_utc == safe.end_utc == START
    assert target not in repr(result) and target not in repr(safe)
    assert all(item.type in {"pattern_id", "request_count"} for item in result.evidence)


@pytest.mark.parametrize("target", [
    "/search?q=select", "/docs/union/select", "/search?q=%27",
    "/search?q=--", "/search?q=%GG",
    "/docs/sql-injection-guide?q=union%20select%20tutorial",
    "/docs/html-script-basics",
    "/assets/script.js", "/search?q=%26lt%3Bscript%26gt%3B",
    "/search?q=%3C", "/search?q=onboarding", "/admin",
    "/docs/configuration", "/docs/env-file", "/docs/backup-guide",
])
def test_normal_or_malformed_single_request_does_not_match(target):
    assert all(not item.is_detected for item in detect_web_observations([_event(target)]).values())


def test_bounded_canonicalization_and_legacy_semantics_separate():
    assert _bounded_decode("%2527OR%25201%253D1") == "'or 1=1"
    assert _bounded_decode("%GG") is None
    assert _bounded_decode("%00") is None
    assert _bounded_decode("/" + "a" * 2048) is None
    assert _bounded_decode("%41" * 700) is None
    assert _bounded_decode("+%41") == "+a"


def test_distinct_types_preserved_repeated_request_lines_counted_and_order_stable():
    mixed = _event("/search?q=%27OR%201%3D1%3Cscript%3E")
    other = _event("/search?q=UNION%20SELECT%201", 1)
    outputs = [detect_web_observations(list(order)) for order in permutations([mixed, other, mixed])]
    assert all(value == outputs[0] for value in outputs)
    assert outputs[0]["sql_injection_like"].is_detected
    assert outputs[0]["xss_like"].is_detected
    assert project_web_observation("sql_injection_like", outputs[0]["sql_injection_like"]).request_count == 3
    assert project_web_observation("xss_like", outputs[0]["xss_like"]).request_count == 2


def test_scan_requires_six_distinct_and_three_client_errors_in_sixty_seconds():
    events = [_event(f"/scan-{i}", i, 404 if i < 3 else 200) for i in range(6)]
    result = detect_web_observations(events)["web_scanning_like"]
    safe = project_web_observation("web_scanning_like", result)
    assert (safe.request_count, safe.distinct_target_count, safe.client_error_count) == (6, 6, 3)
    assert safe.time_window_seconds == 5
    assert detect_web_observations(events[:5])["web_scanning_like"].is_detected is False
    assert detect_web_observations(events[:-1] + [events[0]])["web_scanning_like"].is_detected is False
    assert detect_web_observations([replace(e, http=replace(e.http, status_code=200)) for e in events])["web_scanning_like"].is_detected is False
    assert detect_web_observations(list(reversed(events)))["web_scanning_like"] == result
    boundary = [replace(e, timestamp=START) for e in events[:5]] + [_event("/scan-5", 60)]
    over = boundary[:5] + [_event("/scan-5", 60, micros=1)]
    assert detect_web_observations(boundary)["web_scanning_like"].is_detected
    assert not detect_web_observations(over)["web_scanning_like"].is_detected


def test_scan_counts_repeated_line_but_deduplicates_only_target_identity():
    events = [_event(f"/scan-{i}", i, 404 if i < 3 else 200) for i in range(6)]
    repeated_line = events[0]
    results = [detect_web_observations(order)["web_scanning_like"]
               for order in (events + [repeated_line],
                             list(reversed(events + [repeated_line])))]
    assert results[0] == results[1]
    safe = project_web_observation("web_scanning_like", results[0])
    assert (safe.request_count, safe.distinct_target_count, safe.client_error_count) == (7, 6, 4)
    assert safe.time_window_seconds == 5


def test_scan_above_threshold_uses_one_maximal_earliest_window():
    events = [_event(f"/scan-{i}", i, 404 if i < 4 else 200) for i in range(7)]
    results = [detect_web_observations(order)["web_scanning_like"]
               for order in (events, list(reversed(events)))]
    assert results[0] == results[1]
    safe = project_web_observation("web_scanning_like", results[0])
    assert (safe.request_count, safe.distinct_target_count, safe.client_error_count) == (7, 7, 4)
    assert safe.time_window_seconds == 6


def test_scan_rejects_each_missing_condition_and_ineligible_request():
    events = [_event(f"/scan-{i}", i, 404 if i < 3 else 200) for i in range(6)]
    variants = [
        events[:5],  # request count
        events[:-1] + [replace(events[-1], http=replace(events[-1].http, path="/scan-0"))],
        [replace(events[0], http=replace(events[0].http, status_code=200))] + events[1:],
        [_event("/health", i, 404 if i < 3 else 200) for i in range(6)],
        [replace(events[0], timestamp=START.replace(tzinfo=None))] + events[1:],
        [replace(events[0], timestamp=None)] + events[1:],
        [replace(events[0], http=replace(events[0].http, status_code=None))] + events[1:],
        [replace(events[0], http=replace(events[0].http, path="/%GG"))] + events[1:],
    ]
    for candidate in variants:
        assert not detect_web_observations(candidate)["web_scanning_like"].is_detected


def test_scan_overlapping_windows_emit_one_deterministic_observation():
    events = [_event(f"/scan-{i}", i * 10, 404 if i < 4 else 200) for i in range(8)]
    outputs = [detect_web_observations(list(order))["web_scanning_like"]
               for order in (events, list(reversed(events)))]
    assert outputs[0] == outputs[1]
    safe = project_web_observation("web_scanning_like", outputs[0])
    assert (safe.request_count, safe.distinct_target_count, safe.client_error_count) == (7, 7, 4)
    assert safe.time_window_seconds == 60


def test_scan_bounded_permutations_preserve_same_fact():
    events = [_event(f"/scan-{i}", i, 404 if i < 3 else 200) for i in range(6)]
    expected = detect_web_observations(events)["web_scanning_like"]
    for prefix in permutations(events[:3]):
        assert detect_web_observations(list(prefix) + events[3:])["web_scanning_like"] == expected


def test_scan_requests_distributed_across_subjects_do_not_combine(tmp_path):
    fixture = Path(__file__).resolve().parents[1] / "sample_logs" / "evaluation" / "web_scan_exact.log"
    lines = fixture.read_text(encoding="utf-8").splitlines()
    split = [line.replace("198.51.100.10", "198.51.100.11") if index < 3 else line
             for index, line in enumerate(lines)]
    source = tmp_path / "split.log"
    source.write_text("\n".join(split) + "\n", encoding="utf-8")
    results = analyze([{"source": "access", "path": str(source)}])["results"]
    assert set(results) == {"198.51.100.10", "198.51.100.11"}
    assert all(not result["detections"]["web_scanning_like"].is_detected
               for result in results.values())


def test_malformed_projection_fails_closed_without_private_value():
    detected = detect_web_observations([_event("/search?q=UNION%20SELECT%201")])["sql_injection_like"]
    bad = DetectionResult(True, detected.detection_type, [
        Evidence("pattern_id", "PRIVATE-CANARY-target", "web_observation_detector", time_range=(START, START)),
        detected.evidence[1],
    ])
    with pytest.raises(WebObservationProjectionError) as raised:
        project_web_observation("sql_injection_like", bad)
    assert "PRIVATE-CANARY" not in str(raised.value)
    with pytest.raises(WebObservationProjectionError):
        project_web_observation("sql_injection_like", DetectionResult(True, "sql_injection_like", detected.evidence + [Evidence("raw_path", "/private", "web_observation_detector")]))


def test_unknown_risk_detection_slot_is_rejected():
    with pytest.raises(ValueError, match="Unsupported detection contract"):
        _web_types({"unreviewed_web_rule": DetectionResult(True, "unreviewed_web_rule", [])})


def test_local_api_and_html_show_safe_category_not_original_target():
    root = Path(__file__).resolve().parents[1] / "sample_logs"
    access = (root / "evaluation" / "web_sqli_union.log").read_bytes()
    access = access.replace(b"/search", b"/PRIVATEPATHCANARY")
    files = [
        ("application_file", ("private-a.log", (root / "brute_force.log").read_bytes(), "text/plain")),
        ("ssh_file", ("private-b.log", (root / "ssh_auth.log").read_bytes(), "text/plain")),
        ("access_file", ("private-c.log", access, "text/plain")),
    ]
    client = TestClient(create_app(), base_url="http://127.0.0.1:8000", client=("127.0.0.1", 50000))
    response = client.post("/api/v1/investigations", files=files)
    assert response.status_code == 200
    body = response.json()
    assert any(item["display_type"] == "SQL Injection-like" for item in body["independent_observations"])
    html = body["report_export"]["html"]
    assert _CONTENT_SECURITY_POLICY in html
    assert "SQL Injection-like" in html
    assert "SQL 결합 조회 구문" in html
    assert body["report_export"]["byte_count"] == len(html.encode("utf-8"))
    for private in ("PRIVATEPATHCANARY", "UNION SELECT", "private-c.log"):
        assert private not in response.text
    assert "<script" not in html.casefold()


@pytest.mark.parametrize(("fixture", "display", "category", "private_target"), [
    ("web_xss_script.log", "XSS-like", "스크립트 요소 구문", "%3Cscript%3E"),
    ("web_sensitive_env.log", "Sensitive Resource Probing-like", "환경 설정 파일 탐색", "/.env"),
    ("web_scan_exact.log", "Web Scanning-like", "여러 대상·클라이언트 오류 관찰", "/scan-a"),
])
def test_each_other_type_reaches_local_api_as_independent_safe_observation(
    fixture, display, category, private_target,
):
    root = Path(__file__).resolve().parents[1] / "sample_logs"
    files = [
        ("application_file", ("a.log", (root / "brute_force.log").read_bytes(), "text/plain")),
        ("ssh_file", ("b.log", (root / "ssh_auth.log").read_bytes(), "text/plain")),
        ("access_file", ("c.log", (root / "evaluation" / fixture).read_bytes(), "text/plain")),
    ]
    client = TestClient(create_app(), base_url="http://127.0.0.1:8000", client=("127.0.0.1", 50000))
    response = client.post("/api/v1/investigations", files=files)
    assert response.status_code == 200
    body = response.json()
    independent = next(item for item in body["independent_observations"] if item["display_type"] == display)
    assert independent["evidence"][0]["value"] == category
    assert independent["limitation"] and independent["next_step"]
    assert category in body["report_export"]["html"]
    assert body["case_summary"]["case_count"] == 2
    assert private_target not in response.text


@pytest.mark.parametrize(("fixture", "kind", "display"), [
    ("web_sqli_union.log", "sql_injection_like", "SQL Injection-like"),
    ("web_xss_script.log", "xss_like", "XSS-like"),
    ("web_sensitive_env.log", "sensitive_resource_probing_like", "Sensitive Resource Probing-like"),
    ("web_scan_exact.log", "web_scanning_like", "Web Scanning-like"),
])
def test_each_new_type_is_safe_in_report_and_optional_llm_input(fixture, kind, display):
    path = Path(__file__).resolve().parents[1] / "sample_logs" / "evaluation" / fixture
    result = analyze([{"source": "access", "path": str(path)}])
    subject = result["results"]["198.51.100.10"]
    assert subject["detections"][kind].is_detected
    projection = build_investigation_report_projection(result)
    html = render_investigation_report_html(projection)
    llm = build_llm_input("198.51.100.10", subject)
    assert display in html
    assert WEB_LIMITATION[kind] in html
    assert WEB_NEXT_STEP[kind] in html
    assert llm["detections"][kind]["is_detected"] is True
    for forbidden in ("/search", "/.env", "/scan-", "UNION SELECT", "<script>"):
        assert forbidden not in html
        assert forbidden not in repr(llm)


def test_mismatched_new_type_fails_both_public_projections():
    path = Path(__file__).resolve().parents[1] / "sample_logs" / "evaluation" / "web_sqli_union.log"
    result = analyze([{"source": "access", "path": str(path)}])
    result["results"]["198.51.100.10"]["detections"]["sql_injection_like"].detection_type = "unreviewed_rule"
    with pytest.raises(IncidentCaseAdapterError) as case_error:
        project_investigation_cases_from_analysis(result)
    with pytest.raises(InvestigationReportProjectionError) as report_error:
        build_investigation_report_projection(result)
    assert "unreviewed_rule" not in str(case_error.value)
    assert "unreviewed_rule" not in str(report_error.value)


def test_scan_projection_and_html_are_input_order_independent(tmp_path):
    fixture = Path(__file__).resolve().parents[1] / "sample_logs" / "evaluation" / "web_scan_exact.log"
    lines = fixture.read_text(encoding="utf-8").splitlines()
    lines.append(lines[0].replace("198.51.100.10", "2001:db8::10"))
    first = tmp_path / "forward.log"
    reverse = tmp_path / "reverse.log"
    first.write_text("\n".join(lines) + "\n", encoding="utf-8")
    reverse.write_text("\n".join(reversed(lines)) + "\n", encoding="utf-8")
    outputs = []
    for source in (first, reverse):
        raw = analyze([{"source": "access", "path": str(source)}])
        cases = project_investigation_cases_from_analysis(raw)
        html = render_investigation_report_html(build_investigation_report_projection(raw))
        outputs.append((cases, html))
    assert outputs[0] == outputs[1]
