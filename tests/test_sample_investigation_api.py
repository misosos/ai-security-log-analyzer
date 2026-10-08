import asyncio
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import threading

from fastapi.testclient import TestClient
from starlette.requests import Request
import pytest

import app.api as api
import app.sample_investigation_api as sample
from app.analyzer.incident_case_adapter import project_investigation_cases_from_analysis
from app.main import analyze


EXPECTED_TOP_LEVEL = {
    "schema_version", "sample_context", "analysis_summary", "case_summary",
    "cases", "independent_observations", "interpretation_notices",
    "capabilities", "bounded_warnings", "report_export",
}
EXPECTED_CASE_SUMMARY = {
    "case_count": 2,
    "independent_observation_count": 3,
    "high_case_count": 1,
    "medium_case_count": 0,
    "low_case_count": 1,
    "relation_case_count": 2,
    "no_time_observation_count": 0,
}
EXPECTED_ANALYSIS_SUMMARY = {
    "analyzed_subject_count": 10,
    "supported_detection_count": 4,
    "supported_relation_count": 3,
}


def _client():
    return TestClient(api.create_app())


def test_sample_success_has_fixed_counts_order_labels_and_capabilities():
    client = _client()
    response = client.post("/api/v1/investigations/sample")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    body = response.json()
    assert set(body) == EXPECTED_TOP_LEVEL
    assert body["schema_version"] == "1"
    assert body["sample_context"] == {
        "label": "합성 샘플 결과",
        "environment_notice": "실제 조직 환경의 보안 상태가 아닙니다.",
        "certificate_notice": "보안 점검 인증서가 아닙니다.",
    }
    assert body["analysis_summary"] == EXPECTED_ANALYSIS_SUMMARY
    assert body["case_summary"] == EXPECTED_CASE_SUMMARY
    assert [(case["review_order"], case["case_label"]) for case in body["cases"]] == [
        (1, "조사 사례 1"), (2, "조사 사례 2")
    ]
    assert body["cases"][0]["supported_detections"] == ["Brute Force"]
    assert body["cases"][0]["supported_relations"] == [
        "Brute Force → Successful Login", "Failed Login → Successful Login"
    ]
    assert [item["display_type"] for item in body["independent_observations"]] == [
        "Brute Force", "Password Spraying-like", "Path Traversal"
    ]
    assert "형식이 보장된 내부 계약" in body["independent_observations"][1]["reason"]
    assert [entry["category"] for entry in body["cases"][0]["timeline"]] == [
        "DETECTION_OBSERVATION", "OBSERVED_FACT", "SUPPORTED_RELATION",
        "SUPPORTED_RELATION", "OBSERVED_FACT",
    ]
    assert body["cases"][0]["timeline"][0]["start_time"]["display_kst"].endswith("KST (UTC+09:00)")
    assert body["cases"][0]["timeline"][0]["start_time"]["display_utc"].endswith("Z")
    assert body["cases"][0]["account_alias_state"] == "unavailable"
    assert body["cases"][0]["account_alias_message"] == (
        "계정 별칭을 표시할 수 없음. 원래 계정 정보는 개인정보 보호를 위해 결과에 포함되지 않습니다."
    )
    assert body["capabilities"] == {
        "html_report_available": False,
        "llm_summary_available": False,
        "linux_audit_aggregate_available": False,
        "actual_log_upload_available": False,
    }
    assert body["report_export"]["available"] is False
    assert len(body["interpretation_notices"]) == 5
    assert body["bounded_warnings"] == []


def test_identical_requests_are_deeply_equal_and_no_generated_identifier():
    first = _client().post("/api/v1/investigations/sample").json()
    second = _client().post("/api/v1/investigations/sample").json()
    assert first == second
    assert "analysis_id" not in json.dumps(first, ensure_ascii=False)


@pytest.mark.parametrize("kwargs", [
    {"json": {"fixture": "anything"}},
    {"data": {"fixture": "anything"}},
    {"files": {"file": ("upload.log", b"x", "text/plain")}},
    {"content": b"x"},
    {"content": b"x" * 100_000},
    {"content": b"", "headers": {"content-type": "application/json"}},
])
def test_body_and_content_type_are_rejected_with_bounded_error(kwargs):
    response = _client().post("/api/v1/investigations/sample", **kwargs)
    assert response.status_code == 400
    assert response.json()["error_code"] == "NON_EMPTY_BODY"
    assert set(response.json()) == {"error_code", "user_message", "recovery_action", "retryable"}
    assert "upload.log" not in response.text


def test_query_and_get_are_rejected_and_existing_routes_remain():
    client = _client()
    query = client.post("/api/v1/investigations/sample?fixture=anything")
    assert query.status_code == 400
    assert query.json()["error_code"] == "QUERY_NOT_ALLOWED"
    assert client.get("/api/v1/investigations/sample").status_code == 405
    assert client.get("/api/health").json() == {"status": "ok"}
    paths = client.app.openapi()["paths"]
    assert "/api/v1/investigations/sample" in paths
    assert set(paths["/api/v1/investigations/sample"]) == {"post"}
    assert "/api/analyze" in paths
    assert "/api/analyze-linux-audit" not in paths


def test_fixture_allowlist_is_fixed_and_no_cwd_or_environment_dependence(monkeypatch, tmp_path):
    assert len(sample._FIXTURES) == 3
    expected = tuple(sample._fixture_bytes(item) for item in sample._FIXTURES)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SAMPLE_FIXTURE_PATH", str(tmp_path))
    assert tuple(sample._fixture_bytes(item) for item in sample._FIXTURES) == expected
    assert _client().post("/api/v1/investigations/sample").status_code == 200


@pytest.mark.parametrize("mode", ["missing", "empty", "oversized", "modified", "symlink"])
def test_fixture_validation_fails_closed_without_path_leak(monkeypatch, tmp_path, mode):
    original = sample._FIXTURES[0]
    fixture = tmp_path / original.basename
    if mode == "empty":
        fixture.write_bytes(b"")
    elif mode == "oversized":
        fixture.write_bytes(b"x" * (sample._MAX_FIXTURE_BYTES + 1))
    elif mode == "modified":
        fixture.write_bytes(b"modified synthetic content")
    elif mode == "symlink":
        fixture.symlink_to(Path(sample._SAMPLE_DIR) / original.basename)
    monkeypatch.setattr(sample, "_SAMPLE_DIR", tmp_path)
    with pytest.raises(sample._FixtureUnavailable) as caught:
        sample._fixture_bytes(original)
    assert str(tmp_path) not in str(caught.value)
    assert original.basename not in repr(caught.value)
    response = _client().post("/api/v1/investigations/sample")
    assert response.status_code == 503
    assert response.json()["error_code"] == "FIXTURE_UNAVAILABLE"
    assert str(tmp_path) not in response.text


def test_fixture_digest_is_pinned_and_sample_files_have_no_secret_values():
    for item in sample._FIXTURES:
        data = sample._fixture_bytes(item)
        assert hashlib.sha256(data).hexdigest() == item.sha256
        assert not any(marker in data for marker in (
            b"BEGIN PRIVATE KEY", b"Authorization: Bearer ", b"AKIA",
            b"password=", b"token=", b"cookie=", b"/Users/", b"/home/",
        ))


def test_success_calls_analysis_and_adapter_once_without_other_pipelines(monkeypatch):
    calls = {"analyze": 0, "project": 0}

    def tracked_analyze(sources):
        calls["analyze"] += 1
        assert [source["source"] for source in sources] == ["application", "ssh", "access"]
        return analyze(sources)

    def tracked_project(result):
        calls["project"] += 1
        return project_investigation_cases_from_analysis(result)

    monkeypatch.setattr(api, "analyze", tracked_analyze)
    monkeypatch.setattr(api, "project_investigation_cases_from_analysis", tracked_project)
    response = _client().post("/api/v1/investigations/sample")
    assert response.status_code == 200
    assert calls == {"analyze": 1, "project": 1}


def test_unrelated_llm_linux_audit_and_html_boundaries_are_not_called(monkeypatch):
    import socket
    import app.analyzer.llm as llm
    import app.analyzer.html_report as html_report
    import app.analyzer.html_report_file as html_writer
    import app.analyzer.linux_audit_api as linux_audit

    def forbidden(*_args, **_kwargs):
        raise AssertionError("unrelated boundary was called")

    monkeypatch.setattr(llm.genai, "Client", forbidden)
    monkeypatch.setattr(html_report, "render_investigation_report_html", forbidden)
    monkeypatch.setattr(html_writer, "write_investigation_report_html", forbidden)
    monkeypatch.setattr(linux_audit, "analyze_staged_linux_audit_inputs", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    assert _client().post("/api/v1/investigations/sample").status_code == 200


def test_rate_limit_is_exposed_as_bounded_429():
    client = _client()
    for _ in range(sample._RATE_CAPACITY):
        assert client.post("/api/v1/investigations/sample").status_code == 200
    rejected = client.post("/api/v1/investigations/sample")
    assert rejected.status_code == 429
    assert rejected.json()["error_code"] == "RATE_LIMITED"
    assert rejected.json()["retryable"] is True


def test_case_projection_failure_is_distinct_and_bounded(monkeypatch):
    def broken(_result):
        raise sample.IncidentCaseAdapterError("invalid_timestamp")

    monkeypatch.setattr(api, "project_investigation_cases_from_analysis", broken)
    response = _client().post("/api/v1/investigations/sample")
    assert response.status_code == 500
    assert response.json()["error_code"] == "CASE_PROJECTION_FAILED"
    assert "invalid_timestamp" not in response.text


def test_rate_and_concurrency_budgets_are_fixed_and_client_free(monkeypatch):
    now = [100.0]
    monkeypatch.setattr(sample.time, "monotonic", lambda: now[0])
    limiter = sample._SampleLimit()
    assert limiter.admit() is None
    assert limiter.admit() is None
    assert limiter.admit() == "CONCURRENCY_LIMIT"
    assert len(limiter._requests) == 3
    limiter.release()
    limiter.release()
    for _ in range(sample._RATE_CAPACITY - 3):
        assert limiter.admit() is None
        limiter.release()
    assert limiter.admit() == "RATE_LIMITED"
    assert len(limiter._requests) == sample._RATE_CAPACITY
    assert not hasattr(limiter, "_clients")
    now[0] += sample._RATE_WINDOW_SECONDS
    assert limiter.admit() is None
    limiter.release()


def test_timeout_keeps_slot_until_worker_finishes_and_consumes_exception(monkeypatch):
    entered = threading.Event()
    release = threading.Event()
    monkeypatch.setattr(sample, "_CONCURRENT_CAPACITY", 1)
    monkeypatch.setattr(sample, "_TIMEOUT_SECONDS", 0.01)

    def blocked_analyze(_sources):
        entered.set()
        release.wait(10)
        raise RuntimeError("PRIVATE_INTERNAL_EXCEPTION")

    endpoint = sample.create_sample_endpoint(blocked_analyze, lambda result: result)

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    def request():
        return Request({"type": "http", "query_string": b"", "headers": []}, receive)

    limiter = next(
        cell.cell_contents for cell in endpoint.__closure__
        if isinstance(cell.cell_contents, sample._SampleLimit)
    )

    async def exercise():
        first = await endpoint(request())
        assert first.status_code == 503
        assert b"ANALYSIS_TIMEOUT" in first.body
        assert entered.is_set()
        second = await endpoint(request())
        assert second.status_code == 429
        assert b"CONCURRENCY_LIMIT" in second.body
        release.set()
        for _ in range(100):
            await asyncio.sleep(0.001)
            if limiter._active == 0:
                break
        assert limiter._active == 0
        monkeypatch.setattr(sample, "_TIMEOUT_SECONDS", 1.0)
        third = await endpoint(request())
        assert third.status_code == 500
        assert b"PRIVATE_INTERNAL_EXCEPTION" not in third.body

    asyncio.run(exercise())


def test_response_failure_is_bounded_and_not_zero_result(monkeypatch):
    def broken(_sources):
        raise RuntimeError("PRIVATE_INTERNAL_EXCEPTION")

    monkeypatch.setattr(api, "analyze", broken)
    response = _client().post("/api/v1/investigations/sample")
    assert response.status_code == 500
    assert response.json()["error_code"] == "ANALYSIS_FAILED"
    assert "PRIVATE_INTERNAL_EXCEPTION" not in response.text
    assert "case_count" not in response.text


def test_response_contains_no_raw_fixture_or_internal_private_values(capsys):
    response = _client().post("/api/v1/investigations/sample")
    assert response.status_code == 200
    body = response.text
    for canary in (
        "ACCOUNT_REFERENCE_UNAVAILABLE", "brute_force.log", "ssh_auth.log",
        "web_shell.log", "/Users/", "../../etc/passwd", "UNION SELECT",
        "admin", "alice", "Authorization: Bearer", "PROCTITLE", "CWD=",
        "PRIVATE_INTERNAL_EXCEPTION", "global_correlation", "<script",
    ):
        assert canary not in body
    captured = capsys.readouterr()
    assert "PRIVATE_INTERNAL_EXCEPTION" not in captured.out + captured.err


def test_model_repr_and_openapi_examples_have_no_fixture_or_account_values():
    result = sample._execute(analyze, project_investigation_cases_from_analysis)
    serialized = repr(result) + json.dumps(_client().app.openapi(), ensure_ascii=False)
    for canary in (
        "brute_force.log", "ssh_auth.log", "web_shell.log", "admin",
        "alice", "../../etc/passwd", "ACCOUNT_REFERENCE_UNAVAILABLE",
    ):
        assert canary not in serialized


def test_empty_projection_yields_two_fixed_non_safety_warnings():
    from app.analyzer.incident_case import assemble_incident_cases
    from app.analyzer.incident_case_projection import build_investigation_case_projection

    projection = build_investigation_case_projection(assemble_incident_cases(()))
    body = sample.build_sample_response({"results": {}, "global_correlation": {}}, projection)
    assert body.case_summary.case_count == 0
    assert body.bounded_warnings == (
        "지원되는 규칙으로 구성된 조사 사례가 없습니다.",
        "이 결과는 보안 문제가 없다는 의미가 아닙니다.",
    )


def test_response_invariant_failure_is_bounded():
    from app.analyzer.incident_case import assemble_incident_cases
    from app.analyzer.incident_case_projection import build_investigation_case_projection

    projection = build_investigation_case_projection(assemble_incident_cases(()))
    invalid = replace(projection, summary=replace(projection.summary, high_case_count=1))
    with pytest.raises(sample._ResponseInvalid):
        sample.build_sample_response({"results": {}, "global_correlation": {}}, invalid)
