"""Contracts for the explicit, read-only investigation checklist API/UI."""

import json
import pytest


def test_checklist_api_module_exposes_closed_request_and_endpoint_factory():
    from app.investigation_checklist_api_36_3 import (
        ChecklistRequest,
        ChecklistRegistry,
        create_checklist_endpoint,
    )

    assert ChecklistRequest is not None
    assert ChecklistRegistry is not None
    assert callable(create_checklist_endpoint)


def test_checklist_registry_uses_request_scoped_opaque_refs_only():
    from app.investigation_checklist_api_36_3 import ChecklistRegistry

    registry = ChecklistRegistry()
    assert registry.size == 0


@pytest.mark.parametrize("bad_json", [
    b'{"schema_version":1,"case_ref":"c_0123456789abcdef01234567","case_ref":"c_0123456789abcdef01234567"}',
    b'{"schema_version":NaN,"case_ref":"c_0123456789abcdef01234567"}',
])
def test_checklist_api_rejects_ambiguous_or_nonfinite_json(bad_json):
    from app.investigation_checklist_api_36_3 import parse_checklist_request

    with pytest.raises(ValueError):
        parse_checklist_request(bad_json)


def test_checklist_api_response_is_closed_and_separates_review_priority_from_risk():
    from app.investigation_checklist_api_36_3 import ChecklistResponse

    assert ChecklistResponse is not None


def test_explicit_post_returns_fixed_refusal_without_rerunning_analysis(monkeypatch):
    from fastapi.testclient import TestClient
    import app.api as api

    calls = 0
    real_analyze = api.analyze

    def counted(sources):
        nonlocal calls
        calls += 1
        return real_analyze(sources)

    monkeypatch.setattr(api, "analyze", counted)
    client = TestClient(api.create_app(), base_url="http://127.0.0.1",
                        client=("127.0.0.1", 12345))
    current = client.post("/api/v1/investigations/sample").json()
    assert calls == 1
    case_ref = current["cases"][0]["checklist_ref"]
    response = client.post("/api/v1/investigations/checklist",
                           json={"schema_version": 1, "case_ref": case_ref})
    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"schema", "status", "review_priority", "priority_meaning", "category",
                         "steps", "explanation", "uncertainty_codes", "limitation_codes",
                         "citations", "citation_meaning", "generated_by"}
    assert body["status"] == "available"
    assert body["review_priority"] == "undetermined"
    assert body["steps"]
    assert body["citations"]
    assert body["explanation"]["citation_ids"]
    assert body["priority_meaning"] == "analyst_review_order_only_not_security_risk"
    assert calls == 1
    repeat = client.post("/api/v1/investigations/checklist",
                         json={"schema_version": 1, "case_ref": case_ref})
    assert repeat.status_code == 200 and repeat.content == response.content
    assert calls == 1
    next_result = client.post("/api/v1/investigations/sample").json()
    stale = client.post("/api/v1/investigations/checklist",
                        json={"schema_version": 1, "case_ref": case_ref})
    assert stale.status_code == 404
    assert stale.json()["error_code"] == "NOT_FOUND"
    assert next_result["cases"][0]["checklist_ref"] != case_ref


def test_checklist_api_bytes_are_timezone_independent(monkeypatch):
    import os
    import time
    from fastapi.testclient import TestClient
    from app.api import create_app

    client = TestClient(create_app(), base_url="http://127.0.0.1",
                        client=("127.0.0.1", 12345))
    case_ref = client.post("/api/v1/investigations/sample").json()["cases"][0]["checklist_ref"]
    original = os.environ.get("TZ")
    try:
        bodies = []
        for zone in ("UTC", "Asia/Seoul", "UTC", "Asia/Seoul"):
            monkeypatch.setenv("TZ", zone)
            time.tzset()
            response = client.post("/api/v1/investigations/checklist", json={
                "schema_version": 1, "case_ref": case_ref,
            })
            assert response.status_code == 200
            bodies.append(response.content)
        assert bodies[0] == bodies[1] == bodies[2] == bodies[3]
    finally:
        if original is None:
            monkeypatch.delenv("TZ", raising=False)
        else:
            monkeypatch.setenv("TZ", original)
        time.tzset()


def test_refused_checklist_api_explains_non_safety_and_safe_next_steps(monkeypatch):
    from fastapi.testclient import TestClient
    import app.investigation_checklist_api_36_3 as endpoint_module
    import app.investigation_triage_36_1 as triage
    from app.api import create_app

    refused_item = triage.create_safe_investigation_dto(
        schema_version=1, request_id="r_0123456789abcdef01234567",
        case_ref="c_1123456789abcdef01234567", source_role="application",
        observation_categories=("web_request",), detection_codes=("path_traversal",),
        relation_codes=(), risk_band="UNKNOWN", case_status="open", event_count_bucket="1",
        time_window_bucket="unknown", evidence_completeness="complete", limitation_codes=(),
        corpus_digest=triage.CORPUS_DIGEST,
    )
    original_builder = endpoint_module.build_investigation_checklist
    monkeypatch.setattr(endpoint_module, "build_investigation_checklist",
                        lambda _item: original_builder(refused_item))
    client = TestClient(create_app(), base_url="http://127.0.0.1",
                        client=("127.0.0.1", 12345))
    analysis = client.post("/api/v1/investigations/sample").json()
    response = client.post("/api/v1/investigations/checklist", json={
        "schema_version": 1, "case_ref": analysis["cases"][0]["checklist_ref"]})
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "refused"
    text = body["explanation"]["text"]
    assert "안전 또는 비위험 판정이 아닙니다" in text
    assert "기존 결정적 분석 결과를 확인" in text
    assert "승인된 내부 분석 경로" in text
    assert "추측하지 않습니다" in text
    assert body["steps"] == [] and body["citations"] == []
    assert body["explanation"]["citation_ids"] == []


def test_checklist_openapi_declares_only_post_and_closed_body():
    from app.api import create_app

    schema = create_app().openapi()
    path = schema["paths"]["/api/v1/investigations/checklist"]
    assert set(path) == {"post"}
    operation = path["post"]
    body = operation["requestBody"]["content"]["application/json"]["schema"]
    assert body["type"] == "object" and body["additionalProperties"] is False
    assert body["required"] == ["schema_version", "case_ref"]
    assert set(body["properties"]) == {"schema_version", "case_ref"}


def test_checklist_api_rejects_invalid_body_and_fixed_not_found(monkeypatch):
    from fastapi.testclient import TestClient
    from app.api import create_app

    client = TestClient(create_app(), base_url="http://127.0.0.1",
                        client=("127.0.0.1", 12345))
    for raw in (
        b'{"schema_version":1,"case_ref":"c_0123456789abcdef01234567","extra":1}',
        b'{"schema_version":true,"case_ref":"c_0123456789abcdef01234567"}',
        b'{"schema_version":1,"case_ref":"c_0123456789abcdef01234567","case_ref":"c_0123456789abcdef01234567"}',
        b'{"schema_version":1,"case_ref":"c_0123456789abcdef01234567"}\xff',
        b'{"schema_version":1,"case_ref":"c_0123456789abcdef01234567","x":"\\ud800"}',
        b'{"schema_version":1,"case_ref":"c_0123456789ab\\ud8001234567"}',
    ):
        response = client.post("/api/v1/investigations/checklist", content=raw,
                               headers={"content-type": "application/json"})
        assert response.status_code == 400
        assert response.json()["error_code"] == "INVALID_REQUEST"
        assert set(response.json()) == {"error_code", "user_message"}
    missing = client.post("/api/v1/investigations/checklist", json={
        "schema_version": 1, "case_ref": "c_0123456789abcdef01234567"})
    assert missing.status_code == 404
    assert missing.json()["error_code"] == "NOT_FOUND"


def test_server_case_adapter_drops_private_and_untrusted_public_fields():
    from app.analyzer.incident_case_projection import InvestigationCaseDetailProjection
    from types import SimpleNamespace
    from app.investigation_checklist_api_36_3 import trusted_case_fields_from_projection

    canary = "acct-35.6 198.51.100.9 2001:db8::9 private.example /synthetic/private.log RAW-CANARY"
    case = object.__new__(InvestigationCaseDetailProjection)
    object.__setattr__(case, "timeline_entries", (SimpleNamespace(
        detection_display_name="Brute Force", relation_display_name="Failed Login → Successful Login",
        subject_ip=canary, start_time=canary,
    ),))
    object.__setattr__(case, "timeline_entries_without_time", ())
    object.__setattr__(case, "row", SimpleNamespace(included_highest_risk="HIGH",
        observation_count=7, subject_ip=canary, account_name=canary))
    object.__setattr__(case, "limitations", ())
    values = trusted_case_fields_from_projection(case)
    serialized = json.dumps(values, ensure_ascii=False)
    assert canary not in serialized
    assert values["source_role"] == "unknown"
    assert values["request_id"] is None and values["case_ref"] is None
    assert "subject_ip" not in values and "start_time" not in values


def test_global_case_rate_concurrency_and_late_release_are_bounded(monkeypatch):
    import app.investigation_checklist_api_36_3 as module

    limits = module._Limits()
    assert limits.admit("c_0123456789abcdef01234567") is None
    assert limits.admit("c_0123456789abcdef01234567") is None
    assert limits.admit("c_0123456789abcdef01234567") == "BUSY"
    limits.release()
    limits.release()
    monkeypatch.setattr(module, "CASE_RATE_LIMIT", 1)
    limited = module._Limits()
    assert limited.admit("c_1123456789abcdef01234567") is None
    limited.release()
    assert limited.admit("c_1123456789abcdef01234567") == "RATE_LIMITED"


def test_validation_error_does_not_echo_request_canary():
    from fastapi.testclient import TestClient
    from app.api import create_app

    canary = "acct-36.3 198.51.100.77 host-canary /private/path TOKEN-CANARY"
    client = TestClient(create_app(), base_url="http://127.0.0.1",
                        client=("127.0.0.1", 12345))
    response = client.post("/api/v1/investigations/checklist", json={
        "schema_version": 1, "case_ref": "c_0123456789abcdef01234567", "extra": canary,
    })
    assert response.status_code == 400
    assert canary not in response.text
    assert "extra" not in response.text


@pytest.mark.parametrize("fault", ["corpus", "response"])
def test_faults_fail_closed_without_partial_output_and_recover(monkeypatch, fault):
    from fastapi.testclient import TestClient
    import app.investigation_checklist_api_36_3 as module
    from app.api import create_app

    client = TestClient(create_app(), base_url="http://127.0.0.1",
                        client=("127.0.0.1", 12345))
    case_ref = client.post("/api/v1/investigations/sample").json()["cases"][0]["checklist_ref"]
    original = module._response
    if fault == "corpus":
        monkeypatch.setattr(module, "create_safe_investigation_dto",
                            lambda **_values: (_ for _ in ()).throw(module.ChecklistError("CORPUS_UNAVAILABLE")))
    else:
        monkeypatch.setattr(module, "_response", lambda *_args: (_ for _ in ()).throw(RuntimeError("PRIVATE-EXCEPTION-CANARY")))
    failed = client.post("/api/v1/investigations/checklist",
                         json={"schema_version": 1, "case_ref": case_ref})
    assert failed.status_code == 503
    assert failed.json()["error_code"] == "UNAVAILABLE"
    assert set(failed.json()) == {"error_code", "user_message"}
    assert "PRIVATE-EXCEPTION-CANARY" not in failed.text
    if fault == "corpus":
        monkeypatch.undo()
    else:
        monkeypatch.setattr(module, "_response", original)
    recovered = client.post("/api/v1/investigations/checklist",
                            json={"schema_version": 1, "case_ref": case_ref})
    assert recovered.status_code == 200


def test_endpoint_timeout_is_fixed_and_background_work_releases_admission(monkeypatch):
    import threading
    import time
    from fastapi.testclient import TestClient
    import app.investigation_checklist_api_36_3 as module
    from app.api import create_app

    client = TestClient(create_app(), base_url="http://127.0.0.1",
                        client=("127.0.0.1", 12345))
    case_ref = client.post("/api/v1/investigations/sample").json()["cases"][0]["checklist_ref"]
    entered, release = threading.Event(), threading.Event()
    original = module.build_investigation_checklist

    def blocked(item):
        entered.set()
        release.wait(1.0)
        return original(item)

    monkeypatch.setattr(module, "build_investigation_checklist", blocked)
    monkeypatch.setattr(module, "REQUEST_TIMEOUT_SECONDS", 0.01)
    timed = client.post("/api/v1/investigations/checklist",
                        json={"schema_version": 1, "case_ref": case_ref})
    assert timed.status_code == 503
    assert timed.json()["error_code"] == "TIMEOUT"
    assert set(timed.json()) == {"error_code", "user_message"}
    assert entered.wait(0.5)
    release.set()
    time.sleep(0.05)
    monkeypatch.setattr(module, "build_investigation_checklist", original)
    monkeypatch.setattr(module, "REQUEST_TIMEOUT_SECONDS", 3.0)
    recovered = client.post("/api/v1/investigations/checklist",
                            json={"schema_version": 1, "case_ref": case_ref})
    assert recovered.status_code == 200


def test_cancelled_client_does_not_mutate_analysis_and_next_request_succeeds(monkeypatch):
    import asyncio
    import threading
    import time
    import httpx
    from fastapi.testclient import TestClient
    import app.investigation_checklist_api_36_3 as module
    from app.api import create_app

    app = create_app()
    case_ref = TestClient(app, base_url="http://127.0.0.1",
                          client=("127.0.0.1", 12345)).post(
        "/api/v1/investigations/sample").json()["cases"][0]["checklist_ref"]
    entered, release = threading.Event(), threading.Event()
    original = module.build_investigation_checklist

    def blocked(item):
        entered.set(); release.wait(1.0); return original(item)

    monkeypatch.setattr(module, "build_investigation_checklist", blocked)

    async def exercise():
        transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 12345))
        async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
            pending = asyncio.create_task(client.post("/api/v1/investigations/checklist",
                json={"schema_version": 1, "case_ref": case_ref}))
            reached = await asyncio.to_thread(entered.wait, 0.5)
            assert reached
            pending.cancel()
            with pytest.raises(asyncio.CancelledError):
                await pending
            release.set()
            await asyncio.sleep(0.05)
            return await client.post("/api/v1/investigations/checklist",
                json={"schema_version": 1, "case_ref": case_ref})

    recovered = asyncio.run(exercise())
    monkeypatch.setattr(module, "build_investigation_checklist", original)
    assert recovered.status_code == 200
