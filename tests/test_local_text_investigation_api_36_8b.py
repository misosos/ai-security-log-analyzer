"""Contracts for the bounded, loopback-only single-source text endpoint."""

from pathlib import Path
import json
import stat
import base64
import asyncio
from concurrent.futures import ThreadPoolExecutor
from threading import Event

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from app.api import create_app
from app.security.linux_audit_api import (
    LinuxAuditApiAccessAuditSink, LinuxAuditApiSecurityConfig,
)


ROOT = Path(__file__).resolve().parents[1]
SAMPLES = {
    "application": ROOT / "sample_logs" / "brute_force.log",
    "ssh": ROOT / "sample_logs" / "ssh_auth.log",
    "access": ROOT / "sample_logs" / "web_shell.log",
}
TEXT_NOTICE = (
    "입력한 로그 범위에서만 분석한 결과입니다. 다른 로그나 누락된 시간대에 "
    "발생한 활동은 포함되지 않을 수 있습니다."
)


def _client(host="127.0.0.1"):
    authority = f"[{host}]" if ":" in host else host
    return TestClient(create_app(), base_url=f"http://{authority}:8000",
                      client=(host, 50000))


def _payload(source="ssh", text=None):
    return {
        "schema_version": 1,
        "source": source,
        "log_text": SAMPLES[source].read_text(encoding="utf-8") if text is None else text,
    }


def _post(client, payload=None, *, content=None, headers=None):
    if content is not None:
        return client.post("/api/v1/investigations/text", content=content,
                           headers=headers or {"Content-Type": "application/json"})
    return client.post("/api/v1/investigations/text", json=payload,
                       headers=headers or {})


@pytest.mark.parametrize("source,cases,independent", [
    ("application", 1, 2),
    ("ssh", 1, 0),
    ("access", 0, 2),
])
def test_single_source_samples_return_scoped_existing_analysis(source, cases, independent):
    response = _post(_client(), _payload(source))
    assert response.status_code == 200, response.text
    body = response.json()
    assert set(body) == {"schema_version", "input_scope", "result"}
    assert body["schema_version"] == "1"
    assert body["input_scope"] == {
        "mode": "text", "source": source, "notice_code": "PARTIAL_SINGLE_SOURCE"
    }
    result = body["result"]
    assert result["schema_version"] == "2"
    assert result["case_summary"]["case_count"] == cases
    assert result["case_summary"]["independent_observation_count"] == independent
    assert "지원되는 규칙으로 구성된 조사 사례가 없습니다." in result["bounded_warnings"] if cases == 0 else True
    assert TEXT_NOTICE in result["report_export"]["html"]
    assert result["report_export"]["byte_count"] == len(
        result["report_export"]["html"].encode("utf-8"))


@pytest.mark.parametrize("text", [
    SAMPLES["ssh"].read_text(encoding="utf-8"),
    SAMPLES["ssh"].read_text(encoding="utf-8").rstrip("\n"),
    SAMPLES["ssh"].read_text(encoding="utf-8").replace("\n", "\r\n"),
])
def test_multiline_lf_crlf_and_missing_final_lf_are_accepted(text):
    response = _post(_client(), _payload("ssh", text))
    assert response.status_code == 200, response.text
    assert response.json()["result"]["case_summary"]["case_count"] == 1


def test_text_response_registers_only_real_case_refs_and_checklist_is_explicit():
    client = _client()
    response = _post(client, _payload("ssh"))
    assert response.status_code == 200, response.text
    result = response.json()["result"]
    case = result["cases"][0]
    assert case["checklist_ref"].startswith("c_")
    before = json.dumps(result, sort_keys=True)
    checklist = client.post("/api/v1/investigations/checklist", json={
        "schema_version": 1, "case_ref": case["checklist_ref"]
    })
    assert checklist.status_code == 200, checklist.text
    assert checklist.json()["schema"] == "investigation-checklist/v2"
    assert checklist.json()["source_role"] == "ssh"
    citation_ids = {item["citation_id"] for item in checklist.json()["citations"]}
    assert all(set(step["citation_ids"]) <= citation_ids for step in checklist.json()["steps"])
    assert json.dumps(result, sort_keys=True) == before


def test_application_single_source_checklist_uses_observed_role_and_case():
    client = _client()
    response = _post(client, _payload("application"))
    assert response.status_code == 200, response.text
    result = response.json()["result"]
    assert result["case_summary"]["case_count"] == 1
    assert len(result["cases"]) == 1
    checklist = client.post("/api/v1/investigations/checklist", json={
        "schema_version": 1,
        "case_ref": result["cases"][0]["checklist_ref"],
    })
    assert checklist.status_code == 200, checklist.text
    assert checklist.json()["source_role"] == "application"


def test_access_single_source_does_not_fabricate_case_or_checklist_reference():
    response = _post(_client(), _payload("access"))
    assert response.status_code == 200, response.text
    result = response.json()["result"]
    assert result["cases"] == []
    assert result["case_summary"]["case_count"] == 0
    assert result["case_summary"]["independent_observation_count"] == 2


def test_text_report_has_scope_notice_but_existing_upload_report_does_not():
    client = _client()
    text_response = _post(client, _payload("ssh"))
    assert text_response.status_code == 200
    assert TEXT_NOTICE in text_response.json()["result"]["report_export"]["html"]

    upload = client.post("/api/v1/investigations", files=[
        (field, ("synthetic.log", path.read_bytes(), "text/plain"))
        for field, path in (
            ("application_file", SAMPLES["application"]),
            ("ssh_file", SAMPLES["ssh"]),
            ("access_file", SAMPLES["access"]),
        )
    ])
    assert upload.status_code == 200
    file_result = upload.json()
    assert set(file_result) == {
        "schema_version", "local_context", "analysis_summary", "case_summary", "cases",
        "independent_observations", "interpretation_notices", "capabilities",
        "bounded_warnings", "report_export",
    }
    assert TEXT_NOTICE not in file_result["report_export"]["html"]


@pytest.mark.parametrize("payload,code,status", [
    ({"schema_version": 1, "source": "ssh", "log_text": ""}, "EMPTY_INPUT", 400),
    ({"schema_version": 1, "source": "ssh", "log_text": " \n\t"}, "EMPTY_INPUT", 400),
    ({"schema_version": 1, "source": "unknown", "log_text": "x"}, "UNKNOWN_SOURCE", 422),
    ({"schema_version": 1, "log_text": "x"}, "INVALID_SCHEMA", 422),
    ({"schema_version": 1, "source": "ssh"}, "INVALID_SCHEMA", 422),
    ({"schema_version": 1, "source": "ssh", "log_text": "x", "extra": 1}, "INVALID_SCHEMA", 422),
    ({"schema_version": True, "source": "ssh", "log_text": "x"}, "INVALID_SCHEMA", 422),
    ({"schema_version": 2, "source": "ssh", "log_text": "x"}, "INVALID_SCHEMA", 422),
    ({"schema_version": 1, "source": "ssh", "log_text": {"nested": "x"}}, "INVALID_SCHEMA", 422),
    ({"schema_version": 1, "source": ["ssh"], "log_text": "x"}, "INVALID_SCHEMA", 422),
    ({"schema_version": 1, "source": "ssh", "log_text": 123}, "INVALID_SCHEMA", 422),
    ({"schema_version": 1, "source": "ssh", "log_text": "bad format"}, "PARSER_INCOMPATIBLE", 400),
], ids=["empty", "whitespace", "unknown-source", "missing-source", "missing-text",
        "unknown-field", "boolean-version", "wrong-version", "nested-text", "wrong-source-type",
        "wrong-text-type", "format-mismatch"])
def test_closed_request_and_source_validation(payload, code, status):
    response = _post(_client(), payload)
    assert response.status_code == status
    body = response.json()
    assert body["error_code"] == code
    assert set(body) == {"error_code", "user_message", "recovery_action", "retryable", "field"}


@pytest.mark.parametrize("body,code", [
    (b"{", "INVALID_JSON"),
    (b'{"schema_version":1,"schema_version":1,"source":"ssh","log_text":"x"}', "INVALID_JSON"),
    (b'{"schema_version":1,"source":"ssh","log_text":"\xff"}', "INVALID_UTF8"),
    (b'{"schema_version":1,"source":"ssh","log_text":"\\ud800"}', "INVALID_UTF8"),
    (b'{"schema_version":1,"source":"ssh","log_text":"x","unknown":1}', "INVALID_SCHEMA"),
    (b'{"schema_version":NaN,"source":"ssh","log_text":"x"}', "INVALID_JSON"),
    (b'{"schema_version":Infinity,"source":"ssh","log_text":"x"}', "INVALID_JSON"),
    (b'[{"schema_version":1,"source":"ssh","log_text":"x"}]', "INVALID_SCHEMA"),
], ids=["malformed", "duplicate-key", "invalid-utf8", "lone-surrogate", "unknown-field",
        "nan", "infinity", "array-root"])
def test_json_decode_duplicate_keys_and_utf8_errors_are_closed(body, code):
    response = _post(_client(), content=body)
    assert response.status_code in (400, 422)
    assert response.json()["error_code"] == code


@pytest.mark.parametrize("text,code", [
    ("2025-01-01 00:00:00 sshd: x\x00", "INVALID_TEXT"),
    ("2025-01-01 00:00:00 sshd: x\x01", "INVALID_TEXT"),
    ("2025-01-01 00:00:00 sshd: x\x7f", "INVALID_TEXT"),
    ("2025-01-01 00:00:00 sshd: x\r", "INVALID_TEXT"),
    ("2025-01-01 00:00:00 sshd: " + "x" * 3000, "LINE_TOO_LONG"),
    (("2025-01-01 00:00:00 x Failed password for u from 1.1.1.1\n" * 513), "LINE_COUNT_EXCEEDED"),
    (("2025-01-01 00:00:00 sshd: Failed password for user from 192.0.2.1 port 1 ssh2\n" * 500), "TEXT_TOO_LARGE"),
    (SAMPLES["access"].read_text(encoding="utf-8"), "PARSER_INCOMPATIBLE"),
    ], ids=["nul", "control", "del", "cr-only", "long-line", "too-many-lines", "text-too-large", "wrong-source"])
def test_text_bytes_lines_controls_and_source_format_are_enforced(text, code):
    response = _post(_client(), _payload("ssh", text))
    assert response.status_code == 413 if code in {"LINE_TOO_LONG", "LINE_COUNT_EXCEEDED", "TEXT_TOO_LARGE"} else response.status_code == 400
    assert response.json()["error_code"] == code


def test_wire_body_size_and_content_type_are_bounded():
    client = _client()
    oversized = b'{"schema_version":1,"source":"ssh","log_text":"' + b"x" * (96 * 1024) + b'"}'
    response = _post(client, content=oversized)
    assert response.status_code == 413
    assert response.json()["error_code"] == "ENVELOPE_TOO_LARGE"

    wrong_type = _post(client, content=b"{}", headers={"Content-Type": "text/plain"})
    assert wrong_type.status_code == 415
    assert wrong_type.json()["error_code"] == "INVALID_MEDIA_TYPE"

    charset = _post(_client(), content=json.dumps(_payload("ssh")).encode(),
                    headers={"Content-Type": "application/json; charset=utf-8"})
    assert charset.status_code == 200
    encoded = _post(_client(), content=b"{}",
                    headers={"Content-Type": "application/json", "Content-Encoding": "gzip"})
    assert encoded.status_code == 415
    assert encoded.json()["error_code"] == "INVALID_MEDIA_TYPE"


def test_actual_chunked_stream_is_limited_without_content_length():
    import app.local_investigation_api as local
    from starlette.requests import Request

    chunks = [b"x" * 60_000, b"y" * 40_000]

    async def receive():
        if chunks:
            return {"type": "http.request", "body": chunks.pop(0), "more_body": bool(chunks)}
        return {"type": "http.request", "body": b"", "more_body": False}

    request = Request({
        "type": "http", "method": "POST", "path": "/api/v1/investigations/text",
        "headers": [], "client": ("127.0.0.1", 50000),
    }, receive)
    with pytest.raises(local._TextInputError) as caught:
        asyncio.run(local._bounded_json_body(request))
    assert caught.value.code == "ENVELOPE_TOO_LARGE"


def test_declared_content_length_is_checked_without_unbounded_integer_parse():
    import app.local_investigation_api as local
    from starlette.requests import Request

    async def receive():
        raise AssertionError("oversized declaration must be rejected before reading")

    request = Request({
        "type": "http", "method": "POST", "path": "/api/v1/investigations/text",
        "headers": [(b"content-length", b"9" * 5000)],
        "client": ("127.0.0.1", 50000),
    }, receive)
    with pytest.raises(local._TextInputError) as caught:
        asyncio.run(local._bounded_json_body(request))
    assert caught.value.code == "ENVELOPE_TOO_LARGE"


def test_text_utf8_size_line_size_and_line_count_exact_boundaries():
    import app.local_investigation_api as local

    prefix = "2025-01-01 00:00:00 app event"
    exact_line = prefix + " " * (local._MAX_LINE_BYTES - len(prefix))
    assert len(exact_line.encode("utf-8")) == local._MAX_LINE_BYTES
    assert local._validate_text("application", exact_line)
    with pytest.raises(local._TextInputError) as caught:
        local._validate_text("application", exact_line + " ")
    assert caught.value.code == "LINE_TOO_LONG"

    # Each line remains individually valid; separators are counted as UTF-8 bytes.
    lengths = [local._MAX_LINE_BYTES - 1] * 15 + [local._MAX_LINE_BYTES]
    lines = [prefix + " " * (length - len(prefix)) for length in lengths]
    exact_text = "\n".join(lines)
    assert len(exact_text.encode("utf-8")) == local._MAX_TEXT_BYTES
    assert local._validate_text("application", exact_text)
    over_text = "\n".join([lines[0] + " ", *lines[1:]])
    assert len(over_text.encode("utf-8")) == local._MAX_TEXT_BYTES + 1
    with pytest.raises(local._TextInputError) as caught:
        local._validate_text("application", over_text)
    assert caught.value.code == "TEXT_TOO_LARGE"

    one_line = "2025-01-01 00:00:00 app event"
    exact_line_count = "\n".join([one_line] * local._MAX_LINES_PER_FILE)
    assert local._validate_text("application", exact_line_count)
    with pytest.raises(local._TextInputError) as caught:
        local._validate_text("application", "\n".join([one_line] * (local._MAX_LINES_PER_FILE + 1)))
    assert caught.value.code == "LINE_COUNT_EXCEEDED"

    unicode_line = prefix + " " + "가" * 700
    assert len(unicode_line) < len(unicode_line.encode("utf-8"))
    with pytest.raises(local._TextInputError) as caught:
        local._validate_text("application", unicode_line)
    assert caught.value.code == "LINE_TOO_LONG"


def test_bounded_json_body_accepts_exact_wire_limit_and_rejects_one_byte_over():
    import app.local_investigation_api as local
    from starlette.requests import Request

    async def request_for(body):
        chunks = [body[index:index + 8192] for index in range(0, len(body), 8192)]

        async def receive():
            if chunks:
                chunk = chunks.pop(0)
                return {"type": "http.request", "body": chunk, "more_body": bool(chunks)}
            return {"type": "http.request", "body": b"", "more_body": False}

        return Request({
            "type": "http", "method": "POST", "path": "/api/v1/investigations/text",
            "headers": [], "client": ("127.0.0.1", 50000),
        }, receive)

    async def exercise():
        exact = b"{}" + b" " * (local._MAX_TEXT_REQUEST_BYTES - 2)
        assert len(await local._bounded_json_body(await request_for(exact))) == local._MAX_TEXT_REQUEST_BYTES
        over = exact + b" "
        with pytest.raises(local._TextInputError) as caught:
            await local._bounded_json_body(await request_for(over))
        assert caught.value.code == "ENVELOPE_TOO_LARGE"

    asyncio.run(exercise())


def test_body_receive_timeout_returns_slot_and_does_not_start_analysis(monkeypatch):
    import app.local_investigation_api as local
    from app.api import (
        _analyze_checklist_input, build_investigation_report_projection,
        project_investigation_cases_from_analysis,
    )
    from starlette.requests import Request

    monkeypatch.setattr(local, "_UPLOAD_TIMEOUT_SECONDS", 0.001)
    admission = local.create_local_admission()
    endpoint = local.create_local_text_endpoint(
        _analyze_checklist_input, project_investigation_cases_from_analysis,
        build_investigation_report_projection, admission=admission,
    )

    async def receive():
        await asyncio.sleep(0.02)
        return {"type": "http.request", "body": b"{}", "more_body": False}

    request = Request({
        "type": "http", "scheme": "http", "method": "POST",
        "path": "/api/v1/investigations/text", "query_string": b"",
        "client": ("127.0.0.1", 50000),
        "headers": [(b"host", b"127.0.0.1:8000"),
                    (b"content-type", b"application/json")],
    }, receive)
    response = asyncio.run(endpoint(request))
    assert response.status_code == 503
    assert json.loads(response.body)["error_code"] == "BODY_TIMEOUT"
    assert admission.admit() is None
    admission.release()


def test_rate_limit_state_is_scoped_to_each_app_instance():
    first = _client()
    second = _client()
    for _ in range(6):
        assert _post(first, content=b"{").json()["error_code"] == "INVALID_JSON"
    assert _post(first, content=b"{").json()["error_code"] == "RATE_LIMITED"
    assert _post(second, content=b"{").json()["error_code"] == "INVALID_JSON"


@pytest.mark.parametrize("source", ["application", "ssh", "access"])
def test_text_api_semantic_summary_matches_direct_existing_pipeline(source):
    from app.analyzer.incident_case_adapter import project_investigation_cases_from_analysis
    from app.main import analyze_with_source_role_snapshot

    path = SAMPLES[source]
    direct = analyze_with_source_role_snapshot(({"source": source, "path": str(path)},))
    projection = project_investigation_cases_from_analysis(direct.analysis)
    client = _client()
    response = _post(client, _payload(source))
    assert response.status_code == 200
    public = response.json()["result"]
    summary = projection.summary
    assert public["case_summary"]["case_count"] == summary.case_count
    assert public["case_summary"]["independent_observation_count"] == summary.independent_observation_count
    assert public["case_summary"]["high_case_count"] == summary.high_case_count
    assert public["case_summary"]["medium_case_count"] == summary.medium_case_count
    assert public["case_summary"]["low_case_count"] == summary.low_case_count
    assert public["case_summary"]["relation_case_count"] == summary.cases_with_supported_relation_count
    assert public["analysis_summary"]["supported_detection_count"] == summary.supported_detection_observation_count
    assert public["analysis_summary"]["supported_relation_count"] == summary.supported_relation_observation_count
    public_risks = sorted(case["included_highest_risk"] for case in public["cases"])
    direct_risks = sorted(case.row.included_highest_risk for case in projection.cases)
    assert public_risks == direct_risks
    assert len(public["cases"]) == len(projection.cases)
    for public_case, direct_case in zip(public["cases"], projection.cases, strict=True):
        assert public_case["observation_count"] == direct_case.row.observation_count
        assert public_case["supporting_relation_count"] == direct_case.row.supporting_relation_count
        assert public_case["included_highest_confidence"] == direct_case.row.included_highest_confidence
        assert public_case["supported_detections"] == list(dict.fromkeys(
            entry.detection_display_name
            for entry in direct_case.timeline_entries + direct_case.timeline_entries_without_time
            if entry.detection_display_name is not None
        ))
        assert public_case["supported_relations"] == list(dict.fromkeys(
            entry.relation_display_name
            for entry in direct_case.timeline_entries + direct_case.timeline_entries_without_time
            if entry.relation_display_name is not None
        ))
        expected_timeline = direct_case.timeline_entries + direct_case.timeline_entries_without_time
        assert len(public_case["timeline"]) == len(expected_timeline)
        for public_event, direct_event in zip(public_case["timeline"], expected_timeline, strict=True):
            assert (public_event["sequence"], public_event["category"],
                    public_event["category_label"], public_event["timestamp_state"],
                    public_event["title"], public_event["detection_display_name"],
                    public_event["relation_display_name"]) == (
                direct_event.sequence, direct_event.category, direct_event.category_label,
                direct_event.timestamp_state, direct_event.display_title,
                direct_event.detection_display_name, direct_event.relation_display_name,
            )
            assert [(item["label"], item["value"], item["unit"]) for item in public_event["evidence"]] == [
                (item.label, item.value, item.unit) for item in direct_event.evidence
            ]
    if public["cases"]:
        case_ref = public["cases"][0]["checklist_ref"]
        assert case_ref and case_ref.startswith("c_") and len(case_ref) == 26
        checklist = client.post("/api/v1/investigations/checklist", json={
            "schema_version": 1, "case_ref": case_ref
        })
        assert checklist.status_code == 200
        assert checklist.json()["source_role"] == source


@pytest.mark.parametrize("host,headers,query,code", [
    ("192.0.2.10", {}, "", "LOCAL_ONLY"),
    ("127.0.0.1", {"Host": "attacker.invalid"}, "", "LOCAL_ONLY"),
    ("127.0.0.1", {"Origin": "https://attacker.invalid"}, "", "LOCAL_ONLY"),
    ("127.0.0.1", {"X-Forwarded-For": "127.0.0.1"}, "", "LOCAL_ONLY"),
    ("127.0.0.1", {"Sec-Fetch-Site": "cross-site"}, "", "LOCAL_ONLY"),
    ("127.0.0.1", {}, "?raw=secret", "QUERY_NOT_ALLOWED"),
])
def test_loopback_host_origin_proxy_and_query_security(host, headers, query, code):
    client = _client(host)
    response = client.post("/api/v1/investigations/text" + query,
                           json=_payload("ssh"), headers=headers)
    assert response.status_code == (400 if code == "QUERY_NOT_ALLOWED" else 403)
    assert response.json()["error_code"] == code


def test_response_scope_and_report_never_echo_text_canaries(caplog):
    canaries = (
        "TEXT_RAW_CANARY_36_8B", "TEXT_ACCOUNT_CANARY", "TEXT_CREDENTIAL_CANARY",
        "TEXT_HOST_CANARY", "/private/TEXT_PATH_CANARY", "TEXT_EXCEPTION_CANARY",
        "198.51.100.244", "2001:db8::cafe",
    )
    text = SAMPLES["ssh"].read_text(encoding="utf-8")
    text = text.replace("admin", canaries[1]).replace("10.0.0.5", "198.51.100.244")
    text = text.replace("10.0.0.10", "2001:db8::cafe")
    text = text.replace(
        "ssh2", f"ssh2: {canaries[0]} {canaries[2]} {canaries[3]} "
        f"{canaries[4]} {canaries[5]}"
    )
    response = _post(_client(), _payload("ssh", text))
    assert response.status_code == 200, response.text
    material = response.text + repr(response.json()) + caplog.text
    assert all(value not in material for value in canaries)
    assert TEXT_NOTICE in response.json()["result"]["report_export"]["html"]


def test_unicode_bidi_input_is_not_projected_or_logged(caplog):
    text = SAMPLES["ssh"].read_text(encoding="utf-8").replace("admin", "adm\u202ein")
    response = _post(_client(), _payload("ssh", text))
    assert response.status_code == 200
    assert "\u202e" not in response.text
    assert "\u202e" not in caplog.text


def test_api_contract_and_linux_audit_app_do_not_expose_text_route():
    schema = _client().get("/openapi.json").json()
    assert "/api/v1/investigations/text" in schema["paths"]
    assert "/api/v1/investigations" in schema["paths"]

    class Sink(LinuxAuditApiAccessAuditSink):
        async def emit(self, _event):
            pass

    token = base64.urlsafe_b64encode(bytes(range(32))).rstrip(b"=").decode("ascii")
    protected_app = create_app(
        enable_linux_audit_api=True,
        linux_audit_api_security=LinuxAuditApiSecurityConfig(
            operator_token=SecretStr(token), principal_id="synthetic-operator",
            max_concurrent_analyses=1,
        ),
        linux_audit_api_audit_sink=Sink(),
    )
    protected = TestClient(protected_app)
    assert "/api/v1/investigations/text" not in protected_app.openapi()["paths"]


def _file_request(client):
    return client.post("/api/v1/investigations", files=[
        ("application_file", ("synthetic.log", SAMPLES["application"].read_bytes(), "text/plain"))
    ])


def _valid_file_request(client):
    return client.post("/api/v1/investigations", files=[
        (field, ("synthetic.log", path.read_bytes(), "text/plain"))
        for field, path in (
            ("application_file", SAMPLES["application"]),
            ("ssh_file", SAMPLES["ssh"]),
            ("access_file", SAMPLES["access"]),
        )
    ])


def test_upload_and_text_endpoints_share_the_same_rate_window():
    client = _client()
    for _ in range(3):
        assert _file_request(client).json()["error_code"] == "MISSING_FIELD"
    for _ in range(3):
        assert _post(client, content=b"{").json()["error_code"] == "INVALID_JSON"
    response = _file_request(client)
    assert response.status_code == 429
    assert response.json()["error_code"] == "RATE_LIMITED"

    client = _client()
    for _ in range(6):
        assert _post(client, content=b"{").json()["error_code"] == "INVALID_JSON"
    response = _file_request(client)
    assert response.status_code == 429
    assert response.json()["error_code"] == "RATE_LIMITED"


@pytest.mark.parametrize("first_kind", ["file", "text"], ids=["file-first", "text-first"])
def test_upload_and_text_endpoints_share_the_same_concurrency_slot(monkeypatch, first_kind):
    import app.local_investigation_api as local

    entered = Event()
    release = Event()

    async def blocking_worker(*_args):
        entered.set()
        await asyncio.to_thread(release.wait, 5)
        return local._error("ANALYSIS_FAILED")

    monkeypatch.setattr(local, "_run_worker", blocking_worker)
    client = _client()
    first = _valid_file_request if first_kind == "file" else lambda c: _post(c, _payload("ssh"))
    second = (lambda c: _post(c, _payload("ssh"))) if first_kind == "file" else _valid_file_request
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(first, client)
        assert entered.wait(5)
        denied = second(client)
        assert denied.status_code == 429
        assert denied.json()["error_code"] == "CONCURRENCY_LIMIT"
        release.set()
        completed = pending.result(timeout=10)
        assert completed.status_code == 500
    assert release.is_set()


def test_text_staging_is_private_and_removed_after_worker_failure(monkeypatch):
    import app.local_investigation_api as local

    observed = {}

    async def inspect_staging(sources, *_args):
        assert len(sources) == 1
        assert sources[0]["source"] == "ssh"
        path = Path(sources[0]["path"])
        observed["file"] = path
        observed["directory"] = path.parent
        observed["file_mode"] = stat.S_IMODE(path.stat().st_mode)
        observed["directory_mode"] = stat.S_IMODE(path.parent.stat().st_mode)
        observed["content"] = path.read_bytes()
        return local._error("ANALYSIS_FAILED")

    monkeypatch.setattr(local, "_run_worker", inspect_staging)
    text = SAMPLES["ssh"].read_text(encoding="utf-8")
    response = _post(_client(), _payload("ssh", text))
    assert response.status_code == 500
    assert response.json()["error_code"] == "ANALYSIS_FAILED"
    assert observed["file_mode"] == 0o600
    assert observed["directory_mode"] == 0o700
    assert observed["file"].name == "input-1.log"
    assert observed["content"] == text.encode("utf-8")
    assert not observed["file"].exists()
    assert not observed["directory"].exists()


def test_text_cancellation_cleans_staging_and_releases_shared_slot(monkeypatch):
    from app.api import (
        _analyze_checklist_input, build_investigation_report_projection,
        project_investigation_cases_from_analysis,
    )
    import app.local_investigation_api as local
    from starlette.requests import Request

    original = local.tempfile.TemporaryDirectory
    created = []

    def tracked(*args, **kwargs):
        directory = original(*args, **kwargs)
        created.append(Path(directory.name))
        return directory

    monkeypatch.setattr(local.tempfile, "TemporaryDirectory", tracked)
    entered = asyncio.Event()

    async def blocking_worker(*_args):
        entered.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(local, "_run_worker", blocking_worker)
    admission = local.create_local_admission()
    endpoint = local.create_local_text_endpoint(
        _analyze_checklist_input, project_investigation_cases_from_analysis,
        build_investigation_report_projection, admission=admission,
    )
    payload = json.dumps(_payload("ssh")).encode("utf-8")
    delivered = False

    async def receive():
        nonlocal delivered
        if delivered:
            return {"type": "http.request", "body": b"", "more_body": False}
        delivered = True
        return {"type": "http.request", "body": payload, "more_body": False}

    scope = {
        "type": "http", "scheme": "http", "method": "POST",
        "path": "/api/v1/investigations/text", "query_string": b"",
        "client": ("127.0.0.1", 50000),
        "headers": [(b"host", b"127.0.0.1:8000"),
                    (b"content-type", b"application/json")],
    }

    async def exercise():
        task = asyncio.create_task(endpoint(Request(scope, receive)))
        await entered.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(exercise())
    assert created and all(not directory.exists() for directory in created)
    assert admission.admit() is None
    admission.release()


def test_text_worker_timeout_cleans_staging_and_releases_slot(monkeypatch):
    import app.local_investigation_api as local

    created = []
    original = local.tempfile.TemporaryDirectory

    def tracked(*args, **kwargs):
        directory = original(*args, **kwargs)
        created.append(Path(directory.name))
        return directory

    monkeypatch.setattr(local.tempfile, "TemporaryDirectory", tracked)
    monkeypatch.setattr(local, "_ANALYSIS_TIMEOUT_SECONDS", 0.001)
    client = _client()
    response = _post(client, _payload("ssh"))
    assert response.status_code == 503
    assert response.json()["error_code"] == "ANALYSIS_TIMEOUT"
    assert created and all(not directory.exists() for directory in created)

    monkeypatch.setattr(local, "_ANALYSIS_TIMEOUT_SECONDS", 10.0)
    retry = _post(client, _payload("ssh"))
    assert retry.status_code == 200, retry.text


def test_openapi_documents_closed_text_request_response_and_error_contract():
    schema = _client().get("/openapi.json").json()
    operation = schema["paths"]["/api/v1/investigations/text"]["post"]
    request_schema = operation["requestBody"]["content"]["application/json"]["schema"]
    assert request_schema["additionalProperties"] is False
    assert set(request_schema["properties"]) == {"schema_version", "source", "log_text"}
    assert set(request_schema["required"]) == {"schema_version", "source", "log_text"}
    assert operation["requestBody"]["required"] is True
    assert "LocalTextInvestigationResponse" in json.dumps(operation["responses"])
    assert "LocalTextInvestigationErrorResponse" in json.dumps(operation["responses"])
