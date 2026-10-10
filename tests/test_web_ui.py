from html.parser import HTMLParser
from pathlib import Path
import re
import base64
import json
import shutil
import subprocess

from fastapi.testclient import TestClient
from pydantic import SecretStr
import pytest

import app.api as api
import app.web_ui as web_ui
from app.security.linux_audit_api import (
    LinuxAuditApiAccessAuditSink,
    LinuxAuditApiSecurityConfig,
)


ROOT = Path(__file__).resolve().parents[1]
FRONTEND = ROOT / "frontend"
ASSETS = ("/assets/style.css", "/assets/app.js")


class _Structure(HTMLParser):
    def __init__(self):
        super().__init__()
        self.nodes = []
        self.text = []

    def handle_starttag(self, tag, attrs):
        self.nodes.append((tag, dict(attrs)))

    def handle_data(self, data):
        self.text.append(data)


def test_landing_has_semantic_static_accessible_contract():
    source = (FRONTEND / "index.html").read_text(encoding="utf-8")
    parsed = _Structure()
    parsed.feed(source)
    nodes = parsed.nodes
    text = " ".join(parsed.text)

    assert source.lower().startswith("<!doctype html>")
    assert ("html", {"lang": "ko"}) in nodes
    assert any(tag == "meta" and attrs.get("charset") == "utf-8" for tag, attrs in nodes)
    assert any(tag == "meta" and attrs.get("name") == "viewport" for tag, attrs in nodes)
    assert {"header", "main", "footer"}.issubset({tag for tag, _ in nodes})
    assert [tag for tag, _ in nodes].count("h1") == 1
    assert all(
        int(next_tag[1]) <= int(current_tag[1]) + 1
        for current_tag, next_tag in zip(
            [tag for tag, _ in nodes if re.fullmatch(r"h[1-6]", tag)],
            [tag for tag, _ in nodes if re.fullmatch(r"h[1-6]", tag)][1:],
        )
    )
    ids = {attrs["id"] for _, attrs in nodes if "id" in attrs}
    assert any(tag == "a" and attrs.get("href") == "#main" for tag, attrs in nodes)
    assert "main" in ids
    assert any(tag == "button" and attrs.get("type") == "button" and attrs.get("id") == "sample-button" for tag, attrs in nodes)
    assert any(tag == "button" and attrs.get("type") == "button" and attrs.get("id") == "report-button" for tag, attrs in nodes)
    assert any(attrs.get("id") == "report-download" and "hidden" in attrs for _, attrs in nodes)
    assert any(attrs.get("id") == "error-summary" and attrs.get("tabindex") == "-1" for _, attrs in nodes)
    assert "error-retry" in ids
    assert any(attrs.get("id") == "sample-status" and attrs.get("aria-live") == "polite" for _, attrs in nodes)
    assert any(tag == "link" and attrs.get("href") == "/assets/style.css" for tag, attrs in nodes)
    assert any(tag == "script" and attrs.get("src") == "/assets/app.js" and "defer" in attrs for tag, attrs in nodes)
    for phrase in (
        "샘플로 체험하기", "합성 샘플을 사용합니다", "실제 조직 환경이나 사용자의 보안 상태를 나타내지 않습니다",
        "탐지는 침해 확인이 아니며", "독립 관찰", "인증 없는 공개 웹 업로드는 제공하지 않습니다",
        "HTML 보고서 다운로드", "현재 형식: 대상별 결정적 조사 보고서", "민감한 조사 자료",
        "서버에 영구 저장되지 않으며", "Timeline이 포함되지 않습니다",
    ):
        assert phrase in text
    assert not any(tag in {"iframe", "object", "embed", "video", "audio"} for tag, _ in nodes)
    assert any(tag == "fieldset" for tag, _ in nodes)
    assert any(tag == "legend" for tag, _ in nodes)
    assert any(attrs.get("id") == "local-upload" and "hidden" in attrs for _, attrs in nodes)
    assert {attrs.get("name") for tag, attrs in nodes if tag == "input"} == {
        "application_file", "ssh_file", "access_file"
    }
    assert all("required" in attrs and attrs.get("type") == "file"
               for tag, attrs in nodes if tag == "input")
    assert not any(attr.startswith("on") or attr == "style" for _, attrs in nodes for attr in attrs)
    assert not any(attrs.get("src", "").startswith(("http:", "https:", "data:")) for _, attrs in nodes)
    assert "<style" not in source.lower() and "<script>" not in source.lower()


def test_frontend_source_has_no_unsafe_sinks_or_persistence():
    html = (FRONTEND / "index.html").read_text(encoding="utf-8")
    js = (FRONTEND / "app.js").read_text(encoding="utf-8")
    css = (FRONTEND / "style.css").read_text(encoding="utf-8")
    all_source = "\n".join((html, js, css))
    for forbidden in (
        "innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(",
        "new Function", "localStorage", "sessionStorage", "indexedDB", "document.cookie",
        "serviceWorker", "sourceMappingURL", "data:", "blob:", "unsafe-inline", "unsafe-eval",
        "console.log", "console.error", "https://", "http://", "url(",
    ):
        assert forbidden not in all_source
    assert "@import" not in html + css
    assert 'const ENDPOINT = "/api/v1/investigations/sample"' in js
    assert 'method: "POST"' in js
    assert 'credentials: "omit"' in js
    assert "document.createElement" in js and ".textContent" in js
    assert "MAX_RESPONSE_BYTES" in js and "MAX_ITEMS" in js and "MAX_TEXT" in js
    assert "validateInvestigationResponse" in js and "failContract()" in js
    assert "SAMPLE_ERRORS" in js and "LOCAL_ERRORS" in js
    assert 'value.retryable !== approved[2]' in js
    assert 'errorRetry.textContent' in js
    assert "summary.case_count !== summary.high_case_count + summary.medium_case_count + summary.low_case_count" in js
    assert "errorSummary.focus()" in js and "button.disabled = false" in js
    assert "URL.createObjectURL(file)" in js and "URL.revokeObjectURL(objectUrl)" in js
    assert "new Blob([bytes]" in js and "reportButton.addEventListener" in js
    assert "validateReportExport(value.report_export, mode)" in js
    assert "prefers-reduced-motion" in css and ":focus-visible" in css
    assert "risk-high" in css and "risk-medium" in css and "risk-low" in css


def test_case_detail_source_uses_native_ordered_semantics_and_fixed_mappings():
    js = (FRONTEND / "app.js").read_text(encoding="utf-8")
    css = (FRONTEND / "style.css").read_text(encoding="utf-8")
    assert 'document.createElement("details")' in js
    assert 'document.createElement("summary")' in js
    assert 'document.createElement("ol")' in js
    assert 'document.createElement("dl")' in js
    assert 'element("time", value.display_kst)' in js
    assert 'node.setAttribute("datetime", value.display_utc)' in js
    assert 'element("dt", "시작")' in js
    assert 'element("dt", "종료")' in js
    assert 'element("span", "KST", "time-zone-label")' in js
    assert 'element("span", "UTC", "time-zone-label")' in js
    assert 'appendTimeRange' not in js
    assert 'time-connector' not in js
    assert '"부터"' not in js
    assert 'UTC: ${' not in js
    assert '${start.display_kst} ~ ${end.display_kst}' not in js
    assert 'item.append(evidenceList(entry.evidence))' in js
    assert 'item.included_highest_risk === "HIGH" || item.included_highest_risk === "MEDIUM"' in js
    assert 'caseItem.timeline.forEach' in js
    assert 'caseItem.next_steps.map' in js
    assert 'item.evidence' in js
    assert 'DETECTION_EVIDENCE' in js and 'RELATION_EVIDENCE' in js
    assert 'NEXT_STEP_SEQUENCES' in js and 'LIMITATION_TEXTS' in js
    assert 'category === "SUPPORTED_RELATION"' in js
    assert '.sort(' not in js
    assert 'JSON.stringify(' not in js
    assert 'Object.entries(' not in js
    assert 'case-summary:focus-visible' in css
    assert '.timeline' in css and '.evidence-list' in css
    assert '.time-range' in css and '.time-row' in css
    assert '.time-line' in css and '.time-utc' in css
    assert 'overflow-wrap: anywhere' in css
    assert '@media (max-width: 42rem)' in css


def test_fixed_routes_headers_and_existing_api_contract(monkeypatch):
    client = TestClient(api.create_app())
    def forbid_analyze(_sources):
        raise AssertionError("static delivery cannot analyze")
    monkeypatch.setattr(api, "analyze", forbid_analyze)
    index = client.get("/")
    assert index.status_code == 200
    assert index.headers["content-type"].startswith("text/html")
    assert 'lang="ko"' in index.text
    for route, media_type in ((ASSETS[0], "text/css"), (ASSETS[1], "text/javascript")):
        response = client.get(route)
        assert response.status_code == 200
        assert response.headers["content-type"].startswith(media_type)
        assert response.headers["cache-control"] == "no-store"
    for response in (index, client.get(ASSETS[0]), client.get(ASSETS[1])):
        policy = response.headers["content-security-policy"]
        for directive in (
            "default-src 'none'", "script-src 'self'", "style-src 'self'",
            "connect-src 'self'", "frame-ancestors 'none'", "form-action 'self'",
        ):
            assert directive in policy
        assert "unsafe-" not in policy and "http:" not in policy and "https:" not in policy
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["referrer-policy"] == "no-referrer"
        assert "camera=()" in response.headers["permissions-policy"]
    assert client.get("/assets/other.js").status_code == 404
    assert client.get("/unknown").status_code == 404
    assert client.get("/api/health").json() == {"status": "ok"}
    assert client.get("/docs").status_code == 200
    schema = client.get("/openapi.json").json()
    assert set(schema["paths"]) == {"/api/health", "/api/analyze", "/api/v1/investigations/sample", "/api/v1/investigations"}
    assert client.post("/api/analyze").status_code == 422


def test_static_delivery_is_independent_of_working_directory(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    client = TestClient(api.create_app())
    assert client.get("/").status_code == 200
    assert client.get("/assets/style.css").status_code == 200
    assert client.get("/assets/app.js").status_code == 200


def test_fixed_asset_rejects_symlink_empty_and_oversized_without_path_leak(monkeypatch, tmp_path):
    frontend = tmp_path / "frontend"
    frontend.mkdir()
    monkeypatch.setattr(web_ui, "_FRONTEND", frontend)
    target = tmp_path / "outside"
    target.write_text("private", encoding="utf-8")
    (frontend / "index.html").symlink_to(target)
    client = TestClient(api.create_app())
    response = client.get("/")
    assert response.status_code == 404
    assert str(tmp_path) not in response.text and "outside" not in response.text
    (frontend / "index.html").unlink()
    (frontend / "index.html").write_bytes(b"")
    assert client.get("/").status_code == 404
    (frontend / "index.html").write_bytes(b"x" * (web_ui._MAX_ASSET_BYTES + 1))
    assert client.get("/").status_code == 404
    (frontend / "index.html").unlink()
    assert client.get("/").status_code == 404


def test_only_explicit_sample_post_runs_analysis(monkeypatch):
    calls = []
    original = api.analyze
    def tracked(sources):
        calls.append(1)
        return original(sources)
    monkeypatch.setattr(api, "analyze", tracked)
    client = TestClient(api.create_app())
    assert client.get("/").status_code == 200
    assert client.get(ASSETS[0]).status_code == 200
    assert client.get(ASSETS[1]).status_code == 200
    assert calls == []
    result = client.post("/api/v1/investigations/sample")
    assert result.status_code == 200
    assert len(calls) == 1
    data = result.json()
    assert data["case_summary"]["case_count"] == 2
    assert data["case_summary"]["independent_observation_count"] == 4


def test_protected_linux_audit_factory_does_not_gain_public_ui_routes():
    class Sink(LinuxAuditApiAccessAuditSink):
        async def emit(self, _event):
            pass

    synthetic_token = base64.urlsafe_b64encode(bytes(range(32))).rstrip(b"=").decode("ascii")
    protected = api.create_app(
        enable_linux_audit_api=True,
        linux_audit_api_security=LinuxAuditApiSecurityConfig(
            operator_token=SecretStr(synthetic_token),
            principal_id="synthetic-operator",
            max_concurrent_analyses=1,
        ),
        linux_audit_api_audit_sink=Sink(),
    )
    client = TestClient(protected)
    assert client.get("/").status_code == 404
    assert client.get("/assets/style.css").status_code == 404
    assert client.get("/assets/app.js").status_code == 404
    assert "/api/analyze-linux-audit" in protected.openapi()["paths"]


def test_renderer_logic_with_sample_contract_and_malformed_nested_data():
    if shutil.which("node") is None:
        pytest.skip("Node unavailable; source and API contract tests still run")
    payload = TestClient(api.create_app()).post("/api/v1/investigations/sample")
    assert payload.status_code == 200
    result = subprocess.run(
        ["node", str(ROOT / "tests" / "web_ui_behavior.cjs")],
        input=json.dumps(payload.json()),
        text=True,
        capture_output=True,
        cwd=ROOT,
        timeout=15,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == "renderer logic verified\n"
