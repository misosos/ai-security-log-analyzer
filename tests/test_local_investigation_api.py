"""Focused tests for the loopback-only real-log boundary."""

from pathlib import Path
import asyncio
from io import BytesIO
import json
import shutil
import stat
import subprocess

import pytest

from fastapi.testclient import TestClient
from starlette.datastructures import UploadFile
from starlette.requests import Request

from app.api import create_app
import app.local_investigation_api as local
from app.main import analyze
from app.analyzer.incident_case_adapter import project_investigation_cases_from_analysis
from app.analyzer.report_projection import build_investigation_report_projection


ROOT = Path(__file__).resolve().parents[1]
FILES = {
    "application_file": "brute_force.log",
    "ssh_file": "ssh_auth.log",
    "access_file": "web_shell.log",
}


def _client(host="127.0.0.1"):
    authority = f"[{host}]" if ":" in host else host
    return TestClient(create_app(), base_url=f"http://{authority}:8000", client=(host, 50000))


def _files():
    return [
        (field, ("ignored.bin", (ROOT / "sample_logs" / name).read_bytes(), "application/octet-stream"))
        for field, name in FILES.items()
    ]


def test_local_sample_fixture_is_analyzed_without_sample_label():
    response = _client().post("/api/v1/investigations", files=_files())
    assert response.status_code == 200, response.json()
    body = response.json()
    assert body["local_context"]["label"] == "로컬 실제 로그 분석 결과"
    assert body["case_summary"]["case_count"] == 2
    assert body["case_summary"]["independent_observation_count"] == 4
    assert "합성 샘플" not in response.text
    assert body["report_export"]["byte_count"] == len(body["report_export"]["html"].encode("utf-8"))
    assert body["report_export"]["html"].startswith("<!doctype html>\n<html lang=\"ko\">")
    assert "script-src 'none'" in body["report_export"]["html"]
    assert "style-src 'sha256-" in body["report_export"]["html"]
    for private in ("user=alice", "user=admin", "id=1%20UNION", "?file=", "ignored.bin"):
        assert private not in response.text
    assert "sample_logs" not in response.text
    assert set(body) == {
        "schema_version", "local_context", "analysis_summary", "case_summary", "cases",
        "independent_observations", "interpretation_notices", "capabilities",
        "bounded_warnings", "report_export",
    }


def test_openapi_exposes_closed_local_models_without_fixture_paths():
    schema = _client().get("/openapi.json").text
    assert "/api/v1/investigations" in schema
    assert "LocalInvestigationResponse" in schema
    assert "LocalInvestigationErrorResponse" in schema
    assert "sample_logs" not in schema
    assert str(ROOT) not in schema


def test_original_account_query_filename_and_raw_line_canaries_do_not_escape():
    files = []
    for field, (_, content, media_type) in _files():
        content = content.replace(b"alice", b"PRIVATEACCOUNTCANARY")
        content = content.replace(b"id=1%20UNION", b"id=PRIVATEQUERYCANARY")
        content = content.replace(b"/download?file=", b"/PRIVATEPATHCANARY/../download?file=")
        files.append((field, ("../../PRIVATEFILENAMECANARY.log", content, media_type)))
    response = _client().post("/api/v1/investigations", files=files)
    assert response.status_code == 200
    assert "개인정보 보호를 위해 표시하지 않습니다." in response.json()["report_export"]["html"]
    assert "일치 패턴" in response.json()["report_export"]["html"]
    for canary in ("PRIVATEACCOUNTCANARY", "PRIVATEQUERYCANARY", "PRIVATEPATHCANARY",
                   "PRIVATEFILENAMECANARY", "user=PRIVATEACCOUNTCANARY"):
        assert canary not in response.text
        assert canary not in repr(response.json())


def test_non_loopback_is_rejected_before_analysis():
    response = _client("192.0.2.15").post("/api/v1/investigations", files=_files())
    assert response.status_code == 403
    assert response.json()["error_code"] == "LOCAL_ONLY"


@pytest.mark.parametrize("host,allowed", [
    ("127.0.0.1", True), ("192.0.2.15", False), ("not-an-address", False),
])
def test_loopback_address_gate(host, allowed):
    response = _client(host).post("/api/v1/investigations", files=_files())
    assert (response.status_code == 200) is allowed
    if not allowed:
        assert response.json()["error_code"] == "LOCAL_ONLY"


@pytest.mark.parametrize("host,allowed", [("::1", True), ("::ffff:127.0.0.1", False), (None, False)])
def test_ipv6_and_missing_client_gate(host, allowed):
    scope = {"type": "http", "headers": [(b"host", b"[::1]:8000")],
             "client": (host, 50000) if host is not None else None}
    assert local._loopback_request(Request(scope)) is allowed


@pytest.mark.parametrize("header", ["X-Forwarded-For", "Forwarded", "X-Real-IP"])
def test_proxy_headers_cannot_authorize_local_upload(header):
    response = _client().post("/api/v1/investigations", files=_files(), headers={header: "127.0.0.1"})
    assert response.status_code == 403
    assert response.json()["error_code"] == "LOCAL_ONLY"


def test_multipart_shape_is_exact_and_bounded():
    client = _client()
    valid = _files()
    for fields, code in (
        (valid[:2], "MISSING_FIELD"),
        (valid[:1] + valid[:1], "REPEATED_FIELD"),
        (valid[:2] + [("unknown", valid[2][1])], "UNKNOWN_FIELD"),
        (valid + [valid[0]], "FILE_COUNT_EXCEEDED"),
    ):
        response = client.post("/api/v1/investigations", files=fields)
        assert response.json()["error_code"] == code
    text = client.post("/api/v1/investigations", files=valid, data={"other": "text"})
    assert text.json()["error_code"] == "UNKNOWN_FIELD"
    assert client.post("/api/v1/investigations", json={}).json()["error_code"] == "INVALID_MEDIA_TYPE"
    assert client.post("/api/v1/investigations?x=1", files=valid).json()["error_code"] == "QUERY_NOT_ALLOWED"


@pytest.mark.parametrize("replacement,code", [
    (b"", "EMPTY_INPUT"), (b"  \n\t", "EMPTY_INPUT"),
    (b"PK\x03\x04junk", "ARCHIVE_UNSUPPORTED"),
    (b"\x1f\x8bjunk", "ARCHIVE_UNSUPPORTED"),
    (b"7z\xbc\xaf\x27\x1cjunk", "ARCHIVE_UNSUPPORTED"),
    (b"\x00junk", "BINARY_INPUT"), (b"\xff", "INVALID_UTF8"),
    (b"2026-09-11 10:00:01 INFO login_failed user=test ip=192.0.2.1\r", "BINARY_INPUT"),
    (b"x" * 2049, "LINE_TOO_LONG"),
    ((b"2026-09-11 10:00:01 INFO login_failed user=test ip=192.0.2.1" + b" " * 940 + b"\n") * 40,
     "FILE_TOO_LARGE"),
    (b"not a supported log\n", "PARSER_INCOMPATIBLE"),
], ids=["empty", "whitespace", "zip", "gzip", "7zip", "nul", "utf8", "cr-only", "line", "file", "format"])
def test_invalid_file_is_bounded_without_filename_or_content(replacement, code):
    files = _files()
    files[0] = ("application_file", ("private-file.log", replacement, "text/plain"))
    response = _client().post("/api/v1/investigations", files=files)
    assert response.json()["error_code"] == code
    assert response.json()["field"] == "application_file"
    assert "private-file.log" not in response.text
    assert "not a supported log" not in response.text


def test_staged_file_has_private_permissions(tmp_path):
    content = (ROOT / "sample_logs" / "brute_force.log").read_bytes()
    upload = UploadFile(file=BytesIO(content), filename="ignored.log")
    target = tmp_path / "stage"
    total = asyncio.run(local._stage_file(
        upload, source="application", field="application_file", path=target, total=0,
    ))
    assert total == len(content)
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    with pytest.raises(FileExistsError):
        asyncio.run(local._stage_file(
            UploadFile(file=BytesIO(content)), source="application",
            field="application_file", path=target, total=0,
        ))


def test_incremental_utf8_split_at_chunk_boundary_is_accepted(tmp_path):
    line = b"2026-09-11 10:00:01 INFO login_failed user=test ip=192.0.2.1"
    complete = (line + b"\n") * 60
    padding = 4095 - len(complete) - len(line)
    assert 0 < padding < local._MAX_LINE_BYTES - len(line)
    content = complete + line + b" " * padding + "가".encode("utf-8") + b"\n"
    assert content[4095:4098] == "가".encode("utf-8")
    upload = UploadFile(file=BytesIO(content))
    assert asyncio.run(local._stage_file(
        upload, source="application", field="application_file",
        path=tmp_path / "stage", total=0,
    )) == len(content)


def test_worker_calls_existing_analysis_and_projection_once():
    calls = []
    class Pipe:
        value = None
        def send(self, value):
            self.value = value
        def close(self):
            pass
    pipe = Pipe()
    sources = [
        {"source": source, "path": str(ROOT / "sample_logs" / name)}
        for source, name in (("application", "brute_force.log"),
                             ("ssh", "ssh_auth.log"), ("access", "web_shell.log"))
    ]
    def tracked_analyze(value):
        calls.append("analyze")
        return analyze(value)
    def tracked_project(value):
        calls.append("case")
        return project_investigation_cases_from_analysis(value)
    def tracked_report(value):
        calls.append("report_projection")
        return build_investigation_report_projection(value)
    def tracked_render(value):
        calls.append("renderer")
        return local._render_local_report(value)
    local._worker(pipe, sources, tracked_analyze, tracked_project, tracked_report, tracked_render)
    assert calls == ["analyze", "case", "report_projection", "renderer"]
    assert pipe.value[0] == "ok"


def test_worker_failures_are_phase_specific_and_private():
    class Pipe:
        value = None
        def send(self, value):
            self.value = value
        def close(self):
            pass
    sources = [
        {"source": source, "path": str(ROOT / "sample_logs" / name)}
        for source, name in (("application", "brute_force.log"),
                             ("ssh", "ssh_auth.log"), ("access", "web_shell.log"))
    ]
    def private_failure(_value):
        raise RuntimeError("PRIVATEEXCEPTIONCANARY")
    for functions, code in (
        ((private_failure, project_investigation_cases_from_analysis,
          build_investigation_report_projection, local._render_local_report), "ANALYSIS_FAILED"),
        ((analyze, private_failure,
          build_investigation_report_projection, local._render_local_report), "CASE_PROJECTION_FAILED"),
        ((analyze, project_investigation_cases_from_analysis,
          private_failure, local._render_local_report), "REPORT_GENERATION_FAILED"),
        ((analyze, project_investigation_cases_from_analysis,
          build_investigation_report_projection, private_failure), "REPORT_GENERATION_FAILED"),
    ):
        pipe = Pipe()
        local._worker(pipe, sources, *functions)
        assert pipe.value == ("error", code)
        assert "PRIVATEEXCEPTIONCANARY" not in repr(pipe.value)


def test_origin_and_fetch_metadata_are_same_origin_only():
    files = _files()
    client = _client()
    assert client.post("/api/v1/investigations", files=files,
                       headers={"Origin": "http://127.0.0.1:8000"}).status_code == 200
    for headers in ({"Origin": "http://other.example"},
                    {"Sec-Fetch-Site": "cross-site"}):
        response = client.post("/api/v1/investigations", files=files, headers=headers)
        assert response.json()["error_code"] == "LOCAL_ONLY"


def test_envelope_and_total_decoded_limits_are_distinct(tmp_path):
    response = _client().post("/api/v1/investigations", files=_files(),
                              headers={"Content-Length": str(local._MAX_ENVELOPE_BYTES + 1)})
    assert response.json()["error_code"] == "ENVELOPE_TOO_LARGE"
    valid = (ROOT / "sample_logs" / "brute_force.log").read_bytes()
    upload = UploadFile(file=BytesIO(valid))
    with pytest.raises(local._UploadError) as caught:
        asyncio.run(local._stage_file(
            upload, source="application", field="application_file",
            path=tmp_path / "stage", total=local._MAX_TOTAL_BYTES,
        ))
    assert caught.value.code == "TOTAL_TOO_LARGE"


def test_request_staging_is_removed_after_success_and_validation_error(monkeypatch):
    original = local.tempfile.TemporaryDirectory
    created = []
    def tracked(*args, **kwargs):
        directory = original(*args, **kwargs)
        created.append(Path(directory.name))
        assert stat.S_IMODE(Path(directory.name).stat().st_mode) == 0o700
        return directory
    monkeypatch.setattr(local.tempfile, "TemporaryDirectory", tracked)
    client = _client()
    assert client.post("/api/v1/investigations", files=_files()).status_code == 200
    files = _files()
    files[0] = ("application_file", ("ignored", b"\x00", "text/plain"))
    assert client.post("/api/v1/investigations", files=files).json()["error_code"] == "BINARY_INPUT"
    assert len(created) == 2
    assert all(not directory.exists() for directory in created)


def test_cancellation_cleans_staging_and_closes_form(monkeypatch):
    created = []
    original = local.tempfile.TemporaryDirectory
    def tracked(*args, **kwargs):
        directory = original(*args, **kwargs)
        created.append(Path(directory.name))
        return directory
    monkeypatch.setattr(local.tempfile, "TemporaryDirectory", tracked)
    class FakeForm:
        closed = False
        async def close(self):
            self.closed = True
    form = FakeForm()
    async def fake_form(_request):
        return form
    async def fake_stage(_form, directory):
        (directory / "input-1.log").write_bytes(b"synthetic")
        return []
    entered = asyncio.Event()
    async def fake_worker(*_args):
        entered.set()
        await asyncio.Event().wait()
    monkeypatch.setattr(local, "_form", fake_form)
    monkeypatch.setattr(local, "_stage", fake_stage)
    monkeypatch.setattr(local, "_run_worker", fake_worker)
    endpoint = local.create_local_endpoint(analyze, project_investigation_cases_from_analysis,
                                           build_investigation_report_projection)
    scope = {"type": "http", "scheme": "http", "path": "/api/v1/investigations",
             "query_string": b"", "client": ("127.0.0.1", 50000),
             "headers": [(b"host", b"127.0.0.1:8000"),
                         (b"content-type", b"multipart/form-data; boundary=x")]}
    async def exercise():
        task = asyncio.create_task(endpoint(Request(scope)))
        await entered.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    asyncio.run(exercise())
    assert form.closed
    assert created and all(not directory.exists() for directory in created)


def test_worker_timeout_terminates_before_staging_cleanup(monkeypatch):
    original = local.tempfile.TemporaryDirectory
    created = []
    def tracked(*args, **kwargs):
        directory = original(*args, **kwargs)
        created.append(Path(directory.name))
        return directory
    monkeypatch.setattr(local.tempfile, "TemporaryDirectory", tracked)
    monkeypatch.setattr(local, "_ANALYSIS_TIMEOUT_SECONDS", 0.001)
    client = _client()
    response = client.post("/api/v1/investigations", files=_files())
    assert response.json()["error_code"] == "ANALYSIS_TIMEOUT"
    assert all(not directory.exists() for directory in created)
    monkeypatch.setattr(local, "_ANALYSIS_TIMEOUT_SECONDS", 10.0)
    assert client.post("/api/v1/investigations", files=_files()).status_code == 200


def test_process_local_limiter_is_fixed_size_and_releases_slot(monkeypatch):
    now = [100.0]
    monkeypatch.setattr(local.time, "monotonic", lambda: now[0])
    limiter = local._LocalLimit()
    assert limiter.admit() is None
    assert limiter.admit() == "CONCURRENCY_LIMIT"
    limiter.release()
    for _ in range(local._RATE_CAPACITY - 2):
        assert limiter.admit() is None
        limiter.release()
    assert limiter.admit() == "RATE_LIMITED"
    assert len(limiter._requests) == local._RATE_CAPACITY
    now[0] += local._RATE_WINDOW_SECONDS
    assert limiter.admit() is None
    limiter.release()


def test_local_and_sample_browser_contracts_share_safe_renderer():
    if shutil.which("node") is None:
        pytest.skip("Node unavailable; static contracts remain covered")
    sample = _client().post("/api/v1/investigations/sample")
    local = _client().post("/api/v1/investigations", files=_files())
    assert sample.status_code == 200 and local.status_code == 200
    outcome = subprocess.run(
        ["node", str(ROOT / "tests" / "web_ui_behavior.cjs")],
        input=json.dumps({"sample": sample.json(), "local": local.json()}),
        text=True, capture_output=True, cwd=ROOT, timeout=20, check=False,
    )
    assert outcome.returncode == 0, outcome.stderr
