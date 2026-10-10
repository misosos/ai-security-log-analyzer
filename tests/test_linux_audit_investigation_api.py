"""Phase 9.1 public boundary: one local Audit file, no raw detail."""

from pathlib import Path
import asyncio
from io import BytesIO
import stat

import pytest

from fastapi.testclient import TestClient
from starlette.requests import Request
from starlette.datastructures import UploadFile

from app.api import create_app
import app.linux_audit_investigation_api as linux_local
from app.models.linux_audit_investigation import LinuxAuditInvestigationResponse
from app.linux_audit_investigation_api import (
    MAX_ENVELOPE_BYTES, MAX_FILE_BYTES, MAX_LINE_BYTES, MAX_LINES,
)


ROOT = Path(__file__).resolve().parents[1]
ENDPOINT = "/api/v1/investigations/linux-audit"


def _client(host="127.0.0.1"):
    authority = f"[{host}]" if ":" in host else host
    return TestClient(create_app(), base_url=f"http://{authority}:8000", client=(host, 50000))


def _upload(content=None, filename="ignored-private.log"):
    if content is None:
        content = (ROOT / "sample_logs/evaluation/linux_temp_curl.log").read_bytes()
    return [("audit_file", (filename, content, "application/octet-stream"))]


def test_local_linux_result_is_separate_and_count_only():
    response = _client().post(ENDPOINT, files=_upload())
    assert response.status_code == 200, response.text
    body = response.json()
    assert set(body) == {"schema_version", "source_context", "summary", "observations",
                         "interpretation_notices", "bounded_warnings", "capabilities"}
    assert body["schema_version"] == "1"
    assert body["source_context"]["kind"] == "LOCAL_PRIVATE_UPLOAD"
    assert body["summary"]["eligible_execution_count"] == 1
    assert body["summary"]["classified_execution_count"] == 1
    assert body["summary"]["category_observation_count"] == 2
    assert [item["observation_count"] for item in body["observations"]] == [0, 1, 0, 1]
    assert [item["review_priority"] for item in body["observations"]] == ["LOW", "LOW", "LOW", "MEDIUM"]
    assert not any(body["capabilities"].values())
    for private in ("/tmp/curl", "curl", "SYNTHETIC_ARG_CANARY", "ignored-private.log",
                    "synthetic-temp-curl", "9008", "argv", "PROCTITLE"):
        assert private not in response.text


def test_four_categories_and_outcomes_are_aggregate_only():
    names = ("linux_shell_sh_failure", "linux_network_wget_unknown",
             "linux_permission_chmod", "linux_temp_tool")
    content = b"".join((ROOT / "sample_logs/evaluation" / f"{name}.log").read_bytes() for name in names)
    response = _client().post(ENDPOINT, files=_upload(content))
    assert response.status_code == 200, response.text
    body = response.json()
    assert [item["observation_count"] for item in body["observations"]] == [1, 1, 1, 1]
    assert body["summary"]["eligible_execution_count"] == 4
    assert body["summary"]["outcome_counts"] == {"success": 2, "failure": 1, "unknown": 1}


def test_unclassified_and_empty_category_state():
    content = (ROOT / "sample_logs/evaluation/linux_normal_tool.log").read_bytes()
    response = _client().post(ENDPOINT, files=_upload(content))
    assert response.status_code == 200
    body = response.json()
    assert body["summary"]["eligible_execution_count"] == 1
    assert body["summary"]["unclassified_execution_count"] == 1
    assert body["summary"]["category_observation_count"] == 0
    assert all(item["confidence"] is None for item in body["observations"])


def test_closed_model_rejects_boolean_counts_and_broken_partitions():
    body = _client().post(ENDPOINT, files=_upload()).json()
    body["summary"]["eligible_execution_count"] = True
    with pytest.raises(ValueError):
        LinuxAuditInvestigationResponse.model_validate(body)
    body["summary"]["eligible_execution_count"] = 1
    body["summary"]["category_observation_count"] = 1
    with pytest.raises(ValueError):
        LinuxAuditInvestigationResponse.model_validate(body)


def test_distinct_private_audit_canaries_do_not_cross_public_boundary(capsys, caplog):
    content = (ROOT / "sample_logs/evaluation/linux_temp_curl.log").read_bytes()
    content = content.replace(b"synthetic-temp-curl", b"NODE_CANARY_731")
    content = content.replace(b":9008", b":731991")
    content = content.replace(b"argc=1 a0=\"/var/tmp/curl\"",
                              b"argc=2 a0=\"/var/tmp/curl\" a1=\"ARGV_CANARY_842\"")
    content = content.replace(b"pid=1008", b"pid=8427 acct=\"ACCOUNT_CANARY_953\"")
    suffix = b"msg=audit(1790401007.000008:731991): "
    content += b"node=NODE_CANARY_731 type=CWD " + suffix + b'cwd="/private/CWD_CANARY_164"\n'
    content += b"node=NODE_CANARY_731 type=PATH " + suffix + b'item=0 name="/private/PATH_CANARY_275"\n'
    content += (b"node=NODE_CANARY_731 type=PROCTITLE " + suffix +
                b"proctitle=" + b"PROCTITLE_CANARY_386".hex().encode() + b"\n")
    response = _client().post(ENDPOINT, files=_upload(content, "FILENAME_CANARY_497.log"))
    assert response.status_code == 200, response.text
    schema = _client().get("/openapi.json").text
    captured = capsys.readouterr()
    for value in ("NODE_CANARY_731", "731991", "ARGV_CANARY_842", "ACCOUNT_CANARY_953",
                  "CWD_CANARY_164", "PATH_CANARY_275", "PROCTITLE_CANARY_386", "FILENAME_CANARY_497"):
        assert value not in response.text and value not in repr(response.json()) and value not in schema
        assert value not in captured.out and value not in captured.err and value not in caplog.text


def test_local_gate_and_exact_multipart_shape():
    assert _client("192.0.2.1").post(ENDPOINT, files=_upload()).json()["error_code"] == "LOCAL_ONLY"
    client = _client()
    assert client.post(ENDPOINT, files=[]).json()["error_code"] == "INVALID_MEDIA_TYPE"
    assert client.post(ENDPOINT, content=b"--x--\r\n", headers={
        "Content-Type": "multipart/form-data; boundary=x",
    }).json()["error_code"] == "MISSING_FIELD"
    assert client.post(ENDPOINT, files=_upload() + _upload()).json()["error_code"] == "REPEATED_FIELD"
    assert client.post(ENDPOINT, files=_upload() * 3).json()["error_code"] == "FILE_COUNT_EXCEEDED"
    assert client.post(ENDPOINT, files=[("wrong", _upload()[0][1])]).json()["error_code"] == "UNKNOWN_FIELD"
    assert client.post(ENDPOINT, files=_upload(), data={"extra": "text"}).json()["error_code"] == "UNKNOWN_FIELD"
    assert client.post(ENDPOINT, json={}).json()["error_code"] == "INVALID_MEDIA_TYPE"
    assert client.post(ENDPOINT + "?x=1", files=_upload()).json()["error_code"] == "QUERY_NOT_ALLOWED"
    for headers in ({"X-Forwarded-For": "127.0.0.1"}, {"Origin": "http://outside.invalid"},
                    {"Host": "outside.invalid"}):
        assert client.post(ENDPOINT, files=_upload(), headers=headers).json()["error_code"] == "LOCAL_ONLY"


def test_invalid_content_has_bounded_errors():
    client = _client()
    for content, code in ((b"", "EMPTY_INPUT"), (b"  \n", "EMPTY_INPUT"),
                          (b"\xff", "INVALID_UTF8"), (b"x\0", "BINARY_INPUT"),
                          (b"PK\x03\x04", "ARCHIVE_UNSUPPORTED"),
                          (b"not audit\n", "PARSER_INCOMPATIBLE")):
        response = client.post(ENDPOINT, files=_upload(content))
        assert response.status_code != 200
        assert response.json()["error_code"] == code
        assert "ignored-private.log" not in response.text


def test_fixed_size_and_line_limits_are_bounded():
    assert MAX_FILE_BYTES == 64 * 1024
    assert MAX_ENVELOPE_BYTES == 72 * 1024
    assert MAX_LINE_BYTES == 1024
    assert MAX_LINES == 512
    client = _client()
    assert client.post(ENDPOINT, files=_upload(b"a" * (MAX_LINE_BYTES + 1))).json()["error_code"] == "LINE_TOO_LONG"
    assert client.post(ENDPOINT, files=_upload(b"x\n" * (MAX_LINES + 1))).json()["error_code"] == "LINE_COUNT_EXCEEDED"
    assert client.post(ENDPOINT, files=_upload((b"x" * 128 + b"\n") * MAX_LINES)).json()["error_code"] == "FILE_TOO_LARGE"
    assert client.post(ENDPOINT, files=_upload(), headers={"Content-Length": str(MAX_ENVELOPE_BYTES + 1)}).json()["error_code"] == "ENVELOPE_TOO_LARGE"


def test_streaming_boundaries_and_multibyte_chunk(tmp_path):
    async def stage(content, name):
        path = tmp_path / name
        count = await linux_local._stage(UploadFile(file=BytesIO(content)), path)
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        return count
    exact = (b"x" * 127 + b"\n") * MAX_LINES
    assert len(exact) == MAX_FILE_BYTES
    assert asyncio.run(stage(exact, "exact")) == MAX_LINES
    assert asyncio.run(stage(b"x" * MAX_LINE_BYTES + b"\n", "line-exact")) == 1
    with pytest.raises(linux_local._UploadError) as long_line:
        asyncio.run(stage(b"x" * (MAX_LINE_BYTES + 1) + b"\n", "line-over"))
    assert long_line.value.code == "LINE_TOO_LONG"
    split_utf8 = (b"x" * 1022 + b"\n") * 4 + b"xx" + "가".encode("utf-8") + b"\n"
    assert asyncio.run(stage(split_utf8, "utf8")) == 5
    class Stream:
        def __init__(self, size):
            self.headers = {"content-length": str(size)}
            self.size = size
        async def stream(self):
            yield b"x" * self.size
    async def consume(size):
        total = 0
        async for part in linux_local._bounded_stream(Stream(size)):
            total += len(part)
        return total
    assert asyncio.run(consume(MAX_ENVELOPE_BYTES)) == MAX_ENVELOPE_BYTES
    with pytest.raises(linux_local._UploadError) as failure:
        asyncio.run(consume(MAX_ENVELOPE_BYTES + 1))
    assert failure.value.code == "ENVELOPE_TOO_LARGE"


def test_one_loader_parser_classifier_and_fixed_projection_error(monkeypatch):
    fixture = ROOT / "sample_logs/evaluation/linux_temp_curl.log"
    calls = {"loader": 0, "parser": 0, "classifier": 0}
    original_loader = linux_local.load_linux_audit_events
    original_parser = linux_local.parse_linux_audit_events
    original_classifier = linux_local.classify_process_execution_observations
    def loader(*args, **kwargs):
        calls["loader"] += 1
        return original_loader(*args, **kwargs)
    def parser(*args, **kwargs):
        calls["parser"] += 1
        return original_parser(*args, **kwargs)
    def classifier(*args, **kwargs):
        calls["classifier"] += 1
        return original_classifier(*args, **kwargs)
    monkeypatch.setattr(linux_local, "load_linux_audit_events", loader)
    monkeypatch.setattr(linux_local, "parse_linux_audit_events", parser)
    monkeypatch.setattr(linux_local, "classify_process_execution_observations", classifier)
    class Connection:
        def __init__(self):
            self.message = None
        def send(self, value):
            self.message = value
        def close(self):
            pass
    connection = Connection()
    linux_local._worker(connection, str(fixture), 2)
    assert calls == {"loader": 1, "parser": 1, "classifier": 1}
    assert connection.message[0] == "ok"
    assert b"SYNTHETIC_ARG_CANARY" not in connection.message[1]
    monkeypatch.setattr(linux_local, "_project", lambda _assembly: (_ for _ in ()).throw(ValueError("PRIVATE_EXCEPTION_CANARY")))
    failed = Connection()
    linux_local._worker(failed, str(fixture), 2)
    assert failed.message == ("error", "RESPONSE_INVALID")


def test_staging_cleanup_on_success_and_validation_failure(monkeypatch):
    original = linux_local.tempfile.TemporaryDirectory
    created = []
    def tracked(*args, **kwargs):
        directory = original(*args, **kwargs)
        created.append(Path(directory.name))
        assert stat.S_IMODE(Path(directory.name).stat().st_mode) == 0o700
        return directory
    monkeypatch.setattr(linux_local.tempfile, "TemporaryDirectory", tracked)
    client = _client()
    assert client.post(ENDPOINT, files=_upload()).status_code == 200
    assert client.post(ENDPOINT, files=_upload(b"\0bad")).json()["error_code"] == "BINARY_INPUT"
    assert len(created) == 2
    assert all(not directory.exists() for directory in created)


def test_rate_concurrency_and_timeout_release(monkeypatch):
    now = [100.0]
    monkeypatch.setattr(linux_local.time, "monotonic", lambda: now[0])
    limiter = linux_local._Limiter()
    assert limiter.admit() is None
    assert limiter.admit() == "CONCURRENCY_LIMIT"
    limiter.release()
    for _ in range(linux_local.RATE_CAPACITY - 2):
        assert limiter.admit() is None
        limiter.release()
    assert limiter.admit() == "RATE_LIMITED"
    now[0] += linux_local.RATE_WINDOW_SECONDS
    assert limiter.admit() is None
    limiter.release()


def test_worker_timeout_cleans_staging(monkeypatch):
    original = linux_local.tempfile.TemporaryDirectory
    created = []
    def tracked(*args, **kwargs):
        directory = original(*args, **kwargs)
        created.append(Path(directory.name))
        return directory
    monkeypatch.setattr(linux_local.tempfile, "TemporaryDirectory", tracked)
    monkeypatch.setattr(linux_local, "ANALYSIS_TIMEOUT_SECONDS", 0.001)
    response = _client().post(ENDPOINT, files=_upload())
    assert response.json()["error_code"] == "ANALYSIS_TIMEOUT"
    assert created and all(not directory.exists() for directory in created)


def test_cancellation_cleans_staging(monkeypatch):
    created = []
    original = linux_local.tempfile.TemporaryDirectory
    def tracked(*args, **kwargs):
        directory = original(*args, **kwargs)
        created.append(Path(directory.name))
        return directory
    monkeypatch.setattr(linux_local.tempfile, "TemporaryDirectory", tracked)
    class FakeForm:
        closed = False
        async def close(self):
            self.closed = True
        def __getitem__(self, _key):
            return object()
    form = FakeForm()
    async def fake_form(_request):
        return form
    async def fake_stage(_upload, path):
        path.write_bytes(b"synthetic")
        return 1
    entered = asyncio.Event()
    async def fake_worker(*_args):
        entered.set()
        await asyncio.Event().wait()
    monkeypatch.setattr(linux_local, "_form", fake_form)
    monkeypatch.setattr(linux_local, "_stage", fake_stage)
    monkeypatch.setattr(linux_local, "_run_worker", fake_worker)
    endpoint = linux_local.create_linux_audit_local_endpoint()
    scope = {"type": "http", "scheme": "http", "path": ENDPOINT,
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


def test_openapi_and_existing_routes_remain_separate():
    client = _client()
    schema = client.get("/openapi.json").text
    assert ENDPOINT in schema
    assert "LinuxAuditInvestigationResponse" in schema
    assert "ignored-private.log" not in schema
    assert client.get("/api/health").json() == {"status": "ok"}
    assert client.get("/").status_code == 200
    assert client.get("/assets/linux-audit.js").status_code == 200
    assert client.get("/assets/linux-audit.js").headers["content-type"].startswith("text/javascript")
    assert "/api/analyze-linux-audit" not in schema  # optional secured app only
