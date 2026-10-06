from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import app.analyzer.llm as llm
import app.api as api_module


UPLOAD_CANARY = "SYNTHETIC_UPLOAD_TEST_SECRET_DO_NOT_EXPOSE"


def _analyze_files(
    application_content: bytes = b"application event\n",
    ssh_content: bytes = b"ssh event\n",
    access_content: bytes = b"access event\n",
):
    return {
        "application_file": (
            "application.log",
            application_content,
            "text/plain",
        ),
        "ssh_file": ("ssh.log", ssh_content, "text/plain"),
        "access_file": ("access.log", access_content, "text/plain"),
    }


def _empty_analysis():
    return {
        "results": {},
        "global_correlation": {},
    }


def _track_api_temp_files(monkeypatch, tmp_path: Path) -> list[Path]:
    original = api_module.tempfile.NamedTemporaryFile
    created_paths: list[Path] = []

    def tracked_named_temporary_file(*args, **kwargs):
        kwargs["dir"] = tmp_path
        temp_file = original(*args, **kwargs)
        created_paths.append(Path(temp_file.name))
        return temp_file

    monkeypatch.setattr(
        api_module.tempfile,
        "NamedTemporaryFile",
        tracked_named_temporary_file,
    )
    return created_paths


def test_upload_test_route_is_absent_and_does_not_create_api_temp_file(
    monkeypatch,
):
    def fail_if_called(*args, **kwargs):
        raise AssertionError("removed route must not create an API temp file")

    monkeypatch.setattr(
        api_module.tempfile,
        "NamedTemporaryFile",
        fail_if_called,
    )
    client = TestClient(api_module.app)
    files = {
        "file": (
            f"{UPLOAD_CANARY}.log",
            UPLOAD_CANARY.encode(),
            f"application/{UPLOAD_CANARY}",
        )
    }

    for _ in range(2):
        response = client.post("/api/upload-test", files=files)

        assert response.status_code == 404
        assert response.json() == {"detail": "Not Found"}
        assert UPLOAD_CANARY not in response.text
        assert all(
            UPLOAD_CANARY not in value
            for value in response.headers.values()
        )

    get_response = client.get("/api/upload-test")
    assert get_response.status_code == 404
    assert get_response.json() == {"detail": "Not Found"}


def test_upload_test_route_and_generated_schema_are_absent_from_openapi():
    schema = api_module.app.openapi()

    assert "/api/upload-test" not in schema["paths"]
    assert UPLOAD_CANARY not in str(schema)
    assert all(
        "upload_test" not in name.casefold()
        and "upload-test" not in name.casefold()
        for name in schema.get("components", {}).get("schemas", {})
    )


def test_health_contract_is_unchanged():
    response = TestClient(api_module.app).get("/api/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert "/api/health" in api_module.app.openapi()["paths"]


def test_analyze_success_serialization_cleanup_and_llm_isolation(
    monkeypatch,
    tmp_path,
):
    created_paths = _track_api_temp_files(monkeypatch, tmp_path)
    analyze_calls = []

    def fake_analyze(log_sources):
        analyze_calls.append(log_sources)
        assert all(Path(source["path"]).exists() for source in log_sources)
        return _empty_analysis()

    def fail_llm_client(*args, **kwargs):
        raise AssertionError("the API route must not call an LLM provider")

    monkeypatch.setattr(api_module, "analyze", fake_analyze)
    monkeypatch.setattr(llm.genai, "Client", fail_llm_client)

    response = TestClient(api_module.app).post(
        "/api/analyze",
        files=_analyze_files(),
    )

    assert response.status_code == 200
    body = response.json()
    assert set(body) == {
        "analysis_id",
        "status",
        "summary",
        "results",
        "global_correlation",
        "ai_summary",
    }
    assert body["status"] == "completed"
    assert body["summary"] == {
        "total_sources": 3,
        "total_ips": 0,
        "detected_ips": 0,
        "high_risk_ips": 0,
    }
    assert body["results"] == []
    assert body["global_correlation"] == {}
    assert body["ai_summary"] is None
    assert len(analyze_calls) == 1
    assert [source["source"] for source in analyze_calls[0]] == [
        "application",
        "ssh",
        "access",
    ]
    assert len(created_paths) == 3
    assert all(not path.exists() for path in created_paths)


def test_analyze_validation_and_suffix_error_contracts_are_unchanged(
    monkeypatch,
    tmp_path,
):
    client = TestClient(api_module.app)

    validation_response = client.post("/api/analyze")
    assert validation_response.status_code == 422
    assert validation_response.json()["detail"]

    created_paths = _track_api_temp_files(monkeypatch, tmp_path)
    invalid_files = _analyze_files()
    invalid_files["ssh_file"] = (
        "ssh.csv",
        b"ssh event\n",
        "text/csv",
    )

    suffix_response = client.post("/api/analyze", files=invalid_files)

    assert suffix_response.status_code == 400
    assert suffix_response.json() == {
        "detail": "허용되지 않은 파일 형식입니다: .csv"
    }
    assert len(created_paths) == 1
    assert all(not path.exists() for path in created_paths)


def test_analyze_cleanup_is_preserved_when_analysis_fails(
    monkeypatch,
    tmp_path,
):
    created_paths = _track_api_temp_files(monkeypatch, tmp_path)

    def fail_analysis(log_sources):
        assert all(Path(source["path"]).exists() for source in log_sources)
        raise RuntimeError("synthetic analysis failure")

    monkeypatch.setattr(api_module, "analyze", fail_analysis)

    with pytest.raises(RuntimeError, match="synthetic analysis failure"):
        TestClient(api_module.app).post(
            "/api/analyze",
            files=_analyze_files(),
        )

    assert len(created_paths) == 3
    assert all(not path.exists() for path in created_paths)
