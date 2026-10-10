"""Automated web acceptance paths; not a timed user study."""

from pathlib import Path

from fastapi.testclient import TestClient

from app.api import create_app


ROOT = Path(__file__).resolve().parents[1]
SAMPLES = (
    ("application_file", "brute_force.log"),
    ("ssh_file", "ssh_auth.log"),
    ("access_file", "web_shell.log"),
)


def _files(*, omit: str | None = None):
    return [
        (field, ("synthetic.txt", (ROOT / "sample_logs" / name).read_bytes(), "text/plain"))
        for field, name in SAMPLES if field != omit
    ]


def test_first_user_sample_real_and_missing_file_recovery():
    client = TestClient(create_app(), base_url="http://127.0.0.1:8000", client=("127.0.0.1", 50000))
    assert client.get("/").status_code == 200
    assert client.get("/api/health").json() == {"status": "ok"}

    sample = client.post("/api/v1/investigations/sample")
    assert sample.status_code == 200
    sample_data = sample.json()
    assert sample_data["case_summary"]["case_count"] == 2
    assert sample_data["case_summary"]["independent_observation_count"] == 4
    assert sample_data["cases"][0]["timeline"]
    assert sample_data["cases"][0]["next_steps"]
    assert sample_data["report_export"]["available"] is True

    missing = client.post("/api/v1/investigations", files=_files(omit="ssh_file"))
    assert missing.status_code == 422
    assert missing.json()["error_code"] == "MISSING_FIELD"
    assert missing.json()["field"] == "ssh_file"
    assert missing.json()["retryable"] is False

    local = client.post("/api/v1/investigations", files=_files())
    assert local.status_code == 200
    local_data = local.json()
    assert local_data["local_context"]["label"] == "로컬 실제 로그 분석 결과"
    assert local_data["case_summary"]["case_count"] == 2
    assert local_data["case_summary"]["independent_observation_count"] == 4
    assert local_data["report_export"]["available"] is True
    assert "합성 샘플 결과" not in local.text
    assert "synthetic.txt" not in local.text
