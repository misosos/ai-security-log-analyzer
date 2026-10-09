from html.parser import HTMLParser
import os
from pathlib import Path
import stat
import subprocess
import sys
import tomllib

from fastapi.testclient import TestClient

import app.analyzer.llm as llm
import app.api as api_module


ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
DEMO = ROOT / "docs" / "final_demo_guide.md"
DEFAULT_SAMPLES = (
    ROOT / "sample_logs" / "brute_force.log",
    ROOT / "sample_logs" / "ssh_auth.log",
    ROOT / "sample_logs" / "web_shell.log",
)
LINUX_AUDIT_SAMPLE = (
    ROOT
    / "sample_logs"
    / "linux_audit_session_process_co_observation_contract_synthetic.log"
)


class _StandaloneHtmlParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []
        self.remote_references = []

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        for name, value in attrs:
            if name in {"href", "src"} and value:
                self.remote_references.append(value)


def _run_cli(*arguments):
    return subprocess.run(
        [sys.executable, "-m", "app.main", *arguments],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )


def test_environment_help_and_documented_paths_match_current_contract():
    readme = README.read_text(encoding="utf-8")
    demo = DEMO.read_text(encoding="utf-8")
    project = tomllib.loads(
        (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    )["project"]

    assert project["requires-python"] == ">=3.12"
    assert "Python 3.12 이상" in readme
    for command in (
        "uv sync --locked --dev",
        "uv run python -m app.main --help",
        "uv run python -m app.main",
        "uv run python -m app.main --html-report investigation.html",
        "open investigation.html",
        "uv run uvicorn app.api:app --host 127.0.0.1 --port 8000",
        "curl --fail --silent http://127.0.0.1:8000/api/health",
        "uv run pytest",
    ):
        assert command in readme
    for path in (*DEFAULT_SAMPLES, LINUX_AUDIT_SAMPLE):
        assert path.is_file()
    assert "docs/final_demo_guide.md" in readme
    assert DEMO.is_file()
    assert "GEMINI_API_KEY" in readme
    assert "선택적 개발 경계" in readme
    assert "실제 credential, 사용자 로그, LLM 또는 외부 네트워크는 필요하지 않습니다" in demo
    for obsolete in (
        "uvicorn main:app",
        "python app/main.py",
        "pip install -r requirements.txt",
    ):
        assert obsolete not in readme

    help_result = _run_cli("--help")
    assert help_result.returncode == 0
    assert help_result.stderr == ""
    assert "--linux-audit PATH" in help_result.stdout
    assert "--html-report PATH" in help_result.stdout


def test_demo_guide_is_bounded_reproducible_and_has_safe_cleanup():
    demo = DEMO.read_text(encoding="utf-8")

    for heading in (
        "## 1. 시연 목적",
        "## 2. 사전 조건",
        "## 3. 실행 명령",
        "## 4. 화면에서 확인할 결과",
        "## 5. 결과별 권장 설명",
        "## 6. 개인정보 및 해석 경고",
        "## 7. 안전한 정리",
        "## 8. 문제 해결",
    ):
        assert heading in demo
    for expected in (
        "약 5–7분",
        "Brute Force",
        "Password Spraying-like",
        "Path Traversal",
        "Account N",
        "원본 로그",
        "원래 HTTP path와 전체 query",
        "상관관계는 인과관계가 아니며",
        "HTTP 200은 공격 성공을 입증하지 않습니다",
        "rm -- investigation.html",
    ):
        assert expected in demo
    for prohibited in (
        "rm -rf",
        "rm -r",
        "/Users/",
        "/home/",
        "C:\\Users\\",
        "BEGIN PRIVATE KEY",
        "Authorization: Bearer ",
    ):
        assert prohibited not in demo


def test_default_sample_cli_analysis_is_successful_and_bounded():
    result = _run_cli()

    assert result.returncode == 0
    assert result.stderr == ""
    for detection in (
        "  - brute_force",
        "  - password_spraying_like",
        "  - path_traversal",
    ):
        assert detection in result.stdout
    for correlation in (
        "  - failed_to_successful_login",
        "  - brute_force_to_successful_login",
    ):
        assert correlation in result.stdout
    for risk in ("Risk        : HIGH", "Risk        : MEDIUM", "Risk        : LOW"):
        assert risk in result.stdout
    assert "Failed attempts : 5" in result.stdout
    assert "Target accounts : 4" in result.stdout
    assert "Response size   : 2048 bytes" in result.stdout
    assert "confirmed compromise" not in result.stdout.casefold()


def test_documented_html_report_is_private_standalone_and_no_overwrite(tmp_path):
    destination = tmp_path / "investigation.html"
    result = _run_cli("--html-report", str(destination))

    assert result.returncode == 0
    assert result.stderr == ""
    assert result.stdout.endswith("HTML investigation report created.\n")
    assert destination.is_file()
    if hasattr(os, "chmod"):
        assert stat.S_IMODE(destination.stat().st_mode) == 0o600

    original_bytes = destination.read_bytes()
    html = original_bytes.decode("utf-8")
    parser = _StandaloneHtmlParser()
    parser.feed(html)

    assert html.startswith("<!doctype html>\n")
    assert '<html lang="ko">' in html
    assert "보안 로그 조사 보고서" in html
    assert "<dt>분석 대상 수</dt>\n<dd>10</dd>" in html
    assert "<dt>HIGH 위험도</dt>\n<dd>4</dd>" in html
    assert "<dt>MEDIUM 위험도</dt>\n<dd>1</dd>" in html
    assert "<dt>LOW 위험도</dt>\n<dd>5</dd>" in html
    assert "<dt>지원 탐지 관찰 수</dt>\n<dd>4</dd>" in html
    assert "<dt>지원 상관관계 관찰 수</dt>\n<dd>3</dd>" in html
    ordered_subjects = (
        "조사 순서 1 — 분석 대상 IP 10.0.0.5",
        "조사 순서 2 — 분석 대상 IP 192.168.1.20",
        "조사 순서 3 — 분석 대상 IP 192.168.1.30",
        "조사 순서 4 — 분석 대상 IP 192.168.1.60",
    )
    positions = tuple(html.index(value) for value in ordered_subjects)
    assert positions == tuple(sorted(positions))
    assert "Account 1" in html
    for prohibited in (
        ">alice<",
        ">admin<",
        "file=../../etc/passwd",
        "url_decoded_query",
        "raw_records",
        "PROCTITLE",
        "Authorization:",
        "Cookie:",
        "<script",
    ):
        assert prohibited not in html
    assert parser.remote_references == []

    repeated = _run_cli("--html-report", str(destination))
    assert repeated.returncode != 0
    assert repeated.stdout == ""
    assert "HTML report destination is invalid." in repeated.stderr
    assert str(destination) not in repeated.stderr
    assert "Traceback" not in repeated.stderr
    assert "<!doctype html>" not in repeated.stderr
    assert destination.read_bytes() == original_bytes


def test_default_api_health_analyze_and_route_boundaries(monkeypatch):
    def fail_llm_client(*args, **kwargs):
        raise AssertionError("default API must not call the LLM")

    monkeypatch.setattr(llm.genai, "Client", fail_llm_client)
    client = TestClient(api_module.app)

    health = client.get("/api/health")
    assert health.status_code == 200
    assert health.json() == {"status": "ok"}

    handles = [path.open("rb") for path in DEFAULT_SAMPLES]
    try:
        response = client.post(
            "/api/analyze",
            files={
                "application_file": (
                    "application.log",
                    handles[0],
                    "text/plain",
                ),
                "ssh_file": ("ssh.log", handles[1], "text/plain"),
                "access_file": ("access.log", handles[2], "text/plain"),
            },
        )
    finally:
        for handle in handles:
            handle.close()

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "completed"
    assert body["summary"] == {
        "total_sources": 3,
        "total_ips": 10,
        "detected_ips": 4,
        "high_risk_ips": 4,
    }
    assert body["ai_summary"] is None
    assert len(body["results"]) == 10
    assert client.post("/api/analyze").status_code == 422
    assert client.post("/api/upload-test").status_code == 404
    assert client.get("/api/analyze-linux-audit").status_code == 404
    assert client.get("/internal/readiness").status_code == 404
    assert "/api/html-report" not in api_module.app.openapi()["paths"]


def test_linux_audit_cli_html_boundary_is_count_only(tmp_path):
    destination = tmp_path / "linux-audit-investigation.html"
    result = _run_cli(
        "--linux-audit",
        str(LINUX_AUDIT_SAMPLE),
        "--html-report",
        str(destination),
    )

    assert result.returncode == 0
    assert result.stderr == ""
    html = destination.read_text(encoding="utf-8")
    assert "Linux Audit 집계" in html
    assert "프로세스 관찰 수" in html
    assert "세션-프로세스 공동 관찰 수" in html
    for detail in (
        "SYNTHETIC_SESSION_PROCESS_SECRET_DO_NOT_EXPOSE",
        "PROCTITLE",
        "raw_records",
        "source_instance",
        "event_id",
        "/dev/shm/",
        "audit_session_id",
    ):
        assert detail not in html


def test_expected_html_path_failures_are_bounded_and_path_private(tmp_path):
    existing = tmp_path / "existing.html"
    existing.write_text("original", encoding="utf-8")
    symlink_target = tmp_path / "target.html"
    symlink_target.write_text("target", encoding="utf-8")
    symlink = tmp_path / "destination.html"
    symlink.symlink_to(symlink_target)
    invalid_targets = (
        tmp_path / "wrong.txt",
        tmp_path / "missing-parent" / "report.html",
        existing,
        symlink,
    )

    for target in invalid_targets:
        result = _run_cli("--html-report", str(target))

        assert result.returncode != 0
        assert result.stdout == ""
        assert "HTML report destination is invalid." in result.stderr
        assert str(target) not in result.stderr
        assert "Traceback" not in result.stderr
        assert "<!doctype html>" not in result.stderr
    assert existing.read_text(encoding="utf-8") == "original"
    assert symlink_target.read_text(encoding="utf-8") == "target"
