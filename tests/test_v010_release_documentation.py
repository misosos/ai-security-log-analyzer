"""Stable release-documentation gates; these do not claim manual acceptance."""

from pathlib import Path
import tomllib


ROOT = Path(__file__).resolve().parents[1]


def _text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_single_project_version_and_locked_source_checkout_commands():
    project = tomllib.loads(_text("pyproject.toml"))
    assert project["project"]["version"] == "0.1.0"
    assert project["project"]["license"] == "MIT"
    assert project["project"]["requires-python"].startswith(">=3.12")
    for path in ("README.md", "docs/releases/v0.1.0.md"):
        text = _text(path)
        assert "uv sync --locked --dev" in text
        assert "uv run python -m app.local_web" in text
        assert "http://127.0.0.1:8000/" in text
        assert "Ctrl+C" in text
        assert "git pull --ff-only" in text
        assert "source checkout" in text
        assert "schema version" in text


def test_release_scope_privacy_limits_and_support_are_explicit():
    readme = _text("README.md")
    note = _text("docs/releases/v0.1.0.md")
    for item in (
        "애플리케이션 인증", "SSH", "웹 접근", "Path Traversal",
        "독립 관찰", "HTML", "32 KiB", "80 KiB", "96 KiB",
        "O_NOFOLLOW", "Windows", "Hosted", "Public internet",
    ):
        assert item in readme + note
    assert "실제 운영환경 탐지율이 아니" in note
    assert "사례 Timeline 전체" in note
    assert "원래 HTTP path" in note
    assert "Python 메모리" in note
    assert "삭제되지 않는다" in note
    assert "침해 사실" in note and "인과관계" in note


def test_changelog_security_and_release_gates_do_not_claim_publication():
    changelog = _text("CHANGELOG.md")
    security = _text("SECURITY.md")
    checklist = _text("docs/release_checklist.md")
    for heading in ("### 추가", "### 보안", "### 변경", "### 알려진 제한"):
        assert heading in changelog
    assert "## [0.1.0] - 2026-10-09" in changelog
    assert "Private vulnerability reporting" in security
    assert "Report a vulnerability" in security
    assert "공개 issue" in security
    assert "응답 SLA" in security
    assert "LICENSE" in checklist and "NO-GO" in checklist
    assert "Safari" in checklist and "- [ ]" in checklist
    assert "GitHub Release" in checklist and "PyPI" in checklist
    assert "수행하지 않았다" in checklist
    license_text = _text("LICENSE")
    assert license_text.startswith("The MIT License\n")
    assert "Copyright (c) 2026 misosos" in license_text
    assert "THE SOFTWARE IS PROVIDED “AS IS”" in license_text
    assert "LICENSE 파일이 없어" not in _text("README.md")


def test_artifact_ignore_is_narrow_and_ci_has_no_release_authority():
    ignore = _text(".gitignore")
    workflow = _text(".github/workflows/ci.yml")
    for pattern in (
        "investigation-report.html", "investigation-report-*.html",
        "__pycache__/", ".pytest_cache/", ".env",
    ):
        assert pattern in ignore
    assert "*.html" not in ignore.splitlines()
    assert "*.log" not in ignore.splitlines()
    for contract in (
        "contents: read", "pull_request:", "main", "timeout-minutes:",
        "uv sync --dev --locked", "uv run pytest -q",
    ):
        assert contract in workflow
    assert "upload-artifact" not in workflow


def test_phase10_release_evidence_separates_remote_ci_from_manual_gates():
    readme = _text("README.md")
    note = _text("docs/releases/v0.1.0.md")
    checklist = _text("docs/release_checklist.md")
    assert "2df45cf54f5dd062a2707b09417c9cd63cc2386a" in checklist
    assert "1,617 passed" in checklist
    assert "79/79" in checklist and "21/21" in checklist
    assert "Allow remote automation" in checklist
    assert "NO-GO" in checklist
    assert "Safari 수동 검증과 원격 CI는 아직 남아" not in readme
    assert "Safari 수동 검증과 원격 CI는 공개 릴리스 전 남은 gate" not in note


def test_phase101_voiceover_is_a_disclosed_follow_up_not_a_release_gate():
    checklist = _text("docs/release_checklist.md")
    note = _text("docs/releases/v0.1.0.md")
    readiness = _text("docs/release_readiness.md")
    assert "VoiceOver 후속 접근성 검증" in checklist
    assert "오류 안내 읽기: NOT_TESTED" in checklist
    assert "VoiceOver 미검증만으로 NO-GO로 판정하지 않는다" in checklist
    assert "WCAG 2.2 AA 준수를 주장하지 않는다" in checklist + note + readiness
    assert "Phase 10.1 로컬 릴리스 후보 접근성 수용 판정: GO" in checklist
    assert "정확한 320 CSS px" in checklist + note + readiness
    assert "이 문서 변경 커밋 자체의 원격 CI" in checklist
