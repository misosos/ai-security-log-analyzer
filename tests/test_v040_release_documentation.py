"""Guard the v0.4 release candidate's durable public contract."""

import hashlib
from pathlib import Path
import tomllib


ROOT = Path(__file__).resolve().parents[1]
OLD_RELEASE_SHA256 = {
    "v0.1.0": "72ac3c6ef7aa6b6f3ac80ee32be1941f6cc4ce011914a17511618205de43a843",
    "v0.2.0": "be6e8674dd2dd842a59ea6b742abb3bcd89bc8b53fb20bf271282a9f23e542f2",
    "v0.3.0": "1620be7d32159db89f887bfe3e710ec5a3294c3c943c8cd9c08f8519a5bb5028",
}
OLD_CHANGELOG_SHA256 = "6b7938952d8aa6ef0def62bd4392a843ddb0d63b120c19175ec37b009ffa06e5"
OLD_LOCK_SHA256 = "3e23d1e424d3185c2a0f2ff24237ce7ff415aaa1c0368df15c9138bb01b6a037"


def _read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def test_v040_version_matches_lock_without_dependency_changes():
    project = tomllib.loads(_read("pyproject.toml"))["project"]
    lock_text = _read("uv.lock")
    lock = tomllib.loads(lock_text)
    roots = [item for item in lock["package"] if item["name"] == project["name"]]
    assert len(roots) == 1
    assert project["version"] == roots[0]["version"] == "0.4.0"
    old_root = 'name = "ai-security-log-analyzer"\nversion = "0.4.0"'
    assert lock_text.count(old_root) == 1
    normalized = lock_text.replace(old_root, old_root.replace("0.4.0", "0.3.0"))
    assert _sha256(normalized.encode()) == OLD_LOCK_SHA256
    assert project["dependencies"] == [
        "fastapi>=0.141.1", "google-genai>=2.24.0", "pandas>=3.0.5",
        "python-dotenv>=1.2.3", "python-multipart>=0.0.32", "uvicorn>=0.52.4",
    ]


def test_old_release_notes_and_changelog_entries_are_unchanged():
    for version, digest in OLD_RELEASE_SHA256.items():
        assert _sha256((ROOT / f"docs/releases/{version}.md").read_bytes()) == digest
    changelog = _read("CHANGELOG.md")
    assert changelog.index("## [0.4.0]") < changelog.index("## [0.3.0]")
    assert _sha256(changelog[changelog.index("## [0.3.0]"):].encode()) == OLD_CHANGELOG_SHA256


def test_v040_notes_are_durable_and_scoped():
    note = _read("docs/releases/v0.4.0.md")
    for required in (
        "source checkout", "uv sync --locked --dev", "wheel/PyPI",
        "전체 폭", "왼쪽 탐색", "예시 데이터", "내 로그 분석", "상세 보기",
        "Lucide", "axe", "Playwright", "Safari 18.6", "Option+Tab", "200%",
        "320 CSS px", "VoiceOver", "NOT_TESTED", "WCAG 2.2 AA",
        "API", "SSE", "오류", "계정", "IP", "경로", "원문",
        "공격 성공", "침해", "docs", "SECURITY",
    ):
        assert required.lower() in note.lower()
    for transient in (
        "초안", "아직 push", "tag가 없다", "Release가 없다", "CI 대기",
        "CI 미검증", "working tree", "origin/main", "현재 SHA", "queued",
    ):
        assert transient not in note
    assert "WCAG 2.2 AA 준수** 선언으로 해석하지 않는다" in note
    for unsupported_claim in ("WCAG 2.2 AA를 준수한다", "WCAG 2.2 AA 준수 완료"):
        assert unsupported_claim not in note
    assert "v030_safari_acceptance_27_1.md" in note
    assert "ui_safari_acceptance_28_5.md" in note


def test_readme_map_and_checklist_link_release_without_claiming_publication():
    readme = _read("README.md")
    index = _read("docs/index.md")
    checklist = _read("docs/release_checklist.md")
    assert "v0.4.0 노트" in readme and "docs/releases/v0.4.0.md" in readme
    assert "v0.3.0 Release" in readme
    assert "releases/v0.4.0.md" in index
    assert "ui_safari_acceptance_28_5.md" in index
    assert "## v0.4.0 로컬 릴리스 후보" in checklist
    assert "39547071832" in checklist
    assert "정확한 새 후보 SHA의 원격 CI" in checklist
    assert "NOT_TESTED" in checklist and "320 CSS px" in checklist
    assert "wheel/PyPI" in checklist
