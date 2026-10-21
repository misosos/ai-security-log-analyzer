"""Current release metadata and durable local-live documentation contracts."""

from pathlib import Path
import tomllib


ROOT = Path(__file__).resolve().parents[1]


def _read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_version_and_lock_metadata_have_one_project_source():
    project = tomllib.loads(_read("pyproject.toml"))["project"]
    lock = tomllib.loads(_read("uv.lock"))
    own = [package for package in lock["package"] if package["name"] == project["name"]]
    assert len(own) == 1
    assert project["version"] == own[0]["version"] == "0.4.0"
    assert project["license"] == "MIT"
    assert _read("docs/releases/v0.1.0.md").startswith("# v0.1.0 로컬 릴리스 노트\n")


def test_changelog_and_release_note_describe_supported_live_scope():
    changelog = _read("CHANGELOG.md")
    note = _read("docs/releases/v0.2.0.md")
    assert changelog.index("## [0.2.0]") < changelog.index("## [0.1.0]")
    for document in (changelog, note):
        for required in (
            "--monitor-config", "FROM_END", "application", "SSH/access",
            "observation_changes", "analysis_changes", "replay gap",
            "source checkout", "exactly-once", "crash recovery", "hosted",
            "WCAG 2.2 AA", "wheel/PyPI",
        ):
            assert required.lower() in document.lower()
        assert "침해" in document and "인과관계" in document
    for ephemeral in (
        "초안", "아직 push하지 않았다", "tag가 아직 없다",
        "이 커밋의 CI는 아직 실행되지 않았다", "d1dbcee5fad",
    ):
        assert ephemeral not in note
    assert "uv sync --locked --dev" in note
    assert "Ctrl+C" in note
    assert "[SECURITY](../../SECURITY.md)" in note


def test_readme_and_checklist_keep_release_execution_separate():
    readme = _read("README.md")
    checklist = _read("docs/release_checklist.md")
    gate = _read("docs/live_monitoring_release_gate_18.md")
    assert "v0.3.0 Release" in readme
    index = _read("docs/index.md")
    assert "releases/v0.2.0.md" in index
    assert "releases/v0.1.0.md" in index
    assert "화면 표시 일시 정지" in readme and "서버 수집을 멈추지" in readme
    assert "## v0.2.0 로컬 릴리스 후보 준비" in checklist
    assert "최종 준비 커밋을 push한 뒤" in checklist
    assert "asset이 **0개**" in checklist
    assert "[ ]" in checklist.split("### 게시 전 별도 gate", 1)[1]
    assert "stream_end" in gate and "NOT_TESTED" in gate
    assert "CONDITIONAL GO" in gate
    assert "WCAG 2.2 AA 준수 주장 금지" in gate
