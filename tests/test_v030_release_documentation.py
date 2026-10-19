"""Keep the v0.3 release candidate's durable public contract explicit."""

from pathlib import Path
import tomllib


ROOT = Path(__file__).resolve().parents[1]


def test_current_version_lock_and_changelog_match() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    lock = tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))
    roots = [item for item in lock["package"] if item["name"] == project["name"]]
    assert len(roots) == 1
    assert project["version"] == roots[0]["version"] == "0.3.0"
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert changelog.index("## [0.3.0]") < changelog.index("## [0.2.0]")


def test_release_note_is_durable_and_states_supported_boundary() -> None:
    note = (ROOT / "docs/releases/v0.3.0.md").read_text(encoding="utf-8")
    for required in (
        "source checkout", "uv sync --locked --dev", "app.monitor_setup",
        "--show", "--delete", "--reset-checkpoint", "--monitor",
        "application", "SSH", "FROM_END", "bounded replay",
        "개인정보", "2,343", "79/79", "21/21", "70/70",
        "rotation", "copytruncate", "cross-source", "exactly-once",
        "wheel/PyPI", "WCAG 2.2 AA", "SECURITY",
    ):
        assert required.lower() in note.lower()
    for temporary in ("초안", "아직 push하지 않았다", "tag가 없다", "CI 미확인"):
        assert temporary not in note
    assert "공격 성공" in note and "침해" in note


def test_readme_and_checklist_do_not_promote_unverified_release_gates() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    checklist = (ROOT / "docs/release_checklist.md").read_text(encoding="utf-8")
    assert "`pyproject.toml`의 `0.3.0`" in readme
    assert "docs/releases/v0.3.0.md" in readme
    assert "## v0.3.0 로컬 릴리스 후보" in checklist
    for state in ("PASS", "BLOCKED", "NOT_TESTED", "NOT_APPLICABLE"):
        assert state in checklist
    assert "최종 SHA 원격 CI: **BLOCKED**" in checklist
    assert "Safari" in checklist and "NOT_TESTED" in checklist


def test_private_security_reporting_and_public_issue_warning() -> None:
    policy = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
    assert "Security → Report a vulnerability" in policy
    assert "공개 Issue" in policy
    for sensitive in ("실제 로그", "credential", "개인정보"):
        assert sensitive in policy
    assert "비활성 상태" not in policy
