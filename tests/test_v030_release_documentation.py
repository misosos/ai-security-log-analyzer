"""Keep the v0.3 release candidate's durable public contract explicit."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_historical_changelog_order() -> None:
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
    assert "a3c753a396dbdcd4991212be276caa90f55641e9" not in note
    assert "v030_safari_acceptance_27_1.md" in note
    assert "공격 성공" in note and "침해" in note


def test_readme_and_checklist_do_not_promote_unverified_release_gates() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    checklist = (ROOT / "docs/release_checklist.md").read_text(encoding="utf-8")
    assert "v0.3.0 Release" in readme
    assert "docs/releases/v0.3.0.md" in readme
    assert "docs/v030_safari_acceptance_27_1.md" in readme
    assert "## v0.3.0 로컬 릴리스 후보" in checklist
    for state in ("PASS", "BLOCKED", "NOT_TESTED", "NOT_APPLICABLE"):
        assert state in checklist
    assert "a3c753a396dbdcd4991212be276caa90f55641e9" in checklist
    assert "39205243243" in checklist
    assert "SSH_CHECKPOINT_CLI_SMOKE_PASS" in checklist
    assert "v030_safari_acceptance_27_1.md" in checklist
    assert "CONDITIONAL GO" in checklist
    assert "최종 SHA 원격 CI: **BLOCKED**" not in checklist
    assert "Safari" in checklist and "NOT_TESTED" in checklist


def test_safari_acceptance_keeps_manual_and_automatic_evidence_distinct() -> None:
    record = (ROOT / "docs/v030_safari_acceptance_27_1.md").read_text(encoding="utf-8")
    for required in (
        "a3c753a396dbdcd4991212be276caa90f55641e9",
        "39205243243", "2,347 passed", "SSH_CHECKPOINT_CLI_SMOKE_PASS",
        "Safari 18.6", "127.0.0.1", "application", "SSH", "Option+Tab",
        "--show", "--reset-checkpoint", "FROM_END", "FAILED",
        "Web Inspector", "200%", "VoiceOver", "NOT_TESTED", "CONDITIONAL GO",
        "SSE", "listener",
    ):
        assert required in record
    assert "확인 대기" not in record
    assert "진행 후 증거" not in record


def test_private_security_reporting_and_public_issue_warning() -> None:
    policy = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
    assert "Security → Report a vulnerability" in policy
    assert "공개 Issue" in policy
    for sensitive in ("실제 로그", "credential", "개인정보"):
        assert sensitive in policy
    assert "비활성 상태" not in policy
