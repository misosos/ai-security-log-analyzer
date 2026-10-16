"""Linux checkpoint reset audit remains distinct from macOS-only evidence."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_linux_audit_records_runner_and_limits_without_claiming_handoff() -> None:
    audit = (ROOT / "docs/live_checkpoint_epoch_reset_21_8_linux_audit.md").read_text(
        encoding="utf-8",
    )
    for evidence in (
        "ubuntu-24.04", "75715514fd675fff30b69298ea50fe606a92af66",
        "38761273093", "0700", "0600", "advisory", "두 reset 프로세스",
        "FROM_END", "2173 passed", "2 warnings", "NO-GO", "NOT_TESTED",
    ):
        assert evidence in audit
    assert "Phase 21.8 커밋의 Linux CI는 push 후에만" in audit


def test_linux_ci_runs_explicit_checkpoint_reset_process_gate() -> None:
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert "runs-on: ubuntu-24.04" in workflow
    assert "Verify Linux checkpoint reset and process restart" in workflow
    assert "assert sys.platform == 'linux'" in workflow
    assert "test_two_reset_processes_do_not_share_approval_lock" in workflow
    assert "test_cli_explicit_checkpoint_reset_starts_a_new_epoch" in workflow
