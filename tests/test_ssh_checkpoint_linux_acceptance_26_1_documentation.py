"""Keep Ubuntu SSH acceptance distinct from the earlier full-suite result."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_ubuntu_gate_has_a_real_process_smoke_step() -> None:
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert "Verify Linux SSH checkpoint recovery and process ownership" in workflow
    assert "uv run pytest -q tests/test_ssh_checkpoint_26_0.py" in workflow
    assert "uv run python tests/smoke_ssh_checkpoint_26_0.py" in workflow
    assert "runs-on: ubuntu-24.04" in workflow
    assert "permissions:\n  contents: read" in workflow


def test_audit_does_not_promote_unrun_ubuntu_smoke_to_pass() -> None:
    document = (ROOT / "docs/ssh_checkpoint_linux_acceptance_26_1.md").read_text(encoding="utf-8")
    for required in (
        "CONDITIONAL GO", "39201600155", "2,333 passed", "경고 2개",
        "SSH 별도 프로세스 lock·CLI restart smoke를 실행하지 않았다",
        "Ubuntu CI 대기", "NOT_TESTED", "PARTIAL", "257번째 parsed event",
        "0700", "0600", "FROM_END", "NO-GO", "Secure erase",
    ):
        assert required in document
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "docs/ssh_checkpoint_linux_acceptance_26_1.md" in readme
