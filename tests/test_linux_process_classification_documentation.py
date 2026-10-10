from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_phase9_contract_and_release_boundaries_documented():
    design = _read("docs/linux_audit_process_execution.md")
    evaluation = _read("docs/detection_evaluation.md")
    readme = _read("README.md")
    changelog = _read("CHANGELOG.md")
    release = _read("docs/releases/v0.1.0.md")
    checklist = _read("docs/release_checklist.md")
    for category in (
        "LINUX_SHELL_INTERPRETER_EXECUTION",
        "LINUX_NETWORK_TRANSFER_UTILITY_EXECUTION",
        "LINUX_PERMISSION_CHANGE_UTILITY_EXECUTION",
        "LINUX_TEMP_DIRECTORY_EXECUTION",
    ):
        assert category in design
    for token in ("exe", "comm", "argv[0]", "PATH", "/tmp", "/var/tmp", "/dev/shm",
                  "SUCCESS", "FAILURE", "UNKNOWN", "LOW", "MEDIUM", "HIGH",
                  "unclassified", "CLI", "API", "LLM", "Red Hat", "MITRE", "NIST"):
        assert token in design
    assert "79/79" in evaluation and "21/21" in evaluation
    assert "실제 운영환경" in evaluation
    assert "Linux Audit 집계·조사 후보" in readme
    assert "21개" in changelog and "21/21" in release
    assert "[ ] Phase 9" in checklist
