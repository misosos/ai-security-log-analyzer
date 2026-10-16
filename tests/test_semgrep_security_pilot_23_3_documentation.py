"""Preserve the evidence and limits of the stopped Semgrep image pilot."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PILOT = ROOT / "docs" / "semgrep_security_pilot_23_3.md"


def test_pilot_records_verifiable_supply_chain_stop():
    text = PILOT.read_text(encoding="utf-8")
    for fact in (
        "SUPPLY_CHAIN_BLOCKED",
        "1.181.0-nonroot",
        "sha256:67dd4c7c224746d827c722513b2268eb692af21c274a6b7f3552deaa4865277b",
        "sha256:4c45f49cb3014f0f2428709f2f759bd5fb27c83845acb4b8ae0e5cee130e29e6",
        "semgrep/semgrep-proprietary",
        "72d3525fe7e02f486428386078f192f8c4756804",
        "0f6e09374a8743d5ef1d5a2b778ad24568552335",
        "semgrep --pro --version",
        "서명, SLSA provenance",
    ):
        assert fact in text


def test_pilot_does_not_present_unrun_checks_as_passed():
    text = PILOT.read_text(encoding="utf-8")
    for boundary in (
        "docker run", "NOT_TESTED", "finding snippet", "Docker layer cache",
        "--network none", "--read-only", "--cap-drop ALL", "--metrics=off",
        "--disable-version-check", "--oss-only", "Semgrep baseline이 아니다",
        "CI에 Semgrep 단계를 넣지 않는다",
    ):
        assert boundary in text
    assert "Semgrep scan PASS" not in text
    assert "semgrep_security_pilot_23_3.md" in (ROOT / "README.md").read_text(encoding="utf-8")


def test_project_dependency_and_ci_remain_semgrep_free():
    for relative in ("pyproject.toml", "uv.lock", ".github/workflows/ci.yml"):
        assert "semgrep" not in (ROOT / relative).read_text(encoding="utf-8").lower()
