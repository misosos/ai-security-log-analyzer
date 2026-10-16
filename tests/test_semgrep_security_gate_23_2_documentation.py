"""Guard the design-only, local-only Phase 23.2 static-analysis gate."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "docs" / "semgrep_security_gate_23_2.md"


def test_gate_records_supply_chain_and_offline_boundaries():
    text = GATE.read_text(encoding="utf-8")
    for phrase in (
        "1.181.0", "LGPL-2.1-or-later", "macOS arm64", "Ubuntu x86_64",
        "--metrics=off", "--disable-version-check", "--oss-only",
        "network deny", "local rule", "CONDITIONAL GO", "no installation",
        "Ruff", "Bandit", "CodeQL",
    ):
        assert phrase in text


def test_gate_has_scoped_rules_and_no_unverified_scan_claim():
    text = GATE.read_text(encoding="utf-8")
    for phrase in (
        "DOM HTML sink", "browser storage", "shell=True", "HTTP exception",
        "should-match", "should-not-match", "false positive", "false negative",
        "not a Semgrep baseline", "source snippet", "SARIF", "Phase 23.3",
    ):
        assert phrase in text
    assert "Semgrep scan PASS" not in text


def test_gate_keeps_dependency_and_ci_unchanged():
    assert "semgrep" not in (ROOT / "pyproject.toml").read_text(encoding="utf-8").lower()
    assert "semgrep" not in (ROOT / "uv.lock").read_text(encoding="utf-8").lower()
    assert "semgrep" not in (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8").lower()
