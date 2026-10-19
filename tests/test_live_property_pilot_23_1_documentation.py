"""Keep the bounded dev-only property pilot and artifact boundary explicit."""

from pathlib import Path
import tomllib


ROOT = Path(__file__).resolve().parents[1]
PILOT = ROOT / "docs" / "hypothesis_property_testing_pilot_23_1.md"


def test_pilot_is_dev_only_and_runtime_source_has_no_import():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert "hypothesis==6.170.0" in project["dependency-groups"]["dev"]
    assert not any("hypothesis" in item for item in project["project"]["dependencies"])
    for source in (ROOT / "app").rglob("*.py"):
        body = source.read_text(encoding="utf-8")
        assert "import hypothesis" not in body
        assert "from hypothesis import" not in body


def test_pilot_documents_real_boundaries_and_does_not_claim_unverified_linux():
    text = PILOT.read_text(encoding="utf-8")
    for phrase in (
        "CONDITIONAL GO", "native code", "--no-build-package", "database=None",
        "derandomize=False", "RuleBasedStateMachine", "CRLF", "LINE_TOO_LONG",
        "2,252 passed", "provenance", "Ubuntu", "실제 CI 선택/실행 결과",
        "운영 탐지율", "trusted detection history", ".hypothesis/",
    ):
        assert phrase in text
    assert "hypothesis_property_testing_pilot_23_1.md" in (
        ROOT / "docs/index.md").read_text(encoding="utf-8")
