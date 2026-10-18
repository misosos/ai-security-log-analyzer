"""Guard the bounded development-only OpenAPI property pilot record."""

from pathlib import Path
import tomllib


ROOT = Path(__file__).resolve().parents[1]
PILOT = ROOT / "docs" / "schemathesis_api_pilot_23_5.md"


def test_pilot_records_supply_chain_native_and_output_boundaries():
    text = PILOT.read_text(encoding="utf-8")
    for phrase in (
        "4.31.1", "6.170.0", "0.58.6", "32", "27", "SHA-256",
        "macOS arm64", "Ubuntu x86_64", "native", "Mach-O", "ELF",
        "provenance", "reproducible build", "NETWORK_DENIED", "curl",
        "synthetic", "no report upload", "CONDITIONAL GO",
    ):
        assert phrase in text
    assert "Schemathesis proves API security" not in text


def test_pilot_dependency_is_dev_only_and_ci_is_wheel_only():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert "schemathesis==4.31.1" in project["dependency-groups"]["dev"]
    assert "hypothesis==6.170.0" in project["dependency-groups"]["dev"]
    assert all("schemathesis" not in item for item in project["project"]["dependencies"])
    lock = (ROOT / "uv.lock").read_text(encoding="utf-8")
    assert 'name = "schemathesis"' in lock
    assert 'name = "jsonschema-rs"' in lock
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "uv sync --dev --locked --no-build" in workflow
    assert "tests/test_schemathesis_api_pilot_23_5.py" in workflow
    assert "schemathesis" not in " ".join(path.read_text(encoding="utf-8").lower()
                                        for path in (ROOT / "app").rglob("*.py"))


def test_pilot_distinguishes_covered_and_not_covered_routes():
    text = PILOT.read_text(encoding="utf-8")
    for phrase in (
        "POST /api/v1/investigations/sample", "GET /api/v1/live/status",
        "POST /api/analyze", "NOT_COVERED", "multipart", "SSE",
        "testclient", "loopback", "database=None", "max_examples",
        "deadline", "Linux CI", "79/79", "21/21", "70/70",
    ):
        assert phrase in text
