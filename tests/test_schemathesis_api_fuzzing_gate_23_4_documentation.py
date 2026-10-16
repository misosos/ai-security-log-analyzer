"""Guard the design-only Phase 23.4 OpenAPI fuzzing decision."""

from pathlib import Path

from app.api import create_app


ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "docs" / "schemathesis_api_fuzzing_gate_23_4.md"


def test_gate_records_supply_chain_and_no_install_boundary():
    text = GATE.read_text(encoding="utf-8")
    for phrase in (
        "4.31.1", "MIT", "Python 3.12", "6.170.0", "jsonschema-rs",
        "macOS arm64", "Ubuntu x86_64", "local-only", "no installation",
        "CONDITIONAL GO", "Semgrep", "SUPPLY_CHAIN_BLOCKED",
    ):
        assert phrase in text
    for forbidden in ("schemathesis", "jsonschema-rs"):
        assert forbidden not in (ROOT / "pyproject.toml").read_text(encoding="utf-8").lower()
        assert forbidden not in (ROOT / "uv.lock").read_text(encoding="utf-8").lower()


def test_gate_distinguishes_real_openapi_from_runtime_guards():
    text = GATE.read_text(encoding="utf-8")
    for phrase in (
        "GET /api/health", "POST /api/analyze",
        "POST /api/v1/investigations/sample", "POST /api/v1/investigations",
        "POST /api/v1/investigations/linux-audit", "GET /api/v1/live/status",
        "GET /api/v1/live/events", "multipart/form-data", "Last-Event-ID",
        "in-process ASGI", "response_schema_conformance", "5xx",
    ):
        assert phrase in text
    paths = create_app().openapi()["paths"]
    assert "/api/v1/live/status" not in paths
    assert "/api/v1/live/events" not in paths
    assert paths["/api/analyze"]["post"]["deprecated"] is True
    assert "requestBody" not in paths["/api/v1/investigations"]["post"]
    assert "requestBody" not in paths["/api/v1/investigations/linux-audit"]["post"]
    assert "requestBody" not in paths["/api/v1/investigations/sample"]["post"]


def test_gate_keeps_artifacts_and_expansion_conditional():
    text = GATE.read_text(encoding="utf-8")
    for phrase in (
        "Phase 23.5", "sample", "live status", "legacy /api/analyze",
        "SSE", "synthetic", "HAR", "VCR", "curl", "no report upload",
        "TestClient", "Dredd", "RESTler", "ZAP", "CI 비용",
    ):
        assert phrase in text
    assert "Schemathesis pilot PASS" not in text
