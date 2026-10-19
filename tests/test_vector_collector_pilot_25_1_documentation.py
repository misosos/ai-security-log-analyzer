"""Keep the pilot's observed failures distinct from product support."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "vector_collector_pilot_25_1.md"


def test_vector_pilot_documented_as_test_only_no_go():
    document = DOC.read_text(encoding="utf-8")
    index = (ROOT / "docs/index.md").read_text(encoding="utf-8")
    for term in (
        "NO-GO", "합성 SSH", "긴 줄", "rename", "copytruncate", "receiver",
        "checkpoint", "ack", "SO_PEERCRED", "macOS", "Ubuntu", "secure erase",
        "production", "Phase 25.0",
    ):
        assert term in document
    assert "vector_collector_pilot_25_1.md" in index
    assert "NO-GO — 현 구성의 production 연계 및 연속성 주장 금지" in document
    assert "Vector를 CI/pytest에서 자동 다운로드·실행하지 않는다" in document


def test_vector_pilot_never_changes_runtime_dependency_or_ci():
    source = (ROOT / "tests" / "vector_collector_pilot_25_1.py").read_text(encoding="utf-8")
    assert "test-only" in source
    assert "--binary" in source
    assert "--work" in source
    assert "--summary-output" in source
    assert "--verify-summary" in source
    assert "MAX_RECORDS = 256" in source
    assert "PROJECT_MAX_LINE = 2048" in source
