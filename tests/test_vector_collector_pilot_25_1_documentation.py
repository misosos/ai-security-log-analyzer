"""Keep the pilot's observed failures distinct from product support."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "vector_collector_pilot_25_1.md"


def test_vector_pilot_documented_as_test_only_no_go():
    document = DOC.read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for term in (
        "NO-GO", "합성 SSH", "긴 줄", "rename", "copytruncate", "receiver",
        "checkpoint", "ack", "SO_PEERCRED", "macOS", "Ubuntu", "secure erase",
        "production", "Phase 25.0",
    ):
        assert term in document
    assert "docs/vector_collector_pilot_25_1.md" in readme
    assert "production 연계는 NO-GO" in readme
    assert "Vector는 설치·자동 실행·CI 필수 단계에 포함되지 않습니다" in readme


def test_vector_pilot_never_changes_runtime_dependency_or_ci():
    source = (ROOT / "tests" / "vector_collector_pilot_25_1.py").read_text(encoding="utf-8")
    assert "test-only" in source
    assert "--binary" in source
    assert "--work" in source
    assert "--summary-output" in source
    assert "--verify-summary" in source
    assert "MAX_RECORDS = 256" in source
    assert "PROJECT_MAX_LINE = 2048" in source
