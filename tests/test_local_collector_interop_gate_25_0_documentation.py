"""Keep the optional collector proposal separate from implemented live contracts."""

from pathlib import Path
import tomllib


ROOT = Path(__file__).resolve().parents[1]
DOCUMENT = ROOT / "docs" / "local_collector_interop_gate_25_0.md"


def test_candidate_is_conditional_and_cites_official_product_contracts() -> None:
    document = DOCUMENT.read_text(encoding="utf-8")
    assert "CONDITIONAL GO" in document
    assert "Vector v0.59.0 + SSH source 하나" in document
    for official in (
        "https://github.com/fluent/fluent-bit/releases/tag/v5.1.4",
        "https://github.com/vectordotdev/vector/releases/tag/v0.59.0",
        "https://docs.fluentbit.io/manual/administration/backpressure",
        "https://vector.dev/docs/reference/configuration/sources/file/",
        "https://vector.dev/docs/reference/configuration/sinks/socket/",
        "https://vector.dev/docs/architecture/buffering-model/",
    ):
        assert official in document
    assert "delivery: best effort" in document
    assert "oldest chunk" in document
    assert "SUPPLY_CHAIN_BLOCKED" in document


def test_data_and_recovery_boundaries_remain_explicit() -> None:
    document = DOCUMENT.read_text(encoding="utf-8")
    for boundary in (
        "parser → detector → correlation → risk → case",
        "두 checkpoint를 독립적인 진실 원본으로 병합하지 않는다",
        "raw_message 자체는 upstream sequence 없음",
        "copytruncate", "old-writer late append", "explicit gap/DEGRADED",
        "trusted", "allowlist safe DTO", "strict UTF-8",
        "같은 UID", "source path", "crash dump", "backup",
        "root 설치", "실제 로그", "checkpoint metadata 확대",
    ):
        assert boundary in document
    assert "무유실·crash recovery는 주장하지 않는다" in document
    assert "spool" in document and "raw retention 확대" in document
    assert "브라우저가 source/path를 변경하지 못하게" in document


def test_roadmap_and_dependencies_are_unchanged_by_design_gate() -> None:
    index = (ROOT / "docs/index.md").read_text(encoding="utf-8")
    assert "local_collector_interop_gate_25_0.md" in index
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    all_dependencies = project["project"]["dependencies"] + project["dependency-groups"]["dev"]
    assert not any("fluent-bit" in item.lower() or "vector" in item.lower() for item in all_dependencies)
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "fluent-bit" not in workflow.lower()
    assert "vector" not in workflow.lower()
