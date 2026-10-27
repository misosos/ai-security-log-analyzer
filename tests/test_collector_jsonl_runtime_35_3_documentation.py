from pathlib import Path


def test_runtime_documentation_records_scope_and_boundaries():
    text = Path("docs/collector_jsonl_runtime_35_3.md").read_text()
    for phrase in ("Vector binary", "실제 사용자 자료", "공개 API", "shared collection lock",
                   "NOT_TESTED", "Research Basis", "Observable Evidence Mapping", "Limitations"):
        assert phrase in text
    assert "analysis parity" in text.lower()
