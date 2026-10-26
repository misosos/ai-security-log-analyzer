from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "collector_jsonl_adapter_core_35_2.md"
BENCH = ROOT / "tests" / "benchmark_jsonl_adapter_35_2.py"


def test_core_record_documents_scope_contract_and_remaining_gates():
    text = DOC.read_text(encoding="utf-8")
    for required in (
        "Pure Core Scope", "Closed Envelope", "Limits", "Validation and Errors",
        "Queue and Status", "Privacy Boundary", "Verification", "Limitations",
        "Vector", "NOT_TESTED", "Linux", "NO_GO", "operational SLA",
        "Duplicate key", "NaN", "Infinity", "unpaired surrogate", "CRLF",
        "partial close", "Phase 34",
    ):
        assert required in text
    assert "app/log_collection/jsonl_adapter.py" in text
    assert "tests/test_jsonl_adapter_35_2.py" in text
    assert "tests/benchmark_jsonl_adapter_35_2.py" in text
    assert "no listener" in text.lower()
    assert "public API" in text


def test_navigation_and_phase_35_records_reflect_adapter_core_gate():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    index = (ROOT / "docs" / "index.md").read_text(encoding="utf-8")
    phase_35a = (ROOT / "docs" / "vector_framing_preconditions_35_1a.md").read_text(encoding="utf-8")
    supply = (ROOT / "docs" / "vector_supply_chain_audit_35_1.md").read_text(encoding="utf-8")
    design = (ROOT / "docs" / "enterprise_log_collection_architecture_35_0.md").read_text(encoding="utf-8")
    for text in (index, phase_35a, supply, design):
        assert "collector_jsonl_adapter_core_35_2.md" in text
    assert "PHASE_35_2_ADAPTER_CORE_REQUIRED" in phase_35a
    assert "UNRESOLVED" in phase_35a and "3" in phase_35a
    assert "CHECKSUM_ONLY_ACCEPTED_FOR_ISOLATED_PILOT" in phase_35a
    assert "Vector" in readme and "NOT_TESTED" in readme
    assert "adapter core" in readme.lower()


def test_benchmark_is_test_only_and_reports_required_cases_and_percentiles():
    text = BENCH.read_text(encoding="utf-8")
    for required in (
        "ASCII", "Korean", "one_byte", "batch_32", "maximum_line",
        "refusal", "queue", "median_ms", "p95_ms", "max_ms",
        "payload_bytes", "record_bytes", "queue_accounted_bytes", "operational SLA",
    ):
        assert required in text
