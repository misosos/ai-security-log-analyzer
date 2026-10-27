from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "collector_jsonl_runtime_linux_acceptance_35_3a.md"


def test_linux_acceptance_record_separates_remote_evidence_and_limits():
    text = DOC.read_text(encoding="utf-8")
    for phrase in (
        "Ubuntu 24.04", "PENDING_REMOTE_CI", "NOT_TESTED", "synthetic",
        "roles=2 runs=80", "SIGINT", "SIGTERM", "queue-full", "33-record",
        "256", "port reuse", "file descriptor", "task", "artifact",
        "IPv6", "Vector", "actual user data", "NO_GO", "operational SLA",
        "account metadata", "exactly-once", "durable replay",
    ):
        assert phrase in text
    assert "COLLECTOR_JSONL_LINUX_ACCEPTANCE_PASS roles=2 runs=80 synthetic=1 leaks=0" in text
    assert "40452774780" in text and "2,934" in text
    assert "JSONL runtime의 합성 Ubuntu 수용 범위만 `GO`" in text
    assert "tests/accept_collector_jsonl_runtime_35_3a.py" in text
    assert "tests/test_collector_jsonl_runtime_linux_ci_35_3a.py" in text


def test_runtime_record_links_linux_acceptance_without_claiming_vector_or_user_data():
    runtime = (ROOT / "docs" / "collector_jsonl_runtime_35_3.md").read_text(encoding="utf-8")
    core = (ROOT / "docs" / "collector_jsonl_adapter_core_35_2.md").read_text(encoding="utf-8")
    for text in (runtime, core):
        assert "collector_jsonl_runtime_linux_acceptance_35_3a.md" in text
        assert "Vector" in text and "NOT_TESTED" in text
        assert "NO_GO" in text


def test_navigation_links_linux_reliability_record_and_preserves_scope():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    index = (ROOT / "docs" / "index.md").read_text(encoding="utf-8")
    assert "collector_jsonl_runtime_linux_acceptance_35_3a.md" in index
    assert "Linux" in readme and "NOT_TESTED" in readme
    assert "actual user data" in readme.lower() or "실제 사용자 자료" in readme
