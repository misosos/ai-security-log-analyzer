from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_pair_truncation_record_preserves_evidence_and_vector_boundary() -> None:
    record = (ROOT / "docs/pair_truncation_stability_35_4a1.md").read_text(
        encoding="utf-8"
    )
    for required in (
        "2948 passed, 1 failed, 2 warnings",
        "truncate-application",
        "DID NOT RAISE MultiSourceRuntimeError",
        "상세 traceback은 저장되지 않았고",
        "SOFT_CYCLE_BUDGET_SECONDS",
        "fstat",
        "man7.org/linux/man-pages/man2/ftruncate.2.html",
        "Apple ftruncate(2)",
        "수정 전 이 결정적 테스트는 `DID NOT RAISE`로 실패했다",
        "`test_each_role_file_identity_fault_stops_pair_without_quiet_success[truncate-application]`",
        "| 100 | 0 | 0 |",
        "| 30 | 0 | 0 |",
        "| 20 | 0 | 0 |",
        "2953 passed, 2 warnings",
        "READY_TO_PUSH",
        "ISOLATION_BLOCKED",
        "NO_GO",
    ):
        assert required in record
    assert "Vector binary를 실행하지 않았다" in record


def test_preflight_and_navigation_link_to_regression_record() -> None:
    for relative in (
        "README.md",
        "docs/index.md",
        "docs/vector_artifact_preflight_35_4a.md",
    ):
        text = (ROOT / relative).read_text(encoding="utf-8")
        assert "pair_truncation_stability_35_4a1.md" in text


def test_preflight_retains_isolation_and_supply_chain_decisions() -> None:
    text = (ROOT / "docs/vector_artifact_preflight_35_4a.md").read_text(
        encoding="utf-8"
    )
    for required in (
        "ISOLATION_BLOCKED",
        "CHECKSUM_ONLY_ACCEPTED_FOR_ISOLATED_PILOT",
        "UNRESOLVED 3건",
        "READY_TO_PUSH",
        "전체 pytest 3회 연속 성공",
    ):
        assert required in text
