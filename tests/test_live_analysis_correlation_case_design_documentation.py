"""Phase 16 design-only contract: source scope, parity, privacy, and no-go gates."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DESIGN = ROOT / "docs" / "live_analysis_correlation_case_design.md"


def _design() -> str:
    return DESIGN.read_text(encoding="utf-8")


def test_current_scope_and_batch_prefix_contract_are_explicit():
    text = _design()
    for required in (
        "Phase 16 설계·계약 검증 완료", "단일-source", "application", "SSH", "access",
        "CONDITIONAL GO", "NO-GO", "cross-source", "batch", "prefix",
        "PARSED", "IGNORED", "REJECTED", "out-of-order", "microseconds",
        "closest", "동률", "60초", "120초", "file_access",
        "global_correlation", "256 PARSED event·256KiB", "HISTORY_LIMIT_EXCEEDED",
        "full-prefix", "rolling eviction", "DEGRADED",
    ):
        assert required in text


def test_transaction_identity_membership_and_projection_boundaries():
    text = _design()
    for required in (
        "queue ack", "point of no return", "correlation 또는 risk prepare",
        "case assembly/projection", "detection commit 후 analysis commit 실패",
        "analysis commit 후 publication 실패", "worker summary 실패",
        "LIVE-REL-000001", "LIVE-RISK-000001", "LIVE-CASE-000001",
        "CREATED", "UPDATED", "NO_LONGER_MATCHES", "NO_LONGER_PRESENT",
        "nearest-success", "merge/split", "review order", "supporting",
        "ambiguous_membership", "Spray case", "Path Traversal",
        "계정 별칭을 안전하게 생성할 참조가 없어 표시하지 않습니다.",
        "subject_ip", "LiveAnalysisSnapshot", "LiveRelationSummary",
        "LiveRiskSummary", "LiveCaseSummary", "LiveAnalysisChange",
        "RELATION_CREATED", "RISK_UPDATED", "CASE_NO_LONGER_MATCHES",
        "analysis_changes", "SSE/API/UI에 전달하면 개인정보 경계 위반",
    ):
        assert required in text
    assert "NO_GO_UNTYPED_PRODUCTION_TARGET_MEMBERSHIP" in text
    assert "원래 account" in text
    assert "HTTP path/query" in text
    assert "ack 이후 rollback 주장" in text


def test_research_and_roadmap_do_not_claim_implementation():
    text = _design()
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for required in (
        "NIST SP 800-61 Rev.3", "NIST SP 800-92", "T1110.001", "T1110.003",
        "Observable mapping", "프로젝트 정책", "Phase 16.1", "no-go",
        "실제 file_access", "여러 계정", "비밀번호", "정상 사용자의 재시도",
    ):
        assert required in text
    assert "docs/live_analysis_correlation_case_design.md" in readme
    assert "설계만 완료" in readme
    assert "아직 worker, API, SSE 또는 화면에 연결되지 않았습니다" in readme


def test_phase_16_1_implementation_scope_is_not_presented_as_live_ui():
    text = _design()
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    monitoring = (ROOT / "docs" / "live_log_monitoring_design.md").read_text(encoding="utf-8")
    for required in (
        "Phase 16.1 구현 갱신", "application-only 내부", "미연결",
        "assess_risk_with_metadata()", "같은 메타데이터 snapshot",
        "IncidentCaseSubjectInput", "exact identity", "256 PARSED event / 256 KiB",
        "LIVE_ANALYSIS_HISTORY_LIMIT", "Spray case no-go", "tracemalloc",
        "운영 SLA", "SSH·access·cross-source",
    ):
        assert required in text
    assert "현재 실시간 화면에는 나타나지 않습니다" in readme
    assert "현재 사용자 기능 아님" in monitoring
    assert "case projection의 `subject_ip`" in monitoring
