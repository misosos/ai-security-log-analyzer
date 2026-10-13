"""Phase 16 design-only contract: source scope, parity, privacy, and no-go gates."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DESIGN = ROOT / "docs" / "live_analysis_correlation_case_design.md"


def _design() -> str:
    return DESIGN.read_text(encoding="utf-8")


def test_current_scope_and_batch_prefix_contract_are_explicit():
    text = _design()
    for required in (
        "Phase 16 설계·계약 검증", "단일", "application", "SSH", "access",
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
    assert "worker의 queue ack 이후 detection commit과 함께 확정" in readme


def test_phase_16_1_scope_and_phase_16_3_publication_are_distinguished():
    text = _design()
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    monitoring = (ROOT / "docs" / "live_log_monitoring_design.md").read_text(encoding="utf-8")
    for required in (
        "Phase 16.1 구현 갱신", "application-only 내부", "Phase 16.3",
        "assess_risk_with_metadata()", "같은 메타데이터 snapshot",
        "IncidentCaseSubjectInput", "exact identity", "256 PARSED event / 256 KiB",
        "LIVE_ANALYSIS_HISTORY_LIMIT", "Spray case no-go", "tracemalloc",
        "운영 SLA", "SSH·access·cross-source",
    ):
        assert required in text
    assert "`analysis_changes` SSE" in readme
    assert "Phase 16.3 안전한 표시" in monitoring
    assert "case projection의 `subject_ip`" in monitoring


def test_phase_16_2_worker_boundary_and_phase_16_3_safe_projection():
    text = _design()
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for required in (
        "Phase 16.2 worker 결합", "queue ack", "detection commit", "analysis commit",
        "기존 detection publication", "DEGRADED", "terminal `FAILED`",
        "256 PARSED event/256KiB", "observation_changes", "Phase 16.3",
        "SSH·access·cross-source", "exactly-once",
    ):
        assert required in text
    assert "safe DTO" in text
    assert "원래 subject, 계정, IP" in text
    assert "기존 `observation_changes`는 유지" in readme


def test_phase_16_2_verification_records_each_fault_and_measurement_limit():
    record = (ROOT / "docs" / "live_analysis_16_2_verification.md").read_text(encoding="utf-8")
    monitoring = (ROOT / "docs" / "live_log_monitoring_design.md").read_text(encoding="utf-8")
    assert "live_analysis_16_2_verification.md" in _design()
    assert "live_analysis_16_2_verification.md" in monitoring
    for number in range(1, 26):
        assert f"| {number:02d} |" in record
    for required in (
        "tracemalloc", "55.367ms", "1.310ms", "256 PARSED event",
        "warm-up 2", "측정 12회", "status HTTP 40회", "p95",
        "같은 process", "0.5초", "운영 SLA", "실제 config", "observation_changes",
        "TestClient lifespan", "Phase 16.3", "GO", "exactly-once",
    ):
        assert required in record
