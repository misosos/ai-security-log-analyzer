"""Phase 34.0 remains a design gate, not an automatic collection feature."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DESIGN = ROOT / "docs/automatic_log_collection_design_34_0.md"


def test_design_covers_the_bounded_syslog_pilot_contract():
    text = DESIGN.read_text(encoding="utf-8")
    for phrase in (
        "CONDITIONAL_GO",
        "NOT_IMPLEMENTED",
        "loopback 전용 TCP Syslog",
        "RFC 6587",
        "STARTING",
        "LISTENING",
        "DEGRADED",
        "FAILED",
        "STOPPED",
        "connection당 framing buffer",
        "1 MiB serialized-byte estimate",
        "raw message",
        "analysis pipeline",
        "checkpoint namespace",
        "원격 수집",
        "AI parser",
    ):
        assert phrase in text


def test_design_compares_alternatives_and_preserves_phase_33_boundaries():
    text = DESIGN.read_text(encoding="utf-8")
    for phrase in (
        "Unix domain socket",
        "journald",
        "파일 tail",
        "Fluent Bit",
        "Vector",
        "OpenTelemetry Collector",
        "embedding production 통합은 `NO_GO`",
        "STORAGE_SETUP_BLOCKED",
        "10개 안내 항목은 최종 사용자 응답 `PASS`",
        "실제 자료 export와 조직 사용",
        "Gemini",
        "cross-source correlation",
        "exactly-once",
    ):
        assert phrase in text


def test_design_records_primary_research_and_mapping_limits():
    text = DESIGN.read_text(encoding="utf-8")
    for phrase in (
        "RFC 5424",
        "RFC 6587",
        "Python asyncio streams",
        "Fluent Bit",
        "Vector",
        "OpenTelemetry",
        "OWASP Logging Cheat Sheet",
        "NIST SP 800-92",
        "Research Basis",
        "Observable Evidence Mapping",
        "Limitations",
    ):
        assert phrase in text


def test_repository_navigation_and_readme_limit_collection_to_synthetic_loopback_pilot():
    index = (ROOT / "docs/index.md").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    phase_33d = (ROOT / "docs/trusted_analyst_report_user_acceptance_33_5d.md").read_text(
        encoding="utf-8"
    )
    assert "automatic_log_collection_design_34_0.md" in index
    assert "합성 입력의 loopback TCP Syslog pilot 범위만" in readme
    assert "원격·실제 사용자 로그 수집은 지원하지 않습니다" in readme
    assert "최종 사용자 응답은 10개 모두 `PASS`" in phase_33d
    assert "조직 사용은 **NO_GO**" in phase_33d


def test_design_does_not_claim_a_listener_or_remote_collection_is_implemented():
    text = DESIGN.read_text(encoding="utf-8")
    assert "자동 로그 수집은 `NOT_IMPLEMENTED`" in text
    assert "원격 수집은 인증·암호화 전까지 `NO_GO`" in text
    assert "이 단계에서는 네트워크 listener" in text
