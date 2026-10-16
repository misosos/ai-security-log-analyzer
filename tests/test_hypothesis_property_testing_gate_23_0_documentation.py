"""Phase 23.0 records a bounded, non-installing property-test gate."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DESIGN = ROOT / "docs" / "hypothesis_property_testing_gate_23_0.md"


def test_gate_preserves_design_only_and_supply_chain_boundary():
    text = DESIGN.read_text(encoding="utf-8")
    assert "CONDITIONAL GO" in text
    assert "6.170.0" in text
    assert "MPL-2.0" in text and "Apache-2.0" in text
    assert "sortedcontainers" in text and "maturin" in text
    assert "native" in text and "sdist" in text
    assert "별도 승인" in text
    assert "production runtime dependency" in text
    assert "실제 결함 발견이나 CI 비용 합격은 아직 입증하지 않았다" in text


def test_gate_selects_nonduplicative_bounded_properties_and_private_failures():
    text = DESIGN.read_text(encoding="utf-8")
    for contract in (
        "application", "ssh", "access", "PARSED/IGNORED/REJECTED",
        "strict UTF-8", "CRLF", "partial LF", "RuleBasedStateMachine",
        "resident=available+leased", "stale lease", "FIFO", "ack된 record만",
        "database=None", "@example", "UTC", "Asia/Seoul", "Privacy-safe",
        "checkpoint", "publication", "suffix-or-gap", "기존 수작업 조합",
        "실제 로그·경로·credential", "NO-GO",
    ):
        assert contract in text
    assert "운영 SLA가 아니다" in text


def test_gate_is_linked_without_claiming_feature_support():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "hypothesis_property_testing_gate_23_0.md" in readme
    assert "Hypothesis" in readme
