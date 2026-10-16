"""The SSH parity gate must not claim a feature that remains unsupported."""

from pathlib import Path


DOCUMENT = Path(__file__).resolve().parents[1] / "docs/ssh_live_analysis_design_gate_22_2.md"


def test_ssh_gate_separates_batch_oracle_from_live_feature() -> None:
    text = DOCUMENT.read_text(encoding="utf-8")
    assert "기존 SSH batch 의미 재사용은 조건부 GO" in text
    assert "현재 live 분석 공개 연결은 NO-GO" in text
    assert "기존 batch oracle과 아직 존재하지 않는 SSH live analysis 결과의 parity를 주장하지 않는다" in text
    assert "detection-only" in text and "별도 batch" in text
    assert "SSH durable restart는 이번 gate의 NO-GO" in text


def test_ssh_gate_preserves_security_and_privacy_limits() -> None:
    text = DOCUMENT.read_text(encoding="utf-8")
    for boundary in (
        "LIVE_ANALYSIS_UNSUPPORTED_SOURCE", "같은 계정·IP", "60초",
        "120초", "동률", "raw microseconds", "unsupported_result_shape",
        "CASE-BRUTE-SUCCESS-01", "spray case", "Global·web·cross-source",
        "원본 로그", "계정/IP/path/query/evidence/예외", "ack 전에 fail closed",
        "FROM_END", "두 event batch 원자성", "개인정보", "Docker Linux/arm64",
    ):
        # English and Korean technical labels are both intentionally present.
        assert boundary in text
    assert "계정 탈취·동일 행위자" in text
