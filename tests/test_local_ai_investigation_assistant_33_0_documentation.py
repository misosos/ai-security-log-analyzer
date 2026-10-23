from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_phase_33_0_design_has_closed_scope_and_roadmap():
    doc = (ROOT / "docs/local_ai_investigation_assistant_33_0.md").read_text()
    for text in (
        "상태: 설계 gate 통과, 구현은 미시작",
        "| 개인정보 | FAIL |",
        "`build_llm_input()`",
        "조사 보조 설명이며 탐지·위험도·조사 사례의 권위 있는 결과가 아닙니다.",
        "checkpoint metadata",
        "top-k 5",
        "citation mismatch",
        "embedding index가 manifest보다 우선하지 않는다",
        "Gemini",
        "33.1 진입 gate 후보",
        "34.0",
    ):
        assert text in doc


def test_readme_and_api_design_disclose_existing_gemini_boundary():
    readme = (ROOT / "README.md").read_text()
    api_doc = (ROOT / "docs/linux_audit_api_design.md").read_text()
    assert "별도로 호출하면 IP가 포함된 projection" in readme
    assert "자유 문자열 응답을 검증 없이 반환" in readme
    assert "legacy public projection에 대상 IP가 포함" in api_doc


def test_design_names_threats_and_synthetic_acceptance_metrics():
    doc = (ROOT / "docs/local_ai_investigation_assistant_33_0.md").read_text()
    for text in (
        "로그 간접 prompt injection", "corpus poisoning", "embedding inversion",
        "DNS rebinding", "crash dump/swap", "resource exhaustion",
        "citation precision/completeness", "unsupported claim rate",
        "privacy leakage count", "deterministic retrieval",
    ):
        assert text in doc
