from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_phase_33_4_docs_record_bounded_conditional_contract():
    report = (ROOT / "docs/local_investigation_guidance_33_4.md").read_text()
    readme = (ROOT / "README.md").read_text()
    index = (ROOT / "docs/index.md").read_text()
    for marker in (
        "CONDITIONAL_GO", "e803e4c3c25416863213e94eae3c09bf6fc8347b",
        "fe7cc8cbd77319c4ce9a1af731da004eeffc08d272c0ee04174db96eb2897ac6",
        "POST /api/v1/investigations/guidance", "8 KiB request cap",
        "textContent", "NOT_TESTED", "STORAGE_SETUP_BLOCKED", "embedding remains `NO_GO`",
    ):
        assert marker in report
    assert "local_investigation_guidance_33_4.md" in readme
    assert "local_investigation_guidance_33_4.md" in index
    assert "사용자가 요청할 때만" in readme
    assert "LLM, embedding" in report
