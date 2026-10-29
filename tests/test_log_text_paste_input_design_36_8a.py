from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
DESIGN = ROOT / "docs" / "log_text_paste_input_design_36_8a.md"


def _text() -> str:
    return DESIGN.read_text(encoding="utf-8")


def test_design_has_all_required_sections_and_is_design_only():
    text = _text()
    headings = re.findall(r"^## (\d+)\. ", text, flags=re.MULTILINE)
    assert headings == [str(number) for number in range(1, 21)]
    assert "API·Frontend·Parser·Detector를 구현하지 않았다" in text
    assert "`UNVERIFIED`" in text
    assert "제안이며 아직 계약이 아니다" in text
    assert "`PHASE_36_8A_TEXT_PASTE_INPUT_DESIGN_LOCAL_CONDITIONAL_GO`" in text


def test_design_preserves_upload_contract_and_single_source_caveats():
    text = " ".join(_text().split())
    for token in (
        "POST /api/v1/investigations",
        "application_file",
        "ssh_file",
        "access_file",
        "세 파일을 각각 정확히 하나",
        "32 KiB",
        "80 KiB",
        "96 KiB",
        "2048 bytes",
        "512줄",
        "6회/60초",
        "동시 1건",
        "source 하나",
        "빈 파일 또는 임시 placeholder를 만들지 않는다",
        "안전 판정이 아니다",
        "single-source end-to-end contract = UNVERIFIED",
    ):
        assert token in text


def test_design_requires_shared_admission_and_closed_text_api():
    text = _text()
    for token in (
        "POST /api/v1/investigations/text",
        "schema_version",
        "log_text",
        "duplicate JSON key",
        "하나의 limiter를 공유",
        "별도 endpoint가 별도 limiter를 만들면 업로드 경로의 제한을 우회",
        "`Content-Length`는 조기 거절 힌트",
        "96 KiB",
        "TemporaryDirectory",
        "ChecklistRegistry",
        "OpenAPI",
    ):
        assert token in text


def test_design_records_privacy_partial_scope_ui_and_test_plan():
    text = _text()
    for token in (
        "Clipboard API",
        "localStorage",
        "sessionStorage",
        "IndexedDB",
        "외부 LLM/API",
        "입력한 로그 범위에서만 분석한 결과입니다",
        "HTML report",
        "44×44px",
        "200% equivalent reflow",
        "invalid UTF-8",
        "비동기 응답",
        "RED in later implementation",
        "실제 사용자 자료·조직 운영·자동 대응은 `NO_GO`",
    ):
        assert token in text
