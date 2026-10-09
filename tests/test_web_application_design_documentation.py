import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DESIGN = ROOT / "docs" / "web_application_design.md"


def _text() -> str:
    return DESIGN.read_text(encoding="utf-8")


def _normalized() -> str:
    return " ".join(_text().split())


def test_web_design_has_complete_numbered_structure_and_diagrams():
    text = _text()

    headings = re.findall(r"^## (\d+)\. ", text, flags=re.MULTILINE)
    assert headings == [str(number) for number in range(1, 27)]
    assert text.count("```mermaid") == 3
    for node in (
        "Sample endpoint",
        "Authentication and authorization",
        "Authenticated ingestion",
        "Accessible live dashboard",
    ):
        assert node in text


def test_general_web_local_cli_and_three_modes_are_explicit():
    text = _text()

    assert "웹은 일반 사용자의 기본 진입점" in text
    assert "CLI는 로컬·민감 환경" in text
    assert "Public sample demo" in text
    assert "Local/private upload mode" in text
    assert "Hosted authenticated upload mode" in text
    assert "user upload와 user payload retention이 없다" in text
    assert "hosted upload는 no-go" in text
    for gate in ("authentication", "tenant isolation", "HTTPS"):
        assert gate in text


def test_current_api_and_sample_frontend_are_recorded_with_local_only_upload():
    text = _normalized()

    for route in ("GET /api/health", "POST /api/analyze"):
        assert route in text
    for field in ("application_file", "ssh_file", "access_file"):
        assert f"`{field}`" in text
    assert "10 MiB" in text
    assert "CORS middleware도 없다" in text
    assert "GET /assets/style.css" in text
    assert "GET /assets/app.js" in text
    assert "합성 샘플 Landing/결과 개요" in text
    assert "loopback-only `POST /api/v1/investigations`" in text
    assert "Hosted upload" in text and "no-go" in text
    assert "기존 `/api/analyze` route와 상위 구조는 유지하지만 deprecated" in text
    assert "nested 값은 Phase 6.2" in text


def test_versioned_api_is_one_analysis_privacy_safe_contract():
    text = _text()

    assert "POST /api/v1/investigations/sample" in text
    assert "POST /api/v1/investigations" in text
    assert "one request 안에서 deterministic analysis는 한 번" in text
    assert "case adapter는 한 번" in text
    assert "result GET endpoint" in text
    assert "TO_BE_BENCHMARKED" in text
    for excluded in (
        "raw logs",
        "original accounts",
        "full query",
        "source filename/path",
        "internal error",
        "Linux Audit argv/PROCTITLE/CWD/PATH detail",
    ):
        assert excluded in text
    assert "기본 `llm_summary_available`은 false" in text


def test_bounded_error_and_upload_security_are_recoverable():
    text = _text()

    for field in (
        "error_code",
        "user_message",
        "recovery_action",
        "field",
        "retryable",
        "result_state",
    ):
        assert field in text
    for threat in (
        "oversized upload",
        "multipart abuse",
        "filename traversal",
        "misleading extension/MIME",
        "decompression bomb",
        "slow upload",
        "duplicate submission",
        "tenant data mix-up",
        "prompt-injection-like text",
        "formula/HTML injection",
    ):
        assert threat in text
    assert "archive는 V1에서 지원하지 않는다" in text
    assert "exception text, traceback, absolute path" in text
    assert "실패를 빈/0 결과로 위장하지 않는다" in text


def test_data_lifecycle_and_llm_boundary_are_explicit():
    text = _text()

    for state in (
        "raw input",
        "derived result",
        "HTML",
        "application log",
        "backup",
        "retention",
        "deletion",
        "crash",
    ):
        assert state in text
    assert "raw logs는 기본적으로 영구 저장하지 않는다" in text
    assert "기본 웹 분석은 LLM을 호출하지 않는다" in text
    assert "unchecked-by-default" in text
    assert "raw log" in text and "전송하지 않고" in text


def test_accessibility_and_responsive_requirements_are_release_gates():
    text = _text()

    for requirement in (
        'lang="ko"',
        "skip link",
        "visible label",
        "fieldset`/`legend",
        "error summary heading으로 focus",
        "visible focus",
        "keyboard-only",
        "색상에만 의존하지 않는다",
        "Timeline DOM order",
        'visible `caption`',
        '<th scope="col">',
        "200% zoom",
        "prefers-reduced-motion",
        "aria-live",
        "native HTML",
    ):
        assert requirement in text
    assert "준수”를 주장하지 않는다" in text
    assert "narrow mobile" in text
    assert "page-wide horizontal scroll이 없다" in text


def test_usability_account_wording_and_wireframes_are_testable():
    text = _text()

    for target in ("10초", "30초", "60초"):
        assert target in text
    assert "계정 별칭을 표시할 수 없음" in text
    assert "원래 계정 정보는 개인정보 보호를 위해 결과에 포함되지 않습니다" in text
    assert "이는 오류, 서로 다른 계정 또는 분석 실패를 뜻하지 않는다" in text
    for screen in (
        "Landing",
        "Upload",
        "Progress",
        "Results overview",
        "Case list",
        "Case detail",
        "Independent observations",
        "Error state",
        "Privacy/data handling page",
    ):
        assert f"#### {screen}" in text
    for contract in ("[Primary:", "[Secondary:", "Status:", "Error", "A11y:"):
        assert contract in text


def test_html_frontend_realtime_and_roadmap_decisions_are_bounded():
    text = _text()

    assert "추천 V1은 FastAPI와 같은 origin" in text
    assert "static vanilla HTML/CSS/JavaScript" in text
    assert "조사 사례/Timeline이 없음을 명확히 표시" in text
    assert "기존 renderer에 privacy-safe case projection" in text
    assert "secure CLI writer를 호출하지 않고" in text
    assert "웹사이트는 사용자의 로컬 로그를 자동으로 읽을 수 없다" in text
    assert "local collector" in text
    assert "이벤트마다 LLM을 호출하지 않는다" in text
    for phase in range(9):
        assert f"Phase {phase}" in text


def test_implemented_phase_four_report_contract_is_stateless_and_bounded():
    text = _text()
    for contract in (
        "구현된 Phase 4 stateless HTML 보고서 다운로드",
        "같은 analysis result",
        "25,000 bytes",
        "32 KiB",
        "64 KiB",
        "REPORT_GENERATION_FAILED",
        "standalone_html",
        "investigation-report.html",
        "byte_count",
        "HTML 보고서 다운로드",
        "Blob/object URL",
        "조사 사례의 typed Timeline은 포함하지",
        "서버 측 결과/HTML 영구 저장은 없다",
        "Phase 5가 아래에서 local-only upload를 추가한다",
        "Hosted deployment·LLM 설명은 여전히 범위 밖",
    ):
        assert contract in text


def test_phase_five_local_upload_limits_and_hosted_no_go_are_documented():
    text = _text()
    for contract in (
        "구현된 Phase 5 loopback/local-only 세 로그 업로드",
        "POST /api/v1/investigations",
        "LocalInvestigationResponse",
        "application_file", "ssh_file", "access_file",
        "32 KiB", "80 KiB", "96 KiB", "2048바이트", "512줄",
        "0700", "0600", "O_NOFOLLOW", "UTF-8 incremental decoder",
        "Starlette 1.6.0", "python-multipart 0.0.32",
        "max_part_size", "ASGI/proxy 단일 청크",
        "crash orphan cleanup", "Hosted actual-log upload는 no-go",
        "--no-access-log --no-proxy-headers",
        "field-linked 오류", "Safari 시각·키보드",
    ):
        assert contract in text


def test_deployment_gates_and_usability_protocol_define_no_go():
    text = _text()

    for gate in (
        "authentication 또는 per-action authorization 없음",
        "tenant isolation/ownership test 없음",
        "end-to-end HTTPS 없음",
        "processing/upload timeout",
        "temporary file permission",
        "raw log retention",
        "permissive wildcard CORS",
        "CSRF 방어 없음",
        "dependency/image vulnerability",
        "blocking accessibility defect",
        "명시적 선택 없이 LLM",
    ):
        assert gate in text
    for metric in (
        "task completion rate",
        "time on task",
        "잘못된 보안 결론 수",
        "다음 단계 선택 정확도",
        "perceived workload",
    ):
        assert metric in text


def test_official_references_and_repository_safety_are_documented():
    text = _text()

    for reference in (
        "https://www.w3.org/TR/WCAG22/",
        "https://www.w3.org/WAI/tutorials/forms/",
        "https://www.w3.org/WAI/tutorials/tables/",
        "https://www.w3.org/WAI/ARIA/apg/",
        "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
        "https://fastapi.tiangolo.com/tutorial/request-files/",
    ):
        assert reference in text
    forbidden = (
        "/Users/",
        "BEGIN PRIVATE KEY",
        "AKIA",
        "Authorization: Bearer ",
    )
    for value in forbidden:
        assert value not in text
