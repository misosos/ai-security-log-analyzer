import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DESIGN = ROOT / "docs" / "incident_case_timeline_design.md"


def _text():
    return DESIGN.read_text(encoding="utf-8")


def test_design_exists_is_utf8_and_has_required_sections():
    text = _text()

    assert len(text) > 10_000
    headings = re.findall(r"^## (\d+)\. ", text, flags=re.MULTILINE)
    assert headings == [str(number) for number in range(1, 24)]


def test_personas_and_core_tasks_are_explicit():
    text = _text()

    for persona in ("초보 보안 학습자", "주니어 보안 분석가"):
        assert persona in text
    for task in (
        "분석 입력 선택",
        "분석 실행",
        "첫 조사 사례 찾기",
        "구성 이유 확인",
        "Timeline 이해",
        "단계별 근거 확인",
        "사실과 해석 구분",
        "미확인 사항 확인",
        "다음 조사 단계 선택",
        "저장·공유",
    ):
        assert task in text
    for contract in (
        "시작 조건",
        "성공 조건",
        "필요한 정보",
        "가능한 오류와 복구",
        "접근성 요구사항",
    ):
        assert contract in text


def test_plain_language_contract_uses_investigation_case_not_incident_verdict():
    text = _text()

    assert "사용자 화면의 기본 표시명은 **조사 사례**" in text
    assert "Incident Case | 조사 사례" in text
    for non_goal in (
        "확정된 보안 사고",
        "공격 성공",
        "침해 확인",
        "공격자 식별",
        "자동 대응 단위",
    ):
        assert non_goal in text
    assert "report-local deterministic `조사 사례 N`" in text
    assert "persistent ID" in text


def test_grouping_and_separation_are_deterministic_and_evidence_bounded():
    text = _text()

    for rule_id in (
        "CASE-AUTH-TRANSITION-01",
        "CASE-BRUTE-SUCCESS-01",
        "CASE-SPRAY-SUCCESS-01",
    ):
        assert rule_id in text
    for invariant in (
        "하나의 canonical observation은 최대 한 사례",
        "입력 event, dict, subject 순서가 달라도",
        "독립 관찰",
        "자동 결합하지 않",
        "raw `global_correlation`은 case에 넣지 않는다",
        "Linux Audit aggregate는 count-only 별도 섹션",
    ):
        assert invariant in text
    for deferred in (
        "Path Traversal과 인증 사건 자동 결합",
        "Linux Audit process/session과 로그인 자동 결합",
        "GeoIP",
        "User-Agent similarity",
        "LLM grouping",
        "campaign identification",
    ):
        assert deferred in text


def test_timeline_and_time_contracts_are_typed_and_timezone_explicit():
    text = _text()

    for field in (
        "timeline_order",
        "entry_kind",
        "start_time_utc",
        "end_time_utc",
        "display_time_kst",
        "account_alias",
        "source_category",
        "evidence_reference",
        "limitation_ids",
    ):
        assert f"`{field}`" in text
    for boundary in (
        'ZoneInfo("Asia/Seoul")',
        "KST (UTC+09:00)",
        "timezone-aware UTC",
        "system timezone",
        "시간 정보 없음",
        "DOM/screen-reader reading order",
    ):
        assert boundary in text


def test_risk_and_review_order_do_not_create_a_new_score():
    text = _text()

    assert "포함된 최고 위험도" in text
    assert "새 severity를 계산하지 않는다" in text
    assert "numeric security score" in text
    assert "새 점수가 아닙니다" in text
    assert "navigation aid" in text
    assert "risk/confidence 변경 또는 새 numeric score 0" in text


def test_privacy_boundary_forbids_raw_and_private_values_everywhere():
    text = _text()

    for prohibited in (
        "raw log line",
        "full query",
        "original account",
        "credential",
        "cookie",
        "token",
        "source absolute path",
        "argv",
        "`PROCTITLE`",
        "CWD",
        "PATH detail",
        "internal repr",
        "exception payload",
    ):
        assert prohibited in text
    for surface in (
        "case projection field tree",
        "timeline projection",
        "HTML, CLI, API response, LLM input",
        "test failure output",
    ):
        assert surface in text
    for forbidden_serializer in (
        "`asdict()`",
        "`vars()`",
        "`__dict__`",
        "generic recursive serialization",
        "arbitrary dict passthrough",
    ):
        assert forbidden_serializer in text


def test_accessibility_is_a_release_gate_not_a_claim():
    text = _text()

    for requirement in (
        'lang="ko"',
        "heading hierarchy",
        "visible `<caption>`",
        '`<th scope="col">`',
        "색상뿐 아니라",
        "keyboard만으로",
        "focus visible",
        "200% text 확대",
        "horizontal scroll fallback",
        "screen-reader reading order",
        "JavaScript 없어도",
        "animation, auto refresh, timeout 없음",
        "icon만으로",
    ):
        assert requirement in text
    assert "WCAG 2.2 AA 준수를 주장하지 않는다" in text
    assert "실제 browser/assistive technology 검증 전" in text


def test_usability_acceptance_and_future_protocol_are_measurable():
    text = _text()

    for target in (
        "10초 이내",
        "30초 이내",
        "60초 이내",
        "task completion rate",
        "time on task",
        "잘못된 보안 결론 수",
        "도움 요청 횟수",
        "다음 단계 선택 정확도",
        "용어 이해도",
        "perceived workload",
        "통계적 일반화",
    ):
        assert target in text
    assert "아직 실제 사용자에게 검증되지 않았다" in text
    assert "초보 보안 학습자 3–5명" in text
    assert "주니어 분석가 3–5명" in text


def test_empty_error_ai_and_scope_boundaries_are_bounded():
    text = _text()

    for state in (
        "case 없음",
        "독립 관찰만 있음",
        "timestamp 없음",
        "supported correlation 없음",
        "supported detection 없음",
        "Linux Audit aggregate 없음",
        "일부 입력 parse 실패",
        "분석 입력 없음",
        "case 구성 내부 실패",
        "HTML 생성 실패",
    ):
        assert state in text
    for ai_boundary in (
        "AI는 case를 구성·병합·분리하지 않고",
        "Timeline entry를 추가하지 않는다",
        "risk, confidence 또는 case order를 변경하지 않는다",
        "No LLM grouping",
        "no LLM risk overwrite",
        "no automatic response",
    ):
        assert ai_boundary in text
    assert "### 포함" in text
    assert "### 보류" in text


def test_roadmap_and_go_no_go_define_stop_conditions():
    text = _text()

    for phase in range(7):
        assert f"Phase {phase}" in text
    for gate in (
        "grouping invariant 위반 0",
        "privacy canary 노출 0",
        "unsupported relationship 생성 0",
        "input ordering에 따른 case 구조·순서 변화 0",
        "supported observation 유실 0",
        "duplicate observation 0",
        "bounded error 위반 0",
        "keyboard 접근을 막는 구조 0",
        "색상만으로 상태를 전달하는 구조 0",
    ):
        assert gate in text
    assert "수동 검증 없이 visual acceptance 금지" in text


def test_mermaid_and_official_research_references_are_well_formed():
    text = _text()
    diagrams = re.findall(r"```mermaid\n(.*?)```", text, flags=re.DOTALL)

    assert len(diagrams) == 2
    for diagram in diagrams:
        assert diagram.startswith("flowchart ")
        assert "-->" in diagram
        assert diagram.count("[") == diagram.count("]")
        assert "<script" not in diagram.casefold()
    for official_domain in ("csrc.nist.gov", "nist.gov", "w3.org/WAI"):
        assert official_domain in text
    assert "2026-10-08" in text
    for private_path in ("/Users/", "/home/", "C:\\Users\\"):
        assert private_path not in text
