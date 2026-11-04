"""Product-oriented README information architecture contract for Phase 36.15A1."""

import re
from pathlib import Path
from urllib.parse import unquote


ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
RECORD = ROOT / "docs" / "readme_information_architecture_36_15a1.md"
INDEX = ROOT / "docs" / "index.md"


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_readme_leads_with_product_value_workflow_and_synthetic_screen():
    text = _text(README)
    lines = text.splitlines()

    assert lines[0] == "# AI Security Log Analyzer"
    assert "방어 목적의 로컬 조사 보조 도구" in "\n".join(lines[:12])
    assert "docs/images/review-queue-36-13a1/01-desktop-default-1440.png" in text
    assert "합성 예시" in "\n".join(lines[:24])
    assert (
        "파일·텍스트 입력 → 입력 품질 → 탐지 → 관계·위험도 → 검토 건 → "
        "활동 흐름·확인할 작업 → 보고서"
    ) in text
    assert lines.index("## 빠른 시작") + 1 <= 60


def test_readme_has_scannable_scope_interpretation_and_privacy_boundaries():
    text = _text(README)

    assert "## 지원 입력" in text
    for source in ("application 인증 로그", "OpenSSH 인증 로그", "웹 access 로그", "Linux Audit"):
        assert source in text
    for meaning in (
        "탐지는 조사할 관찰",
        "상관관계는 인과관계가 아님",
        "로그인 성공은 공격 성공이 아님",
        "HTTP 200은 유출 성공이 아님",
        "`reviewed`가 해결·안전·오탐 확정을 뜻하지 않음",
        "`deferred`가 낮은 위험을 뜻하지 않음",
    ):
        assert meaning in text
    for boundary in (
        "외부 LLM을 호출하지 않습니다",
        "원본 로그·credential·개인정보",
        "공개 Issue",
        "secure erase",
        "SIEM·EDR·WAF·자동 대응 제품이 아닙니다",
        "실제 사용자 자료·조직 운영·자동 대응은 계속 `NO_GO`",
    ):
        assert boundary in text


def test_readme_folds_history_and_states_current_acceptance_and_distribution():
    text = _text(README)

    assert "<details>" in text
    assert "<summary><strong>검증·파일럿 기록과 역사적 경계</strong></summary>" in text
    assert "Phase 36.14F" in text and "12/12 PASS" in text
    assert "document memory" in text
    assert "API·SQLite·Web Storage 없음" in text
    assert "Phase 36.15A" in text and "STANDALONE_BUNDLE_FIRST" in text
    assert "standalone bundle은 아직 구현·배포되지 않음" in text


def test_readme_links_are_local_reachable_and_content_is_bounded():
    text = _text(README)

    assert len(text.splitlines()) <= 120
    assert len(text.encode("utf-8")) <= 17_000
    for target in re.findall(r"!?(?:\[[^]]*\])\(([^)]+)\)", text):
        if target.startswith(("https://", "http://", "mailto:", "#")):
            continue
        relative = target.split("#", 1)[0]
        assert (README.parent / unquote(relative)).is_file(), target
    for forbidden in (
        "ahead/behind",
        "origin/main...HEAD",
        "/Users/",
        "C:\\Users\\",
    ):
        assert forbidden not in text
    assert re.search(r"GitHub Actions (?:run|Run) `?\d{8,}`?", text) is None


def test_information_architecture_record_and_index_are_present():
    record = _text(RECORD)
    index = _text(INDEX)

    assert "readme_information_architecture_36_15a1.md" in index
    for repository in (
        "grafana/loki",
        "SigmaHQ/sigma",
        "WithSecureOpenSource/chainsaw",
        "openobserve/openobserve",
        "ollama/ollama",
    ):
        assert repository in record
    for decision in (
        "가치 제안",
        "빠른 시작",
        "합성 화면",
        "지원 범위와 제한",
        "외부 문장·이미지·asset을 복사하지 않았다",
    ):
        assert decision in record
