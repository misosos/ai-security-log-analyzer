from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DESIGN = ROOT / "docs" / "investigation_workspace_production_migration_design_36_6a.md"


def test_design_covers_production_prototype_comparison_and_routing_decision() -> None:
    text = DESIGN.read_text(encoding="utf-8")
    for required in (
        "production/prototype 비교",
        "현재 production 구현",
        "승인 prototype 표현",
        "이식 방법",
        "재사용 데이터",
        "UI projection",
        "backend/schema 변경",
        "privacy 위험",
        "접근성 위험",
        "회귀 테스트",
        "구현 Phase",
        "hash routing",
        "History API",
        "동일 document",
        "직접 진입",
        "만료",
    ):
        assert required in text


def test_design_closes_projection_privacy_and_explicit_checklist_contracts() -> None:
    text = DESIGN.read_text(encoding="utf-8")
    for required in (
        "closed UI projection",
        "case_ref",
        "raw log",
        "account",
        "IP",
        "hostname",
        "checkpoint",
        "명시적 버튼",
        "POST",
        "자동 요청",
        "citation",
        "직접 증거가 아닙니다",
        "detection",
        "relation",
        "risk",
        "case",
    ):
        assert required in text


def test_design_blocks_accessibility_gaps_and_defines_phases_and_rollback() -> None:
    text = DESIGN.read_text(encoding="utf-8")
    for required in (
        "320px",
        "200%",
        "overflow-x: hidden",
        "19px",
        "keyboard-only",
        "focus visible",
        "ARIA",
        "screen-reader",
        "reduced-motion",
        "axe",
        "36.6B",
        "36.6C",
        "36.6D",
        "36.6E",
        "36.6F",
        "36.6G",
        "rollback",
        "production 이식 미구현",
        "Safari",
        "NO_GO",
    ):
        assert required in text
