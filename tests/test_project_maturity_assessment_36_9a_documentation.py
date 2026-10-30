from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ASSESSMENT = ROOT / "docs" / "project_maturity_readiness_assessment_36_9a.md"
INDEX = ROOT / "docs" / "index.md"


def test_phase_36_9a_assessment_records_exact_gate_and_scope():
    text = ASSESSMENT.read_text(encoding="utf-8")

    assert "09b8a649e71f8b21eab03c485c1b5b258ad6c586" in text
    assert "41003791594" in text
    assert "artifact 0" in text.lower()
    assert "79/79" in text
    assert "21/21" in text
    assert "운영환경 precision/recall이 아니다" in text
    assert "PHASE_36_9A_PROJECT_MATURITY_ASSESSMENT_LOCAL_CONDITIONAL_GO" in text


def test_phase_36_9a_assessment_has_readiness_table_and_single_next_phase():
    text = ASSESSMENT.read_text(encoding="utf-8")

    for label in (
        "IMPLEMENTED", "PARTIAL", "PROTOTYPE", "DESIGN_ONLY",
        "NOT_IMPLEMENTED", "UNIT_VERIFIED", "SYNTHETIC_E2E_VERIFIED",
        "USER_ACCEPTED_SYNTHETIC", "LINUX_CI_VERIFIED", "UNVERIFIED", "BLOCKED",
        "DEFECT", "VALIDATION_GAP", "CAPABILITY_GAP", "ENVIRONMENT_BLOCKER",
        "Q1.", "Q2.",
    ):
        assert label in text
    assert "최우선 추천 Phase" in text
    assert "Phase 36.9B" in text
    assert "docs/index.md" in INDEX.read_text(encoding="utf-8")
    assert "project_maturity_readiness_assessment_36_9a.md" in INDEX.read_text(encoding="utf-8")


def test_phase_36_9a_preserves_no_go_and_vector_blocker_boundaries():
    text = ASSESSMENT.read_text(encoding="utf-8")

    assert "실제 사용자 자료: `NO_GO`" in text
    assert "조직 운영: `NO_GO`" in text
    assert "자동 대응: `NO_GO`" in text
    assert "USER_ACTION_REQUIRED / ISOLATION_BLOCKED" in text
    assert "OS-level hard memory cap: 미보장" in text
