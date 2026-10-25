from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_phase_33_4b_documents_versioned_public_projection_and_limits():
    doc = (ROOT / "docs/public_investigation_privacy_33_4b.md").read_text()
    privacy = (ROOT / "docs/public_analysis_privacy.md").read_text()
    readme = (ROOT / "README.md").read_text()
    index = (ROOT / "docs/index.md").read_text()

    for contract in (
        "c70a8190f62bfff7f6c12069ba38a9ccb15fe5fa",
        "40160045789", "2,662 passed", "2 warnings", "0건",
        "수정 전", "schema를 1에서 2로", "subject_alias",
        "대상 A", "응답 밖에서 안정된 대상 식별자가 아니며",
        "schema 2", "schema 3", "lexical guidance", "NOT_TESTED",
        "CONDITIONAL_GO", "Phase 33.4C", "인증·권한·감사 기록",
    ):
        assert contract in doc
    assert "schema_version=2" in privacy
    assert "같은 필드에 별칭을 넣어 의미만 조용히 바꾸지 않는다" in privacy
    assert "응답 안에서만 유효한 대상 별칭" in readme
    assert "public_investigation_privacy_33_4b.md" in index
