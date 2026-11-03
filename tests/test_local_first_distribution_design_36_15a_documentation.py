from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOCUMENT = ROOT / "docs/local_first_distribution_design_36_15a.md"


def _text() -> str:
    assert DOCUMENT.is_file(), "Phase 36.15A local-first distribution design is missing"
    return DOCUMENT.read_text(encoding="utf-8")


def test_phase_36_15a_records_gate_current_runtime_and_closed_decision() -> None:
    text = _text()
    for required in (
        "9185338c7445a8f801ae00276b9e5d285a98809d",
        "41591617594",
        "3638 passed",
        "artifact 0",
        "STANDALONE_BUNDLE_FIRST",
        "Python 3.12",
        "uv sync --locked --dev",
        "uv run python -m app.local_web",
        "127.0.0.1",
        "Node",
        "Windows",
        "Safari",
        "NOT_TESTED",
    ):
        assert required in text


def test_phase_36_15a_compares_every_candidate_and_defines_data_lifecycle() -> None:
    text = _text()
    for required in (
        "기존 개발자 실행 방식",
        "단일 launcher script",
        "Python package / zipapp",
        "PyInstaller onedir",
        "desktop wrapper",
        "Docker",
        "설치",
        "실행",
        "종료",
        "업데이트",
        "제거",
        "임시 자료",
        "코드 서명",
        "notarization",
        "rollback",
    ):
        assert required in text


def test_phase_36_15a_preserves_local_only_and_operational_boundaries() -> None:
    text = _text()
    for required in (
        "GitHub Pages",
        "read-only synthetic demo",
        "실제 로그 업로드 금지",
        "0.0.0.0 금지",
        "telemetry 금지",
        "CDN 금지",
        "Chrome/Chromium",
        "LAUNCHER_FIRST",
        "DESKTOP_WRAPPER_FIRST",
        "DEFER_DISTRIBUTION",
        "36.15B",
        "NO_GO",
    ):
        assert required in text

    index = (ROOT / "docs/index.md").read_text(encoding="utf-8")
    assert "local_first_distribution_design_36_15a.md" in index
