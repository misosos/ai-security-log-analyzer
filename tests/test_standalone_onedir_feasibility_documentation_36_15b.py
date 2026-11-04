from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "pyinstaller_onedir_feasibility_36_15b.md"


def test_standalone_feasibility_record_has_evidence_and_scope_boundaries():
    assert DOC.is_file()
    text = DOC.read_text(encoding="utf-8")
    for required in (
        "Executive Summary",
        "시작 SHA/CI Gate",
        "Production Dependency Closure",
        "PyInstaller 빌드 방식",
        "정적 리소스 및 Native Library",
        "Bundle 실행 E2E",
        "Loopback 및 개인정보 보안 검증",
        "Artifact Manifest·크기·라이선스",
        "OS별 미검증 사항",
        "문제점과 수정 내용",
        "후속 36.15C 진입 조건",
        "최종 판정",
        "ca14b6400b4a5c11aef2949f7c2287c1677fe1a8",
        "41775612153",
        "macOS 15.7.7",
        "arm64",
        "127.0.0.1",
        "NO_GO",
        "NOT_TESTED",
        "PyInstaller 6.22.3",
        "multiprocessing.freeze_support",
        "https://pyinstaller.org/en/stable/runtime-information.html",
        "https://pyinstaller.org/en/stable/common-issues-and-pitfalls.html",
        "https://pypi.org/project/pyinstaller/",
    ):
        assert required in text
    assert "Release artifact 미제공" in text
    assert "Windows 지원 선언 아님" in text
    assert "byte-for-byte 재현성을 검증하지 않음" in text


def test_docs_index_links_to_standalone_feasibility_record():
    index = (ROOT / "docs" / "index.md").read_text(encoding="utf-8")
    assert "pyinstaller_onedir_feasibility_36_15b.md" in index
