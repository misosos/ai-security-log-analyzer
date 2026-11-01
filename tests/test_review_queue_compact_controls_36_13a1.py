from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_compact_queue_record_preserves_user_acceptance_boundary_and_screenshots():
    document = (ROOT / "docs/investigation_review_queue_compact_controls_36_13a1.md").read_text()

    assert "1/12 최초 응답은 사용자의 `FAIL`로 보존" in document
    assert "문항 2–12는 `NOT_TESTED`로 보존" in document
    assert "`USER_ACCEPTANCE_NOT_TESTED`" in document
    assert "Phase 36.13B 검수를 새 화면으로 1/12부터 다시 시작" in document
    assert "외부 요청 0회" in document

    screenshots = [
        "01-desktop-default-1440.png",
        "02-desktop-filter-panel-1440.png",
        "03-desktop-two-chips-1440.png",
        "04-desktop-empty-1440.png",
        "05-mobile-default-390.png",
        "06-mobile-filter-panel-390.png",
        "07-mobile-chips-320.png",
        "08-mobile-reflow-320-200-equivalent.png",
    ]
    for screenshot in screenshots:
        assert screenshot in document
        assert (ROOT / "docs/images/review-queue-36-13a1" / screenshot).is_file()


def test_compact_queue_document_is_indexed():
    index = (ROOT / "docs/index.md").read_text()
    assert "investigation_review_queue_compact_controls_36_13a1.md" in index
