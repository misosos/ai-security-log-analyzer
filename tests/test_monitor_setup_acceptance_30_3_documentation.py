"""Ubuntu evidence, human comprehension, and untested scope stay separate."""

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]


def test_unified_setup_acceptance_records_evidence_and_limits() -> None:
    record = (ROOT / "docs/monitor_setup_acceptance_30_3.md").read_text(encoding="utf-8")
    index = (ROOT / "docs/index.md").read_text(encoding="utf-8")
    prior = (ROOT / "docs/monitor_setup_unified_audit_30_2.md").read_text(encoding="utf-8")
    for required in (
        "a8f046485d923db8b0f24e0c11e38054b76d7775", "39558109981",
        "07d8be7560920686ab6e740e392b810bb46b6246", "39585667955",
        "Ubuntu 24.04", "46 passed", "2413 passed", "artifact", "0700", "0600",
        "application", "SSH", "checkpoint", "SSE", "advisory lock", "reset",
        "delete", "원본", "개인정보", "정리", "NOT_TESTED", "사용자 직접",
        "CHECKPOINT_REVIEW_GUIDANCE_FAILED", "CHECKPOINT_REVIEW_FALSE_ABSENCE",
        "pytrace=False", "fixture 소스 줄",
        "network filesystem", "SIGKILL", "rotation/copytruncate", "exactly-once",
        "Secure erase",
    ):
        assert required in record
    assert "monitor_setup_acceptance_30_3.md" in index
    assert "monitor_setup_acceptance_30_3.md" in prior
    rows = re.findall(r"^\| ([1-9]) \| ([^|]+) \| (PASS|FAIL|NOT_TESTED) \| ([^|]+) \| (PASS|FAIL|NOT_TESTED) \|$",
                      record, flags=re.MULTILINE)
    assert len(rows) == 9
    assert [row[0] for row in rows] == list("123456789")
    assert all(row[4] == "PASS" for row in rows)
    assert {row[0] for row in rows if row[2] == "FAIL"} == {"5", "7", "8"}
    assert all(row[3] == "PASS" for row in rows if row[2] == "FAIL")
    for required in (
        "실제 합성 CLI 출력", "사용자 직접 판정", "명령 입력과 파일 선택은 임시 HOME의 자동 준비",
        "수정 전 실패 계약 테스트", "원본 로그 파일은 삭제하지 않습니다",
        "Parser", "API·SSE", "기존 설정, source 불가", "**NOT_TESTED**",
        "새 로컬 커밋의 Ubuntu CI는 push 전이므로 아직 미검증",
        "53 passed", "2420 passed", "79/79", "21/21", "70/70",
    ):
        assert required in record
