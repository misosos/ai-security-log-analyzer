"""Guard the Phase 30.0 SSH setup design without enabling the proposed feature."""

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
PLAN = ROOT / "docs/monitor_setup_ssh_design_30_0.md"


def _plan() -> str:
    return PLAN.read_text(encoding="utf-8")


def test_design_stays_a_documented_gate_with_one_source_and_no_new_analysis() -> None:
    text = _plan()
    for required in (
        "상태: 설계 gate", "2,384 passed", "application", "SSH", "단일",
        "SOURCE-000001", "FROM_END", "BOUNDED_REPLAY_V1", "FAIL_CLOSED",
        "기존 설정을 안전하게 거부", "no-clobber", "role", "checkpoint",
        "detector·correlation·risk·case·LLM을 실행하지 않는다",
        "다중 source", "cross-source", "exactly-once", "무유실", "NO-GO",
    ):
        assert required in text
    assert "이번 Phase에는 실패 테스트를 실행 상태로 추가하지 않는다" in text
    assert "production 기능을 구현했다" not in text


def test_dry_run_and_privacy_contract_are_bounded_and_specific() -> None:
    text = _plan()
    for required in (
        "4,096 byte", "16줄", "2,048 byte", 'parse_live_records("ssh", records)',
        "한 번", "PARSED", "IGNORED", "REJECTED", "event_type=None",
        "로그인 실패", "성공 기록", "partial UTF-8", "원문", "계정", "IP",
        "hostname", "절대 경로", "SETUP_INVALID_UTF8", "SETUP_LINE_TOO_LONG",
        "운영환경 호환성 보증", "합성 canary", "실제 사용자 로그",
    ):
        assert required in text
    assert "성공 기록은 침해 성공이 아니다" in text


def test_compatibility_threats_and_next_phases_are_reviewable() -> None:
    text = _plan()
    for required in (
        "| 조합 | setup | show | monitor | restart recovery | reset | delete |",
        "기존 application v2 기본", "새 application v2 기본", "새 SSH v2 기본",
        "명시적 application v1/v2", "명시적 SSH v1/v2", "access 설정",
        "손상·권한 오류·symlink 기본 설정", "역할이 다른 checkpoint",
        "symlink·TOCTOU", "다른 사용자 소유", "group/world writable",
        "승인 대기 중 교체", "같은 UID", "shell history", "crash dump",
        "secure erase가 아님", "Phase 30.1", "Phase 30.2", "Phase 30.3",
        "macOS·Ubuntu", "UTC와 Asia/Seoul", "자동 덮어쓰거나 백업·교체하지 않는다",
    ):
        assert required in text
    for column in ("예방", "탐지·실패 동작", "잔여 위험"):
        assert column in text


def test_official_references_and_document_map_are_present() -> None:
    text = _plan()
    for official in (
        "https://man.openbsd.org/sshd_config",
        "https://docs.python.org/3.12/library/os.html",
        "https://man7.org/linux/man-pages/man2/open.2.html",
        "https://man7.org/linux/man-pages/man2/stat.2.html",
        "https://man7.org/linux/man-pages/man2/flock.2.html",
        "https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemDetails/FileSystemDetails.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet/",
        "https://csrc.nist.gov/pubs/sp/800/92/final",
    ):
        assert official in text
    assert "Observable Evidence Mapping" in text
    for target in re.findall(r"\]\(([^)]+)\)", text):
        if "://" not in target:
            assert (PLAN.parent / target.split("#", 1)[0]).exists()
    assert "monitor_setup_ssh_design_30_0.md" in (ROOT / "docs/index.md").read_text(encoding="utf-8")
