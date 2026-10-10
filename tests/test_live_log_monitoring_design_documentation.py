"""Phase 11 design-only contract; no live production route is enabled here."""

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
DESIGN = ROOT / "docs" / "live_log_monitoring_design.md"
README = ROOT / "README.md"


def _design() -> str:
    return DESIGN.read_text(encoding="utf-8")


def test_scope_and_user_flow_are_explicit():
    text = _design()
    assert text.startswith("# v0.2.0 Phase 11")
    for phrase in (
        "설계 전용, 미구현",
        "로컬 로그 실시간 확인",
        "uv run python -m app.local_web --monitor-config",
        "현재는 동작하지 않는다",
        "브라우저 file input으로 장기 tail path를 선택하지 않는다",
        "모니터링 비활성",
        "queue pressure",
        "Ctrl+C",
    ):
        assert phrase in text
    readme = README.read_text(encoding="utf-8")
    assert "[bounded 로컬 로그 모니터링 설계](docs/live_log_monitoring_design.md)" in readme
    assert "collector·SSE·`--monitor-config`가 **구현되지 않았으며**" in readme


def test_config_is_local_exact_and_from_end_only():
    text = _design()
    for phrase in (
        '"schema_version": "1"',
        '"start_policy": "FROM_END"',
        '"role": "application"',
        "Unknown key",
        "중복 JSON key",
        "상대 경로",
        "symlink",
        "FIFO/device/socket/directory",
        "동일 `(device,inode)`",
        "`FROM_START`와 persistent checkpoint는 보류",
        "재시작 이후 추가분만 관찰",
        "Linux Audit",
    ):
        assert phrase in text


def test_line_identity_rotation_and_overflow_are_bounded_and_visible():
    text = _design()
    for phrase in (
        "complete",
        "partial buffer",
        "strict decode",
        "invalid UTF-8",
        "copytruncate",
        "rotation",
        "O_NOFOLLOW",
        "TOCTOU",
        "exactly-once / no-loss 보장 없음",
        "nonzero `maxsize`",
        "item cap + estimated/serialized byte cap",
        "enqueue 확정 뒤",
        "replay gap",
        "무음 drop 금지",
        "정상 0건",
    ):
        assert phrase in text
    assert text.count("TO_BE_BENCHMARKED") >= 5


def test_analysis_preserves_existing_semantics_and_blocks_unsafe_publication():
    text = _design()
    for phrase in (
        "Brute Force는 실패 5건",
        "Spray-like는 4건·3계정",
        "Web Scanning-like는 60초",
        "closest-success",
        "Spray case no-go",
        "Path Traversal",
        "raw global correlation은 live case에 적용하지 않는다",
        "batch 동등성",
        "이벤트마다 전체 pipeline 재실행",
        "Linux Audit는 보류",
        "관찰 publication은 parity·privacy·성능 gate까지 보류",
    ):
        assert phrase in text


def test_session_sse_replay_and_accessible_update_contract():
    text = _design()
    for phrase in (
        "`CREATED`",
        "`STARTING`",
        "`RUNNING`",
        "`PAUSED`",
        "`DEGRADED`",
        "`STOPPING`",
        "`STOPPED`",
        "`FAILED`",
        "GET /api/v1/live/status",
        "GET /api/v1/live/events",
        "text/event-stream",
        "Last-Event-ID",
        "replay_gap",
        "same-origin",
        "loopback",
        "새 결과 N건 보기",
        "aria-live",
        "focus",
        "자동 scroll",
        "200% 확대",
    ):
        assert phrase in text


def test_privacy_threat_benchmark_tests_and_nogo_are_documented():
    text = _design()
    for phrase in (
        "LLM은 live 경로에서 **호출하지 않는다**",
        "영구 저장",
        "source path",
        "account",
        "HTTP path/query",
        "argv",
        "Canary 계획",
        "악의적 local producer",
        "reconnect storm",
        "다른 로컬 사용자",
        "p95/p99",
        "fake clock",
        "no leaked task/thread/FD",
        "No-go: unbounded queue",
        "hosted/public collector",
    ):
        assert phrase in text
    assert re.search(r"/Users/|/home/|C:\\Users\\", text) is None
    assert "BEGIN PRIVATE KEY" not in text


def test_research_basis_is_separate_from_project_policy():
    text = _design()
    for phrase in (
        "확인일: 2026-10-11",
        "인터페이스·실패 방식의 근거",
        "숫자, polling 주기, 탐지 임계값의 외부 권위가 아니다",
        "WHATWG Server-sent events",
        "Python 3.12 asyncio Queue",
        "Starlette StreamingResponse",
        "Linux inotify(7)",
        "Apple File System Events",
        "logrotate manual",
        "NIST SP 800-92",
        "OWASP Logging Cheat Sheet",
        "Observable Evidence Mapping",
        "남은 한계",
    ):
        assert phrase in text
