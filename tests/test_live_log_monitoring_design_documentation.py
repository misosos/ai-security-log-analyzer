"""Phase 11 design and Phase 12 internal-core documentation contract."""

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
        "Phase 12 bounded 내부 core, Phase 12.1 parser adapter, Phase 12.2 단일 active lease, Phase 12.3 명시적 worker step, Phase 13 bounded detection accumulator, Phase 13.1 worker·ack·commit 연결",
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
    assert "[bounded 내부 tail core·parser adapter·단일 record lease·명시적 worker step·detection accumulator](docs/live_log_monitoring_design.md)" in readme
    assert "사용자용 collector·CLI `--monitor-config`·SSE·웹 UI·live 탐지 공개/사례도 **아직 구현되지 않았습니다**" in readme
    assert "uv run python -m app.local_web --monitor-config" not in readme


def test_implemented_core_limits_and_unimplemented_boundaries_are_explicit():
    text = _design()
    for phrase in (
        "load_live_monitor_config(Path)",
        "open_live_tail_session(LiveMonitorConfig)",
        "poll_once()",
        "lease_records(max_records, max_bytes)",
        "acknowledge_lease(lease)",
        "release_lease(lease)",
        "snapshot()",
        "close()",
        "1024",
        "4096",
        "2048",
        "32 item",
        "16384",
        "Parser와 detector는 호출하지 않는다",
        "CLI flag·자동 polling loop·status API·SSE·browser UI·Ctrl+C 연결도 아직 없다",
    ):
        assert phrase in text


def test_live_parser_adapter_is_internal_and_preserves_batch_meaning():
    text = _design()
    for phrase in (
        "parse_live_records(source_role, tuple[LiveTailRecord, ...])",
        "preprocess_log_line()",
        "기존 parser registry와 timezone",
        "normalize_to_utc()",
        "`IGNORED`",
        "`PARSED`",
        "`REJECTED`",
        "Batch pipeline은 일부 malformed",
        "엄격히 증가하는 sequence",
        "Gap은 허용",
        "자동 retry/backoff, retry limit, 프로세스 crash 복구, exactly-once는 없다",
        "운영 실시간 기능으로 사용할 수 없다",
    ):
        assert phrase in text


def test_lease_ownership_and_no_public_integration_are_documented():
    text = _design()
    for phrase in (
        "한 session에는 active lease가 최대 하나",
        "resident items/bytes = available items/bytes + leased items/bytes",
        "Release는 queue를 물리적으로 이동하지 않아",
        "`PARSED`·`IGNORED`·`REJECTED`가 모두 완성된 batch",
        "`abandoned_on_close_count`",
        "Python 메모리의 secure erase까지 보장하지 않는다",
        "single-threaded explicit-step",
        "v0.1 public API·CLI에는 영향이 없다",
    ):
        assert phrase in text


def test_worker_failure_and_deferred_integration_are_documented():
    text = _design()
    for phrase in (
        "LiveProcessingWorker(session, max_lease_records, max_lease_bytes)",
        "전체 ack",
        "REJECTED`도 예상된 완료 결과",
        "명시적 `resume_after_degraded()`",
        "POLL_FAILURE → FAILED",
        "Ack 실패에는 release를 시도하지 않고",
        "단일 worker binding은 두 번째 worker 생성만 runtime에서 거부",
        "Process memory 밖 persistence",
        "CLI·SSE·UI·LLM·detector·상관분석·risk·case·HTML을 실행하지 않는다",
    ):
        assert phrase in text


def test_phase_13_1_ack_identity_and_terminal_boundary_documented():
    text = _design()
    for phrase in (
        "Phase 13.1 현재 내부 처리 계약",
        "point of no return",
        "commit_prepared()",
        "DETECTION_COMMIT_FAILED_AFTER_ACK",
        "uncommitted_after_ack_record_count",
        "NO_LONGER_MATCHES_CURRENT_RESULT",
        "LIVE-OBS-000001",
        "같은 session에서 재등장하면 기존 ID",
        "최신 committed 1개만 보관",
        "진정한 원자적 transaction은 없으며 exactly-once",
    ):
        assert phrase in text


def test_detection_accumulator_contract_and_publication_gap_are_documented():
    text = _design()
    for phrase in (
        "LiveDetectionAccumulator(source_role, max_history_records, max_history_bytes)",
        "PARSED event 전부",
        "HISTORY_LIMIT_EXCEEDED",
        "rolling eviction",
        "detect_attacks(list(history))",
        "safe_summary()",
        "prepare()`는 committed history·detection·revision을 변경하지 않고",
        "abort()`는 committed snapshot을 그대로 유지",
        "commit()`은 exact active owner/proposal ID",
        "Phase 13.1에서 설계",
        "queue ack 성공 → detection commit",
        "LiveProcessingWorker",
        "exactly-once 보장은 없다",
    ):
        assert phrase in text


def test_config_is_local_exact_and_from_end_only():
    text = _design()
    for phrase in (
        '"schema_version": "1"',
        '"start_policy": "FROM_END"',
        '"role": "application"',
        "unknown key",
        "중복 JSON key",
        "상대 경로",
        "symlink",
        "FIFO/device/socket/directory",
        "`(device,inode)`",
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
        "32 item + 16384 UTF-8 payload bytes",
        "원자적 enqueue 실패",
        "replay gap",
        "silent overflow",
        "정상 0건",
    ):
        assert phrase in text
    # Implemented tail limits have numbers; only future analysis/SSE limits remain open.
    assert text.count("TO_BE_BENCHMARKED") >= 4


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
        "Linux Audit는 거부",
        "별도 gate가 필요",
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
