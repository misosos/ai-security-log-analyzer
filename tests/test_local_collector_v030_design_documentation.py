"""Phase 19 design guardrails: proposed behavior must not masquerade as v0.2 code."""

from pathlib import Path
import json
import re

from app.live_monitoring import config, core
from app.live_monitoring.analysis_accumulator import MAX_HISTORY_BYTES, MAX_HISTORY_RECORDS
from app.live_monitoring.publication import MAX_PUBLICATION_BYTES, MAX_PUBLICATION_ITEMS
from app.live_monitoring.runner import POLL_INTERVAL_SECONDS


ROOT = Path(__file__).resolve().parents[1]
DESIGN = ROOT / "docs/local_collector_v030_design.md"


def _section(text: str, number: int) -> str:
    match = re.search(rf"(?ms)^## {number}\. .*?(?=^## [0-9]+\. |\Z)", text)
    assert match, f"missing design section {number}"
    return match.group()


def test_current_contract_is_code_anchored_and_not_a_new_runtime() -> None:
    text = DESIGN.read_text(encoding="utf-8")
    current = _section(text, 1)
    example = json.loads((ROOT / "docs/examples/live-monitor.json").read_text(encoding="utf-8"))
    assert set(example) == {"schema_version", "source", "start_policy"}
    assert set(example["source"]) == {"role", "path"}
    assert example["schema_version"] == "1" and example["start_policy"] == "FROM_END"
    assert config.ROLES == {"application", "ssh", "access"}
    assert config.CONFIG_MAX_BYTES == 4096
    assert (core.MAX_POLL_BYTES, core.MAX_RECORDS_PER_POLL, core.MAX_LINE_BYTES) == (4096, 16, 2048)
    assert (core.MAX_QUEUE_ITEMS, core.MAX_QUEUE_BYTES) == (32, 16 * 1024)
    assert (MAX_HISTORY_RECORDS, MAX_HISTORY_BYTES) == (256, 256 * 1024)
    assert (MAX_PUBLICATION_ITEMS, MAX_PUBLICATION_BYTES) == (32, 16_384)
    assert POLL_INTERVAL_SECONDS == 0.5
    for contract in ("FROM_END", "SSH/access", "Linux Audit", "SOURCE_REPLACED", "SOURCE_TRUNCATED",
                     "256건/256KiB", "32항목/16KiB", "ack", "process-local"):
        assert contract in current
    assert "Phase 19는 **설계만**" in text and "Phase 20에서" in text


def test_wizard_is_trusted_cli_with_complete_recovery_and_no_browser_path_control() -> None:
    text = DESIGN.read_text(encoding="utf-8")
    wizard = _section(text, 2)
    assert "app.monitor_setup" in wizard
    assert "app.local_web --setup-monitoring" in wizard
    assert "브라우저 경로 문자열" in wizard and "no-go" in wizard
    assert "<input type=\"file\">" not in wizard  # no bogus long-term file grant
    for code in ("PATH_MISSING", "PERMISSION_DENIED", "SYMLINK_REJECTED", "NOT_REGULAR_FILE",
                 "UNSUPPORTED_FORMAT", "EMPTY_SOURCE", "BINARY_INPUT", "INVALID_UTF8",
                 "LINE_TOO_LONG", "CONFIG_EXISTS", "SAVE_DENIED", "DUPLICATE_ROLE",
                 "DUPLICATE_SOURCE", "SOURCE_CHANGED", "DRY_RUN_CHANGED", "UNSUPPORTED_OS"):
        assert f"SETUP_{code}" in wizard
    for method in ("CLI 절대 경로 입력", "CLI drag-and-drop", "OS native file picker",
                   "브라우저 file input", "브라우저 경로 문자열"):
        assert method in wizard
    assert wizard.index("승인합니까") < wizard.index("저장 후")


def test_private_config_and_checkpoint_cannot_claim_exactly_once() -> None:
    text = DESIGN.read_text(encoding="utf-8")
    config_section = _section(text, 3)
    recovery = _section(text, 4)
    assert '"schema_version": "2"' in config_section
    proposed = json.loads(re.search(r"```json\n(.*?)\n```", config_section, re.S).group(1))
    assert set(proposed) == {"schema_version", "sources"}
    assert len(proposed["sources"]) == 1
    assert set(proposed["sources"][0]) == {
        "source_id", "source_role", "source_path", "display_alias", "enabled",
        "start_position", "parser_timezone", "checkpoint_policy", "rotation_policy",
    }
    assert proposed["sources"][0]["source_role"] == "application"
    assert proposed["sources"][0]["start_position"] == "FROM_END"
    assert proposed["sources"][0]["checkpoint_policy"] == "DISABLED"
    assert proposed["sources"][0]["rotation_policy"] == "FAIL_CLOSED"
    for rule in ("0700", "0600", "O_EXCL", "O_NOFOLLOW", "fsync", "no-clobber", "덮어쓰"):
        assert rule in config_section
    for rule in ("offset만 저장하면 batch-prefix parity가 깨진다", "queue ack", "DEGRADED",
                 "checkpoint 전 crash", "partial line", "inode 재사용", "exactly-once"):
        assert rule in recovery
    rotation = re.search(r"### Rotation·truncation 전이.*?(?=^## 5\.)", text, re.S | re.M).group()
    for scenario in ("rename rotation", "copytruncate", "파일 삭제", "새 파일 생성",
                     "같은 경로 다른 identity", "파일 크기 감소", "잠시 사라짐", "권한 변경",
                     "symlink 교체", "빠른 연속 rotation", "중지 중 rotation", "partial line 중 rotation"):
        assert scenario in rotation


def test_future_boundaries_threats_retention_and_research_are_explicit() -> None:
    text = DESIGN.read_text(encoding="utf-8")
    assert all(_section(text, number) for number in range(1, 11))
    multi_ipc = _section(text, 5)
    for term in ("application/SSH/access/Linux Audit", "global byte budget", "round-robin",
                 "Unix domain socket", "loopback HTTP", "stdin/stdout subprocess",
                 "named pipe", "파일 spool", "peer UID"):
        assert term in multi_ipc
    threats = _section(text, 7)
    for term in ("악의적 로그", "디스크 고갈", "TOCTOU", "inode reuse", "origin 위조",
                 "collector impersonation", "IPC replay", "crash 중", "shell history",
                 "Time Machine", "uninstall"):
        assert term in threats
    retention = _section(text, 8)
    for term in ("raw 로그", "in-memory queue", "checkpoint", "config", "safe publication",
                 "HTML report", "operational log", "crash dump", "backup", "미정"):
        assert term in retention
    roadmap = _section(text, 9)
    for phase in ("Phase 20 ", "Phase 20.1", "Phase 20.2", "Phase 21 ", "Phase 21.1",
                  "Phase 21.2", "Phase 22", "Phase 23", "Phase 24", "Phase 25+"):
        assert phase in roadmap
    basis = _section(text, 10)
    for official in ("docs.python.org/3.12", "developer.apple.com", "freedesktop.org",
                     "man7.org", "cheatsheetseries.owasp.org", "nist.gov",
                     "github.com/open-telemetry", "docs.fluentbit.io"):
        assert official in basis
    assert "retention은 미정" in basis and "제품별 구현 사례" in basis


def test_readme_roadmap_distinguishes_setup_core_from_unimplemented_features() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    index = (ROOT / "docs/index.md").read_text(encoding="utf-8")
    design = (ROOT / "docs/local_collector_v030_design.md").read_text(encoding="utf-8")
    assert "local_collector_v030_design.md" in index
    assert "마법사" in readme and "checkpoint" in readme and "rotation" in readme.lower()
    assert "설계" in design and "후속" in design
