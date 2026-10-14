"""Keep Phase 20 instructions aligned with the executable CLI and safe v2 contract."""

from pathlib import Path

from app.live_monitoring.config import LiveMonitorConfigV2
from app.monitor_setup import SAMPLE_BYTES, SAMPLE_LINES


ROOT = Path(__file__).resolve().parents[1]


def test_readme_usage_and_boundaries() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "python -m app.monitor_setup" in readme
    assert "python -m app.local_web --monitor" in readme
    assert "python -m app.monitor_setup --show" in readme
    assert "python -m app.monitor_setup --delete" in readme
    for boundary in ("application 로그 하나", "bounded dry-run", "설정 생성만으로", "FROM_END",
                     "외부 LLM 자동 전송", "checkpoint·rotation 자동 복구"):
        assert boundary in readme


def test_design_and_user_guide_reflect_current_scope() -> None:
    design = (ROOT / "docs/local_collector_v030_design.md").read_text(encoding="utf-8")
    guide = (ROOT / "docs/monitor_setup_20.md").read_text(encoding="utf-8")
    assert "Phase 20에서" in design and "Phase 20.1에서" in design
    for fact in ("**구현됨**", "--no-color", "--output", "config 절대 경로", "0600", "0700",
                 "os.link", "os.replace", "SOURCE_DISABLED", "Linux", "checkpoint"):
        assert fact in guide
    assert (SAMPLE_BYTES, SAMPLE_LINES) == (4096, 16)
    document = LiveMonitorConfigV2(Path("/absolute/path/to/application.log")).as_document()
    assert document["schema_version"] == "2"
    assert document["sources"][0]["start_position"] == "FROM_END"
    assert document["sources"][0]["checkpoint_policy"] == "DISABLED"
    assert "Config 수정·덮어쓰기" in guide
    assert "원본 로그·parent·sibling" in guide
