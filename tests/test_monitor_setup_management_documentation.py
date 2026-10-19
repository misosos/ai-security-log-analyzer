"""Current Phase 20.1 public usage and management boundary documentation."""

from pathlib import Path

from app.live_monitoring.config import resolve_default_monitor_config_path


ROOT = Path(__file__).resolve().parents[1]


def test_readme_has_simple_default_flow_and_explicit_limits() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "uv run python -m app.monitor_setup\nuv run python -m app.local_web --monitor" in readme
    assert "uv run python -m app.monitor_setup --show" in readme
    assert "uv run python -m app.monitor_setup --delete" in readme
    for boundary in ("경로를 숨긴", "원본 로그", "secure erase", "checkpoint", "Rotation"):
        assert boundary in readme
    guide = (ROOT / "docs/monitor_setup_20.md").read_text(encoding="utf-8")
    for boundary in ("기본 설정", "사용자 지정", "삭제는 거부", "자동 활성화되지"):
        assert boundary in guide


def test_guide_distinguishes_default_and_explicit_config() -> None:
    guide = (ROOT / "docs/monitor_setup_20.md").read_text(encoding="utf-8")
    design = (ROOT / "docs/local_collector_v030_design.md").read_text(encoding="utf-8")
    for fact in ("--show", "--delete", "--monitor", "--monitor-config", "0700", "0600",
                 "v2", "승인", "source 사용 가능", "File lock", "race", "Time Machine"):
        assert fact in guide
    assert "Phase 20.1에서" in design and "--monitor" in design
    assert resolve_default_monitor_config_path(platform="darwin", home=Path("/synthetic")) == Path(
        "/synthetic/Library/Application Support/ai-security-log-analyzer/monitoring.json"
    )
