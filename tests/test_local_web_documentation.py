"""Stable beginner entry-point and privacy boundaries in user documents."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_readme_starts_with_working_loopback_web_command():
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    quick = text.split("## 빠른 시작", 1)[1].split("### 기존 CLI", 1)[0]
    for command in (
        "git clone https://github.com/misosos/ai-security-log-analyzer.git",
        "cd ai-security-log-analyzer", "uv sync --dev",
        "uv run python -m app.local_web",
    ):
        assert command in quick
    assert "127.0.0.1:8000" in quick
    assert "Ctrl+C" in quick
    assert "--no-browser" in quick
    assert "--port 8001" in quick
    assert "uv run python -m app.local_web --reload" not in quick
    assert "0.0.0.0" in quick and "하지 마십시오" in quick


def test_first_user_guidance_keeps_storage_and_report_limits_visible():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    guide = (ROOT / "docs/final_demo_guide.md").read_text(encoding="utf-8")
    design = (ROOT / "docs/web_application_design.md").read_text(encoding="utf-8")
    for text in (readme, guide):
        assert "uv run python -m app.local_web" in text
        assert "sample_logs/brute_force.log" in text
        assert "sample_logs/ssh_auth.log" in text
        assert "sample_logs/web_shell.log" in text
        assert "Timeline" in text
    for limit in ("32 KiB", "80 KiB", "96 KiB", "2048", "512"):
        assert limit in readme
    assert "임시 파일" in readme and "비정상 종료" in readme
    assert "LLM을 호출하지" in readme
    assert "실시간 수집" in readme
    assert "Phase 5.5" in design
    assert "Hosted upload" in design and "no-go" in design
