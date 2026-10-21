"""The README is a short, durable landing page with reachable detail documents."""

import re
from pathlib import Path
from urllib.parse import unquote


ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
INDEX = ROOT / "docs/index.md"


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _heading_anchor(heading: str) -> str:
    heading = re.sub(r"[^\w\s-]", "", heading.lower()).strip()
    return re.sub(r"\s+", "-", heading)


def _assert_local_links(path: Path) -> None:
    for target in re.findall(r"\[[^]]+\]\(([^)]+)\)", _text(path)):
        if target.startswith(("https://", "http://", "mailto:")):
            continue
        relative, _, fragment = target.partition("#")
        destination = path if not relative else path.parent / unquote(relative)
        # Compare each component exactly; some development filesystems ignore case.
        current = path.parent
        for component in Path(unquote(relative)).parts if relative else ():
            if component == "..":
                current = current.parent
                continue
            assert component in {item.name for item in current.iterdir()}, target
            current /= component
        assert destination.is_file(), target
        if fragment:
            anchors = {
                _heading_anchor(heading)
                for heading in re.findall(r"(?m)^#{1,6}\s+(.+)$", _text(destination))
            }
            assert unquote(fragment).lower() in anchors, target


def test_readme_is_short_and_starts_with_a_working_quick_start():
    text = _text(README)
    lines = text.splitlines()
    assert len(lines) <= 127  # At least 60% shorter than the 318-line baseline.
    assert len(text.encode("utf-8")) <= 17_000
    assert lines[0] == "# AI Security Log Analyzer"
    quick_line = lines.index("## 빠른 시작") + 1
    assert quick_line <= 60
    quick = text.split("## 빠른 시작", 1)[1].split("## 실시간 모니터링", 1)[0]
    for command in (
        "git clone https://github.com/misosos/ai-security-log-analyzer.git",
        "cd ai-security-log-analyzer", "uv sync --locked --dev",
        "uv run python -m app.local_web", "http://127.0.0.1:8000/", "Ctrl+C",
    ):
        assert command in quick
    assert text.count("```") % 2 == 0
    assert not re.search(r"(?m)^Phase\s+\d", text)


def test_readme_keeps_security_and_release_boundaries():
    text = _text(README)
    for term in (
        "방어 목적의 로컬 조사 보조 도구", "v0.3.0 Release",
        "https://github.com/misosos/ai-security-log-analyzer/releases/tag/v0.3.0",
        "source checkout", "wheel·PyPI", "127.0.0.1",
        "외부 LLM을 호출하지 않습니다", "원본 로그·credential·개인정보",
        "공개 Issue", "secure erase", "exactly-once", "무유실",
        "rotation·copytruncate", "cross-source", "애플리케이션 로그인 로그 또는 SSH 인증 로그",
        "Windows", "WCAG 2.2 AA", "SECURITY.md",
        "로그인 성공은 공격 성공", "HTTP 200", "결과가 없다고 안전한 것은 아닙니다",
    ):
        assert term.lower() in text.lower()
    for transient in (
        "현재 CI 대기 중", "아직 push하지 않았다", "다음 커밋에서",
        "ahead/behind", "origin/main...HEAD", "queued", "in_progress",
    ):
        assert transient not in text


def test_readme_and_map_have_reachable_exact_case_links():
    assert "docs/index.md" in _text(README)
    _assert_local_links(README)
    _assert_local_links(INDEX)
    assert "README.md" in _text(INDEX)
