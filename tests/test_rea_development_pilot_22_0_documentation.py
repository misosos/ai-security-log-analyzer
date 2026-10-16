"""Phase 22.0 permits a reviewed development experiment, not REA integration."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DESIGN = ROOT / "docs/rea_development_pilot_22_0.md"


def _section(text: str, heading: str) -> str:
    start = text.index(f"## {heading}\n")
    following = text.find("\n## ", start + 4)
    return text[start:following if following != -1 else None]


def test_pilot_is_pinned_and_tracks_official_supply_chain() -> None:
    design = DESIGN.read_text(encoding="utf-8")
    supply = _section(design, "공급망과 정확한 버전")
    for item in (
        "morluto/rea", "rea-agents-6.5.0", "rea-agents@6.5.0",
        "3b79af28e80785afce9f5998d8f03289402a1847", "registry.npmjs.org",
        "sha512-C6BG7Lyr", "MIT", "SECURITY.md", "npm provenance",
    ):
        assert item in supply
    assert "@latest" in supply and "사용하지" in supply


def test_pilot_scopes_target_permissions_data_and_rollback() -> None:
    design = DESIGN.read_text(encoding="utf-8")
    for heading in (
        "예상 설치 변경과 네트워크", "위협 모델과 개인정보 경계",
        "첫 read-only pilot", "검증 oracle와 판정", "제거와 복원",
        "승인 gate와 금지 범위",
    ):
        assert f"## {heading}\n" in design
    for boundary in (
        "frontend/live-monitoring.js", "tests/test_live_monitoring_ui.py",
        "Process Capture", "현재 사용자 권한", "sandbox가 아니다",
        ".env", "기본 monitor config", "실제 로그", "홈 디렉터리",
        "30초", "15초", "출력", "allowlist", "MCP", "모델 제공자",
        "uv.lock", "production dependency", "CI", "rollback",
    ):
        assert boundary in design
    assert "설치·setup·REA 실행은 Phase 22.0에서 수행하지 않았다" in design


def test_pilot_does_not_claim_setup_is_read_only_or_static_output_is_truth() -> None:
    design = DESIGN.read_text(encoding="utf-8")
    assert "`npx rea-agents setup`은 읽기 전용 명령이 아니다" in design
    assert "설정 파일의 실제 변경 목록은 승인 후 dry-run으로 확인" in design
    assert "REA 결과는 사실의 oracle이 아니다" in design
    assert "자동 rotation/copytruncate handoff" in design
    assert "두 세대 metadata 확대" in design
