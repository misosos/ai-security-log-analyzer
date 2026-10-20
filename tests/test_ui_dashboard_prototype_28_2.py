"""Static isolation contracts for the independent synthetic UI comparisons."""

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
PROTOTYPES = ROOT / "docs" / "prototypes"


def test_two_independent_html_entries_share_local_assets() -> None:
    for name in ("calm", "dense"):
        html = (PROTOTYPES / f"security_dashboard_{name}.html").read_text()
        assert 'lang="ko"' in html
        assert f'data-variant="{name}"' in html
        assert 'script defer src="security_dashboard.js"' in html
        assert 'rel="stylesheet" href="security_dashboard.css"' in html
        assert "connect-src 'none'" in html
        assert "default-src 'none'" in html
        assert "unsafe-inline" not in html
        assert "unsafe-eval" not in html


def test_prototype_logic_has_no_storage_network_or_unsafe_dom() -> None:
    js = (PROTOTYPES / "security_dashboard.js").read_text()
    css = (PROTOTYPES / "security_dashboard.css").read_text()
    forbidden = (
        "innerHTML", "insertAdjacentHTML", "eval(", "new Function", "fetch(",
        "XMLHttpRequest", "EventSource", "WebSocket", "localStorage", "sessionStorage",
        "indexedDB", "location.href", "window.open", "https://", "http://",
    )
    assert all(token not in js for token in forbidden)
    assert "createElement" in js and "textContent" in js
    assert "prefers-reduced-motion" in css
    assert "@import" not in css and "url(" not in css
    assert "https://" not in css and "http://" not in css


def test_same_bounded_fixture_and_expected_states() -> None:
    js = (PROTOTYPES / "security_dashboard.js").read_text()
    assert js.count("const DATA = Object.freeze") == 1
    for term in (
        "RUNNING", "DEGRADED", "FAILED", "replay gap", "FROM_END",
        "새 결과 2건 보기", "화면 표시 일시 정지", "수동 재연결",
        "관찰", "관계", "위험도", "사례", "source checkout",
    ):
        assert term.lower() in js.lower()
    for name in ("calm", "dense"):
        html = (PROTOTYPES / f"security_dashboard_{name}.html").read_text()
        assert "security_dashboard.js" in html


def test_prototype_is_not_served_by_production_routes() -> None:
    # The existing allowlist is intentionally fixed; no prototype path is registered.
    api = (ROOT / "app" / "api.py").read_text()
    assert "docs/prototypes" not in api
    assert "security_dashboard_calm" not in api
    assert "security_dashboard_dense" not in api


def test_prototype_assets_have_no_personal_data_or_secret_canary() -> None:
    assets = [
        PROTOTYPES / "security_dashboard.js",
        PROTOTYPES / "security_dashboard.css",
        *(PROTOTYPES / f"security_dashboard_{name}.html" for name in ("calm", "dense")),
    ]
    for asset in assets:
        source = asset.read_text()
        assert not re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", source)
        assert not re.search(r"/(?:Users|home|tmp|etc)/", source)
        assert not re.search(r"(?i)(?:password|token|secret|api[_-]?key)\s*[:=]", source)
        assert "synthetic-private-account" not in source
