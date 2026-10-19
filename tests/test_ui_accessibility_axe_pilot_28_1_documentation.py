"""Phase 28.1 must stay a bounded development-only accessibility pilot."""

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "ui_accessibility_axe_pilot_28_1.md"


def test_document_records_supply_chain_and_real_automation_limits():
    text = DOC.read_text(encoding="utf-8")
    for term in (
        "88169bccc440ab10e3061f04987e541bf65af133",
        "39255398064", "2,351 passed", "@axe-core/playwright@4.14.0",
        "axe-core@4.14.0", "@playwright/test@1.64.1",
        "playwright@1.64.1", "playwright-core@1.64.1",
        "MPL-2.0", "Apache-2.0", "LGPLv2.1", "SHA-512",
        "prepare", "--ignore-scripts", "webp_codec.wasm",
        "156.0.8078.4", "revision 1248", "revision **1013**",
        "macOS arm64", "Ubuntu 24.04 x64", "Node **24.10.0**",
        "직접/전이", "devDependencies", "production",
        "13개", "checkpoint reset", "serious/critical", "0개",
        "DOM text", "canary", "CI artifact", "외부 origin", "CSP",
        "실제 Safari", "Keyboard-only", "200%", "VoiceOver",
        "WCAG 2.2 A/AA", "NOT_TESTED", "CI 증가 시간",
    ):
        assert term in text


def test_node_lock_is_exact_and_development_only():
    manifest = json.loads((ROOT / "package.json").read_text(encoding="utf-8"))
    lock = json.loads((ROOT / "package-lock.json").read_text(encoding="utf-8"))
    expected = {"@axe-core/playwright": "4.14.0", "@playwright/test": "1.64.1"}
    assert manifest["private"] is True
    assert manifest["devDependencies"] == expected
    assert not manifest.get("dependencies")
    assert lock["packages"][""]["devDependencies"] == expected
    assert set(lock["packages"]) == {
        "", "node_modules/@axe-core/playwright", "node_modules/@playwright/test",
        "node_modules/axe-core", "node_modules/playwright", "node_modules/playwright-core",
    }
    assert all(package.get("dev") for path, package in lock["packages"].items() if path)


def test_ci_and_frontend_preserve_boundaries():
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    script = (ROOT / "tests" / "ui_accessibility_axe_pilot_28_1.mjs").read_text(encoding="utf-8")
    for term in (
        "node-version: \"24.10.0\"", "npm ci --ignore-scripts --no-audit --no-fund",
        "playwright install chromium --only-shell", "sha512sum --check --status",
        "npm run test:a11y --silent",
    ):
        assert term in ci
    for term in (
        "mkdtemp", "XDG_CONFIG_HOME", "127.0.0.1", "AxeBuilder",
        "externalRequests", "CANARY", "AXE_SERIOUS_OR_CRITICAL",
        "CSP_CONTRACT_FAILED", "LOOPBACK_LISTENER_REMAINED",
    ):
        assert term in script
    assert "results.violations" in script
    assert "item.nodes.length" in script
    assert "results.violations" not in ci
    frontend = "\n".join(path.read_text(encoding="utf-8") for path in (ROOT / "frontend").glob("*.js"))
    assert "@axe-core/playwright" not in frontend
    assert "@playwright/test" not in frontend
