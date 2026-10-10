"""Static accessibility/security contract and built-in Node behavior test."""

from html.parser import HTMLParser
from pathlib import Path
import shutil
import subprocess


ROOT = Path(__file__).resolve().parents[1]


class _Tags(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))


def test_linux_audit_native_form_and_separate_result_region():
    source = (ROOT / "frontend/index.html").read_text(encoding="utf-8")
    parsed = _Tags()
    parsed.feed(source)
    nodes = parsed.tags
    ids = {attrs.get("id") for _, attrs in nodes}
    assert {"linux-audit-upload", "linux-audit-form", "linux-audit-results",
            "linux-audit-error", "linux-audit-file", "linux-audit-field-error"} <= ids
    assert any(tag == "script" and attrs.get("src") == "/assets/linux-audit.js" and "defer" in attrs
               for tag, attrs in nodes)
    assert any(tag == "label" and attrs.get("for") == "linux-audit-file" for tag, attrs in nodes)
    assert any(tag == "input" and attrs.get("name") == "audit_file" and attrs.get("type") == "file"
               and "required" in attrs for tag, attrs in nodes)
    assert any(tag == "button" and attrs.get("type") == "submit" and attrs.get("id") == "linux-audit-button"
               for tag, attrs in nodes)
    assert any(tag == "fieldset" for tag, _ in nodes) and any(tag == "legend" for tag, _ in nodes)
    assert any(attrs.get("id") == "linux-audit-error" and attrs.get("tabindex") == "-1"
               for _, attrs in nodes)
    assert any(attrs.get("id") == "linux-audit-status" and attrs.get("aria-live") == "polite"
               for _, attrs in nodes)
    assert "Linux Audit 프로세스 실행 확인" in source
    assert "인증·웹 조사 사례와 자동으로 결합하지 않습니다" in source


def test_linux_script_has_no_unsafe_sinks_or_browser_storage():
    script = (ROOT / "frontend/linux-audit.js").read_text(encoding="utf-8")
    for forbidden in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write",
                      "localStorage", "sessionStorage", "indexedDB", "document.cookie",
                      "eval(", "new Function", "console.log", "https://", "http://"):
        assert forbidden not in script
    assert "document.createElement" in script and "textContent" in script
    assert 'body.append("audit_file", input.files[0])' in script
    assert 'method: "POST"' in script
    assert "Content-Type" not in script


def test_linux_browser_memory_behavior_with_node():
    assert shutil.which("node"), "Node is required for repository behavior tests"
    result = subprocess.run(["node", str(ROOT / "tests/linux_audit_web_ui_behavior.cjs")],
                            cwd=ROOT, capture_output=True, text=True, check=False, timeout=15)
    assert result.returncode == 0, result.stderr
