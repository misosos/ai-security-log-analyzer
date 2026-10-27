from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
STEP_NAME = "Verify collector JSONL runtime on Linux"
HARNESS = "tests/accept_collector_jsonl_runtime_35_3a.py"
MARKER = "COLLECTOR_JSONL_LINUX_ACCEPTANCE_PASS roles=2 runs=80 synthetic=1 leaks=0"


def _step_block(text: str, step_name: str) -> str:
    lines = text.splitlines()
    start = next(i for i, line in enumerate(lines)
                 if line.strip() == f"- name: {step_name}")
    block = [lines[start]]
    for line in lines[start + 1:]:
        if line.startswith("      - name:"):
            break
        block.append(line)
    return "\n".join(block)


def test_linux_jsonl_acceptance_step_is_bounded_and_ordered():
    text = WORKFLOW.read_text(encoding="utf-8")
    assert STEP_NAME in text
    block = _step_block(text, STEP_NAME)
    assert "timeout-minutes: 5" in block
    assert f"uv run python {HARNESS}" in block
    assert "sys.platform == 'linux'" in block or 'sys.platform == "linux"' in block
    assert "continue-on-error" not in block
    assert "|| true" not in block
    assert "|| exit 0" not in block
    assert "upload-artifact" not in text

    assert text.index("Run complete regression") < text.index(STEP_NAME)
    assert text.index("Verify bounded TCP Syslog reliability on Linux") < text.index(STEP_NAME)
    assert text.index("Verify TCP Syslog management pilot on Linux") < text.index(STEP_NAME)
    assert text.index(STEP_NAME) < text.index("Install pinned Node")
    assert re.search(r"(?m)^\s*runs-on: ubuntu-24\.04$", text)
    assert "/Users/" not in block and "~/" not in block
    assert "vector" not in block.lower()
    assert MARKER in (ROOT / HARNESS).read_text(encoding="utf-8")
