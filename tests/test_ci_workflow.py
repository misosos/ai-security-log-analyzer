import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
CHECKOUT_SHA = "3d3c42e5aac5ba805825da76410c181273ba90b1"
SETUP_UV_SHA = "c18668ad3cf93ea998bef934396af7bb5c839dc7"


def _text() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def _top_level_block(name: str) -> str:
    lines = _text().splitlines()
    start = lines.index(f"{name}:") + 1
    block = []
    for line in lines[start:]:
        if line and not line.startswith("  "):
            break
        block.append(line)
    return "\n".join(block)


def test_ci_workflow_exists_and_uses_expected_triggers():
    assert WORKFLOW.is_file()
    triggers = _top_level_block("on")
    assert re.search(r"(?m)^  pull_request:$", triggers)
    assert re.search(r"(?m)^  push:$", triggers)
    assert re.search(r"(?m)^      - main$", triggers)
    assert re.search(r"(?m)^  workflow_dispatch:$", triggers)
    for forbidden in (
        "pull_request_target",
        "schedule:",
        "release:",
        "deployment:",
        "workflow_run:",
    ):
        assert forbidden not in triggers


def test_ci_permissions_are_contents_read_only():
    permissions = [
        line.strip()
        for line in _top_level_block("permissions").splitlines()
        if line.strip()
    ]
    assert permissions == ["contents: read"]
    assert "write" not in _top_level_block("permissions")


def test_ci_has_one_bounded_github_hosted_linux_job():
    jobs = _top_level_block("jobs")
    job_keys = [
        line.strip()[:-1]
        for line in jobs.splitlines()
        if re.fullmatch(r"  [A-Za-z0-9_-]+:", line)
    ]
    assert job_keys == ["test"]
    assert "runs-on: ubuntu-24.04" in jobs
    assert "timeout-minutes: 15" in jobs
    assert "matrix:" not in jobs
    assert "container:" not in jobs
    assert "services:" not in jobs


def test_ci_cancels_obsolete_runs_for_the_same_ref_or_pull_request():
    concurrency = _top_level_block("concurrency")
    assert "github.workflow" in concurrency
    assert "github.event.pull_request.number || github.ref" in concurrency
    assert "cancel-in-progress: true" in concurrency
    assert "secrets." not in concurrency


def test_ci_actions_are_full_sha_pinned_with_reviewed_tags():
    text = _text()
    uses = re.findall(r"(?m)^\s*uses:\s*([^\s#]+)(?:\s+#\s*(\S+))?$", text)
    assert uses == [
        (f"actions/checkout@{CHECKOUT_SHA}", "v7.0.1"),
        (f"astral-sh/setup-uv@{SETUP_UV_SHA}", "v10.2.0"),
    ]
    for reference, _tag in uses:
        assert re.fullmatch(r"[^@]+@[0-9a-f]{40}", reference)


def test_ci_pins_python_uv_and_disables_dependency_cache():
    text = _text()
    assert 'version: "0.11.26"' in text
    assert 'python-version: "3.12.7"' in text
    assert "enable-cache: false" in text
    assert "persist-credentials: false" in text


def test_ci_runs_the_complete_locked_validation_sequence():
    text = _text()
    commands = (
        "uv lock --check",
        "uv sync --dev --locked",
        "uv run python -m compileall -q app tests main.py",
        "uv run pytest -q",
    )
    positions = [text.index(command) for command in commands]
    assert positions == sorted(positions)
    assert "continue-on-error" not in text
    assert "--disable-warnings" not in text


def test_ci_checks_staged_unstaged_and_tracked_status_after_tests():
    text = _text()
    mutation_check = text.index("Verify tests did not modify tracked files")
    assert mutation_check > text.index("uv run pytest -q")
    assert "git diff --exit-code" in text
    assert "git diff --cached --exit-code" in text
    assert "git status --porcelain --untracked-files=no" in text


def test_ci_has_no_secrets_privileged_install_or_deployment_commands():
    text = _text().lower()
    for forbidden in (
        "${{ secrets.",
        "sudo ",
        "curl ",
        "wget ",
        "systemctl",
        "journalctl",
        "uvicorn",
        "nginx",
        "docker",
        "kubectl",
        "printenv",
        "set -x",
        "upload-artifact",
        "tojson(github)",
        "git remote -v",
    ):
        assert forbidden not in text
    assert re.search(r"(?m)^\s*env:\s*$", text) is None
    assert re.search(r"(?m)^\s*[a-z-]+:\s*write\s*$", text) is None


def test_ci_contains_no_sensitive_or_machine_local_literals():
    text = _text()
    assert re.search(
        r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])",
        text,
    ) is None
    for forbidden in (
        "/Users/",
        "/home/",
        "Authorization: Bearer ",
        "BEGIN PRIVATE KEY",
        "PRIVACY_CANARY",
        "type=SYSCALL msg=audit(",
    ):
        assert forbidden not in text
