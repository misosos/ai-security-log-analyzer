import re
from pathlib import Path

import tomllib

from app.deployment.asgi import LINUX_AUDIT_API_CREDENTIAL_FILENAME


ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
RELEASE = ROOT / "docs" / "release_readiness.md"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _local_markdown_links(path: Path) -> list[Path]:
    links = re.findall(r"\[[^]]+\]\(([^)]+)\)", _read(path))
    return [
        (path.parent / target.split("#", 1)[0]).resolve()
        for target in links
        if target
        and not target.startswith(("http://", "https://", "#", "mailto:"))
    ]


def test_primary_documents_are_nonempty_utf8_and_link_targets_exist():
    assert len(_read(README)) > 1000
    assert len(_read(RELEASE)) > 1000
    for document in (README, RELEASE):
        targets = _local_markdown_links(document)
        assert targets
        assert all(target.is_file() for target in targets)


def test_readme_links_to_verified_cli_and_development_api_commands():
    text = _read(README)
    guide = _read(ROOT / "docs/final_demo_guide.md")
    deployment = _read(ROOT / "docs/linux_audit_api_deployment_security.md")
    assert "uv sync --locked --dev" in text and "uv run pytest" in text
    assert "docs/final_demo_guide.md" in text
    for command in (
        "uv run python -m app.main --html-report investigation.html",
        "uv run uvicorn app.api:app --host 127.0.0.1 --port 8000",
        "curl --fail --silent http://127.0.0.1:8000/api/health",
    ):
        assert command in guide
    assert "uvicorn app.deployment.asgi:create_linux_audit_api_app --factory" in deployment


def test_linked_api_docs_match_actual_route_and_multipart_contracts():
    text = _read(ROOT / "docs/linux_audit_api_design.md")
    web = _read(ROOT / "docs/web_application_design.md")
    for value in (
        "GET /api/health",
        "POST /api/analyze",
        "POST /api/analyze-linux-audit",
        "application_file",
        "ssh_file",
        "access_file",
        "linux_audit_files",
    ):
        assert value in text + web
    assert "`/api/analyze-linux-audit`" in text
    assert "OpenAPI" in text
    readiness = _read(ROOT / "docs/linux_audit_api_deployment_security.md")
    assert "GET /internal/readiness" in readiness and "excluded from OpenAPI" in readiness
    assert "docs/index.md" in _read(README)


def test_linked_deployment_doc_matches_constants_and_boundaries():
    text = _read(ROOT / "docs/linux_audit_api_deployment_security.md")
    assert LINUX_AUDIT_API_CREDENTIAL_FILENAME in text
    assert "CREDENTIALS_DIRECTORY" in text
    assert "LINUX_AUDIT_API_PRINCIPAL_ID" in text
    assert "LINUX_AUDIT_API_MAX_CONCURRENT_ANALYSES" in text
    assert "systemd" in text
    assert "Nginx" in text
    assert "not a deployed configuration" in text


def test_readme_and_detail_docs_state_evidence_and_privacy_limits():
    text = _read(README)
    audit = _read(ROOT / "docs/linux_audit_process_execution.md")
    web = _read(ROOT / "docs/web_application_design.md")
    for value in ("탐지는 조사할 관찰", "상관관계는", "외부 LLM을 호출하지 않습니다", "cross-source 결합 없음"):
        assert value in text
    for value in ("argv", "PROCTITLE", "raw record"):
        assert value in audit
    assert "full query" in web


def test_release_matrix_distinguishes_repository_and_host_status():
    text = _read(RELEASE)
    for status in (
        "Repository verified",
        "Reference only",
        "Host acceptance required",
        "Intentionally unsupported",
    ):
        assert status in text
    assert "Repository release candidate: **PASS**" in text
    assert (
        "Production Linux host activation: **NOT APPROVED until the external checklist is completed**"
        in text
    )


def test_release_document_covers_required_evidence_areas():
    text = _read(RELEASE)
    for area in (
        "Dependency lock",
        "Default CLI",
        "Linux Audit CLI",
        "Default API",
        "Authentication / authorization",
        "Upload bounds",
        "Concurrency",
        "Access audit",
        "Secret bootstrap",
        "Journald sink",
        "Lifespan / readiness",
        "Temporary cleanup",
        "LLM isolation",
        "Real Linux production host",
    ):
        assert area in text


def test_documents_contain_no_secret_shaped_value_or_sensitive_fixture_line():
    text = _read(README) + _read(RELEASE)
    assert re.search(r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])", text) is None
    assert "type=SYSCALL msg=audit(" not in text
    assert "type=EXECVE msg=audit(" not in text
    assert "Authorization: Bearer " not in text
    assert "BEGIN PRIVATE KEY" not in text


def test_documents_contain_no_local_user_path_or_canary():
    text = _read(README) + _read(RELEASE)
    for forbidden in (
        "/Users/",
        "/home/",
        "C:\\Users\\",
        "PRIVACY_CANARY",
        "SECRET_CANARY",
        "TOKEN_CANARY",
    ):
        assert forbidden not in text


def test_release_entry_metadata_and_test_total_are_current():
    metadata = tomllib.loads(_read(ROOT / "pyproject.toml"))["project"]
    assert metadata["description"] != "Add your description here"
    assert metadata["requires-python"] == ">=3.12"
    assert "passing tests" not in _read(README)
    assert "1,152 tests pass" in _read(RELEASE)
    launcher = _read(ROOT / "main.py")
    assert "from app.main import main" in launcher
    assert "Hello from" not in launcher
