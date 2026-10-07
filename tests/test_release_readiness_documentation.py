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


def test_readme_has_verified_cli_and_development_api_commands():
    text = _read(README)
    assert "uv sync --dev" in text
    assert "uv run pytest" in text
    assert "uv run python -m app.main" in text
    assert "--linux-audit" in text
    assert "uv run uvicorn app.api:app --reload" in text
    assert "uvicorn app.deployment.asgi:create_linux_audit_api_app --factory" in text


def test_readme_matches_actual_route_and_multipart_contracts():
    text = _read(README)
    for value in (
        "GET /api/health",
        "POST /api/analyze",
        "POST /api/analyze-linux-audit",
        "GET /internal/readiness",
        "application_file",
        "ssh_file",
        "access_file",
        "linux_audit_files",
    ):
        assert value in text
    assert "does **not** register `/api/analyze-linux-audit`" in text
    assert "excluded from OpenAPI" in text


def test_readme_matches_deployment_constants_and_boundaries():
    text = _read(README)
    assert LINUX_AUDIT_API_CREDENTIAL_FILENAME in text
    assert "CREDENTIALS_DIRECTORY" in text
    assert "LINUX_AUDIT_API_PRINCIPAL_ID" in text
    assert "LINUX_AUDIT_API_MAX_CONCURRENT_ANALYSES" in text
    assert "systemd" in text
    assert "Nginx" in text
    assert "not approved" in text.lower()


def test_readme_states_evidence_and_privacy_limits():
    text = _read(README)
    for value in (
        "not by itself proof of compromise",
        "Correlation is not causation",
        "argv",
        "PROCTITLE",
        "raw compound records",
        "not sent to the LLM",
        "do not generically serialize internal objects",
        "No implemented frontend",
        "No stable process identity",
        "process-local",
    ):
        assert value in text


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
    assert "1,150 passing tests" in _read(README)
    assert "1,150 tests pass" in _read(RELEASE)
    launcher = _read(ROOT / "main.py")
    assert "from app.main import main" in launcher
    assert "Hello from" not in launcher
