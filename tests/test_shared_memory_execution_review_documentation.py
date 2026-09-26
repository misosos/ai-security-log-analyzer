from pathlib import Path


DOCUMENT = Path("docs/shared_memory_execution_review.md")

REQUIRED_URLS = {
    "https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/"
    "security_hardening/auditing-the-system_security-hardening",
    "https://raw.githubusercontent.com/linux-audit/audit-documentation/main/"
    "specs/fields/field-dictionary.csv",
    "https://github.com/torvalds/linux/blob/master/kernel/auditsc.c",
    "https://github.com/SigmaHQ/sigma/blob/master/rules/linux/process_creation/"
    "proc_creation_lnx_susp_exec_from_dev_shm.yml",
    "https://github.com/elastic/detection-rules/blob/main/rules/linux/"
    "execution_process_started_in_shared_memory_directory.toml",
    "https://github.com/splunk/security_content/blob/develop/detections/endpoint/"
    "linux_binary_executed_from_shared_memory_directory.yml",
    "https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html",
}


def _document_text() -> str:
    return DOCUMENT.read_text(encoding="utf-8")


def test_review_document_exists_and_describes_repeatable_cli_input():
    text = _document_text()

    assert text.startswith("# Shared-memory Privileged Execution Review")
    assert "--linux-audit /path/to/audit.log" in text
    assert text.count("--linux-audit /path/to/") >= 3
    assert "반복할 수 있다" in text
    assert "source_instance" in text
    assert "host identity" in text


def test_review_document_records_exact_detector_and_failure_contracts():
    text = _document_text()

    for contract in (
        'event_type == "process_execution_attempt"',
        'source == "linux_audit"',
        'outcome == "success"',
        "exact integer `0`",
        "`/dev/shm/`",
        "`/run/shm/`",
        "`/dev/shm-backup/item`",
        "exit code `2`",
        "exit code `1`",
    ):
        assert contract in text


def test_review_document_bounds_meaning_and_external_exposure():
    text = _document_text()

    for limitation in (
        "Observation count != unique process count",
        "Review count != confirmed attack count",
        "Shared-memory path != malware",
        "Effective UID 0 != compromise",
        "Syscall success != attack success",
        "Event scope != process identity",
        "Event scope != host identity",
        "Ordering != causation",
        "Count zero != absence of attack",
    ):
        assert limitation in text

    assert "| CLI | fixed count only | none |" in text
    assert "| API | none | none |" in text
    assert "| LLM | none | none |" in text
    assert "| Risk | 사용하지 않음 | none |" in text
    assert "| Correlation | 사용하지 않음 | none |" in text


def test_review_document_records_required_official_sources_without_canary():
    text = _document_text()

    assert REQUIRED_URLS <= set(text.split())
    assert "접근일: 2026-09-26" in text
    assert "SYNTHETIC_PROCESS_SECRET_DO_NOT_EXPOSE" not in text
    assert "confirmed attack, malware 또는 compromise로 확정하는 근거가" in text
