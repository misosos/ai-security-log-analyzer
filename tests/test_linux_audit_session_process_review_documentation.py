from pathlib import Path


DOCUMENT = Path("docs/linux_audit_session_process_review.md")
PROCESS_DOCUMENT = Path("docs/linux_audit_process_execution.md")
SHARED_MEMORY_DOCUMENT = Path("docs/shared_memory_execution_review.md")
CANARIES = {
    "SYNTHETIC_SESSION_PROCESS_SECRET_DO_NOT_EXPOSE",
    "SYNTHETIC_PROCESS_SECRET_DO_NOT_EXPOSE",
}
REQUIRED_URLS = {
    "https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/"
    "html/security_hardening/auditing-the-system_security-hardening",
    "https://raw.githubusercontent.com/linux-audit/audit-documentation/main/"
    "specs/fields/field-dictionary.csv",
    "https://man7.org/linux/man-pages/man8/pam_loginuid.8.html",
    "https://github.com/torvalds/linux/blob/master/kernel/auditsc.c",
    "https://attack.mitre.org/datacomponents/DC0032/",
    "https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html",
}


def _document_text() -> str:
    return DOCUMENT.read_text(encoding="utf-8")


def test_document_exists_and_records_the_bounded_data_flow():
    text = _document_text()

    assert text.startswith(
        "# Linux Audit Session–Process Co-Observation Review"
    )
    for contract in (
        "--linux-audit",
        "load_normalized_logs() (1회)",
        "parse_linux_audit_events()",
        "collect_shared_memory_execution_observations()",
        "collect_session_process_co_observations()",
        "summarize_session_process_co_observations()",
        "print_analysis_result()",
    ):
        assert contract in text


def test_document_records_strict_scope_lifecycle_and_matching_contracts():
    text = _document_text()

    for field in (
        "source_instance",
        "node",
        "audit_session_id",
        "audit_user_id",
        "process_event_id",
    ):
        assert field in text

    for contract in (
        "start < end",
        "session_start_timestamp <= process_timestamp <= session_end_timestamp",
        "success`, `failure`, `unknown",
        "multiset cardinality",
        "cross-session",
        "internal contract error",
    ):
        assert contract in text


def test_document_explains_overall_and_session_linked_counts():
    text = _document_text()

    assert (
        "session-linked shared-memory count <= overall shared-memory "
        "review count"
    ) in text
    assert "전체 observation이 `2`, session-linked가 `1`이다" in text
    assert "Lifecycle 구간 밖" in text
    assert "두 count가 항상 같다고 가정하지 않는다" in text


def test_document_fixes_privacy_external_and_failure_boundaries():
    text = _document_text()

    for private_field in (
        "`argv`",
        "PROCTITLE",
        "raw records",
        "executable",
        "PATH/CWD",
        "source_instance",
        "session/event ID",
        "timestamp",
    ):
        assert private_field in text

    assert "| CLI | fixed summary count만 |" in text
    assert "| API | 없음 |" in text
    assert "| LLM | 없음 |" in text
    assert "| Frontend | 없음 |" in text
    assert "| Risk | 사용하지 않음 |" in text
    assert "`results`와 `global_correlation` contract 불변" in text
    assert "exit code `2`" in text
    assert "exit code `1`" in text
    assert "partial report" in text
    assert "zero count로" in text


def test_document_bounds_security_meaning_without_prohibited_claims():
    text = _document_text()

    for limitation in (
        "co-observation != causation",
        "session scope != 동일 인간",
        "process count != unique process count",
        "success != program goal achieved",
        "shared-memory observation != malware",
        "count != attack, incident 또는 compromise count",
        "section absence != activity or attack absence",
    ):
        assert limitation in text

    assert "금지되는 표현" in text
    assert "현재 co-observation의 공격 판정" in text


def test_document_records_primary_sources_and_contains_no_fixture_evidence():
    text = _document_text()

    assert REQUIRED_URLS <= set(text.split())
    assert "접근일: 2026-09-26" in text
    assert CANARIES.isdisjoint(text.split())
    assert "type=SYSCALL msg=audit(" not in text
    assert "type=USER_START msg=audit(" not in text
    assert "password=" not in text.casefold()
    assert "credential=" not in text.casefold()
    assert "/Users/" not in text


def test_related_documents_link_to_the_session_process_review():
    link = "linux_audit_session_process_review.md"

    assert link in PROCESS_DOCUMENT.read_text(encoding="utf-8")
    assert link in SHARED_MEMORY_DOCUMENT.read_text(encoding="utf-8")
