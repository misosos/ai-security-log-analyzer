from pathlib import Path


DOCUMENT = Path("docs/linux_audit_process_execution.md")

REQUIRED_URLS = {
    "https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/"
    "html/security_hardening/auditing-the-system_security-hardening",
    "https://raw.githubusercontent.com/linux-audit/audit-documentation/"
    "main/specs/fields/field-dictionary.csv",
    "https://github.com/torvalds/linux/blob/master/kernel/auditsc.c",
    "https://attack.mitre.org/datacomponents/DC0032/",
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Logging_Cheat_Sheet.html",
    "https://nvlpubs.nist.gov/nistpubs/Legacy/SP/"
    "nistspecialpublication800-92.pdf",
    "https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf",
    "https://genai.owasp.org/llmrisk/"
    "llm022025-sensitive-information-disclosure/",
}


def test_process_execution_documentation_preserves_security_contract():
    text = DOCUMENT.read_text(encoding="utf-8")

    assert text.startswith("# Linux Audit Process Execution Telemetry\n")
    for boundary in (
        "observation_count != unique process count",
        "success != program goal achieved",
        "success != attack success",
        "completeness != correctness",
        "completeness != trust",
        "section absence != absence of execution",
        "process telemetry != compromise evidence",
    ):
        assert boundary in text

    assert "| CLI | 고정 count aggregate만 | 없음 |" in text
    assert "| API | 없음 | 없음 |" in text
    assert "| LLM | 없음 | 없음 |" in text
    assert "| Frontend | 없음 | 없음 |" in text
    assert "Detailed evidence" in text

    for url in REQUIRED_URLS:
        assert url in text

    assert "SYNTHETIC_PROCESS_SECRET_DO_NOT_EXPOSE" not in text
    assert "success = attack success" not in text
    assert "process telemetry = compromise evidence" not in text
