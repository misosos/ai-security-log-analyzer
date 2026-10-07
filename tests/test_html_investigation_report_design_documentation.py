from pathlib import Path


DOCUMENT = Path("docs/html_investigation_report_design.md")


def document_text():
    return DOCUMENT.read_text(encoding="utf-8")


def normalized_document_text():
    return " ".join(document_text().split())


def test_design_defines_phase_and_architecture_boundaries():
    text = document_text()

    assert "The initial phase produced design documentation" in text
    assert "documentation and documentation contract\ntests" in text
    assert "It does not add an HTML\nrenderer" in text
    assert "explicit immutable report projection" in text
    assert "pure standalone HTML rendering" in text
    assert "must not invoke the CLI" in text
    assert "Raw `global_correlation` is excluded from V1" in text
    assert "separate from both API and\nLLM contracts" in text


def test_design_defines_summary_counts_and_invariants():
    text = document_text()

    for field in [
        "analyzed_subject_count",
        "high_risk_subject_count",
        "medium_risk_subject_count",
        "low_risk_subject_count",
        "supported_detection_observation_count",
        "supported_correlation_observation_count",
        "linux_audit_process_observation_count",
        "shared_memory_review_observation_count",
        "session_process_co_observation_count",
    ]:
        assert f"`{field}`" in text

    assert "HIGH + MEDIUM + LOW == analyzed_subject_count" in text
    assert "not counts of unique attackers" in text
    assert "not proof of physical session" in text


def test_design_preserves_risk_and_deterministic_sorting_contract():
    text = document_text()

    assert "review_order: positive integer" in text
    assert "rows are enumerated `1..N`" in text
    assert "operator-navigation aid" in text
    assert "must not modify `risk_level`" in text
    assert "canonical IP numeric order" in text
    assert "not a new risk, severity, priority score" in text
    assert "P1" not in text
    assert "P2" not in text
    assert "P3" not in text


def test_design_maps_supported_display_names_and_typed_evidence():
    text = document_text()

    mappings = {
        "`brute_force`": "`Brute Force`",
        "`password_spraying_like`": "`Password Spraying-like`",
        "`path_traversal`": "`Path Traversal`",
        "`failed_to_successful_login`": (
            "`Failed Login → Successful Login`"
        ),
        "`brute_force_to_successful_login`": (
            "`Brute Force → Successful Login`"
        ),
    }
    for internal, display in mappings.items():
        assert f"| {internal} | {display} |" in text

    assert "Evidence is matched by `Evidence.type`, never list position" in text
    assert "`url_decoded_query`" in text
    assert "never copied into the report projection" in text
    assert "Seconds display with `seconds`" in text
    assert "response size displays with `bytes`" in text


def test_design_defines_projection_and_privacy_exclusions():
    text = document_text()

    for prohibited_mechanism in [
        "`asdict()`",
        "`vars()`",
        "`__dict__`",
        "generic recursive serialization",
        "arbitrary dictionary or list passthrough",
        "parsing CLI stdout",
    ]:
        assert prohibited_mechanism in text

    for excluded_data in [
        "full HTTP query strings",
        "raw log lines",
        "credentials, passwords, tokens, cookies, authorization headers",
        "Linux Audit argv, PROCTITLE, raw records",
        "temporary paths, upload filenames, file digests",
        "original account names",
        "LLM input/output or any LLM transmission",
    ]:
        assert excluded_data in text

    assert "Account masked" not in text
    assert "report-local account aliases" in text
    assert "IP addresses can identify\nsystems or people" in text


def test_design_defines_deterministic_private_account_aliases():
    text = normalized_document_text()

    assert "strict UTF-8 byte sequences" in text
    assert "Exact duplicate source strings receive the same alias" in text
    assert "distinct valid source strings receive distinct aliases" in text
    assert "Account 1" in text
    assert "Account 2" in text
    assert "same validated projection input" in text
    assert "raw event arrival order" in text
    assert "not stable cross-report identifiers" in text
    assert "No Unicode normalization, case folding, hashing" in text
    assert "missing or malformed account" in text
    assert "duplicate alias, cardinality mismatch" in text
    assert "source-name to alias mapping must not be retained" in text

    for location in [
        "HTML text",
        "metadata",
        "comments",
        "element IDs",
        "CSS classes",
        "data attributes",
        "filenames",
        "exceptions",
        "renderer errors",
    ]:
        assert location in text


def test_design_defines_fixed_bounded_next_step_mappings():
    text = normalized_document_text()

    mappings = {
        "`brute_force`": "`review_authentication_failures`",
        "`password_spraying_like`": (
            "`review_cross_account_authentication`"
        ),
        "`path_traversal`": "`review_traversal_response_context`",
        "`failed_to_successful_login`": "`review_login_transition`",
        "`brute_force_to_successful_login`": (
            "`review_brute_force_login_transition`"
        ),
    }
    for observation_type, next_step_id in mappings.items():
        assert f"| {observation_type} | {next_step_id} |" in text

    assert "Next steps use this closed allowlist" in text
    assert "de-duplicated by `next_step_id`" in text
    assert "An unsupported type gets no next step" in text
    assert "No LLM generates or rewrites these values" in text
    assert "no log text, rationale, exception, or internal object text" in text
    assert "automatic block of an account/IP" in text
    assert "Every step is limited to evidence review and verification" in text
    assert "privacy-canary exclusion from next-step text" in text
    assert "correlation is not causation" in text


def test_design_requires_standalone_rendering_security():
    text = document_text()

    for directive in [
        "default-src 'none'",
        "base-uri 'none'",
        "form-action 'none'",
        "script-src 'none'",
        "script-src-attr 'none'",
        "style-src 'sha256-{BASE64_SHA256_OF_EXACT_STATIC_STYLE_BLOCK}'",
        "style-src-attr 'none'",
        "img-src 'none'",
        "font-src 'none'",
        "connect-src 'none'",
    ]:
        assert directive in text

    assert "must be escaped for its exact HTML\ntext context" in text
    assert "no inline event handler" in text
    assert "Do not add\n`report-uri`/`report-to`" in text
    assert "neither makes the\nreport non-sensitive" in text
    assert "remove it on every failure" in text


def test_design_covers_empty_states_future_sequence_and_official_research():
    text = document_text()

    assert (
        "No supported detection observations were produced from the "
        "analyzed input."
    ) in text
    assert "This does not establish the absence of malicious activity." in text
    assert "Linux Audit aggregate was not provided for this report." in text
    assert "Unsupported detection type was\nomitted from this report." in text
    assert "`--html-report PATH`" in text
    assert "V1 does not add a web dashboard" in text
    assert "Sources were accessed on **2026-10-07**" in text

    for official_source in [
        "cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html",
        "cheatsheetseries.owasp.org/cheatsheets/"
        "Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
        "developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/"
        "Content-Security-Policy/default-src",
        "csrc.nist.gov/pubs/sp/800/92/final",
    ]:
        assert official_source in text
