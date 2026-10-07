import base64
import builtins
import copy
from dataclasses import replace
import hashlib
from html.parser import HTMLParser
import os
import random
import re
import socket
import time

import pytest

from app.analyzer.html_report import (
    InvestigationReportRendererError,
    render_investigation_report_html,
)
from app.analyzer.llm import build_llm_input
from app.analyzer.report import print_analysis_result
from app.analyzer.report_projection import (
    AssessmentDimensionProjection,
    BruteForceEvidenceProjection,
    CorrelationDisplayItem,
    DetectionDisplayItem,
    FixedNextStepItem,
    InterpretationLimitationItem,
    InvestigationReportProjection,
    InvestigationSubjectRow,
    LinuxAuditAggregateProjection,
    PasswordSprayingLikeEvidenceProjection,
    PathTraversalEvidenceProjection,
    ReportSummaryProjection,
    RiskAssessmentProjection,
)
from app.api import build_analysis_response
from app.models.schemas import DetectionResult


ORIGINAL_ACCOUNT = "PRIVATE-ORIGINAL-ACCOUNT"
FULL_QUERY = "PRIVATE-FULL-QUERY-TOKEN"
RAW_LOG = "PRIVATE-RAW-LOG-CREDENTIAL"
LINUX_DETAIL = "PRIVATE-ARGV-PROCTITLE-CWD-EVENT-ID"

EXPECTED_CSP = (
    "default-src 'none'; "
    "base-uri 'none'; "
    "form-action 'none'; "
    "object-src 'none'; "
    "script-src 'none'; "
    "script-src-attr 'none'; "
    "style-src 'sha256-HrSeyxAgCRxOqI488GcfpWXohRBDF7JsJjos2KT0Jqk='; "
    "style-src-attr 'none'; "
    "img-src 'none'; "
    "font-src 'none'; "
    "connect-src 'none'; "
    "media-src 'none'; "
    "frame-src 'none'; "
    "worker-src 'none'; "
    "manifest-src 'none'"
)


class HtmlInspection(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.tags = []
        self.attributes = []
        self.comments = []
        self.text = []

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        self.attributes.extend((tag, name, value) for name, value in attrs)

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)

    def handle_comment(self, data):
        self.comments.append(data)

    def handle_data(self, data):
        self.text.append(data)


def dimension(level, rationale):
    return AssessmentDimensionProjection(level, (rationale,))


def assessment(risk, confidence):
    return RiskAssessmentProjection(
        risk_level=risk,
        likelihood=dimension(
            "HIGH" if risk == "HIGH" else "LOW",
            "Likelihood rationale & review",
        ),
        impact=dimension("MEDIUM", "Impact rationale <bounded>"),
        confidence=dimension(confidence, "Confidence rationale > observed"),
    )


def subject(
    review_order,
    subject_ip,
    risk,
    confidence,
    *,
    detections=(),
    correlations=(),
    limitations=(),
    next_steps=(),
    unsupported_detection=False,
    unsupported_correlation=False,
):
    return InvestigationSubjectRow(
        review_order=review_order,
        subject_ip=subject_ip,
        primary_detection_display_name=(
            detections[0].display_name if detections else None
        ),
        notable_correlation_display_name=(
            correlations[0].display_name if correlations else None
        ),
        review_reason=f"{risk} review reason & verification",
        detections=detections,
        correlations=correlations,
        risk_assessment=assessment(risk, confidence),
        unsupported_detection_observed=unsupported_detection,
        unsupported_correlation_observed=unsupported_correlation,
        limitations=limitations,
        next_steps=next_steps,
    )


def populated_projection():
    brute = DetectionDisplayItem(
        "brute_force",
        "Brute Force",
        BruteForceEvidenceProjection(5, 1, 16.0),
    )
    spray = DetectionDisplayItem(
        "password_spraying_like",
        "Password Spraying-like",
        PasswordSprayingLikeEvidenceProjection(4, 4, 6),
    )
    traversal = DetectionDisplayItem(
        "path_traversal",
        "Path Traversal",
        PathTraversalEvidenceProjection("/download", "../", "GET", 200, 2048),
    )
    correlation = CorrelationDisplayItem(
        "failed_to_successful_login",
        "Failed Login → Successful Login",
        "Account 1",
        2.5,
    )
    brute_correlation = CorrelationDisplayItem(
        "brute_force_to_successful_login",
        "Brute Force → Successful Login",
        "Account 1",
        3,
    )
    limitation = InterpretationLimitationItem(
        "correlation_not_causation",
        "A correlation is not causation or proof of compromise.",
    )
    next_step = FixedNextStepItem(
        "review_login_transition",
        "Review identity-provider records and verify the correlated login.",
    )
    high = subject(
        1,
        "192.0.2.10",
        "HIGH",
        "HIGH",
        detections=(brute, traversal),
        correlations=(correlation, brute_correlation),
        limitations=(limitation,),
        next_steps=(next_step,),
    )
    medium = subject(
        2,
        "192.0.2.20",
        "MEDIUM",
        "MEDIUM",
        detections=(spray,),
    )
    low = subject(3, "192.0.2.30", "LOW", "LOW")
    return InvestigationReportProjection(
        schema_version="1",
        classification="Sensitive — Security Investigation Data",
        summary=ReportSummaryProjection(3, 1, 1, 1, 3, 2, None, None, None),
        subjects=(low, high, medium),
        linux_audit=None,
    )


def empty_projection(*, linux_audit=None):
    if linux_audit is None:
        summary = ReportSummaryProjection(0, 0, 0, 0, 0, 0, None, None, None)
    else:
        summary = ReportSummaryProjection(0, 0, 0, 0, 0, 0, 0, 0, 0)
    return InvestigationReportProjection(
        "1",
        "Sensitive — Security Investigation Data",
        summary,
        (),
        linux_audit,
    )


def inspect(html):
    parser = HtmlInspection()
    parser.feed(html)
    parser.close()
    return parser


def parsed_start_tags(html):
    class StartTagParser(HTMLParser):
        def __init__(self):
            super().__init__()
            self.values = []

        def handle_starttag(self, tag, attrs):
            self.values.append((tag, attrs))

    parser = StartTagParser()
    parser.feed(html)
    parser.close()
    return parser.values


def test_renderer_accepts_only_exact_projection_runtime_type():
    class ProjectionSubclass(InvestigationReportProjection):
        pass

    valid = empty_projection()
    subclass = ProjectionSubclass(
        valid.schema_version,
        valid.classification,
        valid.summary,
        valid.subjects,
        valid.linux_audit,
    )
    for invalid in (None, {}, valid.summary, subclass):
        with pytest.raises(InvestigationReportRendererError) as caught:
            render_investigation_report_html(invalid)
        assert str(caught.value) == "Investigation report rendering failed."


def test_complete_html5_document_metadata_fixed_title_and_utf8():
    html = render_investigation_report_html(populated_projection())
    parser = inspect(html)

    assert html.startswith("<!doctype html>\n<html lang=\"en\">\n")
    assert html.endswith("</body>\n</html>\n")
    assert '<meta charset="utf-8">' in html
    assert '<meta name="viewport" content="width=device-width, initial-scale=1">' in html
    assert '<meta name="referrer" content="no-referrer">' in html
    assert "<title>Security Log Investigation Report</title>" in html
    assert "Security Log Investigation Report" in "".join(parser.text)


def test_exact_csp_and_static_css_hash_match_the_style_text():
    html = render_investigation_report_html(populated_projection())
    start_tags = parsed_start_tags(html)
    csp = next(
        dict(attrs)["content"]
        for tag, attrs in start_tags
        if tag == "meta"
        and dict(attrs).get("http-equiv") == "Content-Security-Policy"
    )
    css = re.search(r"<style>(.*?)</style>", html, re.DOTALL).group(1)
    digest = base64.b64encode(
        hashlib.sha256(css.encode("utf-8")).digest()
    ).decode("ascii")

    assert csp == EXPECTED_CSP
    assert f"style-src 'sha256-{digest}'" in csp
    assert "report-uri" not in csp
    assert "report-to" not in csp


def test_document_has_no_javascript_remote_resources_or_forbidden_elements():
    html = render_investigation_report_html(populated_projection())
    parser = inspect(html)
    forbidden_tags = {
        "script", "iframe", "object", "embed", "form", "input", "button",
        "canvas", "svg", "img", "video", "audio", "link", "base",
    }

    assert forbidden_tags.isdisjoint(parser.tags)
    assert not parser.comments
    assert "javascript:" not in html.casefold()
    assert "http://" not in html.casefold()
    assert "https://" not in html.casefold()
    assert "data:" not in html.casefold()
    assert "sourceMappingURL" not in html
    assert all(not name.casefold().startswith("on") for _, name, _ in parser.attributes)
    assert all(name != "download" for _, name, _ in parser.attributes)
    assert '<meta http-equiv="refresh"' not in html.casefold()


def test_summary_review_table_and_projection_row_order_are_preserved():
    html = render_investigation_report_html(populated_projection())

    for label, value in (
        ("Analyzed subjects", 3),
        ("HIGH risk", 1),
        ("MEDIUM risk", 1),
        ("LOW risk", 1),
        ("Supported detections", 3),
        ("Supported correlations", 2),
    ):
        assert f"<dt>{label}</dt>\n<dd>{value}</dd>" in html
    for heading in (
        "Review order", "Subject", "Risk", "Primary detection",
        "Notable correlation", "Confidence", "Review reason",
    ):
        assert f'<th scope="col">{heading}</th>' in html
    assert "<caption>Subjects in projected review order</caption>" in html
    assert html.index("192.0.2.30") < html.index("192.0.2.10")
    assert html.index("192.0.2.10") < html.index("192.0.2.20")


def test_risk_has_text_indicators_and_subject_visibility_contract():
    html = render_investigation_report_html(populated_projection())
    blocks = re.findall(
        r'<details class="subject-card"(?: open)?>.*?</details>',
        html,
        re.DOTALL,
    )
    by_subject = {
        subject_ip: next(block for block in blocks if subject_ip in block)
        for subject_ip in ("192.0.2.10", "192.0.2.20", "192.0.2.30")
    }

    assert '<span class="risk risk-high">Risk: HIGH</span>' in html
    assert '<span class="risk risk-medium">Risk: MEDIUM</span>' in html
    assert '<span class="risk risk-low">Risk: LOW</span>' in html
    assert by_subject["192.0.2.10"].startswith(
        '<details class="subject-card" open>'
    )
    assert by_subject["192.0.2.20"].startswith(
        '<details class="subject-card" open>'
    )
    assert by_subject["192.0.2.30"].startswith(
        '<details class="subject-card">'
    )


def test_exact_detection_evidence_labels_units_and_no_positional_fields():
    html = render_investigation_report_html(populated_projection())

    for display_name in (
        "Brute Force", "Password Spraying-like", "Path Traversal",
    ):
        assert f"<h5>{display_name}</h5>" in html
    for expected in (
        "<dt>Failed attempts</dt>\n<dd>5</dd>",
        "<dt>Target accounts</dt>\n<dd>1</dd>",
        "<dt>Time window</dt>\n<dd>16.0 seconds</dd>",
        "<dt>Failed attempts</dt>\n<dd>4</dd>",
        "<dt>Target accounts</dt>\n<dd>4</dd>",
        "<dt>Time window</dt>\n<dd>6 seconds</dd>",
        "<dt>Request path</dt>\n<dd><code>/download</code></dd>",
        "<dt>Matched pattern</dt>\n<dd><code>../</code></dd>",
        "<dt>HTTP method</dt>\n<dd>GET</dd>",
        "<dt>Response status</dt>\n<dd>200</dd>",
        "<dt>Response size</dt>\n<dd>2048 bytes</dd>",
    ):
        assert expected in html
    for internal_name in (
        "failed_attempt_count",
        "target_account_count",
        "time_window_seconds",
        "response_size_bytes",
    ):
        assert internal_name not in html


def test_supported_correlations_render_display_alias_and_seconds_only():
    html = render_investigation_report_html(populated_projection())

    assert "<h5>Failed Login → Successful Login</h5>" in html
    assert "<h5>Brute Force → Successful Login</h5>" in html
    assert "<dt>Account alias</dt>\n<dd>Account 1</dd>" in html
    assert "<dt>Time delta</dt>\n<dd>2.5 seconds</dd>" in html
    assert "failed_to_successful_login" not in html
    assert "brute_force_to_successful_login" not in html
    assert ORIGINAL_ACCOUNT not in html


def test_assessment_limitations_and_next_steps_remain_separate():
    html = render_investigation_report_html(populated_projection())

    assert "<h4>Assessment</h4>" in html
    assert "<h4>Detection evidence</h4>" in html
    assert "<h4>Interpretation limitations</h4>" in html
    assert "<h4>Suggested next investigation steps</h4>" in html
    assert html.count("A correlation is not causation or proof of compromise.") == 1
    assert html.count(
        "Review identity-provider records and verify the correlated login."
    ) == 1


def test_empty_states_are_bounded_and_linux_audit_absence_is_explicit():
    html = render_investigation_report_html(empty_projection())

    assert (
        "No supported detection observations were produced from the analyzed "
        "input."
    ) in html
    assert (
        "No supported per-IP correlation observations were produced from the "
        "analyzed input."
    ) in html
    assert html.count("This does not establish the absence of malicious activity.") == 1
    assert "Linux Audit aggregate was not provided for this report." in html
    assert "<h2>Linux Audit aggregate</h2>" not in html
    lower = html.casefold()
    for prohibited_claim in ("system is safe", "clean system", "no attack", "no compromise"):
        assert prohibited_claim not in lower


def test_unsupported_observation_notices_are_fixed_and_bounded():
    projection = populated_projection()
    high = replace(
        projection.subjects[1],
        unsupported_detection_observed=True,
        unsupported_correlation_observed=True,
    )
    projection = replace(
        projection,
        subjects=(projection.subjects[0], high, projection.subjects[2]),
    )

    html = render_investigation_report_html(projection)

    assert "Unsupported detection type was omitted from this report." in html
    assert "Unsupported correlation type was omitted from this report." in html


def test_html_escapes_all_projected_text_and_keeps_it_out_of_attributes():
    adversarial = "TEXT-CANARY & <tag> > \"double\" 'single'"
    projection = populated_projection()
    high = projection.subjects[1]
    path = high.detections[1]
    hostile_path = replace(
        path,
        evidence=replace(path.evidence, request_path=adversarial),
    )
    hostile_limitation = InterpretationLimitationItem("fixed-id", adversarial)
    high = replace(
        high,
        review_reason=adversarial,
        detections=(high.detections[0], hostile_path),
        limitations=(hostile_limitation,),
    )
    projection = replace(
        projection,
        classification=adversarial,
        subjects=(projection.subjects[0], high, projection.subjects[2]),
    )

    html = render_investigation_report_html(projection)
    parser = inspect(html)

    escaped = "TEXT-CANARY &amp; &lt;tag&gt; &gt; &quot;double&quot; &#x27;single&#x27;"
    assert escaped in html
    assert "<tag>" not in html
    assert adversarial not in html
    assert "TEXT-CANARY" in "".join(parser.text)
    assert all(
        value is None or "TEXT-CANARY" not in value
        for _, _, value in parser.attributes
    )
    style = re.search(r"<style>(.*?)</style>", html, re.DOTALL).group(1)
    assert "TEXT-CANARY" not in style
    assert "TEXT-CANARY" not in EXPECTED_CSP
    assert not parser.comments


def test_projection_privacy_canaries_and_linux_details_cannot_enter_html():
    html = render_investigation_report_html(populated_projection())

    assert "Account 1" in html
    for canary in (ORIGINAL_ACCOUNT, FULL_QUERY, RAW_LOG, LINUX_DETAIL):
        assert canary not in html
    for excluded_name in (
        "url_decoded_query",
        "raw_records",
        "PROCTITLE",
        "source_instance",
        "event_id",
    ):
        assert excluded_name not in html


def test_linux_audit_aggregate_is_count_only_and_zero_state_is_explicit():
    linux = LinuxAuditAggregateProjection(
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    )
    html = render_investigation_report_html(empty_projection(linux_audit=linux))

    assert "<h2>Linux Audit aggregate</h2>" in html
    assert "<dt>Process observations</dt>\n<dd>0</dd>" in html
    assert "<dt>Shared-memory review observations</dt>\n<dd>0</dd>" in html
    assert "<dt>Session-process co-observations</dt>\n<dd>0</dd>" in html
    assert (
        "No Linux Audit process observations were produced from the supplied "
        "aggregate."
    ) in html
    assert LINUX_DETAIL not in html


def test_rendering_is_byte_deterministic_pure_and_non_mutating(monkeypatch):
    projection = populated_projection()
    original = copy.deepcopy(projection)

    def forbidden(*args, **kwargs):
        raise AssertionError("renderer attempted an external read")

    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(os, "getenv", forbidden)
    monkeypatch.setattr(time, "time", forbidden)
    monkeypatch.setattr(random, "random", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)

    first = render_investigation_report_html(projection)
    second = render_investigation_report_html(projection)

    assert first == second
    assert first.encode("utf-8") == second.encode("utf-8")
    assert "\r" not in first
    assert projection == original


def test_malformed_nested_projection_uses_bounded_renderer_error():
    malformed = replace(populated_projection(), summary={"private": RAW_LOG})

    with pytest.raises(InvestigationReportRendererError) as caught:
        render_investigation_report_html(malformed)

    assert str(caught.value) == "Investigation report rendering failed."
    assert RAW_LOG not in str(caught.value)
    assert RAW_LOG not in repr(caught.value)
    assert "192.0.2.10" not in repr(caught.value)


def test_existing_cli_api_and_llm_contracts_are_unchanged(capsys):
    empty = DetectionResult(False, None, [])
    ip_result = {
        "detections": {
            "brute_force": empty,
            "password_spray": DetectionResult(False, None, []),
            "path_traversal": DetectionResult(False, None, []),
        },
        "correlation": {},
        "risk_factors": {
            "likelihood": {"level": "LOW", "rationale": []},
            "impact": {"level": "LOW", "rationale": []},
            "confidence": {"level": "LOW", "rationale": []},
        },
        "risk_level": "LOW",
    }
    analysis = {"results": {"192.0.2.1": ip_result}, "global_correlation": {}}

    print_analysis_result(analysis)
    cli_before = capsys.readouterr().out
    api_before = build_analysis_response(analysis, total_sources=1).model_dump()
    llm_before = build_llm_input("192.0.2.1", ip_result)

    render_investigation_report_html(populated_projection())

    print_analysis_result(analysis)
    cli_after = capsys.readouterr().out
    api_after = build_analysis_response(analysis, total_sources=1).model_dump()
    llm_after = build_llm_input("192.0.2.1", ip_result)
    api_before.pop("analysis_id")
    api_after.pop("analysis_id")

    assert cli_after == cli_before
    assert api_after == api_before
    assert llm_after == llm_before
