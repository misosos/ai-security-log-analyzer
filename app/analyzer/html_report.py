import base64
import hashlib
from html import escape
import math

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


_RENDERER_ERROR_MESSAGE = "Investigation report rendering failed."

_STATIC_CSS = """* { box-sizing: border-box; }
:root {
  color-scheme: light;
  font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  line-height: 1.5;
  color: #172033;
  background: #f4f6f8;
}
body { margin: 0; }
header, main, footer { width: min(1180px, calc(100% - 2rem)); margin-inline: auto; }
header { padding: 2rem 0 1rem; }
main { padding-bottom: 2rem; }
footer { border-top: 1px solid #cbd3dc; padding: 1rem 0 2rem; color: #39475a; }
h1, h2, h3, h4, h5 { line-height: 1.25; }
h1 { margin: 0 0 .75rem; }
h2 { margin-top: 2rem; }
.notice { border-left: .3rem solid #52657a; background: #fff; padding: .75rem 1rem; }
.sensitivity { font-weight: 700; letter-spacing: .03em; }
.summary-grid, .assessment-grid, .evidence-list, .aggregate-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(10rem, 1fr));
  gap: .75rem;
}
.summary-grid > div, .assessment-grid > div, .aggregate-grid > div {
  background: #fff;
  border: 1px solid #cbd3dc;
  border-radius: .35rem;
  padding: .75rem;
}
dt { color: #42536a; font-weight: 600; }
dd { margin: .2rem 0 0; }
.summary-grid dd { font-size: 1.4rem; font-weight: 700; }
.table-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; background: #fff; }
caption { text-align: left; font-weight: 700; padding: 0 0 .5rem; }
th, td { border: 1px solid #cbd3dc; padding: .6rem; text-align: left; vertical-align: top; }
th { background: #e8edf2; }
.risk { display: inline-block; border: 1px solid currentColor; border-radius: 999px; padding: .1rem .55rem; font-weight: 800; }
.risk-high { color: #8a1c1c; background: #fff0f0; }
.risk-medium { color: #765100; background: #fff8df; }
.risk-low { color: #245c3b; background: #edf8f1; }
.subject-card { margin-top: 1rem; border: 1px solid #b8c3cf; border-radius: .4rem; background: #fff; }
.subject-card > summary { cursor: pointer; padding: .85rem 1rem; font-weight: 700; }
.subject-card > summary .risk { margin-left: .75rem; }
.subject-content { border-top: 1px solid #d8dee5; padding: 0 1rem 1rem; }
.observation { border-left: .25rem solid #77889b; padding-left: .8rem; margin: 1rem 0; }
.evidence-list { grid-template-columns: repeat(auto-fit, minmax(13rem, 1fr)); }
ul { padding-left: 1.25rem; }
code { font-family: ui-monospace, SFMono-Regular, Consolas, monospace; overflow-wrap: anywhere; }
@media (max-width: 720px) {
  header, main, footer { width: min(100% - 1rem, 1180px); }
  th, td { min-width: 8rem; }
}"""

_STYLE_HASH = base64.b64encode(
    hashlib.sha256(_STATIC_CSS.encode("utf-8")).digest()
).decode("ascii")

_CONTENT_SECURITY_POLICY = (
    "default-src 'none'; "
    "base-uri 'none'; "
    "form-action 'none'; "
    "object-src 'none'; "
    "script-src 'none'; "
    "script-src-attr 'none'; "
    f"style-src 'sha256-{_STYLE_HASH}'; "
    "style-src-attr 'none'; "
    "img-src 'none'; "
    "font-src 'none'; "
    "connect-src 'none'; "
    "media-src 'none'; "
    "frame-src 'none'; "
    "worker-src 'none'; "
    "manifest-src 'none'"
)

_NO_DETECTIONS = (
    "No supported detection observations were produced from the analyzed "
    "input."
)
_NO_CORRELATIONS = (
    "No supported per-IP correlation observations were produced from the "
    "analyzed input."
)
_ABSENCE_LIMITATION = (
    "This does not establish the absence of malicious activity."
)
_NO_LINUX_AUDIT = "Linux Audit aggregate was not provided for this report."


class InvestigationReportRendererError(ValueError):
    def __init__(self):
        super().__init__(_RENDERER_ERROR_MESSAGE)


def _fail():
    raise InvestigationReportRendererError() from None


def _text(value):
    if type(value) is not str:
        _fail()
    return escape(value, quote=True)


def _non_negative_int(value):
    if type(value) is not int or value < 0:
        _fail()
    return str(value)


def _positive_int(value):
    if type(value) is not int or value <= 0:
        _fail()
    return str(value)


def _non_negative_number(value):
    if type(value) is int:
        if value < 0:
            _fail()
        return str(value)
    if type(value) is float and math.isfinite(value) and value >= 0:
        return str(value)
    _fail()


def _optional_text(value, fallback):
    if value is None:
        return fallback
    return _text(value)


def _risk_markup(level, *, include_label=True):
    if level == "HIGH":
        css_class = "risk risk-high"
    elif level == "MEDIUM":
        css_class = "risk risk-medium"
    elif level == "LOW":
        css_class = "risk risk-low"
    else:
        _fail()
    label = f"Risk: {level}" if include_label else level
    return f'<span class="{css_class}">{label}</span>'


def _dimension_lines(title, dimension):
    if type(dimension) is not AssessmentDimensionProjection:
        _fail()
    level = _risk_markup(dimension.level, include_label=False)
    if type(dimension.rationale) is not tuple:
        _fail()
    lines = [
        f"<h5>{title} rationale</h5>",
        "<ul>",
    ]
    for rationale in dimension.rationale:
        lines.append(f"<li>{_text(rationale)}</li>")
    lines.append("</ul>")
    return level, lines


def _evidence_lines(evidence):
    if type(evidence) is BruteForceEvidenceProjection:
        return (
            ("Failed attempts", _non_negative_int(evidence.failed_attempt_count)),
            ("Target accounts", _non_negative_int(evidence.target_account_count)),
            (
                "Time window",
                f"{_non_negative_number(evidence.time_window_seconds)} seconds",
            ),
        )
    if type(evidence) is PasswordSprayingLikeEvidenceProjection:
        return (
            ("Failed attempts", _non_negative_int(evidence.failed_attempt_count)),
            ("Target accounts", _non_negative_int(evidence.target_account_count)),
            (
                "Time window",
                f"{_non_negative_number(evidence.time_window_seconds)} seconds",
            ),
        )
    if type(evidence) is PathTraversalEvidenceProjection:
        lines = [
            ("Request path", f"<code>{_text(evidence.request_path)}</code>"),
            ("Matched pattern", f"<code>{_text(evidence.matched_pattern)}</code>"),
        ]
        if evidence.http_method is not None:
            lines.append(("HTTP method", _text(evidence.http_method)))
        if evidence.response_status is not None:
            lines.append((
                "Response status",
                _non_negative_int(evidence.response_status),
            ))
        if evidence.response_size_bytes is not None:
            lines.append((
                "Response size",
                f"{_non_negative_int(evidence.response_size_bytes)} bytes",
            ))
        return tuple(lines)
    _fail()


def _detection_lines(detections, unsupported):
    if type(detections) is not tuple or type(unsupported) is not bool:
        _fail()
    lines = ["<section>", "<h4>Detection evidence</h4>"]
    if not detections:
        lines.append(
            "<p>No supported detection observations were produced for this "
            "subject.</p>"
        )
    for detection in detections:
        if type(detection) is not DetectionDisplayItem:
            _fail()
        lines.extend([
            '<article class="observation">',
            f"<h5>{_text(detection.display_name)}</h5>",
            '<dl class="evidence-list">',
        ])
        for label, value in _evidence_lines(detection.evidence):
            lines.extend([
                "<div>",
                f"<dt>{label}</dt>",
                f"<dd>{value}</dd>",
                "</div>",
            ])
        lines.extend(["</dl>", "</article>"])
    if unsupported:
        lines.append(
            "<p>Unsupported detection type was omitted from this report.</p>"
        )
    lines.append("</section>")
    return lines


def _correlation_lines(correlations, unsupported):
    if type(correlations) is not tuple or type(unsupported) is not bool:
        _fail()
    lines = ["<section>", "<h4>Correlations</h4>"]
    if not correlations:
        lines.append(
            "<p>No supported per-IP correlation observations were produced "
            "for this subject.</p>"
        )
    for correlation in correlations:
        if type(correlation) is not CorrelationDisplayItem:
            _fail()
        lines.extend([
            '<article class="observation">',
            f"<h5>{_text(correlation.display_name)}</h5>",
            '<dl class="evidence-list">',
            "<div>",
            "<dt>Account alias</dt>",
            f"<dd>{_text(correlation.account_alias)}</dd>",
            "</div>",
            "<div>",
            "<dt>Time delta</dt>",
            (
                "<dd>"
                f"{_non_negative_number(correlation.time_delta_seconds)} "
                "seconds</dd>"
            ),
            "</div>",
            "</dl>",
            "</article>",
        ])
    if unsupported:
        lines.append(
            "<p>Unsupported correlation type was omitted from this report.</p>"
        )
    lines.append("</section>")
    return lines


def _fixed_item_lines(title, items, expected_type, empty_message):
    if type(items) is not tuple:
        _fail()
    lines = ["<section>", f"<h4>{title}</h4>"]
    if not items:
        lines.append(f"<p>{empty_message}</p>")
    else:
        lines.append("<ul>")
        for item in items:
            if type(item) is not expected_type:
                _fail()
            lines.append(f"<li>{_text(item.text)}</li>")
        lines.append("</ul>")
    lines.append("</section>")
    return lines


def _assessment_lines(assessment):
    if type(assessment) is not RiskAssessmentProjection:
        _fail()
    likelihood, likelihood_lines = _dimension_lines(
        "Likelihood", assessment.likelihood
    )
    impact, impact_lines = _dimension_lines("Impact", assessment.impact)
    confidence, confidence_lines = _dimension_lines(
        "Confidence", assessment.confidence
    )
    lines = [
        "<section>",
        "<h4>Assessment</h4>",
        '<dl class="assessment-grid">',
        "<div><dt>Risk</dt><dd>"
        f"{_risk_markup(assessment.risk_level, include_label=False)}"
        "</dd></div>",
        f"<div><dt>Likelihood</dt><dd>{likelihood}</dd></div>",
        f"<div><dt>Impact</dt><dd>{impact}</dd></div>",
        f"<div><dt>Confidence</dt><dd>{confidence}</dd></div>",
        "</dl>",
    ]
    lines.extend(likelihood_lines)
    lines.extend(impact_lines)
    lines.extend(confidence_lines)
    lines.append("</section>")
    return lines


def _subject_lines(subject):
    if type(subject) is not InvestigationSubjectRow:
        _fail()
    review_order = _positive_int(subject.review_order)
    subject_ip = _text(subject.subject_ip)
    assessment = subject.risk_assessment
    if type(assessment) is not RiskAssessmentProjection:
        _fail()
    open_attribute = " open" if assessment.risk_level in {"HIGH", "MEDIUM"} else ""
    if assessment.risk_level not in {"HIGH", "MEDIUM", "LOW"}:
        _fail()
    lines = [
        f'<details class="subject-card"{open_attribute}>',
        "<summary>",
        f"<span>Review order {review_order} — Subject {subject_ip}</span>",
        _risk_markup(assessment.risk_level),
        "</summary>",
        '<div class="subject-content">',
        f"<h3>Subject {subject_ip}</h3>",
    ]
    lines.extend(_assessment_lines(assessment))
    lines.extend(_detection_lines(
        subject.detections,
        subject.unsupported_detection_observed,
    ))
    lines.extend(_correlation_lines(
        subject.correlations,
        subject.unsupported_correlation_observed,
    ))
    lines.extend(_fixed_item_lines(
        "Interpretation limitations",
        subject.limitations,
        InterpretationLimitationItem,
        "No type-specific interpretation limitations were projected for this subject.",
    ))
    lines.extend(_fixed_item_lines(
        "Suggested next investigation steps",
        subject.next_steps,
        FixedNextStepItem,
        "No fixed next investigation steps were projected for this subject.",
    ))
    lines.extend(["</div>", "</details>"])
    return lines


def _summary_lines(summary):
    if type(summary) is not ReportSummaryProjection:
        _fail()
    cards = [
        ("Analyzed subjects", summary.analyzed_subject_count),
        ("HIGH risk", summary.high_risk_subject_count),
        ("MEDIUM risk", summary.medium_risk_subject_count),
        ("LOW risk", summary.low_risk_subject_count),
        ("Supported detections", summary.supported_detection_observation_count),
        (
            "Supported correlations",
            summary.supported_correlation_observation_count,
        ),
    ]
    optional_cards = (
        (
            "Linux Audit process observations",
            summary.linux_audit_process_observation_count,
        ),
        (
            "Shared-memory review observations",
            summary.shared_memory_review_observation_count,
        ),
        (
            "Session-process co-observations",
            summary.session_process_co_observation_count,
        ),
    )
    cards.extend(
        (label, value)
        for label, value in optional_cards
        if value is not None
    )
    lines = ["<section>", "<h2>Summary</h2>", '<dl class="summary-grid">']
    for label, value in cards:
        lines.extend([
            "<div>",
            f"<dt>{label}</dt>",
            f"<dd>{_non_negative_int(value)}</dd>",
            "</div>",
        ])
    lines.extend(["</dl>", "</section>"])
    return lines


def _review_table_lines(subjects):
    if type(subjects) is not tuple:
        _fail()
    lines = [
        "<section>",
        "<h2>Investigation review</h2>",
        '<div class="table-wrap">',
        "<table>",
        "<caption>Subjects in projected review order</caption>",
        "<thead>",
        "<tr>",
        "<th scope=\"col\">Review order</th>",
        "<th scope=\"col\">Subject</th>",
        "<th scope=\"col\">Risk</th>",
        "<th scope=\"col\">Primary detection</th>",
        "<th scope=\"col\">Notable correlation</th>",
        "<th scope=\"col\">Confidence</th>",
        "<th scope=\"col\">Review reason</th>",
        "</tr>",
        "</thead>",
        "<tbody>",
    ]
    if not subjects:
        lines.append(
            '<tr><td colspan="7">No analyzed subjects were projected for '
            "review.</td></tr>"
        )
    for subject in subjects:
        if type(subject) is not InvestigationSubjectRow:
            _fail()
        assessment = subject.risk_assessment
        if type(assessment) is not RiskAssessmentProjection:
            _fail()
        lines.extend([
            "<tr>",
            f"<td>{_positive_int(subject.review_order)}</td>",
            f"<td>{_text(subject.subject_ip)}</td>",
            f"<td>{_risk_markup(assessment.risk_level, include_label=False)}</td>",
            (
                "<td>"
                f"{_optional_text(subject.primary_detection_display_name, 'None observed')}"
                "</td>"
            ),
            (
                "<td>"
                f"{_optional_text(subject.notable_correlation_display_name, 'None observed')}"
                "</td>"
            ),
            f"<td>{_risk_markup(assessment.confidence.level, include_label=False)}</td>",
            f"<td>{_text(subject.review_reason)}</td>",
            "</tr>",
        ])
    lines.extend(["</tbody>", "</table>", "</div>", "</section>"])
    return lines


def _coverage_lines(summary, linux_audit):
    lines = ["<section>", "<h2>Report scope and limitations</h2>"]
    absence_rendered = False
    if summary.supported_detection_observation_count == 0:
        lines.append(f"<p>{_NO_DETECTIONS}</p>")
        lines.append(f"<p>{_ABSENCE_LIMITATION}</p>")
        absence_rendered = True
    if summary.supported_correlation_observation_count == 0:
        lines.append(f"<p>{_NO_CORRELATIONS}</p>")
        if not absence_rendered:
            lines.append(f"<p>{_ABSENCE_LIMITATION}</p>")
    if linux_audit is None:
        lines.append(f"<p>{_NO_LINUX_AUDIT}</p>")
    lines.append(
        "<p>Review order supports operator navigation only; it is not a new "
        "risk score, severity, security conclusion, or verdict.</p>"
    )
    lines.append("</section>")
    return lines


def _optional_count(lines, label, value):
    if value is None:
        return
    lines.extend([
        "<div>",
        f"<dt>{label}</dt>",
        f"<dd>{_non_negative_int(value)}</dd>",
        "</div>",
    ])


def _linux_audit_lines(linux_audit):
    if type(linux_audit) is not LinuxAuditAggregateProjection:
        _fail()
    lines = [
        "<section>",
        "<h2>Linux Audit aggregate</h2>",
        "<p>Count-only observations from separately supplied validated summaries.</p>",
        '<dl class="aggregate-grid">',
    ]
    _optional_count(lines, "Process observations", linux_audit.process_observation_count)
    _optional_count(lines, "Process outcome: success", linux_audit.process_outcome_success_count)
    _optional_count(lines, "Process outcome: failure", linux_audit.process_outcome_failure_count)
    _optional_count(lines, "Process outcome: unknown", linux_audit.process_outcome_unknown_count)
    _optional_count(lines, "argv evidence: complete", linux_audit.process_argv_complete_count)
    _optional_count(lines, "argv evidence: incomplete", linux_audit.process_argv_incomplete_count)
    _optional_count(lines, "PATH evidence: complete", linux_audit.process_path_complete_count)
    _optional_count(lines, "PATH evidence: incomplete", linux_audit.process_path_incomplete_count)
    _optional_count(
        lines,
        "Shared-memory review observations",
        linux_audit.shared_memory_review_observation_count,
    )
    _optional_count(
        lines,
        "Session-process co-observations",
        linux_audit.session_process_co_observation_count,
    )
    _optional_count(
        lines,
        "Session-linked process observations",
        linux_audit.session_process_observation_count,
    )
    _optional_count(
        lines,
        "Session process outcome: success",
        linux_audit.session_process_outcome_success_count,
    )
    _optional_count(
        lines,
        "Session process outcome: failure",
        linux_audit.session_process_outcome_failure_count,
    )
    _optional_count(
        lines,
        "Session process outcome: unknown",
        linux_audit.session_process_outcome_unknown_count,
    )
    _optional_count(
        lines,
        "Session-linked shared-memory observations",
        linux_audit.session_shared_memory_observation_count,
    )
    _optional_count(
        lines,
        "Sessions containing shared-memory observations",
        linux_audit.sessions_with_shared_memory_observation_count,
    )
    lines.append("</dl>")
    if linux_audit.process_observation_count == 0:
        lines.append(
            "<p>No Linux Audit process observations were produced from the "
            "supplied aggregate.</p>"
        )
    lines.extend([
        "<p>These are observation counts, not unique processes, incidents, "
        "or proof of attack success.</p>",
        "</section>",
    ])
    return lines


def render_investigation_report_html(projection):
    if type(projection) is not InvestigationReportProjection:
        _fail()
    if type(projection.schema_version) is not str:
        _fail()
    classification = _text(projection.classification)
    summary = projection.summary
    subjects = projection.subjects
    linux_audit = projection.linux_audit
    if type(summary) is not ReportSummaryProjection or type(subjects) is not tuple:
        _fail()
    if linux_audit is not None and type(linux_audit) is not LinuxAuditAggregateProjection:
        _fail()

    lines = [
        "<!doctype html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        '<meta name="referrer" content="no-referrer">',
        (
            '<meta http-equiv="Content-Security-Policy" content="'
            f'{_CONTENT_SECURITY_POLICY}">'
        ),
        "<title>Security Log Investigation Report</title>",
        f"<style>{_STATIC_CSS}</style>",
        "</head>",
        "<body>",
        "<header>",
        "<h1>Security Log Investigation Report</h1>",
        f'<p class="sensitivity">{classification}</p>',
        '<p class="notice">This report presents supported observations from '
        "the analyzed input. Detection is not confirmation of compromise; "
        "correlation is not causation; an HTTP response or successful login "
        "does not establish attack success.</p>",
        "</header>",
        "<main>",
    ]
    lines.extend(_coverage_lines(summary, linux_audit))
    lines.extend(_summary_lines(summary))
    lines.extend(_review_table_lines(subjects))
    lines.extend(["<section>", "<h2>Investigation details</h2>"])
    if not subjects:
        lines.append("<p>No analyzed subjects were projected for detail review.</p>")
    for subject in subjects:
        lines.extend(_subject_lines(subject))
    lines.append("</section>")
    if linux_audit is not None:
        lines.extend(_linux_audit_lines(linux_audit))
    lines.extend([
        "</main>",
        "<footer>",
        "<p>This report is sensitive security investigation data.</p>",
        "<p>Displayed observations are not proof of compromise or attack success.</p>",
        "</footer>",
        "</body>",
        "</html>",
    ])
    return "\n".join(lines) + "\n"
