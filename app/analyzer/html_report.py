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
th:nth-child(1), td:nth-child(1) { min-width: 5.5rem; }
th:nth-child(2), td:nth-child(2) { min-width: 9rem; }
th:nth-child(4), td:nth-child(4), th:nth-child(5), td:nth-child(5) { min-width: 11rem; }
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
  th, td { padding: .5rem; }
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

_NO_DETECTIONS = "지원되는 탐지 관찰 없음"
_NO_CORRELATIONS = "지원되는 상관관계 없음"
_ABSENCE_LIMITATION = "이는 악의적 활동의 부재를 입증하지 않습니다."
_NO_LINUX_AUDIT = "이 보고서에는 Linux Audit 집계가 제공되지 않았습니다."

_REPORT_LEVEL_LIMITATION_IDS = frozenset({
    "detection_not_compromise",
    "correlation_not_causation",
    "successful_login_not_account_compromise",
})
_SUBJECT_LIMITATION_IDS = frozenset({
    "spraying_like_not_credential_reuse",
    "path_traversal_not_file_disclosure",
})
_NEXT_STEP_PURPOSES = (
    ("authentication_failure", ("review_authentication_failures",)),
    (
        "cross_account_authentication",
        ("review_cross_account_authentication",),
    ),
    (
        "correlated_login",
        (
            "review_login_transition",
            "review_brute_force_login_transition",
        ),
    ),
    ("traversal_response", ("review_traversal_response_context",)),
)
_NEXT_STEP_IDS = frozenset(
    next_step_id
    for _, choices in _NEXT_STEP_PURPOSES
    for next_step_id in choices
)


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


def _classification_text(value):
    if value == "Sensitive — Security Investigation Data":
        return "민감 정보 — 보안 조사 자료"
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
    label = f"위험도: {level}" if include_label else level
    return f'<span class="{css_class}">{label}</span>'


def _dimension_lines(title, dimension):
    if type(dimension) is not AssessmentDimensionProjection:
        _fail()
    level = _risk_markup(dimension.level, include_label=False)
    if type(dimension.rationale) is not tuple:
        _fail()
    lines = [
        f"<h5>{title} 판단 근거</h5>",
        "<ul>",
    ]
    for rationale in dimension.rationale:
        lines.append(f"<li>{_text(rationale)}</li>")
    lines.append("</ul>")
    return level, lines


def _evidence_lines(evidence):
    if type(evidence) is BruteForceEvidenceProjection:
        return (
            ("실패 횟수", _non_negative_int(evidence.failed_attempt_count)),
            ("대상 계정 수", _non_negative_int(evidence.target_account_count)),
            (
                "시간 범위",
                f"{_non_negative_number(evidence.time_window_seconds)}초",
            ),
        )
    if type(evidence) is PasswordSprayingLikeEvidenceProjection:
        return (
            ("실패 횟수", _non_negative_int(evidence.failed_attempt_count)),
            ("대상 계정 수", _non_negative_int(evidence.target_account_count)),
            (
                "시간 범위",
                f"{_non_negative_number(evidence.time_window_seconds)}초",
            ),
        )
    if type(evidence) is PathTraversalEvidenceProjection:
        lines = [
            ("요청 경로", f"<code>{_text(evidence.request_path)}</code>"),
            ("일치 패턴", f"<code>{_text(evidence.matched_pattern)}</code>"),
        ]
        if evidence.http_method is not None:
            lines.append(("HTTP 메서드", _text(evidence.http_method)))
        if evidence.response_status is not None:
            lines.append((
                "응답 상태",
                _non_negative_int(evidence.response_status),
            ))
        if evidence.response_size_bytes is not None:
            lines.append((
                "응답 크기",
                f"{_non_negative_int(evidence.response_size_bytes)}바이트",
            ))
        return tuple(lines)
    _fail()


def _detection_lines(detections, unsupported):
    if type(detections) is not tuple or type(unsupported) is not bool:
        _fail()
    lines = ["<section>", "<h4>탐지 근거</h4>"]
    if not detections:
        lines.append(f"<p>{_NO_DETECTIONS}</p>")
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
            "<p>지원되지 않는 탐지 유형은 이 보고서에서 제외되었습니다.</p>"
        )
    lines.append("</section>")
    return lines


def _correlation_lines(correlations, unsupported):
    if type(correlations) is not tuple or type(unsupported) is not bool:
        _fail()
    lines = ["<section>", "<h4>상관관계</h4>"]
    if not correlations:
        lines.append(f"<p>{_NO_CORRELATIONS}</p>")
    for correlation in correlations:
        if type(correlation) is not CorrelationDisplayItem:
            _fail()
        lines.extend([
            '<article class="observation">',
            f"<h5>{_text(correlation.display_name)}</h5>",
            '<dl class="evidence-list">',
            "<div>",
            "<dt>계정 별칭</dt>",
            f"<dd>{_text(correlation.account_alias)}</dd>",
            "</div>",
            "<div>",
            "<dt>시간 차이</dt>",
            (
                "<dd>"
                f"{_non_negative_number(correlation.time_delta_seconds)} "
                "초</dd>"
            ),
            "</div>",
            "</dl>",
            "</article>",
        ])
    if unsupported:
        lines.append(
            "<p>지원되지 않는 상관관계 유형은 이 보고서에서 제외되었습니다.</p>"
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


def _subject_limitation_lines(items):
    if type(items) is not tuple:
        _fail()
    specific = []
    for item in items:
        if type(item) is not InterpretationLimitationItem:
            _fail()
        if type(item.limitation_id) is not str:
            _fail()
        if item.limitation_id in _REPORT_LEVEL_LIMITATION_IDS:
            continue
        if item.limitation_id not in _SUBJECT_LIMITATION_IDS:
            _fail()
        specific.append(item)
    return _fixed_item_lines(
        "해석 시 유의사항",
        tuple(specific),
        InterpretationLimitationItem,
        "추가로 표시할 유형별 해석 유의사항이 없습니다.",
    )


def _next_step_lines(items):
    if type(items) is not tuple:
        _fail()
    by_id = {}
    for item in items:
        if type(item) is not FixedNextStepItem:
            _fail()
        if (
            type(item.next_step_id) is not str
            or item.next_step_id not in _NEXT_STEP_IDS
            or item.next_step_id in by_id
        ):
            _fail()
        by_id[item.next_step_id] = item

    selected = []
    for _, choices in _NEXT_STEP_PURPOSES:
        for next_step_id in choices:
            if next_step_id in by_id:
                selected.append(by_id[next_step_id])
                break
    return _fixed_item_lines(
        "다음 조사 단계",
        tuple(selected[:3]),
        FixedNextStepItem,
        "표시할 고정 조사 단계가 없습니다.",
    )


def _assessment_lines(assessment):
    if type(assessment) is not RiskAssessmentProjection:
        _fail()
    likelihood, likelihood_lines = _dimension_lines(
        "가능성", assessment.likelihood
    )
    impact, impact_lines = _dimension_lines("영향도", assessment.impact)
    confidence, confidence_lines = _dimension_lines(
        "신뢰도", assessment.confidence
    )
    lines = [
        "<section>",
        "<h4>평가</h4>",
        '<dl class="assessment-grid">',
        "<div><dt>위험도</dt><dd>"
        f"{_risk_markup(assessment.risk_level, include_label=False)}"
        "</dd></div>",
        f"<div><dt>가능성</dt><dd>{likelihood}</dd></div>",
        f"<div><dt>영향도</dt><dd>{impact}</dd></div>",
        f"<div><dt>신뢰도</dt><dd>{confidence}</dd></div>",
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
        f"<span>조사 순서 {review_order} — 분석 대상 IP {subject_ip}</span>",
        _risk_markup(assessment.risk_level),
        "</summary>",
        '<div class="subject-content">',
        f"<h3>분석 대상 IP {subject_ip}</h3>",
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
    lines.extend(_subject_limitation_lines(subject.limitations))
    lines.extend(_next_step_lines(subject.next_steps))
    lines.extend(["</div>", "</details>"])
    return lines


def _summary_lines(summary):
    if type(summary) is not ReportSummaryProjection:
        _fail()
    cards = [
        ("분석 대상 수", summary.analyzed_subject_count),
        ("HIGH 위험도", summary.high_risk_subject_count),
        ("MEDIUM 위험도", summary.medium_risk_subject_count),
        ("LOW 위험도", summary.low_risk_subject_count),
        ("지원 탐지 관찰 수", summary.supported_detection_observation_count),
        (
            "지원 상관관계 관찰 수",
            summary.supported_correlation_observation_count,
        ),
    ]
    optional_cards = (
        (
            "Linux Audit 프로세스 관찰 수",
            summary.linux_audit_process_observation_count,
        ),
        (
            "공유 메모리 검토 관찰 수",
            summary.shared_memory_review_observation_count,
        ),
        (
            "세션-프로세스 공동 관찰 수",
            summary.session_process_co_observation_count,
        ),
    )
    cards.extend(
        (label, value)
        for label, value in optional_cards
        if value is not None
    )
    lines = ["<section>", "<h2>요약</h2>", '<dl class="summary-grid">']
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
        "<h2>조사 검토</h2>",
        '<div class="table-wrap">',
        "<table>",
        "<caption>정해진 조사 순서의 분석 대상</caption>",
        "<thead>",
        "<tr>",
        "<th scope=\"col\">조사 순서</th>",
        "<th scope=\"col\">분석 대상 IP</th>",
        "<th scope=\"col\">위험도</th>",
        "<th scope=\"col\">주요 탐지</th>",
        "<th scope=\"col\">주요 상관관계</th>",
        "<th scope=\"col\">신뢰도</th>",
        "</tr>",
        "</thead>",
        "<tbody>",
    ]
    if not subjects:
        lines.append(
            '<tr><td colspan="6">조사 검토 대상으로 투영된 분석 대상이 '
            "없습니다.</td></tr>"
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
                f"{_optional_text(subject.primary_detection_display_name, '관찰 없음')}"
                "</td>"
            ),
            (
                "<td>"
                f"{_optional_text(subject.notable_correlation_display_name, '관찰 없음')}"
                "</td>"
            ),
            f"<td>{_risk_markup(assessment.confidence.level, include_label=False)}</td>",
            "</tr>",
        ])
    lines.extend(["</tbody>", "</table>", "</div>", "</section>"])
    return lines


def _coverage_lines(summary, linux_audit):
    lines = ["<section>", "<h2>보고서 범위와 해석 한계</h2>"]
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
    lines.extend([
        "<p>탐지는 침해 확인을 의미하지 않습니다.</p>",
        "<p>상관관계는 인과관계를 의미하지 않습니다.</p>",
        "<p>로그인 성공 기록은 공격 성공을 입증하지 않습니다.</p>",
        "<p>조사 순서는 운영자의 검토 탐색을 돕기 위한 값이며 새로운 "
        "위험 점수, 심각도, 보안 결론 또는 판정이 아닙니다.</p>",
    ])
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
        "<h2>Linux Audit 집계</h2>",
        "<p>별도로 제공되고 검증된 요약의 관찰 수만 표시합니다.</p>",
        '<dl class="aggregate-grid">',
    ]
    _optional_count(lines, "프로세스 관찰 수", linux_audit.process_observation_count)
    _optional_count(lines, "프로세스 결과: 성공", linux_audit.process_outcome_success_count)
    _optional_count(lines, "프로세스 결과: 실패", linux_audit.process_outcome_failure_count)
    _optional_count(lines, "프로세스 결과: 알 수 없음", linux_audit.process_outcome_unknown_count)
    _optional_count(lines, "argv 근거: 완전", linux_audit.process_argv_complete_count)
    _optional_count(lines, "argv 근거: 불완전", linux_audit.process_argv_incomplete_count)
    _optional_count(lines, "PATH 근거: 완전", linux_audit.process_path_complete_count)
    _optional_count(lines, "PATH 근거: 불완전", linux_audit.process_path_incomplete_count)
    _optional_count(
        lines,
        "공유 메모리 검토 관찰 수",
        linux_audit.shared_memory_review_observation_count,
    )
    _optional_count(
        lines,
        "세션-프로세스 공동 관찰 수",
        linux_audit.session_process_co_observation_count,
    )
    _optional_count(
        lines,
        "세션 연결 프로세스 관찰 수",
        linux_audit.session_process_observation_count,
    )
    _optional_count(
        lines,
        "세션 프로세스 결과: 성공",
        linux_audit.session_process_outcome_success_count,
    )
    _optional_count(
        lines,
        "세션 프로세스 결과: 실패",
        linux_audit.session_process_outcome_failure_count,
    )
    _optional_count(
        lines,
        "세션 프로세스 결과: 알 수 없음",
        linux_audit.session_process_outcome_unknown_count,
    )
    _optional_count(
        lines,
        "세션 연결 공유 메모리 관찰 수",
        linux_audit.session_shared_memory_observation_count,
    )
    _optional_count(
        lines,
        "공유 메모리 관찰 포함 세션 수",
        linux_audit.sessions_with_shared_memory_observation_count,
    )
    lines.append("</dl>")
    if linux_audit.process_observation_count == 0:
        lines.append(
            "<p>제공된 집계에서 Linux Audit 프로세스 관찰이 생성되지 "
            "않았습니다.</p>"
        )
    lines.extend([
        "<p>이 값은 관찰 수이며 고유 프로세스 수나 incident 수가 아니고, "
        "공격 성공의 증거도 아닙니다.</p>",
        "</section>",
    ])
    return lines


def render_investigation_report_html(projection):
    if type(projection) is not InvestigationReportProjection:
        _fail()
    if type(projection.schema_version) is not str:
        _fail()
    classification = _classification_text(projection.classification)
    summary = projection.summary
    subjects = projection.subjects
    linux_audit = projection.linux_audit
    if type(summary) is not ReportSummaryProjection or type(subjects) is not tuple:
        _fail()
    if linux_audit is not None and type(linux_audit) is not LinuxAuditAggregateProjection:
        _fail()

    lines = [
        "<!doctype html>",
        '<html lang="ko">',
        "<head>",
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        '<meta name="referrer" content="no-referrer">',
        (
            '<meta http-equiv="Content-Security-Policy" content="'
            f'{_CONTENT_SECURITY_POLICY}">'
        ),
        "<title>보안 로그 조사 보고서</title>",
        f"<style>{_STATIC_CSS}</style>",
        "</head>",
        "<body>",
        "<header>",
        "<h1>보안 로그 조사 보고서</h1>",
        f'<p class="sensitivity">{classification}</p>',
        '<p class="notice">이 보고서는 분석 입력에서 지원되는 관찰만 '
        "표시합니다. 원본 로그와 관련 시스템 기록을 함께 검토하십시오.</p>",
        "</header>",
        "<main>",
    ]
    lines.extend(_coverage_lines(summary, linux_audit))
    lines.extend(_summary_lines(summary))
    lines.extend(_review_table_lines(subjects))
    lines.extend(["<section>", "<h2>분석 대상별 조사 세부정보</h2>"])
    if not subjects:
        lines.append("<p>세부 검토 대상으로 투영된 분석 대상이 없습니다.</p>")
    for subject in subjects:
        lines.extend(_subject_lines(subject))
    lines.append("</section>")
    if linux_audit is not None:
        lines.extend(_linux_audit_lines(linux_audit))
    lines.extend([
        "</main>",
        "<footer>",
        "<p>이 보고서는 민감한 보안 조사 자료입니다.</p>",
        "</footer>",
        "</body>",
        "</html>",
    ])
    return "\n".join(lines) + "\n"
