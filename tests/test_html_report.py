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
    "style-src 'sha256-dugVI89wFmxndpbiVjFenLmRw4HSK3Dw6k21+aq5/dY='; "
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
    generic_limitation = InterpretationLimitationItem(
        "correlation_not_causation",
        "상관관계는 인과관계나 침해의 증거를 의미하지 않습니다.",
    )
    specific_limitation = InterpretationLimitationItem(
        "path_traversal_not_file_disclosure",
        (
            "HTTP 응답과 경로 탐색 패턴만으로 파일 접근 또는 데이터 "
            "노출이 이루어졌다고 판단할 수 없습니다."
        ),
    )
    authentication_step = FixedNextStepItem(
        "review_authentication_failures",
        (
            "관찰된 시간대의 인증 실패 기록을 검토하고, 해당 활동이 "
            "승인된 출발지 또는 프로세스와 일치하는지 확인하십시오."
        ),
    )
    login_step = FixedNextStepItem(
        "review_login_transition",
        (
            "상관된 로그인에 대한 IdP, MFA, 장치 및 세션 기록을 "
            "검토하고, 예상된 로그인인지 확인하십시오."
        ),
    )
    overlapping_login_step = FixedNextStepItem(
        "review_brute_force_login_transition",
        (
            "Brute Force 관찰과 상관된 로그인 전후의 인증, MFA, 장치 "
            "및 세션 기록을 검토하십시오."
        ),
    )
    traversal_step = FixedNextStepItem(
        "review_traversal_response_context",
        (
            "관찰된 요청에 대한 애플리케이션, 리버스 프록시 및 파일 "
            "접근 텔레메트리를 검토하고, 응답 내용이나 파일 접근이 "
            "기록되었는지 확인하십시오."
        ),
    )
    high = subject(
        1,
        "192.0.2.10",
        "HIGH",
        "HIGH",
        detections=(brute, traversal),
        correlations=(correlation, brute_correlation),
        limitations=(generic_limitation, specific_limitation),
        next_steps=(
            overlapping_login_step,
            traversal_step,
            authentication_step,
            login_step,
        ),
    )
    medium = subject(
        2,
        "192.0.2.20",
        "MEDIUM",
        "MEDIUM",
        detections=(spray,),
        limitations=(InterpretationLimitationItem(
            "spraying_like_not_credential_reuse",
            (
                "Password Spraying-like 관찰만으로 동일한 인증정보가 "
                "재사용되었다고 판단할 수 없습니다."
            ),
        ),),
        next_steps=(FixedNextStepItem(
            "review_cross_account_authentication",
            (
                "관련 계정 별칭의 IdP 인증 기록을 검토하고, 예상된 "
                "관리자 또는 자동화 활동인지 확인하십시오."
            ),
        ),),
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

    assert html.startswith("<!doctype html>\n<html lang=\"ko\">\n")
    assert html.endswith("</body>\n</html>\n")
    assert '<meta charset="utf-8">' in html
    assert '<meta name="viewport" content="width=device-width, initial-scale=1">' in html
    assert '<meta name="referrer" content="no-referrer">' in html
    assert "<title>보안 로그 조사 보고서</title>" in html
    assert "보안 로그 조사 보고서" in "".join(parser.text)
    assert "민감 정보 — 보안 조사 자료" in html
    assert "Sensitive — Security Investigation Data" not in html
    for fixed_heading in (
        "보고서 범위와 해석 한계",
        "요약",
        "조사 검토",
        "분석 대상별 조사 세부정보",
        "탐지 근거",
        "상관관계",
        "평가",
        "해석 시 유의사항",
        "다음 조사 단계",
    ):
        assert fixed_heading in html


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
        ("분석 대상 수", 3),
        ("HIGH 위험도", 1),
        ("MEDIUM 위험도", 1),
        ("LOW 위험도", 1),
        ("지원 탐지 관찰 수", 3),
        ("지원 상관관계 관찰 수", 2),
    ):
        assert f"<dt>{label}</dt>\n<dd>{value}</dd>" in html
    headings = (
        "조사 순서",
        "분석 대상 IP",
        "위험도",
        "주요 탐지",
        "주요 상관관계",
        "신뢰도",
    )
    for heading in headings:
        assert f'<th scope="col">{heading}</th>' in html
    table_head = re.search(r"<thead>(.*?)</thead>", html, re.DOTALL).group(1)
    assert table_head.count('<th scope="col">') == 6
    assert "Review reason" not in html
    assert "review reason &amp; verification" not in html
    assert "<caption>정해진 조사 순서의 분석 대상</caption>" in html
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

    assert '<span class="risk risk-high">위험도: HIGH</span>' in html
    assert '<span class="risk risk-medium">위험도: MEDIUM</span>' in html
    assert '<span class="risk risk-low">위험도: LOW</span>' in html
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
        "<dt>실패 횟수</dt>\n<dd>5</dd>",
        "<dt>대상 계정 수</dt>\n<dd>1</dd>",
        "<dt>시간 범위</dt>\n<dd>16.0초</dd>",
        "<dt>실패 횟수</dt>\n<dd>4</dd>",
        "<dt>대상 계정 수</dt>\n<dd>4</dd>",
        "<dt>시간 범위</dt>\n<dd>6초</dd>",
        "<dt>요청 경로</dt>\n<dd><code>/download</code></dd>",
        "<dt>일치 패턴</dt>\n<dd><code>../</code></dd>",
        "<dt>HTTP 메서드</dt>\n<dd>GET</dd>",
        "<dt>응답 상태</dt>\n<dd>200</dd>",
        "<dt>응답 크기</dt>\n<dd>2048바이트</dd>",
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
    assert "<dt>계정 별칭</dt>\n<dd>Account 1</dd>" in html
    assert "<dt>시간 차이</dt>\n<dd>2.5 초</dd>" in html
    assert "failed_to_successful_login" not in html
    assert "brute_force_to_successful_login" not in html
    assert ORIGINAL_ACCOUNT not in html


def test_assessment_limitations_and_next_steps_remain_separate():
    html = render_investigation_report_html(populated_projection())
    high_block = next(
        block
        for block in re.findall(
            r'<details class="subject-card"(?: open)?>.*?</details>',
            html,
            re.DOTALL,
        )
        if "192.0.2.10" in block
    )
    medium_block = next(
        block
        for block in re.findall(
            r'<details class="subject-card"(?: open)?>.*?</details>',
            html,
            re.DOTALL,
        )
        if "192.0.2.20" in block
    )

    assert "<h4>평가</h4>" in html
    assert "<h4>탐지 근거</h4>" in html
    assert "<h4>해석 시 유의사항</h4>" in html
    assert "<h4>다음 조사 단계</h4>" in html
    assert html.count("탐지는 침해 확인을 의미하지 않습니다.") == 1
    assert html.count("상관관계는 인과관계를 의미하지 않습니다.") == 1
    assert html.count("로그인 성공 기록은 공격 성공을 입증하지 않습니다.") == 1
    assert "탐지는 침해 확인을 의미하지 않습니다." not in high_block
    assert "상관관계는 인과관계를 의미하지 않습니다." not in high_block
    assert "로그인 성공 기록은 공격 성공을 입증하지 않습니다." not in high_block
    assert "A correlation is not causation or proof of compromise." not in html
    assert high_block.count(
        "HTTP 응답과 경로 탐색 패턴만으로 파일 접근 또는 데이터 노출이 "
        "이루어졌다고 판단할 수 없습니다."
    ) == 1
    assert medium_block.count(
        "Password Spraying-like 관찰만으로 동일한 인증정보가 "
        "재사용되었다고 판단할 수 없습니다."
    ) == 1
    for rationale in (
        "Likelihood rationale &amp; review",
        "Impact rationale &lt;bounded&gt;",
        "Confidence rationale &gt; observed",
    ):
        assert rationale in html


def test_next_steps_use_explicit_precedence_deduplicate_and_cap_at_three():
    html = render_investigation_report_html(populated_projection())
    high_block = next(
        block
        for block in re.findall(
            r'<details class="subject-card"(?: open)?>.*?</details>',
            html,
            re.DOTALL,
        )
        if "192.0.2.10" in block
    )
    expected_authentication = (
        "관찰된 시간대의 인증 실패 기록을 검토하고, 해당 활동이 승인된 "
        "출발지 또는 프로세스와 일치하는지 확인하십시오."
    )
    expected_login = (
        "상관된 로그인에 대한 IdP, MFA, 장치 및 세션 기록을 검토하고, "
        "예상된 로그인인지 확인하십시오."
    )
    overlapping = (
        "Brute Force 관찰과 상관된 로그인 전후의 인증, MFA, 장치 및 "
        "세션 기록을 검토하십시오."
    )
    expected_traversal = (
        "관찰된 요청에 대한 애플리케이션, 리버스 프록시 및 파일 접근 "
        "텔레메트리를 검토하고, 응답 내용이나 파일 접근이 기록되었는지 "
        "확인하십시오."
    )

    assert expected_authentication in high_block
    assert expected_login in high_block
    assert expected_traversal in high_block
    assert overlapping not in high_block
    next_step_section = re.search(
        r"<h4>다음 조사 단계</h4>\n<ul>(.*?)</ul>",
        high_block,
        re.DOTALL,
    ).group(1)
    assert next_step_section.count("<li>") == 3
    assert high_block.index(expected_authentication) < high_block.index(
        expected_login
    )
    assert high_block.index(expected_login) < high_block.index(
        expected_traversal
    )

    medium_block = next(
        block
        for block in re.findall(
            r'<details class="subject-card"(?: open)?>.*?</details>',
            html,
            re.DOTALL,
        )
        if "192.0.2.20" in block
    )
    assert (
        "관련 계정 별칭의 IdP 인증 기록을 검토하고, 예상된 관리자 또는 "
        "자동화 활동인지 확인하십시오."
    ) in medium_block


def test_next_step_output_is_independent_of_projected_item_order():
    projection = populated_projection()
    high = projection.subjects[1]
    permuted_high = replace(high, next_steps=tuple(reversed(high.next_steps)))
    permuted = replace(
        projection,
        subjects=(projection.subjects[0], permuted_high, projection.subjects[2]),
    )

    assert render_investigation_report_html(permuted) == (
        render_investigation_report_html(projection)
    )


def test_approved_korean_guidance_replaces_exact_legacy_english_sentences():
    projection = populated_projection()
    html = render_investigation_report_html(projection)
    legacy_english = (
        "Review authentication failure records for the observed time window "
        "and verify whether the activity matches an approved source or process.",
        "Review identity-provider, MFA, device, and session records for the "
        "correlated login and verify whether the login was expected.",
        "Review identity-provider authentication records for the affected "
        "account aliases and verify expected administrative or automated activity.",
        "Review application, reverse-proxy, and file-access telemetry for the "
        "observed request and verify what response content or file access, if "
        "any, was recorded.",
        "Review authentication, MFA, device, and session records around the "
        "Brute Force observation and correlated login.",
        "A Password Spraying-like observation does not establish reuse of the "
        "same credential.",
        "An HTTP response and traversal pattern do not establish file access "
        "or data disclosure.",
    )

    for sentence in legacy_english:
        assert sentence not in html
    for retained_term in (
        "Brute Force",
        "Password Spraying-like",
        "Path Traversal",
        "HIGH",
        "MEDIUM",
        "LOW",
        "IdP",
        "MFA",
    ):
        assert retained_term in html
    for internal_id in (
        "review_authentication_failures",
        "review_cross_account_authentication",
        "review_traversal_response_context",
        "review_login_transition",
        "review_brute_force_login_transition",
        "spraying_like_not_credential_reuse",
        "path_traversal_not_file_disclosure",
    ):
        assert internal_id not in html

    high = projection.subjects[1]
    composite_only = replace(
        high,
        next_steps=(high.next_steps[0],),
    )
    composite_projection = replace(
        projection,
        subjects=(
            projection.subjects[0],
            composite_only,
            projection.subjects[2],
        ),
    )
    composite_html = render_investigation_report_html(composite_projection)
    assert (
        "Brute Force 관찰과 상관된 로그인 전후의 인증, MFA, 장치 및 "
        "세션 기록을 검토하십시오."
    ) in composite_html


def test_empty_states_are_bounded_and_linux_audit_absence_is_explicit():
    html = render_investigation_report_html(empty_projection())

    assert "지원되는 탐지 관찰 없음" in html
    assert "지원되는 상관관계 없음" in html
    assert html.count("이는 악의적 활동의 부재를 입증하지 않습니다.") == 1
    assert "이 보고서에는 Linux Audit 집계가 제공되지 않았습니다." in html
    assert "<h2>Linux Audit 집계</h2>" not in html
    for prohibited_claim in (
        "안전",
        "정상",
        "공격 없음",
        "침해 없음",
        "깨끗함",
    ):
        assert prohibited_claim not in html


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

    assert "지원되지 않는 탐지 유형은 이 보고서에서 제외되었습니다." in html
    assert "지원되지 않는 상관관계 유형은 이 보고서에서 제외되었습니다." in html


def test_html_escapes_all_projected_text_and_keeps_it_out_of_attributes():
    adversarial = "TEXT-CANARY & <tag> > \"double\" 'single'"
    projection = populated_projection()
    high = projection.subjects[1]
    path = high.detections[1]
    hostile_path = replace(
        path,
        evidence=replace(path.evidence, request_path=adversarial),
    )
    hostile_limitation = InterpretationLimitationItem(
        "path_traversal_not_file_disclosure",
        adversarial,
    )
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

    assert "<h2>Linux Audit 집계</h2>" in html
    assert "<dt>프로세스 관찰 수</dt>\n<dd>0</dd>" in html
    assert "<dt>공유 메모리 검토 관찰 수</dt>\n<dd>0</dd>" in html
    assert "<dt>세션-프로세스 공동 관찰 수</dt>\n<dd>0</dd>" in html
    assert (
        "제공된 집계에서 Linux Audit 프로세스 관찰이 생성되지 않았습니다."
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
