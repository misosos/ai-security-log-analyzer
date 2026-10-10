from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class _ClosedModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SampleContext(_ClosedModel):
    label: Literal["합성 샘플 결과"]
    environment_notice: Literal["실제 조직 환경의 보안 상태가 아닙니다."]
    certificate_notice: Literal["보안 점검 인증서가 아닙니다."]


class LocalContext(_ClosedModel):
    label: Literal["로컬 실제 로그 분석 결과"]
    environment_notice: Literal["사용자가 제공한 로그를 이 로컬 서버에서 분석한 결과입니다."]
    interpretation_notice: Literal["탐지와 관계는 침해 확정이 아닙니다."]


class AnalysisSummary(_ClosedModel):
    analyzed_subject_count: int
    supported_detection_count: int
    supported_relation_count: int


class CaseSummary(_ClosedModel):
    case_count: int
    independent_observation_count: int
    high_case_count: int
    medium_case_count: int
    low_case_count: int
    relation_case_count: int
    no_time_observation_count: int


class Timestamp(_ClosedModel):
    display_kst: str
    display_utc: str


class Evidence(_ClosedModel):
    label: str
    value: int | float | str
    unit: str | None


class TimelineEntry(_ClosedModel):
    sequence: int
    category: Literal[
        "OBSERVED_FACT", "DETECTION_OBSERVATION", "SUPPORTED_RELATION"
    ]
    category_label: str
    timestamp_state: Literal["TIMESTAMPED", "NO_TIME"]
    timestamp_state_label: str
    start_time: Timestamp | None
    end_time: Timestamp | None
    title: str
    fact: str
    subject: str
    detection_display_name: str | None
    relation_display_name: str | None
    evidence: tuple[Evidence, ...]


class TextItem(_ClosedModel):
    label: str
    text: str


class InvestigationCase(_ClosedModel):
    review_order: int
    case_label: str
    subject: str
    included_highest_risk: Literal["HIGH", "MEDIUM", "LOW"]
    included_highest_confidence: Literal["HIGH", "MEDIUM", "LOW"]
    start_time: Timestamp | None
    end_time: Timestamp | None
    observation_count: int
    supporting_relation_count: int
    grouping_explanation: str
    supported_detections: tuple[str, ...]
    supported_relations: tuple[str, ...]
    timeline_label: Literal["시간순 조사 흐름"]
    timeline: tuple[TimelineEntry, ...]
    limitations: tuple[TextItem, ...]
    unverified_items: tuple[TextItem, ...]
    next_steps: tuple[TextItem, ...]
    account_alias_state: Literal["unavailable"]
    account_alias_message: str


class IndependentObservation(_ClosedModel):
    review_order: int
    label: Literal["독립 관찰"]
    category_label: str
    display_type: str
    subject: str
    existing_risk_level: Literal["HIGH", "MEDIUM", "LOW"]
    existing_confidence: Literal["HIGH", "MEDIUM", "LOW"]
    start_time: Timestamp | None
    end_time: Timestamp | None
    timestamp_state: Literal["TIMESTAMPED", "NO_TIME"]
    evidence: tuple[Evidence, ...]
    reason: str
    limitation: str | None
    next_step: str | None
    account_alias_state: Literal["unavailable"]
    account_alias_message: str


class Capabilities(_ClosedModel):
    html_report_available: Literal[True]
    llm_summary_available: Literal[False]
    linux_audit_aggregate_available: Literal[False]
    actual_log_upload_available: Literal[False]


class LocalCapabilities(_ClosedModel):
    html_report_available: Literal[True]
    llm_summary_available: Literal[False]
    linux_audit_aggregate_available: Literal[False]
    actual_log_upload_available: Literal[True]


class ReportExport(_ClosedModel):
    available: Literal[True]
    format: Literal["standalone_html"]
    filename: Literal["investigation-report.html"]
    media_type: Literal["text/html;charset=utf-8"]
    html: str = Field(min_length=1, max_length=32768, repr=False)
    byte_count: int = Field(gt=0, le=32768)
    format_notice: Literal["현재 형식: 대상별 결정적 조사 보고서. 조사 사례 Timeline은 포함하지 않습니다."]
    handling_warning: Literal["다운로드 파일은 민감한 조사 자료입니다. 저장·공유·삭제에 주의하십시오."]

    @model_validator(mode="after")
    def validate_byte_count(self):
        if len(self.html.encode("utf-8")) != self.byte_count:
            raise ValueError("Report export byte count mismatch.")
        return self


class InvestigationResponse(_ClosedModel):
    schema_version: Literal["1"]
    sample_context: SampleContext
    analysis_summary: AnalysisSummary
    case_summary: CaseSummary
    cases: tuple[InvestigationCase, ...]
    independent_observations: tuple[IndependentObservation, ...]
    interpretation_notices: tuple[str, ...]
    capabilities: Capabilities
    bounded_warnings: tuple[str, ...]
    report_export: ReportExport


class LocalInvestigationResponse(_ClosedModel):
    schema_version: Literal["1"]
    local_context: LocalContext
    analysis_summary: AnalysisSummary
    case_summary: CaseSummary
    cases: tuple[InvestigationCase, ...]
    independent_observations: tuple[IndependentObservation, ...]
    interpretation_notices: tuple[str, ...]
    capabilities: LocalCapabilities
    bounded_warnings: tuple[str, ...]
    report_export: ReportExport


class LocalInvestigationErrorResponse(_ClosedModel):
    error_code: Literal[
        "LOCAL_ONLY", "INVALID_MEDIA_TYPE", "QUERY_NOT_ALLOWED", "MALFORMED_MULTIPART",
        "MISSING_FIELD", "REPEATED_FIELD", "UNKNOWN_FIELD", "FILE_COUNT_EXCEEDED",
        "FILE_TOO_LARGE", "TOTAL_TOO_LARGE", "ENVELOPE_TOO_LARGE",
        "ARCHIVE_UNSUPPORTED", "BINARY_INPUT", "INVALID_UTF8", "EMPTY_INPUT",
        "LINE_TOO_LONG", "LINE_COUNT_EXCEEDED", "PARSER_INCOMPATIBLE",
        "ANALYSIS_TIMEOUT", "UPLOAD_TIMEOUT", "CONCURRENCY_LIMIT", "RATE_LIMITED",
        "ANALYSIS_FAILED", "CASE_PROJECTION_FAILED", "REPORT_GENERATION_FAILED",
        "RESPONSE_INVALID",
    ]
    user_message: str
    recovery_action: str
    retryable: bool
    field: Literal["application_file", "ssh_file", "access_file"] | None


class InvestigationErrorResponse(_ClosedModel):
    error_code: Literal[
        "NON_EMPTY_BODY", "QUERY_NOT_ALLOWED", "RATE_LIMITED",
        "CONCURRENCY_LIMIT", "ANALYSIS_TIMEOUT", "FIXTURE_UNAVAILABLE",
        "ANALYSIS_FAILED", "CASE_PROJECTION_FAILED", "RESPONSE_INVALID",
        "REPORT_GENERATION_FAILED",
    ]
    user_message: str
    recovery_action: str
    retryable: bool
