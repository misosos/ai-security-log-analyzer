from typing import Literal

from pydantic import BaseModel, ConfigDict


class _ClosedModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SampleContext(_ClosedModel):
    label: Literal["합성 샘플 결과"]
    environment_notice: Literal["실제 조직 환경의 보안 상태가 아닙니다."]
    certificate_notice: Literal["보안 점검 인증서가 아닙니다."]


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
    value: int | float
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
    account_alias_state: Literal["unavailable"]
    account_alias_message: str


class Capabilities(_ClosedModel):
    html_report_available: Literal[False]
    llm_summary_available: Literal[False]
    linux_audit_aggregate_available: Literal[False]
    actual_log_upload_available: Literal[False]


class ReportExport(_ClosedModel):
    available: Literal[False]
    message: Literal["HTML 보고서 다운로드는 이 단계에서 제공되지 않습니다."]


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


class InvestigationErrorResponse(_ClosedModel):
    error_code: Literal[
        "NON_EMPTY_BODY", "QUERY_NOT_ALLOWED", "RATE_LIMITED",
        "CONCURRENCY_LIMIT", "ANALYSIS_TIMEOUT", "FIXTURE_UNAVAILABLE",
        "ANALYSIS_FAILED", "CASE_PROJECTION_FAILED", "RESPONSE_INVALID",
    ]
    user_message: str
    recovery_action: str
    retryable: bool
