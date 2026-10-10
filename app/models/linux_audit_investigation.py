"""Closed public contract for local Linux Audit review candidates."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.analyzer.process_execution_classification import (
    CATEGORY_IDS, DISPLAY_NAMES, PRIORITIES, LIMITATIONS, NEXT_STEPS,
    IDENTITY_WARNING,
)


Count = Field(strict=True, ge=0, le=2**63 - 1)
INTERPRETATION_NOTICES = (
    "이 결과는 Linux Audit 로그에서 검토할 프로세스 실행 관찰을 분류한 것입니다.",
    "악성 행위나 침해 성공을 확정하지 않으며, 실행 목적과 승인 여부는 별도로 확인해야 합니다.",
    "성공은 실행 syscall의 기록된 결과를 뜻합니다. 파일 전송, 권한 변경 또는 공격 목적이 성공했다는 의미가 아닙니다.",
    "인증·웹 조사 사례와 자동으로 결합하지 않습니다.",
)


class _Closed(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LinuxAuditSourceContext(_Closed):
    kind: Literal["LOCAL_PRIVATE_UPLOAD"]
    label: Literal["로컬 Linux Audit 분석 결과"]
    storage_notice: Literal["로그와 결과를 서버에 영구 저장하지 않습니다. 비정상 종료 후 임시 파일이 남을 수 있습니다."]


class LinuxAuditOutcomeCounts(_Closed):
    success: int = Count
    failure: int = Count
    unknown: int = Count


class LinuxAuditCategoryObservation(_Closed):
    category_id: Literal[
        "LINUX_SHELL_INTERPRETER_EXECUTION",
        "LINUX_NETWORK_TRANSFER_UTILITY_EXECUTION",
        "LINUX_PERMISSION_CHANGE_UTILITY_EXECUTION",
        "LINUX_TEMP_DIRECTORY_EXECUTION",
    ]
    display_name: str
    observation_count: int = Count
    review_priority: Literal["LOW", "MEDIUM"]
    confidence: Literal["HIGH", "MEDIUM", "LOW"] | None
    outcome_counts: LinuxAuditOutcomeCounts
    limitation: str
    next_step: str

    @model_validator(mode="after")
    def fixed_category(self):
        index = CATEGORY_IDS.index(self.category_id)
        if (self.display_name != DISPLAY_NAMES[index]
                or self.review_priority != PRIORITIES[index]
                or self.limitation != LIMITATIONS[index]
                or self.next_step != NEXT_STEPS[index]
                or (self.confidence is None) != (self.observation_count == 0)
                or self.outcome_counts.success + self.outcome_counts.failure
                   + self.outcome_counts.unknown != self.observation_count):
            raise ValueError("invalid_linux_category")
        return self


class LinuxAuditSummary(_Closed):
    eligible_execution_count: int = Count
    classified_execution_count: int = Count
    unclassified_execution_count: int = Count
    category_observation_count: int = Count
    outcome_counts: LinuxAuditOutcomeCounts
    low_priority_observation_count: int = Count
    medium_priority_observation_count: int = Count
    incomplete_context_count: int = Count


class LinuxAuditCapabilities(_Closed):
    html_report_available: Literal[False]
    llm_summary_available: Literal[False]
    auth_web_case_linking_available: Literal[False]


class LinuxAuditInvestigationResponse(_Closed):
    schema_version: Literal["1"]
    source_context: LinuxAuditSourceContext
    summary: LinuxAuditSummary
    observations: tuple[LinuxAuditCategoryObservation, ...]
    interpretation_notices: tuple[str, ...]
    bounded_warnings: tuple[str, ...]
    capabilities: LinuxAuditCapabilities

    @model_validator(mode="after")
    def consistent_counts(self):
        summary = self.summary
        if (tuple(item.category_id for item in self.observations) != CATEGORY_IDS
                or summary.eligible_execution_count != summary.classified_execution_count
                   + summary.unclassified_execution_count
                or summary.eligible_execution_count != summary.outcome_counts.success
                   + summary.outcome_counts.failure + summary.outcome_counts.unknown
                or summary.category_observation_count != sum(item.observation_count for item in self.observations)
                or summary.category_observation_count < summary.classified_execution_count
                or summary.category_observation_count != summary.low_priority_observation_count
                   + summary.medium_priority_observation_count
                or summary.low_priority_observation_count != sum(
                    item.observation_count for item in self.observations if item.review_priority == "LOW")
                or summary.medium_priority_observation_count != sum(
                    item.observation_count for item in self.observations if item.review_priority == "MEDIUM")
                or summary.incomplete_context_count > summary.eligible_execution_count
                or self.interpretation_notices != INTERPRETATION_NOTICES
                or self.bounded_warnings not in ((), (IDENTITY_WARNING,))):
            raise ValueError("invalid_linux_summary")
        return self


class LinuxAuditInvestigationError(_Closed):
    error_code: str
    user_message: str
    recovery_action: str
    retryable: bool
    field: Literal["audit_file"] | None
