"""Private Audit execution input to bounded, CLI-only review candidates."""

from dataclasses import dataclass
from datetime import datetime, timezone
import re
from typing import Literal

from app.models.schemas import LinuxAuditContext, NormalizedEvent, ProcessExecutionContext


CATEGORY_IDS = (
    "LINUX_SHELL_INTERPRETER_EXECUTION",
    "LINUX_NETWORK_TRANSFER_UTILITY_EXECUTION",
    "LINUX_PERMISSION_CHANGE_UTILITY_EXECUTION",
    "LINUX_TEMP_DIRECTORY_EXECUTION",
)
DISPLAY_NAMES = (
    "셸 인터프리터 실행 관찰",
    "네트워크 전송 도구 실행 관찰",
    "권한·소유권 변경 도구 실행 관찰",
    "임시 디렉터리 실행 관찰",
)
PRIORITIES = ("LOW", "LOW", "LOW", "MEDIUM")
LIMITATIONS = (
    "셸 실행만으로 명령 내용, 사용자 의도 또는 악성 여부를 판단할 수 없습니다.",
    "전송 도구 실행만으로 파일이 다운로드·업로드되었거나 외부 통신이 성공했다고 판단할 수 없습니다.",
    "도구 실행만으로 대상 파일의 권한·소유권이 실제로 변경되었거나 권한 상승이 발생했다고 판단할 수 없습니다.",
    "임시 디렉터리의 실행 관찰만으로 파일의 출처, 내용, 악성 여부 또는 실행 목적을 판단할 수 없습니다.",
)
NEXT_STEPS = (
    "승인된 관리·자동화 작업인지 확인하고 필요한 경우 부모 프로세스와 실행 맥락을 검토하십시오.",
    "승인된 관리·자동화 작업인지 확인하고, 필요한 경우 네트워크·프록시·파일 생성 기록을 함께 검토하십시오.",
    "승인된 배포·관리 작업인지 확인하고, 필요한 경우 파일 metadata와 변경 감사 기록을 검토하십시오.",
    "파일 생성·해시·서명·소유자·부모 프로세스·네트워크 기록과 승인된 작업 여부를 확인하십시오.",
)
_SHELLS = frozenset(("sh", "bash", "dash", "zsh", "ksh"))
_TRANSFER = frozenset(("curl", "wget"))
_PERMISSION = frozenset(("chmod", "chown"))
_TEMP_ROOTS = ("/tmp", "/var/tmp", "/dev/shm")
_EVENT_ID = re.compile(r"\d+\.\d+:\d+\Z", re.ASCII)
_MAX_EVENTS = 4096
NOTICES = (
    "Linux Audit에서 관찰된 프로세스 실행 조사 후보이며 악성·침해·공격 성공을 확정하지 않습니다.",
    "success는 실행 syscall의 결과이며 도구의 후속 작업 성공을 의미하지 않습니다.",
    "검토 우선순위는 고정 조사 순서이며 위험 점수나 침해 확률이 아닙니다.",
)
IDENTITY_WARNING = "실행 파일 식별 정보가 불명확하거나 일치하지 않아 일부 관찰을 분류하지 않았습니다."
COMM_LIMITATION = "comm은 길이가 잘릴 수 있어 실행 파일 전체 식별을 보장하지 않습니다."
ARGV_LIMITATION = "argv[0]은 호출자가 지정할 수 있어 실제 실행 파일 식별을 보장하지 않습니다."


class ProcessExecutionClassificationError(ValueError):
    """Fixed code only; no Audit field or underlying exception is retained."""

    def __init__(self, code: str):
        if code not in {"invalid_input", "invalid_event", "invalid_timestamp", "invalid_outcome", "conflicting_event_identity"}:
            code = "invalid_input"
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class OutcomeCounts:
    success: int
    failure: int
    unknown: int


@dataclass(frozen=True)
class ProcessExecutionCategorySummary:
    category_id: str
    display_name: str
    review_priority: Literal["LOW", "MEDIUM"]
    observation_count: int
    outcome_counts: OutcomeCounts


@dataclass(frozen=True)
class ProcessExecutionSummary:
    eligible_execution_count: int
    classified_execution_count: int
    category_observation_count: int
    outcome_counts: OutcomeCounts
    categories: tuple[ProcessExecutionCategorySummary, ...]


@dataclass(frozen=True)
class ProcessExecutionEvidenceCounts:
    execution_count: int
    argv_complete_count: int
    path_complete_count: int


@dataclass(frozen=True)
class ProcessExecutionObservation:
    observation_id: str
    category_id: str
    display_name: str
    observed_at_utc: datetime
    outcome: Literal["SUCCESS", "FAILURE", "UNKNOWN"]
    review_priority: Literal["LOW", "MEDIUM"]
    confidence: Literal["HIGH", "MEDIUM", "LOW"]
    evidence_counts: ProcessExecutionEvidenceCounts
    limitations: tuple[str, ...]
    next_steps: tuple[str, ...]


@dataclass(frozen=True)
class ProcessExecutionObservationAssembly:
    summary: ProcessExecutionSummary
    observations: tuple[ProcessExecutionObservation, ...]
    unclassified_count: int
    incomplete_context_count: int
    interpretation_notices: tuple[str, ...]
    bounded_warnings: tuple[str, ...]


def _absolute_path(value: str) -> bool:
    return (
        type(value) is str
        and 0 < len(value) <= 4096
        and value.startswith("/")
        and not any(ord(char) < 32 or ord(char) == 127 for char in value)
        and all(part not in {"", ".", ".."} for part in value.split("/")[1:])
    )


def _basename(value: str) -> str | None:
    if type(value) is not str or not value or len(value) > 4096:
        return None
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        return None
    if "/" in value:
        if not _absolute_path(value):
            return None
        return value.rsplit("/", 1)[-1]
    return value if value not in {".", ".."} else None


def _identity(context: ProcessExecutionContext) -> tuple[str | None, str | None, bool]:
    """Return approved basename, full exe location (if trusted), and fallback flag."""
    exe = context.executable
    comm = context.command_name
    argv0 = context.argv[0] if context.argv else None
    if exe is not None and not _absolute_path(exe):
        return None, None, False
    names = tuple(_basename(value) for value in (exe, comm, argv0) if value is not None)
    if not names or any(name is None for name in names) or len(set(names)) != 1:
        return None, None, False
    return names[0], exe, exe is None


def _categories(basename: str, executable: str | None) -> tuple[int, ...]:
    categories = []
    if basename in _SHELLS:
        categories.append(0)
    if basename in _TRANSFER:
        categories.append(1)
    if basename in _PERMISSION:
        categories.append(2)
    if executable is not None and any(
        executable == root or executable.startswith(root + "/") for root in _TEMP_ROOTS
    ):
        categories.append(3)
    return tuple(categories)


def _outcomes(values: tuple[str, ...]) -> OutcomeCounts:
    return OutcomeCounts(values.count("success"), values.count("failure"), values.count("unknown"))


def classify_process_execution_observations(
    events: tuple[NormalizedEvent, ...],
) -> ProcessExecutionObservationAssembly:
    if type(events) is not tuple or len(events) > _MAX_EVENTS:
        raise ProcessExecutionClassificationError("invalid_input")
    unique: dict[tuple[str | None, str | None, str], NormalizedEvent] = {}
    for event in events:
        if (
            type(event) is not NormalizedEvent
            or event.event_type != "process_execution_attempt"
            or event.source != "linux_audit"
            or type(event.process_execution) is not ProcessExecutionContext
            or type(event.linux_audit) is not LinuxAuditContext
        ):
            raise ProcessExecutionClassificationError("invalid_event")
        if type(event.timestamp) is not datetime or event.timestamp.tzinfo is not timezone.utc:
            raise ProcessExecutionClassificationError("invalid_timestamp")
        context = event.process_execution
        if context.outcome not in ("success", "failure", "unknown"):
            raise ProcessExecutionClassificationError("invalid_outcome")
        if type(context.argv_complete) is not bool or type(context.paths_complete) is not bool or type(context.argv) is not tuple:
            raise ProcessExecutionClassificationError("invalid_event")
        audit = event.linux_audit
        if (type(audit.event_id) is not str or len(audit.event_id) > 64
                or _EVENT_ID.fullmatch(audit.event_id) is None
                or any(value is not None and (type(value) is not str or len(value) > 256)
                       for value in (audit.source_instance, audit.node))):
            raise ProcessExecutionClassificationError("invalid_event")
        key = (audit.source_instance, audit.node, audit.event_id)
        previous = unique.get(key)
        if previous is not None:
            if previous.timestamp != event.timestamp or previous.process_execution != context:
                raise ProcessExecutionClassificationError("conflicting_event_identity")
            continue
        unique[key] = event

    ordered = sorted(unique.items(), key=lambda pair: (pair[1].timestamp, tuple(value or "" for value in pair[0])))
    rows = []
    unclassified = 0
    incomplete = 0
    outcome_values = []
    identity_warning = False
    for key, event in ordered:
        context = event.process_execution
        outcome_values.append(context.outcome)
        if not context.argv_complete or not context.paths_complete:
            incomplete += 1
        basename, executable, fallback = _identity(context)
        if basename is None:
            unclassified += 1
            identity_warning = True
            continue
        categories = _categories(basename, executable)
        if not categories:
            unclassified += 1
            continue
        confidence = (
            "LOW" if fallback and context.command_name is None
            else "MEDIUM" if fallback or not context.argv_complete or not context.paths_complete
            else "HIGH"
        )
        identity_limitation = (
            ARGV_LIMITATION if fallback and context.command_name is None
            else COMM_LIMITATION if fallback else None
        )
        for category in categories:
            rows.append((event.timestamp, category, context.outcome, confidence,
                         context.argv_complete, context.paths_complete,
                         identity_limitation, key))

    # Sort on approved public facts first; the private event key only breaks indistinguishable ties.
    rows.sort(key=lambda row: (row[0], row[1], row[2], row[3], row[4], row[5], row[6] or "",
                               tuple(value or "" for value in row[7])))
    observations = tuple(ProcessExecutionObservation(
        observation_id=f"linux-process-observation-{index}",
        category_id=CATEGORY_IDS[category],
        display_name=DISPLAY_NAMES[category],
        observed_at_utc=timestamp,
        outcome=outcome.upper(),
        review_priority=PRIORITIES[category],
        confidence=confidence,
        evidence_counts=ProcessExecutionEvidenceCounts(1, int(argv_complete), int(paths_complete)),
        limitations=(LIMITATIONS[category],) + ((identity_limitation,) if identity_limitation else ()),
        next_steps=(NEXT_STEPS[category],),
    ) for index, (timestamp, category, outcome, confidence, argv_complete,
                  paths_complete, identity_limitation, _) in enumerate(rows, 1))
    summaries = tuple(ProcessExecutionCategorySummary(
        CATEGORY_IDS[index], DISPLAY_NAMES[index], PRIORITIES[index],
        sum(row[1] == index for row in rows),
        _outcomes(tuple(row[2] for row in rows if row[1] == index)),
    ) for index in range(len(CATEGORY_IDS)))
    return ProcessExecutionObservationAssembly(
        summary=ProcessExecutionSummary(
            eligible_execution_count=len(unique),
            classified_execution_count=len(unique) - unclassified,
            category_observation_count=len(rows),
            outcome_counts=_outcomes(tuple(outcome_values)),
            categories=summaries,
        ),
        observations=observations,
        unclassified_count=unclassified,
        incomplete_context_count=incomplete,
        interpretation_notices=NOTICES,
        bounded_warnings=(IDENTITY_WARNING,) if identity_warning else (),
    )
