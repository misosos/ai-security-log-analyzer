"""Trusted live-record adapter for the existing batch parser registry."""

from dataclasses import dataclass, field

from app.live_monitoring.config import ROLES
from app.live_monitoring.core import LiveTailRecord, MAX_COUNTER
from app.loader.file_loader import preprocess_log_line
from app.models.schemas import NormalizedEvent
from app.parser import registry
from app.parser.time_utils import normalize_to_utc


_ERROR_MESSAGES = {
    "INVALID_BATCH_TYPE": "live parser 입력 형식을 확인하십시오.",
    "INVALID_RECORD_TYPE": "live parser 기록 형식을 확인하십시오.",
    "MIXED_SOURCE_ROLE": "하나의 로그 역할만 전달하십시오.",
    "DUPLICATE_SEQUENCE": "중복된 기록 순서가 있습니다.",
    "DECREASING_SEQUENCE": "기록 순서를 확인하십시오.",
    "UNSUPPORTED_ROLE": "지원하는 로그 역할을 사용하십시오.",
    "UNEXPECTED_PARSER_RESULT": "parser 결과 형식을 확인하십시오.",
    "UTC_NORMALIZATION_FAILURE": "시각 정규화 결과를 확인하십시오.",
    "UNEXPECTED_PARSER_FAILURE": "live parser 처리를 중단하십시오.",
    "INVARIANT_VIOLATION": "live parser 결과를 확인하십시오.",
}

_REJECTION_CODES = {
    "application": "MALFORMED_APPLICATION_RECORD",
    "ssh": "MALFORMED_SSH_RECORD",
    "access": "MALFORMED_ACCESS_RECORD",
}


class LiveParseError(ValueError):
    """Fixed, input-free batch error; expected record failures are outcomes."""

    def __init__(self, code: str):
        if type(code) is not str or code not in _ERROR_MESSAGES:
            code = "INVARIANT_VIOLATION"
        self.code = code
        super().__init__(f"{code}: {_ERROR_MESSAGES[code]}")

    def __repr__(self) -> str:
        return f"LiveParseError(code={self.code!r})"


@dataclass(frozen=True, slots=True)
class LiveParseOutcome:
    sequence: int
    status: str
    event: NormalizedEvent | None = field(default=None, repr=False)
    fixed_reason_code: str | None = None

    def __post_init__(self) -> None:
        if type(self.sequence) is not int or not 1 <= self.sequence <= MAX_COUNTER:
            raise LiveParseError("INVARIANT_VIOLATION")
        if self.status == "PARSED":
            if type(self.event) is not NormalizedEvent or self.fixed_reason_code is not None:
                raise LiveParseError("INVARIANT_VIOLATION")
        elif self.status == "IGNORED":
            if self.event is not None or self.fixed_reason_code is not None:
                raise LiveParseError("INVARIANT_VIOLATION")
        elif self.status == "REJECTED":
            if self.event is not None or self.fixed_reason_code not in _REJECTION_CODES.values():
                raise LiveParseError("INVARIANT_VIOLATION")
        else:
            raise LiveParseError("INVARIANT_VIOLATION")


@dataclass(frozen=True, slots=True)
class LiveParseBatch:
    source_role: str
    outcomes: tuple[LiveParseOutcome, ...]
    parsed_count: int
    ignored_count: int
    rejected_count: int

    def __post_init__(self) -> None:
        if (
            type(self.source_role) is not str
            or self.source_role not in ROLES
            or type(self.outcomes) is not tuple
            or any(type(item) is not LiveParseOutcome for item in self.outcomes)
            or any(type(value) is not int or not 0 <= value <= MAX_COUNTER for value in (
                self.parsed_count, self.ignored_count, self.rejected_count,
            ))
            or self.parsed_count + self.ignored_count + self.rejected_count != len(self.outcomes)
            or self.parsed_count != sum(item.status == "PARSED" for item in self.outcomes)
            or self.ignored_count != sum(item.status == "IGNORED" for item in self.outcomes)
            or self.rejected_count != sum(item.status == "REJECTED" for item in self.outcomes)
            or any(left.sequence >= right.sequence for left, right in zip(self.outcomes, self.outcomes[1:]))
        ):
            raise LiveParseError("INVARIANT_VIOLATION")


def parse_live_records(source_role: str, records: tuple[LiveTailRecord, ...]) -> LiveParseBatch:
    """Parse each complete record once; never run detectors or access files."""
    if type(source_role) is not str or source_role not in ROLES:
        raise LiveParseError("UNSUPPORTED_ROLE")
    if type(records) is not tuple:
        raise LiveParseError("INVALID_BATCH_TYPE")

    last_sequence = 0
    for record in records:
        if type(record) is not LiveTailRecord:
            raise LiveParseError("INVALID_RECORD_TYPE")
        if record.role != source_role:
            raise LiveParseError("MIXED_SOURCE_ROLE")
        if record.sequence == last_sequence:
            raise LiveParseError("DUPLICATE_SEQUENCE")
        if record.sequence < last_sequence:
            raise LiveParseError("DECREASING_SEQUENCE")
        last_sequence = record.sequence

    outcomes: list[LiveParseOutcome] = []
    parsed_count = ignored_count = rejected_count = 0
    for record in records:
        try:
            line = preprocess_log_line(record.payload)
        except Exception:
            raise LiveParseError("UNEXPECTED_PARSER_FAILURE") from None
        if not line:
            outcomes.append(LiveParseOutcome(record.sequence, "IGNORED"))
            ignored_count += 1
            continue
        try:
            parser = registry.get_parser(source_role)
            zone = registry.get_timezone(source_role)
        except Exception:
            raise LiveParseError("UNEXPECTED_PARSER_FAILURE") from None
        try:
            event = parser(line, zone)
        except (ValueError, IndexError):
            outcomes.append(LiveParseOutcome(
                record.sequence, "REJECTED", fixed_reason_code=_REJECTION_CODES[source_role],
            ))
            rejected_count += 1
            continue
        except Exception:
            raise LiveParseError("UNEXPECTED_PARSER_FAILURE") from None
        if event is None:
            outcomes.append(LiveParseOutcome(record.sequence, "IGNORED"))
            ignored_count += 1
            continue
        if type(event) is not NormalizedEvent:
            raise LiveParseError("UNEXPECTED_PARSER_RESULT")
        try:
            event.timestamp = normalize_to_utc(event.timestamp)
        except (ValueError, TypeError, AttributeError):
            raise LiveParseError("UTC_NORMALIZATION_FAILURE") from None
        except Exception:
            raise LiveParseError("UNEXPECTED_PARSER_FAILURE") from None
        outcomes.append(LiveParseOutcome(record.sequence, "PARSED", event=event))
        parsed_count += 1
    return LiveParseBatch(
        source_role, tuple(outcomes), parsed_count, ignored_count, rejected_count,
    )
