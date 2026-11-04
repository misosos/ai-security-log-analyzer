"""Bounded byte-level mutations for the ER-1 synthetic evaluation corpus."""

from __future__ import annotations

from datetime import datetime
import ipaddress
import re


MAX_FIXTURE_BYTES = 8192
MAX_FIXTURE_LINES = 64
_SOURCES = frozenset(("application", "ssh"))
_MUTATIONS = frozenset((
    "remove_failure_row", "add_failure_row", "change_timestamp",
    "change_account", "change_source_ip", "reorder_rows", "damage_format",
))
_SYNTHETIC_ACCOUNT = re.compile(r"synthetic_user_[0-9]{2}\Z", re.ASCII)
_ROW_TARGET = re.compile(r"row:(0|[1-9][0-9]{0,2})\Z", re.ASCII)
_APP_TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}\Z", re.ASCII)
_SSH_TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z",
    re.ASCII,
)
_DOCUMENTATION_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
)


class CounterfactualCorpusError(ValueError):
    """Fixed-category failure that never reflects input values."""

    _CODES = frozenset((
        "invalid_manifest", "fixture_unavailable", "invalid_mutation",
        "unsupported_mutation", "mutation_precondition_failed",
        "unsupported_source", "invalid_utf8", "parser_rejected",
        "parser_execution_failed", "label_mismatch", "event_facts_mismatch",
    ))

    def __init__(self, code: str):
        self.code = code if code in self._CODES else "invalid_manifest"
        super().__init__(self.code)


def _decode_fixture(source_bytes: bytes) -> tuple[str, list[str]]:
    if type(source_bytes) is not bytes or not source_bytes or len(source_bytes) > MAX_FIXTURE_BYTES:
        raise CounterfactualCorpusError("invalid_mutation")
    try:
        text = source_bytes.decode("utf-8", errors="strict")
    except UnicodeError:
        raise CounterfactualCorpusError("invalid_utf8") from None
    if "\r" in text or not text.endswith("\n"):
        raise CounterfactualCorpusError("invalid_mutation")
    rows = text[:-1].split("\n")
    if not rows or len(rows) > MAX_FIXTURE_LINES or any(not row for row in rows):
        raise CounterfactualCorpusError("invalid_mutation")
    return text, rows


def _validate_account(value: object) -> str:
    if type(value) is not str or _SYNTHETIC_ACCOUNT.fullmatch(value) is None:
        raise CounterfactualCorpusError("invalid_mutation")
    return value


def _validate_ip(value: object) -> str:
    if type(value) is not str:
        raise CounterfactualCorpusError("invalid_mutation")
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise CounterfactualCorpusError("invalid_mutation") from None
    if str(address) != value or not any(address in network for network in _DOCUMENTATION_NETWORKS):
        raise CounterfactualCorpusError("invalid_mutation")
    return value


def _validate_timestamp(source: str, value: object) -> str:
    pattern = _APP_TIMESTAMP if source == "application" else _SSH_TIMESTAMP
    if type(value) is not str or pattern.fullmatch(value) is None:
        raise CounterfactualCorpusError("invalid_mutation")
    try:
        datetime.strptime(value, "%Y-%m-%d %H:%M:%S" if source == "application" else "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        raise CounterfactualCorpusError("invalid_mutation") from None
    return value


def _row_index(target: str, rows: list[str]) -> int:
    match = _ROW_TARGET.fullmatch(target) if type(target) is str else None
    if match is None:
        raise CounterfactualCorpusError("invalid_mutation")
    index = int(match.group(1))
    if index >= len(rows):
        raise CounterfactualCorpusError("mutation_precondition_failed")
    return index


def _is_failure_row(source: str, row: str) -> bool:
    if source == "application":
        return bool(re.search(r"\blogin_failed\b", row))
    return bool(re.search(r"\bFailed password for synthetic_user_[0-9]{2} from ", row))


def _insert_timestamp(source: str, row: str, value: str) -> str:
    if source == "application":
        return re.sub(r"^[^ ]+ [^ ]+", value, row, count=1)
    match = re.match(r"^(<[0-9]{1,3}>1 )[^ ]+( .*)$", row, re.ASCII)
    if match is None:
        raise CounterfactualCorpusError("mutation_precondition_failed")
    return match.group(1) + value + match.group(2)


def _ssh_add_row(timestamp: str, account: str, source_ip: str) -> str:
    return (
        f"<34>1 {timestamp} synthetic-gateway sshd 123 ER1A - "
        f"Failed password for {account} from {source_ip} port 51000 ssh2"
    )


def _application_add_row(timestamp: str, account: str, source_ip: str) -> str:
    return (
        f"{timestamp} INFO login_failed user={account} "
        f"ip={source_ip} service=ssh"
    )


def apply_mutation(
    source_bytes: bytes,
    *,
    source: str,
    mutation_type: str,
    mutation_target: str,
    mutation_parameters: dict,
) -> bytes:
    """Return a mutated fixture; inputs are strict, synthetic-only, and bounded."""
    if type(source) is not str:
        raise CounterfactualCorpusError("unsupported_source")
    if source not in _SOURCES:
        raise CounterfactualCorpusError("unsupported_source")
    if type(mutation_type) is not str:
        raise CounterfactualCorpusError("unsupported_mutation")
    if mutation_type not in _MUTATIONS:
        raise CounterfactualCorpusError("unsupported_mutation")
    if type(mutation_parameters) is not dict:
        raise CounterfactualCorpusError("invalid_mutation")
    _, rows = _decode_fixture(source_bytes)

    if mutation_type == "remove_failure_row":
        if mutation_parameters or (index := _row_index(mutation_target, rows)) < 0:
            raise CounterfactualCorpusError("invalid_mutation")
        if not _is_failure_row(source, rows[index]):
            raise CounterfactualCorpusError("mutation_precondition_failed")
        del rows[index]
    elif mutation_type == "add_failure_row":
        if mutation_target != "end" or set(mutation_parameters) != {"timestamp", "account", "source_ip"}:
            raise CounterfactualCorpusError("invalid_mutation")
        timestamp = _validate_timestamp(source, mutation_parameters["timestamp"])
        account = _validate_account(mutation_parameters["account"])
        source_ip = _validate_ip(mutation_parameters["source_ip"])
        rows.append(
            _application_add_row(timestamp, account, source_ip)
            if source == "application"
            else _ssh_add_row(timestamp, account, source_ip)
        )
    elif mutation_type in {"change_timestamp", "change_account", "change_source_ip", "damage_format"}:
        index = _row_index(mutation_target, rows)
        row = rows[index]
        if not _is_failure_row(source, row):
            raise CounterfactualCorpusError("mutation_precondition_failed")
        if mutation_type == "change_timestamp":
            if set(mutation_parameters) != {"timestamp"}:
                raise CounterfactualCorpusError("invalid_mutation")
            rows[index] = _insert_timestamp(
                source, row, _validate_timestamp(source, mutation_parameters["timestamp"]),
            )
        elif mutation_type == "change_account":
            if set(mutation_parameters) != {"account"}:
                raise CounterfactualCorpusError("invalid_mutation")
            account = _validate_account(mutation_parameters["account"])
            expression = (
                r"\buser=synthetic_user_[0-9]{2}\b"
                if source == "application"
                else r"\bFailed password for synthetic_user_[0-9]{2}(?= from )"
            )
            rows[index], count = re.subn(
                expression,
                f"user={account}" if source == "application" else f"Failed password for {account}",
                row,
                count=1,
            )
            if count != 1:
                raise CounterfactualCorpusError("mutation_precondition_failed")
        elif mutation_type == "change_source_ip":
            if set(mutation_parameters) != {"source_ip"}:
                raise CounterfactualCorpusError("invalid_mutation")
            source_ip = _validate_ip(mutation_parameters["source_ip"])
            expression = (
                r"\bip=[0-9.]+\b"
                if source == "application"
                else r"\bfrom [0-9.]+(?= port )"
            )
            replacement = f"ip={source_ip}" if source == "application" else f"from {source_ip}"
            rows[index], count = re.subn(expression, replacement, row, count=1)
            if count != 1:
                raise CounterfactualCorpusError("mutation_precondition_failed")
        else:
            if set(mutation_parameters) != {"damage_type"}:
                raise CounterfactualCorpusError("invalid_mutation")
            damage_type = mutation_parameters["damage_type"]
            if damage_type == "remove_account_field" and source == "application":
                rows[index], count = re.subn(r" user=synthetic_user_[0-9]{2}", "", row, count=1)
                if count != 1:
                    raise CounterfactualCorpusError("mutation_precondition_failed")
            elif damage_type == "invalid_timestamp":
                rows[index] = _insert_timestamp(
                    source,
                    row,
                    "not-a-timestamp" if source == "application" else "not-a-timestamp",
                )
            else:
                raise CounterfactualCorpusError("invalid_mutation")
    else:
        if mutation_type != "reorder_rows" or mutation_target != "all_rows" or set(mutation_parameters) != {"order"}:
            raise CounterfactualCorpusError("invalid_mutation")
        order = mutation_parameters["order"]
        if (
            type(order) is not list
            or len(order) != len(rows)
            or any(type(index) is not int for index in order)
            or sorted(order) != list(range(len(rows)))
        ):
            raise CounterfactualCorpusError("mutation_precondition_failed")
        rows = [rows[index] for index in order]

    result = ("\n".join(rows) + "\n").encode("utf-8")
    if len(result) > MAX_FIXTURE_BYTES or len(rows) > MAX_FIXTURE_LINES:
        raise CounterfactualCorpusError("mutation_precondition_failed")
    if result == source_bytes:
        raise CounterfactualCorpusError("mutation_precondition_failed")
    return result
