"""Synthetic-pilot CLI for a bounded restricted analyst JSON report.

This module is deliberately separate from the public API, live monitor and UI.
It does not discover default paths or load user configuration.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import signal
import stat
import sys
import time
import uuid

from app.analyzer.incident_case_adapter import (
    project_investigation_cases_from_analysis,
)
from app.analyzer.pipeline import (
    assess_risk,
    correlate_attacks,
    detect_attacks_with_context,
)
from app.detector.brute_force import AnalysisRunOwner
from app.investigation_role_snapshot_36_4 import (
    AnalysisSourceRoleSnapshot,
    AnalysisWithSourceRoleSnapshot,
)
from app.parser.registry import get_parser, get_timezone
from app.parser.time_utils import normalize_to_utc


SCHEMA_VERSION = "restricted-investigation-report/v1"
CLASSIFICATION = "RESTRICTED_INTERNAL_INVESTIGATION"
ENCRYPTION_STATUS = "NOT_AUTOMATICALLY_ENCRYPTED"
APPROVAL = "제한된 내부 보고서 생성을 승인합니다"
AUDIT_NAME = ".restricted-report-audit.jsonl"
MAX_INPUT_BYTES = 2 * 1024 * 1024
MAX_LINE_BYTES = 16 * 1024
MAX_LINES = 256
MAX_OUTPUT_BYTES = 1024 * 1024
MAX_AUDIT_BYTES = 64 * 1024
MAX_AUDIT_EVENTS = 128
MAX_IDENTIFIER_BYTES = 256
MAX_RUNTIME_SECONDS = 5.0

_DETECTION_LABELS = {
    "brute_force": "반복 인증 실패 관찰",
    "password_spray": "여러 계정 대상 인증 실패 관찰",
    "password_spraying_like": "여러 계정 대상 인증 실패 관찰",
    "path_traversal": "경로 탐색과 유사한 요청 관찰",
    "sql_injection_like": "SQL 삽입과 유사한 요청 관찰",
    "xss_like": "스크립트 삽입과 유사한 요청 관찰",
    "sensitive_resource_probing_like": "민감 리소스 탐색과 유사한 요청 관찰",
    "web_scanning_like": "웹 탐색과 유사한 요청 관찰",
}
_RELATION_LABELS = {
    "failed_to_successful_login": "로그인 실패 뒤 로그인 성공 관찰",
    "brute_force_to_successful_login": "반복 인증 실패 탐지 뒤 로그인 성공 관찰",
    "successful_login_to_file_access": "로그인 성공 뒤 파일 접근 관찰",
    "password_spray_to_successful_login": "여러 계정 인증 실패 탐지 뒤 로그인 성공 관찰",
}
_OBSERVATION_LABEL_SET = {
    "로그인 실패", "로그인 성공 관찰", "HTTP 요청 관찰",
    *_DETECTION_LABELS.values(),
}
_RELATION_LABEL_SET = set(_RELATION_LABELS.values())


class RestrictedReportError(Exception):
    """Fixed-message failure; never carries an input path or raw exception."""

    def __init__(self, recovery_needed: bool = False):
        super().__init__()
        self.recovery_needed = recovery_needed


def _fail(recovery_needed: bool = False) -> None:
    raise RestrictedReportError(recovery_needed=recovery_needed) from None


def _reject_symlink_components(path: Path) -> None:
    if not path.is_absolute():
        _fail()
    current = Path(path.anchor)
    try:
        for component in path.parts[1:]:
            current = current / component
            if stat.S_ISLNK(current.lstat().st_mode):
                _fail()
    except OSError:
        _fail()


def _read_private_input(path_text: str) -> tuple[bytes, os.stat_result]:
    if type(path_text) is not str or not path_text:
        _fail()
    path = Path(path_text)
    _reject_symlink_components(path)
    try:
        before_path = path.lstat()
        if stat.S_ISLNK(before_path.st_mode) or not stat.S_ISREG(before_path.st_mode):
            _fail()
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
    except Exception:
        _fail()
    try:
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or before.st_mode & 0o077
            or before.st_size <= 0
            or before.st_size > MAX_INPUT_BYTES
        ):
            _fail()
        chunks = []
        size = 0
        while True:
            block = os.read(fd, min(65536, MAX_INPUT_BYTES + 1 - size))
            if not block:
                break
            chunks.append(block)
            size += len(block)
            if size > MAX_INPUT_BYTES:
                _fail()
        after = os.fstat(fd)
        after_path = path.lstat()
        stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(getattr(before, field) != getattr(after, field) for field in stable_fields):
            _fail()
        if any(getattr(before, field) != getattr(after_path, field) for field in stable_fields):
            _fail()
        data = b"".join(chunks)
        if len(data) != before.st_size:
            _fail()
        return data, before
    except (OSError, UnicodeError):
        _fail()
    finally:
        os.close(fd)


def _parse_lines(data: bytes, role: str):
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeError:
        _fail()
    if "\x00" in text or "\ufffd" in text or not text.endswith("\n"):
        _fail()
    lines = text.splitlines()
    if not 1 <= len(lines) <= MAX_LINES:
        _fail()
    parser = get_parser(role)
    timezone_name = get_timezone(role)
    events = []
    for line in lines:
        if len(line.encode("utf-8")) > MAX_LINE_BYTES or any(
            ord(char) < 0x20 and char != "\t" for char in line
        ):
            _fail()
        try:
            parsed = parser(line, timezone_name)
            if parsed is not None:
                parsed.timestamp = normalize_to_utc(parsed.timestamp)
                events.append(parsed)
        except (ValueError, TypeError, IndexError, OverflowError):
            _fail()
    return events


def _identifier(value: object, kind: str) -> str | None:
    if type(value) is not str or not value or len(value.encode("utf-8")) > MAX_IDENTIFIER_BYTES:
        return None
    if any(ord(char) < 0x20 or char in "\r\n\x00" for char in value):
        return None
    if kind == "account" and (
        value.startswith(("/", "~")) or "://" in value or "?" in value or "=" in value
    ):
        return None
    if kind == "hostname" and not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", value):
        return None
    if kind in {"ipv4", "ipv6"}:
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return None
        if (kind == "ipv4") != (address.version == 4):
            return None
        return str(address)
    return value


def _collect_subjects(events: list) -> tuple[list[dict], dict[str, str]]:
    grouped: dict[tuple[str, str], set[tuple[str, str]]] = {}
    for event in events:
        source_ip = None
        if event.src_ip is not None:
            try:
                source_ip = str(ipaddress.ip_address(event.src_ip))
            except ValueError:
                _fail()
        account = _identifier(event.user, "account")
        if event.user is not None and account is None:
            _fail()
        if source_ip is not None:
            group = ("ip", source_ip)
        elif account is not None:
            group = ("account", account)
        else:
            group = None
        if group is not None:
            identifiers = grouped.setdefault(group, set())
            if source_ip is not None:
                ip = ipaddress.ip_address(source_ip)
                identifiers.add((f"ipv{ip.version}", source_ip))
            if account is not None:
                identifiers.add(("account", account))
        host = getattr(event.linux_audit, "hostname", None) if event.linux_audit else None
        hostname = _identifier(host, "hostname")
        if host is not None and hostname is None:
            _fail()
        if hostname is not None:
            group = group or ("hostname", hostname)
            grouped.setdefault(group, set()).add(("hostname", hostname))
    ordered_groups = sorted(grouped, key=lambda item: (item[0], item[1].casefold(), item[1]))
    if len(ordered_groups) > MAX_LINES * 3:
        _fail()
    subjects = []
    ip_subject_ids = {}
    for index, group in enumerate(ordered_groups, start=1):
        subject_id = f"subject-{index:03d}"
        subjects.append({
            "subject_id": subject_id,
            "identifiers": [
                {"kind": kind, "value": value}
                for kind, value in sorted(grouped[group], key=lambda item: (item[0], item[1].casefold(), item[1]))
            ],
        })
        if group[0] == "ip":
            ip_subject_ids[group[1]] = subject_id
    return subjects, ip_subject_ids


def _utc_projection_time(value: object) -> str | None:
    if value is None:
        return None
    timestamp = getattr(value, "canonical_utc", None)
    if type(timestamp) is not datetime or timestamp.tzinfo is None:
        _fail()
    return timestamp.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _build_report(role: str, events: list) -> dict:
    started = time.monotonic()
    run_owner = AnalysisRunOwner()
    detections, brute_window_contexts = detect_attacks_with_context(events, run_owner)
    analysis = correlate_attacks(
        events,
        detections,
        brute_window_contexts,
        run_owner=run_owner,
    )
    analysis = assess_risk(analysis)
    run_owner._bind_analysis(analysis)
    analysis_run = AnalysisWithSourceRoleSnapshot(
        analysis,
        AnalysisSourceRoleSnapshot.from_events(analysis, tuple(events)),
        brute_window_contexts,
        run_owner,
    )
    case_projection = project_investigation_cases_from_analysis(analysis_run)

    subjects, ip_subject_ids = _collect_subjects(events)
    observation_counts: dict[str, int] = {}
    for event in events:
        label = {
            "login_failed": "로그인 실패",
            "user_login": "로그인 성공 관찰",
            "http_request": "HTTP 요청 관찰",
        }.get(event.event_type)
        if label:
            observation_counts[label] = observation_counts.get(label, 0) + 1
    observations = [
        {"type": label, "count": count}
        for label, count in sorted(observation_counts.items())
    ]

    detections: dict[str, int] = {}
    risks: dict[str, dict[str, int]] = {}
    relations: dict[str, int] = {}
    for item in analysis["results"].values():
        for slot, detection in item.get("detections", {}).items():
            if getattr(detection, "is_detected", False):
                label = _DETECTION_LABELS.get(detection.detection_type)
                if label:
                    detections[label] = detections.get(label, 0) + 1
        level = item.get("risk_level", "LOW")
        if level not in {"HIGH", "MEDIUM", "LOW"}:
            _fail()
        confidence = item.get("risk_factors", {}).get("confidence", {}).get("level")
        if confidence not in {"HIGH", "MEDIUM", "LOW"}:
            _fail()
        if level not in risks:
            risks[level] = {"subject_count": 0, "confidence_high": 0, "confidence_medium": 0, "confidence_low": 0}
        risks[level]["subject_count"] += 1
        risks[level][f"confidence_{confidence.lower()}"] += 1
        for slot, correlation in item.get("correlation", {}).items():
            if not isinstance(correlation, dict) or not correlation.get("is_correlated"):
                continue
            kind = correlation.get("type") or slot
            label = _RELATION_LABELS.get(kind)
            if label:
                relations[label] = relations.get(label, 0) + 1
    for key, result in analysis.get("global_correlation", {}).items():
        if type(result) is dict and result.get("is_correlated"):
            label = _RELATION_LABELS.get(result.get("type") or key)
            if label:
                relations[label] = relations.get(label, 0) + 1

    cases = []
    for case in case_projection.cases:
        row = case.row
        subject_id = ip_subject_ids.get(row.subject_ip)
        if subject_id is None:
            _fail()
        cases.append({
            "case_type": case.rule_code,
            "subject_id": subject_id,
            "risk_level": row.included_highest_risk,
            "confidence": row.included_highest_confidence,
            "observation_count": row.observation_count,
            "supporting_relation_count": row.supporting_relation_count,
            "start_time": _utc_projection_time(row.start_time),
            "end_time": _utc_projection_time(row.end_time),
        })
    cases.sort(key=lambda item: (
        item["case_type"], item["start_time"] or "", item["end_time"] or ""
    ))
    if time.monotonic() - started > MAX_RUNTIME_SECONDS:
        _fail()
    timestamps = sorted(event.timestamp.astimezone(timezone.utc) for event in events)
    return {
        "schema_version": SCHEMA_VERSION,
        "report_id": uuid.uuid4().hex,
        "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "source_role": role,
        "classification": CLASSIFICATION,
        "encryption_status": ENCRYPTION_STATUS,
        "limitations": [
            "합성 입력 전용 pilot입니다.",
            "관찰과 관계는 공격 성공이나 침해 확정을 의미하지 않습니다.",
            "원본 로그 전체와 원문 근거는 포함하지 않습니다.",
            "이 파일은 자동 암호화되지 않으며 보존·삭제 책임은 사용자에게 있습니다.",
            "현재 선택한 parser는 hostname 식별자를 제공하지 않아 hostname 값은 포함되지 않습니다.",
        ],
        "subjects": subjects,
        "observations": observations + [
            {"type": label, "count": count}
            for label, count in sorted(detections.items())
        ],
        "relations": [
            {"type": label, "count": count}
            for label, count in sorted(relations.items())
        ],
        "risks": [
            {"level": level, **counts}
            for level, counts in sorted(risks.items())
        ],
        "cases": cases,
        "audit_summary": {
            "event_count": len(events),
            "subject_count": len(subjects),
            "identifier_counts": _identifier_counts({"subjects": subjects}),
            "observation_count": sum(item["count"] for item in observations),
            "relation_count": sum(relations.values()),
            "case_count": len(cases),
            "time_start": timestamps[0].isoformat().replace("+00:00", "Z") if timestamps else None,
            "time_end": timestamps[-1].isoformat().replace("+00:00", "Z") if timestamps else None,
        },
    }


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value, ensure_ascii=False, allow_nan=False,
            sort_keys=True, separators=(",", ":"),
        ).encode("utf-8", errors="strict")
    except (TypeError, ValueError, UnicodeError):
        _fail()


def _validate_report(report: dict) -> None:
    expected = {
        "schema_version", "report_id", "generated_at", "source_role",
        "classification", "encryption_status", "limitations", "subjects",
        "observations", "relations", "risks", "cases", "audit_summary",
    }
    if type(report) is not dict or set(report) != expected:
        _fail()
    if (
        report["schema_version"] != SCHEMA_VERSION
        or report["classification"] != CLASSIFICATION
        or report["encryption_status"] != ENCRYPTION_STATUS
        or report["source_role"] not in {"application", "ssh", "access"}
        or type(report["report_id"]) is not str
        or len(report["report_id"]) != 32
        or type(report["subjects"]) is not list
        or type(report["observations"]) is not list
        or type(report["relations"]) is not list
        or type(report["risks"]) is not list
        or type(report["cases"]) is not list
        or type(report["audit_summary"]) is not dict
        or type(report["limitations"]) is not list
        or type(report["generated_at"]) is not str
    ):
        _fail()
    subject_ids = set()
    identifier_total = 0
    for subject in report["subjects"]:
        if (
            type(subject) is not dict or set(subject) != {"subject_id", "identifiers"}
            or type(subject["subject_id"]) is not str
            or not re.fullmatch(r"subject-[0-9]{3}", subject["subject_id"])
            or subject["subject_id"] in subject_ids
            or type(subject["identifiers"]) is not list
            or not 1 <= len(subject["identifiers"]) <= MAX_LINES + 2
        ):
            _fail()
        subject_ids.add(subject["subject_id"])
        identifier_total += len(subject["identifiers"])
        if any(
            type(identifier) is not dict or set(identifier) != {"kind", "value"}
            or identifier["kind"] not in {"account", "ipv4", "ipv6", "hostname"}
            or type(identifier["value"]) is not str
            or len(identifier["value"].encode("utf-8")) > MAX_IDENTIFIER_BYTES
            or _identifier(identifier["value"], identifier["kind"]) != identifier["value"]
            for identifier in subject["identifiers"]
        ):
            _fail()
    if identifier_total > MAX_LINES * 3:
        _fail()
    if any(len(report[key]) > MAX_LINES * 3 for key in ("subjects", "observations", "relations", "risks", "cases")):
        _fail()
    if any(type(item) is not str or len(item) > 240 for item in report["limitations"]):
        _fail()
    if any(
        type(item) is not dict or set(item) != {"type", "count"}
        or type(item["type"]) is not str or item["type"] not in _OBSERVATION_LABEL_SET
        or type(item["count"]) is not int
        or item["count"] < 0
        for item in report["observations"]
    ) or any(
        type(item) is not dict or set(item) != {"type", "count"}
        or type(item["type"]) is not str or item["type"] not in _RELATION_LABEL_SET
        or type(item["count"]) is not int
        or item["count"] < 0
        for item in report["relations"]
    ):
        _fail()
    if any(
        type(item) is not dict or set(item) != {"level", "subject_count", "confidence_high", "confidence_medium", "confidence_low"}
        or item["level"] not in {"HIGH", "MEDIUM", "LOW"}
        or any(type(item[key]) is not int or item[key] < 0 for key in ("subject_count", "confidence_high", "confidence_medium", "confidence_low"))
        for item in report["risks"]
    ):
        _fail()
    case_keys = {
        "case_type", "subject_id", "risk_level", "confidence", "observation_count",
        "supporting_relation_count", "start_time", "end_time",
    }
    if any(
        type(item) is not dict or set(item) != case_keys
        or item["risk_level"] not in {"HIGH", "MEDIUM", "LOW"}
        or item["confidence"] not in {"HIGH", "MEDIUM", "LOW"}
        or type(item["observation_count"]) is not int or item["observation_count"] < 0
        or type(item["supporting_relation_count"]) is not int or item["supporting_relation_count"] < 0
        or item["case_type"] not in {"CASE-AUTH-TRANSITION-01", "CASE-BRUTE-SUCCESS-01"}
        or item["subject_id"] not in subject_ids
        or any(value is not None and type(value) is not str for value in (item["start_time"], item["end_time"]))
        for item in report["cases"]
    ):
        _fail()
    summary_keys = {
        "event_count", "subject_count", "identifier_counts", "observation_count",
        "relation_count", "case_count", "time_start", "time_end",
    }
    summary = report["audit_summary"]
    if (
        set(summary) != summary_keys
        or any(type(summary[key]) is not int or summary[key] < 0 for key in (
            "event_count", "subject_count", "observation_count", "relation_count", "case_count",
        ))
        or type(summary["identifier_counts"]) is not dict
        or set(summary["identifier_counts"]) != {"account", "ipv4", "ipv6", "hostname"}
        or any(type(value) is not int or value < 0 for value in summary["identifier_counts"].values())
        or any(value is not None and type(value) is not str for value in (summary["time_start"], summary["time_end"]))
    ):
        _fail()
    encoded = _canonical_json(report)
    if len(encoded) > MAX_OUTPUT_BYTES:
        _fail()


def _check_local_filesystem(parent: Path) -> None:
    if sys.platform == "linux":
        try:
            lines = Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines()
            resolved = str(parent.resolve())
            best = None
            for line in lines:
                fields = line.split()
                mount = fields[4].replace("\\040", " ")
                if resolved == mount or resolved.startswith(mount.rstrip("/") + "/"):
                    if best is None or len(mount) > len(best[0]):
                        separator = fields.index("-")
                        best = (mount, fields[separator + 1])
            if best is None or best[1] not in {"ext4", "xfs", "btrfs", "tmpfs", "overlay"}:
                _fail()
        except Exception:
            _fail()
    elif sys.platform == "darwin":
        try:
            completed = __import__("subprocess").run(
                ["/sbin/mount"], check=False, capture_output=True, timeout=2,
            )
            target = str(parent.resolve())
            matched = []
            for raw_line in completed.stdout.decode("utf-8", "strict").splitlines():
                if " on " not in raw_line or " (" not in raw_line:
                    continue
                mountpoint = raw_line.split(" on ", 1)[1].rsplit(" (", 1)[0]
                options = raw_line.rsplit(" (", 1)[1].rstrip(")").split(", ")
                if target == mountpoint or target.startswith(mountpoint.rstrip("/") + "/"):
                    matched.append((len(mountpoint), options))
            options = max(matched, key=lambda item: item[0])[1] if matched else []
            if completed.returncode != 0 or "local" not in options or not {"apfs", "hfs"}.intersection(options):
                _fail()
        except Exception:
            _fail()
    else:
        _fail()


def _open_private_directory(path: Path) -> int:
    try:
        _reject_symlink_components(path)
        info = path.lstat()
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            _fail()
        _check_local_filesystem(path)
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
            os.close(fd)
            _fail()
        return fd
    except Exception:
        _fail()


def _audit_append(dir_fd: int, record: dict) -> None:
    name = AUDIT_NAME
    base_flags = os.O_WRONLY | os.O_APPEND | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = None
    locked = False
    created = False
    original_size = None
    try:
        try:
            fd = os.open(name, base_flags | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=dir_fd)
            created = True
            original_size = 0
        except FileNotFoundError:
            _fail()
        except FileExistsError:
            fd = os.open(name, base_flags, dir_fd=dir_fd)
            created = False
        fcntl.flock(fd, fcntl.LOCK_EX)
        locked = True
        if created:
            os.fchmod(fd, 0o600)
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_size > MAX_AUDIT_BYTES
        ):
            _fail()
        original_size = info.st_size
        if info.st_size:
            read_fd = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=dir_fd)
            try:
                read_info = os.fstat(read_fd)
                if (read_info.st_dev, read_info.st_ino) != (info.st_dev, info.st_ino):
                    _fail()
                contents = os.read(read_fd, MAX_AUDIT_BYTES + 1)
            finally:
                os.close(read_fd)
            if contents.count(b"\n") >= MAX_AUDIT_EVENTS:
                _fail()
            _validate_audit_contents(contents)
        payload = _canonical_json(record) + b"\n"
        if info.st_size + len(payload) > MAX_AUDIT_BYTES:
            _fail()
        remaining = memoryview(payload)
        while remaining:
            written = os.write(fd, remaining)
            if written <= 0:
                _fail()
            remaining = remaining[written:]
        os.fsync(fd)
        if created:
            os.fsync(dir_fd)
    except KeyboardInterrupt:
        if fd is not None and original_size is not None:
            try:
                os.ftruncate(fd, original_size)
                os.fsync(fd)
            except OSError:
                pass
        raise
    except Exception:
        if fd is not None and original_size is not None:
            try:
                os.ftruncate(fd, original_size)
                os.fsync(fd)
                if created and original_size == 0:
                    os.unlink(name, dir_fd=dir_fd)
                    os.fsync(dir_fd)
            except OSError:
                pass
        _fail()
    finally:
        if fd is not None:
            if locked:
                try:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                except OSError:
                    pass
            try:
                os.close(fd)
            except OSError:
                recovery_needed = False
                if original_size is not None:
                    try:
                        os.ftruncate(fd, original_size)
                        os.fsync(fd)
                        if created and original_size == 0:
                            os.unlink(name, dir_fd=dir_fd)
                            os.fsync(dir_fd)
                    except OSError:
                        recovery_needed = True
                try:
                    os.close(fd)
                except OSError:
                    recovery_needed = True
                _fail(recovery_needed=recovery_needed)


def _validate_audit_contents(contents: bytes) -> None:
    expected = {
        "status", "occurred_at", "schema_version", "source_role", "report_id",
        "identifier_counts", "case_count", "relation_count", "observation_count",
    }
    try:
        lines = contents.decode("utf-8", errors="strict").splitlines()
        if not contents.endswith(b"\n") or len(lines) > MAX_AUDIT_EVENTS:
            _fail()
        for line in lines:
            record = json.loads(
                line,
                object_pairs_hook=lambda pairs: _reject_duplicate_pairs(pairs),
                parse_constant=lambda _value: _fail(),
            )
            if (
                type(record) is not dict or set(record) != expected
                or record["status"] not in {"success", "failure", "cancelled"}
                or record["schema_version"] != SCHEMA_VERSION
                or record["source_role"] not in {"application", "ssh", "access"}
                or type(record["report_id"]) is not str
                or len(record["report_id"]) != 32
                or type(record["identifier_counts"]) is not dict
                or set(record["identifier_counts"]) != {"account", "ipv4", "ipv6", "hostname"}
                or any(type(value) is not int or value < 0 for value in record["identifier_counts"].values())
                or any(type(record[key]) is not int or record[key] < 0 for key in ("case_count", "relation_count", "observation_count"))
                or type(record["occurred_at"]) is not str
            ):
                _fail()
    except (UnicodeError, ValueError, TypeError):
        _fail()


def _reject_duplicate_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _fail()
        result[key] = value
    return result


def _atomic_publish(dir_fd: int, filename: str, payload: bytes) -> None:
    if not filename.endswith(".json") or Path(filename).name != filename or filename in {".", ".."}:
        _fail()
    if len(payload) > MAX_OUTPUT_BYTES:
        _fail()
    temp_name = f".restricted-{secrets.token_hex(12)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = None
    published = False
    rollback_failed = False
    try:
        fd = os.open(temp_name, flags, 0o600, dir_fd=dir_fd)
        view = memoryview(payload)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                _fail()
            view = view[written:]
        os.fchmod(fd, 0o600)
        os.fsync(fd)
        os.close(fd)
        fd = None
        os.link(temp_name, filename, src_dir_fd=dir_fd, dst_dir_fd=dir_fd, follow_symlinks=False)
        published = True
        os.unlink(temp_name, dir_fd=dir_fd)
        os.fsync(dir_fd)
    except (OSError, TypeError, NotImplementedError, KeyboardInterrupt, TimeoutError):
        if published:
            try:
                os.unlink(filename, dir_fd=dir_fd)
                os.fsync(dir_fd)
            except OSError:
                rollback_failed = True
        else:
            try:
                temp_info = os.stat(temp_name, dir_fd=dir_fd, follow_symlinks=False)
                target_info = os.stat(filename, dir_fd=dir_fd, follow_symlinks=False)
                if (temp_info.st_dev, temp_info.st_ino) == (target_info.st_dev, target_info.st_ino):
                    os.unlink(filename, dir_fd=dir_fd)
                    os.fsync(dir_fd)
            except FileNotFoundError:
                pass
            except OSError:
                rollback_failed = True
        _fail(recovery_needed=rollback_failed)
    finally:
        cleanup_failed = False
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                cleanup_failed = True
        try:
            os.unlink(temp_name, dir_fd=dir_fd)
        except FileNotFoundError:
            pass
        except OSError:
            cleanup_failed = True
        if cleanup_failed:
            _fail(recovery_needed=True)


def _approval_preview(role: str, report: dict) -> str:
    counts = report["audit_summary"]["identifier_counts"]
    values = ", ".join(f"{kind} {counts[kind]}개" for kind in ("account", "ipv4", "ipv6", "hostname"))
    return (
        f"source role: {role}; cases {len(report['cases'])}개, relations {sum(item['count'] for item in report['relations'])}개, "
        f"observations {sum(item['count'] for item in report['observations'])}개; {values}.\n"
        "원문 로그, 파일 경로, 인증 정보, 내부 예외는 포함하지 않습니다.\n"
        "보고서는 지정한 로컬 파일로 저장되며 자동 암호화되지 않습니다. 파일 권한 0600은 암호화가 아닙니다.\n"
        "저장 위치는 사용자가 지정한 소유자 전용(0700) 로컬 폴더여야 합니다. 다른 사용자가 읽을 수 있는 폴더에는 저장하지 않습니다.\n"
        "저장 경로는 이 안내에 표시하지 않습니다.\n"
        "기존 파일은 덮어쓰지 않습니다. 파일이 이미 있으면 다른 새 출력 이름을 지정하십시오.\n"
        "감사 기록에는 상태·시각·schema·역할·보고서 ID·식별자 종류별 개수와 사례/관계/관찰 수만 남습니다.\n"
        "실제 식별자와 파일 경로는 감사 기록에 남기지 않습니다.\n"
        "일반 화면과 공개용 보고서는 보호된 별칭을 계속 사용하며, 이 제한 보고서의 실제 식별자는 공개 화면이나 도움말로 전달되지 않습니다.\n"
        "외부 네트워크나 AI로 전송하지 않습니다.\n"
        "제한된 내부 보고서이며 공유·업로드에 주의하고 사용 후 보존 또는 삭제를 관리해야 합니다.\n"
        "도구는 전달·보관 기간·삭제·백업·클라우드 동기화를 자동 관리하지 않으며, 사용자와 조직 정책에 따라 관리해야 합니다.\n"
        "이 기능은 합성 자료용 pilot이며 실제 자료 export와 조직 운영은 승인되지 않았습니다.\n"
        "실제 사용 전 암호화·보존 정책·인증/RBAC 검토가 필요합니다.\n"
        f"{APPROVAL} 를 입력하면 생성합니다. 취소하려면 그 외의 문구를 입력하십시오."
    )


def export_report(role: str, input_path: str, output_path: str, approval_reader=input) -> tuple[dict, int, str]:
    if role not in {"application", "ssh", "access"}:
        _fail()
    if type(input_path) is not str or not Path(input_path).is_absolute():
        _fail()
    output = Path(output_path)
    if not output.is_absolute():
        _fail()
    if (
        output.suffix != ".json" or not output.name
        or output.name in {".", ".."}
        or any(ord(char) < 0x20 for char in output.name)
    ):
        _fail()
    parent = output.parent
    dir_fd = _open_private_directory(parent)
    report_id = uuid.uuid4().hex
    audit_recorded = False
    audit_failed = False
    published = False
    try:
        try:
            os.stat(output.name, dir_fd=dir_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            # A known existing destination is rejected before consent and leaves
            # both the report and the prior audit record untouched.
            audit_recorded = True
            _fail()
        data, _ = _read_private_input(input_path)
        events = _parse_lines(data, role)
        report = _build_report(role, events)
        report_id = report["report_id"]
        print(_approval_preview(role, report), file=sys.stderr)
        try:
            answer = approval_reader()
        except (EOFError, KeyboardInterrupt):
            # Cancellation must not create or mutate report/audit files.
            audit_recorded = True
            _fail()
        if answer != APPROVAL:
            audit_recorded = True
            _fail()
        _validate_report(report)
        canonical = _canonical_json(report)
        if len(canonical) > MAX_OUTPUT_BYTES:
            _fail()
        digest_basis = dict(report)
        digest_basis.pop("report_id", None)
        digest_basis.pop("generated_at", None)
        digest = hashlib.sha256(_canonical_json(digest_basis)).hexdigest()
        _atomic_publish(dir_fd, output.name, canonical + b"\n")
        published = True
        try:
            _audit_append(dir_fd, {
                "status": "success", "occurred_at": datetime.now(timezone.utc).isoformat(),
                "schema_version": SCHEMA_VERSION, "source_role": role,
                "report_id": report_id, "identifier_counts": _identifier_counts(report),
                "case_count": len(report["cases"]), "relation_count": sum(x["count"] for x in report["relations"]),
                "observation_count": sum(x["count"] for x in report["observations"]),
            })
            audit_recorded = True
        except RestrictedReportError:
            audit_failed = True
            recovery_needed = False
            try:
                os.unlink(output.name, dir_fd=dir_fd)
                os.fsync(dir_fd)
            except OSError:
                recovery_needed = True
            try:
                _audit_append(dir_fd, {
                    "status": "failure", "occurred_at": datetime.now(timezone.utc).isoformat(),
                    "schema_version": SCHEMA_VERSION, "source_role": role,
                    "report_id": report_id, "identifier_counts": _identifier_counts(report),
                    "case_count": len(report["cases"]), "relation_count": sum(x["count"] for x in report["relations"]),
                    "observation_count": sum(x["count"] for x in report["observations"]),
                })
            except RestrictedReportError:
                pass
            _fail(recovery_needed=recovery_needed)
        return report, len(canonical) + 1, digest
    except KeyboardInterrupt:
        recovery_needed = False
        if published and not audit_recorded:
            try:
                os.unlink(output.name, dir_fd=dir_fd)
                os.fsync(dir_fd)
            except OSError:
                recovery_needed = True
        _fail(recovery_needed=recovery_needed)
    except TimeoutError:
        recovery_needed = False
        if published and not audit_recorded:
            try:
                os.unlink(output.name, dir_fd=dir_fd)
                os.fsync(dir_fd)
            except OSError:
                recovery_needed = True
        if not audit_recorded and not audit_failed:
            try:
                _audit_append(dir_fd, {
                    "status": "failure", "occurred_at": datetime.now(timezone.utc).isoformat(),
                    "schema_version": SCHEMA_VERSION, "source_role": role,
                    "report_id": report_id,
                    "identifier_counts": {"account": 0, "ipv4": 0, "ipv6": 0, "hostname": 0},
                    "case_count": 0, "relation_count": 0, "observation_count": 0,
                })
            except RestrictedReportError:
                pass
        _fail(recovery_needed=recovery_needed)
    except RestrictedReportError as exc:
        recovery_needed = exc.recovery_needed
        if published and not audit_recorded and not audit_failed:
            try:
                os.unlink(output.name, dir_fd=dir_fd)
                os.fsync(dir_fd)
            except OSError:
                recovery_needed = True
        if not audit_recorded and not audit_failed:
            try:
                _audit_append(dir_fd, {
                    "status": "failure", "occurred_at": datetime.now(timezone.utc).isoformat(),
                    "schema_version": SCHEMA_VERSION, "source_role": role,
                    "report_id": report_id,
                    "identifier_counts": {"account": 0, "ipv4": 0, "ipv6": 0, "hostname": 0},
                    "case_count": 0, "relation_count": 0, "observation_count": 0,
                })
            except RestrictedReportError:
                pass
        if recovery_needed and not exc.recovery_needed:
            _fail(recovery_needed=True)
        raise
    except Exception:
        recovery_needed = False
        if published and not audit_recorded:
            try:
                os.unlink(output.name, dir_fd=dir_fd)
                os.fsync(dir_fd)
            except OSError:
                recovery_needed = True
        if not audit_recorded and not audit_failed:
            try:
                _audit_append(dir_fd, {
                    "status": "failure", "occurred_at": datetime.now(timezone.utc).isoformat(),
                    "schema_version": SCHEMA_VERSION, "source_role": role,
                    "report_id": report_id,
                    "identifier_counts": {"account": 0, "ipv4": 0, "ipv6": 0, "hostname": 0},
                    "case_count": 0, "relation_count": 0, "observation_count": 0,
                })
            except RestrictedReportError:
                pass
        _fail(recovery_needed=recovery_needed)
    finally:
        os.close(dir_fd)


def _identifier_counts(report: dict) -> dict:
    counts = {"account": 0, "ipv4": 0, "ipv6": 0, "hostname": 0}
    for item in report["subjects"]:
        for identifier in item["identifiers"]:
            counts[identifier["kind"]] += 1
    return counts


class _SafeParser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, "잘못된 제한 보고서 명령입니다.\n")


def main(argv: list[str] | None = None) -> int:
    parser = _SafeParser(prog="python -m app.restricted_report")
    parser.add_argument("--source-role", required=True)
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        def timeout_handler(_signum, _frame):
            raise TimeoutError()

        def terminate_handler(_signum, _frame):
            raise KeyboardInterrupt()

        previous_alarm = signal.signal(signal.SIGALRM, timeout_handler)
        previous_term = signal.signal(signal.SIGTERM, terminate_handler)
        signal.setitimer(signal.ITIMER_REAL, MAX_RUNTIME_SECONDS)
        report, byte_count, digest = export_report(
            args.source_role, args.input, args.output,
        )
    except RestrictedReportError as exc:
        print("제한된 보고서를 생성하지 못했습니다. 입력과 저장 위치를 확인하십시오.", file=sys.stderr)
        if exc.recovery_needed:
            print("보고서 파일이 남아 있을 수 있습니다. 저장 폴더의 상태를 확인하기 전까지 열거나 공유하지 마십시오.", file=sys.stderr)
        return 1
    except Exception:
        print("제한된 보고서를 생성하지 못했습니다. 입력과 저장 위치를 확인하십시오.", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("제한된 보고서 생성을 취소했습니다.", file=sys.stderr)
        return 1
    finally:
        if "previous_alarm" in locals():
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous_alarm)
            signal.signal(signal.SIGTERM, previous_term)
    print(
        f"제한된 보고서를 생성했습니다: ID {report['report_id'][:8]}, "
        f"schema {report['schema_version']}, {byte_count} bytes, SHA-256 {digest[:12]}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
