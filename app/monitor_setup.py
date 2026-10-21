"""Trusted, bounded CLI setup for one application or SSH log."""

import argparse
from dataclasses import dataclass
import json
import os
from pathlib import Path
import secrets
import stat
import sys
from typing import Callable

from app.live_monitoring.config import (
    LiveMonitorConfigV2, LiveMonitorError, _open_regular, _validate_absolute_path,
    load_live_monitor_config, load_live_monitor_setup_config, resolve_default_monitor_config_path,
)
from app.live_monitoring.default_config import open_default_config, source_available
from app.live_monitoring.checkpoint import LiveCheckpointManager, LiveCheckpointError, CHECKPOINT_NAME
from app.live_monitoring.core import LiveTailRecord, MAX_LINE_BYTES
from app.live_monitoring.parser_adapter import parse_live_records


SAMPLE_BYTES = 4096
SAMPLE_LINES = 16
_RECOVERY = {
    "SETUP_CANCELLED": ("설정 생성을 취소했습니다.", "다시 시작하려면 명령을 재실행하십시오.", True),
    "SETUP_INVALID_INPUT": ("입력을 확인하십시오.", "절대 경로와 지원 역할을 확인하십시오.", True),
    "SETUP_UNSUPPORTED_ROLE": ("로그 종류를 선택하지 못했습니다.", "1 또는 2 중 하나만 선택하십시오.", True),
    "SETUP_PATH_MISSING": ("로그 파일을 찾을 수 없습니다.", "존재하는 일반 파일을 선택하십시오.", True),
    "SETUP_PERMISSION_DENIED": ("파일에 접근할 수 없습니다.", "현재 사용자의 권한을 확인하십시오.", True),
    "SETUP_SYMLINK_REJECTED": ("심볼릭 링크를 사용할 수 없습니다.", "일반 파일과 안전한 디렉터리를 선택하십시오.", True),
    "SETUP_NOT_REGULAR_FILE": ("일반 파일이 아닙니다.", "일반 텍스트 로그 파일을 선택하십시오.", True),
    "SETUP_SOURCE_CHANGED": ("검사 중 로그 파일이 교체되었습니다.", "파일 상태를 확인한 뒤 다시 시도하십시오.", True),
    "SETUP_UNSAFE_SOURCE_PARENT": ("로그 파일의 상위 디렉터리가 안전하지 않습니다.", "쓰기 권한을 확인하십시오.", True),
    "SETUP_UNSUPPORTED_OS": ("필수 안전 파일 기능을 사용할 수 없습니다.", "지원 환경에서 다시 실행하십시오.", False),
    "SETUP_BINARY_INPUT": ("텍스트 로그 형식이 아닙니다.", "UTF-8 텍스트 로그를 선택하십시오.", True),
    "SETUP_INVALID_UTF8": ("UTF-8로 읽을 수 없습니다.", "UTF-8 로그를 선택하십시오.", True),
    "SETUP_LINE_TOO_LONG": ("검사 범위에 너무 긴 줄이 있습니다.", "줄 길이를 확인하십시오.", True),
    "SETUP_UNSUPPORTED_FORMAT": ("선택한 로그 형식을 확인하지 못했습니다.", "로그 종류와 형식을 확인하십시오.", True),
    "SETUP_OUTPUT_EXISTS": ("설정 파일이 이미 있습니다.", "기존 설정을 유지합니다. 조회: uv run python -m app.monitor_setup --show. 삭제: uv run python -m app.monitor_setup --delete. 복구 자료 초기화: uv run python -m app.monitor_setup --reset-checkpoint. 삭제와 초기화는 자동 실행하지 않습니다.", True),
    "SETUP_OUTPUT_SYMLINK": ("저장 대상에 심볼릭 링크가 있습니다.", "다른 안전한 저장 위치를 선택하십시오.", True),
    "SETUP_UNSAFE_PARENT": ("안전한 저장 디렉터리를 확인하지 못했습니다.", "사용자 전용 디렉터리를 선택하십시오.", True),
    "SETUP_SAVE_FAILED": ("설정 파일을 저장하지 못했습니다.", "디렉터리 권한과 저장 공간을 확인하십시오.", True),
    "SETUP_POST_WRITE_FAILED": ("저장 후 설정 검증에 실패했습니다.", "설정 파일 상태를 확인하십시오.", False),
    "SETUP_INTERNAL_FAILED": ("설정 준비 중 내부 오류가 발생했습니다.", "다시 시도해도 반복되면 합성 자료로 신고하십시오.", False),
    "DEFAULT_CONFIG_MISSING": ("기본 설정이 없습니다.", "uv run python -m app.monitor_setup 을 실행하십시오.", True),
    "DEFAULT_CONFIG_UNSAFE_PARENT": ("기본 설정 디렉터리가 안전하지 않습니다.", "권한을 수동으로 확인하십시오.", False),
    "DEFAULT_CONFIG_PERMISSION": ("기본 설정의 소유자 또는 권한이 안전하지 않습니다.", "소유자와 0600 권한을 수동으로 확인하십시오.", False),
    "DEFAULT_CONFIG_SYMLINK": ("기본 설정에 심볼릭 링크가 있습니다.", "수동으로 확인하십시오.", False),
    "DEFAULT_CONFIG_TYPE": ("기본 설정은 일반 파일이어야 합니다.", "수동으로 확인하십시오.", False),
    "DEFAULT_CONFIG_TOO_LARGE": ("기본 설정이 너무 큽니다.", "수동으로 확인하십시오.", False),
    "DEFAULT_CONFIG_MALFORMED": ("기본 설정이 손상되었습니다.", "원본을 수동으로 확인하십시오.", False),
    "DEFAULT_CONFIG_SCHEMA": ("기본 설정 버전이 지원되지 않습니다.", "v2 설정을 다시 생성하십시오.", False),
    "DEFAULT_CONFIG_CHANGED": ("검사 중 기본 설정이 변경되었습니다.", "다시 시도하십시오.", True),
    "DEFAULT_CONFIG_DELETE_FAILED": ("기본 설정 삭제에 실패했습니다.", "권한을 확인한 뒤 다시 시도하십시오.", True),
    "DEFAULT_CONFIG_POST_DELETE_FAILED": ("삭제 결과를 확인하지 못했습니다.", "수동으로 확인하십시오.", False),
    "CHECKPOINT_ORPHAN": ("이전에 남은 복구 자료가 있습니다.", "수동으로 상태를 확인하십시오.", False),
    "CHECKPOINT_DELETE_FAILED": ("연결된 복구 자료를 삭제하지 못했습니다.", "수동으로 상태를 확인하십시오.", False),
    "CHECKPOINT_RESET_UNAVAILABLE": ("이 설정에는 복구 자료 초기화 기능이 없습니다.", "설정 정책을 확인하십시오.", False),
    "CHECKPOINT_RESET_MISSING": ("초기화할 복구 자료가 없습니다.", "설정 상태를 확인하십시오.", False),
    "CHECKPOINT_RESET_ACTIVE": ("모니터링 또는 다른 초기화가 복구 자료를 사용 중입니다.", "실행 중인 모니터링을 정상 종료한 뒤 다시 시도하십시오.", True),
    "CHECKPOINT_RESET_UNSAFE": ("복구 자료를 안전하게 검증하지 못했습니다.", "권한과 내용을 수동으로 확인하십시오.", False),
    "CHECKPOINT_RESET_CHANGED": ("승인 전후 복구 자료가 변경되었습니다.", "상태를 확인한 뒤 다시 시도하십시오.", True),
    "CHECKPOINT_RESET_FAILED": ("복구 자료를 삭제하지 못했습니다.", "상태를 수동으로 확인하십시오.", False),
    "CHECKPOINT_RESET_POST_DELETE_FAILED": ("삭제 후 상태를 확인하지 못했습니다.", "자동으로 다시 시작하지 말고 수동으로 확인하십시오.", False),
}


class MonitorSetupError(ValueError):
    def __init__(self, code: str):
        self.code = code if code in _RECOVERY else "SETUP_INTERNAL_FAILED"
        self.description, self.recovery_action, self.retryable = _RECOVERY[self.code]
        super().__init__(f"{self.code}: {self.description} {self.recovery_action}")

    def __repr__(self) -> str:
        return f"MonitorSetupError(code={self.code!r})"


@dataclass(frozen=True, slots=True)
class DryRunSummary:
    inspected_bytes: int
    inspected_lines: int
    parsed_count: int
    ignored_count: int
    rejected_count: int
    partial_line: bool
    empty_source: bool
    sample_limited: bool
    auth_failure_count: int = 0
    auth_success_count: int = 0
    other_ssh_event_count: int = 0


@dataclass(frozen=True, slots=True)
class SetupResult:
    status: str
    source_role: str | None = None
    dry_run: DryRunSummary | None = None


@dataclass(frozen=True, slots=True)
class DefaultConfigSummary:
    schema_version: str
    source_role: str
    enabled: bool
    start_position: str
    parser_timezone: str
    checkpoint_policy: str
    rotation_policy: str
    permission_ok: bool
    source_available: bool
    runnable: bool
    checkpoint_exists: bool = False
    recovery_state: str = "DISABLED"
    bounded_history_count: int = 0


def _safe_path(value: str | Path) -> Path:
    if type(value) is not str and not isinstance(value, Path):
        raise MonitorSetupError("SETUP_INVALID_INPUT")
    raw = os.fspath(value)
    # Terminal drag-and-drop may add one balanced outer quote. No shell parsing.
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in ("'", '"'):
        raw = raw[1:-1]
    if (not raw or raw.startswith("~") or "$" in raw or any(char in raw for char in "*?[]")
        or "://" in raw or "\n" in raw or "\r" in raw):
        raise MonitorSetupError("SETUP_INVALID_INPUT")
    try:
        _validate_absolute_path(raw)
    except LiveMonitorError:
        raise MonitorSetupError("SETUP_INVALID_INPUT") from None
    return Path(raw)


def _same_file(left: os.stat_result, right: os.stat_result) -> bool:
    return (left.st_dev, left.st_ino, left.st_mode, left.st_size,
            left.st_mtime_ns, left.st_ctime_ns) == (
        right.st_dev, right.st_ino, right.st_mode, right.st_size,
        right.st_mtime_ns, right.st_ctime_ns)


def _ssh_source_permissions(path: Path, opened: os.stat_result) -> None:
    if opened.st_uid not in (os.geteuid(), 0):
        raise MonitorSetupError("SETUP_PERMISSION_DENIED")
    for parent in path.parents:
        try:
            metadata = os.stat(parent, follow_symlinks=False)
        except OSError:
            raise MonitorSetupError("SETUP_UNSAFE_SOURCE_PARENT") from None
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise MonitorSetupError("SETUP_UNSAFE_SOURCE_PARENT")
        if metadata.st_mode & 0o022:
            # The system sticky temporary root can contain a private subtree.
            if not (metadata.st_uid == 0 and metadata.st_mode & stat.S_ISVTX):
                raise MonitorSetupError("SETUP_UNSAFE_SOURCE_PARENT")


def _source_descriptor(path: Path, role: str = "application") -> tuple[int, os.stat_result]:
    try:
        before = os.stat(path, follow_symlinks=False)
    except FileNotFoundError:
        raise MonitorSetupError("SETUP_PATH_MISSING") from None
    except PermissionError:
        raise MonitorSetupError("SETUP_PERMISSION_DENIED") from None
    except OSError:
        raise MonitorSetupError("SETUP_NOT_REGULAR_FILE") from None
    if stat.S_ISLNK(before.st_mode):
        raise MonitorSetupError("SETUP_SYMLINK_REJECTED")
    if not stat.S_ISREG(before.st_mode):
        raise MonitorSetupError("SETUP_NOT_REGULAR_FILE")
    try:
        fd, opened = _open_regular(path)
    except LiveMonitorError as error:
        code = {
            "SYMLINK_REJECTED": "SETUP_SYMLINK_REJECTED",
            "NON_REGULAR_SOURCE": "SETUP_NOT_REGULAR_FILE",
            "PERMISSION_DENIED": "SETUP_PERMISSION_DENIED",
            "UNSAFE_PLATFORM": "SETUP_UNSUPPORTED_OS",
        }.get(error.code, "SETUP_SOURCE_CHANGED")
        raise MonitorSetupError(code) from None
    if not _same_file(before, opened):
        os.close(fd)
        raise MonitorSetupError("SETUP_SOURCE_CHANGED")
    if role == "ssh":
        try:
            _ssh_source_permissions(path, opened)
        except MonitorSetupError:
            os.close(fd)
            raise
    return fd, opened


def _validate_source_unchanged(path: Path, fd: int, opened: os.stat_result) -> None:
    try:
        current = os.stat(path, follow_symlinks=False)
        descriptor = os.fstat(fd)
    except OSError:
        raise MonitorSetupError("SETUP_SOURCE_CHANGED") from None
    if not _same_file(opened, current) or not _same_file(opened, descriptor):
        raise MonitorSetupError("SETUP_SOURCE_CHANGED")


def _inspect(fd: int, path: Path, opened: os.stat_result,
             role: str = "application") -> DryRunSummary:
    try:
        sample = os.read(fd, SAMPLE_BYTES)
    except OSError:
        raise MonitorSetupError("SETUP_SOURCE_CHANGED") from None
    if len(sample) > SAMPLE_BYTES:
        raise MonitorSetupError("SETUP_INTERNAL_FAILED")
    if b"\x00" in sample or any((byte < 32 and byte not in (9, 10, 13)) or byte == 127 for byte in sample):
        raise MonitorSetupError("SETUP_BINARY_INPUT")
    # Complete lines alone are parser inputs. A bounded sample may end mid-line.
    chunks = sample.split(b"\n")
    complete = chunks[:-1]
    partial = chunks[-1]
    line_limit_reached = len(complete) > SAMPLE_LINES
    if len(complete) > SAMPLE_LINES:
        complete = complete[:SAMPLE_LINES]
    if any(len(chunk) > MAX_LINE_BYTES for chunk in complete) or len(partial) > MAX_LINE_BYTES:
        raise MonitorSetupError("SETUP_LINE_TOO_LONG")
    records = []
    for sequence, line in enumerate(complete, 1):
        if b"\r" in line[:-1]:
            raise MonitorSetupError("SETUP_BINARY_INPUT")
        if line.endswith(b"\r"):
            line = line[:-1]
        try:
            decoded = line.decode("utf-8", errors="strict")
        except UnicodeError:
            raise MonitorSetupError("SETUP_INVALID_UTF8") from None
        records.append(LiveTailRecord(role, sequence, decoded, len(line)))
    if partial and opened.st_size <= SAMPLE_BYTES:
        try:
            partial.decode("utf-8", errors="strict")
        except UnicodeError:
            raise MonitorSetupError("SETUP_INVALID_UTF8") from None
    try:
        batch = parse_live_records(role, tuple(records))
    except Exception:
        raise MonitorSetupError("SETUP_UNSUPPORTED_FORMAT") from None
    _validate_source_unchanged(path, fd, opened)
    if complete and not batch.parsed_count and batch.rejected_count:
        raise MonitorSetupError("SETUP_UNSUPPORTED_FORMAT")
    failures = successes = others = 0
    if role == "ssh":
        for outcome in batch.outcomes:
            if outcome.status != "PARSED":
                continue
            authentication = outcome.event.authentication
            kind = authentication.outcome if authentication is not None else None
            if kind == "failure":
                failures += 1
            elif kind == "success":
                successes += 1
            else:
                others += 1
    return DryRunSummary(len(sample), len(complete), batch.parsed_count,
                         batch.ignored_count, batch.rejected_count,
                         bool(partial), opened.st_size == 0,
                         opened.st_size > SAMPLE_BYTES or line_limit_reached,
                         failures, successes, others)


def dry_run_application(path: str | Path) -> DryRunSummary:
    source = _safe_path(path)
    fd, opened = _source_descriptor(source)
    try:
        return _inspect(fd, source, opened)
    finally:
        os.close(fd)


def _preview_source(path: Path, role: str = "application") -> tuple[DryRunSummary, tuple[int, int, int, int, int]]:
    fd, opened = _source_descriptor(path, role)
    try:
        summary = _inspect(fd, path, opened, role)
        return summary, (opened.st_dev, opened.st_ino, opened.st_size,
                         opened.st_mtime_ns, opened.st_ctime_ns)
    finally:
        os.close(fd)


def _default_output() -> Path:
    try:
        return resolve_default_monitor_config_path()
    except LiveMonitorError as error:
        raise MonitorSetupError("SETUP_UNSUPPORTED_OS" if error.code == "UNSAFE_PLATFORM"
                                else "SETUP_INVALID_INPUT") from None


def _management_path(path: Path | None) -> Path:
    return path if path is not None else _default_output()


def _management_error(error: LiveMonitorError) -> MonitorSetupError:
    return MonitorSetupError(error.code)


def show_default_config(path: Path | None = None) -> DefaultConfigSummary:
    try:
        with open_default_config(_management_path(path)) as guard:
            available = source_available(guard.config)
            checkpoint_exists = False
            history_count = 0
            recovery_state = "DISABLED"
            if guard.config.checkpoint_policy == "BOUNDED_REPLAY_V1":
                try:
                    with_checkpoint = LiveCheckpointManager(guard.path, guard.config, readonly=True)
                    try:
                        checkpoint_exists = with_checkpoint._checkpoint is not None
                        history_count = (with_checkpoint._checkpoint.history_count
                                         if checkpoint_exists else 0)
                        recovery_state = "RECOVERABLE" if checkpoint_exists else "FIRST_START"
                    finally:
                        with_checkpoint.close()
                except LiveCheckpointError:
                    recovery_state = "NEEDS_REVIEW"
            guard.check()
            config = guard.config
            return DefaultConfigSummary(config.schema_version, config.source_role,
                                        config.enabled, config.start_position,
                                        config.parser_timezone, config.checkpoint_policy,
                                        config.rotation_policy, True, available,
                                        available and recovery_state != "NEEDS_REVIEW",
                                        checkpoint_exists, recovery_state, history_count)
    except LiveMonitorError as error:
        raise _management_error(error) from None


def delete_default_config(path: Path | None = None, *,
                          ask: Callable[[str], str] = input,
                          emit: Callable[[str], None] = print) -> SetupResult:
    try:
        with open_default_config(_management_path(path)) as guard:
            guard.check()
            config = guard.config
            checkpoint = None
            role_name = {"application": "애플리케이션 로그인 로그",
                         "ssh": "SSH 인증 로그"}[config.source_role]
            emit(f"{role_name}용 기본 설정과 연결된 복구 자료를 삭제합니다. "
                 "원본 로그 파일은 삭제하지 않습니다.")
            emit("삭제 후 --monitor는 설정을 다시 만들 때까지 실행되지 않습니다.")
            try:
                if not _approved(ask("기본 모니터링 설정을 삭제하시겠습니까? [y/N] ")):
                    emit("기본 설정 삭제를 취소했습니다.")
                    return SetupResult("CANCELLED")
                guard.check()
                if config.checkpoint_policy == "BOUNDED_REPLAY_V1":
                    try:
                        checkpoint = LiveCheckpointManager(guard.path, config)
                    except LiveCheckpointError:
                        raise MonitorSetupError("CHECKPOINT_DELETE_FAILED") from None
                guard.check()
                guard.unlink()
                if checkpoint is not None:
                    try:
                        checkpoint.delete_after_config()
                    except LiveCheckpointError:
                        raise MonitorSetupError("CHECKPOINT_DELETE_FAILED") from None
                emit("기본 설정 삭제 완료. 원본 로그는 삭제하지 않았습니다.")
                emit("다시 설정하려면 uv run python -m app.monitor_setup 을 실행하십시오.")
                return SetupResult("DELETED", config.source_role)
            finally:
                if checkpoint is not None:
                    checkpoint.close()
    except LiveMonitorError as error:
        raise _management_error(error) from None


def reset_default_checkpoint(path: Path | None = None, *,
                             ask: Callable[[str], str] = input,
                             emit: Callable[[str], None] = print) -> SetupResult:
    """Explicitly abandon one default-config checkpoint; never start a monitor."""
    try:
        with open_default_config(_management_path(path)) as guard:
            guard.check()
            if guard.config.checkpoint_policy != "BOUNDED_REPLAY_V1":
                raise MonitorSetupError("CHECKPOINT_RESET_UNAVAILABLE")
            try:
                checkpoint = LiveCheckpointManager(guard.path, guard.config)
            except LiveCheckpointError as error:
                code = ("CHECKPOINT_RESET_ACTIVE" if error.code == "CHECKPOINT_ALREADY_OWNED"
                        else "CHECKPOINT_RESET_UNSAFE")
                raise MonitorSetupError(code) from None
            try:
                if checkpoint._checkpoint is None:
                    raise MonitorSetupError("CHECKPOINT_RESET_MISSING")
                try:
                    identity = checkpoint._reset_identity()
                except LiveCheckpointError:
                    raise MonitorSetupError("CHECKPOINT_RESET_UNSAFE") from None
                emit("연결된 복구 자료 1개만 삭제합니다. 과거 분석 결과와 알림 연속성은 이어받지 않습니다.")
                emit("다음 모니터링은 원본 로그의 현재 파일 끝에서 새 줄부터 시작합니다. 중단된 동안의 줄은 분석하지 않으며 누락 없는 처리를 보장하지 않습니다.")
                emit("원본 로그와 모니터링 설정, 다른 파일은 삭제하지 않습니다. 설정을 다시 만들 필요는 없습니다.")
                try:
                    answer = ask("복구 자료 1개를 삭제하고 다음 모니터링을 새로 시작하시겠습니까? [y/N] ")
                except (EOFError, KeyboardInterrupt):
                    answer = ""
                if not _approved(answer):
                    emit("복구 자료 초기화를 취소했습니다.")
                    return SetupResult("CANCELLED")
                guard.check()
                try:
                    checkpoint.reset_after_approval(identity)
                except LiveCheckpointError as error:
                    code = ("CHECKPOINT_RESET_CHANGED" if error.code == "CHECKPOINT_IDENTITY_CHANGED"
                            else "CHECKPOINT_RESET_POST_DELETE_FAILED" if error.code == "CHECKPOINT_POST_DELETE_FAILED"
                            else "CHECKPOINT_RESET_UNSAFE" if error.code in (
                                "CHECKPOINT_CORRUPT", "CHECKPOINT_UNSAFE")
                            else "CHECKPOINT_RESET_FAILED")
                    raise MonitorSetupError(code) from None
                try:
                    guard.check()
                except LiveMonitorError:
                    raise MonitorSetupError("CHECKPOINT_RESET_POST_DELETE_FAILED") from None
                emit("복구 자료 1개를 삭제했습니다. 원본 로그와 설정은 삭제하지 않았습니다.")
                emit("모니터링은 자동 시작하지 않습니다. uv run python -m app.local_web --monitor 로 새 분석을 시작하십시오.")
                emit("이 삭제는 secure erase가 아니며 backup·filesystem snapshot·crash dump에 이전 자료가 남을 수 있습니다.")
                return SetupResult("RESET", guard.config.source_role)
            finally:
                checkpoint.close()
    except LiveMonitorError as error:
        raise _management_error(error) from None


def _private_parent(path: Path) -> tuple[int, list[Path]]:
    """Walk by descriptor; create only missing private directories."""
    if not all(hasattr(os, key) for key in ("O_NOFOLLOW", "O_DIRECTORY", "O_CLOEXEC")):
        raise MonitorSetupError("SETUP_UNSUPPORTED_OS")
    fd = -1
    created: list[Path] = []
    try:
        fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        current = Path("/")
        for component in path.parts[1:-1]:
            current = current / component
            try:
                metadata = os.stat(component, dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError:
                os.mkdir(component, mode=0o700, dir_fd=fd)
                created.append(current)
                metadata = os.stat(component, dir_fd=fd, follow_symlinks=False)
            if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                raise MonitorSetupError("SETUP_UNSAFE_PARENT")
            next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                              dir_fd=fd)
            if (os.fstat(next_fd).st_dev, os.fstat(next_fd).st_ino) != (metadata.st_dev, metadata.st_ino):
                os.close(next_fd)
                raise MonitorSetupError("SETUP_UNSAFE_PARENT")
            os.close(fd)
            fd = next_fd
        parent = os.fstat(fd)
        if parent.st_uid != os.geteuid() or parent.st_mode & 0o077:
            raise MonitorSetupError("SETUP_UNSAFE_PARENT")
        return fd, created
    except MonitorSetupError:
        if fd >= 0:
            os.close(fd)
        for directory in reversed(created):
            try:
                directory.rmdir()
            except OSError:
                break
        raise
    except OSError:
        if fd >= 0:
            os.close(fd)
        for directory in reversed(created):
            try:
                directory.rmdir()
            except OSError:
                break
        raise MonitorSetupError("SETUP_UNSAFE_PARENT") from None


def _parent_identity(path: Path, fd: int) -> None:
    try:
        parent = os.stat(path.parent, follow_symlinks=False)
        opened = os.fstat(fd)
    except OSError:
        raise MonitorSetupError("SETUP_UNSAFE_PARENT") from None
    if (parent.st_dev, parent.st_ino) != (opened.st_dev, opened.st_ino):
        raise MonitorSetupError("SETUP_UNSAFE_PARENT")


def _save_private(document: LiveMonitorConfigV2, output: Path,
                  source_guard: Callable[[], None]) -> None:
    encoded = (json.dumps(document.as_document(), ensure_ascii=False, sort_keys=True,
                          separators=(",", ":")) + "\n").encode("utf-8")
    if len(encoded) > 4096:
        raise MonitorSetupError("SETUP_SAVE_FAILED")
    parent_fd, created = _private_parent(output)
    temp_name = None
    published = False
    completed = False
    published_identity = None
    try:
        _parent_identity(output, parent_fd)
        source_guard()
        try:
            existing = os.stat(output.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise MonitorSetupError("SETUP_OUTPUT_SYMLINK" if stat.S_ISLNK(existing.st_mode)
                                    else "SETUP_OUTPUT_EXISTS")
        if document.checkpoint_policy == "BOUNDED_REPLAY_V1":
            try:
                os.stat(CHECKPOINT_NAME, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise MonitorSetupError("CHECKPOINT_ORPHAN")
        temp_name = ".monitor-" + secrets.token_hex(8)
        fd = os.open(temp_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=parent_fd)
        try:
            os.fchmod(fd, 0o600)
            if os.fstat(fd).st_mode & 0o777 != 0o600:
                raise MonitorSetupError("SETUP_SAVE_FAILED")
            written = 0
            while written < len(encoded):
                count = os.write(fd, encoded[written:])
                if count <= 0:
                    raise MonitorSetupError("SETUP_SAVE_FAILED")
                written += count
            os.fsync(fd)
        finally:
            os.close(fd)
        _parent_identity(output, parent_fd)
        try:
            temporary = os.stat(temp_name, dir_fd=parent_fd, follow_symlinks=False)
            os.link(temp_name, output.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd,
                    follow_symlinks=False)
        except FileExistsError:
            raise MonitorSetupError("SETUP_OUTPUT_EXISTS") from None
        published = True
        published_identity = (temporary.st_dev, temporary.st_ino)
        source_guard()
        try:
            verified = load_live_monitor_setup_config(output)
            runtime = load_live_monitor_config(output)
        except LiveMonitorError:
            raise MonitorSetupError("SETUP_POST_WRITE_FAILED") from None
        if verified != document or runtime.role != document.source_role:
            raise MonitorSetupError("SETUP_POST_WRITE_FAILED")
        final_stat = os.stat(output.name, dir_fd=parent_fd, follow_symlinks=False)
        if final_stat.st_uid != os.geteuid() or final_stat.st_mode & 0o777 != 0o600:
            raise MonitorSetupError("SETUP_POST_WRITE_FAILED")
        os.unlink(temp_name, dir_fd=parent_fd)
        temp_name = None
        os.fsync(parent_fd)
        completed = True
    except MonitorSetupError:
        raise
    except (OSError, LiveMonitorError):
        raise MonitorSetupError("SETUP_SAVE_FAILED") from None
    finally:
        if published and not completed:
            # A failed post-publish validation never leaves a partial final file.
            # The success path is distinguished by temp_name being cleared.
            try:
                final = os.stat(output.name, dir_fd=parent_fd, follow_symlinks=False)
                if (final.st_dev, final.st_ino) == published_identity:
                    os.unlink(output.name, dir_fd=parent_fd)
            except OSError:
                pass
        if temp_name is not None:
            try:
                os.unlink(temp_name, dir_fd=parent_fd)
            except OSError:
                pass
        os.close(parent_fd)
        for directory in reversed(created):
            try:
                directory.rmdir()
            except OSError:
                break


def create_monitor_config(source: str | Path, output: str | Path, *,
                          role: str = "application",
                          _expected_identity: tuple[int, int, int, int, int] | None = None) -> DryRunSummary:
    if type(role) is not str or role not in ("application", "ssh"):
        raise MonitorSetupError("SETUP_UNSUPPORTED_ROLE")
    source_path = _safe_path(source)
    output_path = _safe_path(output)
    fd, opened = _source_descriptor(source_path, role)
    try:
        if (_expected_identity is not None and
            (opened.st_dev, opened.st_ino, opened.st_size,
             opened.st_mtime_ns, opened.st_ctime_ns) != _expected_identity):
            raise MonitorSetupError("SETUP_SOURCE_CHANGED")
        summary = _inspect(fd, source_path, opened, role)
        _validate_source_unchanged(source_path, fd, opened)
        if role == "ssh":
            _ssh_source_permissions(source_path, opened)
        document = LiveMonitorConfigV2(
            source_path, source_role=role,
            display_alias="SSH 로그 1" if role == "ssh" else "애플리케이션 로그 1",
            checkpoint_policy="BOUNDED_REPLAY_V1",
        )
        def source_guard() -> None:
            _validate_source_unchanged(source_path, fd, opened)
            if role == "ssh":
                _ssh_source_permissions(source_path, opened)

        _save_private(document, output_path, source_guard)
        return summary
    finally:
        os.close(fd)


def _approved(value: str) -> bool:
    return type(value) is str and value.strip().lower() in ("y", "yes")


def run_setup(*, output: str | Path | None = None,
              ask: Callable[[str], str] = input,
              emit: Callable[[str], None] = print) -> SetupResult:
    emit("로컬 파일의 새 줄만 모니터링하는 설정을 만듭니다. 기존 줄은 읽지 않습니다.")
    emit("원문은 브라우저 결과에 표시하지 않지만 분석 중 내부 메모리에 존재할 수 있습니다.")
    emit("설정에는 로그 경로가 저장됩니다. 공유하지 마세요. 외부 LLM으로 자동 전송하지 않습니다.")
    if not _approved(ask("계속하시겠습니까? [y/N] ")):
        emit("설정 생성을 취소했습니다.")
        return SetupResult("CANCELLED")
    emit("로그 종류를 하나 선택하십시오: 1 애플리케이션 로그인 로그, 2 SSH 인증 로그.")
    choice = ask("로그 종류 [1/2]: ").strip()
    role = {"1": "application", "2": "ssh", "application": "application", "ssh": "ssh"}.get(choice)
    if role is None:
        raise MonitorSetupError("SETUP_UNSUPPORTED_ROLE")
    source = _safe_path(ask("로그 파일의 절대 경로: "))
    summary, expected_identity = _preview_source(source, role)
    destination = _safe_path(output) if output is not None else _default_output()
    emit("선택한 로그 종류: " + ("SSH 인증 로그" if role == "ssh" else "애플리케이션 로그인 로그") + ".")
    emit("기존 줄은 처리하지 않고 다음 새 줄부터 모니터링합니다. 설정은 사용자 전용 파일로 저장됩니다.")
    if output is None:
        emit("기본 --monitor 실행은 같은 파일의 bounded 재시작 복구를 사용합니다.")
    else:
        emit("사용자 지정 --output은 재시작 복구 대상이 아닙니다. 명시적 경로 실행은 매번 FROM_END입니다.")
    emit(f"제한된 형식 검사: {summary.inspected_bytes} byte, 완성 {summary.inspected_lines}줄, "
         f"형식 인식 {summary.parsed_count}건, 무시 {summary.ignored_count}건, "
         f"형식 미확인 {summary.rejected_count}건.")
    if role == "ssh":
        emit(f"형식 검사: 인증 실패 {summary.auth_failure_count}건, 성공 기록 {summary.auth_success_count}건, "
             f"그 밖의 SSH 기록 {summary.other_ssh_event_count}건, 무시 {summary.ignored_count}건, "
             f"형식 미확인 {summary.rejected_count}건.")
        if not summary.auth_failure_count and not summary.auth_success_count:
            emit("검사 범위에서 인증 기록을 확인하지 못했습니다.")
    emit("이 검사는 일부 기존 줄의 형식만 확인합니다. 탐지율, 공격 성공, 침해 여부나 운영 호환성을 보장하지 않습니다.")
    if summary.empty_source or not summary.inspected_lines:
        emit("완성된 기존 줄이 없어 형식을 확인하지 못했습니다. 새 줄이 생긴 뒤 확인하십시오.")
    if summary.partial_line or summary.sample_limited:
        emit("미완성 줄이나 검사 상한 밖의 내용은 확인하지 않았습니다.")
    emit("기존 줄은 분석하지 않으며, 로그 경로는 private config에 저장됩니다.")
    if not _approved(ask("이 설정을 저장하시겠습니까? [y/N] ")):
        emit("설정 생성을 취소했습니다.")
        return SetupResult("CANCELLED", role, summary)
    saved = create_monitor_config(source, destination, role=role,
                                  _expected_identity=expected_identity)
    emit("설정 생성 완료. 새 줄부터 시작합니다. 외부 LLM 자동 전송은 없습니다.")
    emit("설정 파일을 공유하지 마세요. 서버 종료는 Ctrl+C입니다.")
    if output is None:
        emit("실행 명령:")
        emit("uv run python -m app.local_web --monitor")
    else:
        emit("사용자 지정 --output은 기본 checkpoint 대상이 아닙니다. 명시적 경로 실행은 재시작 때 FROM_END입니다.")
        emit("실행하려면 명시적 --monitor-config 경로를 직접 지정하십시오. 경로는 shell history와 프로세스 목록에 남을 수 있습니다.")
    return SetupResult("CREATED", role, saved)


class _SetupParser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        raise MonitorSetupError("SETUP_INVALID_INPUT")


def main(argv: list[str] | None = None, *, ask: Callable[[str], str] = input,
         emit: Callable[[str], None] = print) -> int:
    parser = _SetupParser(
        description="단일 application 또는 SSH 로그의 로컬 모니터링 설정 생성",
        epilog="예: uv run python -m app.monitor_setup --show | --delete | --reset-checkpoint",
    )
    parser.add_argument("--output", metavar="/absolute/path/to/monitoring.json")
    parser.add_argument("--no-color", action="store_true", help="색상 출력 없이 실행 (기본값)")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--show", action="store_true", help="기본 설정의 안전한 요약 조회")
    mode.add_argument("--delete", action="store_true", help="기본 설정 하나만 승인 후 삭제")
    mode.add_argument("--reset-checkpoint", action="store_true",
                      help="명시적 승인 후 연결된 복구 자료 하나만 삭제하고 새 분석 epoch 준비")
    try:
        args = parser.parse_args(argv)
        if args.output is not None and (args.show or args.delete or args.reset_checkpoint):
            raise MonitorSetupError("SETUP_INVALID_INPUT")
        if args.show:
            summary = show_default_config()
            role_name = {"application": "애플리케이션 로그인 로그",
                         "ssh": "SSH 인증 로그"}[summary.source_role]
            emit(f"기본 설정: 설정 버전: {summary.schema_version}, 로그 종류: {role_name}.")
            emit(f"모니터링 설정: {'켜짐' if summary.enabled else '꺼짐'}. "
                 "시작 방식: 기존 줄은 처리하지 않고 새 줄부터 시작합니다.")
            recovery_policy = ("같은 파일의 제한된 이력 복구" if summary.checkpoint_policy == "BOUNDED_REPLAY_V1"
                               else "재시작할 때 현재 파일 끝부터 새로 시작")
            emit(f"시간 기준: {summary.parser_timezone}. 재시작: {recovery_policy}. "
                 "파일 교체·길이 축소 시 자동 이어받지 않습니다.")
            emit(f"설정 권한: {'적합' if summary.permission_ok else '검토 필요'}. "
                 f"원본 로그: {'사용 가능' if summary.source_available else '확인 필요'}.")
            if summary.recovery_state == "NEEDS_REVIEW":
                emit("복구 자료: 검토 필요. 존재·이력 확인 불가.")
            elif summary.recovery_state == "RECOVERABLE":
                emit(f"복구 자료: 정상. 이전 분석 상태를 복구할 수 있습니다. "
                     f"제한된 이력 {summary.bounded_history_count}건.")
            elif summary.recovery_state == "FIRST_START":
                emit("복구 자료: 없음. 첫 실행은 현재 파일의 새 줄부터 시작합니다.")
            else:
                emit("복구 자료: 사용하지 않음.")
            if summary.runnable and summary.enabled:
                emit("다음 행동: uv run python -m app.local_web --monitor")
            elif summary.recovery_state == "NEEDS_REVIEW":
                emit("다음 행동: 복구 자료를 수동으로 확인하십시오. 자동 초기화하지 않습니다.")
            elif not summary.source_available:
                emit("다음 행동: 원본 로그의 접근 가능 여부를 수동으로 확인하십시오.")
            else:
                emit("다음 행동: 설정 상태를 수동으로 확인하십시오.")
            return 0
        if args.delete:
            delete_default_config(ask=ask, emit=emit)
            return 0
        if args.reset_checkpoint:
            reset_default_checkpoint(ask=ask, emit=emit)
            return 0
        run_setup(output=args.output, ask=ask, emit=emit)
        return 0
    except MonitorSetupError as error:
        print(str(error), file=sys.stderr)
        return (2 if error.code in ("SETUP_INVALID_INPUT", "SETUP_UNSUPPORTED_ROLE") else
                3 if error.code in ("SETUP_PATH_MISSING", "SETUP_PERMISSION_DENIED",
                                   "SETUP_SYMLINK_REJECTED", "SETUP_NOT_REGULAR_FILE",
                                   "SETUP_SOURCE_CHANGED", "SETUP_UNSAFE_SOURCE_PARENT", "SETUP_UNSUPPORTED_OS",
                                   "SETUP_BINARY_INPUT", "SETUP_INVALID_UTF8", "SETUP_LINE_TOO_LONG",
                                   "SETUP_UNSUPPORTED_FORMAT") else
                3 if error.code.startswith("DEFAULT_CONFIG_") and error.code not in (
                    "DEFAULT_CONFIG_DELETE_FAILED", "DEFAULT_CONFIG_POST_DELETE_FAILED") else
                3 if error.code in ("CHECKPOINT_RESET_UNAVAILABLE", "CHECKPOINT_RESET_MISSING",
                                    "CHECKPOINT_RESET_ACTIVE", "CHECKPOINT_RESET_UNSAFE",
                                    "CHECKPOINT_RESET_CHANGED") else
                1 if error.code == "SETUP_INTERNAL_FAILED" else 4)
    except (EOFError, KeyboardInterrupt):
        print("SETUP_CANCELLED: 설정 생성을 취소했습니다.")
        return 0
    except Exception:
        print(str(MonitorSetupError("SETUP_INTERNAL_FAILED")), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
