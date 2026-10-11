"""Closed local configuration and descriptor-based regular-file opening."""

from dataclasses import dataclass, field
import errno
import json
import os
from pathlib import Path
import stat


CONFIG_MAX_BYTES = 4096
ROLES = frozenset(("application", "ssh", "access"))


_MESSAGES = {
    "INVALID_CONFIG": "모니터링 설정 형식을 확인하십시오.",
    "CONFIG_TOO_LARGE": "모니터링 설정 파일이 너무 큽니다.",
    "DUPLICATE_JSON_KEY": "모니터링 설정에 중복된 항목이 있습니다.",
    "UNSUPPORTED_SCHEMA": "지원하는 설정 버전을 사용하십시오.",
    "UNSUPPORTED_ROLE": "지원하는 로그 역할을 선택하십시오.",
    "UNSUPPORTED_START_POLICY": "FROM_END 시작 정책을 사용하십시오.",
    "NON_ABSOLUTE_PATH": "절대 경로를 지정하십시오.",
    "CONFIG_UNAVAILABLE": "모니터링 설정 파일을 확인하십시오.",
    "SOURCE_UNAVAILABLE": "로그 파일의 접근 가능 여부를 확인하십시오.",
    "SYMLINK_REJECTED": "심볼릭 링크가 아닌 일반 파일을 선택하십시오.",
    "NON_REGULAR_SOURCE": "일반 로그 파일을 선택하십시오.",
    "PERMISSION_DENIED": "파일 읽기 권한을 확인하십시오.",
    "UNSAFE_PLATFORM": "이 플랫폼에서는 안전한 파일 열기를 지원하지 않습니다.",
    "INVALID_UTF8": "UTF-8 텍스트 로그를 사용하십시오.",
    "BINARY_INPUT": "바이너리가 아닌 텍스트 로그를 사용하십시오.",
    "LINE_TOO_LONG": "줄 길이가 짧은 로그를 사용하십시오.",
    "PARTIAL_BUFFER_EXCEEDED": "완성되지 않은 긴 줄을 줄이십시오.",
    "QUEUE_OVERFLOW": "대기 중인 기록을 처리한 뒤 세션을 다시 시작하십시오.",
    "SOURCE_TRUNCATED": "파일이 잘렸습니다. 세션을 다시 시작하십시오.",
    "SOURCE_REPLACED": "파일이 교체되었습니다. 세션을 다시 시작하십시오.",
    "INVALID_STATE_TRANSITION": "세션 상태를 확인하십시오.",
    "POLL_AFTER_CLOSE": "닫힌 세션을 다시 열어 시작하십시오.",
    "INTERNAL_FAILURE": "모니터링을 중단하고 다시 시작하십시오.",
    "COUNTER_LIMIT": "세션을 종료하고 다시 시작하십시오.",
    "INVALID_LEASE_LIMIT": "한 번에 처리할 기록 한도를 확인하십시오.",
    "LEASE_LIMIT_TOO_SMALL": "첫 대기 기록을 담을 수 있는 byte 한도를 지정하십시오.",
    "LEASE_UNAVAILABLE": "처리할 대기 기록이 없습니다.",
    "ACTIVE_LEASE_EXISTS": "현재 처리 중인 기록을 먼저 완료하십시오.",
    "FOREIGN_LEASE": "다른 세션의 처리 권한은 사용할 수 없습니다.",
    "STALE_LEASE": "만료된 처리 권한은 사용할 수 없습니다.",
    "FORGED_LEASE": "처리 권한 식별자를 확인하십시오.",
    "LEASE_INVARIANT_MISMATCH": "처리 권한의 기록 구성을 확인하십시오.",
    "ACK_AFTER_ACK": "이미 완료된 처리 권한입니다.",
    "RELEASE_AFTER_RELEASE": "이미 반환된 처리 권한입니다.",
    "ACK_AFTER_RELEASE": "반환된 처리 권한은 완료할 수 없습니다.",
    "RELEASE_AFTER_ACK": "완료된 처리 권한은 반환할 수 없습니다.",
    "OPERATION_AFTER_CLOSE": "닫힌 세션의 처리 권한은 사용할 수 없습니다.",
    "INTERNAL_OWNERSHIP_FAILURE": "기록 처리를 중단하고 세션을 다시 시작하십시오.",
    "CLOSE_INVALID_OWNERSHIP": "미완료 기록 상태를 확인한 뒤 세션을 다시 시작하십시오.",
}


class LiveMonitorError(ValueError):
    """Fixed-code error without source values, OS paths, or exception text."""

    def __init__(self, code: str):
        if code not in _MESSAGES:
            code = "INTERNAL_FAILURE"
        self.code = code
        super().__init__(f"{code}: {_MESSAGES[code]}")

    def __repr__(self) -> str:
        return f"LiveMonitorError(code={self.code!r})"


@dataclass(frozen=True, slots=True)
class LiveMonitorConfig:
    role: str
    path: Path = field(repr=False)
    schema_version: str = "1"
    start_policy: str = "FROM_END"

    def __post_init__(self) -> None:
        if type(self.role) is not str or self.role not in ROLES:
            raise LiveMonitorError("UNSUPPORTED_ROLE")
        if not isinstance(self.path, Path):
            raise LiveMonitorError("NON_ABSOLUTE_PATH")
        _validate_absolute_path(os.fspath(self.path))
        if type(self.schema_version) is not str or self.schema_version != "1":
            raise LiveMonitorError("UNSUPPORTED_SCHEMA")
        if type(self.start_policy) is not str or self.start_policy != "FROM_END":
            raise LiveMonitorError("UNSUPPORTED_START_POLICY")


def _validate_absolute_path(value: str) -> None:
    if (
        type(value) is not str
        or not value.startswith("/")
        or value == "/"
        or "\x00" in value
        or any(part in ("", ".", "..") for part in value[1:].split("/"))
    ):
        raise LiveMonitorError("NON_ABSOLUTE_PATH")


def _open_regular(path: Path, *, config_file: bool = False) -> tuple[int, os.stat_result]:
    """Walk an absolute path without following parent or final symlinks."""
    if not all(hasattr(os, name) for name in (
        "O_NOFOLLOW", "O_DIRECTORY", "O_NONBLOCK", "O_CLOEXEC",
    )):
        raise LiveMonitorError("UNSAFE_PLATFORM")
    _validate_absolute_path(os.fspath(path))
    parts = os.fspath(path)[1:].split("/")
    kind = "CONFIG_UNAVAILABLE" if config_file else "SOURCE_UNAVAILABLE"
    root_fd = -1
    file_fd = -1
    try:
        root_fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        for component in parts[:-1]:
            metadata = os.stat(component, dir_fd=root_fd, follow_symlinks=False)
            if stat.S_ISLNK(metadata.st_mode):
                raise LiveMonitorError("SYMLINK_REJECTED")
            next_fd = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=root_fd,
            )
            os.close(root_fd)
            root_fd = next_fd
        metadata = os.stat(parts[-1], dir_fd=root_fd, follow_symlinks=False)
        if stat.S_ISLNK(metadata.st_mode):
            raise LiveMonitorError("SYMLINK_REJECTED")
        file_fd = os.open(
            parts[-1],
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
            dir_fd=root_fd,
        )
        opened = os.fstat(file_fd)
        if not stat.S_ISREG(opened.st_mode):
            raise LiveMonitorError("INVALID_CONFIG" if config_file else "NON_REGULAR_SOURCE")
        if config_file:
            if opened.st_uid != os.geteuid() or opened.st_mode & 0o077:
                raise LiveMonitorError("PERMISSION_DENIED")
        elif opened.st_mode & 0o022:
            raise LiveMonitorError("PERMISSION_DENIED")
        result = file_fd, opened
        file_fd = -1
        return result
    except LiveMonitorError:
        raise
    except PermissionError:
        raise LiveMonitorError("PERMISSION_DENIED") from None
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise LiveMonitorError("SYMLINK_REJECTED") from None
        if error.errno in (errno.EACCES, errno.EPERM):
            raise LiveMonitorError("PERMISSION_DENIED") from None
        raise LiveMonitorError(kind) from None
    finally:
        if file_fd >= 0:
            os.close(file_fd)
        if root_fd >= 0:
            os.close(root_fd)


def _unique_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise LiveMonitorError("DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise LiveMonitorError("INVALID_CONFIG")


def load_live_monitor_config(path: Path) -> LiveMonitorConfig:
    if not isinstance(path, Path):
        raise LiveMonitorError("NON_ABSOLUTE_PATH")
    descriptor, metadata = _open_regular(path, config_file=True)
    try:
        if metadata.st_size > CONFIG_MAX_BYTES:
            raise LiveMonitorError("CONFIG_TOO_LARGE")
        data = os.read(descriptor, CONFIG_MAX_BYTES + 1)
        if len(data) > CONFIG_MAX_BYTES:
            raise LiveMonitorError("CONFIG_TOO_LARGE")
    except OSError:
        raise LiveMonitorError("CONFIG_UNAVAILABLE") from None
    finally:
        os.close(descriptor)
    try:
        decoded = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise LiveMonitorError("INVALID_UTF8") from None
    try:
        parsed = json.loads(
            decoded, object_pairs_hook=_unique_keys, parse_constant=_reject_constant,
        )
    except LiveMonitorError:
        raise
    except (ValueError, TypeError, RecursionError):
        raise LiveMonitorError("INVALID_CONFIG") from None
    if type(parsed) is not dict or set(parsed) != {"schema_version", "source", "start_policy"}:
        raise LiveMonitorError("INVALID_CONFIG")
    source = parsed["source"]
    if type(source) is not dict or set(source) != {"role", "path"}:
        raise LiveMonitorError("INVALID_CONFIG")
    if type(source["path"]) is not str:
        raise LiveMonitorError("NON_ABSOLUTE_PATH")
    _validate_absolute_path(source["path"])
    return LiveMonitorConfig(
        role=source["role"], path=Path(source["path"]),
        schema_version=parsed["schema_version"], start_policy=parsed["start_policy"],
    )
