"""Trusted, bounded CLI setup for one application log; never starts a monitor."""

import argparse
from dataclasses import dataclass
import json
import os
from pathlib import Path
import secrets
import shlex
import stat
import sys
from typing import Callable

from app.live_monitoring.config import (
    LiveMonitorConfigV2, LiveMonitorError, _open_regular, _validate_absolute_path,
    load_live_monitor_config, load_live_monitor_setup_config,
)
from app.live_monitoring.core import LiveTailRecord, MAX_LINE_BYTES
from app.live_monitoring.parser_adapter import parse_live_records


SAMPLE_BYTES = 4096
SAMPLE_LINES = 16
_RECOVERY = {
    "SETUP_CANCELLED": ("설정 생성을 취소했습니다.", "다시 시작하려면 명령을 재실행하십시오.", True),
    "SETUP_INVALID_INPUT": ("입력을 확인하십시오.", "절대 경로와 지원 역할을 확인하십시오.", True),
    "SETUP_UNSUPPORTED_ROLE": ("이 마법사는 application 로그만 지원합니다.", "지원 범위를 확인하십시오.", True),
    "SETUP_PATH_MISSING": ("로그 파일을 찾을 수 없습니다.", "존재하는 일반 파일을 선택하십시오.", True),
    "SETUP_PERMISSION_DENIED": ("파일에 접근할 수 없습니다.", "현재 사용자의 권한을 확인하십시오.", True),
    "SETUP_SYMLINK_REJECTED": ("심볼릭 링크를 사용할 수 없습니다.", "일반 파일과 안전한 디렉터리를 선택하십시오.", True),
    "SETUP_NOT_REGULAR_FILE": ("일반 파일이 아닙니다.", "일반 텍스트 로그 파일을 선택하십시오.", True),
    "SETUP_SOURCE_CHANGED": ("검사 중 로그 파일이 교체되었습니다.", "파일 상태를 확인한 뒤 다시 시도하십시오.", True),
    "SETUP_UNSUPPORTED_OS": ("필수 안전 파일 기능을 사용할 수 없습니다.", "지원 환경에서 다시 실행하십시오.", False),
    "SETUP_BINARY_INPUT": ("텍스트 로그 형식이 아닙니다.", "UTF-8 텍스트 로그를 선택하십시오.", True),
    "SETUP_INVALID_UTF8": ("UTF-8로 읽을 수 없습니다.", "UTF-8 로그를 선택하십시오.", True),
    "SETUP_LINE_TOO_LONG": ("검사 범위에 너무 긴 줄이 있습니다.", "줄 길이를 확인하십시오.", True),
    "SETUP_UNSUPPORTED_FORMAT": ("애플리케이션 로그 형식을 확인하지 못했습니다.", "로그 유형을 확인하십시오.", True),
    "SETUP_OUTPUT_EXISTS": ("설정 파일이 이미 있습니다.", "기존 파일을 유지하고 다른 저장 위치를 선택하십시오.", True),
    "SETUP_OUTPUT_SYMLINK": ("저장 대상에 심볼릭 링크가 있습니다.", "다른 안전한 저장 위치를 선택하십시오.", True),
    "SETUP_UNSAFE_PARENT": ("안전한 저장 디렉터리를 확인하지 못했습니다.", "사용자 전용 디렉터리를 선택하십시오.", True),
    "SETUP_SAVE_FAILED": ("설정 파일을 저장하지 못했습니다.", "디렉터리 권한과 저장 공간을 확인하십시오.", True),
    "SETUP_POST_WRITE_FAILED": ("저장 후 설정 검증에 실패했습니다.", "설정 파일 상태를 확인하십시오.", False),
    "SETUP_INTERNAL_FAILED": ("설정 준비 중 내부 오류가 발생했습니다.", "다시 시도해도 반복되면 합성 자료로 신고하십시오.", False),
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


@dataclass(frozen=True, slots=True)
class SetupResult:
    status: str
    source_role: str | None = None
    dry_run: DryRunSummary | None = None


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


def _source_descriptor(path: Path) -> tuple[int, os.stat_result]:
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
    return fd, opened


def _validate_source_unchanged(path: Path, fd: int, opened: os.stat_result) -> None:
    try:
        current = os.stat(path, follow_symlinks=False)
        descriptor = os.fstat(fd)
    except OSError:
        raise MonitorSetupError("SETUP_SOURCE_CHANGED") from None
    if not _same_file(opened, current) or not _same_file(opened, descriptor):
        raise MonitorSetupError("SETUP_SOURCE_CHANGED")


def _inspect(fd: int, path: Path, opened: os.stat_result) -> DryRunSummary:
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
        records.append(LiveTailRecord("application", sequence, decoded, len(line)))
    if partial and opened.st_size <= SAMPLE_BYTES:
        try:
            partial.decode("utf-8", errors="strict")
        except UnicodeError:
            raise MonitorSetupError("SETUP_INVALID_UTF8") from None
    try:
        batch = parse_live_records("application", tuple(records))
    except Exception:
        raise MonitorSetupError("SETUP_UNSUPPORTED_FORMAT") from None
    _validate_source_unchanged(path, fd, opened)
    if complete and not batch.parsed_count and batch.rejected_count:
        raise MonitorSetupError("SETUP_UNSUPPORTED_FORMAT")
    return DryRunSummary(len(sample), len(complete), batch.parsed_count,
                         batch.ignored_count, batch.rejected_count,
                         bool(partial), opened.st_size == 0,
                         opened.st_size > SAMPLE_BYTES or line_limit_reached)


def dry_run_application(path: str | Path) -> DryRunSummary:
    source = _safe_path(path)
    fd, opened = _source_descriptor(source)
    try:
        return _inspect(fd, source, opened)
    finally:
        os.close(fd)


def _preview_source(path: Path) -> tuple[DryRunSummary, tuple[int, int, int, int, int]]:
    fd, opened = _source_descriptor(path)
    try:
        summary = _inspect(fd, path, opened)
        return summary, (opened.st_dev, opened.st_ino, opened.st_size,
                         opened.st_mtime_ns, opened.st_ctime_ns)
    finally:
        os.close(fd)


def _default_output() -> Path:
    if sys.platform == "darwin":
        return Path.home() / "Library/Application Support/ai-security-log-analyzer/monitoring.json"
    if sys.platform.startswith("linux"):
        xdg = os.environ.get("XDG_CONFIG_HOME")
        base = _safe_path(xdg) if xdg else Path.home() / ".config"
        return base / "ai-security-log-analyzer/monitoring.json"
    raise MonitorSetupError("SETUP_UNSUPPORTED_OS")


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
        if verified != document or runtime.role != "application":
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
                          _expected_identity: tuple[int, int, int, int, int] | None = None) -> DryRunSummary:
    source_path = _safe_path(source)
    output_path = _safe_path(output)
    fd, opened = _source_descriptor(source_path)
    try:
        if (_expected_identity is not None and
            (opened.st_dev, opened.st_ino, opened.st_size,
             opened.st_mtime_ns, opened.st_ctime_ns) != _expected_identity):
            raise MonitorSetupError("SETUP_SOURCE_CHANGED")
        summary = _inspect(fd, source_path, opened)
        _validate_source_unchanged(source_path, fd, opened)
        document = LiveMonitorConfigV2(source_path)
        _save_private(document, output_path,
                      lambda: _validate_source_unchanged(source_path, fd, opened))
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
    emit("지원 로그 유형: application (애플리케이션 인증 로그)만 가능합니다.")
    if ask("로그 유형 [application]: ").strip() != "application":
        raise MonitorSetupError("SETUP_UNSUPPORTED_ROLE")
    source = _safe_path(ask("로그 파일의 절대 경로: "))
    summary, expected_identity = _preview_source(source)
    destination = _safe_path(output) if output is not None else _default_output()
    emit("미리보기: schema 2, application, FROM_END, Asia/Seoul; 저장 위치: 사용자 전용 설정 파일.")
    emit(f"bounded 검사: {summary.inspected_bytes}B, {summary.inspected_lines}줄, "
         f"parsed {summary.parsed_count}, ignored {summary.ignored_count}, "
         f"rejected {summary.rejected_count}, partial {summary.partial_line}.")
    if summary.empty_source or not summary.inspected_lines:
        emit("완성된 기존 줄이 없어 형식을 확인하지 못했습니다. 새 줄이 생긴 뒤 확인하십시오.")
    emit("기존 줄은 분석하지 않으며, 로그 경로는 private config에 저장됩니다.")
    if not _approved(ask("이 설정을 저장하시겠습니까? [y/N] ")):
        emit("설정 생성을 취소했습니다.")
        return SetupResult("CANCELLED", "application", summary)
    saved = create_monitor_config(source, destination, _expected_identity=expected_identity)
    emit("설정 생성 완료. application, FROM_END. 외부 LLM 자동 전송은 없습니다.")
    emit("설정 파일을 공유하지 마세요. 서버 종료는 Ctrl+C입니다.")
    emit("실행 명령 (현재 터미널에 경로가 남을 수 있음):")
    emit("uv run python -m app.local_web --monitor-config " + shlex.quote(os.fspath(destination)))
    return SetupResult("CREATED", "application", saved)


class _SetupParser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        raise MonitorSetupError("SETUP_INVALID_INPUT")


def main(argv: list[str] | None = None, *, ask: Callable[[str], str] = input,
         emit: Callable[[str], None] = print) -> int:
    parser = _SetupParser(description="단일 application 로그의 로컬 모니터링 설정 생성")
    parser.add_argument("--output", metavar="/absolute/path/to/monitoring.json")
    parser.add_argument("--no-color", action="store_true", help="색상 출력 없이 실행 (기본값)")
    try:
        args = parser.parse_args(argv)
        run_setup(output=args.output, ask=ask, emit=emit)
        return 0
    except MonitorSetupError as error:
        print(str(error), file=sys.stderr)
        return (2 if error.code in ("SETUP_INVALID_INPUT", "SETUP_UNSUPPORTED_ROLE") else
                3 if error.code in ("SETUP_PATH_MISSING", "SETUP_PERMISSION_DENIED",
                                   "SETUP_SYMLINK_REJECTED", "SETUP_NOT_REGULAR_FILE",
                                   "SETUP_SOURCE_CHANGED", "SETUP_UNSUPPORTED_OS",
                                   "SETUP_BINARY_INPUT", "SETUP_INVALID_UTF8", "SETUP_LINE_TOO_LONG",
                                   "SETUP_UNSUPPORTED_FORMAT") else
                1 if error.code == "SETUP_INTERNAL_FAILED" else 4)
    except (EOFError, KeyboardInterrupt):
        print("SETUP_CANCELLED: 설정 생성을 취소했습니다.")
        return 0
    except Exception:
        print(str(MonitorSetupError("SETUP_INTERNAL_FAILED")), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
