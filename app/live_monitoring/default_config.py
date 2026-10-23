"""Private default-config inspection; no source data or pathname leaves this module."""

from dataclasses import dataclass, field
import os
from pathlib import Path
import stat

from app.live_monitoring.config import (
    CONFIG_MAX_BYTES, LiveMonitorConfigV2, LiveMonitorConfigV3, LiveMonitorError, _open_regular,
    _parse_v2, _parse_v3, _read_config_document_from_fd, _validate_absolute_path,
)


def _identity(value: os.stat_result) -> tuple[int, ...]:
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid,
            value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def _open_parent(path: Path) -> int:
    if not all(hasattr(os, key) for key in ("O_NOFOLLOW", "O_DIRECTORY", "O_CLOEXEC")):
        raise LiveMonitorError("UNSAFE_PLATFORM")
    _validate_absolute_path(os.fspath(path))
    fd = -1
    try:
        fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        for component in path.parts[1:-1]:
            before = os.stat(component, dir_fd=fd, follow_symlinks=False)
            if not stat.S_ISDIR(before.st_mode) or stat.S_ISLNK(before.st_mode):
                raise LiveMonitorError("DEFAULT_CONFIG_UNSAFE_PARENT")
            next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                              os.O_CLOEXEC, dir_fd=fd)
            if (os.fstat(next_fd).st_dev, os.fstat(next_fd).st_ino) != (before.st_dev, before.st_ino):
                os.close(next_fd)
                raise LiveMonitorError("DEFAULT_CONFIG_UNSAFE_PARENT")
            os.close(fd)
            fd = next_fd
        metadata = os.fstat(fd)
        if metadata.st_uid != os.geteuid() or metadata.st_mode & 0o777 != 0o700:
            raise LiveMonitorError("DEFAULT_CONFIG_UNSAFE_PARENT")
        return fd
    except LiveMonitorError:
        if fd >= 0:
            os.close(fd)
        raise
    except FileNotFoundError:
        if fd >= 0:
            os.close(fd)
        raise LiveMonitorError("DEFAULT_CONFIG_MISSING") from None
    except OSError:
        if fd >= 0:
            os.close(fd)
        raise LiveMonitorError("DEFAULT_CONFIG_UNSAFE_PARENT") from None


@dataclass(slots=True, repr=False)
class DefaultConfigGuard:
    path: Path = field(repr=False)
    config: LiveMonitorConfigV2 = field(repr=False)
    _parent_fd: int = field(repr=False)
    _file_fd: int = field(repr=False)
    _parent_identity: tuple[int, ...] = field(repr=False)
    _file_identity: tuple[int, ...] = field(repr=False)

    def check(self) -> None:
        try:
            parent = os.stat(self.path.parent, follow_symlinks=False)
            named = os.stat(self.path.name, dir_fd=self._parent_fd, follow_symlinks=False)
            # A checkpoint in this private directory legitimately changes its
            # mtime/ctime. Keep the directory identity/owner/mode check while
            # retaining the complete identity check for the config file.
            if (_identity(parent)[:4] != self._parent_identity[:4]
                or _identity(os.fstat(self._parent_fd))[:4] != self._parent_identity[:4]
                or _identity(named) != self._file_identity
                or _identity(os.fstat(self._file_fd)) != self._file_identity):
                raise LiveMonitorError("DEFAULT_CONFIG_CHANGED")
        except OSError:
            raise LiveMonitorError("DEFAULT_CONFIG_CHANGED") from None

    def unlink(self) -> None:
        self.check()
        try:
            os.unlink(self.path.name, dir_fd=self._parent_fd)
        except OSError:
            raise LiveMonitorError("DEFAULT_CONFIG_DELETE_FAILED") from None
        try:
            os.stat(self.path.name, dir_fd=self._parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            try:
                parent = os.stat(self.path.parent, follow_symlinks=False)
                opened = os.fstat(self._parent_fd)
                if (parent.st_dev, parent.st_ino, parent.st_uid, parent.st_mode) != (
                    opened.st_dev, opened.st_ino, opened.st_uid, opened.st_mode
                ):
                    raise LiveMonitorError("DEFAULT_CONFIG_POST_DELETE_FAILED")
                os.fsync(self._parent_fd)
            except LiveMonitorError:
                raise
            except OSError:
                raise LiveMonitorError("DEFAULT_CONFIG_POST_DELETE_FAILED") from None
            return
        except OSError:
            pass
        raise LiveMonitorError("DEFAULT_CONFIG_POST_DELETE_FAILED")

    def close(self) -> None:
        if self._file_fd >= 0:
            os.close(self._file_fd)
            self._file_fd = -1
        if self._parent_fd >= 0:
            os.close(self._parent_fd)
            self._parent_fd = -1

    def __enter__(self) -> "DefaultConfigGuard":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


def open_default_config(path: Path) -> DefaultConfigGuard:
    """Open exactly one v2 config under a private parent, without creating paths."""
    if not isinstance(path, Path):
        raise LiveMonitorError("NON_ABSOLUTE_PATH")
    parent_fd = _open_parent(path)
    file_fd = -1
    try:
        try:
            named = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            raise LiveMonitorError("DEFAULT_CONFIG_MISSING") from None
        if stat.S_ISLNK(named.st_mode):
            raise LiveMonitorError("DEFAULT_CONFIG_SYMLINK")
        if not stat.S_ISREG(named.st_mode):
            raise LiveMonitorError("DEFAULT_CONFIG_TYPE")
        if named.st_uid != os.geteuid() or named.st_mode & 0o777 != 0o600:
            raise LiveMonitorError("DEFAULT_CONFIG_PERMISSION")
        if named.st_size > CONFIG_MAX_BYTES:
            raise LiveMonitorError("DEFAULT_CONFIG_TOO_LARGE")
        file_fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK |
                          os.O_CLOEXEC, dir_fd=parent_fd)
        opened = os.fstat(file_fd)
        if _identity(opened) != _identity(named):
            raise LiveMonitorError("DEFAULT_CONFIG_CHANGED")
        try:
            document = _read_config_document_from_fd(file_fd, opened)
            if type(document) is dict and document.get("schema_version") == "3":
                raise LiveMonitorError("PRIVATE_PAIR_SCHEMA")
            if type(document) is dict and document.get("schema_version") != "2":
                raise LiveMonitorError("UNSUPPORTED_SCHEMA")
            config = _parse_v2(document)
        except LiveMonitorError as error:
            code = ("PRIVATE_PAIR_SCHEMA" if error.code == "PRIVATE_PAIR_SCHEMA"
                    else "DEFAULT_CONFIG_SCHEMA" if error.code == "UNSUPPORTED_SCHEMA"
                    else "DEFAULT_CONFIG_TOO_LARGE" if error.code == "CONFIG_TOO_LARGE"
                    else "DEFAULT_CONFIG_MALFORMED")
            raise LiveMonitorError(code) from None
        if not config.enabled:
            raise LiveMonitorError("SOURCE_DISABLED")
        guard = DefaultConfigGuard(path, config, parent_fd, file_fd,
                                   _identity(os.fstat(parent_fd)), _identity(opened))
        guard.check()
        return guard
    except LiveMonitorError:
        if file_fd >= 0:
            os.close(file_fd)
        os.close(parent_fd)
        raise
    except OSError:
        if file_fd >= 0:
            os.close(file_fd)
        os.close(parent_fd)
        raise LiveMonitorError("DEFAULT_CONFIG_CHANGED") from None


def delete_private_pair_config(path: Path, expected: LiveMonitorConfigV3) -> None:
    """Unlink only the same private v3 document that was explicitly approved."""
    parent_fd = _open_parent(path)
    file_fd = -1
    try:
        try:
            named = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        except OSError:
            raise LiveMonitorError("DEFAULT_CONFIG_CHANGED") from None
        if (stat.S_ISLNK(named.st_mode) or not stat.S_ISREG(named.st_mode)
            or named.st_uid != os.geteuid() or named.st_mode & 0o777 != 0o600
            or named.st_size > CONFIG_MAX_BYTES):
            raise LiveMonitorError("DEFAULT_CONFIG_PERMISSION")
        file_fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK |
                          os.O_CLOEXEC, dir_fd=parent_fd)
        opened = os.fstat(file_fd)
        if _identity(opened) != _identity(named):
            raise LiveMonitorError("DEFAULT_CONFIG_CHANGED")
        parsed = _parse_v3(_read_config_document_from_fd(file_fd, opened))
        if parsed != expected:
            raise LiveMonitorError("DEFAULT_CONFIG_CHANGED")
        current = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        if _identity(current) != _identity(opened):
            raise LiveMonitorError("DEFAULT_CONFIG_CHANGED")
        os.unlink(path.name, dir_fd=parent_fd)
        os.fsync(parent_fd)
        try:
            os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        raise LiveMonitorError("DEFAULT_CONFIG_POST_DELETE_FAILED")
    except LiveMonitorError:
        raise
    except Exception:
        raise LiveMonitorError("DEFAULT_CONFIG_DELETE_FAILED") from None
    finally:
        if file_fd >= 0:
            os.close(file_fd)
        os.close(parent_fd)


def source_available(config: LiveMonitorConfigV2) -> bool:
    """Check current source availability only; never parse or start a session."""
    try:
        fd, opened = _open_regular(config.source_path)
    except LiveMonitorError:
        return False
    try:
        named = os.stat(config.source_path, follow_symlinks=False)
        return (stat.S_ISREG(named.st_mode) and
                (named.st_dev, named.st_ino) == (opened.st_dev, opened.st_ino))
    except OSError:
        return False
    finally:
        os.close(fd)
