from dataclasses import dataclass, field
import os
from pathlib import Path
import stat
import tempfile


_FILE_ERROR_MESSAGE = "HTML investigation report file could not be created."


class InvestigationReportFileError(ValueError):
    def __init__(self):
        super().__init__(_FILE_ERROR_MESSAGE)


@dataclass(frozen=True)
class ValidatedHtmlReportTarget:
    destination: Path = field(repr=False)
    parent: Path = field(repr=False)


def _fail():
    raise InvestigationReportFileError() from None


def _supplied_parent_paths(path):
    parts = path.parts[:-1]
    if path.is_absolute():
        current = Path(path.anchor)
        parts = parts[1:]
    else:
        current = Path(".")

    for part in parts:
        current = current / part
        yield current


def _validate_parent_chain(destination):
    parent_paths = tuple(_supplied_parent_paths(destination))
    if not parent_paths:
        parent_paths = (Path("."),)

    for parent in parent_paths:
        try:
            parent_stat = parent.lstat()
        except OSError:
            _fail()
        if stat.S_ISLNK(parent_stat.st_mode) or not stat.S_ISDIR(
            parent_stat.st_mode
        ):
            _fail()

    return destination.parent


def validate_html_report_target(value):
    if type(value) is not str or not value.strip() or "\x00" in value:
        _fail()

    destination = Path(value)
    if (
        destination.suffix != ".html"
        or ".." in destination.parts
        or any(part.startswith("~") for part in destination.parts)
    ):
        _fail()

    parent = _validate_parent_chain(destination)

    try:
        destination.lstat()
    except FileNotFoundError:
        pass
    except OSError:
        _fail()
    else:
        _fail()

    return ValidatedHtmlReportTarget(
        destination=destination,
        parent=parent,
    )


def _remove_temporary_file(path):
    if path is None:
        return
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    except OSError:
        pass


def _remove_published_file_if_same(destination, temporary_path):
    if temporary_path is None:
        return
    try:
        destination_stat = destination.lstat()
        temporary_stat = temporary_path.lstat()
        if (
            destination_stat.st_dev == temporary_stat.st_dev
            and destination_stat.st_ino == temporary_stat.st_ino
        ):
            os.unlink(destination)
    except OSError:
        pass


def write_investigation_report_html(html, target):
    if type(html) is not str or type(target) is not ValidatedHtmlReportTarget:
        _fail()
    if not isinstance(target.destination, Path) or not isinstance(
        target.parent,
        Path,
    ):
        _fail()
    if (
        target.destination.suffix != ".html"
        or ".." in target.destination.parts
        or any(part.startswith("~") for part in target.destination.parts)
        or _validate_parent_chain(target.destination) != target.parent
    ):
        _fail()

    try:
        encoded = html.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        _fail()

    temporary_path = None
    file_descriptor = None
    published = False
    try:
        try:
            target.destination.lstat()
        except FileNotFoundError:
            pass
        else:
            _fail()

        file_descriptor, temporary_name = tempfile.mkstemp(
            prefix=".investigation-report-",
            suffix=".tmp",
            dir=target.parent,
        )
        temporary_path = Path(temporary_name)
        if hasattr(os, "fchmod"):
            os.fchmod(file_descriptor, 0o600)

        with os.fdopen(file_descriptor, "wb", closefd=True) as output:
            file_descriptor = None
            written = output.write(encoded)
            if written != len(encoded):
                raise OSError
            output.flush()
            os.fsync(output.fileno())

        os.link(
            temporary_path,
            target.destination,
            follow_symlinks=False,
        )
        published = True
        os.unlink(temporary_path)
        temporary_path = None
    except InvestigationReportFileError:
        if file_descriptor is not None:
            try:
                os.close(file_descriptor)
            except OSError:
                pass
        if published:
            _remove_published_file_if_same(
                target.destination,
                temporary_path,
            )
        _remove_temporary_file(temporary_path)
        raise
    except (OSError, TypeError, ValueError):
        if file_descriptor is not None:
            try:
                os.close(file_descriptor)
            except OSError:
                pass
        if published:
            _remove_published_file_if_same(
                target.destination,
                temporary_path,
            )
        _remove_temporary_file(temporary_path)
        _fail()
