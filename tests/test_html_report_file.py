import os
from pathlib import Path
import socket
import stat
import tempfile

import pytest

import app.analyzer.html_report_file as file_module
from app.analyzer.html_report_file import (
    InvestigationReportFileError,
    ValidatedHtmlReportTarget,
    validate_html_report_target,
    write_investigation_report_html,
)


PRIVATE_PATH = "PRIVATE-REPORT-PATH-CANARY"
PRIVATE_HTML = "PRIVATE-HTML-CANARY"
ERROR_MESSAGE = "HTML investigation report file could not be created."


def _assert_bounded(error):
    assert str(error) == ERROR_MESSAGE
    assert PRIVATE_PATH not in str(error)
    assert PRIVATE_PATH not in repr(error)
    assert PRIVATE_HTML not in str(error)
    assert PRIVATE_HTML not in repr(error)


def test_validator_accepts_relative_and_absolute_new_lowercase_html_paths(
    tmp_path,
    monkeypatch,
):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "reports").mkdir()

    relative = validate_html_report_target("reports/output.html")
    absolute = validate_html_report_target(str(tmp_path / "absolute.html"))

    assert relative.destination == Path("reports/output.html")
    assert relative.parent == Path("reports")
    assert absolute.destination == tmp_path / "absolute.html"
    assert absolute.parent == tmp_path
    assert PRIVATE_PATH not in repr(relative)


@pytest.mark.parametrize(
    "value",
    [
        "",
        "   ",
        "report.htm",
        "report.HTML",
        "report.html ",
        "../report.html",
        "~/report.html",
        "$REPORT_DIR/report.html",
        "bad\x00report.html",
    ],
)
def test_validator_rejects_invalid_strings_without_expansion(value):
    with pytest.raises(InvestigationReportFileError) as caught:
        validate_html_report_target(value)
    _assert_bounded(caught.value)


def test_validator_requires_existing_real_directory(tmp_path):
    for destination in (
        tmp_path / "missing" / f"{PRIVATE_PATH}.html",
        tmp_path / f"{PRIVATE_PATH}.html" / "report.html",
    ):
        with pytest.raises(InvestigationReportFileError) as caught:
            validate_html_report_target(str(destination))
        _assert_bounded(caught.value)


def test_validator_rejects_symlink_parent_and_destination(tmp_path):
    real_parent = tmp_path / "real"
    real_parent.mkdir()
    parent_link = tmp_path / "linked"
    parent_link.symlink_to(real_parent, target_is_directory=True)

    destination_link = tmp_path / "linked-report.html"
    destination_link.symlink_to(real_parent / "missing.html")

    for destination in (
        parent_link / "report.html",
        destination_link,
    ):
        with pytest.raises(InvestigationReportFileError) as caught:
            validate_html_report_target(str(destination))
        _assert_bounded(caught.value)


def test_validator_rejects_every_existing_destination_kind(tmp_path):
    regular = tmp_path / "regular.html"
    regular.write_text("existing", encoding="utf-8")
    directory = tmp_path / "directory.html"
    directory.mkdir()
    fifo = tmp_path / "fifo.html"
    os.mkfifo(fifo)
    for destination in (regular, directory, fifo):
        with pytest.raises(InvestigationReportFileError) as caught:
            validate_html_report_target(str(destination))
        _assert_bounded(caught.value)


def test_validator_rejects_existing_unix_socket_where_supported():
    temporary_root = Path(tempfile.gettempdir()).resolve()
    with tempfile.TemporaryDirectory(
        prefix="hr-",
        dir=temporary_root,
    ) as directory:
        socket_path = Path(directory) / "socket.html"
        unix_socket = socket.socket(socket.AF_UNIX)
        unix_socket.bind(str(socket_path))
        try:
            with pytest.raises(InvestigationReportFileError) as caught:
                validate_html_report_target(str(socket_path))
            _assert_bounded(caught.value)
        finally:
            unix_socket.close()


def test_writer_preserves_exact_utf8_bytes_and_uses_restrictive_mode(tmp_path):
    destination = tmp_path / "report.html"
    target = validate_html_report_target(str(destination))
    html = "<!doctype html>\n<p>관찰 &amp; review</p>\n"

    write_investigation_report_html(html, target)

    assert destination.read_bytes() == html.encode("utf-8")
    if os.name == "posix":
        assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    assert not tuple(tmp_path.glob(".investigation-report-*.tmp"))


def test_writer_never_overwrites_and_repeated_invocation_fails_safely(tmp_path):
    destination = tmp_path / "report.html"
    target = validate_html_report_target(str(destination))
    write_investigation_report_html("first\n", target)

    with pytest.raises(InvestigationReportFileError) as caught:
        write_investigation_report_html("second\n", target)

    _assert_bounded(caught.value)
    assert destination.read_text(encoding="utf-8") == "first\n"
    assert not tuple(tmp_path.glob(".investigation-report-*.tmp"))


@pytest.mark.parametrize("invalid", [None, b"html", 1, object()])
def test_writer_requires_exact_html_string(invalid, tmp_path):
    target = validate_html_report_target(str(tmp_path / "report.html"))
    with pytest.raises(InvestigationReportFileError) as caught:
        write_investigation_report_html(invalid, target)
    _assert_bounded(caught.value)


def test_writer_requires_exact_validated_target(tmp_path):
    class TargetSubclass(ValidatedHtmlReportTarget):
        pass

    destination = tmp_path / "report.html"
    for invalid in (
        destination,
        {"destination": destination},
        TargetSubclass(destination, tmp_path),
    ):
        with pytest.raises(InvestigationReportFileError) as caught:
            write_investigation_report_html("html", invalid)
        _assert_bounded(caught.value)


def test_writer_rejects_invalid_utf8_without_creating_a_file(tmp_path):
    destination = tmp_path / "report.html"
    target = validate_html_report_target(str(destination))
    with pytest.raises(InvestigationReportFileError) as caught:
        write_investigation_report_html("\ud800", target)
    _assert_bounded(caught.value)
    assert not destination.exists()
    assert not tuple(tmp_path.iterdir())


@pytest.mark.parametrize(
    "stage",
    [
        "create",
        "chmod",
        "open",
        "write",
        "short_write",
        "flush",
        "fsync",
        "link",
        "finalize_cleanup",
    ],
)
def test_writer_cleans_temporary_files_after_staged_failure(
    stage,
    tmp_path,
    monkeypatch,
):
    destination = tmp_path / "report.html"
    target = validate_html_report_target(str(destination))

    if stage == "create":
        monkeypatch.setattr(
            file_module.tempfile,
            "mkstemp",
            lambda **kwargs: (_ for _ in ()).throw(OSError(PRIVATE_PATH)),
        )
    elif stage == "chmod":
        monkeypatch.setattr(
            file_module.os,
            "fchmod",
            lambda *args: (_ for _ in ()).throw(OSError(PRIVATE_PATH)),
        )
    elif stage == "open":
        monkeypatch.setattr(
            file_module.os,
            "fdopen",
            lambda *args, **kwargs: (_ for _ in ()).throw(
                OSError(PRIVATE_PATH)
            ),
        )
    elif stage in {"write", "short_write", "flush"}:
        original_fdopen = file_module.os.fdopen

        class FailingOutput:
            def __init__(self, descriptor):
                self.output = original_fdopen(descriptor, "wb", closefd=True)

            def __enter__(self):
                return self

            def __exit__(self, *args):
                self.output.close()

            def write(self, value):
                if stage == "write":
                    raise OSError(PRIVATE_PATH)
                if stage == "short_write":
                    return 0
                return self.output.write(value)

            def flush(self):
                if stage == "flush":
                    raise OSError(PRIVATE_PATH)
                return self.output.flush()

            def fileno(self):
                return self.output.fileno()

        monkeypatch.setattr(
            file_module.os,
            "fdopen",
            lambda descriptor, *args, **kwargs: FailingOutput(descriptor),
        )
    elif stage == "fsync":
        monkeypatch.setattr(
            file_module.os,
            "fsync",
            lambda descriptor: (_ for _ in ()).throw(OSError(PRIVATE_PATH)),
        )
    elif stage == "link":
        monkeypatch.setattr(
            file_module.os,
            "link",
            lambda *args, **kwargs: (_ for _ in ()).throw(OSError(PRIVATE_PATH)),
        )
    else:
        original_unlink = file_module.os.unlink
        unlink_calls = 0

        def fail_first_unlink(path):
            nonlocal unlink_calls
            unlink_calls += 1
            if unlink_calls == 1:
                raise OSError(PRIVATE_PATH)
            return original_unlink(path)

        monkeypatch.setattr(file_module.os, "unlink", fail_first_unlink)

    with pytest.raises(InvestigationReportFileError) as caught:
        write_investigation_report_html(PRIVATE_HTML, target)

    _assert_bounded(caught.value)
    assert not destination.exists()
    assert not tuple(tmp_path.glob(".investigation-report-*.tmp"))


def test_writer_does_not_mutate_html_input(tmp_path):
    destination = tmp_path / "report.html"
    target = validate_html_report_target(str(destination))
    html = "<!doctype html>\n<p>fixed</p>\n"
    original = html

    write_investigation_report_html(html, target)

    assert html == original
