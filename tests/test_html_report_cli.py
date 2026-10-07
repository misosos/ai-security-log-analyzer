from html.parser import HTMLParser
from pathlib import Path
from types import SimpleNamespace

import pytest

import app.main as main_module
from app.analyzer.html_report_file import InvestigationReportFileError


LINUX_FIXTURE = Path(
    "sample_logs/"
    "linux_audit_session_process_co_observation_contract_synthetic.log"
)
PRIVATE = "PRIVATE-HTML-REPORT-CLI-CANARY"


class _StructureParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []
        self.remote_references = []

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        for name, value in attrs:
            if name in {"href", "src"} and value:
                self.remote_references.append(value)


def _install_single_pass_spies(monkeypatch, calls):
    logs = []
    analysis = {"results": {}, "global_correlation": {}}
    aggregate = {"observation_count": 0}
    observations = (object(),)
    relations = (object(),)
    process_summary = SimpleNamespace(
        shared_memory_privileged_execution_observation_count=1,
    )
    session_summary = SimpleNamespace(session_co_observation_count=1)
    projection = object()
    rendered = "<!doctype html>\n<html></html>\n"

    monkeypatch.setattr(
        main_module,
        "load_normalized_logs",
        lambda sources: calls.append(("load", sources)) or logs,
    )
    monkeypatch.setattr(
        main_module,
        "_analyze_normalized_logs",
        lambda value: calls.append(("analyze", value)) or analysis,
    )
    monkeypatch.setattr(
        main_module,
        "aggregate_process_execution_observations",
        lambda value: calls.append(("aggregate", value)) or aggregate,
    )
    monkeypatch.setattr(
        main_module,
        "collect_shared_memory_execution_observations",
        lambda value: calls.append(("shared_collect", value)) or observations,
    )
    monkeypatch.setattr(
        main_module,
        "summarize_shared_memory_execution_observations",
        lambda value: calls.append(("shared_summary", value))
        or process_summary,
    )
    monkeypatch.setattr(
        main_module,
        "collect_session_process_co_observations",
        lambda value: calls.append(("session_collect", value)) or relations,
    )
    monkeypatch.setattr(
        main_module,
        "summarize_session_process_co_observations",
        lambda first, second: calls.append(
            ("session_summary", first, second)
        ) or session_summary,
    )

    def build(received, **kwargs):
        calls.append(("project", received, kwargs))
        return projection

    monkeypatch.setattr(main_module, "build_investigation_report_projection", build)
    monkeypatch.setattr(
        main_module,
        "render_investigation_report_html",
        lambda value: calls.append(("render", value)) or rendered,
    )
    monkeypatch.setattr(
        main_module,
        "write_investigation_report_html",
        lambda html, target: calls.append(("write", html, target)),
    )
    monkeypatch.setattr(
        main_module,
        "print_analysis_result",
        lambda received, **kwargs: calls.append(("print", received, kwargs)),
    )
    return {
        "logs": logs,
        "analysis": analysis,
        "aggregate": aggregate,
        "observations": observations,
        "relations": relations,
        "process_summary": process_summary,
        "session_summary": session_summary,
        "projection": projection,
        "rendered": rendered,
    }


def test_help_documents_sensitive_html_report_without_analysis(capsys):
    with pytest.raises(SystemExit) as caught:
        main_module.main(["--help"])

    output = capsys.readouterr().out
    assert caught.value.code == 0
    assert "--html-report PATH" in output
    assert "sensitive standalone investigation report" in output


def test_omitted_option_never_invokes_html_boundaries(monkeypatch):
    for name in (
        "validate_html_report_target",
        "build_investigation_report_projection",
        "render_investigation_report_html",
        "write_investigation_report_html",
    ):
        monkeypatch.setattr(
            main_module,
            name,
            lambda *args, _name=name, **kwargs: pytest.fail(
                f"unexpected HTML boundary: {_name}"
            ),
        )

    main_module.main([])


def test_html_option_uses_one_single_pass_and_same_objects(
    tmp_path,
    monkeypatch,
    capsys,
):
    destination = tmp_path / "report.html"
    linux_input = tmp_path / "audit.log"
    linux_input.write_text("synthetic\n", encoding="utf-8")
    calls = []
    values = _install_single_pass_spies(monkeypatch, calls)

    main_module.main([
        "--linux-audit",
        str(linux_input),
        "--html-report",
        str(destination),
    ])

    assert [call[0] for call in calls] == [
        "load",
        "analyze",
        "aggregate",
        "shared_collect",
        "shared_summary",
        "session_collect",
        "session_summary",
        "project",
        "render",
        "write",
        "print",
    ]
    assert calls[1][1] is values["logs"]
    assert calls[2][1] is values["logs"]
    assert calls[7][1] is values["analysis"]
    assert calls[7][2] == {
        "process_execution_aggregate": values["aggregate"],
        "process_detection_summary": values["process_summary"],
        "session_process_review_summary": values["session_summary"],
    }
    assert calls[8][1] is values["projection"]
    assert calls[9][1] is values["rendered"]
    assert calls[10][1] is values["analysis"]
    assert capsys.readouterr().out == "HTML investigation report created.\n"


def test_html_without_linux_input_omits_linux_projection_arguments(
    tmp_path,
    monkeypatch,
):
    calls = []
    _install_single_pass_spies(monkeypatch, calls)

    main_module.main(["--html-report", str(tmp_path / "report.html")])

    project_call = next(call for call in calls if call[0] == "project")
    assert project_call[2] == {}


def test_report_creation_failure_precedes_text_output_and_is_bounded(
    tmp_path,
    monkeypatch,
    capsys,
):
    destination = tmp_path / f"{PRIVATE}.html"
    calls = []
    _install_single_pass_spies(monkeypatch, calls)
    monkeypatch.setattr(
        main_module,
        "write_investigation_report_html",
        lambda html, target: (_ for _ in ()).throw(
            InvestigationReportFileError()
        ),
    )

    with pytest.raises(SystemExit) as caught:
        main_module.main(["--html-report", str(destination)])

    captured = capsys.readouterr()
    assert caught.value.code == 1
    assert captured.out == ""
    assert captured.err == "HTML investigation report could not be created.\n"
    assert PRIVATE not in captured.err
    assert not destination.exists()
    assert not any(call[0] == "print" for call in calls)


@pytest.mark.parametrize(
    "argument",
    ["", "   ", "report.txt", "report.HTML", "~/report.html"],
)
def test_cli_path_errors_are_bounded(argument, capsys):
    with pytest.raises(SystemExit) as caught:
        main_module.main(["--html-report", argument])

    error = capsys.readouterr().err
    assert caught.value.code == 2
    assert "HTML report destination is invalid." in error
    assert argument not in error or not argument
    assert "Traceback" not in error


def test_real_default_html_report_preserves_text_and_is_standalone(
    tmp_path,
    capsys,
):
    main_module.main([])
    baseline = capsys.readouterr()
    destination = tmp_path / "report.html"

    main_module.main(["--html-report", str(destination)])
    with_report = capsys.readouterr()
    html = destination.read_text(encoding="utf-8")
    parser = _StructureParser()
    parser.feed(html)

    assert with_report.err == baseline.err == ""
    assert with_report.out == baseline.out + (
        "HTML investigation report created.\n"
    )
    assert html.startswith("<!doctype html>\n")
    assert '<html lang="ko">' in html
    assert "보안 로그 조사 보고서" in html
    assert "Brute Force" in html
    assert "Password Spraying-like" in html
    assert "Path Traversal" in html
    assert "Account 1" in html
    assert ">alice<" not in html
    assert ">admin<" not in html
    assert "url_decoded_query" not in html
    assert "file=../../etc/passwd" not in html
    assert "<script" not in html.casefold()
    assert parser.remote_references == []
    assert "<dt>분석 대상 수</dt>\n<dd>10</dd>" in html
    assert "<dt>HIGH 위험도</dt>\n<dd>4</dd>" in html
    assert "<dt>MEDIUM 위험도</dt>\n<dd>1</dd>" in html
    assert "<dt>LOW 위험도</dt>\n<dd>5</dd>" in html
    assert "<dt>지원 탐지 관찰 수</dt>\n<dd>4</dd>" in html
    assert "<dt>지원 상관관계 관찰 수</dt>\n<dd>3</dd>" in html
    ordered_subjects = (
        "조사 순서 1 — 분석 대상 IP 10.0.0.5",
        "조사 순서 2 — 분석 대상 IP 192.168.1.20",
        "조사 순서 3 — 분석 대상 IP 192.168.1.30",
        "조사 순서 4 — 분석 대상 IP 192.168.1.60",
    )
    positions = tuple(html.index(value) for value in ordered_subjects)
    assert positions == tuple(sorted(positions))


def test_real_linux_audit_input_adds_only_aggregate_report_section(
    tmp_path,
    capsys,
):
    destination = tmp_path / "linux-report.html"

    main_module.main([
        "--linux-audit",
        str(LINUX_FIXTURE),
        "--html-report",
        str(destination),
    ])
    captured = capsys.readouterr()
    html = destination.read_text(encoding="utf-8")

    assert captured.err == ""
    assert "Linux Audit 집계" in html
    assert "프로세스 관찰 수" in html
    privacy_canary = "SYNTHETIC_SESSION_PROCESS_SECRET_DO_NOT_EXPOSE"
    assert privacy_canary not in html
    assert privacy_canary not in captured.out
    assert privacy_canary not in captured.err
    for prohibited in (
        "PROCTITLE",
        "raw_records",
        "source_instance",
        "event_id",
        "/dev/shm/",
    ):
        assert prohibited not in html


def test_cli_module_has_no_browser_or_llm_integration():
    source = Path(main_module.__file__).read_text(encoding="utf-8")
    assert "webbrowser" not in source
    assert "build_llm_input" not in source
    assert "app.analyzer.llm" not in source
