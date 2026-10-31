"""Synthetic exact-profile and consumer tests for Apache/Nginx access logs."""

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.api import create_app
from app.local_investigation_api import _compatible
from app.main import analyze
from app.parser.access_log import parse_access_log
from app.parser.time_utils import normalize_to_utc


ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "sample_logs" / "access_combined_compatibility"
MANIFEST = CORPUS / "manifest.json"


def _manifest():
    value = json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert set(value) == {"schema_version", "fixture", "scenarios"}
    assert value["schema_version"] == 1
    fixture = (CORPUS / value["fixture"]).resolve()
    assert fixture.is_relative_to(CORPUS.resolve()) and not fixture.is_symlink()
    lines = fixture.read_text(encoding="utf-8").splitlines()
    return value["scenarios"], lines


def _case(scenario):
    scenarios, lines = _manifest()
    selected = next(item for item in scenarios if item["id"] == scenario)
    return selected, lines[selected["line"]]


def _parse(line):
    try:
        return parse_access_log(line)
    except (ValueError, TypeError, OverflowError):
        return None


def test_synthetic_manifest_has_closed_independent_scenario_inventory():
    scenarios, lines = _manifest()
    assert len(scenarios) >= 20
    assert len({item["id"] for item in scenarios}) == len(scenarios)
    assert {item["expected"] for item in scenarios} == {"SUPPORTED", "REJECTED", "IGNORED"}
    assert all(set(item) == {"id", "line", "profile", "expected", "expected_fields"}
               for item in scenarios)
    assert all(type(item["line"]) is int and 0 <= item["line"] < len(lines)
               for item in scenarios)
    assert {
        item["expected"]: sum(row["expected"] == item["expected"] for row in scenarios)
        for item in scenarios
    } == {"SUPPORTED": 21, "REJECTED": 14, "IGNORED": 1}


@pytest.mark.parametrize("scenario", [
    "apache_common_ipv4", "apache_common_ipv6", "apache_combined_ipv4",
    "apache_combined_ipv6", "nginx_default_combined", "combined_missing_referer",
    "combined_missing_user_agent", "status_200", "status_301", "status_403",
    "status_404", "status_500", "response_size_dash", "query_preserved",
    "path_traversal_observed", "normal_browser", "apache_escaped_quote",
    "nginx_default_hex_escape", "apache_escaped_backslash", "nginx_hex_utf8",
    "ua_not_detection_input",
])
def test_supported_profiles_produce_exact_normalized_fields(scenario):
    item, line = _case(scenario)
    event = parse_access_log(line)
    assert event.event_type == "http_request"
    assert event.source == "access_log"
    assert event.user is None and event.authentication is None
    assert event.src_ip == item["expected_fields"]["src_ip"]
    assert normalize_to_utc(event.timestamp) == datetime.fromisoformat(
        item["expected_fields"]["timestamp"]
    ).astimezone(timezone.utc)
    actual = {
        "method": event.http.method,
        "path": event.http.path,
        "query": event.http.query,
        "protocol": event.protocol,
        "status": event.http.status_code,
        "size": event.http.response_size,
        "user_agent": event.user_agent,
    }
    assert actual == item["expected_fields"]["http"]


@pytest.mark.parametrize("scenario", [
    "hostname", "invalid_ipv4", "invalid_ipv6", "status_999", "invalid_date",
    "malformed_request", "missing_required_fields", "broken_request_quote",
    "combined_missing_trailing_field", "trailing_garbage", "custom_json",
    "fake_prefix_request", "unsupported_escape", "incomplete_hex_escape",
    "escaped_control_character",
])
def test_unsupported_profiles_are_not_normalized_as_http_events(scenario):
    _item, line = _case(scenario)
    assert _parse(line) is None


def test_apache_common_and_combined_are_distinguished_and_ua_is_untrusted():
    _common, common_line = _case("apache_common_ipv4")
    _combined, combined_line = _case("apache_escaped_quote")
    assert parse_access_log(common_line).user_agent is None
    event = parse_access_log(combined_line)
    assert event.user_agent == 'SyntheticBrowser/2.0 "quoted" \\ path'
    assert event.user is None  # IDENT/REMOTE_USER are not promoted to an account.


def test_user_agent_is_not_a_detection_signal_and_projection_does_not_disclose_it(tmp_path):
    item, line = _case("ua_not_detection_input")
    path = tmp_path / "synthetic-ua.log"
    path.write_text(line + "\n", encoding="utf-8")
    analysis = analyze([{"source": "access", "path": str(path)}])
    detections = analysis["results"][item["expected_fields"]["src_ip"]]["detections"]
    assert all(not result.is_detected for result in detections.values())
    assert "PRIVACY-UA-CANARY" in parse_access_log(line).user_agent


def test_parser_preflight_and_direct_parser_have_identical_acceptance():
    scenarios, lines = _manifest()
    for item in scenarios:
        accepted = item["expected"] == "SUPPORTED"
        assert (_parse(lines[item["line"]]) is not None) is accepted
        assert _compatible("access", lines[item["line"]]) is accepted


@pytest.mark.parametrize("ending", ["\n", "\r\n"])
def test_single_record_line_terminators_are_input_framing(ending):
    _item, line = _case("nginx_default_combined")
    assert parse_access_log(line + ending).src_ip == "192.0.2.12"


def test_parser_observation_distinguishes_rejected_records_from_ignored_json():
    scenarios, lines = _manifest()
    for item in scenarios:
        try:
            event = parse_access_log(lines[item["line"]])
        except (ValueError, TypeError, OverflowError):
            observed = "REJECTED"
        else:
            observed = "IGNORED" if event is None else "SUPPORTED"
        assert observed == item["expected"], item["id"]


def test_pipeline_preserves_existing_path_traversal_detection_and_scope(tmp_path):
    item, line = _case("path_traversal_observed")
    path = tmp_path / "synthetic-access.log"
    path.write_text(line + "\n", encoding="utf-8")
    result = analyze([{"source": "access", "path": str(path)}])
    subject = item["expected_fields"]["src_ip"]
    assert set(result["results"]) == {subject}
    assert result["results"][subject]["detections"]["path_traversal"].is_detected
    assert result["results"][subject]["detections"]["path_traversal"].detection_type == "path_traversal"


def test_text_and_file_apis_accept_combined_and_keep_public_schema_closed():
    _item, traversal = _case("path_traversal_observed")
    _item, normal = _case("ua_not_detection_input")
    text = traversal + "\n" + normal + "\n"
    client = TestClient(create_app(), base_url="http://127.0.0.1:8000",
                        client=("127.0.0.1", 50000))
    pasted = client.post("/api/v1/investigations/text", json={
        "schema_version": 1, "source": "access", "log_text": text,
    })
    assert pasted.status_code == 200, pasted.text
    body = pasted.json()
    assert set(body) == {"schema_version", "input_scope", "result"}
    result = body["result"]
    assert set(result) == {
        "schema_version", "local_context", "analysis_summary", "case_summary", "cases",
        "independent_observations", "interpretation_notices", "capabilities",
        "bounded_warnings", "report_export",
    }
    private_values = ["referrer.example/PRIVACY-REFERER-CANARY", "SyntheticBrowser",
                      "PRIVACY-UA-CANARY", "UNION SELECT <script>"]
    assert all(value not in pasted.text for value in private_values)

    files = [
        ("application_file", ("app.log", (ROOT / "sample_logs/brute_force.log").read_bytes(), "text/plain")),
        ("ssh_file", ("ssh.log", (ROOT / "sample_logs/ssh_auth.log").read_bytes(), "text/plain")),
        ("access_file", ("access.log", text.encode("utf-8"), "text/plain")),
    ]
    uploaded = client.post("/api/v1/investigations", files=files)
    assert uploaded.status_code == 200, uploaded.text
    file_body = uploaded.json()
    assert set(file_body) == set(result)
    assert file_body["case_summary"]["case_count"] >= 0
    assert file_body["analysis_summary"]["analyzed_subject_count"] >= 1
    assert all(value not in uploaded.text for value in private_values)


def test_both_api_paths_reject_unsupported_trailing_format_with_closed_error():
    _item, line = _case("trailing_garbage")
    client = TestClient(create_app(), base_url="http://127.0.0.1:8000",
                        client=("127.0.0.1", 50000))
    response = client.post("/api/v1/investigations/text", json={
        "schema_version": 1, "source": "access", "log_text": line,
    })
    assert response.status_code == 400
    assert response.json()["error_code"] == "PARSER_INCOMPATIBLE"
    assert line not in response.text

    files = [
        ("application_file", ("app.log", (ROOT / "sample_logs/brute_force.log").read_bytes(), "text/plain")),
        ("ssh_file", ("ssh.log", (ROOT / "sample_logs/ssh_auth.log").read_bytes(), "text/plain")),
        ("access_file", ("access.log", line.encode(), "text/plain")),
    ]
    rejected = client.post("/api/v1/investigations", files=files)
    assert rejected.status_code == 400
    assert rejected.json()["error_code"] == "PARSER_INCOMPATIBLE"
    assert line not in rejected.text
