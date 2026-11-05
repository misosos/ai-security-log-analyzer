import json

import pytest

from app.evaluation.counterfactual_safe_projection import (
    ProjectionError, build_snapshot, decode_snapshot, encode_snapshot,
)


def test_fixed_corpora_round_trip_and_counts():
    snapshot = build_snapshot()
    encoded = encode_snapshot(snapshot)
    data = json.loads(encoded)
    assert len(data["scenarios"]) == 30
    assert data["summary"]["comparison_counts"] == {
        "PRESERVED": 7, "LOST": 10, "GAINED": 5,
        "UNCHANGED_ABSENT": 2, "INCOMPARABLE": 6, "UNDETERMINED": 0,
    }
    assert encode_snapshot(decode_snapshot(encoded)) == encoded


def test_duplicate_json_key_is_rejected():
    with pytest.raises(ProjectionError):
        decode_snapshot(b'{"schema_version":1,"schema_version":1}')


def _reseal(value):
    import hashlib
    body = {k: v for k, v in value.items() if k != "snapshot_sha256"}
    canonical = json.dumps(body, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    value["snapshot_sha256"] = hashlib.sha256(canonical).hexdigest()
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


@pytest.fixture(scope="module")
def snapshot_data():
    return json.loads(encode_snapshot(build_snapshot()))


@pytest.mark.parametrize("mutation", [
    lambda d: d["scenarios"].pop(),
    lambda d: d["scenarios"].append(d["scenarios"][0]),
    lambda d: d["scenarios"][0].update(corpus_id="unknown"),
    lambda d: d["corpora"][0].update(scenario_count=0),
    lambda d: d["summary"].update(scenario_count=0),
    lambda d: d["scenarios"][0].update(baseline_parser_state="UNKNOWN"),
    lambda d: d["scenarios"][0].update(variant_detection_state="UNKNOWN"),
    lambda d: d["scenarios"][0].update(comparison_state="UNKNOWN"),
    lambda d: d["scenarios"][0].update(reason_codes=["CANARY"]),
    lambda d: d["scenarios"][0].update(baseline_parser_state="REJECTED", baseline_detection_state="DETECTED"),
    lambda d: d.update(extra="<canary>"),
    lambda d: d["summary"].update(scenario_count=True),
])
def test_rejects_resealed_tampered_snapshots(snapshot_data, mutation):
    import copy
    data = copy.deepcopy(snapshot_data)
    mutation(data)
    with pytest.raises(ProjectionError):
        decode_snapshot(_reseal(data))


def test_rejects_digest_version_nonfinite_size_depth(snapshot_data):
    import copy
    bad = copy.deepcopy(snapshot_data)
    bad["snapshot_sha256"] = "0" * 64
    with pytest.raises(ProjectionError, match="SNAPSHOT_DIGEST_MISMATCH"):
        decode_snapshot(json.dumps(bad).encode())
    bad["schema_version"] = 2
    with pytest.raises(ProjectionError, match="UNSUPPORTED_REPORT_VERSION"):
        decode_snapshot(json.dumps(bad).encode())
    for raw in (b'{"a":NaN}', b'[' * 20 + b'0' + b']' * 20, b' ' * (128 * 1024 + 1)):
        with pytest.raises(ProjectionError):
            decode_snapshot(raw)


def test_privacy_allowlist_and_network(monkeypatch):
    import socket
    monkeypatch.setattr(socket.socket, "connect", lambda *a, **k: pytest.fail("network"))
    raw = encode_snapshot(build_snapshot())
    for forbidden in (b"PATTERN_PRESENT", b"label_basis", b"192.0.2.", b"target_subject", b"AnalysisRunOwner", b"BruteWindowContext", b"/Users/", b"<canary>"):
        assert forbidden not in raw
    with pytest.raises(Exception):
        build_snapshot()._canonical = b"modified"


def test_r2_snapshot_exposes_deeply_immutable_structured_projection():
    from dataclasses import FrozenInstanceError
    snapshot = build_snapshot()
    assert isinstance(snapshot.scenarios, tuple)
    assert isinstance(snapshot.corpora, tuple)
    with pytest.raises(TypeError):
        snapshot.scenarios[0]["comparison_state"] = "CANARY"
    with pytest.raises(TypeError):
        snapshot.summary["scenario_count"] = 0
    with pytest.raises(TypeError):
        snapshot.corpora[0]["comparison_counts"]["LOST"] = 0
    with pytest.raises(FrozenInstanceError):
        snapshot._canonical = b"changed"


def test_r2_oversized_scenario_collection_fails_resource_limit(snapshot_data):
    import copy
    data = copy.deepcopy(snapshot_data)
    data["scenarios"] = data["scenarios"] * 3
    with pytest.raises(ProjectionError, match="RESOURCE_LIMIT"):
        decode_snapshot(_reseal(data))


def test_r2_rejects_manifest_changed_after_report(monkeypatch):
    from pathlib import Path
    from app.evaluation import counterfactual_safe_projection as module
    original_report = module.build_report
    original_read = Path.read_bytes
    finished = False

    def report_then_change(*args):
        nonlocal finished
        result = original_report(*args)
        finished = True
        return result

    def changed_read(path):
        data = original_read(path)
        if finished and path == module.CORPUS_ROOT / module.MANIFEST_PATH:
            return data + b" "
        return data

    monkeypatch.setattr(module, "build_report", report_then_change)
    monkeypatch.setattr(Path, "read_bytes", changed_read)
    with pytest.raises(ProjectionError):
        module.build_snapshot()


def test_r2_schema_fields_counts_and_reason_preservation(snapshot_data):
    from app.evaluation.counterfactual_analyst_report import build_report
    from app.evaluation.counterfactual_replay import run_corpus
    from app.evaluation.counterfactual_holdout import run_holdout
    assert set(snapshot_data) == {"schema_version", "evaluation_scope", "snapshot_sha256", "human_review_status", "operational_validation", "corpora", "summary", "scenarios"}
    fields = {"corpus_id", "scenario_id", "detector_id", "mutation_type", "baseline_parser_state", "variant_parser_state", "baseline_detection_state", "variant_detection_state", "comparison_state", "reason_codes"}
    assert all(set(row) == fields for row in snapshot_data["scenarios"])
    report = build_report(run_corpus(), run_holdout())
    assert {row.scenario_id: list(row.reason_codes) for row in report.scenarios} == {row["scenario_id"]: row["reason_codes"] for row in snapshot_data["scenarios"]}
    assert [item["scenario_count"] for item in snapshot_data["corpora"]] == [16, 14]
    assert snapshot_data["summary"]["comparable_count"] == 24
    assert snapshot_data["summary"]["excluded_comparisons"] == 6


@pytest.mark.parametrize("mutation", [
    lambda d: d.pop("summary"),
    lambda d: d["corpora"][0].update(manifest_sha256="0" * 64),
    lambda d: d["scenarios"][0].update(scenario_id="<canary>"),
    lambda d: d["scenarios"][0].update(reason_codes=["OUTCOME_PRESERVED", "OUTCOME_LOST"]),
    lambda d: d["summary"].update(scenario_count=-1),
    lambda d: d["scenarios"][0].update(extra="RAW_LOG_CANARY"),
])
def test_r2_rejects_resealed_schema_and_privacy_tampering(snapshot_data, mutation):
    import copy
    data = copy.deepcopy(snapshot_data)
    mutation(data)
    with pytest.raises(ProjectionError) as exc:
        decode_snapshot(_reseal(data))
    assert "CANARY" not in str(exc.value)


def test_r2_invalid_bytes_and_fixed_cli_failure(monkeypatch, capsys):
    from app.evaluation import counterfactual_safe_projection_cli as cli
    for invalid in (b"\xff", b'{"x":Infinity}', b'{"x":-Infinity}'):
        with pytest.raises(ProjectionError):
            decode_snapshot(invalid)
    def fail():
        raise RuntimeError("EXCEPTION_CANARY")
    monkeypatch.setattr(cli, "build_snapshot", fail)
    assert cli.main([]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "INVALID_PROJECTION\n"
    assert cli.main(["--path"]) == 2
    assert capsys.readouterr().err == "INVALID_PROJECTION\n"


def test_r2_cli_deterministic_and_network_denied(monkeypatch):
    import socket
    import subprocess
    import sys
    def denied(*args, **kwargs):
        pytest.fail("network connection attempted")
    monkeypatch.setattr(socket.socket, "connect", denied)
    monkeypatch.setattr(socket.socket, "connect_ex", denied)
    monkeypatch.setattr(socket, "create_connection", denied)
    first = encode_snapshot(build_snapshot())
    assert first == encode_snapshot(build_snapshot())
    result = subprocess.run([sys.executable, "-m", "app.evaluation.counterfactual_safe_projection_cli"], capture_output=True, check=False)
    assert result.returncode == 0 and result.stderr == b"" and result.stdout == first


@pytest.mark.parametrize(("actual", "forged"), [
    ("LOST", "PRESERVED"), ("GAINED", "LOST"),
    ("PRESERVED", "GAINED"), ("UNCHANGED_ABSENT", "PRESERVED"),
])
def test_r2_real_report_boundary_rejects_forged_replay(monkeypatch, actual, forged):
    from dataclasses import replace
    from app.evaluation import counterfactual_safe_projection as module
    original = module.run_corpus()
    row = next(item for item in original.results if item.comparison_state == actual)
    rows = tuple(replace(item, comparison_state=forged) if item is row else item for item in original.results)
    counts = dict(original.counts)
    counts["comparison"] = dict(counts["comparison"])
    counts["comparison"][actual] -= 1
    counts["comparison"][forged] += 1
    monkeypatch.setattr(module, "run_corpus", lambda: replace(original, results=rows, counts=counts))
    with pytest.raises(ProjectionError, match="INVALID_PROJECTION"):
        module.build_snapshot()


def test_r2_digest_scope_and_deep_mutation_isolation(snapshot_data):
    import hashlib
    body = {key: value for key, value in snapshot_data.items() if key != "snapshot_sha256"}
    assert snapshot_data["snapshot_sha256"] == hashlib.sha256(json.dumps(body, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    snapshot = decode_snapshot(_reseal(snapshot_data.copy()))
    before = encode_snapshot(snapshot)
    snapshot_data["scenarios"][0]["reason_codes"].append("CANARY")
    assert encode_snapshot(snapshot) == before
