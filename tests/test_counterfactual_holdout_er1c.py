import hashlib
import json
from pathlib import Path
import shutil
import socket
import tempfile

import pytest

from app.evaluation.counterfactual_comparison import ComparisonState
from app.evaluation.counterfactual_holdout import (
    HoldoutError,
    audit_scenario,
    canonical_holdout_json,
    load_holdout,
    run_holdout,
)


def test_holdout_has_twelve_independent_scenarios_and_required_coverage():
    corpus = load_holdout()
    assert len(corpus.scenarios) >= 12
    assert sum(item.detector_id == "brute_force" for item in corpus.scenarios) >= 6
    assert sum(item.detector_id == "password_spraying_like" for item in corpus.scenarios) >= 6
    assert sum(item.source == "ssh" for item in corpus.scenarios) >= 4
    assert {item.source for item in corpus.scenarios} == {"application", "ssh"}
    assert {item.expected_parser_disposition for item in corpus.scenarios} >= {
        "VERIFIED", "PARTIAL", "REJECTED",
    }
    assert corpus.human_review_status == "INDEPENDENT_HUMAN_REVIEW_PENDING"


def test_holdout_labels_are_audited_from_input_facts_without_detector_output():
    corpus = load_holdout()
    audit = corpus.audit
    assert audit.status == "AUTOMATED_CONTRACT_VALIDATED"
    assert audit.scenario_count == len(corpus.scenarios)
    assert audit.input_validation_failures == 0
    assert audit.label_mismatches == 0
    assert all(item.input_facts_match and item.pattern_label_match for item in audit.rows)


def test_development_corpus_label_audit_is_separate_and_human_review_pending():
    from app.evaluation.counterfactual_holdout import audit_development_corpus

    audit = audit_development_corpus()
    assert audit.status == "AUTOMATED_CONTRACT_VALIDATED"
    assert audit.scenario_count == 16
    assert audit.input_validation_failures == 0
    assert audit.label_mismatches == 0
    assert audit.parser_baseline_counts["VERIFIED"] == 16
    assert audit.parser_variant_counts == {
        "VERIFIED": 13, "PARTIAL": 2, "REJECTED": 1, "NOT_EVALUATED": 0,
    }
    assert audit.human_review_status == "INDEPENDENT_HUMAN_REVIEW_PENDING"


def test_holdout_parser_bytes_are_the_bytes_replayed_with_fresh_run_owners(monkeypatch):
    from app.evaluation import counterfactual_holdout as holdout_module
    from app.evaluation import counterfactual_replay as replay
    from app.detector.brute_force import AnalysisRunOwner

    parser_inputs = []
    production_inputs = []
    owners = {}
    original_parser = holdout_module._parse_fixture
    original_executor = replay._execute_production
    original_entrypoint = replay.analyze_with_source_role_snapshot
    paths = []

    def parser(source, data):
        disposition, events = original_parser(source, data)
        parser_inputs.append((disposition, data))
        return disposition, events

    def entrypoint(configs):
        path = Path(configs[0]["path"])
        paths.append(path)
        production_inputs.append(path.read_bytes())
        return original_entrypoint(configs)

    def executor(scenario, input_bytes, *args, **kwargs):
        execution, observation = original_executor(scenario, input_bytes, *args, **kwargs)
        owners.setdefault(scenario.scenario_id, []).append(execution.owner)
        return execution, observation

    monkeypatch.setattr(holdout_module, "_parse_fixture", parser)
    monkeypatch.setattr(replay, "analyze_with_source_role_snapshot", entrypoint)
    monkeypatch.setattr(replay, "_execute_production", executor)
    report = run_holdout()

    parsed_for_detector = [data for state, data in parser_inputs if state != "REJECTED"]
    assert parsed_for_detector == production_inputs
    assert len(production_inputs) == 2 * report.scenario_count - 1
    assert all(not path.exists() for path in paths)
    for scenario_owners in owners.values():
        owned = [owner for owner in scenario_owners if owner is not None]
        assert len(owned) in (1, 2)
        assert all(type(owner) is AnalysisRunOwner for owner in owned)
        assert len({id(owner) for owner in owned}) == len(owned)


def test_audit_reports_label_mismatch_without_rewriting_expected_label():
    corpus = load_holdout()
    scenario = corpus.scenarios[0]
    baseline = corpus.fixture_bytes[scenario.baseline_fixture_id]
    variant = corpus.variant_bytes[scenario.scenario_id]
    wrong = scenario.__class__(
        **{
            field: getattr(scenario, field)
            for field in scenario.__dataclass_fields__
        }
    )
    object.__setattr__(wrong, "expected_behavioral_pattern", "PATTERN_ABSENT")
    result = audit_scenario(wrong, baseline, variant)
    assert result.pattern_label_match is False
    assert result.expected_variant_pattern == "PATTERN_ABSENT"
    assert "DETECTED" not in result.status


def test_audit_output_does_not_echo_free_form_label_basis_canary():
    corpus = load_holdout()
    scenario = corpus.scenarios[0]
    fields = {field: getattr(scenario, field) for field in scenario.__dataclass_fields__}
    fields["label_basis"] = "ER1C_PRIVATE_CANARY"
    canary_scenario = scenario.__class__(**fields)
    row = audit_scenario(
        canary_scenario,
        corpus.fixture_bytes[scenario.baseline_fixture_id],
        corpus.variant_bytes[scenario.scenario_id],
    )
    assert "ER1C_PRIVATE_CANARY" not in json.dumps(row.to_mapping())


@pytest.mark.parametrize(
    ("payload", "reason"),
    [
        (b'{"schema_version":1,"schema_version":1}', "INVALID_MANIFEST"),
        (b'{"value":NaN}', "INVALID_MANIFEST"),
        (b'{"value":Infinity}', "INVALID_MANIFEST"),
        (b"\xff", "INVALID_MANIFEST"),
    ],
)
def test_holdout_manifest_decoder_rejects_unsafe_json(payload, reason):
    from app.evaluation.counterfactual_holdout import decode_holdout_manifest

    with pytest.raises(HoldoutError) as caught:
        decode_holdout_manifest(payload)
    assert caught.value.code == reason


@pytest.mark.parametrize("change", ["unknown_root", "unknown_field", "unknown_enum", "path_traversal"])
def test_holdout_manifest_rejects_open_schema_and_traversal(change):
    from app.evaluation.counterfactual_holdout import decode_holdout_manifest

    manifest = json.loads(load_holdout().raw_manifest)
    if change == "unknown_root":
        manifest["extra"] = True
    elif change == "unknown_field":
        manifest["scenarios"][0]["hidden"] = "value"
    elif change == "unknown_enum":
        manifest["scenarios"][0]["expected_parser_disposition"] = "ACCEPTED"
    else:
        manifest["scenarios"][0]["baseline_fixture_id"] = "../outside"
    with pytest.raises(HoldoutError) as caught:
        decode_holdout_manifest(json.dumps(manifest, allow_nan=False).encode())
    assert caught.value.code == "INVALID_MANIFEST"


@pytest.mark.parametrize("damage", ["symlink", "oversized", "invalid_utf8", "extra_file"])
def test_holdout_loader_fails_closed_on_fixture_filesystem_damage(monkeypatch, damage):
    from app.evaluation import counterfactual_holdout as holdout

    with tempfile.TemporaryDirectory(prefix="er1c-safe-fixture-") as temporary:
        root = Path(temporary) / "holdout"
        shutil.copytree(holdout.HOLDOUT_ROOT, root)
        fixture_id = load_holdout().scenarios[0].baseline_fixture_id
        fixture = root / f"{fixture_id}.log"
        if damage == "symlink":
            outside = Path(temporary) / "outside.log"
            outside.write_bytes(fixture.read_bytes())
            fixture.unlink()
            fixture.symlink_to(outside)
        elif damage == "oversized":
            fixture.write_bytes(b"x" * 8193)
        elif damage == "invalid_utf8":
            fixture.write_bytes(b"\xff\n")
        else:
            (root / "unlisted.txt").write_text("synthetic", encoding="utf-8")
        monkeypatch.setattr(holdout, "HOLDOUT_ROOT", root)
        with pytest.raises(HoldoutError):
            load_holdout()


def test_holdout_loader_rejects_manifest_and_fixture_digest_changes(monkeypatch):
    from app.evaluation import counterfactual_holdout as holdout

    corpus = load_holdout()
    scenario = corpus.scenarios[0]
    original_bytes = corpus.fixture_bytes[scenario.baseline_fixture_id]
    changed_hashes = {"schema_version": 1, **dict(corpus.hashes)}
    changed_hashes["fixtures"] = dict(corpus.hashes["fixtures"])
    monkeypatch.setattr(
        holdout,
        "_read_manifest_and_fixtures",
        lambda: (corpus.raw_manifest + b" ", dict(corpus.fixture_bytes), changed_hashes),
    )
    with pytest.raises(HoldoutError) as caught:
        load_holdout()
    assert caught.value.code == "HASH_MISMATCH"
    assert hashlib.sha256(original_bytes).hexdigest() == corpus.hashes["fixtures"][scenario.baseline_fixture_id]

    changed_manifest = json.loads(corpus.raw_manifest)
    changed_manifest["scenarios"][0]["expected_behavioral_pattern"] = "PATTERN_ABSENT"
    changed_manifest_bytes = (json.dumps(changed_manifest, ensure_ascii=False, indent=2) + "\n").encode()
    sidecar = {
        "schema_version": 1,
        "manifest_sha256": corpus.hashes["manifest_sha256"],
        "fixtures": dict(corpus.hashes["fixtures"]),
    }
    monkeypatch.setattr(
        holdout, "_read_manifest_and_fixtures",
        lambda: (changed_manifest_bytes, dict(corpus.fixture_bytes), sidecar),
    )
    with pytest.raises(HoldoutError) as caught:
        load_holdout()
    assert caught.value.code == "HASH_MISMATCH"

    changed_fixtures = dict(corpus.fixture_bytes)
    changed_fixtures[scenario.baseline_fixture_id] = original_bytes + b"\n"
    sidecar["manifest_sha256"] = hashlib.sha256(corpus.raw_manifest).hexdigest()
    monkeypatch.setattr(
        holdout, "_read_manifest_and_fixtures",
        lambda: (corpus.raw_manifest, changed_fixtures, sidecar),
    )
    with pytest.raises(HoldoutError) as caught:
        load_holdout()
    assert caught.value.code == "HASH_MISMATCH"


def test_holdout_result_runs_real_production_replay_and_all_dimensions():
    result = run_holdout()
    assert result.corpus_id == "er1c_independent_holdout_v1"
    assert result.human_review_status == "INDEPENDENT_HUMAN_REVIEW_PENDING"
    assert result.scenario_count >= 12
    assert set(result.counts["comparison"]) == {item.value for item in ComparisonState}
    assert all(result.counts["comparison"][state] > 0 for state in (
        "PRESERVED", "LOST", "GAINED", "UNCHANGED_ABSENT", "INCOMPARABLE",
    ))
    assert result.counts["input_validation_failures"] == 0
    assert result.counts["execution_failures"] == 0
    assert result.counts["label_validation"]["mismatch_total"] == 0
    assert len(result.results) == result.scenario_count
    assert result.development_audit.scenario_count == 16
    assert result.development_audit.status == "AUTOMATED_CONTRACT_VALIDATED"


def test_holdout_canonical_json_is_deterministic_private_and_bounded():
    first = canonical_holdout_json(run_holdout())
    second = canonical_holdout_json(run_holdout())
    assert first == second
    assert len(first) <= 64 * 1024
    decoded = json.loads(first)
    assert decoded["corpus_kind"] == "holdout"
    assert decoded["independent_human_review_status"] == "INDEPENDENT_HUMAN_REVIEW_PENDING"
    assert decoded["label_provenance"] == "INDEPENDENT_INPUT_FACTS_AND_POLICY_TABLE"
    assert decoded["development_corpus_audit"]["corpus_kind"] == "development"
    assert decoded["development_corpus_audit"]["scenario_count"] == 16
    assert decoded["development_corpus_audit"]["parser_variant"] == {
        "VERIFIED": 13, "PARTIAL": 2, "REJECTED": 1, "NOT_EVALUATED": 0,
    }
    for forbidden in (
        "192.0.2.", "198.51.100.", "203.0.113.", "synthetic_user_",
        "2026-11-04", "/tmp/", "ER1C_PRIVATE_CANARY",
    ):
        assert forbidden not in first.decode("utf-8")


def test_holdout_replay_uses_allowlisted_inputs_and_attempts_no_network(monkeypatch, capsys):
    attempts = []

    def denied(_socket, *_args, **_kwargs):
        attempts.append(True)
        raise AssertionError("network disabled")

    monkeypatch.setattr(socket.socket, "connect", denied)
    monkeypatch.setattr(socket.socket, "connect_ex", denied)
    run_holdout()
    captured = capsys.readouterr()
    assert attempts == []
    assert captured.out == captured.err == ""


def test_holdout_cli_has_no_path_arguments_or_exception_echo(capsys):
    from app.evaluation.counterfactual_holdout_cli import main

    assert main([]) == 0
    result = capsys.readouterr()
    assert result.out.encode() == canonical_holdout_json(run_holdout())
    assert result.err == ""
    assert main(["ER1C_PRIVATE_CANARY"]) == 2
    error = capsys.readouterr()
    assert error.out == ""
    assert error.err == "INVALID_INTERNAL_CONTRACT\n"
    assert "ER1C_PRIVATE_CANARY" not in error.err


def test_holdout_does_not_change_development_corpus_results():
    from app.evaluation.counterfactual_replay import run_corpus

    report = run_corpus()
    assert report.scenario_count == 16
    assert report.counts["comparison"] == {
        "PRESERVED": 4,
        "LOST": 6,
        "GAINED": 2,
        "UNCHANGED_ABSENT": 1,
        "INCOMPARABLE": 3,
        "UNDETERMINED": 0,
    }
    assert report.counts["label_baseline"]["MATCH"] == 16
    assert report.counts["label_variant"]["MATCH"] == 13
    assert report.counts["label_variant"]["NOT_EVALUATED"] == 3
