import json
import pytest

from app.evaluation.counterfactual_corpus import (
    CounterfactualCorpusError,
    load_corpus,
    prepare_corpus,
)
from app.evaluation.counterfactual_mutation import apply_mutation


def test_er1a_corpus_has_bounded_closed_independent_cases_and_parsers():
    scenarios = load_corpus()
    assert len(scenarios) >= 14
    assert {item.detector_id for item in scenarios} == {
        "brute_force", "password_spraying_like",
    }
    assert {item.source for item in scenarios} == {"application", "ssh"}
    assert {item.mutation_type for item in scenarios} == {
        "remove_failure_row", "add_failure_row", "change_timestamp",
        "change_account", "change_source_ip", "reorder_rows", "damage_format",
    }

    prepared = prepare_corpus()
    assert len(prepared) == len(scenarios)
    assert all(item.baseline_parser_disposition == "VERIFIED" for item in prepared)
    assert all(item.parser_disposition == scenario.expected_parser_disposition
               for item, scenario in zip(prepared, scenarios))
    assert {item.parser_disposition for item in prepared} >= {
        "VERIFIED", "PARTIAL", "REJECTED",
    }
    assert all(item.detector_execution == "NOT_EVALUATED" for item in prepared)
    assert all(item.comparison_status == "NOT_EVALUATED" for item in prepared)


def test_independent_pattern_labels_cover_present_absent_and_undetermined():
    prepared = prepare_corpus()
    assert {item.expected_behavioral_pattern for item in prepared} == {
        "PATTERN_PRESENT", "PATTERN_ABSENT", "PATTERN_UNDETERMINED",
    }
    assert all(item.label_validated is True for item in prepared)
    assert all(not hasattr(item, "detection_result") for item in prepared)


def test_mutation_changes_bytes_without_mutating_source_and_is_deterministic():
    source = (
        b"2026-11-04 09:00:00 INFO login_failed "
        b"user=synthetic_user_01 ip=192.0.2.10 service=ssh\n"
    )
    original = bytes(source)
    kwargs = {
        "source": "application",
        "mutation_type": "change_account",
        "mutation_target": "row:0",
        "mutation_parameters": {"account": "synthetic_user_02"},
    }
    first = apply_mutation(source, **kwargs)
    second = apply_mutation(source, **kwargs)
    assert first != source
    assert first == second
    assert source == original


def test_each_manifested_mutation_changes_only_a_new_byte_copy():
    from app.evaluation.counterfactual_corpus import load_fixture

    scenarios = load_corpus()
    mutation_types = set()
    for scenario in scenarios:
        mutation_types.add(scenario.mutation_type)
        original = load_fixture(scenario.baseline_fixture_id)
        mutated = apply_mutation(
            original,
            source=scenario.source,
            mutation_type=scenario.mutation_type,
            mutation_target=scenario.mutation_target,
            mutation_parameters=_plain(scenario.mutation_parameters),
        )
        assert mutated != original
        assert load_fixture(scenario.baseline_fixture_id) == original
    assert mutation_types == {
        "remove_failure_row", "add_failure_row", "change_timestamp",
        "change_account", "change_source_ip", "reorder_rows", "damage_format",
    }


def _plain(value):
    if hasattr(value, "items"):
        return {key: _plain(item) for key, item in value.items()}
    if type(value) is tuple:
        return [_plain(item) for item in value]
    return value


def test_row_order_mutation_preserves_timestamps_and_field_multiset():
    from app.evaluation.counterfactual_corpus import load_fixture

    scenario = next(item for item in load_corpus() if item.mutation_type == "reorder_rows")
    source_bytes = load_fixture(scenario.baseline_fixture_id)
    changed = apply_mutation(
        source_bytes,
        source=scenario.source,
        mutation_type=scenario.mutation_type,
        mutation_target=scenario.mutation_target,
        mutation_parameters=_plain(scenario.mutation_parameters),
    )
    assert sorted(source_bytes.splitlines()) == sorted(changed.splitlines())
    assert source_bytes != changed


@pytest.mark.parametrize(
    ("mutation_type", "target", "parameters"),
    [
        ("unknown", "row:0", {}),
        ("change_source_ip", "row:0", {"source_ip": "127.0.0.1"}),
        ("change_account", "row:0", {"account": "real-user"}),
        ("change_timestamp", "row:0", {"timestamp": "not-a-time"}),
        ("remove_failure_row", "row:9", {}),
        ("reorder_rows", "all_rows", {"order": [0, 0]}),
        ("damage_format", "row:0", {"damage_type": "unknown"}),
    ],
)
def test_invalid_mutation_preconditions_fail_with_fixed_codes(
    mutation_type, target, parameters,
):
    source_bytes = (
        b"2026-11-04 09:00:00 INFO login_failed "
        b"user=synthetic_user_01 ip=192.0.2.10 service=ssh\n"
    )
    with pytest.raises(CounterfactualCorpusError) as caught:
        apply_mutation(
            source_bytes,
            source="application",
            mutation_type=mutation_type,
            mutation_target=target,
            mutation_parameters=parameters,
        )
    assert str(caught.value) in {
        "invalid_mutation", "mutation_precondition_failed", "unsupported_mutation",
        "unsupported_source",
    }
    assert "192.0.2.10" not in str(caught.value)
    assert "synthetic_user_01" not in str(caught.value)


@pytest.mark.parametrize(
    "raw",
    [
        b'{"schema_version":1,"schema_version":1}',
        b'{"schema_version":1,"x":NaN}',
        b"\xff",
        json.dumps({"schema_version": 2, "data_scope": "synthetic-only", "scenarios": []}).encode(),
    ],
)
def test_manifest_decoder_fails_closed_without_echo(raw):
    from app.evaluation.counterfactual_corpus import decode_manifest

    with pytest.raises(CounterfactualCorpusError) as caught:
        decode_manifest(raw)
    assert str(caught.value) == "invalid_manifest"
    assert "NaN" not in str(caught.value)


def test_fixture_symlink_and_traversal_are_rejected(tmp_path, monkeypatch):
    from app.evaluation import counterfactual_corpus as corpus

    root = tmp_path / "corpus"
    root.mkdir()
    source = tmp_path / "outside.log"
    source.write_bytes(b"synthetic\n")
    (root / "safe_fixture.log").symlink_to(source)
    monkeypatch.setattr(corpus, "CORPUS_ROOT", root)
    with pytest.raises(CounterfactualCorpusError) as caught:
        corpus.load_fixture("safe_fixture")
    assert str(caught.value) == "fixture_unavailable"
    with pytest.raises(CounterfactualCorpusError) as caught:
        corpus.load_fixture("../outside")
    assert str(caught.value) == "invalid_manifest"


def test_fixture_size_and_utf8_are_bounded(tmp_path, monkeypatch):
    from app.evaluation import counterfactual_corpus as corpus

    monkeypatch.setattr(corpus, "CORPUS_ROOT", tmp_path)
    (tmp_path / "oversized.log").write_bytes(b"x" * (corpus.MAX_FIXTURE_BYTES + 1))
    with pytest.raises(CounterfactualCorpusError) as caught:
        corpus.load_fixture("oversized")
    assert str(caught.value) == "fixture_unavailable"
    (tmp_path / "invalid_utf8.log").write_bytes(b"\xff\n")
    with pytest.raises(CounterfactualCorpusError) as caught:
        corpus.load_fixture("invalid_utf8")
    assert str(caught.value) == "invalid_utf8"


def test_unknown_source_and_canary_are_not_reflected_in_errors():
    canary = b"ER1A_SYNTHETIC_PRIVATE_CANARY"
    with pytest.raises(CounterfactualCorpusError) as caught:
        apply_mutation(
            canary,
            source="outside",
            mutation_type="remove_failure_row",
            mutation_target="row:0",
            mutation_parameters={},
        )
    assert str(caught.value) == "unsupported_source"
    assert canary.decode() not in repr(caught.value)


def test_independent_label_conflict_is_rejected_with_fixed_category():
    from dataclasses import replace

    scenario = next(item for item in load_corpus() if item.expected_behavioral_pattern == "PATTERN_PRESENT")
    conflicting = replace(scenario, expected_behavioral_pattern="PATTERN_ABSENT")
    with pytest.raises(CounterfactualCorpusError) as caught:
        from app.evaluation.counterfactual_corpus import prepare_scenario

        prepare_scenario(conflicting)
    assert str(caught.value) == "label_mismatch"
    assert scenario.target_subject not in repr(caught.value)


def test_original_counterfactual_corpus_is_unchanged_by_preparation():
    from app.evaluation import counterfactual_corpus as corpus

    root = corpus.CORPUS_ROOT
    before = {
        path.name: path.read_bytes()
        for path in root.glob("*.log")
    }
    prepare_corpus()
    after = {
        path.name: path.read_bytes()
        for path in root.glob("*.log")
    }
    assert after == before


def test_manifest_unknown_fields_and_paths_fail_closed(tmp_path, monkeypatch):
    import shutil
    from app.evaluation import counterfactual_corpus as corpus

    root = tmp_path / "copy"
    shutil.copytree(corpus.CORPUS_ROOT, root)
    monkeypatch.setattr(corpus, "CORPUS_ROOT", root)
    original = json.loads((root / "manifest.json").read_text(encoding="utf-8"))

    unknown = json.loads(json.dumps(original))
    unknown["unexpected"] = "canary"
    (root / "manifest.json").write_text(json.dumps(unknown), encoding="utf-8")
    with pytest.raises(CounterfactualCorpusError) as caught:
        corpus.load_corpus()
    assert str(caught.value) == "invalid_manifest"

    contradictory = json.loads(json.dumps(original))
    contradictory["scenarios"][0]["expected_event_facts"]["event_count"] = 0
    (root / "manifest.json").write_text(json.dumps(contradictory), encoding="utf-8")
    with pytest.raises(CounterfactualCorpusError) as caught:
        corpus.load_corpus()
    assert str(caught.value) == "invalid_manifest"

    unevaluated = json.loads(json.dumps(original))
    unevaluated["scenarios"][0]["expected_parser_disposition"] = "NOT_EVALUATED"
    unevaluated["scenarios"][0]["expected_event_facts"] = None
    unevaluated["scenarios"][0]["expected_behavioral_pattern"] = "PATTERN_UNDETERMINED"
    (root / "manifest.json").write_text(json.dumps(unevaluated), encoding="utf-8")
    with pytest.raises(CounterfactualCorpusError) as caught:
        corpus.load_corpus()
    assert str(caught.value) == "invalid_manifest"
    assert "canary" not in repr(caught.value)

    traversal = json.loads(json.dumps(original))
    traversal["scenarios"][0]["baseline_fixture_id"] = "../outside"
    (root / "manifest.json").write_text(json.dumps(traversal), encoding="utf-8")
    with pytest.raises(CounterfactualCorpusError) as caught:
        corpus.load_corpus()
    assert str(caught.value) == "invalid_manifest"


def test_parser_unexpected_execution_failure_is_not_rejection(monkeypatch):
    from app.evaluation import counterfactual_corpus as corpus

    monkeypatch.setattr(
        corpus,
        "load_normalized_logs",
        lambda _sources: (_ for _ in ()).throw(RuntimeError("PRIVATE_CANARY")),
    )
    with pytest.raises(CounterfactualCorpusError) as caught:
        corpus._parse_fixture("application", b"synthetic\n")
    assert str(caught.value) == "parser_execution_failed"
    assert "PRIVATE_CANARY" not in repr(caught.value)


def test_preparation_is_byte_deterministic_and_keeps_detector_unrun():
    first = prepare_corpus()
    second = prepare_corpus()
    assert first == second
    assert all(item.detector_execution == "NOT_EVALUATED" for item in first)
    assert all(item.comparison_status == "NOT_EVALUATED" for item in first)
