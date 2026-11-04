import hashlib
import json
import socket

import pytest

from app.evaluation.counterfactual_review_packet import (
    ReviewSubmissionError,
    build_review_packet,
    canonical_review_packet_json,
    compare_review_submission,
    decode_review_submission,
)


def _scenario(packet, scenario_id):
    return next(item for item in packet.to_mapping()["scenarios"] if item["scenario_id"] == scenario_id)


def test_blind_packet_covers_all_30_scenarios_and_omits_existing_answers():
    packet = build_review_packet()
    raw = canonical_review_packet_json(packet)
    mapping = json.loads(raw)
    assert len(mapping["scenarios"]) == 30
    assert mapping["review_status"] == "INDEPENDENT_HUMAN_REVIEW_PENDING"
    assert {item["corpus_id"] for item in mapping["scenarios"]} == {
        "er1a_development", "er1c_independent_holdout_v1",
    }
    for scenario in mapping["scenarios"]:
        assert "expected_pattern" not in scenario
        assert "detector_output" not in scenario
        assert "comparison_result" not in scenario
        assert "label_basis" not in scenario
        assert "review_match" not in scenario
    encoded = raw.decode("utf-8")
    for forbidden in (
        "PATTERN_PRESENT", "PATTERN_ABSENT", "PRESERVED", "LOST", "GAINED",
        "MATCH", "synthetic_user_", "192.0.2.", "198.51.100.", "203.0.113.",
        "ER1C_PRIVATE_CANARY",
    ):
        assert forbidden not in encoded


def test_packet_is_deterministic_bounded_and_bound_to_source_digests():
    first = canonical_review_packet_json(build_review_packet())
    second = canonical_review_packet_json(build_review_packet())
    assert first == second
    assert len(first) <= 512 * 1024
    packet = json.loads(first)
    assert len(packet["source_corpora"]["er1a_development"]["fixture_sha256"]) == 16
    assert len(packet["source_corpora"]["er1c_independent_holdout_v1"]["fixture_sha256"]) == 14
    digest = packet.pop("packet_sha256")
    canonical_body = (json.dumps(packet, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()
    assert hashlib.sha256(canonical_body).hexdigest() == digest


def test_packet_preserves_anonymized_group_relations_across_mutation():
    packet = build_review_packet()
    scenario = _scenario(packet, "er1c_bf_app_subject_membership_change")
    baseline, variant = scenario["baseline"]["events"], scenario["variant"]["events"]
    baseline_ip_groups = {event["source_group"] for event in baseline}
    variant_ip_groups = {event["source_group"] for event in variant}
    assert len(baseline_ip_groups) == 1
    assert len(variant_ip_groups) == 2
    assert baseline_ip_groups < variant_ip_groups
    assert all(event["account_group"] is not None for event in baseline + variant)
    assert all("src_ip" not in event and "user" not in event for event in baseline + variant)


def test_packet_separates_input_order_from_timestamp_order_and_keeps_exact_spans():
    packet = build_review_packet()
    reordered = _scenario(packet, "er1c_spray_app_exact60_permutation")
    baseline = reordered["baseline"]["events"]
    variant = reordered["variant"]["events"]
    assert [event["chronological_order"] for event in variant] != list(range(len(variant)))
    assert sorted(event["chronological_order"] for event in variant) == list(range(len(variant)))
    for scenario_id, baseline_span, variant_span in (
        ("er1c_bf_ssh_61_second_crossing", 60, 61),
        ("er1c_bf_app_61_to_60", 61, 60),
        ("er1c_spray_ssh_span_61", 60, 61),
        ("er1c_spray_app_exact60_permutation", 60, 60),
    ):
        item = _scenario(packet, scenario_id)
        for side, expected_span in (("baseline", baseline_span), ("variant", variant_span)):
            rows = item[side]["events"]
            span = max(x["relative_seconds"] for x in rows) - min(x["relative_seconds"] for x in rows)
            assert span == expected_span


def test_packet_discloses_parser_gaps_without_rewriting_rejected_input_as_events():
    packet = build_review_packet()
    partial = _scenario(packet, "er1c_bf_app_partial_missing_user")
    rejected = _scenario(packet, "er1c_bf_ssh_rejected_timestamp")
    assert partial["variant"]["parser_disposition"] == "PARTIAL"
    assert any(event["account_group"] is None for event in partial["variant"]["events"])
    assert rejected["variant"]["parser_disposition"] == "REJECTED"
    assert rejected["variant"]["events"] == []
    assert rejected["variant"]["unmapped_input_line_count"] > 0


def test_direct_mutation_is_separate_from_observed_derived_changes():
    packet = build_review_packet()
    item = _scenario(packet, "er1c_spray_app_third_account_added")
    assert item["direct_change"]["kind"] == "change_account"
    assert "target_account_cardinality_changed" in item["derived_observations"]
    assert "unique_cause_claimed" not in item


def test_blind_source_contract_has_no_label_or_replay_fields():
    import app.evaluation.counterfactual_review_packet as module
    from dataclasses import fields

    names = {field.name for field in fields(module.BlindScenarioInput)}
    assert not names.intersection({
        "expected_pattern", "baseline_expected_behavioral_pattern",
        "expected_behavioral_pattern", "label_basis", "detector_output",
        "comparison_result", "replay_result",
    })


def test_packet_builder_does_not_load_label_bearing_scenario_dtos(monkeypatch):
    import app.evaluation.counterfactual_corpus as development
    import app.evaluation.counterfactual_holdout as holdout

    def forbidden():
        raise AssertionError("label-bearing corpus DTO loader must not run")

    monkeypatch.setattr(development, "load_corpus", forbidden)
    monkeypatch.setattr(holdout, "decode_holdout_manifest", forbidden)
    monkeypatch.setattr(holdout, "_validate_scenario", forbidden)
    assert len(build_review_packet().scenarios) == 30


def test_submission_contract_rejects_unknown_duplicate_and_wrong_packet():
    packet = build_review_packet()
    mapping = packet.to_mapping()
    digest = mapping["packet_sha256"]
    bad_cases = [
        b'{"schema_version":1,"schema_version":1}',
        json.dumps({"schema_version": 1, "packet_sha256": digest, "reviewer": {}, "responses": [{"scenario_id": "x", "review_status": "REVIEWED", "baseline_label": "PATTERN_GUESS", "variant_label": "PATTERN_ABSENT"}]}).encode(),
    ]
    for raw in bad_cases:
        with pytest.raises(ReviewSubmissionError):
            decode_review_submission(raw, packet)
    response = _valid_submission(packet, responses=[])
    response["packet_sha256"] = "0" * 64
    with pytest.raises(ReviewSubmissionError) as caught:
        compare_review_submission(json.dumps(response).encode())
    assert caught.value.code == "PACKET_DIGEST_MISMATCH"


def _valid_submission(packet, responses):
    return {
        "schema_version": 1,
        "packet_sha256": packet.to_mapping()["packet_sha256"],
        "reviewer": {
            "reviewer_ref": "reviewer_local_01",
            "independence_claim": "DECLARED_INDEPENDENT",
            "has_viewed_existing_labels_or_replay": False,
        },
        "responses": responses,
    }


def test_missing_or_auto_generated_review_never_marks_human_review_complete():
    packet = build_review_packet()
    report = compare_review_submission(json.dumps(_valid_submission(packet, [])).encode())
    assert report.review_status == "INDEPENDENT_HUMAN_REVIEW_PENDING"
    assert report.scenario_count == 30
    assert report.counts["NOT_REVIEWED"] == 30
    assert report.independence_verification == "SELF_REPORTED_NOT_VERIFIED"


def test_actual_submission_comparison_is_read_only_and_never_upgrades_approval():
    packet = build_review_packet()
    rows = packet.to_mapping()["scenarios"]
    labels = {(row["corpus_id"], row["scenario_id"]): row for row in _expected_labels_for_test_only()}
    responses = [
        {
            "scenario_id": row["scenario_id"],
            "review_status": "REVIEWED",
            "baseline_label": labels[(row["corpus_id"], row["scenario_id"])]["baseline"],
            "variant_label": labels[(row["corpus_id"], row["scenario_id"])]["variant"],
            "parser_scope": "SUFFICIENT" if row["baseline"]["parser_disposition"] == row["variant"]["parser_disposition"] == "VERIFIED" else "UNDETERMINED",
            "review_opinion": "synthetic review note",
        }
        for row in rows
    ]
    report = compare_review_submission(json.dumps(_valid_submission(packet, responses)).encode())
    assert sum(report.counts.values()) == 30
    assert report.counts["INSUFFICIENT_EVIDENCE"] > 0
    assert report.review_status == "INDEPENDENT_HUMAN_REVIEW_PENDING"
    assert report.approval_status == "MANUAL_APPROVAL_REQUIRED"
    assert report.independence_verification == "SELF_REPORTED_NOT_VERIFIED"
    assert report.has_viewed_existing_labels_or_replay is False
    assert all("review_opinion" not in item for item in report.to_mapping()["scenarios"])


def test_review_cannot_claim_sufficient_scope_for_parser_incomplete_fixture():
    packet = build_review_packet()
    labels = {(row["corpus_id"], row["scenario_id"]): row for row in _expected_labels_for_test_only()}
    target = _scenario(packet, "er1c_bf_app_partial_missing_user")
    response = {
        "scenario_id": target["scenario_id"], "review_status": "REVIEWED",
        "baseline_label": labels[(target["corpus_id"], target["scenario_id"])]["baseline"],
        "variant_label": labels[(target["corpus_id"], target["scenario_id"])]["variant"],
        "parser_scope": "SUFFICIENT", "review_opinion": "synthetic",
    }
    report = compare_review_submission(json.dumps(_valid_submission(packet, [response])).encode())
    result = next(row for row in report.scenarios if row["scenario_id"] == target["scenario_id"])
    assert result["comparison"] == "INSUFFICIENT_EVIDENCE"


def _expected_labels_for_test_only():
    """Test-only fixture to verify comparison outcomes; production code must not import this."""
    from app.evaluation.counterfactual_corpus import load_corpus
    from app.evaluation.counterfactual_holdout import load_holdout

    values = []
    for scenario in load_corpus():
        values.append({
            "corpus_id": "er1a_development",
            "scenario_id": scenario.scenario_id,
            "baseline": scenario.baseline_expected_behavioral_pattern,
            "variant": scenario.expected_behavioral_pattern,
        })
    for scenario in load_holdout().scenarios:
        values.append({
            "corpus_id": "er1c_independent_holdout_v1",
            "scenario_id": scenario.scenario_id,
            "baseline": scenario.baseline_expected_behavioral_pattern,
            "variant": scenario.expected_behavioral_pattern,
        })
    return values


def test_submission_comparator_rejects_duplicate_unknown_and_invalid_labels():
    packet = build_review_packet()
    scenario_id = packet.to_mapping()["scenarios"][0]["scenario_id"]
    base = _valid_submission(packet, [])
    invalid_rows = [
        [{"scenario_id": scenario_id, "review_status": "NOT_REVIEWED", "baseline_label": None, "variant_label": None, "parser_scope": "UNDETERMINED", "review_opinion": ""}] * 2,
        [{"scenario_id": "unknown_case", "review_status": "REVIEWED", "baseline_label": "PATTERN_PRESENT", "variant_label": "PATTERN_ABSENT", "parser_scope": "SUFFICIENT", "review_opinion": ""}],
        [{"scenario_id": scenario_id, "review_status": "REVIEWED", "baseline_label": "MATCH", "variant_label": "PATTERN_ABSENT", "parser_scope": "SUFFICIENT", "review_opinion": ""}],
    ]
    for rows in invalid_rows:
        base["responses"] = rows
        with pytest.raises(ReviewSubmissionError):
            decode_review_submission(json.dumps(base).encode(), packet)


def test_review_packet_and_adjudication_attempt_no_network(monkeypatch):
    attempts = []

    def denied(*_args, **_kwargs):
        attempts.append(True)
        raise AssertionError("network disabled")

    monkeypatch.setattr(socket.socket, "connect", denied)
    monkeypatch.setattr(socket.socket, "connect_ex", denied)
    build_review_packet()
    assert attempts == []


def test_cli_accepts_no_arbitrary_paths_and_reports_fixed_usage_error(capsys):
    from app.evaluation.counterfactual_review_packet_cli import main

    assert main(["/tmp/private-review.json"]) == 2
    captured = capsys.readouterr()
    assert captured.err == "INVALID_PACKET\n"
    assert "/tmp" not in captured.err


def test_submission_wrong_json_value_types_are_rejected_without_internal_errors():
    packet = build_review_packet()
    scenario_id = packet.to_mapping()["scenarios"][0]["scenario_id"]
    base = _valid_submission(packet, [])
    cases = [
        {"reviewer": {**base["reviewer"], "independence_claim": []}},
        {"responses": [{"scenario_id": scenario_id, "review_status": [], "baseline_label": None,
                        "variant_label": None, "parser_scope": "UNDETERMINED", "review_opinion": ""}]},
        {"responses": [{"scenario_id": scenario_id, "review_status": "REVIEWED", "baseline_label": [],
                        "variant_label": "PATTERN_ABSENT", "parser_scope": "SUFFICIENT", "review_opinion": ""}]},
    ]
    for update in cases:
        candidate = dict(base)
        candidate.update(update)
        with pytest.raises(ReviewSubmissionError):
            decode_review_submission(json.dumps(candidate).encode(), packet)
    surrogate = _valid_submission(packet, [{
        "scenario_id": scenario_id, "review_status": "NOT_REVIEWED", "baseline_label": None,
        "variant_label": None, "parser_scope": "UNDETERMINED", "review_opinion": "\ud800",
    }])
    with pytest.raises(ReviewSubmissionError):
        decode_review_submission(json.dumps(surrogate).encode(), packet)


def test_packet_nested_values_are_immutable():
    packet = build_review_packet()
    with pytest.raises(TypeError):
        packet.scenarios[0]["baseline"]["events"][0]["source_group"] = "changed"


def test_parser_canary_values_are_replaced_before_packet_serialization(monkeypatch):
    from datetime import datetime, timezone
    import app.evaluation.counterfactual_corpus as development
    from app.models.schemas import AuthenticationContext, NormalizedEvent

    canary = "ER1CR_PRIVATE_ACCOUNT_CANARY"
    event = NormalizedEvent(
        timestamp=datetime(2025, 1, 1, tzinfo=timezone.utc),
        event_type="login_failed", source="application", user=canary,
        src_ip="ER1CR_PRIVATE_IP_CANARY", dst_ip=None, application=None,
        protocol=None, user_agent=None, raw=f"raw {canary}",
        authentication=AuthenticationContext(outcome="failure"),
    )
    monkeypatch.setattr(development, "_parse_fixture", lambda _source, _data: ("VERIFIED", (event,)))
    raw = canonical_review_packet_json(build_review_packet()).decode()
    assert canary not in raw
    assert "ER1CR_PRIVATE_IP_CANARY" not in raw
    assert "Source Group A" in raw and "Account Group 1" in raw
