"""Application-only live analysis remains a proposal until detection commits."""

from dataclasses import asdict, replace
from datetime import datetime

import pytest

from app.analyzer.risk import load_account_metadata
from app.live_monitoring.analysis_accumulator import (
    LiveAnalysisAccumulator, LiveAnalysisError,
)
from app.live_monitoring.detection_accumulator import LiveDetectionAccumulator
from app.live_monitoring.detection_accumulator import LiveDetectionError
from app.live_monitoring.parser_adapter import parse_live_records
from app.live_monitoring.core import LiveTailRecord


def _metadata():
    return tuple((account, value["privilege"])
                 for account, value in load_account_metadata().items())


def _setup(role="application", records=256, bytes_=256 * 1024):
    detection = LiveDetectionAccumulator(role, records, bytes_)
    return detection, LiveAnalysisAccumulator(detection, _metadata())


def _batch(lines, start=1):
    records = tuple(LiveTailRecord("application", start + i, line, len(line.encode()))
                    for i, line in enumerate(lines))
    return parse_live_records("application", records)


def _line(event="login_failed", user="alice", second=1, ip="192.0.2.10"):
    return f"2026-01-02 03:04:{second:02d} INFO {event} user={user} ip={ip}"


def _commit(detection, analysis, lines, start):
    proposal = detection.prepare(_batch(lines, start))
    analysis_proposal = analysis.prepare(proposal)
    assert analysis.snapshot().revision == start - 1
    detection.commit(proposal)
    snapshot = analysis.commit(analysis_proposal)
    assert snapshot.revision == detection.snapshot().revision
    return snapshot


def test_empty_and_supported_source_contract():
    detection, analysis = _setup()
    assert analysis.snapshot().revision == 0
    assert analysis.snapshot().relation_count == 0
    assert not analysis.snapshot().active_proposal
    assert "192.0.2" not in repr(analysis)
    analysis.close()
    analysis.close()
    with pytest.raises(LiveAnalysisError) as raised:
        analysis.prepare(None)
    assert raised.value.code == "LIVE_ANALYSIS_CLOSED"
    ssh = LiveAnalysisAccumulator(LiveDetectionAccumulator("ssh", 4, 4096), _metadata())
    assert ssh.snapshot().source_role == "ssh"
    ssh.close()
    with pytest.raises(LiveAnalysisError) as raised:
        LiveAnalysisAccumulator(LiveDetectionAccumulator("access", 4, 4096), _metadata())
    assert raised.value.code == "LIVE_ANALYSIS_UNSUPPORTED_SOURCE"


@pytest.mark.parametrize("metadata", (
    [], (("alice", "normal"), ("alice", "privileged")),
    (("alice", True),), (("alice", "normal", "extra"),),
))
def test_metadata_requires_exact_immutable_shape(metadata):
    detection = LiveDetectionAccumulator("application", 4, 4096)
    with pytest.raises(LiveAnalysisError) as raised:
        LiveAnalysisAccumulator(detection, metadata)
    assert raised.value.code == "LIVE_ANALYSIS_INVALID_INPUT"


def test_raw_dict_or_arbitrary_iterable_cannot_be_prepared():
    _, analysis = _setup()
    for invalid in ({"results": {}}, iter(()), (), True):
        with pytest.raises(LiveAnalysisError) as raised:
            analysis.prepare(invalid)
        assert raised.value.code == "LIVE_ANALYSIS_INVALID_INPUT"


def test_naive_event_time_is_rejected_upstream_before_analysis_prepare():
    detection, analysis = _setup()
    parsed = _batch((_line(),))
    parsed.outcomes[0].event.timestamp = datetime(2026, 1, 2, 3, 4, 1)
    with pytest.raises(LiveDetectionError):
        detection.prepare(parsed)
    assert analysis.snapshot().revision == 0


def test_prepare_abort_retry_and_detection_commit_order():
    detection, analysis = _setup()
    dp = detection.prepare(_batch((_line(),)))
    ap = analysis.prepare(dp)
    assert analysis.snapshot().active_proposal
    assert analysis.snapshot().revision == 0
    with pytest.raises(LiveAnalysisError) as raised:
        analysis.commit(ap)
    assert raised.value.code == "LIVE_ANALYSIS_REVISION_MISMATCH"
    analysis.abort(ap)
    assert analysis.snapshot().revision == 0
    ap = analysis.prepare(dp)
    detection.commit(dp)
    assert analysis.commit(ap).revision == 1
    assert analysis.latest_change_set().analysis_revision == 1
    with pytest.raises(LiveAnalysisError):
        analysis.commit(ap)


def test_relation_case_and_risk_are_safe_in_snapshot():
    detection, analysis = _setup()
    _commit(detection, analysis, (_line(),), 1)
    snap = _commit(detection, analysis, (_line("user_login", second=2),), 2)
    assert snap.relation_count == 1
    assert snap.case_count == 1
    assert snap.risk_count == 1
    assert snap.relations[0].relation_id == "LIVE-REL-000001"
    assert snap.cases[0].case_id == "LIVE-CASE-000001"
    assert snap.risks[0].risk_id == "LIVE-RISK-000001"
    text = repr((analysis, snap, analysis.latest_change_set(), asdict(snap)))
    assert "192.0.2.10" not in text
    assert "alice" not in text
    assert "login_failed" not in text


def test_foreign_and_forged_proposal_rejected():
    detection, analysis = _setup()
    other_detection, other_analysis = _setup()
    dp = detection.prepare(_batch((_line(),)))
    ap = analysis.prepare(dp)
    with pytest.raises(LiveAnalysisError):
        other_analysis.prepare(dp)
    with pytest.raises(LiveAnalysisError):
        analysis.commit(replace(ap, target_revision=7))
    with pytest.raises(LiveAnalysisError):
        analysis.abort(replace(ap))
    analysis.abort(ap)
    detection.abort(dp)
    other_analysis.close()
    other_detection.close()


def test_history_limit_fail_closed_and_empty_revision():
    detection, analysis = _setup(records=2)
    _commit(detection, analysis, (_line(),), 1)
    dp = detection.prepare(_batch(("   ",), 2))
    ap = analysis.prepare(dp)
    detection.commit(dp)
    snap = analysis.commit(ap)
    assert snap.revision == 2
    assert analysis.latest_change_set().changes == ()
    _commit(detection, analysis, (_line(second=3),), 3)
    before = analysis.snapshot()
    with pytest.raises(Exception):
        detection.prepare(_batch((_line(second=4),), 4))
    assert analysis.snapshot() == before


def test_error_repr_does_not_expose_payload():
    error = LiveAnalysisError("private-account-999")
    assert "private-account-999" not in str(error)
    assert "private-account-999" not in repr(error)


def test_nearest_endpoint_change_creates_new_relation_and_case_ids():
    detection, analysis = _setup()
    _commit(detection, analysis, (_line(second=1),), 1)
    first = _commit(detection, analysis, (_line("user_login", second=5),), 2)
    old_relation = first.relations[0].relation_id
    old_case = first.cases[0].case_id
    risk_id = first.risks[0].risk_id
    changed = _commit(detection, analysis, (_line(second=4),), 3)
    assert changed.relations[0].relation_id == old_relation
    assert changed.relations[0].state == "NO_LONGER_MATCHES_CURRENT_RESULT"
    assert changed.relations[1].relation_id != old_relation
    assert changed.cases[0].case_id == old_case
    assert changed.cases[0].state == "NO_LONGER_MATCHES_CURRENT_RESULT"
    assert changed.cases[1].case_id != old_case
    assert changed.risks[0].risk_id == risk_id
    categories = {item.category for item in analysis.latest_change_set().changes}
    assert {"RELATION_CREATED", "RELATION_NO_LONGER_MATCHES",
            "CASE_CREATED", "CASE_NO_LONGER_MATCHES"} <= categories


def test_tied_distinct_failure_facts_remove_relation_without_guessing():
    detection, analysis = _setup()
    _commit(detection, analysis, (_line(second=1),), 1)
    _commit(detection, analysis, (_line("user_login", second=2),), 2)
    tied = _commit(detection, analysis, (_line(second=1) + " note=distinct",), 3)
    assert tied.relation_count == 0
    assert tied.case_count == 0
    assert tied.relations[0].state == "NO_LONGER_MATCHES_CURRENT_RESULT"


def test_brute_precedence_replaces_generic_case_without_reusing_its_id():
    detection, analysis = _setup()
    _commit(detection, analysis, (_line(second=1),), 1)
    before = _commit(detection, analysis, (_line("user_login", second=2),), 2)
    generic_id = before.cases[0].case_id
    latest = before
    for sequence in range(3, 7):
        latest = _commit(detection, analysis, (_line(second=sequence),), sequence)
    assert latest.case_count == 1
    assert latest.cases[0].case_id == generic_id
    assert latest.cases[0].state == "NO_LONGER_MATCHES_CURRENT_RESULT"
    assert latest.cases[1].case_id != generic_id
    assert latest.cases[1].rule_id == "CASE-BRUTE-SUCCESS-01"
    assert latest.cases[1].supporting_relation_count == 1


def test_case_ids_do_not_depend_on_review_order():
    detection, analysis = _setup()
    _commit(detection, analysis, (_line(second=1, ip="192.0.2.10"),), 1)
    _commit(detection, analysis, (_line("user_login", second=2, ip="192.0.2.10"),), 2)
    _commit(detection, analysis, (_line(second=3, ip="192.0.2.11"),), 3)
    before = _commit(detection, analysis, (_line("user_login", second=4, ip="192.0.2.11"),), 4)
    ids_before = {item._anchor: item.public_id for item in analysis._state.cases}
    before_order = tuple(case.subject_ip for case in analysis._state._assembly.cases)
    after = _commit(detection, analysis, (
        _line(second=5, user="admin", ip="192.0.2.11"),), 5)
    ids_after = {item._anchor: item.public_id for item in analysis._state.cases}
    after_order = tuple(case.subject_ip for case in analysis._state._assembly.cases)
    assert ids_after == ids_before
    assert {item.case_id for item in after.cases} == {item.case_id for item in before.cases}
    assert after_order != before_order


def test_abort_and_detection_abort_do_not_commit_analysis():
    detection, analysis = _setup()
    dp = detection.prepare(_batch((_line(),)))
    ap = analysis.prepare(dp)
    analysis.abort(ap)
    detection.abort(dp)
    assert analysis.snapshot().revision == 0
    dp2 = detection.prepare(_batch((_line(),)))
    ap2 = analysis.prepare(dp2)
    detection.abort(dp2)
    with pytest.raises(LiveAnalysisError) as raised:
        analysis.commit(ap2)
    assert raised.value.code == "LIVE_ANALYSIS_REVISION_MISMATCH"
    analysis.abort(ap2)
    assert analysis.snapshot().revision == 0


def test_same_revision_and_empty_prefix_from_replacement_proposal_is_not_enough():
    detection, analysis = _setup()
    first = detection.prepare(_batch((" ",), 1))
    analysis_proposal = analysis.prepare(first)
    detection.abort(first)
    replacement = detection.prepare(_batch(("malformed timestamp",), 1))
    detection.commit(replacement)
    with pytest.raises(LiveAnalysisError) as raised:
        analysis.commit(analysis_proposal)
    assert raised.value.code == "LIVE_ANALYSIS_REVISION_MISMATCH"
    with pytest.raises(LiveAnalysisError) as terminal:
        analysis.abort(analysis_proposal)
    assert terminal.value.code == "LIVE_ANALYSIS_COMMIT_FAILED"
    analysis.close()


def test_abort_after_detection_commit_is_terminal_not_silent():
    detection, analysis = _setup()
    dp = detection.prepare(_batch((_line(),)))
    ap = analysis.prepare(dp)
    detection.commit(dp)
    with pytest.raises(LiveAnalysisError) as raised:
        analysis.abort(ap)
    assert raised.value.code == "LIVE_ANALYSIS_COMMIT_FAILED"
    with pytest.raises(LiveAnalysisError):
        analysis.commit(ap)
    analysis.close()
    assert analysis.snapshot().closed


def test_no_filesystem_metadata_reload_or_detector_reexecution(monkeypatch):
    from app.analyzer import pipeline
    from app.live_monitoring import detection_accumulator as detection_module

    detection, analysis = _setup()
    proposal = detection.prepare(_batch((_line(),)))
    monkeypatch.setattr(pipeline, "load_account_metadata", lambda: (_ for _ in ()).throw(AssertionError("I/O")))
    monkeypatch.setattr(detection_module, "detect_attacks", lambda *_: (_ for _ in ()).throw(AssertionError("detector")))
    prepared = analysis.prepare(proposal)
    detection.commit(proposal)
    analysis.commit(prepared)


def test_analysis_hard_history_limit_is_not_silently_evicted():
    detection, analysis = _setup(records=257, bytes_=256 * 1024)
    lines = tuple(_line(second=(i % 59) + 1) for i in range(257))
    dp = detection.prepare(_batch(lines))
    with pytest.raises(LiveAnalysisError) as raised:
        analysis.prepare(dp)
    assert raised.value.code == "LIVE_ANALYSIS_HISTORY_LIMIT"
    assert analysis.snapshot().revision == 0
    detection.abort(dp)


@pytest.mark.parametrize("after_swap", (False, True))
def test_commit_swap_failure_is_terminal_without_guessing_rollback(monkeypatch, after_swap):
    detection, analysis = _setup()
    dp = detection.prepare(_batch((_line(),)))
    ap = analysis.prepare(dp)
    detection.commit(dp)
    original = type(analysis)._install_candidate
    def fail(self, candidate):
        if after_swap:
            original(self, candidate)
        raise RuntimeError("private_commit_exception_CANARY")
    monkeypatch.setattr(type(analysis), "_install_candidate", fail)
    with pytest.raises(LiveAnalysisError) as raised:
        analysis.commit(ap)
    assert raised.value.code == "LIVE_ANALYSIS_COMMIT_FAILED"
    assert "private_commit_exception_CANARY" not in repr(raised.value)
    with pytest.raises(LiveAnalysisError) as closed:
        analysis.prepare(dp)
    assert closed.value.code == "LIVE_ANALYSIS_CLOSED"
    analysis.close()
    assert analysis.snapshot().closed
