"""Trusted analysis values never cross the safe proposal/snapshot boundary."""

from dataclasses import asdict
import json
from pathlib import Path

import pytest

from app.analyzer.risk import load_account_metadata
from app.live_monitoring import analysis_accumulator as module
from app.live_monitoring.core import LiveTailRecord
from app.live_monitoring.detection_accumulator import LiveDetectionAccumulator
from app.live_monitoring.parser_adapter import parse_live_records


def _pending(account="private_account_CANARY", ip="198.51.100.88"):
    detector = LiveDetectionAccumulator("application", 256, 256 * 1024)
    metadata = tuple((key, value["privilege"])
                     for key, value in load_account_metadata().items())
    analysis = module.LiveAnalysisAccumulator(detector, metadata)
    line = ("2026-01-02 03:04:05 INFO login_failed "
            f"user={account} ip={ip} note=secret_raw_CANARY "
            "path=/private_path_CANARY query=token_query_CANARY "
            "user_agent=private_agent_CANARY credential=credential_CANARY")
    record = LiveTailRecord("application", 1, line, len(line.encode()))
    detection_proposal = detector.prepare(parse_live_records("application", (record,)))
    return detector, analysis, detection_proposal


def test_safe_typed_values_and_generic_json_exclude_canaries(capsys, caplog):
    detector, analysis, detection_proposal = _pending()
    proposal = analysis.prepare(detection_proposal)
    detector.commit(detection_proposal)
    snapshot = analysis.commit(proposal)
    safe = (repr(analysis), repr(proposal), repr(snapshot),
            repr(analysis.latest_change_set()), json.dumps(asdict(proposal)),
            json.dumps(asdict(snapshot)), json.dumps(asdict(analysis.latest_change_set())))
    exposed = " ".join(safe) + capsys.readouterr().out + capsys.readouterr().err + caplog.text
    for canary in ("private_account_CANARY", "198.51.100.88", "secret_raw_CANARY",
                   "private_path_CANARY", "token_query_CANARY", "private_agent_CANARY",
                   "credential_CANARY"):
        assert canary not in exposed
    assert "secret_raw_CANARY" in detector._history[0].raw


@pytest.mark.parametrize(("boundary", "code"), (
    ("correlation", "LIVE_ANALYSIS_CORRELATION_FAILED"),
    ("risk", "LIVE_ANALYSIS_RISK_FAILED"),
    ("case", "LIVE_ANALYSIS_CASE_FAILED"),
    ("projection", "LIVE_ANALYSIS_PROJECTION_FAILED"),
))
def test_prepare_failure_is_fixed_and_committed_state_unchanged(monkeypatch, boundary, code, capsys, caplog):
    detector, analysis, detection_proposal = _pending()
    target = {
        "correlation": "correlate_authentication_transition",
        "risk": "assess_risk_with_metadata",
        "case": "assemble_incident_cases",
        "projection": "build_investigation_case_projection",
    }[boundary]
    def fail(*_args, **_kwargs):
        raise RuntimeError("internal_exception_CANARY")
    monkeypatch.setattr(module, target, fail)
    with pytest.raises(module.LiveAnalysisError) as raised:
        analysis.prepare(detection_proposal)
    assert raised.value.code == code
    assert analysis.snapshot().revision == 0
    assert not analysis.snapshot().active_proposal
    public = repr(raised.value) + str(raised.value) + repr(analysis.snapshot())
    public += capsys.readouterr().out + capsys.readouterr().err + caplog.text
    assert "internal_exception_CANARY" not in public
    assert "private_account_CANARY" not in public
    detector.abort(detection_proposal)


def test_prepare_does_not_access_filesystem_or_reparse(monkeypatch):
    detector, analysis, detection_proposal = _pending()
    def fail(*_args, **_kwargs):
        raise AssertionError("I/O or parser call")
    monkeypatch.setattr(Path, "open", fail)
    proposal = analysis.prepare(detection_proposal)
    analysis.abort(proposal)
    detector.abort(detection_proposal)
