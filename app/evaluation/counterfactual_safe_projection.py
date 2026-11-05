"""Closed synthetic snapshot; integrity is not authentication or human approval."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from types import MappingProxyType

from app.evaluation.counterfactual_analyst_report import build_report
from app.evaluation.counterfactual_comparison import ComparisonState
from app.evaluation.counterfactual_corpus import CORPUS_ROOT, MANIFEST_PATH, MAX_MANIFEST_BYTES
from app.evaluation.counterfactual_holdout import load_holdout, run_holdout
from app.evaluation.counterfactual_replay import run_corpus

MAX_SNAPSHOT_BYTES = 128 * 1024
MAX_DEPTH = 8


class ProjectionError(ValueError):
    def __init__(self, code="INVALID_PROJECTION"):
        self.code = code if code in {"INVALID_PROJECTION", "UNSUPPORTED_REPORT_VERSION", "SNAPSHOT_DIGEST_MISMATCH", "RESOURCE_LIMIT"} else "INVALID_PROJECTION"
        super().__init__(self.code)


@dataclass(frozen=True, slots=True)
class Snapshot:
    """Immutable bytes, not a reference to any mutable producer object."""
    _canonical: bytes

    def _view(self, name):
        validated = decode_snapshot(self._canonical)
        return _freeze(json.loads(validated._canonical)[name])

    @property
    def scenarios(self):
        return self._view("scenarios")

    @property
    def corpora(self):
        return self._view("corpora")

    @property
    def summary(self):
        return self._view("summary")


def _freeze(value):
    if type(value) is dict:
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if type(value) is list:
        return tuple(_freeze(item) for item in value)
    return value


def _json(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _digest(body):
    return hashlib.sha256(_json(body)).hexdigest()


def _produce():
    # build_report checks the real replay, inventories, policy, evidence and counts.
    path = CORPUS_ROOT / MANIFEST_PATH
    if CORPUS_ROOT.is_symlink() or path.is_symlink() or path.stat().st_size > MAX_MANIFEST_BYTES:
        raise ProjectionError()
    raw = path.read_bytes()
    if not raw or len(raw) > MAX_MANIFEST_BYTES:
        raise ProjectionError("RESOURCE_LIMIT")
    holdout_before = load_holdout()
    development_run = run_corpus()
    holdout_run = run_holdout()
    report = build_report(development_run, holdout_run)
    holdout = load_holdout()
    if (CORPUS_ROOT.is_symlink() or path.is_symlink() or path.stat().st_size > MAX_MANIFEST_BYTES
            or path.read_bytes() != raw or holdout.raw_manifest != holdout_before.raw_manifest
            or holdout_run.manifest_sha256 != hashlib.sha256(holdout.raw_manifest).hexdigest()):
        raise ProjectionError()
    digests = {"er1a_development": hashlib.sha256(raw).hexdigest(), holdout.corpus_id: hashlib.sha256(holdout.raw_manifest).hexdigest()}
    rows = []
    fields = ("corpus_id", "scenario_id", "detector_id", "mutation_type", "baseline_parser_state", "variant_parser_state", "baseline_detection_state", "variant_detection_state", "comparison_state", "reason_codes")
    for row in report.scenarios:
        rows.append({field: list(row.reason_codes) if field == "reason_codes" else getattr(row, field) for field in fields})
    rows.sort(key=lambda row: (row["corpus_id"], row["scenario_id"]))
    corpora = []
    for item in (report.development, report.holdout):
        corpora.append({"corpus_id": item.corpus_id, "manifest_sha256": digests[item.corpus_id], "scenario_count": item.denominator,
            "baseline_parser_counts": dict(item.parser_baseline), "variant_parser_counts": dict(item.parser_variant),
            "baseline_detection_counts": dict(item.detection_baseline), "variant_detection_counts": dict(item.detection_variant),
            "comparison_counts": dict(item.comparison_counts), "excluded_comparisons": item.excluded_comparisons})
    corpora.sort(key=lambda item: item["corpus_id"])
    counts = {state.value: sum(row["comparison_state"] == state.value for row in rows) for state in ComparisonState}
    excluded = counts["INCOMPARABLE"] + counts["UNDETERMINED"]
    return {"schema_version": 1, "evaluation_scope": "SYNTHETIC_ONLY", "human_review_status": "INDEPENDENT_HUMAN_REVIEW_PENDING", "operational_validation": "NOT_APPROVED", "corpora": corpora,
        "summary": {"scenario_count": len(rows), "comparison_counts": counts, "comparable_count": len(rows) - excluded, "excluded_comparisons": excluded}, "scenarios": rows}


def build_snapshot():
    try:
        body = _produce()
        data = dict(body, snapshot_sha256=_digest(body))
        encoded = _json(data) + b"\n"
        if len(encoded) > MAX_SNAPSHOT_BYTES:
            raise ProjectionError("RESOURCE_LIMIT")
        return Snapshot(encoded)
    except ProjectionError:
        raise
    except Exception:
        raise ProjectionError() from None


def encode_snapshot(snapshot):
    if type(snapshot) is not Snapshot or type(snapshot._canonical) is not bytes:
        raise ProjectionError()
    # Public construction of Snapshot must not bypass validation.
    return decode_snapshot(snapshot._canonical)._canonical


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ProjectionError()
        result[key] = value
    return result


def _depth(value, depth=0):
    if depth > MAX_DEPTH:
        raise ProjectionError("RESOURCE_LIMIT")
    if type(value) is dict:
        if len(value) > 64:
            raise ProjectionError("RESOURCE_LIMIT")
        for child in value.values():
            _depth(child, depth + 1)
    elif type(value) is list:
        if len(value) > 32:
            raise ProjectionError("RESOURCE_LIMIT")
        for child in value:
            _depth(child, depth + 1)


def decode_snapshot(raw):
    if type(raw) is not bytes or not raw:
        raise ProjectionError()
    if len(raw) > MAX_SNAPSHOT_BYTES:
        raise ProjectionError("RESOURCE_LIMIT")
    try:
        data = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_pairs, parse_constant=lambda _: (_ for _ in ()).throw(ProjectionError()), parse_int=lambda x: int(x) if len(x) <= 3 else (_ for _ in ()).throw(ProjectionError("RESOURCE_LIMIT")))
        _depth(data)
        if type(data) is not dict:
            raise ProjectionError()
        if type(data.get("schema_version")) is not int or data["schema_version"] != 1:
            raise ProjectionError("UNSUPPORTED_REPORT_VERSION")
        digest = data.get("snapshot_sha256")
        body = {key: value for key, value in data.items() if key != "snapshot_sha256"}
        if type(digest) is not str or digest != _digest(body):
            raise ProjectionError("SNAPSHOT_DIGEST_MISMATCH")
        # Revalidate against current fixed producer: rejects untrusted provenance,
        # forged consistent counts, metadata, unknown fields, and stale snapshots.
        if _json(body) != _json(_produce()):
            raise ProjectionError()
        canonical = _json(data) + b"\n"
        return Snapshot(canonical)
    except ProjectionError:
        raise
    except Exception:
        raise ProjectionError() from None
