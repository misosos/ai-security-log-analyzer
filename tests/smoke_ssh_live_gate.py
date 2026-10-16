"""Synthetic SSH FROM_END smoke; batch analysis is intentionally separate."""

from pathlib import Path
from tempfile import TemporaryDirectory

from app.analyzer.incident_case_adapter import project_investigation_cases_from_analysis
from app.analyzer.pipeline import assess_risk_with_metadata, correlate_attacks, detect_attacks
from app.live_monitoring import (
    LiveDetectionAccumulator, LiveMonitorConfig, LiveProcessingWorker,
    open_live_tail_session,
)


def main() -> None:
    with TemporaryDirectory(prefix="ssh-live-gate-") as directory:
        source = Path(directory) / "synthetic.log"
        source.write_text("existing content is not processed\n", encoding="utf-8")
        session = open_live_tail_session(LiveMonitorConfig("ssh", source.resolve()))
        detector = LiveDetectionAccumulator("ssh", 256, 256 * 1024)
        worker = LiveProcessingWorker(session, detector, 16, 4096)
        try:
            with source.open("a", encoding="utf-8") as output:
                for second in range(1, 6):
                    output.write(
                        f"2026-01-02 03:04:{second:02d} sshd: Failed password "
                        "for synthetic from 192.0.2.10 port 5001 ssh2\n"
                    )
                output.write(
                    "2026-01-02 03:04:06 sshd: Accepted password "
                    "for synthetic from 192.0.2.10 port 5001 ssh2\n"
                )
            result = worker.step()
            assert result.accumulator_revision == 1
            assert detector.snapshot().history_record_count == 6
            assert worker._analysis is None
            assert session.snapshot().queue_item_count == 0
            assert session.snapshot().active_lease is False
            assert detector.snapshot().active_proposal is False
            events = detector._history  # trusted synthetic test oracle only
            detection = detect_attacks(events)
            analysis = assess_risk_with_metadata(correlate_attacks(events, detection), {})
            projection = project_investigation_cases_from_analysis(analysis)
            subject = analysis["results"]["192.0.2.10"]
            assert subject["detections"]["brute_force"].is_detected
            assert subject["correlation"]["authentication"]["is_correlated"]
            assert subject["correlation"]["brute_force_to_success"]["is_correlated"]
            assert subject["risk_level"] in {"LOW", "MEDIUM", "HIGH"}
            assert any(case.rule_code == "CASE-BRUTE-SUCCESS-01"
                       for case in projection.cases)
        finally:
            worker.close()
        assert session._fd == -1
    print("SSH_GATE_SMOKE_PASS detection_live analysis_batch_only cleanup_complete")


if __name__ == "__main__":
    main()
