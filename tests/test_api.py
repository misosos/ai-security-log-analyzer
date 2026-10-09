from app.api import build_analysis_response
from app.main import analyze


def test_build_analysis_response_uses_canonical_contract():
    global_correlation = {
        "multi_ip_authentication": [
            {
                "is_correlated": True,
                "type": "multi_ip_authentication_failure",
                "user": "admin",
                "source_ips": [
                    "10.0.0.1",
                    "10.0.0.2",
                    "10.0.0.3",
                ],
                "failure_count": 3,
                "failure_start_timestamp": "2026-09-16T10:00:01Z",
                "failure_end_timestamp": "2026-09-16T10:00:05Z",
                "time_window_seconds": 4.0,
                "rationale": [],
            },
            {
                "is_correlated": True,
                "type": "multi_ip_authentication_failure",
                "user": "alice",
                "source_ips": [
                    "10.0.1.1",
                    "10.0.1.2",
                    "10.0.1.3",
                ],
                "failure_count": 3,
                "failure_start_timestamp": "2026-09-16T10:01:01Z",
                "failure_end_timestamp": "2026-09-16T10:01:05Z",
                "time_window_seconds": 4.0,
                "rationale": [],
            },
        ],
        "distributed_authentication_to_success": [
            {
                "is_correlated": True,
                "type": (
                    "distributed_authentication_failures_"
                    "to_successful_login"
                ),
                "user": "admin",
                "failure_source_ips": [
                    "10.0.0.1",
                    "10.0.0.2",
                    "10.0.0.3",
                ],
                "failure_count": 3,
                "failure_start_timestamp": "2026-09-16T10:00:01Z",
                "failure_end_timestamp": "2026-09-16T10:00:05Z",
                "failure_duration_seconds": 4.0,
                "success_timestamp": "2026-09-16T10:00:20Z",
                "success_source_ip": "10.0.0.4",
                "success_from_failure_source": False,
                "time_delta_seconds": 15.0,
                "rationale": [],
            },
        ],
        "linux_audit_session_lifecycle": [
            {
                "is_correlated": True,
                "type": "linux_audit_session_lifecycle",
                "source": "linux_audit",
                "source_instance": "prod-audit-feed",
                "node": "producer-a.example",
                "audit_session_id": 61,
                "user": "training-user",
                "start_event_id": "1790100000.001:601",
                "end_event_id": "1790100120.002:650",
                "start_timestamp": "2026-09-18T01:00:00Z",
                "end_timestamp": "2026-09-18T01:02:00Z",
                "observed_session_lifecycle_interval_seconds": (
                    120.0
                ),
                "matched_fields": [
                    "source",
                    "source_instance",
                    "node",
                    "audit_session_id",
                    "user",
                ],
                "missing_fields": [],
                "context_differences": ["operation"],
                "rationale": [],
            },
        ],
        "linux_audit_login_start_co_observation": [
            {
                "is_correlated": True,
                "type": "linux_audit_login_start_co_observation",
                "source": "linux_audit",
                "source_instance": "prod-audit-feed",
                "node": "producer-a.example",
                "audit_session_id": 61,
                "user": "training-user",
                "login_event_id": "1790100002.003:603",
                "start_event_id": "1790100001.002:602",
                "login_timestamp": "2026-09-18T01:00:02Z",
                "start_timestamp": "2026-09-18T01:00:01Z",
                "matched_fields": [
                    "source",
                    "source_instance",
                    "node",
                    "audit_session_id",
                    "user",
                ],
                "missing_fields": [],
                "context_differences": ["operation"],
                "rationale": [],
            },
        ],
    }

    analysis = analyze()
    analysis["global_correlation"] = global_correlation

    response = build_analysis_response(
        analysis,
        total_sources=3,
    )

    assert response.summary.total_sources == 3
    assert response.summary.total_ips == 10
    assert response.summary.detected_ips == 4
    assert response.summary.high_risk_ips == 4
    assert response.global_correlation.multi_ip_authentication_count == 2
    assert response.global_correlation.distributed_authentication_to_success_count == 1
    assert response.global_correlation.linux_audit_session_lifecycle_count == 1
    assert response.global_correlation.linux_audit_login_start_co_observation_count == 1
    rendered = response.model_dump_json()
    for forbidden in ("admin", "alice", "training-user", "prod-audit-feed", "producer-a.example"):
        assert forbidden not in rendered
