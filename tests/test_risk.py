from app.analyzer.risk import (
    build_risk_context,
    build_risk_factors,
    evaluate_likelihood,
    evaluate_volume_signal,
    evaluate_temporal_signal,
    evaluate_targeting_signal,
    evaluate_detection_signal,
    evaluate_impact,
    evaluate_login_success_risk,
    evaluate_failure_risk,
    evaluate_target_scope_risk,
    evaluate_time_window_risk,
    get_account_context,
    evaluate_account_privilege_risk,
    evaluate_risk_level,
    evaluate_confidence,
    evaluate_correlation_signal,
)
from app.models.schemas import DetectionResult, Evidence


def empty_detection():
    return DetectionResult(
        is_detected=False,
        detection_type=None,
        evidence=[],
    )


def detected_brute_force():
    return DetectionResult(
        is_detected=True,
        detection_type="brute_force",
        evidence=[],
    )


def detected_password_spray():
    return DetectionResult(
        is_detected=True,
        detection_type="password_spraying_like",
        evidence=[],
    )


def detected_path_traversal(
    status_code=200,
    response_size=2048,
):
    evidence = [
        Evidence(
            type="http_status_code",
            value=status_code,
            source="path_traversal_detector",
        ),
        Evidence(
            type="http_response_size",
            value=response_size,
            source="path_traversal_detector",
        ),
    ]

    return DetectionResult(
        is_detected=True,
        detection_type="path_traversal",
        evidence=evidence,
    )


def make_features(
    failure_count=0,
    target_users=None,
    login_succeeded=False,
    within_window=False,
    window_seconds=0,
    average_interval=0,
    interval_variability=0,
    brute_force=None,
    password_spray=None,
    path_traversal=None,
    correlated=False,
):
    if target_users is None:
        target_users = []

    if brute_force is None:
        brute_force = empty_detection()

    if password_spray is None:
        password_spray = empty_detection()

    detections = {
        "brute_force": brute_force,
        "password_spray": password_spray,
    }

    if path_traversal is not None:
        detections["path_traversal"] = path_traversal

    return {
        "failure_count": failure_count,
        "target_users": target_users,
        "login_succeeded": login_succeeded,
        "within_window": within_window,
        "window_seconds": window_seconds,
        "average_interval": average_interval,
        "interval_variability": interval_variability,
        "unique_target_count": len(target_users),
        "detections": detections,

        # 새로운 Correlation 구조
        "correlation": {
            "authentication": {
                "is_correlated": correlated,
            },
            "post_authentication": {
                "is_correlated": False,
            },
        },
    }


# ---------------------------------------------------------
# build_risk_context
# ---------------------------------------------------------

def test_build_risk_context():
    result = {
        "features": {
            "failure_count": 5,
            "target_users": ["admin"],
            "login_succeeded": False,
            "within_window": True,
            "window_seconds": 16.0,
            "average_interval": 4.0,
            "interval_variability": 0.0,
            "unique_target_count": 1,
        },
        "detections": {
            "brute_force": detected_brute_force(),
            "password_spray": empty_detection(),
        },
        "correlation": {
            "authentication": {
                "is_correlated": False,
            },
            "post_authentication": {
                "is_correlated": False,
            },
        },
    }

    context = build_risk_context(result)

    assert context["failure_count"] == 5
    assert context["target_users"] == ["admin"]
    assert context["within_window"] is True
    assert context["window_seconds"] == 16.0
    assert context["detections"]["brute_force"].is_detected is True

    assert (
        context["correlation"]["authentication"]["is_correlated"]
        is False
    )

    assert (
        context["correlation"]["post_authentication"]["is_correlated"]
        is False
    )


# ---------------------------------------------------------
# evaluate_likelihood
# ---------------------------------------------------------

def test_evaluate_likelihood_brute_force():
    features = make_features(
        failure_count=5,
        target_users=["admin"],
        within_window=True,
        window_seconds=16,
        average_interval=4,
        brute_force=detected_brute_force(),
    )

    result = evaluate_likelihood(features)

    assert result["level"] == "HIGH"
    assert "Brute Force 탐지 조건을 충족함" in result["rationale"]


def test_evaluate_likelihood_password_spray():
    features = make_features(
        failure_count=4,
        target_users=["admin", "alice", "bob", "guest"],
        within_window=True,
        window_seconds=6,
        average_interval=2,
        password_spray=detected_password_spray(),
    )

    result = evaluate_likelihood(features)

    assert result["level"] == "HIGH"
    assert "Password Spraying-like 탐지 조건을 충족함" in result["rationale"]


def test_evaluate_likelihood_path_traversal():
    features = make_features(
        path_traversal=detected_path_traversal()
    )

    result = evaluate_likelihood(features)

    assert result["level"] == "HIGH"
    assert (
        "Path Traversal 공격 패턴이 HTTP 요청에서 직접 확인됨"
        in result["rationale"]
    )


def test_evaluate_likelihood_normal_failure():
    features = make_features(
        failure_count=2,
        target_users=["alice"],
        within_window=True,
        window_seconds=9,
        average_interval=9,
    )

    result = evaluate_likelihood(features)

    assert result["level"] == "LOW"


def test_evaluate_likelihood_repeated_failure():
    features = make_features(
        failure_count=3,
        target_users=["admin"],
        within_window=True,
        window_seconds=20,
        average_interval=10,
    )

    result = evaluate_likelihood(features)

    assert result["level"] == "MEDIUM"


# ---------------------------------------------------------
# Signal functions
# ---------------------------------------------------------

def test_evaluate_volume_signal():
    assert evaluate_volume_signal(
        make_features(failure_count=2)
    ) == "LOW"

    assert evaluate_volume_signal(
        make_features(failure_count=3)
    ) == "MEDIUM"

    assert evaluate_volume_signal(
        make_features(failure_count=5)
    ) == "HIGH"


def test_evaluate_temporal_signal():
    assert evaluate_temporal_signal(
        make_features(
            failure_count=2,
            within_window=True,
            average_interval=2,
        )
    ) == "LOW"

    assert evaluate_temporal_signal(
        make_features(
            failure_count=3,
            within_window=True,
            average_interval=10,
        )
    ) == "MEDIUM"

    assert evaluate_temporal_signal(
        make_features(
            failure_count=5,
            within_window=True,
            average_interval=5,
        )
    ) == "HIGH"


def test_evaluate_targeting_signal():
    assert evaluate_targeting_signal(
        make_features(
            target_users=["alice"]
        )
    ) == "LOW"

    assert evaluate_targeting_signal(
        make_features(
            target_users=["alice", "bob"]
        )
    ) == "MEDIUM"

    assert evaluate_targeting_signal(
        make_features(
            target_users=["alice", "bob", "guest"]
        )
    ) == "HIGH"


def test_evaluate_detection_signal():
    features = make_features(
        brute_force=detected_brute_force()
    )

    result = evaluate_detection_signal(features)

    assert result["level"] == "HIGH"
    assert result["types"] == ["brute_force"]


def test_evaluate_detection_signal_no_detection():
    features = make_features()

    result = evaluate_detection_signal(features)

    assert result["level"] == "LOW"
    assert result["types"] == []


# ---------------------------------------------------------
# evaluate_impact
# ---------------------------------------------------------

def test_evaluate_impact_brute_force_privileged():
    features = make_features(
        brute_force=detected_brute_force()
    )

    result = evaluate_impact(
        features,
        account_privilege_risk=True,
    )

    assert result["level"] == "HIGH"
    assert result["basis"]["attack_type"] == "brute_force"
    assert result["basis"]["privileged_account_targeted"] is True


def test_evaluate_impact_brute_force_normal_account():
    features = make_features(
        brute_force=detected_brute_force()
    )

    result = evaluate_impact(
        features,
        account_privilege_risk=False,
    )

    assert result["level"] == "LOW"
    assert result["basis"]["attack_type"] == "brute_force"
    assert result["basis"]["privileged_account_targeted"] is False


def test_evaluate_impact_password_spray_privileged():
    features = make_features(
        password_spray=detected_password_spray()
    )

    result = evaluate_impact(
        features,
        account_privilege_risk=True,
    )

    assert result["level"] == "HIGH"
    assert result["basis"]["attack_type"] == "password_spraying_like"


def test_evaluate_impact_path_traversal_200():
    features = make_features(
        path_traversal=detected_path_traversal(
            status_code=200,
            response_size=2048,
        )
    )

    result = evaluate_impact(
        features,
        account_privilege_risk=False,
    )

    assert result["level"] == "MEDIUM"
    assert result["basis"]["attack_type"] == "path_traversal"
    assert result["basis"]["http_status_code"] == 200
    assert result["basis"]["response_size"] == 2048
    assert result["basis"]["impact_status"] == "insufficient_evidence"
    assert result["basis"]["exploit_success_confirmed"] is False


def test_evaluate_impact_path_traversal_404():
    features = make_features(
        path_traversal=detected_path_traversal(
            status_code=404,
            response_size=512,
        )
    )

    result = evaluate_impact(
        features,
        account_privilege_risk=False,
    )

    assert result["level"] == "LOW"
    assert result["basis"]["http_status_code"] == 404
    assert result["basis"]["impact_status"] == "insufficient_evidence"
    assert result["basis"]["exploit_success_confirmed"] is False


# ---------------------------------------------------------
# Simple feature accessors
# ---------------------------------------------------------

def test_evaluate_login_success_risk():
    features = make_features(
        login_succeeded=True
    )

    assert evaluate_login_success_risk(features) is True


def test_evaluate_failure_risk():
    features = make_features(
        failure_count=5
    )

    assert evaluate_failure_risk(features) == 5


def test_evaluate_target_scope_risk():
    features = make_features(
        target_users=["admin", "alice", "bob"]
    )

    assert evaluate_target_scope_risk(features) == 3


def test_evaluate_time_window_risk():
    features = make_features(
        window_seconds=16
    )

    assert evaluate_time_window_risk(features) == 16


# ---------------------------------------------------------
# Account context
# ---------------------------------------------------------

def test_get_account_context():
    features = make_features(
        target_users=["admin", "alice", "unknown"]
    )

    account_metadata = {
        "admin": {
            "privilege": "privileged"
        },
        "alice": {
            "privilege": "normal"
        },
    }

    result = get_account_context(
        features,
        account_metadata,
    )

    assert result == {
        "admin": {
            "privilege": "privileged"
        },
        "alice": {
            "privilege": "normal"
        },
    }


def test_evaluate_account_privilege_risk():
    account_context = {
        "admin": {
            "privilege": "privileged"
        },
        "alice": {
            "privilege": "normal"
        },
    }

    assert (
        evaluate_account_privilege_risk(account_context)
        is True
    )


def test_evaluate_account_privilege_risk_normal_accounts():
    account_context = {
        "alice": {
            "privilege": "normal"
        },
        "guest": {
            "privilege": "low"
        },
    }

    assert (
        evaluate_account_privilege_risk(account_context)
        is False
    )


# ---------------------------------------------------------
# evaluate_confidence
# ---------------------------------------------------------

def test_evaluate_confidence_brute_force():
    features = make_features(
        brute_force=detected_brute_force()
    )

    result = evaluate_confidence(features)

    assert result["level"] == "HIGH"


def test_evaluate_confidence_path_traversal():
    features = make_features(
        path_traversal=detected_path_traversal()
    )

    result = evaluate_confidence(features)

    assert result["level"] == "MEDIUM"


def test_evaluate_confidence_no_detection():
    features = make_features()

    result = evaluate_confidence(features)

    assert result["level"] == "LOW"


# ---------------------------------------------------------
# evaluate_correlation_signal
# ---------------------------------------------------------

def test_evaluate_correlation_signal():
    correlated_features = make_features(
        correlated=True
    )

    normal_features = make_features(
        correlated=False
    )

    assert (
        evaluate_correlation_signal(correlated_features)
        == "MEDIUM"
    )

    assert (
        evaluate_correlation_signal(normal_features)
        == "LOW"
    )


def test_evaluate_correlation_signal_post_authentication():
    features = make_features()

    features["correlation"]["post_authentication"] = {
        "is_correlated": True,
    }

    assert (
        evaluate_correlation_signal(features)
        == "MEDIUM"
    )


def test_evaluate_correlation_signal_both():
    features = make_features(
        correlated=True
    )

    features["correlation"]["post_authentication"] = {
        "is_correlated": True,
    }

    assert (
        evaluate_correlation_signal(features)
        == "MEDIUM"
    )


# ---------------------------------------------------------
# evaluate_risk_level
# ---------------------------------------------------------

def test_evaluate_risk_level_high():
    result = {
        "risk_factors": {
            "likelihood": {
                "level": "HIGH"
            },
            "impact": {
                "level": "HIGH"
            },
        }
    }

    assert evaluate_risk_level(result) == "HIGH"


def test_evaluate_risk_level_low():
    result = {
        "risk_factors": {
            "likelihood": {
                "level": "LOW"
            },
            "impact": {
                "level": "LOW"
            },
        }
    }

    assert evaluate_risk_level(result) == "LOW"


def test_evaluate_risk_level_medium():
    result = {
        "risk_factors": {
            "likelihood": {
                "level": "HIGH"
            },
            "impact": {
                "level": "MEDIUM"
            },
        }
    }

    assert evaluate_risk_level(result) == "MEDIUM"


# ---------------------------------------------------------
# build_risk_factors
# ---------------------------------------------------------

def test_build_risk_factors_brute_force():
    features = make_features(
        failure_count=5,
        target_users=["admin"],
        within_window=True,
        window_seconds=16,
        average_interval=4,
        brute_force=detected_brute_force(),
    )

    result = build_risk_factors(
        features,
        account_privilege_risk=True,
    )

    assert result["likelihood"]["level"] == "HIGH"
    assert result["impact"]["level"] == "HIGH"
    assert result["confidence"]["level"] == "HIGH"

    assert result["likelihood"]["failure_count"] == 5
    assert result["likelihood"]["target_scope"] == 1
    assert result["likelihood"]["time_window"] == 16

    assert (
        result["impact"]["privileged_account_targeted"]
        is True
    )

    assert (
        result["impact"]["authentication_success"]
        is False
    )


def test_build_risk_factors_path_traversal():
    features = make_features(
        path_traversal=detected_path_traversal(
            status_code=200,
            response_size=2048,
        )
    )

    result = build_risk_factors(
        features,
        account_privilege_risk=False,
    )

    assert result["likelihood"]["level"] == "HIGH"
    assert result["impact"]["level"] == "MEDIUM"
    assert result["confidence"]["level"] == "MEDIUM"

    assert (
        result["impact"]["basis"]["impact_status"]
        == "insufficient_evidence"
    )

    assert (
        result["impact"]["basis"]["exploit_success_confirmed"]
        is False
    )


def test_risk_handles_new_correlation_structure():
    result = {
        "features": {
            "failure_count": 5,
            "target_users": ["admin"],
            "login_succeeded": True,
            "within_window": True,
            "window_seconds": 8.0,
            "average_interval": 2.0,
            "interval_variability": 0.0,
            "unique_target_count": 1,
        },

        "detections": {
            "brute_force": DetectionResult(
                is_detected=False,
                detection_type=None,
                evidence=[],
            ),
            "password_spray": DetectionResult(
                is_detected=False,
                detection_type=None,
                evidence=[],
            ),
            "path_traversal": DetectionResult(
                is_detected=False,
                detection_type=None,
                evidence=[],
            ),
        },

        "correlation": {
            "authentication": {
                "is_correlated": True,
                "type": "failed_to_successful_login",
                "user": "admin",
            },
            "post_authentication": {
                "is_correlated": True,
                "type": "successful_login_to_file_access",
                "user": "admin",
            },
        },
    }

    context = build_risk_context(result)

    risk_factors = build_risk_factors(
        context,
        account_privilege_risk=False,
    )

    assert "authentication" in context["correlation"]
    assert "post_authentication" in context["correlation"]

    assert (
        context["correlation"]["authentication"]["is_correlated"]
        is True
    )

    assert (
        context["correlation"]["post_authentication"]["is_correlated"]
        is True
    )

    assert (
        risk_factors["likelihood"]["signals"]["correlation"]
        == "MEDIUM"
    )