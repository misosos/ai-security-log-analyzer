from app.analyzer.pipeline import (
    load_normalized_logs,
    detect_attacks,
)

from app.correlation.attack_chain import (
    correlate_authentication_transition
)

from app.analyzer.risk import (
    build_risk_factors,
    load_account_metadata,
    get_account_context,
    evaluate_account_privilege_risk,
    evaluate_risk_level,
)


LOG_SOURCES = [
    {
        "source": "application",
        "path": "sample_logs/brute_force.log",
    },
    {
        "source": "ssh",
        "path": "sample_logs/ssh_auth.log",
    },
]


logs = load_normalized_logs(LOG_SOURCES)

result = detect_attacks(logs)

account_metadata = load_account_metadata()

print(account_metadata)


for ip, features in result.items():

    ip_logs = [
        log for log in logs
        if log.src_ip == ip
    ]

    correlation_result = correlate_authentication_transition(
        ip_logs
    )

    features["correlation"] = correlation_result

    print(ip, correlation_result)


    account_context = get_account_context(
        features,
        account_metadata
    )

    account_privilege_risk = evaluate_account_privilege_risk(
        account_context
    )

    risk_factors = build_risk_factors(
        features,
        account_privilege_risk
    )

    risk_factors["account_context"] = account_context

    features["risk_factors"] = risk_factors

    risk_level = evaluate_risk_level(features)

    features["risk_level"] = risk_level


print("분석 결과:")
print(result)