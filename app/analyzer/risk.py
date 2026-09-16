import json


def load_account_metadata():
    with open("data/account_metadata.json", "r") as f:
        return json.load(f)


def build_risk_factors(features, account_privilege_risk):

    likelihood = evaluate_likelihood(features)
    impact = evaluate_impact(account_privilege_risk)
    confidence = evaluate_confidence(features)

    volume_signal = evaluate_volume_signal(features)
    temporal_signal = evaluate_temporal_signal(features)
    targeting_signal = evaluate_targeting_signal(features)
    detection_signal = evaluate_detection_signal(features)
    correlation_signal = evaluate_correlation_signal(features)

    return {

        "likelihood": {
            "level": likelihood["level"],
            "rationale": likelihood["rationale"],

            "signals": {
                "volume": volume_signal,
                "temporal": temporal_signal,
                "targeting": targeting_signal,
                "detection": detection_signal,
                "correlation": correlation_signal,
            },

            "failure_count": features["failure_count"],
            "target_scope": features["unique_target_count"],
            "time_window": features["window_seconds"],
        },

        "impact": {
            "level": impact["level"],
            "rationale": impact["rationale"],
            "privileged_account_targeted": account_privilege_risk,
            "authentication_success": features["login_succeeded"],
        },

        "confidence": {
            "level": confidence["level"],
            "rationale": confidence["rationale"],
        },

        "detections": features["detections"]
    }

def evaluate_likelihood(features):
    detections = features["detections"]
    correlation = features["correlation"]

    brute_force_detected = detections["brute_force"]["is_detected"]
    password_spray_detected = detections["password_spray"]["is_detected"]
    correlated = correlation["is_correlated"]

    failure_count = features["failure_count"]
    target_scope = features["unique_target_count"]
    within_window = features["within_window"]
    average_interval = features["average_interval"]

    rationale = []

    # 1. Brute Force + Failed → Successful Login
    #
    # 반복적인 인증 실패가 탐지되었고
    # 이후 동일 계정의 로그인 성공까지 연결된 경우
    if brute_force_detected and correlated:
        rationale.append(
            f"{failure_count}회의 인증 실패가 발생함"
        )

        if within_window:
            rationale.append(
                f"평균 실패 간격이 {average_interval:.1f}초로 짧음"
            )

        rationale.append(
            "Brute Force 탐지 조건을 충족함"
        )

        rationale.append(
            "인증 실패 이후 동일 계정의 로그인 성공이 확인됨"
        )

        return {
            "level": "HIGH",
            "rationale": rationale,
        }

    # 2. Brute Force
    if brute_force_detected:
        rationale.append(
            f"{failure_count}회의 인증 실패가 발생함"
        )

        if within_window:
            rationale.append(
                f"평균 실패 간격이 {average_interval:.1f}초로 짧음"
            )

        rationale.append(
            "Brute Force 탐지 조건을 충족함"
        )

        return {
            "level": "HIGH",
            "rationale": rationale,
        }

    # 3. Password Spraying-like + Failed → Successful Login
    #
    # 현재 로그에는 비밀번호 재사용 여부가 없으므로
    # Password Spraying 자체가 아니라
    # Password Spraying-like로 표현한다.
    if password_spray_detected and correlated:
        rationale.append(
            f"{failure_count}회의 인증 실패가 발생함"
        )

        rationale.append(
            f"{target_scope}개의 계정이 대상으로 확인됨"
        )

        rationale.append(
            f"실패가 {features['window_seconds']:.1f}초 내에 집중됨"
        )

        rationale.append(
            "Password Spraying-like 탐지 조건을 충족함"
        )

        rationale.append(
            "인증 실패 이후 동일 계정의 로그인 성공이 확인됨"
        )

        return {
            "level": "HIGH",
            "rationale": rationale,
        }

    # 4. Password Spraying-like
    if (
        password_spray_detected
        and target_scope >= 3
        and within_window
    ):
        rationale.append(
            f"{failure_count}회의 인증 실패가 발생함"
        )

        rationale.append(
            f"{target_scope}개의 계정이 대상으로 확인됨"
        )

        rationale.append(
            f"실패가 {features['window_seconds']:.1f}초 내에 집중됨"
        )

        rationale.append(
            "Password Spraying-like 탐지 조건을 충족함"
        )

        return {
            "level": "HIGH",
            "rationale": rationale,
        }

    # 5. 반복 실패 + Failed → Successful Login
    #
    # 공격 탐지까지는 되지 않았지만
    # 반복적인 실패와 이후 성공이 함께 확인된 경우
    if failure_count >= 3 and within_window and correlated:
        rationale.append(
            f"{failure_count}회의 인증 실패가 짧은 시간에 발생함"
        )

        rationale.append(
            "인증 실패 이후 동일 계정의 로그인 성공이 확인됨"
        )

        return {
            "level": "MEDIUM",
            "rationale": rationale,
        }

    # 6. 일반적인 반복 인증 실패
    if failure_count >= 3 and within_window:
        rationale.append(
            f"{failure_count}회의 인증 실패가 짧은 시간에 발생함"
        )

        return {
            "level": "MEDIUM",
            "rationale": rationale,
        }

    # 7. 강한 공격 증거가 없는 경우
    rationale.append(
        "공격으로 판단할 만큼 강한 인증 이상 징후가 확인되지 않음"
    )

    return {
        "level": "LOW",
        "rationale": rationale,
    }


def evaluate_volume_signal(features):
    failure_count = features["failure_count"]

    if failure_count >= 5:
        return "HIGH"

    if failure_count >= 3:
        return "MEDIUM"

    return "LOW"


def evaluate_temporal_signal(features):
    failure_count = features["failure_count"]
    average_interval = features["average_interval"]
    within_window = features["within_window"]

    if failure_count >= 5 and within_window and average_interval <= 5:
        return "HIGH"

    if failure_count >= 3 and within_window and average_interval <= 10:
        return "MEDIUM"

    return "LOW"


def evaluate_targeting_signal(features):
    target_scope = features["unique_target_count"]

    if target_scope >= 3:
        return "HIGH"

    if target_scope >= 2:
        return "MEDIUM"

    return "LOW"


def evaluate_detection_signal(features):
    detections = features["detections"]

    detection_types = []

    if detections["brute_force"]["is_detected"]:
        detection_types.append("brute_force")

    if detections["password_spray"]["is_detected"]:
        detection_types.append(
            detections["password_spray"]["detection_type"]
        )

    if detection_types:
        return {
            "level": "HIGH",
            "types": detection_types,
        }

    return {
        "level": "LOW",
        "types": [],
    }


def evaluate_impact(account_privilege_risk):
    if account_privilege_risk:
        return {
            "level": "HIGH",
            "rationale": [
                "Privileged 계정이 공격 대상으로 확인됨"
            ],
        }

    return {
        "level": "LOW",
        "rationale": [
            "Privileged 계정이 공격 대상으로 확인되지 않음"
        ],
    }


def evaluate_login_success_risk(features):
    return features["login_succeeded"]


def evaluate_failure_risk(features):
    return features["failure_count"]


def evaluate_target_scope_risk(features):
    return features["unique_target_count"]


def evaluate_time_window_risk(features):
    return features["window_seconds"]


def get_account_context(features, account_metadata):
    context = {}

    for user in features["target_users"]:
        if user in account_metadata:
            context[user] = account_metadata[user]

    return context


def evaluate_account_privilege_risk(account_context):
    for user, context in account_context.items():
        privilege = context["privilege"]

        if privilege == "privileged":
            return True

    return False


def evaluate_risk_level(features):

    risk_factors = features["risk_factors"]

    likelihood = risk_factors["likelihood"]["level"]
    impact = risk_factors["impact"]["level"]

    if likelihood == "HIGH" and impact == "HIGH":
        return "HIGH"

    if likelihood == "LOW" and impact == "LOW":
        return "LOW"

    return "MEDIUM"


def evaluate_confidence(features):
    detections = features["detections"]
    correlation = features["correlation"]

    brute_force_detected = detections["brute_force"]["is_detected"]
    password_spray_detected = detections["password_spray"]["is_detected"]
    correlated = correlation["is_correlated"]

    # Brute Force + Failed → Successful Login
    if brute_force_detected and correlated:
        return {
            "level": "HIGH",
            "rationale": [
                "Brute Force의 주요 행동 증거가 로그에서 직접 확인됨",
                "인증 실패 이후 동일 계정의 로그인 성공이 확인됨",
            ],
        }

    # Brute Force
    if brute_force_detected:
        return {
            "level": "HIGH",
            "rationale": [
                "Brute Force의 주요 행동 증거가 로그에서 직접 확인됨"
            ],
        }

    # Password Spraying-like
    if password_spray_detected:
        return {
            "level": "MEDIUM",
            "rationale": [
                "여러 계정에 대한 짧은 시간 내 인증 실패가 확인됨",
                "실제 비밀번호 재사용 여부는 로그에서 확인되지 않음",
            ],
        }

    # Failed → Successful Login
    if correlated:
        return {
            "level": "MEDIUM",
            "rationale": [
                "동일 계정에서 인증 실패 이후 로그인 성공 전이가 확인됨",
                "이벤트 간 연관관계는 확인되지만 공격 행위 자체를 확정할 수는 없음",
            ],
        }

    # 반복적인 인증 실패
    if features["failure_count"] >= 3 and features["within_window"]:
        return {
            "level": "MEDIUM",
            "rationale": [
                "짧은 시간 내 반복적인 인증 실패가 확인됨"
            ],
        }

    return {
        "level": "LOW",
        "rationale": [
            "판단을 뒷받침할 충분한 공격 증거가 확인되지 않음"
        ],
    }

def evaluate_correlation_signal(features):
    correlation = features["correlation"]

    if correlation["is_correlated"]:
        return "MEDIUM"

    return "LOW"