import json


def load_account_metadata():
    with open("data/account_metadata.json", "r") as f:
        return json.load(f)


def build_risk_context(result):

    context = {}

    context.update(result["features"])

    context["detections"] = result["detections"]

    context["correlation"] = result.get(
        "correlation",
        {
            "authentication": {
                "is_correlated": False,
            },
            "post_authentication": {
                "is_correlated": False,
            },
        },
    )

    return context


def build_risk_factors(features, account_privilege_risk):

    likelihood = evaluate_likelihood(features)

    impact = evaluate_impact(
        features,
        account_privilege_risk,
    )

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
                "volume": {
                    "level": volume_signal,
                    "rationale": (
                        f"인증 실패가 {features['failure_count']}회 발생함"
                    ),
                },
                "temporal": {
                    "level": temporal_signal,
                    "rationale": (
                        f"인증 실패가 {features['window_seconds']:.1f}초 동안 발생했으며 "
                        f"평균 실패 간격은 {features['average_interval']:.1f}초임"
                    ),
                },
                "targeting": {
                    "level": targeting_signal,
                    "rationale": (
                        f"{features['unique_target_count']}개의 계정이 "
                        "인증 실패 대상으로 확인됨"
                    ),
                },
                "detection": detection_signal,
                "correlation": {
                    "level": correlation_signal,
                    "types": [
                        correlation_result["type"]
                        for correlation_result
                        in features["correlation"].values()
                        if correlation_result["is_correlated"]
                        and correlation_result.get("type") is not None
                    ],
                },
            },

            "failure_count": features["failure_count"],
            "target_scope": features["unique_target_count"],
            "time_window": features["window_seconds"],
        },

        "impact": {
            "level": impact["level"],
            "rationale": impact["rationale"],
            "basis": impact["basis"],
            "privileged_account_targeted": account_privilege_risk,
            "authentication_success": features["login_succeeded"],
        },

        "confidence": {
            "level": confidence["level"],
            "rationale": confidence["rationale"],
        },

        "evidence": (
            extract_evidence({
                "detections": features["detections"],
            })
            + extract_correlation_evidence({
                "correlation": features["correlation"],
            })
        ),
                
    }


def evaluate_likelihood(features):

    detections = features["detections"]
    correlation = features["correlation"]

    brute_force = detections["brute_force"]

    brute_force_detected = (
        brute_force.is_detected
    )

    password_spray_detected = (
        detections["password_spray"].is_detected
    )

    path_traversal = detections.get("path_traversal")

    path_traversal_detected = (
        path_traversal is not None
        and path_traversal.is_detected
    )

    authentication_correlated = (
        correlation["authentication"]["is_correlated"]
    )

    post_authentication_correlated = (
        correlation["post_authentication"]["is_correlated"]
    )

    brute_force_to_success = (
        correlation["brute_force_to_success"]["is_correlated"]
    )

    password_spray_to_success = (
        correlation["password_spray_to_success"]["is_correlated"]
    )

    failure_count = features["failure_count"]
    target_scope = features["unique_target_count"]
    within_window = features["within_window"]
    average_interval = features["average_interval"]

    rationale = []

    # 1. Path Traversal
    if path_traversal_detected:

        rationale.append(
            "Path Traversal 공격 패턴이 HTTP 요청에서 직접 확인됨"
        )

        rationale.append(
            "URL 디코딩 이후 상위 경로 접근 패턴(../)이 확인됨"
        )

        rationale.append(
            "실제 대상 파일 접근 성공 여부는 현재 로그만으로 확인할 수 없음"
        )

        return {
            "level": "HIGH",
            "rationale": rationale,
        }

    # 2. Brute Force + Failed → Successful Login
    if (
        brute_force_detected
        and brute_force_to_success
    ):

        for evidence in brute_force.evidence:

            if evidence.type == "multiple_login_failures":
                rationale.append(
                    f"{evidence.value}회의 인증 실패가 발생함"
                )

            elif evidence.type == "single_target_user":
                rationale.append(
                    "단일 계정에 인증 실패가 집중됨"
                )

            elif evidence.type == "failures_within_short_window":
                rationale.append(
                    f"실패가 {evidence.value:.1f}초 내에 집중됨"
                )

        rationale.append(
            "Brute Force 탐지 조건을 충족함"
        )

        rationale.append(
            "Brute Force 탐지 이후 동일 계정의 로그인 성공이 확인됨"
        )

        return {
            "level": "HIGH",
            "rationale": rationale,
        }

    # 3. Brute Force
    if brute_force_detected:

        for evidence in brute_force.evidence:

            if evidence.type == "multiple_login_failures":
                rationale.append(
                    f"{evidence.value}회의 인증 실패가 발생함"
                )

            elif evidence.type == "single_target_user":
                rationale.append(
                    "단일 계정에 인증 실패가 집중됨"
                )

            elif evidence.type == "failures_within_short_window":
                rationale.append(
                    f"실패가 {evidence.value:.1f}초 내에 집중됨"
                )

        rationale.append(
            "Brute Force 탐지 조건을 충족함"
        )

        return {
            "level": "HIGH",
            "rationale": rationale,
        }

    # 4. Password Spraying-like + Failed → Successful Login
    if (
        password_spray_detected
        and password_spray_to_success
    ):

        password_spray = (
            detections["password_spray"]
        )

        for evidence in password_spray.evidence:

            if evidence.type == "multiple_login_failures":
                rationale.append(
                    f"{evidence.value}회의 인증 실패가 발생함"
                )

            elif evidence.type == "multiple_target_users":
                rationale.append(
                    f"{evidence.value}개의 계정이 대상으로 확인됨"
                )

            elif evidence.type == "failures_within_short_window":
                rationale.append(
                    f"실패가 {evidence.value:.1f}초 내에 집중됨"
                )

        rationale.append(
            "Password Spraying-like 탐지 조건을 충족함"
        )

        rationale.append(
            "Password Spraying-like 탐지 이후 동일 계정의 로그인 성공이 확인됨"
        )

        return {
            "level": "HIGH",
            "rationale": rationale,
        }

    # 5. Password Spraying-like
    if (
        password_spray_detected
        and target_scope >= 3
        and within_window
    ):

        password_spray = (
            detections["password_spray"]
        )

        for evidence in password_spray.evidence:

            if evidence.type == "multiple_login_failures":
                rationale.append(
                    f"{evidence.value}회의 인증 실패가 발생함"
                )

            elif evidence.type == "multiple_target_users":
                rationale.append(
                    f"{evidence.value}개의 계정이 대상으로 확인됨"
                )

            elif evidence.type == "failures_within_short_window":
                rationale.append(
                    f"실패가 {evidence.value:.1f}초 내에 집중됨"
                )

        rationale.append(
            "Password Spraying-like 탐지 조건을 충족함"
        )

        return {
            "level": "HIGH",
            "rationale": rationale,
        }

    # 6. 반복 실패 + Failed → Successful Login
    if (
        failure_count >= 3
        and within_window
        and authentication_correlated
    ):

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

    # 7. 일반적인 반복 인증 실패
    if (
        failure_count >= 3
        and within_window
    ):

        rationale.append(
            f"{failure_count}회의 인증 실패가 짧은 시간에 발생함"
        )

        return {
            "level": "MEDIUM",
            "rationale": rationale,
        }

    # 8. 강한 공격 증거가 없는 경우
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

    if (
        failure_count >= 5
        and within_window
        and average_interval <= 5
    ):
        return "HIGH"

    if (
        failure_count >= 3
        and within_window
        and average_interval <= 10
    ):
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

    if detections["brute_force"].is_detected:
        detection_types.append("brute_force")

    if detections["password_spray"].is_detected:
        detection_types.append(
            detections["password_spray"].detection_type
        )

    path_traversal = detections.get("path_traversal")

    if (
        path_traversal is not None
        and path_traversal.is_detected
    ):
        detection_types.append(
            path_traversal.detection_type
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


def evaluate_impact(features, account_privilege_risk):

    detections = features["detections"]

    brute_force_detected = (
        detections["brute_force"].is_detected
    )

    password_spray_detected = (
        detections["password_spray"].is_detected
    )

    path_traversal = detections.get("path_traversal")

    path_traversal_detected = (
        path_traversal is not None
        and path_traversal.is_detected
    )

    # 1. Web Attack
    if path_traversal_detected:

        status_code = None
        response_size = None

        for evidence in path_traversal.evidence:

            if evidence.type == "http_status_code":
                status_code = evidence.value

            elif evidence.type == "http_response_size":
                response_size = evidence.value

        # 현재 로그에서 HTTP 응답은 확인되지만
        # 실제 민감 파일 노출 여부는 확인되지 않은 경우
        if status_code is not None:

            if 200 <= status_code < 300:

                return {
                    "level": "MEDIUM",
                    "rationale": [
                        "Path Traversal 공격 패턴이 확인됨",
                        f"공격 요청에 대해 HTTP {status_code} 응답이 확인됨",
                        "요청이 애플리케이션에서 처리된 정황이 확인됨",
                        "실제 민감 파일의 내용이 반환되었는지는 현재 로그만으로 확인되지 않음",
                    ],
                    "basis": {
                        "attack_type": "path_traversal",
                        "http_status_code": status_code,
                        "response_size": response_size,
                        "impact_status": "insufficient_evidence",
                        "exploit_success_confirmed": False,
                    },
                }

            # 4xx / 5xx 등
            return {
                "level": "LOW",
                "rationale": [
                    "Path Traversal 공격 패턴이 확인됨",
                    f"공격 요청에 대해 HTTP {status_code} 응답이 확인됨",
                    "현재 로그만으로 실제 파일 접근 또는 정보 노출 여부는 확인되지 않음",
                ],
                "basis": {
                    "attack_type": "path_traversal",
                    "http_status_code": status_code,
                    "response_size": response_size,
                    "impact_status": "insufficient_evidence",
                    "exploit_success_confirmed": False,
                },
            }

        # HTTP 결과 자체가 없는 경우
        return {
            "level": "LOW",
            "rationale": [
                "Path Traversal 공격 패턴이 확인됨",
                "실제 대상 파일 접근 또는 정보 노출 여부를 판단할 HTTP 결과가 확인되지 않음",
            ],
            "basis": {
                "attack_type": "path_traversal",
                "http_status_code": None,
                "response_size": None,
                "impact_status": "insufficient_evidence",
                "exploit_success_confirmed": False,
            },
        }

    # 2. Authentication Attack
    if brute_force_detected or password_spray_detected:

        attack_type = (
            "brute_force"
            if brute_force_detected
            else "password_spraying_like"
        )

        if account_privilege_risk:

            return {
                "level": "HIGH",
                "rationale": [
                    "인증 공격의 대상에 Privileged 계정이 포함됨"
                ],
                "basis": {
                    "attack_type": attack_type,
                    "privileged_account_targeted": True,
                },
            }

        return {
            "level": "LOW",
            "rationale": [
                "인증 공격 패턴은 확인되었으나 Privileged 계정 대상은 확인되지 않음"
            ],
            "basis": {
                "attack_type": attack_type,
                "privileged_account_targeted": False,
            },
        }

    # 3. 기타 인증 이상
    if account_privilege_risk:

        return {
            "level": "HIGH",
            "rationale": [
                "Privileged 계정이 인증 이상 행위의 대상으로 확인됨"
            ],
            "basis": {
                "privileged_account_targeted": True,
            },
        }

    return {
        "level": "LOW",
        "rationale": [
            "영향도를 높일 수 있는 대상 중요도 정보가 확인되지 않음"
        ],
        "basis": {
            "privileged_account_targeted": False,
        },
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


def evaluate_risk_level(result):
    likelihood = result["risk_factors"]["likelihood"]["level"]
    impact = result["risk_factors"]["impact"]["level"]

    risk_matrix = {
        "LOW": {
            "LOW": "LOW",
            "MEDIUM": "LOW",
            "HIGH": "MEDIUM",
        },
        "MEDIUM": {
            "LOW": "MEDIUM",
            "MEDIUM": "MEDIUM",
            "HIGH": "HIGH",
        },
        "HIGH": {
            "LOW": "MEDIUM",
            "MEDIUM": "HIGH",
            "HIGH": "HIGH",
        },
    }

    return risk_matrix[likelihood][impact]


def evaluate_confidence(features):

    detections = features["detections"]
    correlation = features["correlation"]

    brute_force_detected = (
        detections["brute_force"].is_detected
    )

    password_spray_detected = (
        detections["password_spray"].is_detected
    )

    path_traversal = detections.get("path_traversal")

    path_traversal_detected = (
        path_traversal is not None
        and path_traversal.is_detected
    )

    authentication_correlated = (
        correlation["authentication"]["is_correlated"]
    )

    post_authentication_correlated = (
        correlation["post_authentication"]["is_correlated"]
    )

    brute_force_to_success = (
        correlation["brute_force_to_success"]["is_correlated"]
    )

    password_spray_to_success = (
        correlation["password_spray_to_success"]["is_correlated"]
    )

    # Path Traversal
    if path_traversal_detected:

        return {
            "level": "MEDIUM",
            "rationale": [
                "HTTP 요청에서 Path Traversal 공격 패턴이 직접 확인됨",
                "실제 대상 파일 접근 성공 여부는 현재 로그에서 확인되지 않음",
            ],
        }

    # Brute Force + Failed → Successful Login
    if (
        brute_force_detected
        and brute_force_to_success
    ):

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

    # Password Spraying-like + Failed → Successful Login
    if (
        password_spray_detected
        and password_spray_to_success
    ):

        return {
            "level": "HIGH",
            "rationale": [
                "여러 계정에 대한 짧은 시간 내 인증 실패가 확인됨",
                "Password Spraying-like 탐지 조건을 충족함",
                "Password Spraying-like 탐지 이후 동일 계정의 로그인 성공이 확인됨",
                "실제 비밀번호 재사용 여부는 로그에서 확인되지 않음",
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
    if authentication_correlated:

        return {
            "level": "MEDIUM",
            "rationale": [
                "동일 계정에서 인증 실패 이후 로그인 성공 전이가 확인됨",
                "이벤트 간 연관관계는 확인되지만 공격 행위 자체를 확정할 수는 없음",
            ],
        }

    # Post-authentication activity
    if post_authentication_correlated:

        return {
            "level": "MEDIUM",
            "rationale": [
                "로그인 성공 이후 동일 계정의 후속 파일 접근 행위가 확인됨",
                "정상적인 사용자 활동일 가능성을 배제할 수 없어 공격 행위 자체를 확정할 수는 없음",
            ],
        }

    # 반복적인 인증 실패
    if (
        features["failure_count"] >= 3
        and features["within_window"]
    ):

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

    authentication_correlated = (
        correlation["authentication"]["is_correlated"]
    )

    post_authentication_correlated = (
        correlation["post_authentication"]["is_correlated"]
    )

    brute_force_to_success = (
        correlation["brute_force_to_success"]["is_correlated"]
    )

    password_spray_to_success = (
        correlation["password_spray_to_success"]["is_correlated"]
    )

    if (
        authentication_correlated
        or post_authentication_correlated
        or brute_force_to_success
        or password_spray_to_success
    ):
        return "MEDIUM"

    return "LOW"


def extract_evidence(result):

    evidence = []

    detections = result["detections"]

    for detection in detections.values():

        if not detection.is_detected:
            continue

        for item in detection.evidence:

            evidence.append({
                "type": item.type,
                "value": item.value,
                "source": item.source,
                "timestamp": item.timestamp,
                "time_range": item.time_range,
            })

    return evidence


def extract_correlation_evidence(result):

    evidence = []

    correlation = result["correlation"]

    for correlation_key, correlation_result in correlation.items():

        if not correlation_result["is_correlated"]:
            continue

        correlation_type = correlation_result.get("type")
        user = correlation_result.get("user")
        failure_timestamp = correlation_result.get("failure_timestamp")
        success_timestamp = correlation_result.get("success_timestamp")
        time_delta = correlation_result.get("time_delta_seconds")

        if correlation_type:
            evidence.append({
                "type": "correlation_type",
                "value": correlation_type,
                "source": f"{correlation_key}_correlation",
            })

        if user:
            evidence.append({
                "type": "correlation_user",
                "value": user,
                "source": f"{correlation_key}_correlation",
            })

        if time_delta is not None:
            evidence.append({
                "type": "correlation_time_delta",
                "value": time_delta,
                "source": f"{correlation_key}_correlation",
            })

        if failure_timestamp and success_timestamp:
            evidence.append({
                "type": "correlation_time_range",
                "value": (
                    failure_timestamp,
                    success_timestamp,
                ),
                "source": f"{correlation_key}_correlation",
                "time_range": (
                    failure_timestamp,
                    success_timestamp,
                ),
            })

    return evidence