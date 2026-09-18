def correlate_authentication_transition(
    ip_logs,
    correlation_window_seconds=60,
):
    failed_logs = [
        log for log in ip_logs
        if log.event_type == "login_failed"
    ]

    success_logs = [
        log for log in ip_logs
        if log.event_type == "user_login"
    ]

    for success in success_logs:

        closest_failure = None
        closest_time_delta = None

        for failure in failed_logs:

            # 같은 계정인지 확인
            if failure.user != success.user:
                continue

            failure_time = failure.timestamp
            success_time = success.timestamp

            # 성공 이후에 발생한 실패는 제외
            if failure_time >= success_time:
                continue

            # 실패 → 성공까지 걸린 시간
            time_delta = (
                success_time - failure_time
            ).total_seconds()

            # 설정된 시간 범위를 벗어나면 연결하지 않음
            if time_delta > correlation_window_seconds:
                continue

            # 성공에 가장 가까운 실패를 선택
            if (
                closest_time_delta is None
                or time_delta < closest_time_delta
            ):
                closest_failure = failure
                closest_time_delta = time_delta

        # 연결되는 실패가 존재하는 경우
        if closest_failure is not None:
            return {
                "is_correlated": True,
                "type": "failed_to_successful_login",
                "user": success.user,

                "failure_timestamp": closest_failure.timestamp,
                "success_timestamp": success.timestamp,
                "time_delta_seconds": closest_time_delta,

                "rationale": [
                    f"{success.user} 계정에서 로그인 실패 이후 로그인 성공이 확인됨",
                    f"마지막 인증 실패와 로그인 성공 사이의 시간 차이는 {closest_time_delta:.1f}초임",
                ],
            }

    # 연결되는 공격 전이가 없는 경우
    return {
        "is_correlated": False,
        "type": None,
        "user": None,
        "rationale": [],
    }


def correlate_post_authentication_activity(
    ip_logs,
    correlation_window_seconds=60,
):
    success_logs = [
        log for log in ip_logs
        if log.event_type == "user_login"
    ]

    file_access_logs = [
        log for log in ip_logs
        if log.event_type == "file_access"
    ]

    for file_access in file_access_logs:

        closest_success = None
        closest_time_delta = None

        for success in success_logs:

            # 같은 계정인지 확인
            if success.user != file_access.user:
                continue

            success_time = success.timestamp
            file_access_time = file_access.timestamp

            # 로그인 성공 이후의 파일 접근만 확인
            if success_time >= file_access_time:
                continue

            # 로그인 성공 → 파일 접근까지 걸린 시간
            time_delta = (
                file_access_time - success_time
            ).total_seconds()

            # 설정된 시간 범위를 벗어나면 연결하지 않음
            if time_delta > correlation_window_seconds:
                continue

            # 파일 접근에 가장 가까운 로그인 성공을 선택
            if (
                closest_time_delta is None
                or time_delta < closest_time_delta
            ):
                closest_success = success
                closest_time_delta = time_delta

        # 연결되는 로그인 성공이 존재하는 경우
        if closest_success is not None:
            return {
                "is_correlated": True,
                "type": "successful_login_to_file_access",
                "user": file_access.user,

                "success_timestamp": closest_success.timestamp,
                "file_access_timestamp": file_access.timestamp,
                "time_delta_seconds": closest_time_delta,

                "rationale": [
                    f"{file_access.user} 계정에서 로그인 성공 이후 파일 접근이 확인됨",
                    f"로그인 성공과 파일 접근 사이의 시간 차이는 {closest_time_delta:.1f}초임",
                ],
            }

    return {
        "is_correlated": False,
        "type": None,
        "user": None,
        "rationale": [],
    }

def correlate_brute_force_to_success(
    ip_logs,
    brute_force_detection,
    correlation_window_seconds=60,
):
    # Brute Force 탐지가 발생하지 않았다면
    # 이 전이는 확인하지 않음
    if not brute_force_detection.is_detected:
        return {
            "is_correlated": False,
            "type": None,
            "user": None,
            "rationale": [],
        }

    failed_logs = [
        log
        for log in ip_logs
        if log.event_type == "login_failed"
    ]

    success_logs = [
        log
        for log in ip_logs
        if log.event_type == "user_login"
    ]

    for success in success_logs:

        closest_failure = None
        closest_time_delta = None

        for failure in failed_logs:

            # 같은 계정인지 확인
            if failure.user != success.user:
                continue

            failure_time = failure.timestamp
            success_time = success.timestamp

            # 실패 이후의 성공만 확인
            if failure_time >= success_time:
                continue

            # 실패 → 성공 시간 차이
            time_delta = (
                success_time - failure_time
            ).total_seconds()

            # 설정된 시간 범위를 벗어나면 제외
            if time_delta > correlation_window_seconds:
                continue

            # 성공에 가장 가까운 실패를 선택
            if (
                closest_time_delta is None
                or time_delta < closest_time_delta
            ):
                closest_failure = failure
                closest_time_delta = time_delta

        if closest_failure is not None:
            return {
                "is_correlated": True,
                "type": "brute_force_to_successful_login",
                "user": success.user,

                "failure_timestamp": closest_failure.timestamp,
                "success_timestamp": success.timestamp,
                "time_delta_seconds": closest_time_delta,

                "rationale": [
                    f"{success.user} 계정에서 Brute Force 탐지 이후 로그인 성공이 확인됨",
                    f"마지막 인증 실패와 로그인 성공 사이의 시간 차이는 {closest_time_delta:.1f}초임",
                ],
            }

    return {
        "is_correlated": False,
        "type": None,
        "user": None,
        "rationale": [],
    }

def correlate_password_spray_to_success(
    ip_logs,
    password_spray_detection,
    correlation_window_seconds=60,
):
    # Password Spray 탐지가 발생하지 않았다면
    # 이 전이는 확인하지 않음
    if not password_spray_detection.is_detected:
        return {
            "is_correlated": False,
            "type": None,
            "user": None,
            "rationale": [],
        }

    failed_logs = [
        log
        for log in ip_logs
        if log.event_type == "login_failed"
    ]

    success_logs = [
        log
        for log in ip_logs
        if log.event_type == "user_login"
    ]

    for success in success_logs:

        closest_failure = None
        closest_time_delta = None

        for failure in failed_logs:

            # 같은 계정인지 확인
            if failure.user != success.user:
                continue

            failure_time = failure.timestamp
            success_time = success.timestamp

            # 실패 이후의 성공만 확인
            if failure_time >= success_time:
                continue

            # 실패 → 성공 시간 차이
            time_delta = (
                success_time - failure_time
            ).total_seconds()

            # 설정된 시간 범위를 벗어나면 제외
            if time_delta > correlation_window_seconds:
                continue

            # 성공에 가장 가까운 실패를 선택
            if (
                closest_time_delta is None
                or time_delta < closest_time_delta
            ):
                closest_failure = failure
                closest_time_delta = time_delta

        if closest_failure is not None:
            return {
                "is_correlated": True,
                "type": "password_spray_to_successful_login",
                "user": success.user,
                "failure_timestamp": closest_failure.timestamp,
                "success_timestamp": success.timestamp,
                "time_delta_seconds": closest_time_delta,
                "rationale": [
                    f"{success.user} 계정에서 Password Spray 유사 탐지 이후 로그인 성공이 확인됨",
                    f"마지막 인증 실패와 로그인 성공 사이의 시간 차이는 {closest_time_delta:.1f}초임",
                ],
            }

    return {
        "is_correlated": False,
        "type": None,
        "user": None,
        "rationale": [],
    }

def correlate_multi_ip_authentication(
    logs,
    correlation_window_seconds=60,
    min_unique_ips=3,
):
    failed_logs = [
        log
        for log in logs
        if log.event_type == "login_failed"
        and log.user is not None
        and log.src_ip is not None
    ]

    users = {}

    for log in failed_logs:
        if log.user not in users:
            users[log.user] = []

        users[log.user].append(log)

    correlations = []

    for user, user_logs in users.items():
        user_logs.sort(
            key=lambda log: (
                log.timestamp,
                log.src_ip,
            )
        )

        for start_index, start_log in enumerate(user_logs):
            window_logs = []

            for log in user_logs[start_index:]:
                time_delta = (
                    log.timestamp - start_log.timestamp
                ).total_seconds()

                if time_delta > correlation_window_seconds:
                    break

                window_logs.append(log)

            unique_ips = {
                log.src_ip
                for log in window_logs
            }

            if len(unique_ips) >= min_unique_ips:
                correlations.append({
                    "is_correlated": True,
                    "type": "multi_ip_authentication_failure",
                    "user": user,
                    "source_ips": sorted(unique_ips),
                    "failure_count": len(window_logs),
                    "failure_start_timestamp": (
                        window_logs[0].timestamp
                    ),
                    "failure_end_timestamp": (
                        window_logs[-1].timestamp
                    ),
                    "time_window_seconds": (
                        window_logs[-1].timestamp
                        - window_logs[0].timestamp
                    ).total_seconds(),
                    "rationale": [
                        f"{user} 계정에 대한 인증 실패가 여러 IP에서 확인됨",
                        f"{len(unique_ips)}개의 서로 다른 IP에서 "
                        f"{len(window_logs)}회의 인증 실패가 확인됨",
                    ],
                })

                # v1에서는 사용자별 첫 qualifying campaign만 보존
                break

    correlations.sort(
        key=lambda result: (
            result["failure_start_timestamp"],
            result["user"],
        )
    )

    return correlations


def correlate_distributed_authentication_to_success(
    logs,
    failure_correlations,
    success_window_seconds=60,
):
    success_logs = [
        log
        for log in logs
        if log.event_type == "user_login"
        and log.user is not None
    ]

    success_logs.sort(
        key=lambda log: (
            log.timestamp,
            log.user,
            log.src_ip or "",
        )
    )

    correlations = []

    for failure in sorted(
        failure_correlations,
        key=lambda result: (
            result["failure_start_timestamp"],
            result["user"],
        ),
    ):
        failure_end = failure["failure_end_timestamp"]

        matching_success = None
        matching_delta = None

        for success in success_logs:
            if success.user != failure["user"]:
                continue

            time_delta = (
                success.timestamp - failure_end
            ).total_seconds()

            if time_delta <= 0:
                continue

            if time_delta > success_window_seconds:
                continue

            matching_success = success
            matching_delta = time_delta
            break

        if matching_success is None:
            continue

        failure_source_ips = list(failure["source_ips"])
        success_from_failure_source = (
            matching_success.src_ip in failure_source_ips
        )

        failure_duration = (
            failure["failure_end_timestamp"]
            - failure["failure_start_timestamp"]
        ).total_seconds()

        correlations.append({
            "is_correlated": True,
            "type": (
                "distributed_authentication_failures_"
                "to_successful_login"
            ),
            "user": failure["user"],
            "failure_source_ips": failure_source_ips,
            "failure_count": failure["failure_count"],
            "failure_start_timestamp": (
                failure["failure_start_timestamp"]
            ),
            "failure_end_timestamp": failure_end,
            "failure_duration_seconds": failure_duration,
            "success_timestamp": matching_success.timestamp,
            "success_source_ip": matching_success.src_ip,
            "success_from_failure_source": (
                success_from_failure_source
            ),
            "time_delta_seconds": matching_delta,
            "rationale": [
                f"{failure['user']} 계정의 인증 실패가 여러 "
                "source IP에서 관찰됨",
                f"failure campaign 종료 이후 동일 계정의 로그인 "
                f"성공이 {matching_delta:.1f}초 뒤 관찰됨",
                f"로그인 성공 source IP는 "
                f"{matching_success.src_ip}임",
                "로그인 성공 source IP가 앞선 failure source "
                f"집합에 포함되는지 여부: "
                f"{success_from_failure_source}",
                "이 이벤트 관계만으로 계정 침해, 공격자 로그인 "
                "또는 앞선 실패와 성공 사이의 인과관계를 "
                "확인할 수 없음",
            ],
        })

    return correlations
