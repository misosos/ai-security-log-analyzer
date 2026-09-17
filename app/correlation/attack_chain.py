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