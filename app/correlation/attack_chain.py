from datetime import datetime


def correlate_authentication_transition(ip_logs):
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

            failure_time = datetime.strptime(
                failure.timestamp,
                "%Y-%m-%d %H:%M:%S"
            )

            success_time = datetime.strptime(
                success.timestamp,
                "%Y-%m-%d %H:%M:%S"
            )

            # 성공 이후에 발생한 실패는 제외
            if failure_time >= success_time:
                continue

            # 실패 → 성공까지 걸린 시간
            time_delta = (
                success_time - failure_time
            ).total_seconds()

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