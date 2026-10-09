"""Reviewed synthetic labels; never derive these from analyzer output."""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path


FIXTURE_ROOT = Path(__file__).resolve().parents[2] / "sample_logs" / "evaluation"
SUBJECT = "192.0.2.10"
WEB_SUBJECT = "198.51.100.10"
DETECTION_TYPES = ("brute_force", "password_spraying_like", "path_traversal")
RELATION_TYPES = (
    "failed_to_successful_login",
    "brute_force_to_successful_login",
    "password_spray_to_successful_login",
)
CASE_RULES = ("CASE-BRUTE-SUCCESS-01", "CASE-AUTH-TRANSITION-01")
LEVELS = ("HIGH", "MEDIUM", "LOW")


def utc(second: int) -> datetime:
    return datetime(2026, 10, 8, tzinfo=timezone.utc) + timedelta(seconds=second)


@dataclass(frozen=True)
class ExpectedParser:
    lines: int
    parsed: int
    ignored: int
    failed: int
    event_types: tuple[str, ...]
    subject: str | None
    first_timestamp: datetime | None
    last_timestamp: datetime | None
    account_present: tuple[bool, ...]
    http_methods: tuple[str | None, ...]
    http_statuses: tuple[int | None, ...]
    line_dispositions: tuple[str, ...]


@dataclass(frozen=True)
class ExpectedDetection:
    detection_type: str
    subject: str
    start: datetime | None = None
    end: datetime | None = None
    failure_count: int | None = None
    target_count: int | None = None
    window_seconds: int | None = None


@dataclass(frozen=True)
class ExpectedRelation:
    relation_type: str
    subject: str
    failure_timestamp: datetime
    success_timestamp: datetime


@dataclass(frozen=True)
class ExpectedRisk:
    subject: str
    level: str
    confidence: str


@dataclass(frozen=True)
class ExpectedCase:
    rule: str
    risk: str
    supporting_relations: int
    observation_count: int


@dataclass(frozen=True)
class EvaluationScenario:
    id: str
    description: str
    fixture: str
    source: str
    parser: ExpectedParser
    detections: tuple[ExpectedDetection, ...]
    relations: tuple[ExpectedRelation, ...]
    risks: tuple[ExpectedRisk, ...]
    cases: tuple[ExpectedCase, ...]
    independent_count: int
    rationale: str
    limitation: str
    label_scope: str = "labeled"
    exclusion_reason: str | None = None


def _parser(count: int, event_types: tuple[str, ...], end: int,
            subject: str = SUBJECT, status: int = 200) -> ExpectedParser:
    is_web = subject == WEB_SUBJECT
    return ExpectedParser(
        count, count, 0, 0, event_types, subject, utc(0), utc(end),
        (not is_web,) * count,
        (("GET" if is_web else None),) * count,
        ((status if is_web else None),) * count,
        ("parsed",) * count,
    )


def _auth(count: int, end: int, *, success: bool = False) -> ExpectedParser:
    events = ("login_failed",) * (count - int(success))
    if success:
        events += ("user_login",)
    return _parser(count, events, end)


def _brute(end: int = 40) -> tuple[ExpectedDetection, ...]:
    return (ExpectedDetection("brute_force", SUBJECT, utc(0), utc(end), 5, 1, end),)


def _spray(end: int = 60) -> tuple[ExpectedDetection, ...]:
    return (ExpectedDetection("password_spraying_like", SUBJECT, utc(0), utc(end), 4, 3, end),)


def _relation(kind: str, failure: int, success: int) -> ExpectedRelation:
    return ExpectedRelation(kind, SUBJECT, utc(failure), utc(success))


SCENARIOS: tuple[EvaluationScenario, ...] = (
    EvaluationScenario("login_only", "정상 로그인만", "login_only.log", "application",
                       _parser(1, ("user_login",), 0), (), (),
                       (ExpectedRisk(SUBJECT, "LOW", "LOW"),), (), 0,
                       "실패 또는 탐지 근거 없음", "정상 로그인은 안전 판정이 아님"),
    EvaluationScenario("brute_below", "Brute Force 임계값 아래", "brute_below.log", "application",
                       _auth(4, 30), (), (),
                       (ExpectedRisk(SUBJECT, "MEDIUM", "MEDIUM"),), (), 0,
                       "4회는 승인된 5회 임계값 아래", "반복 실패 위험도는 탐지와 별개"),
    EvaluationScenario("brute_exact", "5회·60초 포함 경계", "brute_exact.log", "application",
                       _auth(5, 60), _brute(60), (),
                       (ExpectedRisk(SUBJECT, "MEDIUM", "HIGH"),), (), 1,
                       "5회와 60초는 포함", "탐지는 침해 확정이 아님"),
    EvaluationScenario("brute_over_window", "61초는 범위 밖", "brute_over_window.log", "application",
                       _auth(5, 61), (), (),
                       (ExpectedRisk(SUBJECT, "LOW", "LOW"),), (), 0,
                       "전체 실패 폭 61초는 60초 초과", "슬라이딩 부분창이 아닌 전체 폭"),
    EvaluationScenario("brute_success", "같은 계정 후속 성공", "brute_success.log", "application",
                       _auth(6, 100, success=True), _brute(),
                       (_relation("failed_to_successful_login", 40, 100),
                        _relation("brute_force_to_successful_login", 40, 100)),
                       (ExpectedRisk(SUBJECT, "MEDIUM", "HIGH"),),
                       (ExpectedCase("CASE-BRUTE-SUCCESS-01", "MEDIUM", 2, 3),), 0,
                       "동일 계정·정확한 끝점, generic 관계 흡수", "로그인 성공은 계정 침해 증거가 아님"),
    EvaluationScenario("brute_other_account", "성공 계정 불일치", "brute_other_account.log", "application",
                       _auth(6, 50, success=True), _brute(), (),
                       (ExpectedRisk(SUBJECT, "MEDIUM", "HIGH"),), (), 1,
                       "다른 계정은 연결하지 않음", "동일 IP만으로 연결하지 않음"),
    EvaluationScenario("brute_success_late", "상관 범위 1초 초과", "brute_success_late.log", "application",
                       _auth(6, 101, success=True), _brute(), (),
                       (ExpectedRisk(SUBJECT, "MEDIUM", "HIGH"),), (), 1,
                       "61초 관계는 제외", "파일 parser는 초 단위"),
    EvaluationScenario("spray_exact", "4회·3계정·60초 포함", "spray_exact.log", "application",
                       _auth(4, 60), _spray(), (),
                       (ExpectedRisk(SUBJECT, "MEDIUM", "MEDIUM"),), (), 1,
                       "spray 경계 정확히 포함", "Spray 사례는 typed membership 부재로 no-go"),
    EvaluationScenario("spray_success", "Spray 관계는 사례 no-go", "spray_success.log", "application",
                       _auth(5, 40, success=True), _spray(30),
                       (_relation("failed_to_successful_login", 30, 40),
                        _relation("password_spray_to_successful_login", 30, 40)),
                       (ExpectedRisk(SUBJECT, "MEDIUM", "HIGH"),),
                       (ExpectedCase("CASE-AUTH-TRANSITION-01", "MEDIUM", 1, 2),), 2,
                       "generic 인증 사례만, spray 탐지와 관계는 독립", "Spray 성공 사례 자동 결합 불가"),
    EvaluationScenario("spray_below_accounts", "계정 수 부족", "spray_below_accounts.log", "application",
                       _auth(4, 30), (), (),
                       (ExpectedRisk(SUBJECT, "MEDIUM", "MEDIUM"),), (), 0,
                       "2계정은 3계정 미만", "같은 계정 반복은 spray가 아님"),
    EvaluationScenario("spray_over_window", "Spray 시간 범위 초과", "spray_over_window.log", "application",
                       _auth(4, 61), (), (),
                       (ExpectedRisk(SUBJECT, "LOW", "LOW"),), (), 0,
                       "61초는 범위 초과", "파일 parser는 초 단위"),
    EvaluationScenario("auth_transition", "실패 후 성공 60초 경계", "auth_transition.log", "application",
                       _auth(2, 60, success=True), (),
                       (_relation("failed_to_successful_login", 0, 60),),
                       (ExpectedRisk(SUBJECT, "LOW", "MEDIUM"),),
                       (ExpectedCase("CASE-AUTH-TRANSITION-01", "LOW", 1, 2),), 0,
                       "동일 subject·account·60초", "상관관계는 인과관계가 아님"),
    EvaluationScenario("auth_transition_late", "실패 후 성공 61초", "auth_transition_late.log", "application",
                       _auth(2, 61, success=True), (), (),
                       (ExpectedRisk(SUBJECT, "LOW", "LOW"),), (), 0,
                       "61초는 관계 범위 초과", "로그인 성공은 공격 성공이 아님"),
    EvaluationScenario("traversal", "반복 인코딩 traversal, HTTP 200", "traversal.log", "access",
                       _parser(1, ("http_request",), 0, WEB_SUBJECT),
                       (ExpectedDetection("path_traversal", WEB_SUBJECT, utc(0), utc(0)),), (),
                       (ExpectedRisk(WEB_SUBJECT, "HIGH", "MEDIUM"),), (), 1,
                       "반복 decode 후 ../", "HTTP 200은 파일 노출 증거가 아님"),
    EvaluationScenario("normal_web", "정상 query와 HTTP 200", "normal_web.log", "access",
                       _parser(1, ("http_request",), 0, WEB_SUBJECT), (), (),
                       (ExpectedRisk(WEB_SUBJECT, "LOW", "LOW"),), (), 0,
                       "승인된 traversal pattern 없음", "응답 상태만으로 공격 성공 추정 금지"),
    EvaluationScenario("brute_above", "실패 6회", "brute_above.log", "application",
                       _auth(6, 50),
                       (ExpectedDetection("brute_force", SUBJECT, utc(0), utc(50), 6, 1, 50),), (),
                       (ExpectedRisk(SUBJECT, "MEDIUM", "HIGH"),), (), 1,
                       "5회 초과도 탐지", "실패 중복은 별도 이벤트로 계수"),
    EvaluationScenario("low_failures", "낮은 빈도의 실패", "low_failures.log", "application",
                       _auth(2, 50), (), (),
                       (ExpectedRisk(SUBJECT, "LOW", "LOW"),), (), 0,
                       "탐지·반복 실패 위험 경계 아래", "탐지 부재는 안전 판정이 아님"),
    EvaluationScenario("spray_below_failures", "세 계정이지만 실패 3회", "spray_below_failures.log", "application",
                       _auth(3, 20), (), (),
                       (ExpectedRisk(SUBJECT, "MEDIUM", "MEDIUM"),), (), 0,
                       "계정 범위만 충족하고 실패 수 부족", "계정 수만으로 탐지하지 않음"),
    EvaluationScenario("success_before", "성공이 모든 실패보다 앞", "success_before.log", "application",
                       _parser(6, ("user_login",) + ("login_failed",) * 5, 50),
                       (ExpectedDetection("brute_force", SUBJECT, utc(10), utc(50), 5, 1, 40),), (),
                       (ExpectedRisk(SUBJECT, "MEDIUM", "HIGH"),), (), 1,
                       "앞선 성공을 후속 성공 관계로 바꾸지 않음", "로그인 성공은 공격 성공 증거가 아님"),
    EvaluationScenario("traversal_raw", "명시적 ../ 와 HTTP 404", "traversal_raw.log", "access",
                       _parser(1, ("http_request",), 0, WEB_SUBJECT, 404),
                       (ExpectedDetection("path_traversal", WEB_SUBJECT, utc(0), utc(0)),), (),
                       (ExpectedRisk(WEB_SUBJECT, "MEDIUM", "MEDIUM"),), (), 1,
                       "승인된 ../ pattern", "404에서도 파일 접근 성공은 추정하지 않음"),
    EvaluationScenario("traversal_false_like", "상위 경로 패턴이 아닌 문자열", "traversal_false_like.log", "access",
                       _parser(1, ("http_request",), 0, WEB_SUBJECT), (), (),
                       (ExpectedRisk(WEB_SUBJECT, "LOW", "LOW"),), (), 0,
                       ".. 뒤에 slash가 없으므로 미탐지", "HTTP 200만으로 탐지하지 않음"),
    EvaluationScenario("ssh_login_only", "SSH 정상 publickey 성공", "ssh_login_only.log", "ssh",
                       _parser(1, ("user_login",), 0), (), (),
                       (ExpectedRisk(SUBJECT, "LOW", "LOW"),), (), 0,
                       "지원 SSH 성공 문구", "로그인 성공은 공격 성공 증거가 아님"),
    EvaluationScenario("ssh_failure_only", "SSH 단일 실패", "ssh_failure_only.log", "ssh",
                       _auth(1, 0), (), (),
                       (ExpectedRisk(SUBJECT, "LOW", "LOW"),), (), 0,
                       "지원 SSH 실패 문구", "한 번의 실패만으로 탐지하지 않음"),
    EvaluationScenario("ssh_brute_below", "SSH 임계값 바로 아래", "ssh_brute_below.log", "ssh",
                       _auth(4, 30), (), (),
                       (ExpectedRisk(SUBJECT, "MEDIUM", "MEDIUM"),), (), 0,
                       "SSH 실패 4회", "반복 실패 risk는 탐지와 별개"),
    EvaluationScenario("ssh_brute_exact", "SSH 5회·60초 경계", "ssh_brute_exact.log", "ssh",
                       _auth(5, 60), _brute(60), (),
                       (ExpectedRisk(SUBJECT, "MEDIUM", "HIGH"),), (), 1,
                       "SSH 실패 5회와 60초 포함", "탐지는 침해 확정이 아님"),
    EvaluationScenario("ssh_brute_success", "SSH 동일 계정 후속 성공", "ssh_brute_success.log", "ssh",
                       _auth(6, 50, success=True), _brute(),
                       (_relation("failed_to_successful_login", 40, 50),
                        _relation("brute_force_to_successful_login", 40, 50)),
                       (ExpectedRisk(SUBJECT, "MEDIUM", "HIGH"),),
                       (ExpectedCase("CASE-BRUTE-SUCCESS-01", "MEDIUM", 2, 3),), 0,
                       "SSH 실패 뒤 동일 계정 성공", "성공은 계정 침해 증거가 아님"),
    EvaluationScenario("ssh_other_account", "SSH 성공 계정 불일치", "ssh_other_account.log", "ssh",
                       _auth(6, 50, success=True), _brute(), (),
                       (ExpectedRisk(SUBJECT, "MEDIUM", "HIGH"),), (), 1,
                       "SSH 계정 불일치", "동일 IP만으로 연결 금지"),
    EvaluationScenario("ssh_success_before", "SSH 성공이 실패보다 앞", "ssh_success_before.log", "ssh",
                       _parser(6, ("user_login",) + ("login_failed",) * 5, 50),
                       (ExpectedDetection("brute_force", SUBJECT, utc(10), utc(50), 5, 1, 40),), (),
                       (ExpectedRisk(SUBJECT, "MEDIUM", "HIGH"),), (), 1,
                       "앞선 성공은 후속 관계가 아님", "실패·성공 순서 유지"),
    EvaluationScenario("ssh_multi_success", "SSH 성공 두 후보 중 가까운 시각", "ssh_multi_success.log", "ssh",
                       _parser(7, ("login_failed",) * 5 + ("user_login",) * 2, 50), _brute(),
                       (_relation("failed_to_successful_login", 40, 50),
                        _relation("brute_force_to_successful_login", 40, 50)),
                       (ExpectedRisk(SUBJECT, "MEDIUM", "HIGH"),),
                       (ExpectedCase("CASE-BRUTE-SUCCESS-01", "MEDIUM", 2, 3),), 0,
                       "파일상 먼 성공이 먼저 나와도 10초 delta 선택", "가까움은 인과관계가 아님"),
    EvaluationScenario("ssh_unsupported", "SSH 지원하지 않는 문구", "ssh_unsupported.log", "ssh",
                       ExpectedParser(1, 1, 0, 0, (None,), None, utc(0), utc(0),
                                      (False,), (None,), (None,), ("parsed",)),
                       (), (), (), (), 0,
                       "timestamp는 파싱되나 event_type과 IP는 없음", "무시된 line으로 세지 않음",
                       "parser_only"),
    EvaluationScenario("ssh_malformed", "SSH 잘못된 timestamp", "ssh_malformed.log", "ssh",
                       ExpectedParser(1, 0, 0, 1, (), None, None, None,
                                      (), (), (), ("rejected",)),
                       (), (), (), (), 0,
                       "timestamp 변환에서 거부", "production analyze는 예외를 전파",
                       "parser_only"),
    EvaluationScenario("access_ignored", "웹 요청 필드 부족", "access_ignored.log", "access",
                       ExpectedParser(1, 0, 1, 0, (), None, None, None,
                                      (), (), (), ("ignored",)),
                       (), (), (), (), 0,
                       "request_parts 부족으로 None", "parse 예외와 구분",
                       "parser_only"),
    EvaluationScenario("app_malformed", "애플리케이션 timestamp 오류", "app_malformed.log", "application",
                       ExpectedParser(1, 0, 0, 1, (), None, None, None,
                                      (), (), (), ("rejected",)),
                       (), (), (), (), 0,
                       "timestamp 변환에서 거부", "production analyze는 예외를 전파",
                       "parser_only"),
    EvaluationScenario("normal_success_burst", "같은 IP의 여러 사용자 성공", "normal_success_burst.log", "application",
                       _parser(3, ("user_login",) * 3, 1), (), (),
                       (ExpectedRisk(SUBJECT, "LOW", "LOW"),), (), 0,
                       "인증 실패 없이 성공만 집중", "동일 IP는 같은 사람을 뜻하지 않음"),
    EvaluationScenario("normal_retry", "한 번 실패 뒤 정상 재시도", "normal_retry.log", "application",
                       _auth(2, 20, success=True), (),
                       (_relation("failed_to_successful_login", 0, 20),),
                       (ExpectedRisk(SUBJECT, "LOW", "MEDIUM"),),
                       (ExpectedCase("CASE-AUTH-TRANSITION-01", "LOW", 1, 2),), 0,
                       "탐지는 없지만 관계는 관찰", "정상 재시도와 구별할 승인 정보 없음"),
    EvaluationScenario("monitoring_success", "모니터링 계정 성공", "monitoring_success.log", "application",
                       _parser(1, ("user_login",), 0), (), (),
                       (ExpectedRisk(SUBJECT, "LOW", "LOW"),), (), 0,
                       "성공만 있는 합성 모니터링 활동", "계정명만으로 승인 여부 추정 불가"),
    EvaluationScenario("normal_web_burst", "정상 웹 query·404·500 혼합", "normal_web_burst.log", "access",
                       ExpectedParser(3, 3, 0, 0, ("http_request",) * 3, WEB_SUBJECT,
                                      utc(0), utc(1), (False,) * 3, ("GET",) * 3,
                                      (200, 404, 500), ("parsed",) * 3),
                       (), (), (ExpectedRisk(WEB_SUBJECT, "LOW", "LOW"),), (), 0,
                       "응답 상태와 점·percent만으로 traversal 아님", "HTTP 상태는 공격 성공 증거가 아님"),
    EvaluationScenario("automation_ambiguous", "승인 여부 모르는 자동화 실패", "automation_ambiguous.log", "application",
                       _auth(5, 40), _brute(), (),
                       (ExpectedRisk(SUBJECT, "MEDIUM", "HIGH"),), (), 1,
                       "현재 규칙상 Brute 관찰", "승인된 자동화인지 로그로 판단 불가",
                       "ambiguous_operational", "authorization_context_unavailable"),
    EvaluationScenario("ssh_whitespace", "SSH whitespace-only line", "ssh_whitespace.log", "ssh",
                       ExpectedParser(1, 0, 0, 1, (), None, None, None,
                                      (), (), (), ("rejected",)),
                       (), (), (), (), 0,
                       "timestamp token 부재로 예외", "loader/API 계층과 parser 계층을 구분",
                       "parser_only"),
    EvaluationScenario("access_empty", "access 빈 line", "access_empty.log", "access",
                       ExpectedParser(1, 0, 1, 0, (), None, None, None,
                                      (), (), (), ("ignored",)),
                       (), (), (), (), 0,
                       "access parser는 None 반환", "빈 파일 전체와 한 줄은 다름",
                       "parser_only"),
    EvaluationScenario("app_missing_ip", "application 필수 IP 누락", "app_missing_ip.log", "application",
                       ExpectedParser(1, 1, 0, 0, ("login_failed",), None, utc(0), utc(0),
                                      (True,), (None,), (None,), ("parsed",)),
                       (), (), (), (), 0,
                       "parser는 src_ip None event를 반환", "분석 grouping에서 attribution 불가",
                       "parser_only"),
    EvaluationScenario("ssh_extra_text", "SSH 허용 extra text", "ssh_extra_text.log", "ssh",
                       ExpectedParser(1, 1, 0, 0, ("user_login",), SUBJECT, utc(0), utc(0),
                                      (True,), (None,), (None,), ("parsed",)),
                       (), (), (), (), 0,
                       "지원 regex의 ssh2 뒤 추가 text", "자유형 상세는 public 평가 출력에 복사하지 않음",
                       "parser_only"),
    EvaluationScenario("ssh_invalid_ip", "SSH 비정상 IP 문자열", "ssh_invalid_ip.log", "ssh",
                       ExpectedParser(1, 1, 0, 0, ("login_failed",), "not-an-ip", utc(0), utc(0),
                                      (True,), (None,), (None,), ("parsed",)),
                       (), (), (), (), 0,
                       "현재 parser는 IP 형식을 검증하지 않음", "후속 adapter는 malformed subject를 거부",
                       "parser_only"),
)
