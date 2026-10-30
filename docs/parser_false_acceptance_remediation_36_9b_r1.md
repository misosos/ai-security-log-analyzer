# Phase 36.9B-R1 — Parser False Acceptance Remediation

## 1. 판정 범위

이 문서는 Phase 36.9B가 최초 기록한 세 가지 false acceptance를 수정하고 검증한 후속 기록이다. 최초 조사 결과와 `37 passed, 3 failed` 재현 이력은 [36.9B 호환성 보고서](supported_log_format_compatibility_36_9b.md)에 그대로 보존했다. 해당 문서의 최초 결과를 수정 후 결과로 덮어쓰지 않는다.

이번 수정은 기존 ISO-style Application/SSH 및 NCSA 유사 Access 입력 경계만 좁힌다. 새 로그 형식, detector, correlation, risk 기준은 추가하지 않았다.

## 2. 시작 Gate와 작업 트리

| 확인 | 결과 |
|---|---|
| 기준 SHA | `2ca0cea0f71d11ea7bafe6c1ce0ee077c812cd3e` |
| Exact Actions Run | [41005468167](https://github.com/misosos/ai-security-log-analyzer/actions/runs/41005468167) |
| Run 상태 | push / completed / success; 정확한 head SHA |
| Artifact | 0 |
| 필수 CI jobs | Locked Python 3.12, Linux process/SSH recovery, TCP Syslog, JSONL, restricted report, Chromium/axe, tracked-file invariant 성공 |
| Branch / HEAD / local main / origin main | `main`, 모두 기준 SHA |
| Ahead / behind | 0 / 0 |
| 시작 tree | 승인된 36.9B 미커밋 docs/index, 호환성 문서, 테스트, manifest 및 합성 fixture 21개만 존재 |
| v0.4.0 | tag 유지; Release target `eecd6ee1cda0545e34b01c42e1a2163a899bcc27` |

36.9B 작업 자산을 보존했다. 시작 전 focused 재실행 결과는 `37 passed, 3 failed`; 실패는 hostname-as-IP, wrong-process SSH phrase, status 999 assertion이었다.

## 3. 고정한 입력 계약

### Access source address

`NormalizedEvent.src_ip`에는 IPv4/IPv6 literal만 전달한다. hostname, 잘못된 주소, IP:port, 대괄호로 감싼 주소, zone ID가 붙은 IPv6는 주소 필드에 넣지 않는다. DNS 해석, 대체 주소, hostname hash, 실제 client identity 추정은 하지 않는다. 완전한 Access 행으로 인식된 뒤 주소가 유효하지 않으면 Parser가 입력 내용 없는 `ValueError`로 거부한다. 요청과 무관한 비 Access 문자열은 기존처럼 무시할 수 있다.

### SSH source process

인증 문구는 timestamp 바로 뒤에 있는 고정 process position과 결합되어야 한다. 허용된 기존 형태는 `sshd ...`, `sshd: ...`, 그리고 저장소의 realistic fixture에서 확인된 `HOST sshd[PID]: ...`이다. PID 형식에는 숫자 PID와 colon을 요구한다. `web-worker`, `fake-sshd`, `sshd-helper`, process 누락, 본문 중간에만 있는 sshd 문자열은 거부한다. RFC3164/5424 envelope 지원을 추가하지 않는다. OpenSSH auth phrase는 전체 라인 검색이 아닌 process 분리 후 메시지 시작 위치에서만 매칭한다.

### HTTP status

Access status token은 ASCII 십진 숫자 정확히 3자리이며 범위 100–599만 허용한다. 이는 숫자 범위 정책이며 각 코드가 IANA에 등록되어 있다는 주장은 아니다. 요청 line, 시간 및 IP address 형식도 함께 유효해야 한다.

## 4. 코드 변경과 처리 경계

- `app/parser/access_log.py`: `ipaddress.ip_address`로 literal을 검증하고 scoped IPv6를 거부한다. 검증은 timestamp/request/status/size가 갖춰진 Access record를 확인한 뒤 수행하여 무관한 문자열의 기존 ignored 처리를 유지한다. status/size는 request 직후의 정확한 token으로 읽으며 status range를 검사한다.
- `app/parser/ssh_auth.py`: timestamp 뒤의 process marker를 고정 패턴으로 추출하고, 허용된 `sshd` 형태만 처리한다. authentication regex는 message 시작점에서 매칭한다. 지원하지 않는 process/형식은 값 없는 `ValueError`로 거부하고, sshd의 비인증 이벤트는 기존대로 인증 이벤트를 만들지 않는다.
- `app/local_investigation_api.py`: `_compatible()`가 Access/SSH 실제 Parser를 호출해 preflight와 분석 Parser의 수용 판단을 공유한다. 기존 고정 `PARSER_INCOMPATIBLE` 오류, HTTP 상태, Multipart와 Text API 계약은 유지한다. Application preflight는 변경하지 않았다.
- `app/monitor_setup.py`: Parser가 지원하지 않는 source를 조기에 거부하므로, 다중 모니터 설정은 두 경로가 같은 파일인지 확인한 뒤 source별 내용을 미리 본다. 동일 파일 거부가 형식 미리보기 결과에 가려지지 않도록 오류 우선순위만 보존한다. 입력 검증·분석 의미는 바꾸지 않았다.
- 기존 `profiles.json`의 `expected` 세 값 `FALSE_ACCEPT`는 최초 관측 보존용이다. 수정 후 disposition은 추가한 `expected_after_r1: REJECTED`에 기록했다. 최초 기록과 현재 동작을 분리한다.

Loader는 기존 구분을 유지한다. Parser의 `None`은 ignored, 예상 가능한 `ValueError`는 live adapter에서 rejected outcome이 된다. Batch analysis는 Parser 예외를 정상 이벤트로 바꾸지 않는다. File/Text API는 staging 전 `_compatible()`에서 고정 오류 계약으로 거부한다. API 전체 구조나 loader 상태 회계는 바꾸지 않았다.

## 5. 수정 전후 결과

| Fixture/profile | 최초 36.9B | 수정 후 | 분석 영향 |
|---|---|---|---|
| `ACCESS-CLF-HOSTNAME` | hostname을 `src_ip`로 파싱, 결과 grouping key 도달 | `REJECTED` | event/group key 생성 안 됨; file/text API는 `PARSER_INCOMPATIBLE` |
| `SSH-NON-SSHD-PHRASE` | `web-worker` 문구가 `login_failed`, `application=sshd`로 파싱 | `REJECTED` | auth event 및 result key 생성 안 됨; file/text API는 `PARSER_INCOMPATIBLE` |
| `ACCESS-INVALID-STATUS` | 999 status의 `http_request` 파싱 | `REJECTED` | HTTP event 및 result key 생성 안 됨; file/text API는 `PARSER_INCOMPATIBLE` |

추가 경계 테스트는 IPv4/IPv6 literal 통과, hostname/잘못된 IPv4·IPv6/IP:port/bracket/IPv6 zone 거부, SSH process mismatch 및 PID delimiter 거부, status 99/099/000/600/999/non-numeric/empty 거부, 100/200/301/404/500/599 허용을 확인한다. 599 허용은 range acceptance만 뜻한다.

정상 SSH 회귀에는 Failed/Accepted password/publickey, invalid user, source port 유무, 기존 `sshd:` 및 `HOST sshd[PID]:` 합성 fixture가 포함된다. 정상 Access fixture의 IPv4/IPv6, request, query, status, size, timestamp 의미는 보존된다. Combined의 누락된 referer/User-Agent는 여전히 지원되지 않으며 Apache/Nginx 전체 호환성으로 승격하지 않는다.

## 6. API 및 live-path 검증

세 false-accept fixture 각각을 Parser, `analyze()` pipeline, text endpoint, 세 파일 multipart endpoint에서 검사했다. 직접 분석에서는 거부 예외가 이벤트 생성 전에 발생한다. text/file endpoint는 동일한 기존 `PARSER_INCOMPATIBLE` 공개 오류로 분석 전에 거부한다. 따라서 성공 사례나 독립 관찰로 변환되지 않는다.

Live parser adapter 테스트는 세 레코드 모두 `parsed=0`, `ignored=0`, `rejected=1`, event 없음임을 확인한다. 무관한 문자열의 기존 `IGNORED` 동작을 보존하도록 Access IP 검증은 완전한 Access 행 판별 뒤 실행한다.

새 HTTP privacy canary 전체 감사는 이 remediation 전용으로 확장하지 않았다. 기존 closed public projection 및 report regression을 전체 회귀에서 실행한다. Raw log는 NormalizedEvent 내부 `raw`에 계속 존재할 수 있으며 공개 결과에 넣지 않았다.

## 7. 테스트와 검증 결과

| 검증 | 상태 |
|---|---|
| 최초 compatibility RED 재현 | `37 passed, 3 failed` |
| Focused compatibility + Parser + live adapter + Text/File API | `220 passed, 2 upstream deprecation warnings` (first combined run) |
| Focused compatibility + Parser + live adapter + Text/File API + same-file setup regression | `221 passed, 2 upstream deprecation warnings` |
| Compatibility suite only | `77 passed, 2 upstream deprecation warnings` |
| `uv sync --locked --dev` | PASS; dependency 변경 없음 |
| `uv lock --check` | PASS; lockfile 변경 없음 |
| `uv run python -m app.evaluation` | PASS; synthetic boundary 79/79, parser 195/200 / unexpected parse 0 / unexpected rejection 0, risk 70/70, case 70/70, Linux process evaluation 21/21 |
| 관련 broad focused regression | `477 passed, 2 warnings`; 전체 실행에서 동일 파일 identity ordering 회귀를 별도 발견해 수정 |
| 전체 `uv run pytest -q` | `3249 passed, 2 upstream deprecation warnings` |
| `python3 -m compileall -q app tests` | PASS |
| `git diff --check` 및 신규 파일 whitespace | 최종 확인 PASS |
| `npm run test:a11y --silent` | PASS; 25 states, Axe violations 0, external requests 0; 본 로컬 Chromium 결과 |

기준 SHA의 Ubuntu/Linux CI와 이번 로컬 macOS 회귀는 서로 다른 증거다. 수정 후 Linux/Ubuntu CI는 새 SHA push 전에는 검증되지 않는다. Chromium/axe도 이번 단계에서 다시 실행하지 않았으므로 시작 SHA CI 증거만 유지한다.

## 8. 미지원 범위와 잔여 위험

- SSH RFC3164/5424 envelope, 임의 syslog 헤더, 다른 OpenSSH 배포판 형식은 미지원이다. Yearless RFC3164 timestamp는 `TIME_SEMANTICS_UNRESOLVED` 상태로 남는다.
- Apache CLF/Combined와 NGINX Combined는 일부 필드만 파싱한다. Apache hostname `%h` 입력은 이 계약에서 거부하며 hostname 별도 모델을 추가하지 않았다.
- Custom JSON, Apache/Nginx error logs, multiline event 조립은 미지원이다.
- Access IP literal이 실제 client인지, proxy/NAT address인지 알 수 없다. IP validation은 문법 확인만 한다.
- Text/file limits, shared limiter, worker timeout, private temp staging은 변경하지 않았다. OS-level hard memory ceiling이나 강제 종료 뒤 orphan cleanup/secure erase를 보장하지 않는다.
- 실제 운영 로그 호환성, 실제 환경 탐지 정확도는 `UNVERIFIED`다.

## 9. 판정

세 알려진 오해석은 합성 Parser/pipeline/API/live-path 테스트에서 거부됨을 확인했다. 전체 regression과 로컬 Chromium/axe를 통과했다. 판정은 **PHASE_36_9B_R1_PARSER_FALSE_ACCEPTANCE_LOCAL_CONDITIONAL_GO**이며, 새 commit의 Ubuntu CI는 push 전까지 확인되지 않았다. 이는 실제 Apache/NGINX/OpenSSH 배포 환경 호환성이나 조직 운영 승인이 아니다.

보안 경계: 실제 사용자 자료 `NO_GO`; 조직 운영 `NO_GO`; 자동 대응 `NO_GO`; 모델 AI `NOT_TESTED`; Safari/VoiceOver/실제 모바일 `NOT_TESTED`; Vector/VM `USER_ACTION_REQUIRED / ISOLATION_BLOCKED`; 기존 renderer `KEEP_LEGACY`.
