# Phase 36.9B-R2 — 로그 형식 호환성 종결 및 회귀 수용

## 1. Executive Summary

기준 SHA의 CI와 이번 로컬 합성 회귀를 확인했다. 21개 기존 compatibility fixture가 manifest에 정확히 연결되고, R1에서 고친 hostname-as-IP, SSH가 아닌 process의 인증 문구, HTTP status 999가 Parser·analysis pipeline·Text API·File API·Live parser adapter 경로에서 재현되지 않았다. 지원 문법의 제한과 부분 해석 범위를 유지한다.

판정: **`PHASE_36_9B_R2_COMPATIBILITY_CLOSURE_LOCAL_CONDITIONAL_GO`**. 이는 알려진 세 문제의 closure를 이 문서가 명시한 합성 corpus, 코드 경로 및 로컬/기준 CI 범위에서 인정한다는 뜻이다. 모든 Apache/NGINX/OpenSSH 변형, collector wire 경로별 세 악성 후보의 별도 E2E, 실제 운영 로그 호환성은 승인하지 않는다.

## 2. 시작 Gate

| 확인 | 결과 |
|---|---|
| 기준 SHA | `64711380dde1df4bd78f1a2b9a90311272ddc6db` |
| Branch / HEAD / local main / origin/main / GitHub main | `main`; 모두 기준 SHA |
| Ahead / behind | `0 / 0` |
| Working tree | clean |
| Exact Actions Run | [41011075325](https://github.com/misosos/ai-security-log-analyzer/actions/runs/41011075325), head SHA 일치 |
| Event / status / conclusion | `push / completed / success` (2026-10-30 05:59:51 UTC 완료) |
| Artifact | 0 |
| 필수 CI | Locked Python 3.12 regression, Linux process/SSH recovery, 전체 regression, TCP Syslog Linux, JSONL runtime Linux, restricted report, Chromium/axe, tracked-file invariant 모두 성공 |
| v0.4.0 | tag object `855a92827a605805b62c627ed719958620150ec4`, peeled target 및 Release target `eecd6ee1cda0545e34b01c42e1a2163a899bcc27` |

CI 결과는 시작 기준 SHA의 GitHub 증거다. 이번 R2 문서는 새 로컬 커밋에 대한 CI 성공을 주장하지 않는다.

## 3. 기존 36.9B HOLD 이력

Phase 36.9B는 최초 `PHASE_36_9B_UNSAFE_ACCEPTANCE_HOLD`였다. 합성 corpus 21개에서 `37 passed, 3 failed`를 기록했고, hostname `%h`를 source IP로 취급, 비-`sshd` 인증 유사 문구 수용, status 999 수용을 각각 `FALSE_ACCEPT`로 보존했다. 당시 전체 결과는 `3 failed, 3209 passed`였다. 최초 기록은 [36.9B 원본 보고서](supported_log_format_compatibility_36_9b.md)에 남아 있으며 이 문서로 대체하지 않는다.

R1은 최소 Parser/preflight 경계 수정 후 `PHASE_36_9B_R1_PARSER_FALSE_ACCEPTANCE_LOCAL_CONDITIONAL_GO`를 기록했다. 최초 `expected: FALSE_ACCEPT`는 manifest에서 유지되고, 수정 후 `expected_after_r1: REJECTED`가 별도로 기록돼 있다. R1 당시 결과는 Compatibility 77, 관련 focused 221, 전체 `3249 passed, 2 warnings`, synthetic boundary 79/79, Linux process consistency 21/21이었다. 이들은 R2 결과와 별개의 과거 증거다. 자세한 변경은 [R1 remediation 기록](parser_false_acceptance_remediation_36_9b_r1.md)을 참조한다.

## 4. 검증 환경과 실행 결과

| 검증 | R2 실행 결과 |
|---|---|
| `uv sync --locked --dev` 및 `uv lock --check` | 성공; lockfile 변경 없음 |
| 시작 기준선 `uv run pytest -q` | `3249 passed, 2 warnings` (107.01초) |
| Compatibility + Parser + Text/File API + Live adapter + TCP Syslog + JSONL + Correlation/Risk + Case/Checklist/Report + Linux Audit focused 묶음 | `609 passed, 2 warnings` (28.77초) |
| `uv run python -m app.evaluation` | 성공: boundary 79/79; parser 195/200, ignored 2, rejected 3, unexpected parse 0, unexpected rejection 0; risk 70/70; case 70/70; Linux process 21/21 |
| `python3 -m compileall -q app tests` | 성공 |
| `npm run test:a11y --silent` | 성공; Chromium 출력에 외부 요청 0, 주요 반응형 레이아웃의 overflow/clipping 및 target 크기/간격 위반 0; 320px 및 200% equivalent 검사 포함 |

Evaluation에 출력된 작은 합성 표본의 precision/recall 값은 fixture 라벨에 대한 결과일 뿐, 실제 운영환경 정확도 지표가 아니다. Safari, VoiceOver, 실제 모바일 기기는 `NOT_TESTED`다. 시작 SHA의 Linux CI와 로컬 macOS 검증을 서로 대체하지 않는다.

## 5. Corpus 무결성

읽기 전용 검증 결과:

- `profiles.json`의 profile 21개, 고유 ID 21개, 고유 fixture 경로 21개.
- Fixture 파일 21개이며 manifest 참조와 정확히 일치한다. 누락·미참조 fixture 없음.
- 모든 경로 `sample_logs/compatibility/` 아래로 resolve되고 파일이며 symlink가 아니다.
- 모든 profile에 timestamp/disposition 설명이 있고, 공식 근거는 해당 형식 문서 및 [호환성 원본 보고서](supported_log_format_compatibility_36_9b.md)에 연결된다.
- 최초 `FALSE_ACCEPT` 3개와 수정 후 `REJECTED` 3개 기록이 함께 보존됐다.
- fixture는 저장소에서 직접 만든 합성 문자열이며 문서용 주소 대역을 사용한다. 실제 사용자·조직 로그는 사용하지 않았다.
- Replay 테스트는 fixture를 읽기만 한다. 이 Phase에서 corpus/manifest/test를 수정하지 않았다.

## 6. Profile별 Compatibility Matrix

`실행 disposition`은 수정 후 실제 Parser 관측이다. `PARSED_PARTIAL`은 Parser가 이벤트를 만들었다는 뜻이며 profile 전체 필드/설정 호환을 뜻하지 않는다.

| Profile / fixture | 기존 기대 또는 최초 상태 | 실행 disposition | 관측 필드 / 제한 |
|---|---|---|---|
| `APP-AUTH-01` | `SUPPORTED_VERIFIED` | `SUPPORTED_VERIFIED` | `login_failed`, analyst, 192.0.2.11, failure; Asia/Seoul naive timestamp → UTC |
| `APP-AUTH-SUCCESS` | `SUPPORTED_VERIFIED` | `SUPPORTED_VERIFIED` | `user_login`, reviewer, 192.0.2.13, success |
| `SSH-NORM-01` | `SUPPORTED_VERIFIED` | `SUPPORTED_VERIFIED` | ISO-style, `sshd`, Failed password, user/IP/outcome/method/source port |
| `SSH-NORM-NO-PORT` | `PARSED_PARTIAL` | `PARSED_PARTIAL` | Accepted publickey와 user/IP/outcome; port는 `None`으로 유지 |
| `SSH-NON-SSHD-PHRASE` | 최초 `FALSE_ACCEPT` | `REJECTED` (`expected_after_r1`) | `web-worker`의 auth phrase는 이벤트를 만들지 않음 |
| `SSH-NORM-INVALID-USER-PUBKEY` | `SUPPORTED_VERIFIED` | `SUPPORTED_VERIFIED` | invalid user, publickey 실패, IPv6, port 및 관측된 invalid-user flag |
| `SSH-SYSLOG-3164` | `REJECTED` | `REJECTED` | 연도·timezone 없는 BSD envelope; 시간 의미 unresolved |
| `SSH-SYSLOG-5424` | `REJECTED` | `REJECTED` | RFC5424 envelope 전체 지원 아님 |
| `ACCESS-APACHE-CLF-IP-SUBSET` | `PARSED_PARTIAL` | `PARSED_PARTIAL` | IPv4, offset timestamp, method/path/query/status/size; `%l/%u` 미보존 |
| `ACCESS-APACHE-COMBINED` | `PARSED_PARTIAL` | `PARSED_PARTIAL` | HTTP core 파싱; Referer/User-Agent 및 remote user 미보존 |
| `ACCESS-NGINX-COMBINED` | `PARSED_PARTIAL` | `PARSED_PARTIAL` | HTTP core 파싱; 설정별 형식 및 부가 필드 전반 지원 아님 |
| `ACCESS-IPV6-SIZE-DASH` | `PARSED_PARTIAL` | `PARSED_PARTIAL` | IPv6, path/status; `-` response size는 `None` |
| `ACCESS-INVALID-STATUS` | 최초 `FALSE_ACCEPT` | `REJECTED` (`expected_after_r1`) | 999가 HTTP event를 만들지 않음 |
| `ACCESS-CLF-HOSTNAME` | 최초 `FALSE_ACCEPT` | `REJECTED` (`expected_after_r1`) | hostname을 `src_ip`로 만들지 않음 |
| `ACCESS-INVALID-DATE` | `REJECTED` | `REJECTED` | 잘못된 calendar date 거부 |
| `ACCESS-INVALID-OFFSET` | `REJECTED` | `REJECTED` | 잘못된 numeric offset 거부 |
| `ACCESS-MISSING-REQUEST-PARTS` | `IGNORED` | `IGNORED` | 세 구성요소 request line이 아니므로 event 없음 |
| `ACCESS-CUSTOM-JSON` | `IGNORED` | `IGNORED` | 자동 JSON detection/변환 없음 |
| `ACCESS-APACHE-ERROR` | `REJECTED` | `REJECTED` | Apache error 문법은 Access parser 대상 아님 |
| `ACCESS-NGINX-ERROR` | `REJECTED` | `REJECTED` | NGINX error 문법은 Access parser 대상 아님 |
| `SSH-MULTILINE` | `PARSED_PARTIAL` | `PARSED_PARTIAL` | 첫 timestamp 행만 인증 event, continuation은 reject; multiline 조립 미지원 |

## 7. 세 FALSE_ACCEPT Closure Matrix

각 경로의 근거를 분리했다. Pipeline은 잘못된 input의 batch `analyze()`가 `ValueError`로 끝나고 정상 결과 key로 변환되지 않는지 확인한다. HTTP API는 고정 `PARSER_INCOMPATIBLE`와 원문 미반향을 별도로 검사한다.

| Finding | Parser | Pipeline | Text API | File API | Live parser adapter | Closure |
|---|---|---|---|---|---|---|
| Hostname-as-IP | `test_hostname_clf_is_not_misrepresented_as_source_ip`, `test_access_rejects_non_literal_or_decorated_source_addresses` — `REJECTED` | `test_false_accept_fixtures_are_stopped_before_analysis_result_keys` — 거부, group/result key 없음 | `test_text_api_rejects_false_accept_fixtures_before_analysis` — HTTP 400 `PARSER_INCOMPATIBLE` | `test_file_api_rejects_false_accept_fixtures_before_analysis` — HTTP 400 및 field mapping | `test_live_parser_reports_false_accept_fixtures_as_rejected_records` — rejected 1, event 없음 | `VERIFIED` (위 직접 경로 한정) |
| Wrong SSH Process | `test_non_sshd_authentication_phrase_is_not_misclassified_as_ssh`, `test_ssh_authentication_phrase_requires_supported_sshd_process`, `test_ssh_process_marker_in_message_body_does_not_authorize_event` | `test_false_accept_fixtures_are_stopped_before_analysis_result_keys` — 거부, auth/result key 없음 | 동일 Text API parametrized test — HTTP 400 `PARSER_INCOMPATIBLE` | 동일 File API parametrized test — HTTP 400 `PARSER_INCOMPATIBLE` | 동일 Live adapter test — rejected 1, event 없음 | `VERIFIED` (위 직접 경로 한정) |
| Invalid status 999 | `test_invalid_http_status_is_not_admitted_as_normalized_request`, `test_access_status_is_three_digits_in_100_to_599_range` | `test_false_accept_fixtures_are_stopped_before_analysis_result_keys` — 거부, HTTP observation/result key 없음 | 동일 Text API parametrized test — HTTP 400 `PARSER_INCOMPATIBLE` | 동일 File API parametrized test — HTTP 400 `PARSER_INCOMPATIBLE` | 동일 Live adapter test — rejected 1, event 없음 | `VERIFIED` (위 직접 경로 한정) |

주소 검사는 Python `ipaddress` literal 검증을 사용한다. DNS, 대체 IP, hostname hash는 없다. SSH는 timestamp 이후 정해진 process marker에서 허용된 `sshd`만 분리하고 인증 phrase를 메시지 시작에서 검사한다. Access status는 정확한 세 자리 ASCII decimal과 100–599 범위를 요구한다. 599는 범위상 수용이며 등록된 표준 상태 코드라는 의미를 추가하지 않는다.

### Live/Collector 경계

False acceptance용 Live 증거는 `parse_live_records()` adapter에 같은 corpus fixture를 직접 전달한 테스트다. 이는 공통 live parsing 단계가 rejected count 1/event 0을 내는 것을 확인한다. Local file monitor의 실제 checkpoint lifecycle에 각 세 fixture를 주입한 전용 테스트는 이번 실행에 없다(`UNVERIFIED`). TCP Syslog 및 JSONL은 별도 runtime/Linux CI 검증이 성공했지만, 해당 wire protocol을 통해 세 fixture 각각을 투입한 개별 adversarial E2E는 이 corpus 테스트가 아니다(`UNVERIFIED`). 두 collector는 source/wire 제한을 유지하며, 이 문서는 그 별도 fixture 검증을 했다고 주장하지 않는다. 기존 compatibility corpus에서 `access` 지원을 collector source 범위로 확대하지 않는다.

## 8. Timestamp 및 Observable Evidence 검증

Compatibility 테스트는 Application/SSH의 naive `2026-10-30 09:00:00`을 registry의 `Asia/Seoul`로 붙여 `2026-10-30T00:00:00Z`로 비교한다. Access는 explicit offset을 사용하며 `+0000`/`+0900` 동일 순간, day/month/year rollover를 UTC-aware 비교로 검사한다. 잘못된 날짜와 offset은 거부된다. RFC3164 year/zone 부재는 `TIME_SEMANTICS_UNRESOLVED`로 유지되며 연도·timezone/DST 추정이 없다.

| 관측 | NormalizedEvent 결과 확인 |
|---|---|
| 시각 | timezone-aware `timestamp`, UTC normalization 비교 |
| SSH 인증 결과/계정/IP/method/port | `event_type`, `authentication.outcome`, `user`, `src_ip`, `authentication.method`, 선택적 `source_port` |
| HTTP 요청 | `event_type=http_request`, `src_ip`, `http.method/path/query/status_code/response_size` |
| 누락 정보 | SSH port 없음은 `None`; access size `-`는 `None`; Referer/User-Agent는 모델에 반영되지 않음 |

`src_ip`는 관측 IP literal이지 공격자 신원, NAT 뒤 사용자, reverse proxy 뒤 실제 클라이언트의 증명이 아니다. 인증 성공은 침해 증거가 아니며 HTTP status 200도 exploit 성공을 입증하지 않는다. `raw`는 내부 NormalizedEvent에 남을 수 있으나 공개 projection과 report로 노출하지 않는다.

## 9. Parser / API 일관성

`app/local_investigation_api.py::_compatible()`는 SSH/Access에서 실제 parser를 호출하고, API staging 전 같은 실패 의미를 적용한다. `test_upload_and_text_preflight_match_parser_acceptance_for_changed_profiles`는 허용 SSH/Access와 세 invalid 사례의 preflight 결과를 직접 비교한다. 두 API의 별도 parametrized tests는 실패가 고정 `PARSER_INCOMPATIBLE`로 매핑되고 원문이 응답에 들어가지 않는지 확인한다.

Application은 `_compatible()`에서 timestamp와 최소 token 수만 검사하며, Parser는 level/event 및 key=value token을 읽는다. 이를 모든 외부 Application 형식의 의미 검증으로 해석하지 않는다. 이번 R2에서 이 기존 차이를 변경하지 않았다. 잘못된 timestamp/짧은 레코드는 preflight에서 거부되지만, 형식에 맞는 임의 event 이름의 전체 의미/제품별 지원은 별도 계약이 아니다.

## 10. Live / Collector와 downstream 회귀

`test_live_parser_reports_false_accept_fixtures_as_rejected_records`는 세 후보를 각기 Live adapter에 전달해 `parsed_count=0`, `ignored_count=0`, `rejected_count=1`, event 없음으로 확인한다. 기존 live parser adapter/equivalence/privacy 테스트도 focused regression에 포함됐다. 시작 Run에서는 Linux process/SSH recovery, TCP Syslog/Linux, JSONL runtime/Linux 검사가 모두 성공했다. R2 로컬 focused 묶음은 `tests/test_tcp_syslog_runtime_34_2.py`와 `tests/test_collector_jsonl_runtime_35_3.py`를 포함한다.

기존 loader의 처리 구분은 유지된다: parser `None`은 ignored, 예상된 `ValueError`는 live adapter에서 rejected, batch analysis의 parser 예외는 정상 이벤트로 바뀌지 않는다. 잘못된 fixture가 Detector/Correlation/Risk/Case에 들어가지 않는 것은 각 fixture의 `analyze()` 거부와 빈 grouping assertion으로 확인한다. 정상 동작 회귀는 evaluation의 boundary/parser/risk/case/Linux process 기준과 `test_parser.py`, correlation, risk, case projection, checklist 및 report 회귀를 통해 확인했다. Detector/Correlation/Risk 코드 또는 의미 변경은 없다.

## 11. Privacy / Security

이번 검증은 synthetic fixture만 사용했다. Text/File API 거부 테스트는 raw input을 오류 응답에 반향하지 않고, R1/기존 privacy tests는 공개 projection/report/logging 경계와 private staging 정책을 검사한다. R2 focused 묶음에서 Text/File API, HTML/restricted report, live privacy, Linux Audit isolation 테스트를 실행했다. 일반 공개 결과에 원문 추가는 없고 API/schema 변경도 없다.

R1에서 유지된 resource 경계: Text 32 KiB, JSON wire 96 KiB, 한 줄 2048 bytes, 512줄, worker timeout 10초, app 인스턴스 내부 공유 limiter, 임시 directory `0700`, file `0600`. 이 Phase에서 변경하지 않았다. OS-level hard memory/CPU cap, 강제 종료 후 orphan cleanup, secure erase는 보장하지 않는다. 외부 사용자 자료/조직 운영/자동 대응은 계속 `NO_GO`다.

## 12. 지원 범위 확정

### 안전하게 검증된 제한 형식

- **Application 내부 인증 subset:** `YYYY-MM-DD HH:MM:SS LEVEL EVENT key=value ...`; 현재 합성 계약의 `login_failed`/`user_login`에서 user와 `ip` key가 제공되면 관측하고, naive 시각은 registry `Asia/Seoul`로 해석한다. 외부 제품 로그 표준이 아니다.
- **ISO-style SSH subset:** `YYYY-MM-DD HH:MM:SS` 뒤 허용된 정확한 `sshd` marker와 지원된 Failed/Accepted password/publickey 문구; user, `from` IP, method, 제공된 port만 관측한다. timezone은 caller registry의 Asia/Seoul이다. ISO timestamp 형태를 가진 프로젝트 subset이며 실제 syslog envelope가 아니다.
- **Access HTTP core subset:** NCSA형 IP literal + `[day/Mon/year:HH:MM:SS ±ZZZZ]` + 3요소 quoted request + 100–599 status + bytes 또는 `-`. IPv4/IPv6와 URL path/query core가 검증됐다. Apache/Nginx 제품 전체 형식이라고 주장하지 않는다.

### 부분 지원

Apache CLF/Combined, NGINX combined 및 no-port SSH는 `PARSED_PARTIAL`이다. Apache `%l/%u`, remote user, Referer, User-Agent 등 필드가 손실되며 arbitrary `LogFormat`/`log_format`, escaping 및 setting을 지원한다고 볼 수 없다. 정상 Access subset도 IPv4/IPv6 literal만 받으므로 Apache `%h` hostname variant는 거부된다.

### 미지원 또는 거부

RFC3164 SSH envelope (연도/timezone 추정 불가), RFC5424 SSH envelope parser, Custom JSON Access 자동 감지/변환, Apache/NGINX error log, multiline event assembly, 지원하지 않는 SSH process 형식은 미지원이다. 일부 행은 parser 예외 대신 `None`/ignored일 수 있으므로 호출 경로별 rejection 의미를 유지해야 한다.

## 13. 잔여 위험 및 미검증

1. 지원 Profile은 저장소의 21개 직접 작성 fixture로 제한된다. 다양한 daemon 버전, 설정, locale, proxy topology, encoding, rotation, out-of-order/duplicate 및 실제 운영 로그는 검증되지 않았다.
2. TCP Syslog와 JSONL/Linux runtime의 기준 CI는 성공했지만, 각 collector wire 경로에 세 false-accept fixture를 직접 실은 전용 적대 E2E는 없다.
3. Local file monitoring의 false-accept 세 fixture별 checkpoint/recovery 수용 테스트는 별도 실행하지 않았다.
4. CLF/Combined 부가 필드 누락은 의도된 partial disposition이며 보완된 지원이 아니다.
5. Naive Application/SSH timestamps의 Asia/Seoul 해석은 현재 계약이다. 다른 producer timezone에서는 잘못된 시점이 될 수 있으며 자동 감지하지 않는다.
6. 합성 탐지 수치는 실제 precision/recall 일반화, 실제 환경 정확도 또는 운영 승인이 아니다.
7. 모델 기반 AI `NOT_TESTED`; Safari/VoiceOver/실제 모바일 `NOT_TESTED`; Vector/VM `USER_ACTION_REQUIRED / ISOLATION_BLOCKED`; hard OS resource cap 및 secure erase 미보장; Renderer `KEEP_LEGACY`.

## 14. 전체 pytest 및 회귀 결과

시작 시 동일 SHA에서 실행한 전체 baseline은 `3249 passed, 2 warnings`였고, 문서 반영 후 최종 `uv run pytest -q`도 `3249 passed, 2 warnings` (92.15초)였다. Production/test 코드 및 corpus 변경은 없었다. focused 결과 `609 passed, 2 warnings`, evaluation 결과와 Chromium/axe 결과는 §4의 해당 실행 기록이다. 이들은 R2 로컬 실행이다. GitHub Linux CI 결과는 §2의 시작 SHA Run에서 온 별도 증거다.

## 15. 기존 36.9B HOLD 및 Phase 36.9C 진입 Gate

세 기존 `FALSE_ACCEPT`는 R1 수정 이후 이 문서의 Parser, batch pipeline, Text API, File API 및 Live parser adapter 검사에서 다시 관측되지 않았다. 정상 합성 Evaluation 기준도 유지됐다. 따라서 기존 36.9B의 알려진 세 문제에 대한 `UNSAFE_ACCEPTANCE_HOLD`는 **제한된 synthetic corpus 범위에서 해소 가능**하다고 판정한다. 이는 21개 corpus가 모든 변형을 증명한다는 뜻은 아니며 §13의 미검증 항목은 유지한다.

Phase 36.9C는 이 로컬 판정만으로 시작하지 않는다. 우선 이 문서 커밋을 push한 후 새 SHA에 대한 exact GitHub CI success와 artifact 0개를 확인해야 한다. 또한 compatibility Profile 경계를 유지하고 parser/detector baseline을 보존해야 한다. 조건 충족 후 **Phase 36.9C — Detector Accuracy & False Positive/Negative Evaluation**을 별도 시작할 수 있다.

## 16. 최종 판정

**`PHASE_36_9B_R2_COMPATIBILITY_CLOSURE_LOCAL_CONDITIONAL_GO`** — R1의 알려진 세 오해석은 정의된 합성 검증 범위에서 closure 됐고 기존 정상 분석 기준에 회귀가 관측되지 않았다. 실무 형식 전체 호환성, collector별 적대 입력 E2E, 실제 운영환경 정확도는 승인하지 않는다.
