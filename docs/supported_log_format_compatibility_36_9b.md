# Phase 36.9B — Supported Log Format Compatibility Profiles

## 1. Phase 목적

이 문서는 Parser가 어떤 문법과 필드를 실제로 처리하는지 합성 fixture로 측정한 기록이다. 문자열이 파싱되거나 예외가 없었다는 사실만으로 형식 전체가 지원된다고 보지 않는다. 파싱 결과의 필드 의미, 시간대 변환, 기존 분석 파이프라인 유입을 각각 확인한다.

이번 Phase에서는 Parser/Detector/Correlation/Risk/API/UI를 수정하지 않았다. 검증 테스트가 발견한 false acceptance를 숨기지 않고 기록한다. 확인된 입력 의미 오류가 분석 결과를 왜곡할 수 있어 최종 상태는 **PHASE_36_9B_UNSAFE_ACCEPTANCE_HOLD**다. 이 문서는 후속 수정 승인을 대신하지 않는다.

## 2. 시작 Gate

| Gate | 결과 |
|---|---|
| 기준 커밋 | 2ca0cea0f71d11ea7bafe6c1ce0ee077c812cd3e |
| Branch/HEAD/local main/origin main/GitHub main | main; 모두 기준 SHA |
| ahead/behind | 0/0 |
| 시작 Working tree | clean |
| Actions Run | [41005468167](https://github.com/misosos/ai-security-log-analyzer/actions/runs/41005468167), head SHA 일치 |
| Event/status/conclusion | push / completed / success |
| Artifact | 0 |
| 필수 CI | locked Python 3.12 regression, Linux process/SSH recovery, TCP Syslog, JSONL, restricted report, Chromium/axe, tracked-file invariant 모두 success |
| v0.4.0 tag/Release target | eecd6ee1cda0545e34b01c42e1a2163a899bcc27 |

CI 증거는 위 기준 SHA의 GitHub Actions만 가리킨다. 새 테스트를 추가한 현 작업 트리의 CI 결과가 아니다.

## 3. 공식 출처 및 버전

문서 확인일은 2026-10-30이다. vendor 문서는 형식 정의 근거로 사용했고, 현재 parser 지원 여부는 별도로 실행해 판단했다.

| 출처 | 제품/버전·날짜 | 형식/근거 필드 | 현재 Parser와의 차이 |
|---|---|---|---|
| [Apache HTTP Server Log Files](https://httpd.apache.org/docs/2.4/logs.html) | Apache HTTP Server 2.4 문서, 확인 2026-10-30 | CLF 예시 %h %l %u %t "%r" %>s %b; %h remote host/address, %u remote ident user, timezone offset 있는 bracket timestamp, request/status/response bytes. Combined는 Referer/User-Agent 추가 | parser는 유사한 core token을 읽지만 %l/%u/Referer/User-Agent를 정규화하지 않는다. %h가 hostname일 수 있고 proxy 주소일 수 있다는 문서 경고가 src_ip 오매핑 테스트 근거다. |
| [Apache mod_log_config](https://httpd.apache.org/docs/2.4/mod/mod_log_config.html) | Apache HTTP Server 2.4, 확인 2026-10-30 | LogFormat/CustomLog는 directives로 필드를 선택·배열할 수 있음. CLF/Combined는 명시된 format string | 동일한 제품이라도 arbitrary CustomLog를 고정 CLF parser가 지원하지 않는다. |
| [NGINX ngx_http_log_module](https://nginx.org/en/docs/http/ngx_http_log_module.html) | NGINX 공식 문서(현재 문서 버전 표기 없음), 확인 2026-10-30 | built-in combined: $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"; Custom log_format, escape default/json/none | core textual layout sample은 읽히지만 referer/agent/remote_user는 모델에 반영되지 않는다. custom JSON/escaping이 같은 parser 계약은 아니다. |
| [RFC 3164](https://datatracker.ietf.org/doc/html/rfc3164) | Informational RFC, 2001-08 | PRI, TIMESTAMP, HOSTNAME, MSG 구조. BSD TIMESTAMP는 연도·zone을 제공하지 않는 형식 | parser는 입력의 첫 두 token을 ISO %Y-%m-%d %H:%M:%S로 고정 파싱한다. year/timezone을 임의로 채우지 않아 RFC3164 envelope를 거부한다. |
| [RFC 5424](https://www.rfc-editor.org/rfc/rfc5424.html) | Standards Track RFC, 2009-03 | PRI VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA [MSG]; timestamp는 RFC3339 derived, offset 포함 또는 NILVALUE | parser는 envelope parser가 아니다. 5424 timestamp가 명시돼도 첫 두 token이 ISO local date/time 문법이 아니므로 거부된다. |
| [OpenSSH portable auth.c](https://github.com/openssh/openssh-portable/blob/master/auth.c) | upstream portable source master, 확인 2026-10-30; release tag 고정 아님 | auth_log는 Accepted/Failed, method, user 또는 invalid user, remote IP, port, ssh2, optional method information을 syslog message로 전달 | 이는 OpenSSH authentication message의 1차 코드 근거이지 전체 syslog envelope 규격이 아니다. distro syslog가 붙이는 timestamp/hostname/PID 형식은 별도다. 특정 배포판·버전을 고정한 증거는 UNVERIFIED. |
| [RFC 9110 §15](https://www.rfc-editor.org/rfc/rfc9110.html#section-15) | HTTP Semantics, 2022-06 | HTTP status는 3자리이며 valid range는 100–599 | parser는 숫자를 읽지만 range를 검증하지 않는다. 합성 999의 false acceptance 기준이다. |

RFC 번호가 있다는 사실만으로 parser의 해당 envelope 지원을 의미하지 않는다. OpenSSH auth message는 RFC 3164/5424 header와 별개다.

## 4. 현재 Parser 구조

- app/parser/auth_log.py: 첫 두 공백 token을 %Y-%m-%d %H:%M:%S로 파싱하고, 전달받은 timezone이 있으면 naive datetime에 ZoneInfo를 부착한다. 나머지 token을 key=value로 나눈다. login_failed와 user_login만 authentication outcome을 만든다.
- app/parser/ssh_auth.py: 첫 두 token을 같은 ISO-style로 파싱한 뒤 전체 원문에서 authentication regex를 search한다. regex는 Failed|Accepted, password|publickey, user, from 값 및 선택적인 port/ssh2 suffix를 찾는다. sshd 프로그램 token이 실제 존재하는지 확인하지 않는다.
- app/parser/access_log.py: 첫 token을 src_ip로 그대로 복사하고 bracket text를 고정 Access timestamp로 파싱한다. 첫 quote pair의 request를 세 토큰으로 나눈다. 정규식으로 status와 size를 찾고 urlsplit으로 path/query를 나눈다. IP address 형식 및 HTTP status range 검증은 하지 않는다.
- app/parser/registry.py: application/ssh에 Asia/Seoul, access에는 parser timezone None을 준다.
- app/parser/time_utils.py: timezone-aware datetime만 UTC로 변환한다.
- app/loader/file_loader.py: UTF-8 text를 line 단위로 읽고 양 끝 공백을 제거하며 빈 줄은 건너뛴다. 여러 줄 이벤트를 합치지 않는다.

### 입력 경로 연결

| 경로 | Parser 전 변환/검증 | Parser 연결 |
|---|---|---|
| 기존 세 파일 upload | local API가 source별 UTF-8/control/size/line 및 일부 format 검사 후 private staging; 원문 문법을 자동변환하지 않음 | 기존 pipeline의 source별 parser |
| Text API | closed JSON/source allowlist와 동일한 text limits, staging; format auto-detection/변환 없음 | 동일 pipeline |
| Local file monitoring | line preprocessing/sequence 및 record guard; source role을 config에서 지정 | parse_live_records가 같은 registry parser와 timezone 사용, UTC 변환 |
| TCP Syslog | bounded framing/queue에서 payload frame 분리; loopback pilot, source role application/ssh만 | runtime의 live record adapter가 같은 parser를 호출 |
| JSONL collector | closed collector envelope 검증 후 payload를 queue에 둠; JSONL envelope 자체가 application log schema를 뜻하지 않음 | JSONL runtime이 payload line을 live parser adapter로 보냄 |
| Linux Audit | 별도 parser/model/API 경로 | 세 text parser와 다른 계약; 이번 corpus 입력 경로에 연결하지 않음 |

source 선택·collector framing은 Application/SSH 내부 로그 문법을 바꾸지 않는다. 각 경로의 parser timezone 및 rejection semantics는 해당 adapter 테스트와 함께 유지해야 한다.

## 5. 로그 형식 Profile 목록

profiles.json은 ID, source, fixture path, expected disposition, timestamp semantics를 제한적으로 고정한다. 아래 각 형식은 정확한 input grammar와 현재 관측 범위를 함께 정의한다. expected=FALSE_ACCEPT는 올바른 동작 기대가 아니라 발견된 오류 분류다.

## 6. Application Profile

### APP-AUTH-01

- 문법: YYYY-MM-DD HH:MM:SS LEVEL EVENT key=value ...
- 근거: 프로젝트 내부 Application 인증 로그 계약 및 기존 합성 fixtures. 외부 제품 표준이라고 주장하지 않는다.
- 시간: timezone 없는 datetime을 registry의 Asia/Seoul로 부착 후 UTC 변환. 2026-10-30 09:00:00 → 2026-10-30T00:00:00Z.
- 필수/추출: timestamp, level token, event token. user, ip, service 등은 key=value인 경우에만 얻는다. event가 login_failed이면 failure, user_login이면 success; method는 제공되지 않아 None.
- 선택/미보존: 임의 extra key는 NormalizedEvent에 일반 metadata map으로 보존하지 않는다. user=, ip= 자체가 없으면 값은 None.
- 판정: 고정된 기존 synthetic profile에 대해 SUPPORTED_VERIFIED. 임의 Application 제품 log/JSON/stack trace 지원이 아니다.

## 7. SSH Profile

### SSH-NORM-01

- 문법: YYYY-MM-DD HH:MM:SS [intervening tokens] (Failed|Accepted) (password|publickey) for [invalid user ]USER from ADDRESS [port INTEGER ssh2[: detail]]. Code는 AUTHENTICATION_MESSAGE.search를 사용하므로 process label을 강제하지 않으며, 실제 지원 범위가 이보다 넓게 오인식될 수 있다.
- 시간: timestamp 첫 두 token, registry Asia/Seoul, UTC 변환. Year와 local zone 가정은 caller가 제공한다.
- 필드: outcome→event type/authentication outcome, method, user, from 값→src_ip, 선택적인 source_port. invalid_user는 source_port가 있을 때만 Boolean으로 정해진다.
- OpenSSH 근거 차이: upstream auth.c는 sshd auth message format의 source다. 정식 실제 syslog line에는 syslog implementation이 timestamp/hostname/process/PID envelope를 붙인다. 현재 fixture는 ISO timestamp로 envelope를 바꾼 프로젝트 형식이지 OpenSSH 원본 syslog profile이 아니다.
- 판정: 기존 ISO-style synthetic 실패·성공, publickey, invalid-user fixture 중 검증된 하위집합은 SUPPORTED_VERIFIED; port 없는 경우 PARSED_PARTIAL.

### SSH-SYSLOG-3164

- 문법 후보: Mmm dd hh:mm:ss HOSTNAME sshd[PID]: AUTH-MESSAGE; RFC3164 timestamp에 year/timezone이 없음.
- 판정: 현재 parser가 첫 두 token을 ISO timestamp로 요구해 REJECTED.
- 시간: TIME_SEMANTICS_UNRESOLVED; 시스템 연도/수신시각/DST를 임의로 주입하지 않는다.
- OpenSSH authentication text가 있어도 syslog header parser가 없으므로 전체 형식은 지원하지 않는다.

### SSH-SYSLOG-5424

- 문법 후보: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
- 시간: RFC5424 timestamp가 explicit offset을 가질 수 있지만 현재 parser는 header를 해석하지 않는다.
- 판정: sample은 REJECTED. RFC5424 parser 지원이 아니다.
- envelope field에서 host/IP/PID/auth outcome을 만들어내지 않는다.

## 8. Apache Profile

### ACCESS-APACHE-CLF

- 공식 형식: %h %l %u %t "%r" %>s %b. %h는 host lookup 설정에 따라 hostname 또는 address가 될 수 있고 reverse proxy가 있으면 remote client 원주소가 아니라 proxy address일 수 있다.
- 현재 추출: 첫 필드를 src_ip, %t timestamp, request method/target/protocol, status, bytes. %l 및 %u는 보존·매핑하지 않는다.
- 시간: Apache example의 30/Oct/2026:09:00:00 +0900는 explicit offset으로 UTC 변환된다.
- 판정: numeric IPv4 %h sample은 핵심 일부를 파싱하지만 %l/%u omission으로 PARSED_PARTIAL. hostname %h는 confirmed FALSE_ACCEPT; 전체 CLF 지원 아님.

### ACCESS-APACHE-COMBINED

- 공식 형식: CLF core + quoted Referer + quoted User-Agent.
- 현재 추출: CLF와 동일한 HTTP core. Referer는 어느 model field에도 없고 NormalizedEvent.user_agent도 parser가 항상 None으로 설정한다. %u도 빠진다.
- 판정: textual sample parses, fields omitted, PARSED_PARTIAL. CustomLog로 token order/escaping/extra fields가 바뀌면 profile 밖이다.

## 9. NGINX Profile

### ACCESS-NGINX-COMBINED

공식 내장 combined는 remote_addr, remote_user, local Common Log Format time, request, status, body_bytes_sent, referer, user_agent를 출력한다. 현재 parser는 IPv4 sample의 timestamp, method/target, status, size를 얻으나 remote_user/referer/user_agent 의미는 잃는다. $body_bytes_sent는 NGINX 변수이고 Apache %b와 명칭·수집 설정이 동일하다고 단정하지 않는다. 기본 combined sample의 core fields는 PARSED_PARTIAL이며 NGINX 일반/custom log 전반 지원이 아니다.

### ACCESS-CUSTOM-JSON

NGINX log_format은 custom fields와 JSON escaping 옵션을 제공한다. JSON escaping이 설정된 JSON record는 고정 NCSA parser의 입력 문법이 아니며 corpus에서는 IGNORED. JSON source를 임의 추측하거나 자동 변환하지 않는다.

## 10. Syslog 형식 경계

RFC3164는 PRI/TIMESTAMP/HOSTNAME/MSG의 envelope로 연도·timezone을 보장하지 않는다. RFC5424는 versioned header, app/process/message ID, structured data 및 RFC3339-derived timestamp를 정의한다. 두 형식의 envelope가 인증 메시지의 의미를 자동 보증하지 않는다.

현재 plain SSH parser는 OpenSSH syslog envelope를 먼저 분리하지 않는다. ISO timestamp, 임의의 중간 token, auth phrase를 한 문자열에 search한다. 따라서 BSD syslog timestamp sample은 reject, RFC5424 sample은 reject, timestamp가 맞고 다른 program token 뒤에 같은 auth phrase가 나오면 잘못 SSH로 accept한다.

## 11. Timestamp 정책

| Case | 관측 결과 |
|---|---|
| Application/SSH naive datetime | registry에서 고정 Asia/Seoul 부착; 09:00 KST → 00:00 UTC |
| Access explicit +0000 / +0900 | aware datetime; 직접 offset으로 UTC 변환 |
| 동시각 비교 | 09:00 +0900과 00:00 +0000는 동일한 UTC instant |
| Day rollover | 31/Jan/2026 23:30 -0200 → 2026-02-01 01:30Z |
| Year rollover | 31/Dec/2026 23:30 -0200 → 2027-01-01 01:30Z |
| Invalid calendar date/offset | strptime이 예외를 발생시킴; live adapter에서는 source-specific reject |
| RFC3164 yearless time | TIME_SEMANTICS_UNRESOLVED; 현재 parser reject |
| RFC5424 explicit offset | 의미상 timestamp는 정의되어도 envelope unsupported라 현재 parser reject |
| DST | application/SSH timezone은 Asia/Seoul로 고정되어 ZoneInfo historical rules 적용; source actual timezone이 이 설정과 다른지 입력만으로 증명할 수 없음. Access numeric offset만으로 UTC instant는 정해지나 named zone/DST regime는 식별되지 않음 |
| timezone 없는 access timestamp | 현재 고정 parser grammar에 맞지 않아 reject |

연도나 timezone 보정 정책은 추가하지 않았다. 시간 상관은 잘못된 source timezone 가정에 민감하다.

## 12. Observable Evidence Mapping

현재 model은 app/models/schemas.py의 NormalizedEvent, AuthenticationContext, HttpContext를 기준으로 했다.

| 관측 원문 | NormalizedEvent 매핑 | 범위/주의 |
|---|---|---|
| Application/SSH 시간 | timestamp → UTC normalization | Application/SSH는 parser registry Asia/Seoul 가정 |
| Access 시간 | timestamp aware numeric offset → UTC | 날짜 문자열 offset만 근거 |
| auth event phrase | event_type, authentication.outcome/method | phrase의 source process 검증 필요; 확인된 SSH false accept 존재 |
| login account | user | invalid user 문구는 별도 flag; 실제 계정 존재/탈취 아님 |
| source address | src_ip | IP validation 없음; Apache %h hostname 오매핑 확인 |
| SSH port | authentication.source_port | optional, 없으면 None; client identity proof 아님 |
| HTTP method | http.method | 첫 quoted request token |
| URL path/query | http.path, http.query | urlsplit; percent-encoding은 별도 탐지 코드가 처리할 수 있음 |
| HTTP status/size | http.status_code, http.response_size | 100–599 range 검증이 없어 999 false acceptance 확인 |
| Referer/User-Agent | 현재 HttpContext에 없음; event user_agent도 parser에서 None | Combined에 존재해도 discard |

외부 client identity, NAT 뒤 사용자, reverse proxy 뒤 실제 IP, 행위자 동일성, 악의적 의도, 인증 성공에 따른 compromise는 관측 필드로부터 추정하지 않는다.

## 13. Synthetic Corpus

sample_logs/compatibility/에 직접 작성한 synthetic fixture 21개를 추가했다. 주소는 RFC 5737 문서용 IPv4 및 RFC 3849 문서용 IPv6 범위다. 계정, host, user-agent, URL은 .example 또는 synthetic marker만 사용했다. 실제 로그 파일을 복사하지 않았다.

구성: Application 2개, SSH 7개, Access 12개로 총 21개다. SSH는 ISO baseline, port omission, invalid-user/publickey, RFC3164, RFC5424, other-program phrase, multiline을 포함한다. Access는 CLF, Combined, NGINX Combined, IPv6/size dash, hostname, invalid status/date/offset, request omission, JSON, Apache/NGINX error를 포함한다.

profiles.json은 ID, source, fixture path, observed disposition, timestamp semantics를 제한적으로 고정한다. 상세 공식 format mapping은 이 문서에 있다.

## 14. Acceptance/Rejection Matrix

PARSED_PARTIAL은 parser가 event를 반환했지만 profile의 추가 field/record semantics가 빠졌음을 뜻한다. FALSE_ACCEPT는 parsed event가 잘못된 의미를 가진 것을 뜻한다.

| Profile / fixture | 관측 및 주요 필드 | Timestamp 의미 | 판정 |
|---|---|---|---|
| APP-AUTH-01 | login_failed, analyst, 192.0.2.11, failure, method 없음 | KST → UTC 정확 | SUPPORTED_VERIFIED |
| APP-AUTH-SUCCESS | user_login, reviewer, 192.0.2.13, success | KST → UTC 정확 | SUPPORTED_VERIFIED |
| SSH-NORM-01 | failure/password, analyst, 192.0.2.12, port 51000, invalid_user=False | KST → UTC 정확 | SUPPORTED_VERIFIED |
| SSH-NORM-NO-PORT | success/publickey, port 없음, invalid_user=None | KST → UTC 정확 | PARSED_PARTIAL |
| SSH-NORM-INVALID-USER-PUBKEY | failure/publickey, guest, 2001:db8::12, port와 invalid-user 추출 | KST → UTC 정확 | SUPPORTED_VERIFIED |
| SSH-SYSLOG-3164 | ISO datetime parse 예외 | year/zone 없음 | REJECTED |
| SSH-SYSLOG-5424 | ISO datetime parse 예외 | explicit offset이어도 envelope 미지원 | REJECTED |
| SSH-NON-SSHD-PHRASE | web-worker phrase를 SSH failure로 수용하고 application=sshd 생성 | timestamp만 KST 처리 | FALSE_ACCEPT |
| SSH-MULTILINE | 첫 line parsed, continuation rejected; lines를 별도 처리 | continuation timestamp 없음 | PARSED_PARTIAL |
| ACCESS-APACHE-CLF-IP-SUBSET | IPv4, GET, /items, query 그대로 q=one%2Ftwo, 200, size 10; remote %u 없음 | +0900 → UTC 정확 | PARSED_PARTIAL |
| ACCESS-APACHE-COMBINED | GET /health, 204, size 0; referer/user-agent/user 미보존 | +0000 → UTC 정확 | PARSED_PARTIAL |
| ACCESS-NGINX-COMBINED | GET /search, query, 200/48; referer/user-agent 미보존 | +0000 → UTC 정확 | PARSED_PARTIAL |
| ACCESS-IPV6-SIZE-DASH | IPv6 보존, status 304, size - → None | +0000 → UTC 정확 | PARSED_PARTIAL |
| ACCESS-INVALID-STATUS | status 999가 http_request로 수용됨 | +0000 parse 가능 | FALSE_ACCEPT |
| ACCESS-CLF-HOSTNAME | synthetic-host.example가 src_ip가 되고 analysis results key로 유입 | +0000 parse 가능 | FALSE_ACCEPT |
| ACCESS-INVALID-DATE | calendar date parse 예외 | 31-Feb invalid | REJECTED |
| ACCESS-INVALID-OFFSET | offset parse 예외 | +2500 invalid | REJECTED |
| ACCESS-MISSING-REQUEST-PARTS | parser None | explicit offset | IGNORED |
| ACCESS-CUSTOM-JSON | bracket timestamp 없음, parser None | JSON fields로 시간 추출하지 않음 | IGNORED |
| ACCESS-APACHE-ERROR | bracket text가 access timestamp가 아니어서 예외 | 미지원 | REJECTED |
| ACCESS-NGINX-ERROR | [error]를 bracket timestamp 후보로 읽다 parse 예외 | 미지원 | REJECTED |

## 15. False Acceptance

세 false acceptance를 분리해 재현했다.

1. **SSH source misclassification:** parse_ssh_auth_log는 timestamp 이후 전체 line에서 auth phrase를 search한다. synthetic web-worker Failed password for ...가 SSH failure, service sshd event로 변환된다. 실제 source process가 sshd인지 검사하지 않아 source/format mismatch가 분석 event로 들어갈 수 있다.
2. **Apache hostname %h → src_ip:** Apache 2.4 문서는 HostnameLookups가 켜지면 %h가 address 대신 hostname일 수 있다고 한다. parser는 첫 token을 검증하지 않고 src_ip로 설정한다. analyze([{"source":"access","path": fixture}]) 결과 key가 synthetic-host.example인 것을 synthetic fixture로 확인했다. Reverse proxy일 때 %h는 proxy address일 수 있다는 별도 한계도 공식 문서가 설명한다.
3. **Invalid status 999:** RFC9110 valid range는 100–599지만 parser는 모든 숫자를 허용한다. http_request(status=999)가 생성되고 기존 analysis result key에 도달한다. 4xx 조건 등 downstream 해석을 왜곡할 수 있다.

Compatibility focused test 결과: 37개 통과, fail-closed를 요구하는 위 세 boundary regression은 3개 실패했다. 이는 새 tests의 실패이며 기존 36.9A baseline 실패가 아니다. 어떤 실패도 skip/xfail이나 기대값 완화로 숨기지 않았다.

**영향 및 조치:** 잘못된 source IP grouping과 invalid HTTP status는 실무 결과 의미를 바꿀 수 있어 UNSAFE_ACCEPTANCE_HOLD다. 이번 범위에서 코드 변경하지 않는다. 후속 수정은 좁은 boundary validation, SSH process/source discriminator, Access IP/status validation을 각각 RED→GREEN으로 다루고 기존 formats/tests 및 consumer contracts를 검증해야 한다. Apache hostname 처리는 hostname을 src_ip에 넣지 않는 별도 schema/profile 설계가 필요할 수 있다.

## 16. Security/Privacy Review

- 합성 fixture만 사용했고 외부 로그/사용자 자료는 사용하지 않았다.
- 이 Phase에서는 HTTP API를 호출하거나 로그를 서버에 전송하지 않았다. 기존 API bounds를 변경하지 않았으며, API의 96 KiB wire / 32 KiB text / 2048-byte line / 512 lines / 10 s worker timeout / shared limiter 계약은 기존 테스트 대상이다.
- parser 내부 NormalizedEvent.raw는 원문 line을 보유한다. parser-level test에서 원문 제거를 주장하지 않는다. Public API/report privacy는 별도 closed projection regression 범위이며 이번 corpus는 그 모든 경로를 재검증하지 않았다.
- synthetic marker는 예상 request path/raw 필드에만 전달되는 것을 확인했다. 실제 개인정보 공개 여부를 평가하지 않았다.
- Vector/VM, Linux Audit 보호 API 또는 외부 collector를 실행하지 않았다.

## 17. Regression 결과

| 검증 | 결과 |
|---|---|
| 시작 baseline uv run pytest -q | 3172 passed, 2 upstream deprecation warnings |
| Compatibility focused tests | 37 passed, 3 failed — fail-closed SSH process mismatch, hostname-as-IP, status 999 |
| 기존 Parser tests | `uv run pytest -q tests/test_parser.py`: 21 passed |
| Evaluation CLI | `uv run python -m app.evaluation`: boundary 79/79, Linux process 21/21, 기존 집계 결과 재현; synthetic/self-labeled 범위 |
| API/UI schema, Detector, Correlation, Risk | 코드 변경 0 |
| Lockfile/Dependency | 변경 0 |
| Chromium/axe/TCP Syslog/JSONL/restricted report | 시작 SHA CI에서 PASS; 이번 UI/collector 수정 없음 |
| 전체 pytest after corpus | `uv run pytest -q`: 3 failed, 3209 passed, 2 warnings; 세 실패는 아래 재현된 위험한 false acceptance assertion |
| `python3 -m compileall -q app tests` | PASS |
| `uv sync --locked --dev` / `uv lock --check` | PASS; dependency/lockfile 변경 없음 |
| `git diff --check` | PASS |

3개의 focused 실패가 있으므로 acceptance criteria를 충족한 것으로 처리하지 않는다.

## 18. 현재 지원 형식

정확히 주장을 제한하면:

- **Application:** 내부 synthetic/application contract의 YYYY-MM-DD HH:MM:SS LEVEL EVENT key=value...; registry가 naive time에 Asia/Seoul 부착. login_failed와 user_login에만 검증된 failure/success map. 실제 특정 제품 형식이 아니다.
- **SSH:** ISO-style timestamp + auth phrase grammar의 synthetic subset. 성공/실패, password/publickey, user, from address, port가 있을 때 port/invalid-user flag를 추출하는 조건. Syslog envelope, arbitrary sshd journal, PAM messages, 모든 OpenSSH distro formats를 지원한다고 주장하지 않는다. wrong-program false acceptance가 있어 운영 입력의 안전한 지원으로 승인할 수 없다.
- **Access:** bracketed NCSA-like textual subset with explicit %z numeric offset, quoted 3-token request, numeric size or -, core status/size/path/query fields. IPv4/IPv6 samples parse. %u, referer, User-Agent는 손실되고 hostname %h는 잘못 src_ip가 된다. 999 status도 accept한다. 현재 이를 완전하고 안전한 Apache/Nginx 지원이라고 주장할 수 없다.
- **미지원/거부:** sampled RFC3164/5424 SSH envelopes 및 custom JSON access는 parser가 reject 또는 ignore한다. Error log는 access event로 처리하지 않는다. Multi-line event 조립을 하지 않는다.

## 19. 후속 Parser 확장 제안

1. 먼저 기존 three false accept를 제한적으로 고치는 별도 remediation phase를 승인한다. src_ip를 strict IPv4/IPv6로 검증할지, hostname source field가 필요한지 설계한다. HTTP status 100–599 check. SSH auth pattern을 process/source validated profile로 좁히되 ISO synthetic compatibility를 어떻게 유지할지 명시한다.
2. 안전한 base contract 이후, 공식 제품 문서 기반 named parser profiles를 단계적으로 추가한다. Apache CLF, Combined, NGINX Combined는 각 field loss와 custom format 차이를 명시하며, autodetection 없이 선택된 profile로 처리한다.
3. RFC3164는 year/timezone ambiguity resolution policy가 승인되기 전 구현하지 않는다.
4. RFC5424는 header/structured data grammar와 OpenSSH MSG separation이 명세되기 전 구현하지 않는다.
5. custom JSON access log는 named JSON schema/field map이 별도 승인된 경우만 다룬다.
6. 이후 Phase 36.9C detector evaluation은 Parser false acceptance가 해결되고 input profiles 및 failure dispositions가 고정된 뒤 시작한다.

## 20. Phase 36.9C 연결

**결정: HOLD.** Parser 입력 계약은 36.9C에서 탐지 정확도 평가를 시작하기에 충분히 안전하게 고정되지 않았다. ssh_wrong_program_phrase, Apache hostname-as-IP, invalid HTTP status는 event result에 도달한다. 36.9C corpus를 이 parser 위에 바로 확대하면 잘못된 normalized input을 ground truth로 평가할 위험이 있다. 선행 parser acceptance boundary를 수정하고 full regression을 통과한 뒤 36.9C를 시작한다.

## 21. 검증 명령 상태

| 명령/검증 | 상태 |
|---|---|
| 시작 Gate exact CI | PASS, 시작 SHA 전용 |
| baseline uv run pytest -q | PASS, 3172 |
| uv run pytest -q tests/test_log_format_compatibility_36_9b.py | 37 passed, 3 failing safety assertions (40 total) |
| uv sync --locked --dev | PASS |
| uv lock --check | PASS |
| uv run pytest -q tests/test_parser.py | 21 passed |
| uv run python -m app.evaluation | PASS; 79/79 synthetic boundary, 21/21 Linux process consistency |
| uv run pytest -q after corpus | 3 failed, 3209 passed, 2 warnings; 실패 3건은 동일한 hostname-as-IP / wrong-program SSH phrase / HTTP 999 false acceptance |
| python3 -m compileall -q app tests | PASS |
| git diff --check | PASS |
| Existing API/privacy focused tests for these fixtures | NOT_TESTED; no HTTP API executed |
| Real Apache/NGINX/OpenSSH deployment | NOT_TESTED |

Compatibility failures are actionable. They are not made green by changing production code in this phase or lowering assertion strength.

## 22. 최종 판정

**PHASE_36_9B_UNSAFE_ACCEPTANCE_HOLD**

세 false acceptance가 parser normalization 및 기존 analysis grouping에 도달하는 것을 synthetic input으로 재현했다. Parser 변경·Detector 변경·API/schema 변경은 하지 않았다. 이 Phase에서 지원 profile을 안전하게 완료했다고 선언하거나 완료 커밋을 만들지 않는다.

경계 유지:
- 실제 사용자 자료: NO_GO
- 조직 운영: NO_GO
- 자동 대응: NO_GO
- 실제 환경 탐지 정확도: UNVERIFIED
- 모델 기반 AI: NOT_TESTED
- Safari/VoiceOver/실제 모바일: NOT_TESTED
- Vector/VM: USER_ACTION_REQUIRED / ISOLATION_BLOCKED
- OS-level hard memory cap: 미보장
- 기존 UI renderer: KEEP_LEGACY
