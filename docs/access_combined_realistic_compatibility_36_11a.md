# Phase 36.11A — Apache/Nginx Combined Access Log 호환성

## 1. Executive Summary

이 Phase는 Access Parser가 문자열 중간에서 timestamp/request를 찾아 앞부분만 해석하던 동작을 전체 레코드 검증으로 바꿨다. Apache Common Log Format, Apache Combined, Nginx 기본 Combined의 제한된 공통 문법만 지원한다. Referer는 인용 필드와 escape 문법을 검증한 뒤 폐기하고, User-Agent는 기존 `NormalizedEvent.user_agent`에만 보존한다.

합성 Corpus 36개 중 지원 21, 거부 14, 무시 1이며 직접 Parser·Pipeline·파일 및 텍스트 입력 경로에서 검사했다. 이 결과는 합성 형식 호환성만 설명한다. 실환경 정확도나 조직 운영 승인이 아니다.

## 2. 시작 SHA / CI Gate

- 기준 SHA: `199041a0b279014fb32e2ac2636a7ac7aa87ab83`
- GitHub Actions Run: `41212757593`
- 시작 시 repository/branch 및 local, origin, GitHub SHA 일치, clean tree, ahead/behind 0/0 확인
- 동일 SHA push Run은 completed/success, 필수 regression 및 브라우저 검사 성공, artifact 0개
- 기준 pytest: 3463 passed, 2 warnings
- v0.4.0 tag/release target은 변경하지 않았다.

## 3. 기존 Parser 문제

이전 Parser는 레코드 전체를 하나의 문법으로 검증하지 않았다. Timestamp와 quoted request를 로그 어느 위치에서든 검색하고, request 이후 status/size prefix만 확인해 뒤쪽의 잘못된 토큰을 허용할 수 있었다. Combined Referer/User-Agent는 구조적으로 검증되지 않았고 User-Agent도 기존 이벤트 필드에 전달되지 않았다. 따라서 겉으로 유효한 prefix를 가진 조작 레코드가 실제 Access Event로 수용될 위험이 있었다.

## 4. 공식 형식 근거와 지원 Profile

Apache Common은 remote address, ident, remote user, timestamp, quoted request, status, byte count 순서다. Combined는 Referer 및 User-Agent quoted field를 추가한다. Apache 형식은 설정에 따라 hostname도 기록할 수 있으므로 본 Parser는 주소 literal만 받는 더 좁은 계약을 사용한다. Proxy 환경의 기록 주소가 최종 사용자를 뜻한다고 가정하지 않는다. [Apache HTTP Server 2.4 Log Files](https://httpd.apache.org/docs/2.4/logs.html)

Apache mod_log_config는 임의 CustomLog 필드 순서를 설정할 수 있고, 문자열 필드의 quote/backslash 및 임의 바이트 escape 규칙을 설명한다. 본 구현은 해당 전체 공간을 추측하지 않고 지원 가능한 escape 일부만 허용한다. [Apache mod_log_config](https://httpd.apache.org/docs/2.4/mod/mod_log_config.html)

Nginx 기본 Combined 형식은 remote address, literal dash, remote user, local time, request, status, body bytes, Referer, User-Agent 순서다. 기본 escape 모드는 따옴표·backslash·제어 및 비 ASCII byte를 `\xXX`로 기록할 수 있다. [Nginx ngx_http_log_module](https://nginx.org/en/docs/http/ngx_http_log_module.html)

지원되는 레코드 profile:

- Common: `REMOTE_ADDR IDENT USER [TIMESTAMP] "REQUEST" STATUS BYTES`
- Combined: 위 필드 뒤에 `"REFERER" "USER_AGENT"`
- 동일한 구조를 사용하는 Nginx 기본 Combined
- 레코드 구분을 위해 입력 끝의 단일 LF 또는 CRLF 허용

Parser는 구조를 식별할 뿐 원 로그가 Apache인지 Nginx인지 확정하지 않는다.

## 5. 지원하지 않는 문법

- 임의 Apache CustomLog 및 Nginx JSON/사용자 정의 format
- hostname, IPv4:port, IPv6 zone identifier, 잘못된 IP literal
- X-Forwarded-For로 원본 주소 추정
- 지원된 Common/Combined 필드 뒤 추가 토큰, 앞에 붙은 임의 문자열
- 잘못된 status/size, 날짜 또는 인용부호
- unsupported/incomplete escape 및 decoded control byte
- 누락된 Combined Referer/User-Agent
- 요청 필드의 안전하지 않거나 지원하지 않는 quoting
- Python 내부의 단독 잘못된 한 토큰 request는 기존 parser 관찰 계약대로 `None`; 입력 API preflight는 해당 레코드를 유효 입력으로 보지 않는다.
- JSON custom 입력은 기존 호환 disposition대로 Parser에서 `None`(IGNORED)이며, `PARSER_INCOMPATIBLE` 거부와 혼동하지 않는다.

잘못된 구조를 유효한 이벤트로 부분 수용하지 않으며, 알려진 레코드 구조의 잘못된 필드는 고정된 ValueError 메시지로 거부한다.

## 6. 필드와 정규화 의미

| 관측 필드 | 처리 |
|---|---|
| Remote address | `ipaddress` literal 검증 후 `src_ip`; 사용자/행위자 귀속은 아님 |
| IDENT / remote user | escape와 필드 위치 검증 후 폐기; 인증된 사용자로 승격하지 않음 |
| Timestamp | 명시적 숫자 UTC offset을 요구하고 timezone-aware datetime 생성; pipeline이 UTC 정규화 |
| Request | method, target, protocol 형식 검증; 기존 path/query 의미 유지 |
| Status / bytes | status 100–599, bytes 정수 또는 `-` → None |
| Referer | quoted syntax/escape/UTF-8 검증 후 폐기; fetch 또는 외부 요청 없음 |
| User-Agent | 지원 escape 해석 후 기존 내부 이벤트 필드에 저장; `-`는 None |

`"`, `\\`, `\xHH`만 허용한다. `\xHH`는 byte 단위로 strict UTF-8 decode한다. 잘못된 UTF-8, 제어문자, 알 수 없는 escape는 거부하며 URL decode나 lossy recovery를 하지 않는다. User-Agent는 공격자 제어 입력이며 탐지 신호가 아니고 Public API/Report로 내보내지 않는다. 원문 이벤트 필드는 기존 내부 분석에 남지만 이 Phase에서 공개 projection을 변경하지 않았다.

HTTP 200은 exploit 성공, 파일 노출, 데이터 반출의 증거가 아니다.

## 7. Synthetic Corpus 및 Parser 결과

`sample_logs/access_combined_compatibility/`에 36개 라벨 사전 작성 시나리오가 있다.

- SUPPORTED: 21
- REJECTED: 14
- IGNORED: 1 (JSON custom format)
- IPv4/IPv6 Common/Combined, 상태·size 경계, query, path traversal, quote/backslash/hex escape, 비 ASCII UTF-8, 잘못된 후행 토큰·주소·날짜·escape 등을 포함
- 문서용 IP, 합성 계정/UA/Referer만 사용

Parser와 API preflight 수용 여부는 기대 라벨과 일치했다. 잘못된 형식은 지원 이벤트로 정상화되지 않았다. 기존 단독 한 토큰 malformed request 및 JSON custom input의 무시 동작은 그대로 별도 분류했다.

## 8. File/Text API 및 Pipeline 검증

`parse_access_log()`, 전체 `analyze()`, `POST /api/v1/investigations/text`의 `source=access`, 기존 세 파일 필드 계약을 사용하는 `POST /api/v1/investigations`를 검증했다.

- 정상 Combined 로그는 두 입력 경로에서 허용된다.
- 잘못된 trailing field는 두 경로에서 HTTP 400 / `PARSER_INCOMPATIBLE`로 거부되고 원문은 응답에 포함되지 않는다.
- 양쪽 모두 기존 closed response schema를 유지한다.
- 두 API의 분석 범위는 다르다. Text 입력은 지정한 단일 source를 분석하고 File API는 application·SSH·access 세 파일을 합친다. 따라서 응답 envelope와 입력 수용 정책은 호환되지만 전체 aggregate 결과가 같다고 주장하지 않는다.
- 합성 path traversal request는 기존 Web Detector에 전달되어 기존 path-traversal 관찰을 생성했다. 정상 요청과 User-Agent canary는 새로운 탐지를 만들지 않았다.
- Referer/User-Agent privacy canary가 공개 Text/File API 응답에 나타나지 않았다.

## 9. False Acceptance / Rejection

36개 합성 사례에서 예상치 못한 수용, 예상치 못한 거부, 필드 매핑 오류, timestamp 오류 및 public privacy canary 노출은 없었다. 지원된 record profile의 실제 필드값을 정확히 비교했다. JSON custom 입력은 API rejection과 별개인 ignored case로 셌다. 이 분모는 구성된 fixture에만 적용되며 운영 오탐률/정탐률 추정치가 아니다.

## 10. Research Basis

공식 문서의 필드 순서와 escaping 정의를 본 프로젝트가 관측할 수 있는 문법으로 제한 매핑했다. Apache가 CustomLog를 설정할 수 있고 Nginx가 custom escape/format을 허용하기 때문에 모든 서버 로그를 자동 판별한다고 주장하지 않는다.

## 11. Observable Evidence Mapping

- 입력 문자열이 제한된 field order 및 record end에 일치할 때만 `http_request` event를 만든다.
- REMOTE_ADDR는 literal IP 검사로 제한한다. Proxy/NAT 너머의 사람이나 실제 client는 증명하지 않는다.
- timestamp의 offset은 로그에 실제 기록된 숫자 offset에서만 얻는다. 누락된 timezone은 추정하지 않는다.
- Referer는 문법만 확인하며 의미를 신뢰하지 않는다.
- User-Agent는 내부 보존만 하며 새로운 Detection/Risk 근거가 아니다.
- path/query/status/size는 기존 HTTP Context로 전달된다. 공격 성공이나 결과를 추론하지 않는다.

## 12. 보안 / 개인정보 / CSP

외부 URL fetch, 외부 네트워크 요청, LLM 호출을 추가하지 않았다. Public schema, CSP, API, UI, checklist/guidance opt-in, case isolation 및 report projection은 변경하지 않았다. 실제 사용자 자료·조직 운영·자동 대응은 계속 NO_GO다.

## 13. Regression

- `uv sync --locked --dev`, `uv lock --check`: 통과
- Parser/API/Live parsing/privacy 및 36.9B compatibility 집중 회귀: 167 passed, 2 warnings
- Evaluation CLI: 기존 spray scope, consumer boundary, R4A semantic result 유지
- 전체 pytest / compileall / Chromium axe / UI3 E2E: 최종 실행 결과를 완료 시 기록
- Existing Ground Truth 및 36.10B/R4A 결과는 변경하지 않음

## 14. Rollback / 운영 제한

이 Phase 커밋만 revert하면 기존 Parser로 되돌릴 수 있다. 롤백하면 Combined User-Agent 보존과 전체 record/trailing-field 검증이 제거되므로 지원하지 않는 후행 토큰의 부분 수용 위험이 다시 생긴다.

실제 조직 로그는 사용하지 않았다. Apache/Nginx의 모든 custom profile, 실제 proxy topology, 운영 중 개인정보 정책, 실환경 탐지 정확도, live collector parity는 검증하지 않았다. 실제 로그 사용과 조직 운영은 별도 승인 대상이다.

## 15. 최종 판정

`PHASE_36_11A_ACCESS_COMBINED_COMPATIBILITY_LOCAL_CONDITIONAL_GO`는 모든 필수 regression이 성공한 경우에만 적용한다. Production 범위는 Parser 호환성으로 한정하며 detector threshold/분석 의미는 바꾸지 않았다.
