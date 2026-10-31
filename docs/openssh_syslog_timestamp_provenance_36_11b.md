# Phase 36.11B — OpenSSH Syslog 호환성과 Timestamp Provenance

## 1. Executive Summary

기존 SSH Parser는 프로젝트 ISO-style 입력을 처리했지만 RFC 5424 header를 인식하지 않았다. 이번 변경은 **검증 가능한 제한된 RFC 5424 subset**을 `sshd` 인증 메시지에만 적용한다. 로그의 명시적 시간대는 UTC로 변환하고, PRI·VERSION·필드 순서·APP-NAME·PID/MSGID·NILVALUE Structured Data·인증 메시지·IP·port를 검사한다.

RFC 3164 형태는 계속 거부한다. 연도나 timezone을 현재 시각, 시스템 설정, 파일 시각, 수집 시각으로 보정하지 않는다. 기존 ISO-style parser, API schema, detector threshold 및 downstream 분석 계약은 유지했다.

독립 합성 Corpus는 38개 사례(지원 16, 미지원 22)이며, Parser·pipeline, text/file 입력, Live Parser 동일성, 기존 Brute Force 및 Password Spraying-like 경로를 검증했다. 합성 결과는 운영 정확성이나 조직 로그 수용을 입증하지 않는다.

## 2. 시작 Git / CI Gate

- 기준 SHA: `66856ef34487beccf017d8ad4a96f55dfdcc51a1`
- GitHub Actions Run: `41216419982`
- 시작 시 `main`, local HEAD/local main/origin main/GitHub main 일치, clean tree, ahead/behind `0/0` 확인
- 동일 SHA push Run: `completed / success`, Locked Python 3.12 regression 및 필수 Linux/SSH/TCP Syslog/JSONL/Restricted Report/Chromium/axe/tracked-file 검사 성공, artifact 0개
- 로컬 `uv` Python: 3.12.7
- 변경 전 전체 회귀: 3509 passed, 2 warnings
- v0.4.0 tag/release target `eecd6ee1cda0545e34b01c42e1a2163a899bcc27` 변경 없음

## 3. 기존 Parser 상태

`app/parser/ssh_auth.py`는 `YYYY-MM-DD HH:MM:SS` 뒤의 `sshd` 또는 `sshd[PID]` message를 해석하고, Registry에서 지정하는 `Asia/Seoul`을 timezone-naive ISO 시각에 부여했다. 인증 message mapping은 Accepted/Failed, password/publickey, 사용자, remote IP, 선택적 source port와 invalid-user 표식을 생성했다.

RFC 5424는 ISO-style 앞부분처럼 해석되지 않았고 입력 API는 `PARSER_INCOMPATIBLE`로 처리했다. Live Adapter는 Registry parser를 재사용하므로 Parser 지원 변경이 Batch/Live 모두에 적용된다. Adapter, checkpoint 및 publication 코드는 변경하지 않았다.

## 4. Research Basis — 공식 형식 근거

- [RFC 3164](https://www.rfc-editor.org/rfc/rfc3164)는 전통적인 timestamp를 `Mmm dd hh:mm:ss` 형태로 설명한다. 해당 시각 문자열 자체에는 연도나 UTC offset이 들어 있지 않다. 따라서 본 구현은 이 입력으로 absolute event time을 만들지 않는다.
- [RFC 5424](https://www.rfc-editor.org/rfc/rfc5424)는 PRI, VERSION, TIMESTAMP, HOSTNAME, APP-NAME, PROCID, MSGID, STRUCTURED-DATA, MSG 순서를 정의한다. PRI 범위는 0–191이며 header의 APP-NAME/PROCID/MSGID는 문자열 필드다. PROCID는 인증 시도 ID라는 보장이 없다. 이 구현은 RFC 전체가 아닌 VERSION 1, APP-NAME `sshd`, PID digits/NILVALUE, MSGID printable ASCII/NILVALUE, Structured Data NILVALUE만 허용한다.
- [RFC 3339](https://www.rfc-editor.org/rfc/rfc3339)는 numeric offset과 `-00:00`의 의미를 구분한다. `-00:00`은 local offset이 알려지지 않은 표현이므로 신뢰 가능한 절대 timezone으로 사용하지 않는다.
- [OpenSSH Portable](https://github.com/openssh/openssh-portable)는 OpenSSH 구현의 공식 저장소다. SSH 로그 문구와 설정은 배포판·버전·설정에 따라 달라질 수 있으므로 아래 인증 메시지는 이 저장소의 기존 parser가 인식하던 message grammar로 범위를 제한한다.

위 자료는 필드/시각 구조를 결정하는 근거다. 프로젝트의 60초 Brute/Correlation threshold나 실환경 정확도에 관한 근거로 사용하지 않는다.

## 5. RFC 3164와 RFC 5424

| 형식 | 시간 근거 | 처리 |
|---|---|---|
| 기존 ISO-style | timezone-naive 시각 + Registry `Asia/Seoul` 정책 | 이전 동작 유지. 원천 장비가 실제 서울 timezone이었다는 증명은 아님 |
| 제한 RFC 5424 | 명시 연도와 `Z` 또는 숫자 offset | aware datetime을 UTC로 변환 |
| RFC 3164 유사 | 연도/offset 없음 | 거부. 자동 보정 없음 |

## 6. 지원 문법

지원 profile은 단일 레코드의 다음 subset이다.

```text
<PRI>1 TIMESTAMP HOSTNAME sshd PROCID MSGID - MSG
```

- `PRI`: shortest decimal integer 0–191; leading-zero 변형은 거부
- `VERSION`: 정확히 `1`
- `TIMESTAMP`: `YYYY-MM-DDTHH:MM:SS[.fraction](Z|±HH:MM)`, 대문자 `T`/`Z`; fraction 1–6자리
- offset hour 00–23/minute 00–59; `-00:00`, naive, NILVALUE, 잘못된 날짜·offset은 거부
- Python datetime의 microsecond보다 세밀한 fraction은 손실 없이 표현할 수 없어 거부
- `HOSTNAME`: RFC header 위치의 printable ASCII/NILVALUE만 구조 검증; DNS lookup 또는 신뢰된 서버 신원으로 승격하지 않음
- `APP-NAME`: 정확히 `sshd`
- `PROCID`: ASCII digits 또는 `-`; 실제 PID 존재나 인증 시도 identity를 증명하지 않음
- `MSGID`: printable ASCII 최대 32자 또는 `-`; 의미/인증 상태/Event ID로 사용하지 않음
- `STRUCTURED-DATA`: `-`만 허용; SD-ELEMENT은 건너뛰지 않고 거부
- record 최대 8192 Python 문자, CR/LF 불허
- MSG는 기존 인증 message subset을 재사용한다. `Failed|Accepted password|publickey for [invalid user] USER from IP [port N ssh2[: ...]]` 형태만 인증 이벤트가 된다.

인증 message의 port는 기존 grammar처럼 생략될 수 있다. 제공되면 ASCII decimal 및 1–65535 범위를 검증한다. IP는 IPv4/IPv6 literal이어야 하며 hostname, `IP:port`, scoped IPv6와 잘못된 주소는 거부한다. DNS 및 X-Forwarded-For 해석은 없다.

## 7. 미지원 문법

- RFC 3164 yearless timestamp 및 timezone 추정
- RFC 5424 VERSION 2 등 다른 version, non-`sshd` APP-NAME, 비-NIL Structured Data
- JSON Syslog, custom header, 여러 레코드를 합친 입력, PRI 없는 변형
- UTF-8 BOM, 제어/format/surrogate 문자, 과도한 timestamp precision, 잘못된 quote/header separators
- `sshd-helper`, `fake-sshd`, `opensshd` 등 근사 APP-NAME
- 인증 message의 잘못된 문법, 유효하지 않은 IP/port

명확히 잘못된 인증 message는 고정 ValueError로 거부한다. `sshd`의 다른 메시지는 기존 SSH Parser 의미처럼 authentication 없는 SSH event로 남을 수 있다. 입력 preflight/API는 AuthenticationContext 없는 SSH-only 입력을 유효 인증 입력으로 취급하지 않는다.

## 8. Timestamp Provenance 및 UTC 정규화

RFC 5424 경로는 로그에 기록된 offset을 실제로 검증한 뒤에만 aware datetime을 만든다. 결과는 Parser 내부에서 UTC로 정규화되어 Batch와 Live가 동일 시각을 소비한다. Parser의 `timezone` 인자는 이 profile의 timestamp 해석에 적용되지 않는다.

RFC 3164의 연도 없음, timezone 없음은 provenance 결손이다. 현재 OS 연도·timezone, 파일 mtime, 수집 시각, 다른 레코드 시각을 대입하지 않는다. `NormalizedEvent`에 provenance schema를 새로 추가하지 않았기 때문에 ISO-style timestamp의 timezone은 기존 Registry 정책이라는 사실만 보존되며, 별도 provenance 필드로 증명되지는 않는다.

## 9. SSH Header 및 Authentication Mapping

Header parse 후 APP-NAME이 정확히 `sshd`일 때만 MSG를 SSH auth grammar에 전달한다. HOSTNAME/PROCID/MSGID의 문자열 일치로 `sshd`를 추정하지 않는다. Header metadata는 Event identity, user, source IP 또는 trust context가 아니다.

| 관측 사실 | 내부 NormalizedEvent |
|---|---|
| 명시 timestamp + offset | `timestamp` (UTC-aware) |
| `Failed` / `Accepted` | `login_failed` / `user_login` |
| `password` / `publickey` | `authentication.method` |
| username | `user` |
| validated remote literal | `src_ip` |
| validated optional port | `authentication.source_port` |
| invalid user marker | `authentication.invalid_user` |
| parser profile | `application=sshd`, `protocol=ssh` |

`Accepted`는 인증 성공 이벤트 관찰이지 계정 침해나 동일 공격 행위자의 증거가 아니다. 동일 IP는 한 행위자를 뜻하지 않으며 PROCID/MSGID는 로그인 attempt ID가 아니다.

## 10. Observable Evidence Mapping

- RFC5424 header가 정확한 순서·길이·문자 정책에 맞을 때만 그 APP-NAME과 MSG를 읽는다.
- 시각은 메시지에 포함된 연도/offset에서만 계산된다. Yearless 입력은 event로 변환하지 않는다.
- AuthenticationContext는 기존 `AUTHENTICATION_MESSAGE`가 인식한 message만 생성한다.
- Remote IP/port는 새 RFC5424 profile에서만 추가 검증한다. 기존 ISO-style parser의 관찰 범위를 별도 계약 없이 좁히지 않았다.
- Pipeline은 정규화된 `login_failed`/`user_login` 이벤트를 기존 Brute/Spray/Correlation/Risk/Case/Report 흐름으로 전달한다. Detector threshold나 결과 의미는 변경하지 않았다.

## 11. Synthetic Corpus 및 결과

`sample_logs/ssh_syslog_compatibility/manifest.json`에는 38개 사전 라벨 합성 시나리오가 있다.

- SUPPORTED 17개: IPv4/IPv6, failed/accepted password/publickey, invalid user, Z/offset, fraction, PRI 경계, NILVALUE PROCID/MSGID, UTC 날짜 경계 및 port 경계
- UNSUPPORTED 21개: 잘못된 PRI/version, APP spoof, 연도/offset 결손, `-00:00`, invalid date/offset/fraction, IP/port 오류, non-NIL Structured Data, prefix/header spoof, 잘못된 message, control/bidi, overlong record
- 모든 IP는 documentation range, 계정과 hostname은 synthetic
- 모든 fixture 라벨은 parser 실행 결과와 분리해 정적으로 저장

신규 compatibility 테스트는 모든 manifest row의 expected event type/user/IP/port/UTC 또는 fail-closed 결과를 비교한다. 사례 수는 해당 합성 manifest에만 적용되고 운영 정확도 지표가 아니다.

## 12. Direct Parser, Batch, Live 및 API 검증

- `parse_ssh_auth_log()`: 기존 ISO-style 서울 timezone parity 및 RFC5424 field exactness 검증
- Batch: `load_normalized_logs()`가 RFC5424 시각을 동일 UTC로 전달
- Live Parser: 동일 기록에서 Batch와 Event object 동일성 및 UTC 동일성 확인; yearless RFC3164는 `REJECTED`
- Text API `source=ssh`: HTTP 200 및 closed response schema; 계정/IP/hostname/PID canary 비노출
- File API: 기존 application/ssh/access 세 파일 multipart 계약으로 HTTP 200; RFC3164 SSH 파일은 HTTP 400 `PARSER_INCOMPATIBLE`
- Detector pipeline: 동일한 기존 Brute Force 및 whole-span Password Spray 검증 사례가 검출됨. 기존 threshold/정책을 변경하지 않음
- Text 및 File API는 분석 scope가 다르므로 전체 결과 equality를 주장하지 않는다. 입력 수용/거부 및 Parser event 의미가 같은지를 검증한다.

## 13. Downstream 의미와 Privacy

Correlation, Risk, Case Adapter, Incident Case, Report Projection 코드는 변경하지 않았다. 기존 accepted/failure 이벤트가 소비되는 방식은 현재 계약 그대로다. `Accepted`를 compromise로 승격하지 않았고 Spray relation, risk, case, report schema를 바꾸지 않았다.

Raw Log는 내부 `NormalizedEvent.raw`에 기존 계약대로 남을 수 있지만 API public projection에 나오지 않는다. RFC header의 hostname/PID/MSGID와 계정/IP는 API response에 추가되지 않는다. External network/DNS/LLM 요청 및 schema/CSP/UI 수정은 없다. 실제 사용자 자료, 조직 운영, 자동 대응은 계속 `NO_GO`다.

## 14. 기존 Regression 및 판정 근거

- 변경 전 전체: 3509 passed, 2 warnings
- 신규 Compatibility 테스트: 50 passed, 2 warnings (manifest의 개별 38 사례도 같은 테스트에서 검증)
- 기존 Parser, 36.9B false-acceptance, Live equivalence/privacy, Text/File API 집중 회귀: 233 passed, 2 warnings. 마지막 추가 Text API yearless rejection 검사는 신규 50개 테스트와 최종 전체 suite에도 포함했다.
- 전체 pytest: 3559 passed, 2 warnings
- `uv sync --locked --dev`, `uv lock --check`, `python3 -m compileall -q app tests`, `git diff --check`: 통과
- 전체 Evaluation CLI 및 Brute Window / Spray Scope / Consumer Boundary / R4A Semantic CLI: 기존 baseline 결과 유지
- Chromium/axe: 25 states 통과, 1920/1440/1280/1024/768/390/320 및 200% reflow에서 overflow/clipping/target 실패 0, 외부 요청 0
- UI3 Navigation E2E: 통과, `externalRequests=0`, `cspVerified=true`
- 36.10B/R4A Ground Truth와 Password Spray 결과는 수정하지 않는다.
- Public Schema, detector threshold, Correlation/Risk/Case/Report 정책, Live checkpoint/publication은 변경하지 않는다.

36.9B compatibility manifest의 `SSH-SYSLOG-5424`는 과거 실행 시점의 `REJECTED` label을 그대로 유지한다. 기존 회귀 검사는 그 historical label과 신규 36.11B Parser의 정확한 현재 field mapping을 별도로 검증한다. Fixture와 manifest 값은 변경하지 않았다.

## 15. Rollback / 운영 한계 / Next Phase

이 변경을 revert하면 RFC5424 제한 profile은 다시 거부되고 기존 ISO-style parser로 복귀한다. RFC3164는 어느 경우에도 이번 변경으로 추정 시간 지원을 받지 않는다.

RFC 5424의 모든 Structured Data/transport framing, OpenSSH 버전·배포판별 모든 message, 실제 collector의 replay/rotation/checkpoint parity, 운영 timezone provenance는 검증 범위 밖이다. `NormalizedEvent` timestamp provenance field, 실제 RFC3164 신뢰 Context, 실제 조직 로그 정확도, live collector 통합은 별도 Phase 대상이다.

후속 Phase는 `Phase 36.11C — Log Ingestion Quality & Coverage Assessment`를 권고한다. Parser가 거부/무시/수용한 입력량과 timestamp/source coverage를 분석 결과와 별도로 표현하는 내부 계약부터 설계한다.

## 16. 최종 판정

`PHASE_36_11B_OPENSSH_SYSLOG_COMPATIBILITY_LOCAL_CONDITIONAL_GO`는 필수 전체 회귀가 성공하고 변경 범위가 유지된 경우에만 적용한다. 이는 명시한 RFC5424 subset에 대한 합성 parser/API/Live-parser parity 성공이다. 모든 OpenSSH/Linux Syslog 형식, 실제 운영 정확도, live collector 통합, 사용자 자료 또는 조직 운영을 승인하지 않는다.
