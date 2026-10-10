# v0.2.0 Phase 11 — bounded 로컬 로그 모니터링 설계

상태: **설계 전용, 미구현** (2026-10-11). `v0.1.0`의 파일 업로드·분석 계약과 공개 Release는 변경하지 않는다. 사용자 표시명은 **로컬 로그 실시간 확인**을 우선한다. 여기서 ‘실시간’은 polling 기반의 추가분 관찰을 뜻하며 즉시 처리, 무유실, SIEM·EDR, 침해 판정을 보장하지 않는다. 이 문서의 숫자 미확정 항목은 `TO_BE_BENCHMARKED`이며 구현 기본값으로 간주하지 않는다.

## 1. 현재 계약, 목표와 관찰 가능한 근거

현재 `app.local_web`은 `127.0.0.1` 전경 서버이며 `--port`, `--no-browser`만 받는다. 샘플·3파일·Linux Audit 업로드는 각각 **일회성** 분석이다. `load_normalized_logs()`는 파일 전체를 읽어 list를 만든다. registry는 application/SSH의 naive 시각을 `Asia/Seoul`로, access의 명시적 offset을 UTC로 정규화한다. `NormalizedEvent.raw`, account, HTTP path/query 및 Linux Audit 실행 문맥은 trusted 내부 값이다. 공개 경계는 별도 allowlist projection이다. `detect_attacks()`는 IP별 단일 detection slot을 갖고, 인증 실패 전체의 min/max가 60초 이내인지 본다. Brute Force는 실패 5건·단일 계정, Spray-like는 4건·3계정, Web Scanning-like는 60초 안의 요청 6건·distinct target 6개·4xx 3건을 요구한다. 인증 실패→성공 및 Brute Force→성공은 60초의 가까운 후속 성공을 택한다. Path Traversal은 새 웹 탐지의 bounded canonicalizer와 달리 기존 반복 percent decode를 사용한다. **이 차이를 live 설계가 몰래 바꾸지 않는다.**

| 소스 역할 | 현재 parser가 실제로 볼 수 있는 것 | live에서 보존할 의미/공백 |
|---|---|---|
| application authentication | 줄별 timestamp, event type, account, source IP | 초 단위 원본 시각·KST 규칙 유지; malformed line은 현재 parser가 예외를 낼 수 있음 |
| SSH authentication | 지원하는 Failed/Accepted 문구, account, source IP | 미지원 문구는 event type이 없을 수 있음; 수집 성공=탐지 성공 아님 |
| NCSA access | offset 있는 timestamp, method, 분리된 path/query, status | request target은 내부에서만 사용; 200은 공격 성공 증거 아님 |
| Linux Audit | 다중 record grouping, execution context | 별도 역할; 1차 live 구현에서 보류하며 IP 사례와 결합 금지 |

이 설계가 목표로 하는 흐름은 `명시적 로컬 설정 → 파일 identity 검증 → bounded tail → 완전한 줄 framing → typed parser → bounded queue → 결정적 micro-batch → privacy-safe projection → bounded 메모리 replay → SSE → 접근 가능한 UI`다. 탐지는 관찰 후보, correlation은 인과관계가 아니며 Linux 분류는 인증·웹 사례와 합치지 않는다. LLM은 live 경로에서 **호출하지 않는다**. 파일 내용·분석 결과·checkpoint의 서버 영구 저장도 없다.

## 2. 사용자 흐름과 구성 계약

설계할 명령은 `uv run python -m app.local_web --monitor-config /absolute/local/config.json`이다. **현재는 동작하지 않는다.** 기본 실행은 계속 기존 UI만 제공한다. config 없는 상태에서는 `모니터링 비활성`과 시작 방법을 보인다. config를 검증한 실행에서는 서버가 준비된 뒤 tail을 시작하며 브라우저는 모니터링 경로를 지정하거나 config를 수정할 수 없다. 앱은 계속 `127.0.0.1` 한 process·한 worker 전경 실행이고 `Ctrl+C`가 수집까지 중지한다. 브라우저를 닫아도 수집은 계속된다. 브라우저 file input으로 장기 tail path를 선택하지 않는다. 다운로드·업로드 UI는 기존 기능으로 남는다.

Config는 UTF-8 JSON 단일 local regular file, exact-key typed schema다. 후보 계약은 아래와 같고 구현 전에 security test로 확정한다.

```json
{
  "schema_version": "1",
  "start_policy": "FROM_END",
  "sources": [
    {"role": "application", "path": "/absolute/example/auth.log"}
  ]
}
```

예시 경로는 형식 설명일 뿐 실제 소스나 권장 위치가 아니다. Poll 간격은 config에서 조정할 수 없는 고정 프로젝트 정책으로 시작하며 값은 benchmark 뒤 결정한다. `sources`는 1~3개, role은 `application`·`ssh`·`access` 각 1회만 허용한다. `linux_audit`는 typed role로 예약하지만 Phase 12에서는 **거부**한다. `source_id`는 중복·유출 위험 때문에 V1에 두지 않는다. UI 표시명은 역할별 고정 한국어 이름만 사용하며 path, basename, path hash, inode/offset을 공개하지 않는다. Unknown key, 중복 JSON key, 중복 role, 동일 `(device,inode)`를 두 role에 연결, 상대 경로, `..` 경로 성분, symlink, FIFO/device/socket/directory, 불가한 소유·권한은 고정 오류로 fail closed한다. 설정 파일은 실행 사용자 소유·group/world 접근 금지(0600 또는 그보다 제한적)로 하고, 소스는 읽기 가능하면서 group/world writable이 아니어야 한다. 소스 소유자는 실행 사용자 또는 OS 관리 계정일 수 있으므로 일률적 0600을 강제하지 않는다. 권한 상승·`sudo`·임의 경로 자동 검색은 없다. Parent symlink도 승인 없이 경로 밖으로 이동하지 않도록 dir-fd 기반 단계별 no-follow open 및 `fstat()` 검증을 설계한다. OS가 필요한 no-follow 검증을 제공하지 않으면 모니터링을 거부한다. 경로는 API/UI/일반 오류·로그에 넣지 않는다. CLI argument의 config 경로가 OS process list·shell history에 보일 수 있음은 범위 밖 잔여 위험으로 고지한다.

`FROM_END`만 V1에서 허용한다. 검증·open한 파일의 시작 시점 `fstat().st_size`를 offset으로 잡고 **그 뒤 append된 완전한 줄만** 처리한다. `FROM_START`와 persistent checkpoint는 보류한다. 재시작 시 다시 끝에서 시작하므로 중단 동안의 append는 놓칠 수 있고, UI에 `재시작 이후 추가분만 관찰`을 표시한다. 시스템 시각은 상태·지연 측정에만 쓰고 event timestamp를 바꾸지 않는다. 초기 세션에는 `STARTING → RUNNING`까지의 준비 상태와 고정 역할명이 보인다.

화면 상태는 `모니터링 비활성 / 시작 준비 / 실행 중 / 일시 중지 / 입력 지연 / 일부 입력 오류 / queue pressure / 관찰 유실 가능성 / 중지 완료 / 복구 필요`를 구분한다. 마지막 처리 시각(없으면 `아직 없음`), 처리한 줄 수, 새 조사 후보 수, queue 깊이/상태, 완전성 경고, 규칙 기반·LLM 비호출, 저장 정책과 `Ctrl+C` 중지 방법을 표시한다. 상태가 좋아 보인다고 안전을 뜻하지 않는다.

## 3. 구성 요소와 파일 수명주기

| 경계 | 책임 | 금지 |
|---|---|---|
| supervisor | 승인 파일만 열고 reader/worker/SSE를 시작·취소·join, 고정 상태/오류 수집 | 디렉터리 재귀 검색, `/var/log` 전체 검색, 홈 자동 검색, sudo, 자동 source 추가, 원격 수집 |
| tail reader | 열려 있는 FD의 새 byte를 chunk로 읽고 offset·partial buffer·rotation 감지 | unbounded `read()`, filename 재해석, FIFO/device 열기, 무음 skip |
| parser dispatch | 완전한 UTF-8 줄을 기존 역할 parser로 보내고 UTC typed event 생성 | loader 재호출, detector 판단, raw 예외 출력 |
| queue + analysis | bounded typed event 전달, 승인된 event-time micro-batch, 기존 detector 의미 검증 | 전체 파일 매 이벤트 재분석, event별 LLM, 무한 history |
| projection + publisher | allowlist DTO, bounded replay, same-origin SSE | raw line/event/account/path/query/argv, 내부 repr, 영구 결과 저장 |

파일 identity는 open FD의 `(st_dev, st_ino)`와 `fstat` mode를 내부에서 사용하고, path의 `lstat`/재open 결과와 비교한다. macOS/Linux POSIX filesystem에서 이 값은 합리적인 근접 identity지만 inode 재사용·network filesystem·동시 교체를 완벽히 판별하지 못한다. 파일을 `O_NOFOLLOW | O_NONBLOCK`으로 열고 regular file을 `fstat`한 뒤 사용한다. 경로 확인과 open 사이의 TOCTOU는 dir-fd 검증과 open 뒤 재검증으로 줄이지만 0으로 만들지는 못한다. 지원하지 않는 filesystem/OS에서는 시작 거부가 기본이다.

| 감지 상황 | reader 전이와 bounded 동작 | 완전성 안내 |
|---|---|---|
| 같은 identity, size 증가 | offset부터 chunk를 읽되 완전한 줄만 queue에 확정 | poll 지연 가능 |
| 같은 identity, size < offset (`copytruncate` 등) | partial 폐기·카운트, offset 0으로 재설정 후 새 내용은 한도 내에서 처리 | truncate 전 미읽은 byte 유실 가능 |
| path가 새 identity로 교체/rename 후 재생성 | 옛 FD의 현재 남은 완전한 줄을 bounded drain; 새 FD를 안전하게 열어 offset 0부터 bounded 처리 | swap 사이 append의 중복·유실 가능 |
| path 소실/권한 변경/symlink swap | 기존 FD를 무한 추적하지 않고 source를 `DEGRADED`로 pause, 제한된 재검증 후 명시적 복구 | missed interval과 재개 기준 표시 |
| rotation 시 partial line | old partial은 parser에 전달하지 않고 폐기 수만 기록 | partial 유실 가능 |
| 동일 timestamp 또는 내용 재등장 | 줄마다 별도 물리 기록으로 처리; raw 동등성만으로 dedup하지 않음 | rotation 중복 가능성 표시 |

새 파일은 길이·줄·backlog budget 초과 시 무조건 `DEGRADED`/복구 필요로 멈춘다. rotate된 파일의 과거 전체를 무한 재처리하지 않는다. 파일 identity 재사용, 크기가 offset과 같아질 때의 copytruncate, 두 poll 사이 여러 rotation은 탐지 불가능할 수 있으므로 **exactly-once / no-loss 보장 없음**. source별 독립 오류는 다른 source를 멈추지 않되 전체 세션은 `DEGRADED`로 보인다.

줄 framing은 raw byte chunk를 source-local bounded partial buffer에 넣고 LF(`\n`)가 끝난 줄만 처리한다. CRLF는 마지막 CR 하나만 제거한다. EOF의 미완성 줄은 다음 poll까지 보존한다. UTF-8 multibyte가 chunk 경계에서 갈려도 **완성 byte line을 strict decode**하므로 깨지지 않는다. 최대 chunk·줄·partial byte는 기존 업로드 상한을 그대로 복사하지 않고 benchmark 후 확정한다. invalid UTF-8, NUL, 명백한 binary, 너무 긴 줄은 source를 `DEGRADED`로 멈추고 fixed code/복구 행동만 전한다. parser 실패와 의도적 무시는 별도 count다. 잘못된 줄을 조용히 버리고 `정상 0건`으로 표시하지 않는다. partial은 repr/log/error/SSE에 포함하지 않는다.

## 4. 3단계 backpressure와 분석 의미

| 구간 | bounded 한도 (Phase 12 측정 후 결정) | 꽉 찼을 때 / 복구 |
|---|---|---|
| reader → normalized-event queue | item cap + estimated/serialized byte cap `TO_BE_BENCHMARKED`; nonzero `maxsize`, enqueue timeout | reader는 마지막 완전한 줄을 source-local bounded pending으로 잡고 offset을 **enqueue 확정 뒤** commit. Timeout이면 읽기 pause·`queue pressure`/`DEGRADED`; 재시도는 같은 pending fact. 회전·truncate로 복구 불가면 gap 경고/카운트. 무음 drop 금지 |
| analysis → live projection replay | event count + 총 UTF-8 byte cap `TO_BE_BENCHMARKED` | 오래된 공개 frame을 퇴출하되 수집 사실은 버리지 않음. 이어지는 browser는 replay gap + 최신 snapshot. 버퍼 압력이 지속되면 새 publication을 pause하고 `DEGRADED`; 결과를 정상 0건으로 표시하지 않음 |
| SSE → browser | 연결 수 + 각 연결의 frame/item/byte cap + send timeout `TO_BE_BENCHMARKED` | 느린 연결만 종료; server-side session은 계속. 재접속하면 replay 또는 gap/snapshot. storm은 접속 거부/고정 warning; producer를 무한 대기시키지 않음 |

모든 count는 bool 제외 nonnegative signed 64-bit 범위이며 포화 시 고정 `COUNTER_LIMIT`와 fail-closed 상태로 전환한다. queue memory는 항목 수만 제한해서는 부족하다. byte budget에는 Python 객체 overhead도 benchmark해서 여유를 포함해야 한다. `asyncio.Queue(maxsize=0)`은 무한 queue이므로 금지한다. `put()` timeout, cancellation, `task_done()`/join, FD close와 slot 해제를 각각 테스트한다. overflow count는 실제 버려진 공개 replay frame과 놓친 원본 line을 구분하고 후자는 추정치이면 `unknown`으로 표시한다.

기존 detector는 batch 전체의 min/max와 per-IP 단일 slot을 사용한다. 따라서 단순히 60초 rolling deque를 넘기면 batch의 범위 선택이 달라질 수 있다. `detect_web_observations()`의 subject 요청 상한 4096, legacy traversal의 반복 decode, raw account/target이 남는 `NormalizedEvent`도 별도 gate다. 세 대안을 비교한다.

| 분석 방식 | 장점 | 결정성·메모리·의미 위험 | 결정 |
|---|---|---|---|
| 이벤트마다 전체 pipeline 재실행 | 코드 재사용 | 파일 I/O·메모리 무한 증가, 이전 결과 변동, event별 비용 | no-go |
| bounded micro-batch + 기존 pure 단계 재사용 | 기존 threshold/관계/위험도 재사용 가능 | event-time window 구성·중복 case revision 검증 필요; batch 동등성 없으면 오표시 | **권장 후속 단계**, 동등성 gate 필수 |
| detector별 incremental state machine | 처리량 우수 | 7개 웹/인증 detection과 auth correlation을 재구현하는 의미 변경 위험 | 성능 측정 뒤 별도 단계 |

분석 worker는 source별 reader sequence와 canonical UTC event time으로 bounded reorder buffer를 만들고, watermark/allowed lateness는 `TO_BE_BENCHMARKED`로 남긴다. 시스템 clock은 watermark와 혼합하지 않는다. 동일 timestamp는 source role·source-local sequence로 안정 정렬하되 이 순서가 endpoint 선택 의미를 바꾸면 relation을 내지 않는다. 재전송 ID는 `(internal file generation, byte span, role)`을 내부에서만 사용하고 **같은 로그 줄 내용/시각만으로는 중복 제거하지 않는다**. late/out-of-order/far-future/past event가 허용된 버퍼를 넘으면 `DEGRADED`, gap/late count와 재검토 요구를 표시한다. Brute/Spray/Web Scanning 60초와 기존 auth 관계 60초, Path Traversal/개별 웹 관찰의 event-local 필요 history를 일람표로 테스트하되 threshold/window를 바꾸지 않는다. 위험도·case는 원래 pipeline과 같은 bounded fact set에서만 만든다. closest-success 정책, Spray case no-go, 웹 독립 관찰, Linux 분리 유지. raw global correlation은 live case에 적용하지 않는다. 현재 pipeline의 global 범위를 보존할 수 없으면 그 output을 **미지원**으로 표시한다.

한 번 공개한 관찰을 자동으로 다른 사실로 덮어쓰지 않는다. 비교 가능한 fact key와 증가 revision을 가진 `case_revision`으로 변경·철회를 명시하며 client는 revision 단조 증가와 전체 snapshot을 검증한다. session 종료 시 pending complete line과 queue를 deadline 내 drain하고 최종 revision/완전성 상태를 공개한다. Deadline을 넘기면 `STOPPED_WITH_GAP` 성격의 terminal warning을 남기며 성공 완료로 표시하지 않는다. Analysis timeout 뒤 실제 worker가 살아 있으면 slot을 먼저 풀지 않는다. **Phase 12 첫 구현은 아래처럼 tail/status/snapshot까지로 좁힌다**; detector·case publication은 배치 동등성, bounded memory, privacy test가 통과한 다음 하위 단계에서 켠다. 이 단계의 UI를 `탐지 동작 중`으로 표현하지 않는다.

## 5. process-local session 및 SSE 계약

V1은 **단일 process-local session**이다. 영구 DB/offset/result가 없고 다중 worker 간 공유도 없다. Config를 받은 launcher가 소유하고 browser는 session을 시작하거나 path를 바꿀 수 없다. Server restart는 새 generation/offset이다. Public session ID는 필요 없으므로 노출하지 않는다. Worker 내부에는 bounded typed event와 필요한 raw account/target이 TTL 동안 잠시 존재할 수 있으나 public `LiveSessionSnapshot`에는 저장하지 않는다. 원본 줄·account·query·argv·파일 경로·credential·cookie/token은 session DTO·replay에 없다. Python 메모리 완전 삭제, crash 후 정리, 다른 로컬 사용자에 대한 격리는 보장하지 않는다.

| 상태 | 진입 조건 | 허용 전이 |
|---|---|---|
| `CREATED` | config 미적용 | `STARTING`, `FAILED` |
| `STARTING` | 파일 검증/reader 준비 | `RUNNING`, `DEGRADED`, `FAILED`, `STOPPING` |
| `RUNNING` | reader/worker 정상 | `PAUSED`, `DEGRADED`, `STOPPING` |
| `PAUSED` | 후속 operator 수집 pause를 위한 상태; reader offset 유지. **V1의 브라우저 표시 pause는 여기에 진입하지 않음** | `RUNNING`, `DEGRADED`, `STOPPING` |
| `DEGRADED` | source 오류·queue pressure·gap 가능성 | 조건 해결 시 `RUNNING`, operator 조치 시 `PAUSED`, `STOPPING`, `FAILED` |
| `STOPPING` | Ctrl+C/종료 요청; 새 analysis 성공으로 표기 금지 | `STOPPED`, `FAILED` |
| `STOPPED` | task/FD/connection 종료 확인 | 종결 |
| `FAILED` | unrecoverable 또는 shutdown deadline 위반 | 종결/새 process에서만 재시작 |

Session 속성은 monotonic revision, 시작·마지막 활동의 UTC 시각, 상태, role tuple, 처리/거부 줄 수, queue 깊이, overflow/gap indicator, 마지막 처리 시각, bounded warning, privacy-safe 관찰 count다. 상태는 결과 확정·완전성의 증거가 아니다. 브라우저 `pause updates`는 화면 반영만 멈추고 server tail 중단과 다르며 별도 문구를 쓴다. V1 수집 시작·중지는 CLI 실행/`Ctrl+C`만 지원한다. Browser mutation endpoint를 만들지 않으므로 다른 local site의 CSRF 시작/중지 문제를 줄인다. 후속 browser pause/stop API가 필요하면 Origin/Host/CSRF token 검증과 local-process 접근 위협을 별도 설계해야 한다. 키보드로 UI의 표시 pause/resume 및 터미널 Ctrl+C가 가능해야 한다.

후속 SSE 후보는 `GET /api/v1/live/status`, `GET /api/v1/live/events` 두 개만이다. `POST /api/v1/live/start`/`stop`은 V1 **없음**. Config 없이 status는 고정 비활성 DTO, events는 고정 거부다. 모든 요청은 peer IP를 Python `ipaddress`로 loopback 검증하며 없는/invalid client, IPv4-mapped IPv6, forwarding header, 외부 Host/Origin 우회는 fail closed한다. Launcher는 `127.0.0.1`, proxy header 비신뢰, CORS 비활성, no redirects to remote. Same-origin `Origin`/Fetch Metadata가 있는 요청은 정확히 검증하되, header 부재나 loopback 자체가 악의적 로컬 프로세스에 대한 인증은 아니다. 다른 로컬 사용자/프로세스가 loopback port에 접근할 수 있으므로 live SSE에 개인정보-safe DTO만 싣고, OS 사용자 격리가 필요한 환경에서는 V1 no-go다.

`/status`는 no-store의 typed snapshot. `/events`는 `text/event-stream; charset=utf-8`, `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, 연결 수·시간·frame cap과 disconnect cleanup. Proxy buffering을 끄도록 설계하되 reverse proxy/hosted는 지원하지 않는다. Heartbeat는 comment 또는 `heartbeat`의 revision/고정 상태만 포함한다. EventSource reconnect는 브라우저가 `Last-Event-ID`를 보낼 수 있지만 전송·수신 정확성을 보장하지 않는다. Event ID는 비밀이나 audit ID가 아닌 process generation + 증가 sequence, 문법·길이를 정확히 검증한다. Transport generation은 process마다 달라도 **분석 의미/순서에 사용하지 않는다**.

`Last-Event-ID`가 현재 replay의 연속 범위 안이면 `id` 다음 frame부터 재전송한다. 처음 연결처럼 ID가 없으면 정상 `snapshot`, 옛 generation·너무 오래된 ID·ahead ID면 `replay_gap` warning을 포함한 최신 `snapshot`을 보내고 완전성 재확인을 요구한다. Gap을 0건으로 바꾸지 않는다. Reconnect 폭주/느린 client는 연결 단위 제한 후 종료. Browser가 끊겨도 수집은 계속; 서버 종료 시 terminal frame을 보내고 FD/task를 정리한다.

| event | exact public data 의미 (모두 schema `"1"`, revision, UTC 시각, 고정 kind 포함) | 사용 시점 |
|---|---|---|
| `snapshot` | 상태, role별 fixed label, bounded count/queue, completeness flag, 현재 승인된 case/관찰 projection | 첫 연결, replay gap, 재접속 동기화 |
| `observation` | 고정 type·fact ID·risk/confidence·승인된 scalar만, raw 제외 | 동등성 검증 후에만 |
| `case_revision` | case ID·old/new revision·typed 공개 projection 또는 명시적 철회 | 동등성 검증 후에만 |
| `status` | 상태 전이, 마지막 처리 시각, role별 count | bounded coalescing |
| `warning` | 고정 code, 영향 역할, 복구 행동, 완전성 flag | gap/queue/rotation/오류 |
| `heartbeat` | 고정 heartbeat·revision만 | 연결 유지; 개인정보 없음 |
| `terminal_error` | 고정 code, 종료 상태, 재시작 행동 | 재시도 불가 오류 |

`id`는 data event에만 주고 heartbeat가 revision을 증가시키지 않도록 한다. JSON은 explicit Pydantic/typed allowlist에서만 만들고 raw analysis, `jsonable_encoder(raw)`, exception text 전달 금지. Frame별 byte cap과 `Last-Event-ID` 길이·형식 cap은 benchmark/테스트로 확정한다. `retry:`는 bounded 고정값을 측정 뒤 선택하며 client가 임의 rapid reconnect하지 못하게 server connection rate도 제한한다.

모든 data frame은 정확히 `schema_version: "1"`, `kind: 고정 enum`, `revision: 0..2^63-1의 정수(bool 제외)`, `emitted_at_utc: canonical UTC`, `payload: kind별 닫힌 typed DTO`의 5개 JSON key를 갖는다. `id`는 별도의 SSE field로만 전송하며 JSON payload에 복제하지 않는다. `snapshot` payload는 `state`, `roles`(고정 role ID·display label tuple), `processed_line_count`, `rejected_line_count`, `queue_depth`, `gap_possible`, `last_processed_at_utc`, `observation_count`, `bounded_warnings`의 exact key를 갖는다. `status`는 같은 집계에서 변경된 revision의 **전체** 값이지 임의 patch가 아니다. `warning`/`terminal_error`는 고정 `code`, 영향 `role` 또는 `null`, `recovery_action`, `retryable`, `gap_possible`만 허용한다. `observation`과 `case_revision` payload는 기존 공개 case projection의 고정 필드만 재검증해 구성하고 새 raw key를 전파하지 않는다. `heartbeat`는 comment-only를 우선하여 JSON event도 revision도 만들지 않는다. 범위 밖/unknown enum·추가 key·bool-as-int·잘못된 UTC는 frame 전체 거부다.

## 6. 접근 가능한 live UI와 개인정보

새 결과는 목록에 곧바로 삽입하지 않는다. 짧고 낮은 빈도의 `aria-live="polite"` 상태 count와 **새 결과 N건 보기** native button만 갱신한다. 사용자가 누르면 검증된 batch를 append하고 기존 읽기 위치·focus·Timeline DOM 순서를 유지한다. 자동 scroll/focus/re-sort/삭제, 이벤트별 screen reader announcement, countdown/autoplay/animation은 없다. `업데이트 표시 일시 중지`/`다시 표시`는 keyboard-only로 조작되며 **서버 수집은 계속**임을 명시한다. 실제 수집 종료는 터미널 `Ctrl+C`; UI에는 고정 방법을 표시한다. 연결 끊김, `DEGRADED`, queue pressure, 유실 가능성, 빈 결과(`안전함 아님`)을 색상 이외 텍스트로 표시한다. Visible focus, semantic headings/landmarks, table caption/`th scope`, reduced motion, 좁은 화면과 200% 확대를 수동 확인한다. WCAG 2.2 AA 준수를 자동으로 주장하지 않는다.

공개 DTO/SSE/UI/log/OpenAPI/metrics/shutdown에는 전체 source path·basename·account·HTTP path/query·Linux exe/argv/CWD·raw line·partial line·credential·cookie/token·내부 exception/repr가 없어야 한다. 운영 log는 고정 source role, 전이, signed-64 count, fixed code, queue depth, duration/revision만. 오류는 fixed code·한국어 복구 행동·retryable과 완전성 flag이며 raw exception chaining을 public/log에 남기지 않는다. Python 내부 parser/worker의 trusted state에는 join을 위한 계정·target이 TTL 동안 남을 수 있고, memory dump/debugger/악성 내부 코드는 보호 범위 밖이다. Browser close 후에도 bounded worker state는 세션 종료까지 남으므로 ‘저장하지 않는다’는 **영구 저장 없음**으로만 표현한다.

Canary 계획: 서로 다른 합성 account, HTTP path/query, credential, exe/argv/CWD, config source path, filename, partial line, parser exception을 넣고 SSE/status/UI DOM/browser console/stdout/stderr/application log/error/model repr/OpenAPI/metrics/shutdown을 전부 검색한다. 원문·부분 segment·URL-encoding·JSON-escaped 형태를 검사한다. Known private path를 테스트 오류 diff에도 넣지 않는다. `NormalizedEvent.raw` 자체를 generic serializer나 logger에 전달하는 테스트는 반드시 실패해야 한다.

## 7. 위협 모델 (예방 / 탐지 / bounded failure / 잔여 위험)

| 위협 | 예방 | 탐지·bounded failure | 잔여 위험 |
|---|---|---|---|
| 악의적 local producer, 무한 append, 긴 줄, 고정 partial | chunk·line·partial·rate/queue cap | source pause + fixed warning | FD backlog 증가/유실 가능 |
| invalid UTF-8, NUL/binary, parser 예외 반복, crafted percent encoding | 완전 줄 strict decode, typed dispatch, web target bound; legacy traversal 별도 gate | 오류 count 및 `DEGRADED`; 반복 예외 budget 초과 시 source 중단 | parser CPU 폭주를 hard-stop하려면 별도 process 필요 |
| 빠른 rename rotation, copytruncate, replacement, inode 재사용 | fstat/path identity, bounded drain, no-follow 재open | rotation/gap warning, 재open budget 초과 시 pause | poll 사이 변경·copytruncate 데이터 유실/중복 |
| symlink swap, TOCTOU, FIFO/device 등록, 권한 상실 | absolute path, dir-fd no-follow, open 뒤 regular/owner/permission 확인 | 안전 검증 불가면 reject/degraded | filesystem·OS별 race 완전 제거 불가 |
| queue exhaustion, high-cardinality IP/account/target, 미래/과거 timestamp | item+byte+subject+history+lateness cap | pressure/gap 또는 fail closed; 정상 0건 금지 | 합성 benchmark 밖 load는 지원 안 함 |
| 느린 browser, reconnect storm, 많은 local 연결 | 연결/frame/replay cap·rate, browser 표시 batch | 느린 client 종료·snapshot/gap | loopback의 다른 local process가 자원 소모 가능 |
| disk full, source disappearance, shutdown 중 append | 원본 변경/서버 기록 없음, FD close·bounded drain | `DEGRADED`/terminal warning | writer 또는 OS의 데이터 손실은 통제 못 함 |
| server crash, browser close | 전경 process, in-memory only, restart FROM_END | 다음 시작에 restart-gap 안내 | crash 중 append 누락, secure memory erasure 없음 |
| 다른 로컬 사용자/포트 포워딩/hosted 노출 | loopback bind·peer 검사·same-origin, CORS off, privacy-safe DTO | 고정 접근 거부·연결 제한 | loopback은 사용자 인증이 아님; 공유 host와 공개 노출 no-go |

## 8. 대안 비교와 Phase 12 최소 수용 범위

| 선택 | 대안의 비용/위험 | V1 결정 |
|---|---|---|
| 변화 감지 | Linux inotify는 플랫폼 종속·event coalescing/overflow, Apple FSEvents는 디렉터리 계층/latency, 외부 watcher는 새 dependency | **portable polling**. identity 재검증을 항상 하고 latency는 측정 전 미보장 |
| 처리 | 전파일 재실행은 unbounded; incremental state machine은 의미 drift; micro-batch는 bounded state와 parity 필요 | 순차적으로 **bounded tail/status → 동등성 검증된 micro-batch** |
| session | 여러 session은 ownership·리소스 증가; DB는 영구 민감 state | **단일 process-local session** |
| 시작 | FROM_START는 초기 backlog; checkpoint는 저장/복구 | **FROM_END only**, 재시작 gap 명시 |
| UI 전달 | polling은 반복 요청, WebSocket은 양방향 공격면, SSE는 일방향·replay 관리 필요 | **SSE**와 읽기 전용 status; mutation endpoint 없음 |

다음 표는 각 대안을 개인정보(P), 결정성(D), 유실/중복(L), 접근성(A), 구현·운영 부담(C/O) 축으로 비교한 결정 기록이다. `낮음/높음`은 측정치가 아니라 상대 설계 부담이다.

| 영역·대안 | P / D / L / A / C·O 핵심 차이 |
|---|---|
| 감지: polling | path는 서버 내부만; 명시적 poll step으로 D 우수; poll 사이 L 가능; UI는 coalesced update 가능; C·O 낮음 |
| 감지: inotify | path 이벤트 취급 주의; 커널 event coalescing/overflow로 L 완전 해결 안 됨; Linux 전용 C·O 상승; A 자체 효과 적음 |
| 감지: FSEvents | 디렉터리 계층 metadata 주의; latency/coalescing으로 L 가능; macOS 전용 C·O 상승; A 자체 효과 적음 |
| 감지: 외부 watcher | dependency·권한·path 처리 확대; 이벤트 순서 D/유실 L 재검증 필요; C·O 높음, A 직접 효과 없음 |
| 처리: 전파일 재실행 | raw 파일 반복 접촉(P), 지속 비용(C·O) 무한; 중복 publication(L), 읽기 위치(A) 교란; D도 rotation에 취약 |
| 처리: bounded micro-batch | raw TTL을 제한(P); event-time 정렬/parity로 D 증명 가능; late/gap L 경고 필요; 사용자 batch 반영(A); C·O 중간 |
| 처리: incremental state machine | 최소 raw retention 가능(P)하지만 별도 규칙 D drift 위험; 재시작 L 복잡; UI revision(A), C·O 최고 |
| 세션: 단일 process-local | raw 상태 한 곳(P), revision D 단순; crash L은 남음; UI 상태 A 단순; C·O 낮음 |
| 세션: 다중 | session 간 raw/권한 격리(P)·ordering(D)·gap(L) 어려움; UI 구분(A)·C·O 상승 |
| 세션: persistent DB | 삭제/backup(P)·checkpoint D/L 설계 필요; 재개 UI(A) 유리할 수 있으나 C·O 높음 |
| 시작: FROM_END | 기존 raw 재처리(P) 최소; 재시작 gap(L) 명시; D 간단, UI(A) 설명 필요, C·O 낮음 |
| 시작: FROM_START | 과거 raw backlog(P)·유실/중복(L) 경계 복잡; D 정렬 필요, UI(A) 초기 지연; C·O 높음 |
| 시작: checkpoint | 영구 offset/identity(P)와 atomicity(D/L) 필요; 재개 UI(A) 유리하나 C·O 높음 |
| 전달: polling | 반복 status 접촉(P), revision D 단순, gap L 비교 필요; UI(A) batch 가능; C·O 낮음 |
| 전달: SSE | 공개 DTO만(P), ID/revision D·replay L 필요; 조용한 UI(A) 적합; C·O 중간 |
| 전달: WebSocket | 양방향 입력 공격면(P), message order D·replay L 별도; UI(A) 이점 제한, C·O 높음 |

Phase 12 첫 구현의 정확한 최소 범위: application/SSH/access 중 **명시된 1개 source**만 활성화(여러 source는 후속 배치 동등성 검증 뒤), Linux Audit는 보류. Portable polling, FROM_END, 단일 session, regular-file/identity gate, chunk+complete-line reader, bounded parser/queue, count-only privacy-safe status와 SSE `snapshot/status/warning/heartbeat`, 합성 append simulation, browser의 조용한 상태 count와 표시 pause/resume, Ctrl+C shutdown. 이 시점에는 `observation/case_revision`을 생성하지 않으며 화면에 `탐지 동작 중`이라고 쓰지 않는다. 별도 Phase 12 후속 gate에서 bounded micro-batch가 기존 detector·correlation·risk·case 결과와 순열별로 일치함을 보인 다음 관찰 publication을 켠다. 이것은 v0.2.0의 궁극적 사용자 목표를 아직 완성하지 않는 의도적인 안전 단계다. Linux live parsing은 다중 record framing·privacy 한도를 별도 설계한 후에만 추가한다.

No-go: unbounded queue/list/history, raw event SSE, browser arbitrary path, recursive watch, silent overflow, rotation 추측 병합, 기존 threshold·risk·case 변경, input-order dependence, canary 노출, shutdown 후 task/thread/FD 잔존, 실제 sleep에 의존하는 test, hosted/public collector, event별 LLM. 기존 Path Traversal 반복 decoding을 live에서 bounded하게 실행할 수 있는지 입증 전에는 web 관찰 publication도 no-go다.

## 9. benchmark 및 구현 전 테스트 계획

Benchmark는 fixed synthetic inputs와 동일 머신·Python/OS metadata를 기록하고 저속 정상, 순간 burst, 지속 고속, 긴 줄, 많은 IP/account/distinct target, Linux multi-record burst(후속), 느린 SSE client, disconnect/reconnect를 사용한다. 측정: lines/s, bytes/s, parser/detector/correlation throughput, queue peak bytes, per-subject state peak, SSE frame 크기, browser DOM render cost, append→관찰 p50/p95/p99 latency, shutdown latency, rotation recovery. 평균뿐 아니라 peak RSS/tracemalloc와 p95/p99를 기록한다. 이 수치로 poll interval, chunk/line/partial, source count, queue item+byte, subject/history, replay/frame/connection, enqueue/send/shutdown timeout을 정하고 **한도 바로 아래/정확히/초과**를 고정 테스트한다. 합성 benchmark를 운영환경 탐지율/지연 보장으로 일반화하지 않는다.

결정적 fake clock·fake filesystem/explicit `poll_step()`를 사용해 실제 장시간 sleep 없이 다음을 시험한다: 한 줄 append, 여러 줄 append, partial UTF-8, newline 없는 partial, 긴 partial, invalid UTF-8, NUL/binary, truncation, rename rotation, copytruncate, 소실/재출현, 권한 상실, symlink swap, 중복 timestamp, 역순 timestamp, 정확한 detector 경계, queue full, slow consumer, SSE disconnect/reconnect·replay 성공·gap, cancellation, graceful shutdown, 강제 worker 예외, privacy canary, event/file permutation, UTC/KST, no leaked task/thread/FD. 동일한 합성 이벤트를 현재 batch pipeline과 live candidate에 넣어 detection endpoint/count, closest-success, risk, case rule/revision, independent 관찰과 JSON order를 비교한다. Late event가 한도를 넘는 경우는 **불완전 경고**여야 하며 parity 성공으로 포장하지 않는다. Actual filesystem integration test는 temporary file+rotation을 별도로 수행한다.

## 10. 연구 근거, 프로젝트 정책, 남은 한계

확인일: 2026-10-11. 아래 자료는 **인터페이스·실패 방식의 근거**이며 queue 숫자, polling 주기, 탐지 임계값의 외부 권위가 아니다.

| 공식 1차 자료 | 설계에 반영한 관찰 |
|---|---|
| [WHATWG Server-sent events](https://html.spec.whatwg.org/multipage/server-sent-events.html) | `text/event-stream`, `id`/`Last-Event-ID` 재연결, heartbeat·replay gap 고려 |
| [Python 3.12 asyncio Queue](https://docs.python.org/3.12/library/asyncio-queue.html), [Task cancellation](https://docs.python.org/3.12/library/asyncio-task.html) | nonzero `maxsize`, `put` 대기/timeout, cancellation `try/finally`·task join |
| [Starlette StreamingResponse](https://www.starlette.io/responses/) | async iterator로 SSE를 내보내되 연결 해제·slow consumer는 별도 구현/검증 필요 |
| [Linux inotify(7)](https://man7.org/linux/man-pages/man7/inotify.7.html), [Apple File System Events](https://developer.apple.com/documentation/coreservices/file_system_events) | 플랫폼별 notification이 달라 portable polling 선택; 변경 통지는 정확한 line 카운트가 아님 |
| [logrotate manual](https://github.com/logrotate/logrotate/blob/main/logrotate.8.in) | copytruncate 자체에도 손실 구간이 존재하므로 no-loss 주장 금지 |
| [NIST SP 800-92](https://csrc.nist.gov/pubs/sp/800/92/final), [SP 800-61 Rev.3](https://csrc.nist.gov/pubs/sp/800/61/r3/final) | 로그 관리와 조사 보조라는 범위; 관찰을 사고·침해 확정으로 과장하지 않음 |
| [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) | 입력 유래 민감값과 log injection을 운영 로그에 재출력하지 않는 경계 |

**Observable Evidence Mapping:** 파일 byte 증가·완전 LF 줄·parser가 만든 UTC event만 detector 입력 후보가 된다. IP·account join은 trusted bounded worker에서만, 웹 target은 bounded canonicalization/기존 승인 pattern 판단에만, Linux argv/path는 후속 별도 분류에만 쓴다. SSE에는 승인된 count/type/time/risk/confidence/limitation만 projection한다. Writer가 기록하지 않았거나 rotation 중 잃은 byte, 사용자 의도·공격 성공·인과관계·파일 유출은 이 telemetry로 성립하지 않는다.

**남은 한계:** 현재 batch detector는 live window semantics가 정의되어 있지 않고 Path Traversal decode는 반복형이다. Phase 12에서 bounded tail/status까지만 구현하고 관찰 publication은 parity·privacy·성능 gate까지 보류한다. Polling과 process-local memory는 crash·rotation·다른 local user·OS permission 문제에 대해 완전성/격리를 보장하지 않는다. 외부 인증·tenant isolation·배포 보호가 없으므로 hosted/public exposure는 계속 no-go다.
