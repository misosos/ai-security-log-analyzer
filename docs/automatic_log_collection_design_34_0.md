# Phase 34.0 — 자동 보안 로그 수집 설계 gate

## 후속 상태 — Phase 35.0 기업형 수집 연동

Phase 34 종료 판정은 합성 loopback 관리 pilot `GO`, 안내 이해도 최종 10/10 사용자 `PASS`, 실제 사용자 자료·조직 운영·인증 없는 원격 수집 `NO_GO`다. 과거 macOS SSH/SIGTERM 실패는 `UNEXPLAINED_NON_REPRODUCED`; 과거 Ubuntu smoke 실패의 내부 stage는 기록되지 않아 후속 local marker race와 같은 원인으로 단정하지 않는다. Phase 35.0은 공식 자료 정적 비교만 수행했으며, Vector 0.60.0 별도 프로세스 후보를 합성 연동 설계에 한해 `CONDITIONAL_GO`로 선정했다. collector는 설치·실행되지 않았고 자동 수집은 여전히 `NOT_IMPLEMENTED`다. [Phase 35.0 설계 기록](enterprise_log_collection_architecture_35_0.md).

## 후속 상태 — Phase 34.4 CLI management

Phase 34.4는 기존 loopback runtime을 application/SSH 단일 역할의 합성 전용 CLI 흐름에 연결했다. Phase 34.5의 정확한 SHA CI run `40308485200`에서 Ubuntu management subprocess smoke를 확인했고, 10개 사용자 안내 항목은 최종 PASS를 받았다. [구현 기록](loopback_tcp_syslog_management_34_4.md) · [수용 기록](loopback_tcp_syslog_management_acceptance_34_5.md). 실제 사용자 자료·조직 운영·원격 수집은 `NO_GO`다.

## 후속 상태 — Phase 34.3A Ubuntu bounded reliability

Phase 34.3A bounded Ubuntu reliability matrix는 시작 SHA `746c6d517fc27ca9a32b728b57df57c9912b2596`의 push CI run `40282366828`에서 `TCP_SYSLOG_LINUX_RELIABILITY_PASS roles=2 runs=80 synthetic=1 leaks=0`로 통과했다. 이는 기존 loopback runtime의 합성 반복성 범위만 확인하며 Phase 34.4 management 변경의 Ubuntu 결과를 대신하지 않는다.

## 후속 상태 — Phase 34.2

Phase 34.2는 [bounded loopback pilot](loopback_tcp_syslog_pilot_34_2.md)로 loopback-only listener를 추가하고 기존 application/SSH parser·결정적 분석 pipeline에 volatile in-process 연결을 구성했다. 합성 local pilot만 CONDITIONAL_GO이며 실제 사용자 자료·조직 운영·원격 수집은 NO_GO다. 정확한 수정 SHA의 Ubuntu CI smoke는 run `40274877704`에서 PASS했다. Phase 34.3 반복 lifecycle matrix는 로컬 macOS에서만 측정했으며 Ubuntu 확장 반복은 NOT_TESTED다. [Phase 34.3 수용 기록](loopback_tcp_syslog_acceptance_34_3.md).

Phase 34.3A는 별도 [Ubuntu bounded reliability step](loopback_tcp_syslog_linux_reliability_34_3a.md)을 준비했다. 새 SHA의 push CI 전까지 이 확장 검증은 `NOT_TESTED`다.

## 후속 상태 — Phase 34.1

Phase 34.0의 설계 gate를 바탕으로 [Phase 34.1 순수 core 구현](bounded_tcp_syslog_core_34_1.md)을 추가했다. immutable closed config, RFC 6587 octet-counting incremental decoder, in-memory bounded queue와 safe status DTO만 존재했다. **Phase 34.1 시점에는 listener·socket·network 송수신·parser/analysis 연결이 `NOT_IMPLEMENTED`였다.** Core status state는 listener 존재를 뜻하지 않는 `READY`로 닫혔다.

**판정: `CONDITIONAL_GO` — 설계와 계약만 진행 가능. 자동 로그 수집은 `NOT_IMPLEMENTED`.** 이 단계에서는 네트워크 listener, 외부 collector, AI 모델, dependency를 설치·실행·구현하지 않았다. 문서와 문서 계약 테스트만 추가한다. 아래 수치는 구현 전 합성 평가를 위한 설계 상한 후보이며, RFC나 외부 프로젝트가 보장한 값 또는 운영 SLA가 아니다.

## 시작 gate와 Phase 33 종료

- 시작 SHA `bab03903629ec75bd7fae0221586bf167052b831`; branch `main`, clean tree, local `main`과 `origin/main` 일치, ahead/behind `0/0`.
- [push CI run 40212889491](https://github.com/misosos/ai-security-log-analyzer/actions/runs/40212889491)은 정확한 SHA에서 `completed/success`였다. Ubuntu 24.04 locked Python 환경과 lock 검증, 전체 pytest **2725 passed, 2 warnings**, Linux restricted-report subprocess smoke `RESTRICTED_REPORT_LINUX_SMOKE_PASS roles=3 audit_rows=6 fs=ext4`, Linux bounded benchmark, Chromium·axe **14 states**, `external_requests=0`, tracked-file 불변 단계가 성공했다.
- 저장 CI artifact **0개**. `v0.4.0` tag/Release target은 기존 `eecd6ee1cda0545e34b01c42e1a2163a899bcc27`을 유지했다.
- Phase 33.5D의 10개 안내 항목은 최종 사용자 응답 `PASS`다. 이 결과는 합성 제한 보고서 안내 범위만 `CONDITIONAL_GO`로 둔다. 실제 자료 export와 조직 사용은 `NO_GO`다.
- Phase 33.2 embedding production 통합은 `NO_GO`; Phase 33.3F local LLM 실행·production 연결은 `STORAGE_SETUP_BLOCKED`다. Phase 34는 제한 보고서, embedding, LLM, Gemini 경계를 확장하지 않는다.

## 목적·범위

사용자가 로그 파일을 직접 준비해야 하는 현재 한계를 줄이기 위한 장기 설계다. 첫 pilot 후보는 **loopback 전용 TCP Syslog**, **application 또는 SSH 중 명시적으로 선택한 단일 역할**, 단일 listener, 최대 2개의 동시 연결, RFC 6587 octet-counting framing이다. 완성 메시지는 UTF-8로 검증한 뒤 해당 역할의 기존 parser와 결정적 분석 pipeline에 전달한다. 웹 access 수집, 서로 다른 역할을 잇는 cross-source correlation, 새 탐지 규칙은 포함하지 않는다.

첫 pilot에서도 제외:

- UDP, 외부 인터페이스 bind, 인터넷 노출, TLS/mTLS 없는 원격 송신, 다중 tenant, 자동 장비 탐색
- journald·Windows Event Log·cloud API 직접 연결, SIEM 양방향 연동, 파일 tail의 동작 변경
- 무제한 연결·메모리·queue, exactly-once 또는 무유실 보장, 자동 parser 생성·적용
- AI가 source identity, 탐지, 위험도, 이벤트 폐기 또는 대응을 결정하는 동작
- raw message를 public API, SSE, UI, 공개 HTML, 오류, metrics, checkpoint에 넣는 동작

## Research Basis

2026-10-26에 공식/1차 자료를 확인했다.

- [RFC 5424](https://www.rfc-editor.org/rfc/rfc5424.html)는 Syslog 메시지와 UTF-8 관련 규칙, 수신기 메시지 크기 고려를 정의한다. [RFC 6587](https://www.rfc-editor.org/rfc/rfc6587.html)는 TCP octet-counting을 `MSG-LEN SP SYSLOG-MSG`로 정의하고 delimiter 기반 framing의 모호성을 설명한다. RFC 6587은 Historic 문서이며, 그 자체를 현재 보안 전송 권고로 취급하지 않는다. RFC 5424는 보안 전송에 TLS 기반 transport를 권고한다.
- [Python asyncio streams](https://docs.python.org/3.12/library/asyncio-stream.html)는 `start_server`, `readexactly`, `StreamReader`의 limit 및 overrun 동작을 설명한다. `limit` 하나만으로 애플리케이션 전체 resident memory 상한이 증명되는 것은 아니다. 구현 시 parser buffer, active connections, queue, message copy를 별도로 계산하고 테스트해야 한다.
- [Fluent Bit Syslog input](https://docs.fluentbit.io/manual/data-pipeline/inputs/syslog), [backpressure](https://docs.fluentbit.io/manual/administration/backpressure), [공식 매뉴얼·라이선스](https://docs.fluentbit.io/manual/)는 TCP/Unix socket Syslog 입력, 메시지 buffer 및 queue backpressure 옵션, Apache-2.0 라이선스를 설명한다. 파일 buffer 사용은 persistent data를 남길 수 있으므로 이번 pilot의 raw-message 비보존 원칙과 다르게 구성될 수 있다.
- [Vector Syslog source](https://vector.dev/docs/reference/configuration/sources/syslog/)는 TCP/UDP/Unix socket, `max_length`, connection limit과 origin filtering 구성을 제공한다. [Vector 공식 저장소](https://github.com/vectordotdev/vector)는 MPL-2.0을 표시한다. 이 자료는 기능 비교만 뒷받침하며 특정 release artifact나 dependency closure를 승인하지 않는다.
- [OpenTelemetry Collector security best practices](https://opentelemetry.io/docs/security/config-best-practices/)는 최소 component, 인증·암호화, 제한된 bind, 낮은 권한을 권고한다. [resiliency guidance](https://opentelemetry.io/docs/collector/resiliency/)는 bounded queue가 차거나 retry 기간이 지나면 data loss가 가능하고 file storage는 WAL 자료를 남길 수 있음을 설명한다. [공식 Collector 저장소](https://github.com/open-telemetry/opentelemetry-collector)의 라이선스는 core repository 기준 Apache-2.0이며, 배포판/collector component 구성은 별도 closure가 필요하다.
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)는 외부 trust zone의 로그를 누락·변조·위조·replay 가능한 untrusted input으로 취급하고 민감정보 최소화, 접근 제어, 안전한 전송, log injection 방어를 다룬다. [NIST SP 800-92](https://csrc.nist.gov/pubs/sp/800/92/final)는 log management 계획을 다루는 2006 최종본이며, [SP 800-92 Rev. 1](https://csrc.nist.gov/pubs/sp/800/92/r1/iprd)은 2023년 초안 상태 자료다. 두 문서 모두 이 프로젝트의 숫자 상한을 정하지 않는다.

### Observable Evidence Mapping

현재 parser와 analysis pipeline은 application·SSH의 source role 별 관찰과 지원 관계를 처리한다. 따라서 pilot은 frame을 해당 단일 role로만 넘기고, 기존 parser가 받아들이는 입력 표현을 재사용해야 한다. TCP peer address나 Syslog의 HOSTNAME 필드는 송신 신원의 인증 근거가 아니다. message의 timestamp와 body도 송신자가 제공한 untrusted data다. 기존 file checkpoint는 파일 identity·offset 복구를 위한 것이므로 TCP connection sequence나 재시작 지점으로 재사용할 수 없다.

현 코드에는 TCP 수집 상태·frame parser·TCP checkpoint 계약이 없다. 이 설계는 observable detection/correlation meaning이나 event identity를 새로 정의하지 않는다. 분석 window/누적 상태를 frame 단위 입력에 연결하는 구체적인 handoff는 Phase 34.1/34.2 전에 기존 pipeline producer와 consumer를 다시 대조해 닫아야 한다. 기존 분석을 우회하거나 새로운 의미를 유추하면 중단한다.

## 수집 아키텍처 비교와 첫 pilot 선택

| 후보 | 플랫폼·권한 | 운영/신뢰·backpressure | 유실·중복·rotation·개인정보 | parser 연결·공급망·검증 |
|---|---|---|---|---|
| Loopback TCP Syslog | macOS·Ubuntu 표준 socket; 비특권 임의 포트로 bind 가능 | 한 프로세스/한 listener로 경계 단순화. loopback은 같은 호스트 프로세스를 인증하지 않음. 작은 연결·byte queue와 명시적 reject/drop 계수 필요 | 파일 rotation 없음; 재연결·ack 전후 crash에서 유실/재전송/중복 가능. raw는 parsing 동안 memory에만 후보 | 현재 TCP framing/parser adapter는 없음. stdlib socket/asyncio로 별도 dependency 없이 합성 검증 가능 |
| Unix domain socket | Unix 계열; socket 권한/parent 디렉터리 소유권 설정 필요 | 경로 권한이 추가 접근 경계이나 same-UID/권한 있는 로컬 프로세스 위협은 남음. 연결 backpressure 직접 설계 | 파일 rotation 없음; client reconnect/ack 계약은 여전히 필요. socket path와 메모리에 raw 존재 가능 | socket path lifecycle/stale node와 macOS·Linux 차이 검증 필요; 기존 syslog parser 연결은 TCP와 유사 |
| journald reader | systemd 플랫폼; journal 접근은 계정/group/ACL 권한에 좌우 | 권한과 system service coupling이 큼; journal 자체의 저장·보존·rotation을 앱이 통제하지 않음 | journal cursor를 둘 별도 checkpoint 필요; vacuum/rotation/권한 문제 별도 | macOS에 systemd 없음; Linux 전용 adapter 및 native/system integration 검토 필요. pilot portability 낮음 |
| 기존 file tail 확장 | 현재 지원되는 macOS·Linux 흐름과 연속 | 파일 permission/locking/checkpoint와 rotation 복잡도가 이미 있음. TCP 상태와 합치면 lifecycle coupling 증가 | file identity·offset·rotation·replay 의미 변경 위험 | 기존 checkpoint/pipeline을 재사용하기 쉽지만 요구한 독립 namespace와 분리 기준을 해칠 수 있음. 이번에는 확장하지 않음 |
| Fluent Bit | Linux·macOS 등 폭넓은 플랫폼, daemon/agent 배포 고려 | 성숙한 Syslog input 및 memory/filesystem backpressure; 설정·plugin·service 권한과 운영 부담 추가 | filesystem buffering/DLQ는 persistent raw/processed data를 만들 수 있고 queue overflow/drop 의미가 구성에 따라 다름 | 기존 parser로의 data contract adapter 필요. Apache-2.0 core; release, plugin, binary checksum/signature와 full closure 미검토 |
| Vector | 공식 Syslog source TCP/UDP/UDS 지원; 배포 binary/agent 운영 | connection_limit·max_length 등 기능. component/config/buffer 운영 복잡도와 trust mapping 추가 | source와 sink 설정에 따라 buffering/persistence 및 delivery semantics가 달라짐 | output-to-current-parser adapter 필요. MPL-2.0 repository; pinned release/artifact closure 미검토 |
| OpenTelemetry Collector | 여러 OS/deployment 지원, component distribution 선택 가능 | receiver/processors/extensions 구성, 낮은 권한·최소 component·secure endpoint 필요. queue/WAL 구성에 따라 persistence와 loss semantics 달라짐 | exporter queue/WAL은 raw/telemetry를 남길 수 있음; crash/disk/timeout loss 보장 불가 | Syslog receiver/component availability와 정확한 distribution을 고정해야 함. core Apache-2.0; component closure 미검토 |

**후보 선택:** loopback TCP Syslog를 별도 단일-source pilot 후보로 선택한다. 이는 사용자가 명시한 자동 수집 목표와 직접 연결되며, 외부 package/daemon 없이 pure framing 테스트를 계획할 수 있다. Unix socket은 로컬 권한 경계를 제공할 수 있지만 socket path lifecycle과 platform-specific behavior가 첫 네트워크 수신 경계보다 유리하다고 아직 증명되지 않았다. journald는 macOS와 맞지 않고 privilege/system coupling이 있다. 파일 tail 변경은 기존 회귀 경계를 위험하게 넓힌다. 외부 collector는 기능상 대안이지만 이번 pilot의 공급망·buffer persistence·integration surface를 늘린다. 어느 후보도 이번 단계에서 실행/설치하지 않았다.

Fluent Bit·Vector·OpenTelemetry Collector는 **외부 권장 adapter 대안**으로만 둔다. source revision, exact release artifact, checksum/signature/provenance, license 및 transitive license, plugin set, runtime permission을 닫기 전에는 다운로드·설치·실행하지 않는다. 외부 collector output도 untrusted input으로 validate/parse한 뒤 기존 pipeline에 넣는다.

## 별도 config·상태·공개 DTO 후보

TCP 수집 설정은 별도 closed schema 후보(`tcp-syslog-config/v1`)이며 기존 v1/v2 단일-file, v3 pair-file 설정에 넣지 않는다. 최소 입력은 `schema_version`, `source_role` (`application` 또는 `ssh`), 명시적 loopback bind family/address, 비특권 port, 고정 `octet_counting` framing, 상한 묶음뿐이다. unknown field, non-loopback address, unsupported role/framing, 상한 초과는 고정 오류로 거부한다. 설정·상태·checkpoint directory/identity는 file monitor와 분리한다. TCP state는 file offset checkpoint가 아니며 reconnect는 `FROM_END`/file recovery와 같은 뜻이 아니다.

상태 전이 후보:

```text
STOPPED → STARTING → LISTENING
                      ↘ DEGRADED → LISTENING (명시적 복구 조건에서만)
                      ↘ FAILED → STOPPED
LISTENING → STOPPED
```

`DEGRADED`는 과부하, 반복 parser reject, publication/analysis failure 등으로 수집 completeness가 낮아졌음을 나타내며 정상으로 표시하지 않는다. 예외가 해결됐다고 추정해 자동으로 healthy로 전환하지 않는다. 종료 요청은 신규 accept를 중단하고 기존 connection을 제한 시간까지 drain한 다음 listener, task, buffer를 닫는다. 반복 close는 안전한 no-op 후보로 테스트하지만, 강제 종료·전원 장애 복구는 보장하지 않는다.

공개 status DTO closed field 후보: `schema_version`, `role`, `collection_mode`, `listener_active`, `active_connections`, `connection_limit`, `received_count`, `accepted_count`, `rejected_count`, `dropped_count`, `queue_events`, `queue_event_limit`, `queue_bytes`, `queue_byte_limit`, `last_success_at | unavailable`, `state`, `error_category`, `next_action`. 주소 상세·port·peer·socket path·host name, message, account, parser rationale, exception text와 file path는 포함하지 않는다. 오류 category와 next action은 고정 enum/문구다. count의 증가/초기화는 monitor instance epoch 내에서만 해석한다.

## TCP framing·validation 계약 후보

RFC 6587 octet-counting 우선, newline/non-transparent framing fallback 없음. 첫 pilot 구현 후보 상한은 decimal prefix 최대 **6자리**, payload 최대 **8192 octets**, prefix grammar는 `[1-9][0-9]{0,5} SP`로 제한한다. 이는 RFC 문법의 하위집합을 받는 프로젝트 heuristic이며 RFC가 요구한 메시지 크기/호환 보장이 아니다. 0 길이, 부호, 공백 변형, leading zero, overflow, 최대 초과는 reject 후 connection close. Prefix를 읽는 동안도 6 digits+separator를 넘지 않는 고정 buffer만 둔다.

선언 길이만큼 정확히 읽는다. incomplete header/payload 뒤 EOF는 reject로 계수하고 event로 만들지 않는다. 한 read에서 여러 frame은 순서대로 parse하되 queue 상한 검사를 매 frame마다 한다. 선언 길이보다 payload가 짧으면 더 이상 기다리다 EOF/idle timeout 시 거부한다. 길이보다 “긴” payload는 뒤 byte를 다음 frame prefix로 해석하는 TCP stream의 정상 특성이므로, 현재 frame에 초과 byte를 붙이지 않고 parser가 후속 frame을 독립 검증한다. framing 상태가 어긋나면 해당 연결을 닫고 재동기화를 추측하지 않는다.

Payload는 strict UTF-8 decode; invalid UTF-8, NUL, C0/DEL control, forbidden line/control delimiter, malformed Syslog header, message에 정의된 parser byte/field 상한 초과는 고정 reject category와 connection close 후보로 처리한다. 본문 텍스트는 untrusted data다. 송신자 HOSTNAME, account, PRI/severity, timestamp를 인증된 source identity나 trusted time으로 승격하지 않는다. raw payload는 bounded in-memory frame과 parser 호출 동안만 보유하고 reject reason/metrics에는 category/count만 남긴다. Python immutable bytes/string copy, allocator, swap/core dump까지 zeroization을 보장하지 않는다.

## Backpressure와 연결 상한 후보

설계 상한(합성 pilot에서 검증할 값): 최대 2 connections; connection당 framing buffer 최대 `8192 + 7` bytes; 전체 queue 최대 256 events 및 1 MiB serialized-byte estimate; 처리 budget은 role별 batch 최대 32 events. Queue의 byte accounting에는 Python object overhead가 포함되지 않으므로, process RSS는 별도 관측하고 추가 safety headroom을 둔다. 실제 구현 전 한 message를 동시에 frame, decoded text, normalized event로 보유할 때의 memory multiplier를 측정해야 한다.

Queue full이면 조용히 drop하지 않는다. 새 메시지는 `rejected` 또는 `dropped` 중 실제 확정 단계에 맞춰 한 번만 계수하고, status를 `DEGRADED`로 바꾸며 sender connection을 닫는다. `accepted`는 bounded queue에 들어가 기존 analysis handoff가 수락한 경우에만 증가; “탐지됨”이나 durable 저장을 뜻하지 않는다. read pause가 sender를 보호한다는 가정만 하지 않으며 TCP peer는 재전송할 수 있고 buffer가 더 앞단에 쌓일 수 있다. 재시도 여부를 수집기가 보장하지 않으며 duplicate 가능성을 기록한다. Connection limit 초과는 고정 reject counter를 증가시키고 message를 읽거나 기록하지 않은 채 신규 connection을 닫는다.

Parser/analysis 지연 시 bounded queue를 넘기지 않도록 추가 read를 pause하고 짧은 idle/processing timeout 후보를 적용한다. timeout이나 queue full 이후 drop/reject는 명시적 상태와 count에 반영한다. 자동 retry, disk spool, dead-letter, persistent queue는 첫 pilot에서 제외한다. 이 값은 운영 처리량이나 무유실 성능 주장이 아니다.

## 신뢰 경계·listener lifecycle

Loopback은 외부 interface exposure를 줄이지만 local authentication이 아니다. same UID 또는 로컬 악성 프로세스가 메시지를 주입할 수 있고, bind address 재해석·port race·listener hijacking을 가정한다. IPv4/IPv6 loopback은 명시적으로 선택하며 wildcard `0.0.0.0`/`::` bind를 거부한다. privileged port는 요구하지 않고 non-root를 우선한다. source identity는 사용자가 명시한 단일 role로만 정해지며 payload의 IP/hostname으로 role을 추론하지 않는다.

Bind 실패/port 경쟁은 `FAILED`와 고정 `BIND_UNAVAILABLE` category로 닫는다. 이미 점유된 listener를 교체하거나 강제로 종료하지 않는다. listener가 의도치 않게 close되면 `FAILED`; 재시작은 별도 명시적 재실행이며 새 epoch다. stale socket은 TCP에는 없지만 stale process/port 상태를 공개값 없이 안전하게 진단해야 한다. 파일 모니터와 TCP를 같은 role에 동시에 허용하지 않는 것이 첫 pilot 기본안이다. TCP enable/disable은 file config/checkpoint를 삭제·초기화하지 않는다.

첫 pilot은 신뢰된 단일 호스트의 합성 메시지 전용이다. 원격 수집은 TLS/mTLS 또는 동등하게 인증된 collector 경계, source authorization, replay policy, retention/storage review 전까지 `NO_GO`. TLS가 없는 TCP Syslog는 외부 네트워크에서 기밀성·송신자 인증을 제공하지 않는다. loopback만으로 원격 use case를 정당화하지 않는다.

## 기존 pipeline·API/SSE 호환성

Pipeline은 다음 책임을 유지한다: framed bytes → strict Syslog envelope validation → 선택된 application/SSH role에 허용된 body를 기존 parser가 받는 입력 형태로 전달 → 기존 normalized schema → 기존 detection/correlation/risk/case. Syslog envelope와 parser 간 adapter 형식은 34.1에서 기존 parser 입력 contract를 확인해 고정한다. 현재 parser가 지원하지 않는 payload variant는 거부하며 임의 변환하지 않는다. Syslog header hostname·timestamp는 authenticated identity/time으로 사용하지 않고, 기존 schema가 명시적으로 수용하지 않으면 분석 입력에서 제외한다. 수집 adapter가 탐지 의미를 새로 만들지 않는다. 기존 사례·risk 결과는 권위 있는 기존 계산 결과다. Application과 SSH를 같은 listener에서 혼합하지 않으며 cross-source correlation은 제외한다.

기존 v1/v2 single-file 및 v3 pair-file runtime·checkpoint·replay·publication은 유지한다. TCP는 독립한 `tcp_syslog` config/status/checkpoint namespace 및 새 run epoch 후보를 사용한다. TCP sequence/counter를 file offset처럼 복구하지 않는다. 새 epoch는 이전 분석을 재게시/초기화/삭제하지 않으며, UI/API가 instance identity를 명확히 분리하지 못하면 public integration을 하지 않는다. 기존 schema 2/3 status/SSE는 그대로 둔다. TCP status를 노출하려면 별도 schema/version/API/SSE contract와 public privacy review가 필요하다. Phase 34.0은 endpoint, API, SSE, UI를 추가하지 않는다.

## Failure semantics

| 실패 | 계약 후보 | 유실·중복/재처리 의미 |
|---|---|---|
| bind 실패·port 경쟁 | `FAILED`, 고정 category; listener 교체 없음 | 입력 수락 전이므로 수신 없음 |
| accept 실패·연결 제한 | `DEGRADED` 또는 `FAILED`; 신규 connection 거부/close, bounded count | 송신자가 재전송할 수 있지만 수집기가 약속하지 않음 |
| malformed/oversized prefix/frame | connection close; reject count/category만 | 해당 frame 미전달; 이어진 bytes는 재동기화하지 않음 |
| incomplete frame/EOF | reject, 정상 event 생성 금지 | 불완전 payload 유실 |
| invalid UTF-8/control | reject 후 close; 원문 보관 금지 | frame 미전달 |
| queue full | accepted로 세지 않고 drop/reject 분리, `DEGRADED`, close | 앞단/송신자 재전송 여부에 따라 유실·중복 가능 |
| parser 거부 | fixed parser category/count; raw 없이 다음 frame 처리는 연결 계약에 따름 | 거부 frame은 분석되지 않음 |
| analysis handoff/ack 전 실패 | queue 항목을 수락 처리하지 않음; 상태 degraded/failed | in-memory queue process 종료 시 유실 가능 |
| analysis ack 후 publication 실패 | 이미 확정된 내부 분석을 rollback했다고 말하지 않음; publication failure 고정 상태 | 재시도 범위/중복 게시는 별도 contract 전 미보장 |
| TCP state/checkpoint write 실패 | TCP adapter를 `FAILED`; file checkpoint 수정 금지 | last durable cursor가 없으므로 restart 후 중복 또는 유실 가능 |
| SIGINT/SIGTERM/listener close 실패 | 신규 accept 차단, connection/task/buffer close를 각각 시도; 비정상 close는 고정 오류 | 정상 종료여도 pending in-memory frame/queue는 유실 가능 |
| 반복 close | 소유 자원에 대해 idempotent cleanup 후보; 반복 fault 테스트 | 이미 publication된 결과 rollback 아님 |
| crash/SIGKILL/power loss | 보장 없음 | memory queue 유실, OS buffer 재전송에 따른 duplicate 가능 |

모든 외부 상태·오류에는 raw message, peer address, account, host, path, exception string이 없다. 오류 발생이 이전 분석의 rollback·재분석·삭제를 뜻하지 않는다. “accepted”, “processed”, “published”는 별개의 단계로 정의해야 한다.

## Privacy·retention·metrics

Raw message는 bounded frame/parser memory에서만 일시 보유하는 후보다. persistent spool, dead-letter, packet capture, trace payload, rejected-frame log는 기본 생성하지 않는다. Checkpoint에는 raw payload 대신 제한된 role/epoch/sequence/analysis state metadata만 후보로 둔다. Metrics는 고정 category와 aggregate counts만 허용하고 label에 account/IP/hostname/port/path/raw string을 넣지 않는다. CI는 합성 input만 사용하고 input/trace/pcap artifact를 업로드하지 않는다.

제한은 프로세스 memory만을 다룬다. swap, core dump, crash reporter, host compromise, process inspection, same-UID attacker, OS log, backup은 잔여 위험이다. 분석 권한이 있는 실행 계정이 socket으로 허용하지 않은 입력을 주입할 수 있다는 local threat도 남는다. Parser는 length/framing, encoding, field count/size, CR/LF/control abuse에 fail closed 한다. Payload 안의 prompt injection은 단지 untrusted text이며 어떠한 tool, file, network, parser config를 실행하지 않는다.

## AI 활용 경계

Phase 34 수집은 결정적 framing·validation·기존 parser adapter부터 검증한다. 향후 별도 gate에서만 익명 통계 요약, parser 후보/필드 mapping 초안(사람 승인 필수), 수집 품질 설명, 승인된 safe DTO의 조사 도움말을 검토할 수 있다. Raw log의 외부 AI 전송, 자동 parser 적용, AI에 의한 drop/source identity/trust/detection/risk/response 결정, injection에 따른 tool/file/network 호출은 금지한다. 첫 pilot은 AI를 실행하지 않는다. Embedding은 production `NO_GO`; local LLM은 `STORAGE_SETUP_BLOCKED`; Gemini helper는 연결·수정하지 않는다.

## Failure/threat model

대상 위협은 local unauthorized process injection, framing desynchronization, slowloris, connection flood, enormous declared length, queue/memory exhaustion, parser confusion, Unicode/control abuse, replay/duplicate, source spoofing, prompt-injection text, PII in error/metric/trace, listener hijacking, restart/port collision, external collector supply chain, admin/same-UID attacker, swap/core dump, crash 및 host compromise다. Mitigation 후보는 explicit loopback bind, non-root, single role/listener, strict prefix+payload bounds, bounded active connection/read timeout/queue, close-on-protocol-error, closed DTO, aggregate-only diagnostics, no spool, no auto-restart/role inference, dependency-free initial adapter, and fault/property testing이다. These limits reduce exposure but do not authenticate local senders or guarantee delivery, confidentiality on remote links, or host integrity.

주요 residual risks: local processes can inject fabricated events; count-only status cannot explain a particular rejected record; transport reconnect may duplicate or lose frames; memory caps do not cap OS buffers/process overhead precisely; swap/core dump and forced termination can preserve or lose transient data; local host compromise bypasses process-level trust boundaries. TLS/mTLS and authenticated remote collection remain separate design gates.

## Validation roadmap

1. **Phase 34.1 — pure framing/config contract:** implemented in [`bounded_tcp_syslog_core_34_1.md`](bounded_tcp_syslog_core_34_1.md); incremental octet-count parser, digit/length/control/UTF-8/EOF/multi-frame properties, closed config/status DTO, fixed buffer/queue model, fuzz/property tests. No listener, public UI or production integration.
2. **Phase 34.2 — loopback isolated synthetic smoke:** implemented in [the pilot record](loopback_tcp_syslog_pilot_34_2.md); Ubuntu CI run `40274877704` passed at its exact SHA. Phase 34.3 extended repetition is separately recorded as macOS-local evidence; its Ubuntu matrix remains NOT_TESTED. No real user log.
3. **Phase 34.3 — independent Ubuntu validation:** locked environment, subprocess smoke, overload/longer soak, listener/FD/memory lifecycle, SIGINT/SIGTERM and actual status review. User acceptance is synthetic and separate.
4. **Phase 34.4+ — separate gates:** authenticated remote collector and TLS/mTLS, additional source adapters, deployment/retention policy, AI parser suggestion isolated supply-chain and evaluation pilot. No phase is implied approved by this design.

### Phase 34.1/34.2 entry and stop criteria

Proceed to 34.1 only if the pure parser can enforce finite prefix, frame, buffer and queue limits without changing existing file config/runtime. Stop if parser bytes cannot be safely routed through the existing role parser, internal analysis state would be mutated via presentation/retrieval, raw data must be written to public status/logs, a dependency is required, or the file checkpoint namespace must be reused. 34.2 additionally requires passing property tests, explicit synthetic config, fixed public status projection and a subprocess boundary review. Any canary in public API/SSE/UI/report, silent queue drop, wildcard bind, ambiguous accepted/ack semantics, or cleanup failure is NO_GO. Neither phase entry approves real logs or remote collection.

## Limitations and verdict

Research documents framing, secure transport guidance, component capabilities and risks; it does not prove that this project's runtime, parsers, operating systems or resource budgets meet production requirements. The queue/frame values above are engineering hypotheses to test, not source-backed operating limits. RFC 6587 describes legacy TCP framing and is Historic; no remote unauthenticated transport is approved. Collector docs are not an endorsement to install them; exact versions/artifact provenance/transitive closure were not assessed. NIST SP 800-92 Rev. 1 remains draft as checked on the research date.

**Phase 34.0 설계만 `CONDITIONAL_GO`; 자동 로그 수집 `NOT_IMPLEMENTED`.** 원격 수집은 인증·암호화 전까지 `NO_GO`; AI parser 제안은 별도 공급망·격리·평가 gate 전까지 `NO_GO`. No listener/collector/model was downloaded, installed, run, or implemented. No dependency, lockfile, API, SSE, UI, CI, version, public report, detection, correlation, risk, or case behavior changed.
