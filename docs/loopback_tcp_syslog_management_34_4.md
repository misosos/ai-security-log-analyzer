# Phase 34.4 — loopback TCP Syslog 사용자 설정·실행·상태 관리

## 판정과 범위

Phase 34.4는 application 또는 SSH 중 한 역할을 선택하는 **로컬·합성 입력 전용 CLI management pilot**이다. 설정 마법사, 안전 요약 조회, foreground 실행, 별도 endpoint 표시, 설정 삭제를 기존 명령 `uv run python -m app.monitor_setup`에 추가했다. 기존 파일 설정의 의미와 v1/v2/v3 계약은 유지한다.

이 구현은 실제 장비·사용자 로그·조직 운영에 승인되지 않았다. 원격 호스트, 외부 interface, 인증 없는 원격 수집은 `NO_GO`다. TLS/mTLS, durable spool, checkpoint, 재시작 복구, 자동 재연결, exactly-once·무유실은 지원하지 않는다. TCP 결과는 공개 API·OpenAPI·SSE·UI·HTML 보고서에 게시하지 않는다. embedding production 통합은 `NO_GO`, local LLM은 `STORAGE_SETUP_BLOCKED`로 유지한다.

Phase 34.4 management의 Ubuntu subprocess smoke는 정확한 SHA `961e279c19ae848d405724cc09d71bfba5cfbb38`의 push CI run `40308485200`에서 통과했다. 이후 Phase 34.5에서 합성 CLI 캡처를 사용한 10개 안내 항목의 사용자 이해도 검수를 완료했다. 사용자 응답과 범위는 [Phase 34.5 수용 기록](loopback_tcp_syslog_management_acceptance_34_5.md)에 분리해 기록했다. **합성 loopback management 안내 범위만 `CONDITIONAL_GO`**다.

## CLI 흐름

| 동작 | 명령 | 동작 |
|---|---|---|
| 설정 | `uv run python -m app.monitor_setup --setup-tcp-syslog` | 역할, IPv4/IPv6 loopback, 높은 포트를 묻고 고정된 profile을 저장한다. |
| 요약 조회 | `uv run python -m app.monitor_setup --show-tcp-syslog` | role, family, 권한과 안전한 다음 행동만 보여준다. |
| 실행 | `uv run python -m app.monitor_setup --run-tcp-syslog` | 검증된 설정으로 foreground 수집을 시작한다. `Ctrl+C` 또는 `SIGTERM`으로 끝낸다. |
| 연결 정보 표시 | `uv run python -m app.monitor_setup --reveal-tcp-syslog-endpoint` | 실행 중일 때 별도 정확한 승인을 받고 주소와 port를 한 번 표시한다. |
| 설정 삭제 | `uv run python -m app.monitor_setup --delete-tcp-syslog` | 정확한 승인 후 TCP 설정만 삭제한다. |

설정 마법사는 같은 컴퓨터의 프로그램만 연결할 수 있는 loopback 범위, application/SSH 역할, 길이가 포함된 TCP 메시지 형식, 고정 상한, 중단 중 유실·sender 재전송 중복, 원격 미지원, 공개 화면의 원문 비표시와 외부 AI 미전송을 설명한다. TCP 연결만으로 송신자 신원이 인증되지 않으며 TLS·mTLS를 제공하지 않는다는 점을 명시한다. 저장 승인은 `TCP Syslog 설정 저장을 승인합니다`와 정확히 일치해야 한다. 오타·EOF·`Ctrl+C`에서는 config를 생성하지 않는다. 설정 위치는 사용자에게 출력하지 않는다.

입력 선택은 application 또는 SSH, IPv4 `127.0.0.1` 또는 IPv6 `::1`, `49152–65535` 범위의 port뿐이다. privileged port와 port 0은 거부한다. 입력 형식은 strict ASCII decimal로 제한한다. 저장 전에 현재 bind 가능 여부를 확인하지만, 그 검사 뒤 port 경쟁은 가능하므로 실행 시 다시 bind가 확인된다. 내부 config에는 port가 필요하지만 show·일반 오류·실행 요약·audit·문서에는 실제 주소나 port를 넣지 않는다.

## Private config와 상호 배제

TCP 설정은 별도 closed `tcp-syslog-user-config/v1` JSON이며 정확히 `schema_version`, `source_role`, `bind_family`, `port`, `runtime_profile` 필드만 가진다. Role, family, port는 합성 pilot 설정값이고 file source path·credential·raw message·checkpoint를 저장하지 않는다. 실제 config 경로는 기본 monitor 설정과 같은 private application config 디렉터리의 별도 파일로 결정된다. 설정 파일은 `0600`, 최종 parent는 현재 사용자 소유 `0700`이어야 한다. symlink, regular-file 아닌 target, unsafe parent/owner/mode, hard link, unknown field, duplicate key, oversized 또는 손상 JSON은 거부한다. show는 손상 설정을 “없음”이나 “안전함”으로 보고하지 않고 `검토 필요`로 안내한다. 기존 파일은 no-clobber로 보존한다. temp 파일은 같은 private directory에서 `0600`으로 만들고 write/fsync 후 hard-link 기반 no-replace publish를 수행한 뒤 temp 이름을 제거하고 directory fsync와 재-open 검증을 한다. 이 파일 계약은 모든 filesystem이나 전원 장애까지의 보장을 뜻하지 않는다.

TCP runtime은 기존 file 설정·checkpoint와 별도다. file monitor 실행과 TCP 실행은 같은 private collector lock으로 상호 배제하며, TCP는 별도의 TCP lock도 고정 순서로 얻는다. lock 획득 실패, 두 번째 TCP run, 실행 중 setup/delete는 listener를 열거나 config를 변경하기 전에 거부한다. 시작 실패와 종료 때 각 lock을 해제하며 lock 파일 자체는 private directory에 남을 수 있다. 같은 UID의 비협력 프로세스가 파일이나 프로세스를 조작하는 것을 인증·RBAC으로 막는 설계는 아니다.

기존 file `v1/v2/v3` 설정, checkpoint와 reset 의미는 바꾸지 않는다. TCP에는 checkpoint를 만들거나 재사용하지 않는다. setup/delete 중 기존 file 설정과 checkpoint, 원본 sender 자료, 이미 확정된 분석 결과는 변경하지 않는다. TCP 설정을 지워도 이들은 삭제·rollback되지 않는다.

## 상태·개인정보·endpoint

`--show-tcp-syslog`는 설정 존재, 한국어 role 설명, loopback-only, 주소 family, 권한 적합 여부, “길이가 포함된 TCP 메시지”, 최대 연결 2개, queue bounded 여부, 재시작 때 과거 메시지를 복구하지 않는다는 점, 인증·암호화 부재와 다음 행동만 표시한다. 주소·port·설정 경로·socket·raw message·account·IP·hostname·credential·parser rationale·내부 exception/code/repr는 일반 화면에 표시하지 않는다.

`--run-tcp-syslog`는 시작 상태와 5초 간격의 제한된 집계를 보여준다. 집계는 수신, 거부, 내용 인식, 형식 미인식, 분석 완료, 처리 중 폐기, 연결 수, queue event/byte 사용량이다. 시작 때 각 count의 뜻과 한계를 안내한다. 이 수치는 처리 현황이며 탐지 성공, 침해 없음, 무유실을 뜻하지 않는다. 메시지별 출력이나 송신 주소 표시는 없다. `DEGRADED`·`FAILED`는 정상으로 표시하지 않고 자동 재시작하지 않는다. 종료는 listener와 runtime을 멈추고 대기 중이던 frame이 복구되지 않을 수 있음을 안내한다. 다음 시작은 새 실행이며 이전 frame이나 분석 결과를 재게시하지 않는다.

연결을 실제로 구성할 때만 사용자가 endpoint를 알아야 한다. 별도 `--reveal-tcp-syslog-endpoint` 명령은 runtime lock이 활성 상태인지 확인하고, 먼저 로컬 연결 정보의 공유 주의와 loopback 다른 프로그램의 주입 가능성을 말한 뒤 `로컬 TCP 연결 정보를 표시합니다`를 정확히 입력받아 1회 출력한다. 출력에는 shell command나 history에 남길 수 있는 명령을 만들지 않는다. endpoint는 credential이 아니며 sender 인증을 제공하지 않는다. 사용자가 이를 사용 설명서·공개 이슈·로그에 복사하지 않도록 한다.

raw frame은 기존 bounded decoder/queue/parser/runtime 경로에서 일시적으로 존재할 수 있다. 별도 spool·dead-letter·audit·checkpoint를 만들지 않으며 CLI status와 exception에는 payload를 넣지 않는다. 외부 AI, Gemini, embedding, network API 전송은 없다. OS swap/crash dump, 같은 UID 프로세스, 호스트 침해는 이 pilot의 보장 범위가 아니다.

## 삭제·실패·미지원 경계

`--delete-tcp-syslog`는 `TCP Syslog 설정 삭제를 승인합니다`가 정확히 입력된 경우에만 TCP config를 삭제한다. 실행 중이면 먼저 거부한다. config가 없는 상태·손상 상태를 자동 초기화하거나, file config/checkpoint를 찾아서 변경하지 않는다. 별도 audit log는 생성하지 않는다.

일반 오류는 고정 한국어 안내만 사용한다. 상세 내부 예외·path·port·payload는 출력하지 않는다. setup은 no-clobber, exclusive temp, fsync/publish, private permissions와 post-write parse를 확인한다. delete는 현재 config identity/permission을 재확인한다. cleanup 오류는 성공으로 표시하지 않는다. 프로세스 강제 종료나 전원 장애 후 temp 파일 정리는 보장하지 않는다.

## Ownership 오류 회귀 후속 수정

Phase 34.4 최초 push SHA `128ffa2a5f9a380c537414b9dd4d274e57ef8ac1`의 CI run `40292029527`은 `Verify Linux SSH checkpoint recovery and process ownership` 단계에서 실패했다. 기존 SSH smoke의 두 번째 v2 file monitor는 nonzero 종료했지만 stderr에 기존 `CHECKPOINT_ALREADY_OWNED`가 없었다. 그 run에서는 전체 회귀와 이후 TCP smoke·management·axe 단계가 실행되지 않았다. 실패 CI의 전체 출력이나 합성 경로·식별자는 이 문서에 복사하지 않는다.

합성 lock-precedence 재현에서 collector lock을 사용할 수 없고 기존 runtime이 `CHECKPOINT_ALREADY_OWNED`를 반환하면, 이전 구현은 runtime/checkpoint 검사 전에 공용 collector lock을 시도해 exit code 4와 `LOCAL_COLLECTION_BUSY`로 먼저 거부했다. 이는 실제 v2 checkpoint ownership 검사를 가린 Phase 34.4 production lock-order 회귀다. v3 pair runtime도 기존 초기화/ownership 오류가 공용 lock에 가려질 수 있었다.

수정 후 file monitor는 기존 v1/v2 checkpoint manager 또는 v3 pair runtime을 먼저 준비한다. 기존 ownership 오류가 있으면 해당 기존 fixed code를 유지하고 listener와 공용 lock을 열지 않는다. 준비가 성공한 경우에만 listener 직전에 공용 collector lock을 nonblocking으로 얻는다. 이 lock 충돌이면 준비한 service를 닫아 source FD·worker·checkpoint manager를 정리하고 고정 `LOCAL_COLLECTION_BUSY`로 종료한다. TCP는 file checkpoint를 얻지 않으며 기존 순서대로 공용 collector lock 다음 TCP 전용 lock을 얻는다. 따라서 양쪽 lock 획득은 모두 nonblocking이고 TCP 경로는 file checkpoint를 기다리지 않아 교착 순환이 없다. 부분 lock 획득 실패는 이미 얻은 descriptor를 모두 해제한다.

수정 뒤 로컬 synthetic SSH checkpoint smoke는 기존 `CHECKPOINT_ALREADY_OWNED` assertion을 유지한 채 통과했다. v2 checkpoint·v3 pair error 우선순위 계약, file/TCP 양방향 상호 배제, TCP/TCP 충돌 및 두 번째 lock 실패 후 첫 lock 해제를 focused 테스트로 확인했다. 수정 SHA의 Ubuntu CI 전까지 Phase 34.4 Linux management는 `NOT_TESTED`다.

다음은 지원하지 않는다.

- 실제 장비/실제 사용자 로그, 원격 호스트, 외부 interface, TLS/mTLS
- application과 SSH 동시 수집, 두 TCP collector 동시 실행, file monitor와 TCP 동시 실행
- UDP, newline framing, 자동 재연결, durable spool/checkpoint, 과거 frame 복구
- browser UI/API/SSE/report 게시, shell command 자동 생성, 공유 workflow
- 정확히 한 번 처리, 무유실, 조직 운영, 인증/RBAC, retention·백업 정책

## Ubuntu CI 및 사용자 수용 기록

정확한 시작 SHA의 Ubuntu 증거와 사용자 화면 검수는 별도 기록에 남겼다. Phase 34.4 smoke는 Ubuntu 24.04에서 application/SSH를 각각 검사했고, completion marker는 `TCP_SYSLOG_MANAGEMENT_SMOKE_PASS roles=2 synthetic=1 leaks=0`이었다. 전체 pytest, 기존 SSH ownership·unified monitoring, basic TCP smoke, bounded reliability, restricted report, Chromium·axe 및 tracked-file 불변 단계도 같은 run에서 성공했다. 자세한 run ID·집계·사용자별 PASS/FAIL 기록은 [Phase 34.5 수용 기록](loopback_tcp_syslog_management_acceptance_34_5.md)을 참조한다.

사용자 검수는 실제 명령을 직접 조작한 검사가 아니라, 임시 HOME·합성 자료로 실행한 실제 CLI 출력을 캡처해 한 항목씩 보여주고 판단을 받은 방식이다. 최초 FAIL 항목은 메시지 형식 예시·거부 안내, count의 뜻과 한계, 삭제 후 재설정 안내의 누락이었다. 각 문구에 대한 계약 테스트를 수정 전에 실패시킨 뒤 CLI 문구만 보완하고 같은 항목을 재확인해 PASS를 받았다. 분석 의미, 설정 schema, 공개 API/SSE/UI는 바꾸지 않았다.

**최종 범위 판정:** Ubuntu management smoke와 10개 안내 항목은 검증되었고, 합성 loopback management 안내 범위만 `CONDITIONAL_GO`다. 실제 사용자 자료·조직 운영·원격 수집은 계속 `NO_GO`다.

### Phase 34.4B subprocess smoke follow-up

Ubuntu run `40299125326` at `70c4971cd75b48cd7b789f3d0ab10345152904d6` passed SSH checkpoint ownership and the full suite (**2855 passed / 2 existing warnings**) but failed the preceding loopback pilot smoke in the application/SIGTERM combination. Management and later CI checks were skipped. The earlier wrapper hid the inner stage. Local macOS reproduction found a harness-only readiness marker race: parent could observe the marker file before its port text was fully written. The test harness now atomically publishes complete 0600 markers, validates them separately, and limits failure output to fixed stage/category fields. Post-fix macOS first-attempt checks passed application SIGTERM 50/50, application SIGINT 20/20, SSH SIGTERM 20/20, 20 normal stops and 8 lifecycle-boundary cases. The exact inner cause of the historical Ubuntu failure remains unconfirmed; do not claim it was the same marker race. The later run `40308485200` passed the updated basic, reliability and management steps, which validates that SHA but does not retroactively identify the old failure. Production listener/runtime, management contracts and checkpoint ownership code were not changed by the marker harness repair. The historical macOS SSH/SIGTERM event remains `UNEXPLAINED_NON_REPRODUCED`; actual user data, organization operation and unauthenticated remote collection remain `NO_GO`.
