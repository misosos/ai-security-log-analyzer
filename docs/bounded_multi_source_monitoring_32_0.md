# Phase 32.0 — bounded multi-source local monitoring 설계 gate

**상태: 설계 gate. 구현·지원 완료가 아니다.** 기준은 `e7c15060fb22aa3c104d90492a10fd2988a3ebe7`의 main과 [CI run 39727916286](https://github.com/misosos/ai-security-log-analyzer/actions/runs/39727916286) `completed/success`다. Ubuntu 통합 설정 관리, 전체 pytest, locked 설치, Node·axe가 성공했고 저장 artifact는 0개다. v0.4.0 공개 tag·Release는 기존 커밋에 유지한다. [Phase 31 최종 판정](disposable_vm_isolation_31_2a.md#phase-31-최종-판정)은 PentAGI 실행과 Phase 31.2B 모두 NO-GO다. 이 설계는 PentAGI와 연결되지 않는다.

후속 [Phase 32.1A private v3 설정 구현](multi_source_private_config_32_1.md)은 경로 두 개와 역할별 checkpoint 연결 metadata를, [Phase 32.1B](multi_source_runtime_32_1b.md)는 내부 runtime·scheduler·checkpoint를 추가했다. [Phase 32.2](multi_source_publication_32_2.md)는 명시적 내부 launcher에 한해 공개 publication·API·SSE 계약을 추가했다. Phase 32.3 setup 관리 UX·production UI·Safari 사용자 검증은 미구현이다. 두 source 사용자 모니터링 지원 선언이 아니다.

## 목적과 닫힌 지원 범위

한 로컬 프로세스에서 **application 최대 1개, SSH 최대 1개, 총 2개**의 로컬 파일을 함께 모니터링하는 후보를 설계한다. 두 역할의 기존 parser, detection, relation, risk, case는 **source 내부**에서만 계산한다. 동일 역할 중복, access 및 Linux Audit live, cross-source correlation, source 무제한 추가를 거부한다. 성공 로그인 기록이나 관계는 침해·공격 성공·인과관계 확정이 아니다. Phase 32.0에는 production 코드, 공개 API/SSE schema, frontend를 바꾸지 않는다.

## 현재 구현에서 확인한 단일 source 경계

| 경계 | 현재 사실 | 두 source에 필요한 결정 |
|---|---|---|
| Config | [`config.py`](../app/live_monitoring/config.py)의 v1은 단일 `role/path`, v2는 `SOURCE-000001`과 `sources` 길이 1을 강제한다. [`local_web.py`](../app/local_web.py)는 하나의 runtime chain을 만든다. | 기존 v1 명시적 설정과 단일-source private v2를 그대로 유지하고, **새 닫힌 schema_version `3`** 후보를 별도로 둔다. 자동 migration 금지. |
| Setup·관리 | [`monitor_setup.py`](../app/monitor_setup.py)의 show/reset/delete는 기본 v2와 연결 checkpoint 하나를 대상으로 승인·잠금을 수행한다. | v3 생성은 명시적 두 역할 선택과 no-clobber만 허용. reset/delete는 대상을 역할별로 명시 선택해야 한다. |
| Tail·worker | [`worker.py`](../app/live_monitoring/worker.py)는 한 tail·queue·detection·analysis를 소유한다. [`runner.py`](../app/live_monitoring/runner.py)는 단일 asyncio loop에서 유일한 `worker.step()` caller이며 개발 polling 간격은 0.5초다. | source별 state를 분리하고 하나의 상위 scheduler가 순서대로 호출한다. thread, subprocess, IPC는 최소 범위에서 제외. |
| Checkpoint | [`checkpoint.py`](../app/live_monitoring/checkpoint.py)의 private checkpoint/lock 이름과 source ID는 한 source용이며 역할·file identity·prefix를 검증한다. 256 parsed event/256 KiB history와 checkpoint byte 상한을 적용한다. | 역할별 독립 파일과 lock·identity를 갖는다. 기존 단일 checkpoint를 추측해 재사용하지 않는다. |
| Publication·UI | [`publication.py`](../app/live_monitoring/publication.py)는 한 revision 공간과 replay buffer 32 item/16 KiB다. [`service.py`](../app/live_monitoring/service.py)는 한 source 상태·SSE stream을 내보낸다. [`live-monitoring.js`](../frontend/live-monitoring.js)는 단일 session/source의 닫힌 JSON 계약과 수동 새 결과 적용을 검사한다. | 새 버전의 status/snapshot/event와 frontend 동시 migration이 필요하다. 현 schema를 조용히 재해석하지 않는다. |

## 설정 호환성 및 개인정보

| 입력 | 설계 판정 |
|---|---|
| 명시적 v1 `--monitor-config` | 기존 application·SSH·access 단일 source 의미와 `FROM_END` 유지. v3로 자동 변환하지 않음. |
| 명시적 v2와 기본 private v2 | 기존 단일 source 실행·checkpoint 복구·show/reset/delete 그대로 유지. 기존 config를 자동 덮어쓰지 않음. |
| 새 v3 후보 | private 기본 설정에 **정확히 두 enabled entry**: application 1개 + SSH 1개. 닫힌 source 필드와 순서(application→SSH), `FROM_END`, `Asia/Seoul`, `BOUNDED_REPLAY_V1`, `FAIL_CLOSED`를 검증. 다른 역할·중복·추가 필드·부분 구성 거부. 새로운 명시적 v3 파일 지원 여부는 별도 gate. |

v3 문서의 최상위 필드는 `schema_version`(해석 버전), `sources`(정확히 두 entry)만 제안한다. 각 entry는 `source_role`(parser/analysis 선택), `source_id`(역할별 고정 비식별 내부 key), `source_path`(로컬 파일 입력), `display_alias`(고정 쉬운 이름), `enabled`(명시적 사용 여부), `start_position`(첫 실행의 기존 줄 처리), `parser_timezone`(시각 해석), `checkpoint_policy`(복구 허용 범위), `rotation_policy`(교체 시 중단)로 닫는다. `source_path`는 private config에만 보존하고 공개 status·SSE·오류·ID·repr에 넣지 않는다. 계정·IP·hostname을 설정이나 public ID에 추가하지 않는다. 설정 parent 0700, config 0600, symlink/소유권/identity 검증, 원자적 no-clobber 게시를 유지한다. 수명은 사용자의 명시적 delete까지이며 backup/snapshot의 안전한 완전 삭제를 보장하지 않는다.

새 v3를 기존 v2 파일 위에 덮어쓰지 않는다. 사용자가 명시적으로 기존 설정을 관리한 뒤 새 구성으로 이동해야 한다. 역할별 checkpoint는 고정 비식별 이름과 role binding을 사용하고 원본 경로의 hash도 파일명·공개 ID에 쓰지 않는다. Config 자체와 연결된 두 checkpoint를 검증할 때 application→SSH 순서로 lock을 획득하고 역순으로 해제한다. 타 프로세스가 순서를 달리 잡는 경로를 허용하지 않으며 lock 경쟁은 고정 오류로 거부한다. 두 파일의 delete/reset은 원자적이지 않다. 부분 삭제·손상·역할 불일치는 자동 초기화나 조용한 `FROM_END`로 바꾸지 않고 수동 검토가 필요하다.

`reset`은 v3에서 **application 또는 SSH 대상 하나를 명시적으로 선택**하고 해당 checkpoint만 폐기한다. 다른 source의 연속성은 유지한다. `delete`는 **두 로그 설정 전체**를 대상으로 선택·승인하게 한다. Source 한쪽만 삭제해 지원 범위 밖의 불완전 v3 config를 남기는 방식은 금지한다. 전체 v3 설정과 두 checkpoint를 삭제하되 승인 화면에서 두 역할을 모두 나열하고 partial failure를 명확히 보고한다. 원본 로그와 sibling은 보존한다. 실행 중 reset/delete는 모든 연관 lock을 확인하고 거부한다. 별도의 source 제거/교체 UX는 후속 설계다.

## 실행·공정성·장애 정책

각 source에 tail session, bounded queue, detection accumulator, analysis accumulator, publication state, checkpoint를 독립으로 둔다. 한 프로세스의 단일 asyncio loop에서 한 caller만 step을 호출한다. Source 순서를 고정한 뒤 매 polling cycle의 시작 역할을 번갈아 바꾸는 **bounded round-robin**을 제안한다. Source별 최대 1 step/회, 기존 step당 최대 16 record·4,096 byte poll을 유지한다. Cycle admission 상한은 최대 2 step, 32 record, **global byte 8,192**, **global time 100 ms soft admission budget**으로 제안한다. 100 ms가 지나면 다음 step을 시작하지 않고 다음 cycle에서 지연된 역할을 우선한다. 동기 `worker.step()`을 중단할 수 없으므로 이는 hard wall-clock 상한이 아니다. 측정상 무제한 stall 가능성이 발견되면 Phase 32.1은 NO-GO이며 실제 운영 지연 SLA를 주장하지 않는다. Queue 32 item/16 KiB와 history 256 parsed event/256 KiB는 **source별** 상한으로 유지하고 global memory 상한은 별도 계측 후 확정한다.

각 source는 `poll → lease → parse → detection/analysis/publication prepare → checkpoint prevalidate → source identity 재확인 → ack → detection/analysis commit → publication → checkpoint` 순서를 독립적으로 지킨다. **ack 전** 실패는 proposal abort·lease release 후 DEGRADED로 표시한다. **ack 후** commit/publication/checkpoint 실패는 해당 source의 terminal FAILED이며 재시도나 다른 source 결과로 메우지 않는다. 한 source의 terminal failure 또는 복구가 필요한 DEGRADED 상태에서는 **전체 runner의 새 수집을 중단**하는 보수적 정책을 채택한다. 이미 확정된 다른 source의 결과는 source별 마지막 시점과 함께 읽기 전용으로 남기고 전체 상태를 `중단됨·한 로그 확인 필요`로 표시한다. 다른 source만 계속하는 대안은 가용성은 높지만 부분 성공·지연·checkpoint 이해가 어렵고 실패 은폐 위험이 있으므로 최소안에서는 채택하지 않는다. 이 정책은 cross-source 원자적 transaction이 아니다. Exactly-once·무유실·crash recovery·rotation/copytruncate 자동 handoff를 주장하지 않는다.

## Publication, API/SSE, UI 제안

기존 `observation_changes`·`analysis_changes`의 관찰/분석 의미와 수동 새 결과 적용은 유지한다. 다만 현재 observation payload에는 role이 없고 상태·revision·cursor는 단일 source이므로 **새 공개 schema version**이 필요하다. 모든 안전한 변경·status·snapshot에 닫힌 `source_role` 값과 그 역할의 revision을 넣는다. 같은 숫자의 application/SSH revision을 합치지 않는다. 원본 로그·IP·계정·경로·rationale는 계속 비노출이다. Public ID는 비식별 process/session sequence를 사용한다.

**선택: 단일 EventSource + 단일 global replay cursor.** 기존 한 연결 UX를 유지하고 순서화된 safe event에 role과 source별 revision을 같이 싣는다. 역할별 cursor 두 개는 두 EventSource나 복합 Last-Event-ID가 필요해 브라우저 재연결·수동 적용 계약이 더 복잡해진다. Global cursor만으로 source별 유실을 숨기지 않도록 buffer는 evicted event의 역할별 마지막 sequence를 기억하고, 재연결 cursor가 뒤처지면 **replay gap**과 영향 역할을 표시한 뒤 두 source의 최신 안전 snapshot으로 재동기화한다. 영향 역할을 확정할 수 없으면 `두 로그 모두 최신 상태 확인 필요`로 fail closed한다. Gap은 정상 0건이 아니다. Event ID는 path/account/IP에서 파생하지 않는다.

초기 안전 상한 후보: replay **전체 32 item/16 KiB**, 단일 event **16 KiB**, 각 source의 snapshot **256 item/category 및 128 KiB**, combined snapshot **512 item/category 합계 및 256 KiB**, status **16 KiB**. 모든 serialize/size 검사를 게시 전 수행하고 초과는 명시적 DEGRADED/FAILED로 전환한다. 분석이 없는 범주를 빈 카드로 채우지 않는다. 이 수치는 설계 제안이며 Phase 32.1 합성 최악 조건에서 재검토한다. 기존 API/SSE schema는 이번 Phase에서 변경하지 않는다.

UI는 `애플리케이션 로그인 로그`와 `SSH 인증 로그` 각각의 RUNNING·DEGRADED·FAILED·복구 필요 상태를 텍스트로 표시하고 전체 상태는 둘 모두 정상이 확인될 때만 `모니터링 중`으로 표시한다. 한쪽만 실패하면 `한 로그 확인 필요·전체 모니터링 중단`과 해당 역할의 다음 행동을 제공한다. 새 결과 N건, 적용 버튼, replay gap, checkpoint reset의 **대상 역할**을 보여 준다. 내부 revision·schema 코드는 일반 화면에서 숨긴다. 결과 화면은 source별 요약→확인할 항목→상세 순서를 유지하며 서로 다른 source의 관찰을 하나의 관계나 사례로 결합하지 않는다. Safari에서 두 상태가 읽기·키보드·VoiceOver로 구분되는지 별도 사용자 검수한다.

## 성능 기준선과 Phase 32.1 측정

[application 256-prefix benchmark](live_analysis_16_4_audit.md)와 [SSH 256-prefix benchmark](ssh_live_analysis_audit_22_4.md)의 마지막 bounded worker step p95는 각각 약 **8.963 ms**, **9.033 ms**, status p95는 각각 **3.973 ms**, **2.475 ms**였다. 256-event prefix는 앞선 여러 step에서 쌓인 history이며 같은 poll에서 256개의 새 event가 들어온 뜻이 아니다. 두 source가 각각 256-event 근처에 도달한 **같은 polling 구간**에서 두 bounded step의 비용, serialization과 status 경쟁을 측정한다. 단일 source 수치를 더해 두 source p95나 0.5초 운영 SLA로 주장하지 않는다.

Phase 32.1B는 내부 역할별 prefix·cycle·checkpoint·close를, Phase 32.2는 status HTTP·SSE·publication·replay/gap을 각각 합성 benchmark로 측정했다. Phase 32.3은 production pair wiring의 별도 개발 benchmark/soak를 [기록](multi_source_user_monitoring_32_3.md)했다. Ubuntu 별도 프로세스와 실제 Safari 사용자 검수는 미완료다.

## Phase 32.1 수정 전 실패 테스트 후보

| 후보 | 현재 예상 실패와 요구 불변식 |
|---|---|
| Config·compat | v3 application+SSH loader round-trip은 현재 `sources` 길이 1 guard에서 실패해야 한다. v1/v2 단일 loader·마법사·checkpoint는 그대로 PASS; 빈/중복/세 번째/access/Linux Audit/역할 불일치/경로 canary v3는 거부. 자동 migration·no-clobber 검사. |
| Runtime·fairness | application만/SSH만 기존 경로와 두 source 동시, 한쪽 idle/다른쪽 burst, 양쪽 burst; 최대 1 step/source/cycle과 alternating first role, global byte·time admission, queue age를 검사. Hypothesis scheduling state machine은 상태 전이·서비스 횟수·상한의 반례 탐색에 가치가 있지만 실제 wall-clock·OS fairness 증명은 아니다. |
| Transaction·failure | 한 source ack 전 실패에서 lease 복구와 전체 중단; ack 후 terminal 실패에서 재처리 금지, 다른 source의 확정 결과 보존, 전체 정상 표시 금지. 257번째 parsed event는 silent eviction 없이 ack 전 거부. |
| Checkpoint·관리 | source별 identity/offset/revision, 역할 불일치·손상·교체·부분 삭제 fail closed, 두 monitor·reset/delete lock 경쟁, 역할 선택 없는 reset 거부, 대상 외 checkpoint·원본·sibling 보존. |
| Publication·privacy | mixed observation_changes·analysis_changes 순서, source별 revision, 단일 cursor의 foreign/future/evicted/gap, 한 source eviction 후 영향 역할 표시, 16 KiB event·32 item/16 KiB replay·combined snapshot 상한; path·account·IP·raw/rationale canary가 status/SSE/DOM/error/repr에 없음. |
| 환경·사용자 | UTC/KST 결과 결정성, macOS·Ubuntu 별도 프로세스 smoke, listener·FD 정리, Safari의 source 상태·새 결과·gap·reset 대상 이해와 keyboard/VoiceOver 확인. 자동 테스트를 Safari 사용자 PASS로 바꾸지 않음. |

## 단계와 명시적 NO-GO

**단계 상태:** 32.1A private v3 설정 생성·로드, 32.1B 내부 runtime·scheduler·checkpoint, 32.2 안전한 publication/API/SSE, 32.3 setup·management·production UI 구현, 32.4 독립 수용·장애 검증이 각각 별도로 기록되어 있다. 합성 CLI·loopback·Chromium 자동 검증은 수행했지만 실제 Safari 사용자 수용은 NOT_TESTED다. 구현된 production 흐름도 rotation/copytruncate, second-generation replay, cross-source analysis, exactly-once 지원을 뜻하지 않는다. [Phase 32.4 수용 기록](multi_source_acceptance_32_4.md)을 참조한다.

이 설계 문서는 32.0 시점의 proposal을 보존한다. 당시 v3 사용자 실행·production UI는 미구현이었으며 이후 단계 구현은 proposal의 제한을 제거하지 않았다.

계속 **NO-GO**: cross-source correlation, 자동 rotation/copytruncate 복구, 무제한 source, silent eviction, 한 source 실패 은폐, raw event SSE 금지, 개인정보 기반 public ID, crash 이후 exactly-once·무유실 주장, PentAGI·REA·Vector 등 외부 실행 도구 연결. Phase 31의 PentAGI 실행 NO-GO는 이 설계와 독립적으로 유지한다.
