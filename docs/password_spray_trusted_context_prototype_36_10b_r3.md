# Phase 36.10B-R3 — Trusted Spray Window Context Prototype

## 1. Executive Summary

판정은 `PHASE_36_10B_R3_TRUSTED_CONTEXT_PROTOTYPE_LOCAL_CONDITIONAL_GO`다. 평가 전용 Prototype에서 같은 실행에 등록된 실제 `NormalizedEvent` 참조만 Window 멤버로 허용하고, 등록 후 핵심 필드 변조·Context 재포장·Evidence 불일치·Cross-run 입력을 고정 오류 코드로 거부하는 경계를 구현했다. Window 밖 실패는 C1/C2 Correlation 후보가 될 수 없다.

이는 같은 프로세스의 우발적인 실행 간 혼합을 다루는 **Prototype**이다. 악의적 Python 코드, Reflection, 프로세스 메모리 조작, OS 격리 또는 Production 신뢰성 보장은 다루지 않는다. Production Password Spray는 계속 `WHOLE_SPAN`; 정책 권고는 `MORE_EVIDENCE_REQUIRED`다. Risk, Case, Report, API, UI, Live 경로에 연결하지 않았다.

## 2. 시작 Gate 및 CI

- Repository: `ai-security-log-analyzer`; branch `main`
- 기준 SHA / HEAD / local main / origin main / GitHub main: `77e410f90f19469ee04f7fd861719d6a1fd397f3`
- 시작 Working Tree: clean; ahead/behind `0/0`
- GitHub Actions [Run 41196576197](https://github.com/misosos/ai-security-log-analyzer/actions/runs/41196576197): exact SHA, `push`, `completed / success`
- 필수 Locked Python 3.12 회귀, 전체 pytest, Linux checkpoint/SSH/TCP Syslog/JSONL, Restricted Report, Chromium/axe 및 tracked-file 검사: 성공
- Artifact: 0개
- v0.4.0 tag/release target `eecd6ee1cda0545e34b01c42e1a2163a899bcc27`: 불변
- 시작 전체 pytest: `3409 passed, 2 warnings`

## 3. R2 기준과 Prototype 경계

R2의 33개 시나리오와 Evaluation-only `EvaluationRun`/`SprayWindowContext`는 그대로 읽기 전용으로 뒀다. R2 결과(Current Pattern TP23/FP1/FN5/TN3, Known Benign 4/6, Current Correlation 6, C1 5, C2 2)는 별도 분모의 기준선이다. R3는 이 수치를 재계산해 합산하지 않는다.

새 모듈은 `app/evaluation/spray_trusted_context_prototype.py` 하나에 격리돼 있다. Production Pipeline·Correlation·Risk·Case·Report 모듈이 이 Prototype을 Import하지 않는 정적 검사를 추가했다. 신규 코드에는 Production analysis consumer 호출이나 파일/네트워크 side effect가 없다.

## 4. Threat Model 및 Run Owner

`PrototypeSprayRunOwner`는 한 번만 Event 집합을 등록하고 각 Event 객체를 강한 참조와 함께 보관한다. 객체 identity와 핵심 필드의 등록 시점 snapshot을 함께 사용한다. 같은 값의 복제 Event는 등록 객체가 아니므로 거부한다. Owner 상태는 모듈 전역 Registry가 아니라 Owner 수명에 한정된다. 재등록, 중복 객체 참조, 상한을 넘는 등록도 거부한다.

Snapshot은 timestamp(UTC 정규화), event type, source, user, IP, 기타 정규화된 관련 필드, 인증 context를 비교한다. Raw 문자열은 출력하지 않고 내부 mutation 감지에만 digest를 사용한다. 등록 후 timestamp/IP/user/type/authentication mutation은 사용 시점 검증에서 `event_mutated`로 거부한다. Object identity는 입력 객체 수명 안의 실행 결속을 나타낼 뿐, 실제 수집 이벤트 ID나 전달 중복 식별자가 아니다.

동일 프로세스 내부 우발적 misbinding만 위협 모델에 포함한다. Private attribute에 대한 악의적 조작, Reflection, 프로세스 메모리 침해, OS sandbox 우회, secure erase는 보장하지 않는다.

## 5. Window Context / Membership

`PrototypeSprayWindowContext`는 Owner가 직접 발급한 객체 identity까지 확인한다. 값이 같은 재포장 Context는 발급 객체가 아니므로 거부한다. Brute `BruteWindowContext`는 정확한 타입 경계에서 거부한다.

불변식: 같은 Owner, 등록된 실제 Event 참조, `login_failed`, 동일 Source IP, timezone-aware timestamp, UTC start/end, 실제 member count, 알려진 계정 cardinality, missing-user count, member source 집합, 승인된 policy ID 및 60초 이내 범위를 매 소비 시 검증한다. 선택된 membership 외의 Window 밖 이벤트는 Context에 삽입되지 않는다. Caller가 Owner 등록 집합과 다른 subset/superset을 전달하면 `event_set_mismatch`다. 입력 Iterable은 상한+1까지만 소비하며 Owner당 Event는 최대 512개, Raw 문자열은 UTF-8 8 KiB, Context는 최대 128개이면서 IP당 1개, Context당 Evidence는 1개로 제한한다. Window 탐색은 이 이벤트 상한 안에서 수행되지만 별도 CPU 시간제한은 없고, 상한은 OS CPU/memory cap이 아니다.

### Selection 규칙

R2 평가 휴리스틱을 재사용한다: IP별, 실패 4회 이상, 알려진 계정 3개 이상, 최대 60초, 가장 이른 qualifying timestamp group을 선택하고 그 끝 시점에서 불필요한 앞부분을 줄인다. 계정 누락 실패는 failure count에 포함되나 계정 cardinality에는 포함되지 않는다. 시간은 UTC로 비교한다. 서로 다른 source가 같은 IP 집계에 포함될 수 있고 Context는 source 집합을 드러낸다. 이는 한 사용자/행위자라는 의미가 아니다.

같은 selection key 또는 같은 핵심 event signature를 가진 distinct Event가 선택 결과를 모호하게 만들면 `ambiguous_selection`으로 거부한다. 중복을 삭제하지 않는다. 같은 timestamp에 다른 계정이 있는 경우 안정적인 필드 정렬로 순서를 정할 수 있으나, 모호한 동일 key의 구별은 신뢰 가능한 Event ID가 없어 해결되지 않는다.

## 6. Evidence Integrity

`PrototypeSprayDetectionEvidence`는 Context에서만 발급되고, owner가 발급 객체 자체와 필드 snapshot을 보관한다. Source IP, 정책 ID, UTC 범위, 실패/계정/missing count, 정확한 member 참조, Owner 및 Context 결속을 재검증한다. 변경 복사본은 미발급 Evidence, 발급 후 필드 변조는 불일치로 거부한다. 생산 `Evidence` 모델이나 Public Schema는 변경하지 않았다.

오류는 `invalid_context`, `wrong_run`, `event_mutated`, `ambiguous_selection`, `invalid_evidence` 등 고정된 안전 코드만 반환한다. 원문 로그·계정·IP·예외 세부는 CLI에 출력하지 않는다.

## 7. Correlation C1 / C2

두 후보 모두 검증된 Context와 Owner 전체 Event 집합만 받는다. 실제 Window member 실패, 같은 알려진 계정, 동일 IP, 실패 이후 성공, 최대 60초 조건을 적용한다. 선택된 실패 Endpoint는 반드시 Window member다. Window 밖 90초 실패와 95초 성공만 있는 경우 관계는 없다.

- **C1:** 실패 Event 시점부터 성공까지 최대 60초. 성공은 Window 종료 전·중·후 모두 허용될 수 있다. 실패 이후의 성공만 허용.
- **C2:** C1 기본 조건에 더해 모든 Window member의 계정이 있어야 하며 성공은 Window 종료 이후이고 Window 종료부터 성공까지도 60초 이내여야 한다.
- 서로 다른 endpoint의 최소 delta가 동률이면 `ambiguous_pair`/no relation. 성공 Event identity를 중복값으로 합치지 않는다.
- Cross-account, Cross-IP, Cross-run, Missing member account(C2), success-before-failure, same timestamp는 관계를 만들지 않는다.

C1/C2의 시간 기준은 R3 비교용이다. Production 정책으로 확정하지 않았다. Relation은 행위자 동일성, credential reuse, 공격 성공, 침해 또는 인과를 증명하지 않는다.

## 8. Cross-run / Copy / Mutation 결과

| 경계 | Prototype 결과 |
|---|---|
| 다른 Owner의 Event 또는 Success | `wrong_run` |
| 값이 같은 복제 Event | 등록 참조와 다르므로 `wrong_run` |
| Context를 다른 Owner에 전달 | `unissued_context` |
| 같은 값의 Context 재포장 | Owner 발급 identity 없음으로 거부 |
| Context 필드 변경 | `context_mutated` |
| Owner 등록 Event 집합의 subset/superset | `event_set_mismatch` |
| Event의 timestamp/IP/user/type/auth 변경 | `event_mutated` |
| 같은 Event 참조 중복 등록/입력 | `duplicate_event_reference` 또는 invalid set |
| Brute Context를 Spray Context로 전달 | exact type 검사에서 `invalid_context` |
| 같은 값의 Detection Evidence 복제 | 발급 객체 identity가 없어 거부 |

위 결과는 Prototype 테스트에서 관찰한 동작이며, 악의적 동일 프로세스 코드로부터의 변조 방지 증명은 아니다.

## 9. Brute와 Spray 분리

Brute Context는 단일 계정의 실패 Window이고 기존 Production `AnalysisRunOwner` 경계 및 Correlation 소비자가 있다. Spray는 여러 알려진 계정의 관측 패턴이므로 별도 Prototype Owner/Context와 별도 membership을 사용했다. Brute Owner/Context 구현은 수정하거나 재사용하지 않았다.

## 10. 기존 Consumer 계약

Detector whole-span Feature/Evidence, Production Correlation, Risk, Case Adapter, Incident Case, Report Projection, Restricted Report, Checklist, Guidance, 19-field Workspace Projection 및 Live Monitoring은 바뀌지 않았다. R1의 현재 동작 characterization을 기존 회귀에서 유지한다: Risk는 whole-IP 값, Case Adapter는 범위 불일치 Evidence를 거부, Report는 기존 scalar projection만 사용한다. Prototype Context가 이 소비자들의 호환성을 보장하거나 R1의 제한을 해소하지 않는다.

## 11. Static/Live 제한

동일 Owner Event set에서 입력 순서가 달라도 같은 정렬 가능 입력은 결정적인 Window reference 집합을 생성한다. 이는 batch 합성 Event 집합의 동작이다. Prefix, late arrival, checkpoint, rotation, collector replay, restart 및 실제 Live Runtime의 membership 재평가를 통합 검증하지 않았다. Static/Live parity는 `UNVERIFIED`다.

## 12. Research Basis / Observable Evidence Mapping / Limitations

이 Phase는 공격 분류나 운영 임계값을 새로 정하지 않고 기존 평가 후보를 격리해 검증한다. `4 failure / 3 known accounts / 60 seconds`는 36.10B/R2에서 사용한 **프로젝트 평가 휴리스틱**이며 표준이나 공식 권고값이 아니다.

- MITRE ATT&CK의 [T1110.003 Password Spraying](https://attack.mitre.org/techniques/T1110/003/)은 하나 또는 소수의 비밀번호를 여러 계정에 시도하는 행위와 탐지 회피를 위해 시도를 늦출 수 있음을 설명한다. 페이지 표시 수정일은 2025-10-24다. 이는 행위 정의와 관측 한계의 배경이며, 현재 Parser가 비밀번호 재사용이나 행위자 동일성을 관측한다는 뜻은 아니다.
- Microsoft Learn의 [Entra sign-in activity details](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-sign-in-log-activity-details)는 제품별 Request ID/Correlation ID 및 event-time과 ingestion-time 구분을 설명한다. 문서는 Entra 전용이다. 이 Repository의 Application/SSH Parser에 동일 식별자가 있다는 근거로 사용하지 않았으며, 현재 공통 Event ID가 없는 한 중복 수집 식별을 보장할 수 없다는 제한을 명확히 하는 데 사용했다.

**Observable Evidence Mapping:** 현재 normalized Event의 `timestamp`, `event_type`, `source`, `user`, `src_ip`, `authentication` → Owner가 강한 참조와 mutation snapshot으로 등록 → 실패 Event 중 같은 IP·UTC 60초 범위·실패 4회·알려진 계정 3개의 실제 member 집합 → 발급 Evidence 및 member-bound relation. 비밀번호 값, underlying attempt, 수집 재전송 identity, NAT 뒤 사용자, Batch 승인 여부는 관측되지 않는다.

**Limitations:** 합성 Prototype은 실제 운영의 false-alert rate나 탐지 정확도를 추정하지 않는다. 같은 문자열이 실제 retry인지 delivery replay인지 결정할 수 없다. Shared NAT/VPN/Proxy, 승인 Batch, cross-source semantics, User canonicalization, live checkpoint/replay, 실제 Run integration, OS-level hard CPU/memory 제한, secure erase는 검증하지 않았다. Python object identity는 log-level event identity가 아니다.

## 13. 테스트 및 검증

- 시작 전체 pytest baseline: `3409 passed, 2 warnings`
- 신규 `tests/test_spray_trusted_context_prototype_36_10b_r3.py`: 33 tests PASS; CLI smoke용 독립 합성 fixture 2개
- Prototype CLI: text/JSON 모두 exit 0, 동일한 검증 상태, 원문·계정·IP·Owner token 미출력
- `uv sync --locked --dev`, `uv lock --check`, `python3 -m compileall -q app tests`, `git diff --check`: PASS
- 전체 pytest 최종: `3442 passed, 2 warnings` (시작 기준선 3409에서 신규 테스트 33개 추가)
- 기존 evaluator: synthetic boundary `79/79`; Detector Accuracy corpus 46개, Password Spray `TP2/FP0/FN0/TN5`; Brute Window 24개 실행
- 36.10B Scope CLI: 36개, Current `15/1/4/10`, Sliding `17/1/2/10`, Known-account `16/1/3/10`, 각 정책 operational false-alert candidate 3건
- R2 CLI: 33개, parsed 150, ignored/rejected 0, Current Pattern `23/1/5/3`, Current Correlation 6, C1 5, C2 2, gate-open out-of-window endpoint 1
- `npm run test:a11y --silent`: 25 states PASS, 외부 요청 0; 1920/1440/1280/1024/768/390/320 CSS px 및 200% equivalent reflow에서 clipping/overflow/target-size 실패 0
- `node tests/ui_navigation_closure_36_10a_ui3.mjs`: PASS; sample POST 1, guidance POST 1, checklist POST 0, 지연 Case 응답 격리, stale route 만료, CSP 확인, 외부 요청 0
- 구형 `tests/ui_workspace_navigation_28_4.mjs` stale DOM selector 테스트는 이번 Phase에서 실행하지 않았으며 역사적 실패를 PASS로 간주하지 않는다.

### TDD 기록

첫 실행은 Context의 발급 스냅샷 조회 경계가 실패해 RED였다. 이를 Owner 내부 조회 API로 고친 뒤 테스트를 통과시켰다. 추가 경계 테스트에서 동시각 중복 member의 결정성 및 동일 값 distinct Success endpoint 문제가 드러나, 중복 제거 대신 선택 모호성 거부와 Event identity 기준 tie 판정으로 수정했다.

## 14. Privacy / Resource / Production Non-change

문서용 IP와 합성 `spray_*` 계정만 테스트에 쓴다. 출력에는 Context token, Owner, Event, Raw line, 계정, IP가 없다. 평가 경로는 외부 Network/LLM을 사용하지 않는다. Owner당 Event 512개·이벤트 Raw 8 KiB·Context 128개 및 IP당 단일 Context 상한을 적용한다. 이는 명시적인 Python 측 입력/보존 상한이지 OS 수준 hard memory/CPU cap이 아니다. Prototype은 Production 모듈에서 import되지 않고 Detection/Risk/Case/Report/API/Frontend/Live 동작은 변경되지 않았다.

## 15. 알려진 위험과 Rollback

남은 위험: 중복 전달을 실 Event ID 없이 판별할 수 없음, NAT 귀속 불확실성, C1/C2 시간 anchor의 정책 미결정, mutable object identity가 프로세스 내부 전제에 의존, Live 재평가·Consumer integration 미검증. 따라서 `MORE_EVIDENCE_REQUIRED`를 유지한다.

Rollback은 신규 Prototype 모듈·CLI·테스트·이 문서·색인 링크만 되돌리면 된다. 기존 R2 corpus, Production 코드, 기존 Phase 기록은 손대지 않는다.

## 16. 다음 Phase

권고: `Phase 36.10B-R4 — Trusted Spray Context Consumer Integration Design & Security Gate`. Production Owner 확장, Detection binding, Correlation anchor 확정, Risk/Case/Report semantic migration 및 Static/Live gate를 설계·독립 검증한다. 중복/NAT 운영 근거가 부족한 동안 Production 정책 변경은 승인하지 않는다.

## 17. 최종 경계

- Production Password Spray: `WHOLE_SPAN`
- Policy: `MORE_EVIDENCE_REQUIRED`
- 사용자 자료 / 조직 운영 / 자동 대응: `NO_GO`
- 실환경 정확도: `UNVERIFIED`; 모델 AI: `NOT_TESTED`
- Safari 사용자 수용: `SAFARI_USER_ACCEPTANCE_PENDING`
- Vector/VM: `USER_ACTION_REQUIRED / ISOLATION_BLOCKED`
- OS-level hard CPU/memory cap: 미보장; secure erase: 미보장
- Renderer: `KEEP_LEGACY`
