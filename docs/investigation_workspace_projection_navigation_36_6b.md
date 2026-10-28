# Phase 36.6B — closed UI projection과 navigation shell

## 판정과 시작 gate

판정은 `PHASE_36_6B_PROJECTION_NAVIGATION_CONDITIONAL_GO`다. 닫힌 projection과 기존 hash route 기반 shell을 합성 브라우저 경로에서 검증했다. 이는 새 디자인 이식 완료, 실제 자료 사용 승인 또는 조직 운영 승인이 아니다.

- 시작 branch: `main`; 시작 tree clean
- 시작 SHA/local `main`/`origin/main`: `e5c367742a39525fe2fc354925766c61baece038`
- 시작 `origin/main...HEAD`: behind 0 / ahead 0
- exact-SHA Actions run: [40722724436](https://github.com/misosos/ai-security-log-analyzer/actions/runs/40722724436), `push`, 정확한 head SHA, `completed/success`
- locked Python 설치, 전체 회귀, TCP Syslog smoke/reliability/management, JSONL Linux acceptance, restricted report Linux smoke, Chromium/axe, tracked-file 불변: 모두 성공
- Actions artifact: 0
- `v0.4.0` tag와 Release target: 기존 릴리스 commit `eecd6ee1cda0545e34b01c42e1a2163a899bcc27`
- 시작 전 작업 트리: clean

## TDD 기록

production 코드를 바꾸기 전에 브라우저 계약을 추가했다. 최초 실행은 기존 `workspaceNavigation`에 테스트용 legacy switch/projection adapter가 없어 `TypeError`로 실패했다. 이어 문서 계약 테스트는 기록 파일과 README/docs index 연결이 없어서 2건 실패했다. 이 실패들을 구현 후 기대값 변경 없이 해결했다.

기존 상세 화면 회귀는 loopback 전용 테스트 legacy switch로 계속 실행한다. projection 조회·잘못된 입력 주입·benchmark helper도 loopback에서만 `workspaceNavigation`에 붙는다. 외부 host에서는 이 helper가 없다. production의 기본값은 새 shell이며 기존 화면의 분석, checklist, guidance 검사는 그대로 유지했다.

회귀 중 새 shell의 중첩 named section이 axe `landmark-unique`를 발생시켜 내부 shell wrapper를 `<div>`로 바꾸고, outer detail region 하나만 accessible name을 갖게 했다. direct-entry 검사는 같은 URL 탐색이 메모리를 지우지 않는 SPA 동작을 발견해 실제 `reload` 후 고정 expiry를 확인한다. 기존 320px test가 첫 카드 summary node에 긴 합성 문장을 주입한 뒤 복구하지 않아 shared projection 비교가 실패했던 부분은 테스트 cleanup에서 projection의 고정 summary를 복원하도록 했다. 검증된 KST·UTC 쌍을 보존하되 KST 표시 문자열에 `UTC+09:00` 접미사가 남아 기존 KST-only UI 계약을 어긴 실패를 확인했다. 고정된 timezone suffix만 projection label에서 제거하고 검증된 UTC는 semantic `datetime` attribute에 유지했다.

## Closed projection

`frontend/app.js`는 기존 공개 사례 응답을 전체 `validateInvestigationResponse`와 사례 검증으로 통과시킨 다음에만 `investigation-workspace-ui/v1` projection을 생성한다. API schema는 바꾸지 않았다. projection은 `Object.freeze`된 단일 객체이며 목록과 상세가 동일 객체 snapshot을 사용한다.

정확한 허용 key:

`schema_version`, `case_ref`, `display_order`, `display_title`, `risk_band`, `subject_alias`, `source_role`, `review_priority`, `start_time_kst`, `start_time_utc`, `end_time_kst`, `end_time_utc`, `observation_count`, `relation_count`, `task_count`, `limitation_count`, `category`, `summary`, `checklist_status`.

- `case_ref`는 검증된 `c_` + 소문자 24자리 hex opaque ref다.
- `display_title`과 `summary`는 검증된 기존 고정 activity/설명 mapping에서 온다.
- `risk_band`는 기존 분석 값 그대로다.
- 공개 사례 response에는 role/priority가 없으므로 각각 `unknown`/`undetermined`로 둔다. risk나 category에서 계산하지 않는다.
- role은 이후 명시적인 기존 checklist 응답에서 검증될 때까지 미확인이다. 이번 shell에는 checklist 동작을 추가하지 않았다.
- 시간은 검증된 공개 KST 및 ISO UTC display string만 사용하고 기존 `<time datetime>` 의미를 유지한다. 원본 timestamp object는 projection 밖에 둔다.
- task count는 미요청 상태의 0이며 limitation count는 기존 검증 사례 자료에서 온다.
- 허용 category는 현재 이 사례 projection이 지원하는 `authentication`이다. 알 수 없는 enum은 projection을 거부한다.
- unknown/missing key, 잘못된 type/count, 유효하지 않은 case ref, title mapping 밖 값은 고정 `WORKSPACE_PROJECTION_INVALID`로 거부된다. 내부 값은 오류에 붙이지 않는다.

raw log, 원 account/IP/hostname, 파일 경로, checkpoint, credential, parser/rationale 원문, 내부 예외, 정확한 내부 DB key, 다른 사례 metadata는 허용하지 않는다. 합성 개인정보 canary 추가 key, 누락 key, bool-as-int를 주입해도 projection 생성이 거부되는 브라우저 계약을 추가했다. 검증은 허용 alias `대상 A/B`를 제외한 canary 비노출을 확인한다.

## Route와 상태

기존 `#/investigations/{case_ref}` hash route를 유지한다. pathname server route나 새 API를 추가하지 않았다. 상세 진입은 같은 분석 응답에서 만든 projection snapshot을 표시한다. `case_ref` 외의 category, alias, source role, risk 또는 분석 payload를 URL/history state에 저장하지 않는다.

상태 흐름:

```text
validated result → projection map → result list
result list + explicit detail link → opaque hash detail shell
browser back → list + saved list scroll/focus
browser forward → same in-memory projection shell
missing/stale/mismatched case_ref or direct entry without memory → fixed expiry view
```

직접 진입(`direct-entry`)·새로고침·stale reference는 기존 고정 만료 view로 간다. 다른 사례를 대신 고르지 않으며 analysis API를 재호출하지 않는다. route, back, forward와 만료 화면은 checklist 자동 요청 0건이다. 결과가 새로 렌더링될 때 projection map을 교체하고, duplicate `case_ref` 집합은 고정 response-format 오류로 거부하므로 다른 사례의 projection이 섞이지 않는다. 이는 사례 격리 계약이다. 상세 subtree는 교체 렌더링한다.

상세 shell은 고정 제목, 결과로 돌아가기 링크, synthetic/local context, display title, 기존 risk, `확인 순서 미정`, `역할 미확인`, 보호 alias, 검증된 시간·count, checklist 미요청 상태만 보여준다. timeline, 확인 작업, citation/evidence 화면은 이 Phase에 이식하지 않았다. 텍스트는 DOM text node로 출력한다.

## Checklist와 분석 불변

목록 진입 0 POST, 상세 진입 0, hash 변경 0, 뒤로/앞으로 0, 만료 route 0이다. 기존 상세 renderer를 rollback mode로 실행한 회귀에서는 사용자 명시 checklist 버튼 요청 계약 1건 및 v2 response 검증을 계속 확인한다. shell은 버튼이나 자동 checklist 경로를 만들지 않는다. 분석 endpoint 호출도 상세 route에서 0건이다.

projection/navigation 전후 기존 결과 DOM은 동일했고 브라우저 검증에서 detection·relation·risk·case summary 렌더링은 재실행되지 않았다. backend state, checkpoint, publication, SSE, report, guidance digest, source data는 변경 경로에 연결하지 않았다. 이 단계는 analysis API를 호출하거나 그 상태를 갱신하지 않는다.

## Rollback / 롤백

`frontend/app.js`의 `USE_WORKSPACE_DETAIL_SHELL_36_6B` 한 곳이 rollout switch다. 이를 `false`로 바꾸면 기존 `renderCaseDetail(item, index)` 경로가 사용된다. 이전 renderer, checklist와 guidance 구현은 제거하지 않았고 rollback을 위해 데이터 migration이나 API/backend 변경이 필요 없다. 이 단일 switch 변경은 rollback 전용 작은 patch로 검토한다.

roll back trigger: canary/사례 혼입, unknown field 수용, route/history에 민감 데이터 유입, 자동 POST, 분석 호출/변경, focus/expiry 실패 또는 기존 endpoint 회귀.

## 성능 관측

브라우저 검증은 warm-up 후 1·32·256 합성 closed projection batch를 각각 100회 측정하고, 요청/응답 대신 projection input/output bytes를 기록한다. route 전환은 2회 warm-up 뒤 8개 관측, DOM node와 serialized shell HTML bytes를 측정했다.

| synthetic batch | projection 생성 median / p95 / max | input bytes | output bytes |
| ---: | ---: | ---: | ---: |
| 1 | 0.1 / 0.2 / 0.2 ms | 5,406 | 663 |
| 32 | 0.3 / 0.3 / 0.7 ms | 172,992 | 21,185 |
| 256 | 1.4 / 1.6 / 2.1 ms | 1,383,936 | 169,473 |

route 전환(2 warm-up, 8 samples)은 median 66.996 ms / p95 68.542 ms / max 68.542 ms, shell DOM 23 nodes, HTML 1,490 bytes였다. route 관측은 작은 Chromium 개발 환경의 합성값이다. 운영 SLA, 최악 지연 또는 실제 production workload 보장이 아니다.

## 이번 범위와 다음 단계

- 포함: closed projection, 기존 hash route navigation shell, history/direct-entry expiry, case isolation, 기존 renderer rollback 경로
- 제외: 승인 prototype dashboard 스타일, timeline, 작업 master-detail, citation/evidence 화면, 기존 화면 제거, API/schema/backend/analysis 변경, dependency 추가
- 36.6C: 축약 dashboard와 독립 상세 개요
- 36.6D: 접근 가능한 activity timeline 및 non-causal relation 표시
- 36.6E: 확인 작업, citation/한계 progressive disclosure, explicit checklist 연결
- 36.6F: 320 CSS px, 실제 200% reflow, 19px target, keyboard/ARIA/axe 수용
- 36.6G: 새 화면 사용자 수용 후 기존 화면 제거 여부 별도 결정

200% equivalent overflow와 19px target은 해결 완료가 아니다. 36.6F 차단 항목으로 유지한다. Safari와 실제 모바일 기기는 `NOT_TESTED`; Safari는 `USER_HOME_ISOLATION_BLOCKED`다. Vector/VM은 `USER_ACTION_REQUIRED / ISOLATION_BLOCKED`로 변경하지 않았다. 실제 사용자 자료·조직 운영·자동 대응은 `NO_GO`; 모델 기반 AI는 `NOT_TESTED`다.
