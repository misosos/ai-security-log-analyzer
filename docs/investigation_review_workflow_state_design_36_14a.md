# Phase 36.14A — 검토 진행 상태 설계와 보안 경계

## 1. 목적과 판정 범위

이 문서는 검토 큐에 분석가의 작업 진행 상태를 덧붙이기 위한 설계와 위협 경계를 정한다. 현재 production 화면은 검색·필터·정렬만 제공한다. 이번 Phase는 설계 및 문서 계약 테스트만 추가하며 production 코드, API, frontend, dependency와 lockfile은 변경하지 않았다. 저장 파일이나 데이터베이스도 만들지 않았다.

시작 Gate: `main`, clean tree, HEAD/local main/origin main `d97e70d83588adf263c1ab64cf0a101b068837b2`, ahead/behind `0/0`. Exact push run [41334854186](https://github.com/misosos/ai-security-log-analyzer/actions/runs/41334854186)는 해당 SHA에서 `completed/success`; 전체 pytest 3590 passed·기존 warning 2개, 필수 Linux·Restricted Report·Chromium/axe·tracked-file 검사 성공, artifact 0개였다. Annotated `v0.4.0` tag object는 `855a92827a605805b62c627ed719958620150ec4`이고 peeled tag target 및 GitHub Release target은 기존 `eecd6ee1cda0545e34b01c42e1a2163a899bcc27`였다.

권고 상태는 `PHASE_36_14A_REVIEW_WORKFLOW_STATE_DESIGN_LOCAL_CONDITIONAL_GO`이다. 이는 후속 구현을 위한 설계 검토 결과이며 production 구현·실제 사용자 자료·조직 운영 승인이 아니다. production 코드·API·frontend는 변경하지 않았다.

## 2. 조사한 현재 구조

- 공개 사례 응답은 `app/models/investigation_sample_api.py`의 closed Pydantic 모델을 통과한다. `checklist_ref`는 `c_`와 소문자 24자리 hex 형식이며 요청 응답 범위의 opaque `case_ref`다. 기존 문서는 이를 분석 간 안정 식별자로 쓰지 않는다고 명시한다.
- `frontend/app.js`는 검증된 response로 `investigation-workspace-ui/v1`의 19필드 projection을 만들고, `caseByRef`, `currentInvestigation`, `currentInvestigationMode`, `workspaceDetailGeneration`을 브라우저 메모리에 둔다. 결과 교체 전에는 projection map과 `reviewQueue`를 지운다.
- `frontend/review-queue-ui-36-13a.js`의 검색·필터·정렬 값은 메모리에만 있다. 상세로 이동하면 현재 projection을 사용하고, browser back/forward는 같은 문서 메모리에서 목록을 복원한다. history state에는 목록 scroll/focus만 저장한다.
- 기존 `#/investigations/{case_ref}` route는 opaque case ref만 담는다. direct-entry, reload 또는 stale ref에 current projection이 없으면 고정 만료 화면을 제공하며, 이전 사례를 추측해 연결하거나 분석을 재요청하지 않는다.
- checklist 요청은 `frontend/app.js`의 상세 화면에서 `확인할 작업 불러오기` 버튼을 누른 뒤에만 `POST /api/v1/investigations/checklist`로 전송된다. 목록 진입·route 왕복·workflow metadata 변경은 checklist 요청을 발생시키지 않아야 한다.
- 새 분석·결과 제거는 `clearPreviousResult()`를 통해 현재 queue와 사례 projection을 비운다. 입력 품질 요약도 기존 응답 렌더링 과정에서 별도 영역으로 관리한다.

기준 구현·계약은 [검토 큐 Phase 36.13A](investigation_review_queue_controls_36_13a.md), [compact controls Phase 36.13A1](investigation_review_queue_compact_controls_36_13a1.md), [closed projection/navigation Phase 36.6B](investigation_workspace_projection_navigation_36_6b.md) 및 위 source files다. 이 설계는 확인된 동작과 이후 희망 기능을 구분하며, 아직 없는 durable analysis snapshot을 있다고 가정하지 않는다.

## 3. 상태 모델과 분석 불변식

닫힌 상태 집합은 다음 네 값으로 제한한다.

| 값 | 조사자 작업 의미 | 보안 판단이 아닌 것 |
| --- | --- | --- |
| `unreviewed` | 현재 분석 세대에서 아직 상태를 지정하지 않음. 명시 레코드가 없을 때의 기본값 | 낮은 위험, 안전, 미탐 또는 미확인 공격이 아님 |
| `in_review` | 조사자가 현재 검토를 진행 중이라고 표시 | 진행 완료, 확인된 침해 또는 위험도 변경이 아님 |
| `reviewed` | 조사자가 이 항목을 검토했다고 표시 | 해결, 안전, 무해, 오탐 확정, 종결 또는 조치 완료가 아님 |
| `deferred` | 조사자가 이 항목의 확인을 나중으로 미룸 | 낮은 우선도, 무시 가능, 위험 감소 또는 검토 불필요가 아님 |

**분석 결과와 workflow 상태는 분리한다.** 상태는 분석 response, 탐지·관계·risk·case, 입력 품질, review priority, checklist, report, checkpoint, publication, SSE와 독립된 조사자 작업 메타데이터다. 상태나 상태 필터는 표시 범위만 바꾼다. 탐지 0건, `reviewed`, `deferred` 또는 `unreviewed`를 안전 판단으로 표현하지 않는다. 상태별 개수는 분석 결과 건수와 별도 이름·영역으로 집계한다. 자동 상태 변경 금지: 상태 변경은 사용자 조작으로만 발생한다.

현재 세대에서 상태를 변경하는 유일한 원인은 조사자의 명시적 상태 선택이다. 새 분석은 새 세대를 만들고 그 세대의 항목은 `unreviewed`로 시작한다. checklist 응답, 위험도 변경, 시간 경과, route 이동, 화면 표시, 저장 복구가 상태를 자동 변경하지 않는다.

허용 전이:

| 현재 | 사용자가 선택할 수 있는 다음 상태 |
| --- | --- |
| `unreviewed` | `in_review`, `reviewed`, `deferred` |
| `in_review` | `reviewed`, `deferred` |
| `reviewed` | `in_review`, `deferred` |
| `deferred` | `in_review`, `reviewed` |

모든 상태에서 `unreviewed`로 되돌리기는 별도의 명시적 상태 초기화 동작으로만 허용한다. `reviewed`는 terminal state가 아니다. 전이 제약은 잘못된 enum을 막고 사용자가 선택한 작업 의미를 보존하기 위한 것이다. 저장 성공을 확인하기 전에는 UI가 변경 성공을 표시하지 않는다.

## 4. 사례 결합과 세대 수명

카드 제목, display order, 위험도, 시간, 역할 또는 배열 위치는 식별 키가 될 수 없다. 같은 제목의 서로 다른 사례와 순서 변경이 흔히 가능하기 때문이다.

후속 durable 설계에서 필요한 논리 키는 다음의 닫힌 조합이다.

```text
(schema_version, analysis_ref, case_ref)
```

- `case_ref`: 기존 검증된 `c_[0-9a-f]{24}` 형식. 현재 응답의 사례를 가리키며 분석 간 안정성이 없다.
- `analysis_ref`: 현재 memory-only 후속 단계에서는 검증된 response를 설치할 때 새로 만드는 문서 메모리 generation token이다. 이후 durable API가 승인되면 서버가 128-bit 이상 무작위 값 또는 동등한 CSPRNG ID를 발급하고 해당 response의 허용 `case_ref` 집합에 묶어야 한다. 입력·사용자·시간·사례 내용을 해시해 만들지 않는다.
- `schema_version`: 저장 계약을 닫고 migration 경계를 명시한다.
- 결정적 analysis fingerprint는 사용하지 않는다. 원문을 저장하지 않더라도 내용 지문은 같은 입력·결과를 재연결하고 반복 사용을 추적할 수 있다. 현재 시스템에는 이를 정당화할 필요가 없다.

`analysis_ref`는 현재 API response나 hash route에 추가하지 않았고, 아래 DTO/API는 후속 설계 초안일 뿐이다. 새 분석마다 항상 새 generation을 만든다. 입력이 같아 보여도 예전 상태를 자동 재사용하지 않는다. 다른 분석의 상태를 현재 분석에 결합하지 않는다.

| 상황 | 요구 동작 |
| --- | --- |
| 새 분석 / 다른 입력 / 같은 제목의 다른 사례 | 새 generation; 모든 항목 기본 `unreviewed`; 이전 상태와 결합 금지 |
| 같은 generation에서 카드 순서 변경 | `(analysis_ref, case_ref)`로 결합; 순서에 영향받지 않음 |
| 상세 화면 진입 후 뒤로/앞으로 | 같은 document-memory generation이 살아 있는 동안 해당 workflow map을 유지 |
| 직접 URL 진입 / browser reload | 현행처럼 projection이 없으면 만료 안내; 이전 상태를 복원하거나 분석을 재요청하지 않음 |
| stale `case_ref` 또는 다른 generation | 읽기/쓰기 거부; 사례 상태를 다른 항목에 대체 결합하지 않음 |
| 서로 다른 상태로 열린 여러 탭 | 현재 권고인 memory-only에서는 탭마다 별도 상태, 탭 간 일관성 보장 없음; 서로 덮어쓰지 않음 |
| 미래 저장소에서 동시 변경 | `revision` 비교 후 stale write 거부; last-write-wins 금지 |
| 알 수 없는 schema version | 적용하지 않음; 고정 `workflow_state_unavailable` 상태로 격리/보고; 자동 downgrade 금지 |
| 손상 또는 일부 필드 누락 | 해당 workflow metadata를 거부; 분석 결과는 계속 표시; 조용히 기본값으로 성공 복구하지 않음 |

알 수 없는 `case_ref`(unknown case_ref)도 같은 방식으로 거부하며 오류 응답에서 참조값을 되돌려 주지 않는다.

상태 초기화·해당 generation 삭제는 명시적인 사용자 동작만 수행한다. 저장소 용량 정리나 stale 레코드 제거 정책이 필요해지면 보존 기간·삭제 대상·오프라인 백업까지 별도 설계하며 분석 결과를 근거 없이 자동 삭제하지 않는다.

## 5. 저장 후보 비교 및 권고

현재 분석 projection은 새로고침 뒤 복원되지 않는다. workflow 상태만 디스크에 저장해도 reload 뒤 사례 projection이 없어 상태를 안전하게 적용할 수 없다. 그래서 현 구조에서의 최종 권고는 **메모리 전용**이다. 같은 analysis generation의 상세 왕복 동안 상태를 유지하고, 새 분석·명시적 결과 제거·문서 종료 시 폐기한다. 이는 영속성 편의보다 현재의 projection 수명과 stale-case 차단을 일치시킨 선택이다.

| 기준 | 메모리 전용 | `sessionStorage` | `localStorage` | 서버 로컬 JSON sidecar | Python 표준 SQLite |
| --- | --- | --- | --- | --- | --- |
| 새로고침 후 유지 | 아니오. projection과 함께 만료 | 탭 새로고침에는 유지 가능하나 projection은 복원 안 됨 | 유지하지만 현재 분석과의 안전한 연결 불가 | 재시작 후 유지하나 projection은 복원 안 됨 | 유지하나 projection은 복원 안 됨 |
| 브라우저 종료 후 유지 | 아니오 | 일반적으로 탭/세션 종료 시 목적에 맞지 않음 | 예 | 브라우저와 무관 | 브라우저와 무관 |
| 다중 탭 일관성 | 탭별 독립; 충돌 없음 | 탭별 저장 영역이 기본; 동기화 설계 필요 | 같은 origin에서 공유되나 동시 변경 충돌 처리 필요 | 서버 여러 worker 간 lock/version 필요 | transaction/CAS 설계로 충돌 검출 가능 |
| 조작·손상 가능성 | 현재 JS 실행 중 메모리 값은 코드 경계 내 | 같은 origin JS에서 읽고 조작 가능 | 같은 origin JS에서 읽고 조작 가능 | 로컬 계정/프로세스가 직접 편집 가능, 손상 가능 | 로컬 계정/프로세스가 편집 가능, DB 손상 가능 |
| 민감정보 노출면 | 가장 작음; 분석 session 수명만 | browser profile과 same-origin JS | browser profile·same-origin JS·오래된 데이터 | 앱 데이터 디렉터리·백업·권한·잔존 파일 | DB/WAL/journal·백업·권한·잔존 페이지 |
| 원자적 쓰기·충돌 | 단일 문서 이벤트 루프 내 동기 변경 | 개별 key 쓰기; 다중 field 트랜잭션 제한 | 개별 key 쓰기; 다중 field 트랜잭션 제한 | 임시 파일+rename 및 OS lock 직접 설계 필요 | transaction 원자성 제공; revision CAS 추가 필요 |
| 백업·삭제 | 문서 수명 종료 시 소멸 | 브라우저 제거·clear 가능 | 설정·사이트 데이터에서 제거 가능 | 파일 복사·삭제 가능; 잔존·백업 통제 필요 | 파일 백업·삭제 가능; WAL/삭제 페이지 처리 필요 |
| 파일 권한 | 해당 없음 | 브라우저 profile ACL에 의존 | 브라우저 profile ACL에 의존 | `0600`/private directory 등 플랫폼별 설정 필요 | `0600`/private directory 및 journal 파일 권한 필요 |
| stale analysis 격리 | generation별 map과 projection 교체 시 간단 | 명시 generation key 필요; reload projection 없음 | 명시 generation key 필요; 오래된 key 정리 필요 | `analysis_ref` 및 사례 집합 검증 필요 | 복합 primary key와 사례 집합 검증 필요 |
| 테스트 가능성 | 결정적 unit/browser 테스트 용이 | browser profile·reload·tab 테스트 필요 | cross-tab·profile cleanup 테스트 필요 | filesystem·권한·atomic rename 테스트 필요 | transaction·lock·crash/corruption 테스트 필요 |
| dependency 추가 | 없음 | 없음 | 없음 | 없음 | 없음(Python stdlib `sqlite3`) |
| 현재 단일 사용자 local-first 적합성 | **현재 lifecycle에 가장 적합** | stale projection 문제로 부적합 | 불필요하게 긴 client-side 잔존 | 현재 snapshot 수명과 불일치 | 향후 resumable analysis snapshot이 생길 때 후보 |

`sessionStorage`/`localStorage`는 같은 origin에서 실행되는 JavaScript가 접근·수정할 수 있고 저장 내용을 신뢰할 수 없다는 OWASP 지침을 고려해 권고하지 않는다. 서버 파일은 사용자 권한에서 벗어나 권한·백업·원자적 교체를 직접 책임져야 한다. SQLite는 transaction 원자성과 표준 라이브러리 이점이 있지만, 분석 projection의 부재와 generation 수명 문제를 해결하지 않는다. SQLite 삭제가 매체의 모든 잔존 사본을 지운다고 보장할 수도 없다.

### 최종 권고

현재 분석 response와 projection이 document-memory 수명이므로 첫 상태 저장소는 메모리 전용으로 제한한다. 지속 저장을 선택하지 않는 것은 향후 요구를 부정하는 것이 아니라, 다시 열 수 있는 analysis snapshot 계약이 준비되지 않은 현재 구조에 orphan 상태를 남기지 않기 위한 경계다.

**향후 영속 상태가 꼭 필요해지고, 사용자가 다시 열 수 있는 분석 snapshot을 별도로 설계·승인한 경우의 후보는 SQLite**다. 그때도 각 DB row는 위 복합 키, closed enum, `revision` 및 최소 상태만 담는다. 현 단계에서는 SQLite도 만들지 않는다. durable analysis snapshot 자체가 없는 상태에서 상태만 영속화하는 구현은 이익보다 orphan/stale 상태 위험이 크다.

향후 SQLite 후보의 논리 schema 예시는 다음과 같다. 이 SQL은 설명용이며 이번 단계에서 실행하거나 DB 파일을 생성하지 않았다.

```sql
CREATE TABLE review_workflow_state_v1 (
  schema_version INTEGER NOT NULL CHECK (schema_version = 1),
  analysis_ref TEXT NOT NULL,
  case_ref TEXT NOT NULL,
  review_state TEXT NOT NULL CHECK (
    review_state IN ('unreviewed', 'in_review', 'reviewed', 'deferred')
  ),
  revision INTEGER NOT NULL CHECK (revision >= 0),
  PRIMARY KEY (schema_version, analysis_ref, case_ref)
);
```

## 6. 저장 DTO와 함수 경계 초안

현재 구현하지 않는 후속 closed DTO 후보:

```text
ReviewWorkflowStateV1 (frozen, strict, extra fields forbidden)
  schema_version: literal 1
  analysis_ref: opaque random generation ID
  case_ref: c_[0-9a-f]{24}
  review_state: unreviewed | in_review | reviewed | deferred
  revision: integer >= 0
```

`updated_at`은 저장하지 않는 것을 권고한다. 정확한 시각은 workflow 사용 분석·근무 습관 추론에 쓰일 수 있고, UI 의미에 필요하지 않으며 시계·timezone·결정성 복잡도를 더한다. 생성된 시간순 정렬은 추가하지 않는다. `revision`은 optimistic concurrency용 단조 증가 정수이며 보안 순서나 분석 시간을 뜻하지 않는다.

후속 pure boundary 후보:

```text
new_analysis_generation() -> opaque analysis_ref
initial_workflow_state(analysis_ref, validated_case_refs) -> immutable state map
transition_state(current, requested_state, expected_revision, explicit_user_action) -> updated | fixed conflict
read_workflow_state(analysis_ref, validated_case_refs) -> closed state set | unavailable
delete_workflow_state(analysis_ref, explicit_user_action) -> fixed result
```

저장 실패 시 이미 계산된 분석 결과는 그대로 표시하고 workflow metadata만 `unavailable`로 둔다. 저장 실패·검증 실패·stale revision은 상태 변경 성공으로 보여주지 않는다. 예외 문자열이나 파일 위치를 UI/API에 싣지 않는다. 상태 filter가 추가되더라도 검토 카드의 표시 subset만 바꾼다.

## 7. API 경계 초안 — 저장 구현 전용

현재 구조에서는 API가 필요 없다. 메모리 전용 구현은 기존 validated analysis generation 내부의 함수 호출만으로 가능하다. 아래는 향후 durable snapshot이 별도 승인된 뒤에만 재검토할 API 초안이며 이번 Phase에 route·schema·request를 추가하지 않았다.

```text
GET /api/v1/investigations/{analysis_ref}/review-state
PUT /api/v1/investigations/{analysis_ref}/cases/{case_ref}/review-state
DELETE /api/v1/investigations/{analysis_ref}/review-state
```

- 요청/응답은 versioned closed envelope만 허용하고 unknown field, unknown enum, duplicate JSON key, NaN/Infinity를 거부한다. body는 1 KiB 이하의 작은 고정 상한을 둔다.
- PUT 요청 예: `{schema_version: 1, expected_revision: 2, review_state: "in_review"}`. 성공 response는 분석 결과를 포함하지 않는 `{schema_version, analysis_ref, case_ref, review_state, revision}`만 반환한다.
- `analysis_ref`가 만료됐거나 `case_ref`가 해당 분석 사례 집합에 없으면 404 fixed error; 참조값을 오류 문구에 echo하지 않는다. 저장 장애는 503 `WORKFLOW_STATE_UNAVAILABLE`, stale revision은 409 `STALE_REVISION`, 잘못된/미지원 schema 또는 값은 400/422 fixed error로 구분한다.
- 같은-origin 요청만 허용하고 exact `Origin`/`Host` 및 loopback bind 경계를 검증한다. mutating request는 JSON content type, CSRF 방어용 same-origin 정책과 필요시 unpredictable CSRF token을 확인한다. CORS wildcard 금지. 현재 API의 검증 계약과 별도로 구체 route 설계를 검토한다.
- PUT는 반드시 사용자의 명시적인 상태 조작에서만 발생한다. 화면 진입·분석 완료·필터 조작·checklist 응답은 GET/PUT/POST를 자동 발생시키지 않는다. 상태는 checklist body에도 넣지 않는다.
- optimistic update는 `expected_revision`이 현재 revision과 일치할 때만 원자적으로 적용한다. 충돌에는 현재 상태를 덮어쓰지 않고 재확인을 요구한다. last-write-wins는 금지한다.
- DELETE는 명시적 사용자 확인을 받은 특정 `analysis_ref` 범위의 상태만 지운다. 전체 상태 초기화는 별도 명시 조작이며 implicit cleanup, report export, clipboard, API 분석 response 또는 URL query/hash에 자동 포함하지 않는다.

## 8. 무결성·개인정보 위협 경계

저장 가능한 필드는 version, random generation ref, opaque case ref, 허용 상태 enum 및 revision뿐이다. projection에 원문 로그·event 객체·account·IP·hostname·경로·token·checkpoint 내용·category별 evidence·report를 넣지 않는다. 자유 입력 메모는 `DEFERRED`다. 메모가 필요하면 길이 제한, 민감정보 경고, 저장·삭제·export·clipboard 경계와 사용자 검토를 별도 Phase에서 정한다.

- 알 수 없는 schema version과 unknown field는 적용하지 않는다. 자동 migration/downgrade로 의미를 추측하지 않는다.
- 손상·필드 누락·잘못된 revision은 workflow 상태만 unavailable 처리한다. 분석 response를 훼손하거나 빈 결과/안전으로 재표현하지 않는다.
- 후속 persistent store의 revision 비교는 stale write를 차단한다. 그렇더라도 마지막 저장자 우선(last-write-wins) 위험을 설계·테스트에서 명시한다.
- 상태 초기화와 삭제는 사용자 명시 동작으로만 실행한다. 종료/만료 때 삭제하는 경우에도 별도의 보존 정책과 UI 설명이 필요하다.
- HTML report, public API response, clipboard, URL query/hash, checkpoint, publication, SSE와 분석 재실행에 workflow status를 자동 포함하지 않는다.
- status update 또는 status filter로 checklist API를 요청하지 않는다. workflow 상태는 detection, relation, risk, case projection과 별도다.
- 저장 불가·schema 불일치·permission 오류는 fixed category만 노출한다. Python repr, 경로, 원문, 내부 예외를 로그/응답에 기록하지 않는다.

## 9. UI wireframe과 상호작용

Production UI를 이번 Phase에서 바꾸지 않는다. 향후 compact queue에 다음과 같이 시각 위계가 낮은 metadata를 배치한다.

```text
검토 건 12건                         [위험도 배지] [역할 배지]
제목 / 기존 안전 요약                검토 상태: [검토 전 ▾]
                                       (검토함은 안전 또는 해결을 뜻하지 않습니다)

검토 상태 필터: 전체 | 검토 전 | 검토 중 | 검토함 | 나중에 확인
검토 상태별 항목: 12건  ·  분석 결과 수와 별도 집계
```

상태 선택은 native select 또는 접근 가능한 button/menu로 키보드 변경 가능해야 한다. 저장 전/성공/실패/unavailable 피드백을 분리하고, `reviewed`를 종결·성공 색상이나 위험도보다 높은 우선 계층으로 표시하지 않는다. 상태 badge는 기존 risk·role badge와 겹치지 않게 작은 보조 정보로 배치한다. 모바일은 badge를 카드 하단의 별도 줄에 놓고 200% reflow에서 겹침·가로 overflow가 없어야 한다. 실제 target 크기, focus-visible, screen reader name, axe와 keyboard 검증은 후속 E 단계의 필수 gate다.

상태별 개수는 “검토 상태별 항목”으로 표현하고 위험도·탐지 count와 시각적으로 분리한다. 상태 filter는 현재 projection의 표시 범위만 바꾸며 `검토함은 안전 또는 해결을 뜻하지 않습니다`라는 안내를 유지한다.

## 10. 전이·실패 예시

```text
unreviewed ──(사용자 선택)──> in_review ──(사용자 선택)──> reviewed
      │                          │                          │
      └──(나중에 확인)──> deferred <──(사용자 선택)─────────┘
                                  │
                                  └──(사용자 선택)──> in_review

각 상태 ──(명시적 초기화만)──> unreviewed
```

검토 항목이 목록에서 사라졌다고 상태가 삭제되거나 완료 처리되지 않는다. status POST 실패/409/permission error는 기존 위험도와 analysis response를 유지하며 fixed message로 실패를 알린다. 사용자는 새로고침이나 재분석을 통해 workflow 저장 성공을 추론하지 않는다.

## 11. Research Basis — 공식 자료와 적용 범위

자료는 2026-11-02 확인했다. 제품의 용어를 복사하는 것이 아니라 사용자 작업 상태와 보안 판정을 분리하는 설계 참고로만 사용한다.

- NIST SP 800-61 Rev. 3은 incident response를 조직의 risk management 전반에 통합하는 지침이다. 이 문서에서는 그 점을 근거로 analyst workflow metadata를 incident 사실이나 확정된 보안 판정으로 부풀리지 않는다. 제품 UI의 특정 상태 enum이나 저장 방식을 NIST 표준이라고 주장하지 않는다. [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- Microsoft Sentinel은 사건 목록의 New/Active/Closed 상태와 severity 필터를 설명한다. 그 운영 상태는 외부 incident lifecycle에 속하므로 이 프로젝트의 `reviewed`·`deferred`로 그대로 옮기지 않는다. 여기서 참고하는 것은 상태 필터와 severity가 별도 축이라는 UI 구조뿐이다. [Microsoft Sentinel incident triage](https://learn.microsoft.com/en-us/azure/sentinel/investigate-cases)
- Elastic Security Cases는 사례 수집·협업·종결과 alert 동기화를 설명한다. 이 시스템은 사례 협업 저장소나 종결/alert status 연동이 없으므로 해당 기능이나 의미를 복제하지 않는다. [Elastic Security cases](https://www.elastic.co/docs/solutions/security/investigate/security-cases)
- OWASP HTML5 Security는 Web Storage가 동일 origin JavaScript에서 읽고 수정될 수 있으며 stored data를 신뢰하지 말라고 권고하고, persistent storage가 필요하지 않으면 `sessionStorage`를 고려하라고 설명한다. 여기서는 더 좁은 기존 memory-only projection 수명과 개인정보 표면을 우선해 Web Storage도 선택하지 않는다. [OWASP HTML5 Security](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html)
- SQLite transaction은 atomic commit 특성을 제공하지만, 이는 분석 snapshot identity나 저장 파일 권한·삭제 잔존 문제를 해결하지 않는다. `secure_delete` 동작도 설정과 DB 페이지/저널에 따라 별도 고려가 필요하다. 따라서 SQLite는 향후 후보이며 현 구현 선택은 아니다. [SQLite Atomic Commit](https://www.sqlite.org/atomiccommit.html), [SQLite `secure_delete`](https://www.sqlite.org/pragma.html#pragma_secure_delete)

## 12. 구현 단계와 GO/NO_GO/rollback

| Phase | 범위 | GO 조건 | NO_GO 및 rollback |
| --- | --- | --- | --- |
| 36.14B | frozen closed DTO, 허용 전이, 분석 세대별 in-memory state map | unknown field/enum 거부, generation/case 격리, 분석 불변, route 왕복 수명 테스트 통과 | 사례 혼입·상태 자동 변경·분석 결과 변경 시 해당 단계 revert; 기존 검색 큐만 유지 |
| 36.14C | API/persistence 결정 gate. snapshot resume 요구가 없다면 API 구현하지 않음. 필요 승인 시 SQLite transaction store와 same-origin API 설계·구현 | durable snapshot 수명/권한/CSRF/body limit/revision conflict/삭제 정책 합의와 test; 저장 실패가 분석에 영향 없음 | snapshot 없는 영속 상태, stale overwrite, path disclosure, wrong case binding, CSRF 또는 failure false-success 발견 시 endpoint 비활성화/revert |
| 36.14D | 카드 상태 선택과 검토 상태 filter | 명시 조작만 상태 변경, 접근 가능한 피드백, risk/category/checklist 불변 | state를 안전/해결로 오해시키거나 키보드 조작 실패 시 UI switch rollback |
| 36.14E | privacy, corruption, stale write, keyboard, target, 200% reflow, privacy canary E2E | 자동 상태 변경·외부 요청·개인정보 노출 0; stale revision 거부 | 경계·접근성·privacy gate 하나라도 실패하면 사용자 검수 전 중단, 이전 compact queue로 rollback |
| 36.14F | 합성 상태 사용자 이해도 및 workflow 수용 | 각 문항에 실제 화면을 보여주고 사용자 응답을 기록; 의미 오해 없는 별도 수용 | FAIL은 보존하고 다음 질문 중단; 자동화로 PASS 대체 금지; 실제 자료·운영 승인은 별도 |

각 단계는 별도 revert 가능한 커밋으로 유지한다. Phase 36.14C의 SQLite는 저장 대상과 snapshot 재개 계약이 승인되기 전까지 NO_GO다. 자유 입력 메모는 모든 위 단계와 분리해 `DEFERRED` 상태로 둔다.

## 13. 설계 계약 테스트와 검증

`tests/test_investigation_review_workflow_state_design_36_14a_documentation.py`는 설계 문서의 enum, 상태/분석 분리, 자동 전이 금지, 메모 연기, 저장 후보 비교, privacy boundary, API 초안, phase/rollback 및 NO_GO 문구를 고정한다. TDD 첫 실행에서는 문서가 없어서 5개 모두 `FileNotFoundError`로 실패했고, 문서 작성 뒤 계약을 통과했다.

구현 회귀는 이 설계 단계에서 production behavior를 바꾸지 않는 범위로 실행한다. 새 문서 테스트와 전체 pytest, 기존 검토 큐 계약, Phase 36.1·36.2 및 합성 평가, Python/Node syntax, `uv lock --check`, Chromium/axe, external request 검증을 기록한다. Linux-only smoke는 macOS 실행 결과로 대체하지 않으며 실행하지 못하면 `NOT_TESTED`다.

## 14. 한계와 최종 경계

이 문서는 local single-user 분석기 구조를 기준으로 한 설계다. cross-user collaboration, authentication, multi-host synchronization, durable analysis snapshots, team ownership, audit-grade authorship, exact operator timestamps는 범위 밖이다. memory-only 권고는 reload 이후 작업 상태를 보존하지 않는다. 사용자가 reload 후에도 결과와 상태를 재개해야 한다면 분석 snapshot의 보존·삭제·재식별 경계를 먼저 별도 설계해야 한다.

- 실제 사용자 자료: `NO_GO`
- 조직 운영: `NO_GO`
- 자동 대응: `NO_GO`
- production workflow state 저장: 아직 구현하지 않음
- 모델 기반 AI: `NOT_TESTED`; 이번 Phase에서 호출하지 않음

## Sources

- [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final) — 2026-11-02 확인
- [Microsoft Sentinel incident triage](https://learn.microsoft.com/en-us/azure/sentinel/investigate/cases) — 2026-11-02 확인
- [Elastic Security cases](https://www.elastic.co/docs/solutions/security/investigate/security-cases) — 2026-11-02 확인
- [OWASP HTML5 Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html) — 2026-11-02 확인
- [SQLite Atomic Commit](https://www.sqlite.org/atomiccommit.html) 및 [SQLite PRAGMA `secure_delete`](https://www.sqlite.org/pragma.html#pragma_secure_delete) — 2026-11-02 확인
