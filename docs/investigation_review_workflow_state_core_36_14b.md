# Phase 36.14B — 검토 상태 closed DTO와 메모리 core

## 판정 범위

권고 판정: `PHASE_36_14B_REVIEW_WORKFLOW_STATE_CORE_LOCAL_CONDITIONAL_GO`. 시작 기준은 `efaf37a038fd786ab48382c6703d68745ac80c31`, exact push run [41334854186](https://github.com/misosos/ai-security-log-analyzer/actions/runs/41334854186)이며 `push / completed / success`였다. 이 구현은 독립 Python core와 합성 테스트만 추가한다. API/UI 연결, durable 저장, 운영 승인을 뜻하지 않는다.

## DTO와 저장 allowlist

`app/investigation_review_state_36_14b.py`의 `ReviewCaseIdentity`, `ReviewStateSnapshot`, `ReviewTransitionCommand`, `ReviewResetCommand`는 모두 frozen·slots DTO다. 스키마는 정수 `1`만 허용한다. `analysis_ref`는 `a_` + 32 lowercase hex, `case_ref`는 기존 계약과 같은 `c_` + 24 lowercase hex로 제한한다. 대소문자·공백 보정은 하지 않는다. 제목, 순서, 위험도, timestamp, fingerprint는 식별자로 쓰지 않는다.

Snapshot 필드는 identity, `review_state`, `revision`뿐이다. Timestamp를 저장하지 않는다. JSON 유사 mapping 변환은 명시 필드만 생성하고 unknown key를 거부한다. `repr`은 opaque ref를 숨긴다. 저장소는 상태 snapshot만 보유하며 raw event, request, 분석 DTO를 입력받지 않는다.

허용 상태는 `unreviewed`, `in_review`, `reviewed`, `deferred`다. `reviewed`는 해결·안전·오탐 확정이 아니며 `deferred`는 낮은 위험이나 검토 불필요가 아니다. 분석 결과, 탐지·관계·risk·case·checklist·report와 별도 작업 metadata다.

## 전이와 revision/CAS

| 현재 상태 | 일반 명시 전이 |
| --- | --- |
| `unreviewed` | `in_review`, `reviewed`, `deferred` |
| `in_review` | `reviewed`, `deferred` |
| `reviewed` | `in_review`, `deferred` |
| `deferred` | `in_review`, `reviewed` |

모든 상태에서 `unreviewed`로 복귀하는 것은 `ReviewResetCommand`만 허용한다. 동일 상태 전이는 no-op 성공으로 취급하지 않는다. 등록된 사례는 revision `0`에서 시작하며 명시적인 성공 변경마다 `1` 증가한다. 각 command는 strict non-bool integer `expected_revision`을 요구한다. 최대 revision은 `(2^53)-1`로 제한해 향후 JSON/JavaScript 경계에서도 정수 정밀도를 보장한다. stale revision, 잘못된 전이 및 상한 실패는 상태를 바꾸지 않는다. last-write-wins를 허용하지 않는다.

단일 표준 `threading.Lock`이 조회/전이/초기화/분석 교체를 직렬화한다. 이 compare-and-set (CAS) 계약에서 동일 revision 동시 변경은 하나만 성공하고 다른 변경은 `STALE_REVISION`이다. 폐기와 변경의 경쟁은 lock 순서에서 원자적으로 선형화된다.

## 세대 격리와 수명

저장소는 한 시점에 활성 analysis generation 하나만 둔다. `register_analysis`는 opaque generation과 검증된 사례 ref 목록만 받으며 최대 128개를 복사·검증한 뒤 원자적으로 기존 세대를 교체한다. 동일 active analysis ref 재등록은 상태 초기화 우회가 되지 않도록 거부한다. 새 generation은 모두 `unreviewed/revision=0`으로 시작한다. 동일 case ref라도 다른 generation에서는 상태가 재사용되지 않는다. 사례 순서는 결과 결합에 쓰이지 않으며 반환 순서는 ref 기준으로 결정적이다.

128건 상한은 기존 checklist/projection 경계인 `MAX_CASES = 128`에 맞춘다. 저장소는 활성 분석 하나(`MAX_ACTIVE_ANALYSES = 1`), 전체 상태 128개, case ref 26자, analysis ref 34자, revision 상한을 강제한다. 초과 시 기존 활성 상태를 보존하고 fixed error를 낸다. 자동 LRU 삭제는 없다. `clear_analysis`와 `clear_all`은 명시 함수이며 `close`는 상태를 제거한 뒤 추가 사용을 막는다. reload/direct route 복구는 기존 projection을 복원하지 않으므로 이 메모리 상태도 재생성하지 않는다.

오류 category는 `INVALID_INPUT`, `INVALID_IDENTIFIER`, `UNSUPPORTED_SCHEMA`, `UNKNOWN_ANALYSIS`, `UNKNOWN_CASE`, `INVALID_TRANSITION`, `STALE_REVISION`, `CAPACITY_EXCEEDED`, `STORE_CLOSED`, `ANALYSIS_ALREADY_ACTIVE`, `REVISION_LIMIT_REACHED`로 닫혀 있다. 메시지와 repr은 입력·식별자를 echo하지 않는다. 손상/미지원 상태는 분석 손상이나 안전 판정으로 바꾸지 않으며, 이 memory-only core에는 외부 복구 경로가 없다.

## Privacy, 연결 경계와 불변성

저장 가능한 필드는 schema version, opaque analysis/case ref, enum state, revision뿐이다. 원문 로그, event object, 계정, IP, hostname, 경로, token, checkpoint, 자유 입력 note, 정확한 timestamp는 저장하지 않는다. content fingerprint도 생성하지 않는다. 식별값은 허용된 opaque reference 문법으로 제한되고 오류/`repr`에서는 숨겨진다.

모듈은 FastAPI route, request path 또는 frontend에서 import하지 않는다. 공개 OpenAPI, checklist, file/text API, report, checkpoint, publication, SSE, queue UI는 변경하지 않는다. 상태 변경 함수는 checklist 요청이나 분석 재실행을 호출하지 않는다. API/UI 배선 및 공개 schema 변경은 후속 검토 전까지 하지 않는다. 자유 입력 메모는 `DEFERRED`다.

## 테스트와 한계

새 focused test는 closed DTO, enum, 입력 검증, 허용 전이, CAS/stale, reset, generation/case 격리, capacity 보존, immutable snapshot, privacy repr/error, Hypothesis 상태 전이, 동시 변경 및 clear 경쟁을 확인한다. 문서 계약 테스트는 설계 경계와 core의 request/frontend 비연결을 고정한다. Phase 36.14A 문서는 상태 의미와 memory-only 수명 기준으로 유지된다.

이 단계는 API authentication/CSRF, durable 저장, 여러 탭 합의, 재시작 후 projection 복원, UI 접근성·사용자 이해도 또는 운영 성능을 검증하지 않는다. Ubuntu/Linux 전용 CI는 새 SHA에서 아직 검증되지 않았다. Safari와 실제 모바일은 검증하지 않았다. 실제 사용자 자료·조직 운영·자동 대응은 `NO_GO`; 모델 기반 AI는 사용하지 않는다.

## 다음 Phase gate와 rollback

- **36.14C:** API/persistence 필요성부터 재검토한다. 새 snapshot 수명, same-origin/CSRF, body limit, stale write, 권한·삭제 계약이 승인되지 않으면 API나 SQLite를 구현하지 않는다. 경계 위반 시 core 연결을 중단하고 이 독립 모듈을 제거해 기존 분석·큐만 유지한다.
- **36.14D:** 별도 승인 후 UI 상태 선택과 필터를 연결한다. 자동 상태 변경, risk/checklist 변경 또는 오해 유발 시 UI 변경을 되돌린다.
- **36.14E:** privacy, stale, keyboard, target 및 reflow E2E가 모두 통과해야 한다. 실패 시 사용자 검수 전에 rollback한다.
- **36.14F:** 합성 화면 사용자 수용 검수만 진행한다. FAIL은 보존하고 자동화로 PASS 대체를 금지한다.

이 Phase의 로컬 조건부 판정은 closed DTO와 bounded memory store의 합성 검증에 한정된다. Production API/UI 승인, durable 상태 저장 승인, workflow 완료 또는 보안 판정 승인이 아니다.
