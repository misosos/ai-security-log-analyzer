# Phase 36.14D — 검토 진행 상태 선택·필터 UI

## 판정과 Gate

판정: `PHASE_36_14D_REVIEW_WORKFLOW_STATE_UI_LOCAL_CONDITIONAL_GO`. 기준 SHA `5ac3e784b9884aec6e8bde21e3661cb04513b47b`, exact push run [41424680105](https://github.com/misosos/ai-security-log-analyzer/actions/runs/41424680105)은 `push / completed / success`였다. 필수 Python·Linux TCP/JSONL/Restricted Report·Chromium/axe·tracked-file 검사에 성공했고 artifact는 0개였다. 시작 당시 `main` 및 origin과 일치했고 working tree clean, ahead/behind `0/0`이었다. `v0.4.0` tag와 Release target은 기존 `eecd6ee1cda0545e34b01c42e1a2163a899bcc27`이었다.

이 판정은 로컬 합성 자동 검증 범위에 한정한다. 새 변경 SHA의 Ubuntu CI와 사용자 수용 검수 전 production 승인으로 해석하지 않는다.

## 구현 구조와 수명

- `frontend/investigation-review-state-36-14d.js`는 고정된 ES module 전역 helper로서 memory store 및 queue UI adapter를 제공한다. module은 Phase 36.14C JSON contract vector를 요청하거나 import하지 않는다.
- 검증된 새 결과를 설치할 때 128-bit `crypto.getRandomValues()`로 새 `a_` + 32 lowercase hex generation을 만든다. 안전한 random을 쓸 수 없으면 검토 상태 UI만 unavailable 처리하고 이미 검증된 분석 결과는 계속 표시한다. `Math.random()` 대체는 없다.
- 현재 response의 검증된 `case_ref`만 최대 128개 등록하며 초기 값은 `unreviewed`, revision 0이다. 저장 projection은 `schema_version`, `analysis_ref`, `case_ref`, `review_state`, `revision` 다섯 필드다.
- store는 브라우저 document memory에서만 유지된다. 목록→상세→뒤로 이동은 동일 store를 사용한다. 새 분석, 결과 제거, 만료 route는 상태를 폐기한다. 새 generation에서 같은 case ref라도 새 `unreviewed` 값으로 시작한다.
- URL/hash/history, API 요청/응답, checklist body, HTML report, clipboard, Web Storage, cookie, 파일 또는 DB에 상태를 쓰지 않는다. 다른 탭과 동기화하지 않는다.

## 상태 의미와 전이

화면 값은 `unreviewed`(검토 전), `in_review`(검토 중), `reviewed`(검토함), `deferred`(나중에 확인)로 제한된다. 검토함은 해결·안전·오탐·조치 완료가 아니며, 나중에 확인은 낮은 위험·무시 가능·검토 불필요가 아니다.

| 현재 상태 | 일반 선택으로 허용되는 상태 |
| --- | --- |
| `unreviewed` | `in_review`, `reviewed`, `deferred` |
| `in_review` | `reviewed`, `deferred` |
| `reviewed` | `in_review`, `deferred` |
| `deferred` | `in_review`, `reviewed` |

동일 상태 전이는 거부한다. `unreviewed` 복귀는 카드 상태 control의 명시적 `상태 초기화 — 검토 전으로` command만 사용한다. 성공할 때만 revision을 1 증가시키며 실패·stale write는 기존 상태를 유지한다. 실패 안내는 고정 한국어 문구고 ref나 예외를 반사하지 않는다.

상태는 명시적인 native select 변경으로만 바뀐다. 검색·risk·role·priority·workflow-state filter, 정렬, 상세 진입, 뒤로 가기, checklist 요청/응답은 상태를 바꾸지 않는다. 분석 결과·risk·case·checklist·report는 별도 객체로 유지한다.

## UI 배치

- 기존 compact queue를 유지한다. 카드의 기존 risk/role/priority badge 행에 상태 badge를 섞지 않고, 카드 하단에 `검토 상태` native select를 둔다. 상세 화면에도 같은 store를 읽고 쓰는 select가 있다.
- 목록 제목 아래에는 현재 분석 전체의 상태 개수를 보조 텍스트 한 줄로 표시하고, “검토 상태는 작업 진행 표시이며 안전·해결 판정이 아닙니다.” 안내를 한 번 둔다. 상태 개수는 검색/필터 결과 수나 분석 건수와 다르다.
- 기존 compact filter panel에 `검토 상태` 한 항목을 더했다. workflow filter와 기존 검색/risk/role/review priority가 AND로 결합되고 표시 집합만 바뀐다. 기존 “조건 초기화”는 workflow 상태를 되돌리지 않는다.
- 상태 select 및 안내는 키보드 접근 가능하고 최소 44px 높이를 유지한다. 상태 의미를 색상에만 맡기지 않는다. filter panel은 넓은 화면에서 4열, 1024px 이하에서 2열, 390/320px에서 1열이다. 200% equivalent zoom도 가로 overflow를 허용하지 않는다.
- `REVIEW_WORKFLOW_STATE_UI_ENABLED` 단일 상수로 rollback한다. OFF이면 store를 만들지 않고 새 control·집계·filter를 표시하지 않으며 기존 compact queue를 유지한다.

## API·저장·privacy 경계

검토 상태 endpoint, OpenAPI schema, SQLite, JSON sidecar, `localStorage`, `sessionStorage`, cookie, 분석 snapshot 및 dependency 변경은 없다. 추가된 고정 JS asset route는 기존 정적 frontend 파일 제공이며 상태 API가 아니다.

상태 map은 분석 결과 및 projection을 인자로 받거나 수정하지 않는다. 제목, 요약, 원문 로그, account, IP, hostname, 경로, timestamp, risk, role, priority, checklist, event, note, fingerprint를 저장하지 않는다. DOM에 새 generation/ref/state data attribute를 추가하지 않는다. 기존 hash detail route는 같은 opaque `case_ref`만 사용한다. checklist는 원래처럼 사용자의 명시 버튼에서만 POST한다.

## Contract·검증

- 새 JS store는 `tests/fixtures/investigation_review_state_v1_contract.json`이 고정한 4개 상태, 전이, reset, revision, 128개 상한, 고정 오류 category 및 5-field allowlist를 합성 vector 테스트로 확인한다. fixture는 production 경로에서 읽히지 않는다.
- `tests/test_review_state_ui_36_14d.py`는 asset/rollback/closed UI 구조를 고정한다. `tests/ui_review_state_36_14d.mjs`는 합성 sample API를 거쳐 목록·상세·뒤로·filter·reset·새 generation·rollback OFF, API/checklist 요청 계수, storage/URL 누출, viewport overflow, target 높이, axe, console/page error, secure random 불능 시 분석 유지 동작을 확인한다.
- 기존 `tests/ui_review_queue_36_13a.mjs`의 keyboard tab order에 상태 filter를 반영했다. **통제된 synthetic Chromium**에서 1440/1024/768/390/320px 및 320px 200% equivalent reflow를 측정하고 task 임시 디렉터리에 `queue-1440.png`, `queue-390.png`, `queue-320.png`를 생성한다. 캡처는 실제 자료가 아닌 sample 결과다.
- 개발용 store benchmark는 합성 100 refs, warm-up 5회, 측정 25회/operation이다. 초기화·전이·상태 filter·복합+상태 filter·목록-상세-목록·generation 교체의 median/p95/max는 모두 대략 `0.0/0.1/0.1 ms`였다. 테스트 브라우저 `performance.now()`의 해상도로 0.1ms 구간에 모인 값이며 운영 SLA가 아니다.
- workflow summary/control의 관측치는 6 DOM nodes, serialized HTML 2,045 bytes다. 고정 asset 크기는 상태 module 12,459 bytes, 변경된 queue helper 12,888 bytes, `app.js` 160,096 bytes, CSS 76,439 bytes였다. 각 파일이 160 KiB fixed-asset 상한 이내이며 상한을 늘리지 않았다.
- TDD 기록: 구현 전 새 static/UI 계약 테스트는 모듈 및 rollback UI 부재로 `2 failed`를 확인했다. 통합 후 Phase 36.14A-D/36.13A focused 계약은 `46 passed`. 첫 200% 글자 reflow 검사는 상태 control의 최소 열 너비로 overflow를 재현해 실패했고, 768px 이하 한 열 배치 후 통과했다. 상태 변경 뒤 목록 재렌더로 keyboard focus가 사라지는 E2E도 처음 실패했으며, 보이는 카드에 focus를 복원하고 filtered-out 카드일 때 상태 filter로 옮기도록 개선했다. 또한 기존 axe runner가 새 same-origin 고정 asset을 미허용 요청으로 차단해 allowlist에 해당 asset을 추가한 뒤 전체 25개 UI 상태가 통과했다.
- 새 상태 UI E2E: transition vector 16쌍, API 요청은 synthetic sample 경로 3회(POST 2회), checklist POST 0, 상태 API 요청 0, 외부 요청 0, page/console error 0, axe 위반 0, rollback OFF 통과. queue E2E: checklist POST 0, 외부 요청 0, axe 위반 0.
- 전체 `uv run pytest -q`: `3634 passed, 2 warnings`. Parser/API/privacy/checklist/report/queue와 Phase 36.14A-D focused set은 별도로 `503 passed, 2 warnings`; 최신 문서/API-schema focused set은 `46 passed`다.
- 합성 evaluator `79/79`, Linux process 분류 evaluator `21/21`(macOS에서 합성 평가), Risk `70/70`, Case `70/70`, Phase 36.1 `44/44`, Phase 36.2 `24/24`. TCP Syslog 기본·관리 smoke 및 JSONL runtime smoke 통과.
- Chromium/axe 기존 회귀는 `25 states`, `external_requests=0`; UI navigation, queue, input-quality 36.12B, 36.12C 합성 mixed scenario 통과. 36.12C 실행 중 checklist explicit POST 1, 목록/상세 이동에서 자동 checklist POST 0. restricted-report Linux smoke는 macOS platform guard 결과 `stage=linux_platform category=platform`으로 `NOT_TESTED`.
- `uv sync --locked --dev`, `uv lock --check`, Python compile, Node syntax, `git diff --check` 통과. README는 `16,781 bytes / 120 lines`; dependency/lockfile은 변경하지 않았다.

## 검증 경계 및 다음 단계

Phase 36.14E에서 보안·접근성·reflow E2E를 독립적으로 보강하고, Phase 36.14F에서 사용자 이해도와 실제 workflow 적합성을 검수한다. 이번 단계에서는 Safari와 실제 모바일 기기를 검증하지 않았다. macOS에서 Linux process 분류 평가는 합성 실행으로 `21/21`이었지만 Linux host acceptance, TCP reliability 및 Restricted Report Linux smoke는 `NOT_TESTED`다. 새 변경 SHA의 Ubuntu CI는 push 전까지 미검증이다.

실제 사용자 자료·조직 운영·자동 대응은 계속 `NO_GO`다. 모델 기반 AI는 사용하지 않는다. 검토 상태는 보안 판정이 아니다.
