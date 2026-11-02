# Phase 36.14E — 검토 진행 상태 보안·접근성·수명 E2E

## 판정 범위

결과는 `PHASE_36_14E_REVIEW_WORKFLOW_STATE_SECURITY_ACCESSIBILITY_LOCAL_CONDITIONAL_GO`다. 검증 대상 시작 SHA는 `63a26cf4fdc6b85c396a61be1c93fd1effb320bb`, exact push run은 [41435552667](https://github.com/misosos/ai-security-log-analyzer/actions/runs/41435552667)이었다. 시작 Gate에서 `main`, clean tree, origin 일치, `push / completed / success`, 전체 회귀, Linux TCP/JSONL/Restricted Report, Chromium/axe, tracked-file 검사와 artifact 0개를 확인했다. `v0.4.0` tag와 Release target은 `eecd6ee1cda0545e34b01c42e1a2163a899bcc27`이었다.

이 Phase는 합성 자동 검증이다. document memory 기반 UI의 사용자 수용, Ubuntu 새 SHA 검증, Safari, 실제 모바일 기기 또는 운영 적합성을 뜻하지 않는다.

## TDD와 최소 수정

새 E2E assertion으로 수정 전 다음 실패를 확인했다.

- 129개 사례 등록 거부가 기존 활성 generation을 제거함: `E_CAPACITY_REJECTION_MUST_PRESERVE_ACTIVE_GENERATION`.
- JS가 알 수 없는 schema와 중복 case ref를 Python reference와 다른 오류 범주로 반환함: `E_UNKNOWN_SCHEMA_CATEGORY_MUST_MATCH_PYTHON_CORE`, `E_DUPLICATE_CASE_CATEGORY_MUST_MATCH_PYTHON_CORE`.
- rollback 상수가 꺼져도 HTML의 정적 script tag가 상태 asset을 로드·실행함: `E_ROLLBACK_OFF_MUST_NOT_LOAD_OR_EXECUTE_STATE_ASSET`.
- 검토 상태 select의 여러 카드 accessible name이 동일했음: `E_CARD_STATE_CONTROL_NAMES_MUST_BE_DISTINGUISHABLE`.

수정은 위 계약에 한정했다. generation은 case 수·식별자·중복을 검증한 뒤 기존 map을 교체한다. JS 오류 category를 36.14B Python core와 맞췄고, 각 select에 카드 순번을 포함한 accessible name을 부여했다. rollback switch를 app module 시작부로 올리고 상태 asset을 조건부 same-origin `import()`로 로드해 OFF일 때 요청하지 않도록 했다. `index.html`은 app을 module script로 시작한다. Parser, detector, relation, risk, case, checklist 의미, API schema, dependency와 lockfile은 바꾸지 않았다.

## 격리 환경 및 하네스

`tests/ui_review_workflow_state_security_36_14e.mjs`는 production FastAPI와 Production UI를 loopback `127.0.0.1`에서 실행하고 합성 sample API만 사용한다. Chromium은 task 임시 HOME/XDG config와 전용 임시 user-data profile을 사용한다. 브라우저 외부 요청은 차단하며 method/path/count만 계수하고 body·원문은 출력하지 않는다. 임시 서버 process group, profile, report 파일, screenshots는 종료 시 제거한다.

고정 JS contract vector는 기존 `tests/fixtures/investigation_review_state_v1_contract.json`을 읽어 네 상태, 전이 행렬, reset, revision, stale CAS, unknown analysis/case, schema, 128/129 상한과 오류 범주를 검사한다. fixture와 Python core를 frontend production 코드에서 가져오지 않는다. 동일 revision 경쟁은 한 변경만 성공하고 다른 변경은 `STALE_REVISION`이며 최종 revision은 1이었다. 오류 projection에는 합성 canary를 넣어 고정 category 외 문자열이 나오지 않는지 검사했다.

## 수명·격리·저장 경계

검토 상태는 document memory에만 존재한다.

- 같은 document에서 목록→상세→뒤로/앞으로는 같은 상태를 보존한다. checklist를 명시적으로 요청해도 상태는 바뀌지 않는다.
- 다중 탭에서 동일한 sample 분석을 열어도 한 탭의 변경은 다른 탭에 반영되지 않았다. `storage` listener, BroadcastChannel, Worker/SharedWorker 사용은 관찰되지 않았다.
- 새 분석은 같은 사례 수와 같은 합성 입력이어도 모든 상태를 `unreviewed`, revision 0으로 시작한다. 이전 상태를 재사용하지 않는다.
- 직접 hash 진입과 reload는 만료 화면을 유지하고 분석이나 checklist를 자동 재실행하지 않는다.
- `localStorage`, `sessionStorage`, cookie, IndexedDB, Cache Storage 및 Service Worker 등록은 변경되지 않았다. URL, hash, `history.state`, DOM data attribute에 generation/ref/state map을 추가하지 않았다.
- Web Storage를 비롯한 브라우저 persistent storage에는 검토 상태를 기록하지 않았다.
- 상태 API 요청 0건. 상태 변경·필터 조작으로 인한 API 요청 0건. 사용자의 checklist 버튼 클릭 전 자동 checklist POST 0건, 명시 클릭 후 1건이며 기존 body key만 확인했다. 외부 요청 0건.
- report 다운로드 HTML은 상태 변경 전후 같은 합성 report projection과 byte-identical이고, workflow state 및 generation 표식이 포함되지 않았다. clipboard 쓰기 0, page error 0, console error 0.

문서 상태 map은 저장소·분석 결과와 분리된다. 검토 상태는 `reviewed`여도 안전·해결·오탐·종결이 아니며 `deferred`는 낮은 위험이나 검토 불필요가 아니다. 확인 안내 문구는 한 번만 표시된다. 상태 집계와 분석 건수는 별도 이름으로 표시되고 상태 filter는 목록 subset만 바꾼다.

## 분석 불변성과 실패 격리

상태 변경·reset·filter·목록/상세 왕복 전후에 검토 상태 control을 제외한 요약, 사례 카드, independent observation 및 input quality DOM projection을 비교했다. 최초 분석 response의 analysis summary, case summary, cases, independent observations 및 report export digest도 확인했다. 상태 조작은 risk badge, 우선순위, 역할, 사례 수와 report를 변경하지 않았다. stale revision, unknown case와 invalid enum은 상태를 성공으로 표시하지 않는다.

secure random API 사용 불가를 합성해도 검증된 분석 사례 2건은 표시되고 workflow 영역만 고정 unavailable 안내로 전환됐다. 임시 경로, stack, opaque ref, 사용자 입력 또는 canary는 오류·화면에 표시되지 않았다. rollback OFF에서는 compact queue가 유지되고 workflow control/집계/filter가 없으며 상태 asset의 resource entry도 0이었다.

## 키보드·viewport·axe

Chromium keyboard E2E 검색에서 filter opener까지 focus-visible, Enter로 panel 열기, panel 내 순서, Escape 닫기 및 opener로 focus 복귀를 확인했다. 각 상태 select의 accessible name은 카드 순번과 `검토 상태`를 포함하고 서로 달랐다. native select의 OS popup 항목 선택은 Playwright macOS automation에서 신뢰성 있게 키 입력으로 구동할 수 없어 `NOT_TESTED`다. select focus/tab order와 native change/value 계약은 자동 검증했다. 실제 OS 키보드와 보조기술 조합은 별도 검수가 필요하다.

1440, 1024, 768, 390, 320 CSS px 및 640 CSS px에서 글자 200% 설정으로 가로 overflow 0, 사례 카드 텍스트 overflow 0, 보이는 workflow select 높이 44px 이상을 확인했다. filter panel 닫힘/열림, 빈 filter 결과, 세 상태, 상세, unavailable, 좁은 화면과 reflow 상태에 axe를 실행했다. 위반 0. 전체 E2E 표식은 `REVIEW_WORKFLOW_STATE_SECURITY_36_14E_SMOKE_PASS`; 브라우저 API 요청은 12건(명시 checklist POST 1건 포함), 외부 0, page/console error 0이었다.

실제 상태별 클릭 target의 포인터 사용성, screen reader 실제 발화, Safari와 실제 모바일 기기는 자동 DOM/axe 검사로 대신하지 않았으며 `NOT_TESTED`로 남긴다. native popup 키 선택도 위와 같이 `NOT_TESTED`다.

## Evidence screenshots

하네스는 격리된 Chromium에서 다음 합성 캡처를 임시 `evidence` directory에 만들고 종료 시 지운다. binary는 repository에 보관하지 않는다.

- `01-queue-1440.png`: 1440px 초기 큐
- `02-filter-open-1440.png`: 1440px filter panel
- `03-filter-empty-1440.png`: 상태 filter 0건
- `04-state-in-review-1440.png`, `05-state-reviewed-1440.png`, `06-state-deferred-1440.png`: 카드 상태별 표시
- `07-detail-state-1440.png`: 상세 상태 control
- `08-list-390.png`, `09-list-320.png`, `10-detail-390.png`: 좁은 목록·상세
- `11-reflow-200.png`: 200% equivalent text reflow

캡처에는 DevTools나 개인 경로가 없고 합성 Production sample만 사용한다. 캡처를 사용자 검수 PASS로 해석하지 않는다.

## 검증 및 개발용 자원 관측

신규 Node/Chromium 하네스는 100/128 합성 사례에서 store 등록, 100개 전이, 상태 filter/count, 목록-상세-목록 snapshot 및 generation 교체를 warm-up 5회·operation당 25 sample로 측정한다. 아래는 median/p95/max로 요약한 macOS Chromium `performance.now()` 개발용 합성 관측값이다.

| 사례 수 | 동작 | median / p95 / max (ms) |
| ---: | --- | ---: |
| 100 | store 등록 | 0.0 / 0.1 / 0.1 |
| 100 | 100회 전이 | 0.1 / 0.2 / 0.2 |
| 100 | 상태 filter + count | 0.1 / 0.1 / 0.2 |
| 100 | 목록-상세-목록 snapshot | 0.0 / 0.1 / 0.1 |
| 100 | generation 교체 | 0.1 / 0.1 / 0.2 |
| 128 | store 등록 | 0.0 / 0.1 / 0.2 |
| 128 | 100회 전이 | 0.1 / 0.2 / 0.2 |
| 128 | 상태 filter + count | 0.1 / 0.2 / 0.2 |
| 128 | 목록-상세-목록 snapshot | 0.0 / 0.1 / 0.2 |
| 128 | generation 교체 | 0.1 / 0.2 / 0.2 |

운영 SLA가 아니다. 측정 clock 해상도가 낮아 작은 연산은 0.1ms 단위로 뭉칠 수 있다. 화면 100개 사례 렌더 성능을 측정한 것으로 해석하지 않는다.

초기 2-case 화면은 전체 DOM 761 nodes, workflow 관련 상위 node 6개, 비교한 rollback 화면 622 nodes(순증 139 nodes), workflow 관련 markup 2,113 bytes였다. change listener 계측은 enabled 16 / rollback 9로 관찰되어 차이 7건이며 누적 생성 계수이지 live listener leak 측정은 아니다. rollback 화면의 DOMContentLoaded 관측은 55.6ms 한 번이다. 고정 asset 원본 크기는 상태 JS 12,625 bytes, `app.js` 160,171 bytes, CSS 76,439 bytes로 모두 160 KiB 제한 이내(app.js 여유 3,669 bytes)다. browser transfer-size 계측은 각각 12,925 / 160,471 / 76,739 bytes였다. 수치는 개발용 합성 관측치다.

문서 계약은 `tests/test_review_workflow_state_security_36_14e_documentation.py`가 확인한다. Phase 36.14D state E2E와 Phase 36.13A queue E2E, Phase 36.12B quality UI E2E, UI navigation을 재실행했다. 기존 Node `vm.Script` renderer harness는 ES module의 conditional import를 직접 실행할 수 없으므로, 테스트에서 module loader 한 줄만 제거하고 app 본문을 검증하도록 맞췄다. Production 경로는 격리 Chromium E2E에서 module import와 CSP를 확인한다. 전체 `pytest`, Phase 36.14A-D, parser/API/privacy/checklist/report/queue, evaluation, TCP/JSONL, 기존 Chromium/axe 결과는 완료 보고에 기록한다. `uv sync --locked --dev`, `uv lock --check`, Python/Node syntax, `git diff --check`, dependency/lockfile와 README byte 계약도 확인한다.

현재 macOS 환경에서 새 커밋의 Ubuntu CI 및 Linux-only TCP reliability, JSONL Linux acceptance, Restricted Report Linux smoke는 `NOT_TESTED`다. Playwright macOS Chromium에서 native select popup의 keyboard-only option 선택은 자동화되지 않아 `keyboardSelectedFilter=all`로 남았고, 포커스·Tab 순서·focus-visible과 브라우저 `change` 동작은 검사했다. 이 항목은 OS-native keyboard popup 및 실제 screen reader 검수가 필요하다.

추가로 실행한 Phase 36.12C legacy acceptance harness의 `text-empty` 시나리오는 `QUALITY_STATUS_MISSING`으로 실패했다. harness는 empty(0줄) quality fixture를 주입하면서 실제 non-empty application log line을 제출한다. strict frontend validator가 불일치 projection을 거부하는 것은 계약에 맞으므로 이번 Phase에서 assertion을 완화하거나 production 검증을 우회하지 않았다. 나머지 file-complete/mixed/disclosure 및 text-complete/partial/none/parser-incompatible/legacy 시나리오는 통과했다. 이 추가 harness scenario는 fixture 일치 수정 전까지 `NOT_TESTED`다. 이전 시작 SHA CI 성공은 현재 변경 SHA 검증을 대신하지 않는다.

## 후속 단계와 운영 경계

Phase 36.14F에서 실제 화면을 격리된 합성 자료로 사용자에게 검수받는다. 자동 검증은 사용자 수용 응답을 대체하지 않는다. 새 Ubuntu push CI도 별도 필요하다. 실제 사용자 자료, 조직 운영 및 자동 대응은 계속 `NO_GO`; 모델 기반 AI는 사용하지 않는다.
