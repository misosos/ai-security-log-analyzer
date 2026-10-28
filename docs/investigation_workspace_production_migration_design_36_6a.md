# Phase 36.6A — 조사 작업공간 production 이식 설계

## 목적과 현재 판정

이 문서는 Phase 36.5C/D에서 사용자가 수용한 PatternFly 참고 정적 prototype의 정보 구조와 시각적 위계를 기존 production UI에 단계적으로 이식하기 위한 설계다. 이번 Phase는 문서와 문서 계약 테스트만 변경하며 production 코드, API, schema, 분석 pipeline, dependency와 lockfile은 변경하지 않는다.

- prototype desktop 검수와 모바일 6/6 문항은 사용자 `PASS`; prototype 판정은 `PROTOTYPE_USER_ACCEPTED`
- 이는 production 이식 승인이 아니다. production UI는 아직 기존 화면을 사용한다.
- 200% equivalent 좁은 폭 검사에서 overflow가 관찰됐고, dashboard 텍스트 링크의 target 높이는 19px이었다. 이 두 항목은 해결되지 않았으며 이식 수용의 차단 조건이다.
- 실제 모바일 기기와 Safari 동작은 `NOT_TESTED`; Safari는 기존 `NOT_TESTED / USER_HOME_ISOLATION_BLOCKED` 상태를 유지한다.
- 실제 사용자 자료·조직 운영·자동 대응은 `NO_GO`; 모델 기반 AI는 `NOT_TESTED`다.
- Vector/VM 상태는 변경하지 않는다.

## 조사한 현재 production 구조

현재 production UI는 server-rendered HTML shell, 한 개의 vanilla JavaScript 앱, 로컬 CSS로 구성된다. frontend에 별도 SPA router나 UI framework는 없다.

| 영역 | 현재 구현과 계약 |
| --- | --- |
| 결과 목록 | `frontend/app.js`의 `renderSummary`, `renderCaseOverview`, `renderIndependentObservations`가 공개 analysis response에서 결과 수, 검토 사례 요약, 독립 관찰을 렌더링한다. 카드 요약은 기존 case grouping/risk projection과 보호된 대상 alias를 소비한다. |
| 사례 상세 | `renderCaseDetail`이 목록 클릭에 맞춰 선택 사례의 전체 상세 DOM을 만든다. 현재 상세에는 개요, timeline, 확인된 사실, 추가 확인, 위험 설명, guidance, checklist가 긴 단일 흐름으로 포함된다. |
| Navigation/state | `reviewRouteRef`, `openReviewCase`, `restoreReviewList`와 `popstate` listener가 `#/investigations/{case_ref}`를 다룬다. `caseByRef`와 현재 분석은 memory에만 있고, history state에는 목록 scroll과 허용된 focus element ID만 둔다. direct entry에 그 memory가 없으면 만료 안내를 보인다. |
| Timeline | `renderTimeline`은 projection의 `timeline` 순서를 `<ol>`로 출력하고 관찰·탐지·관계를 텍스트 label과 icon으로 구분한다. 관계 label은 `인과관계 미확정`을 명시한다. 사건·관계 의미와 순서는 projection이 정하며 UI가 재정렬하거나 원인을 추론할 수 없다. |
| Checklist POST | `renderChecklist`는 `확인할 작업 불러오기` click handler 안에서만 `POST /api/v1/investigations/checklist`를 호출한다. 요청은 `{schema_version, case_ref}`이고, loading, available, refused, unavailable, fixed error를 구분한다. 응답은 `investigation-checklist/v2` closed contract다. |
| Guidance/citation | `renderGuidance`는 명시적 도움말 버튼과 허용된 topic을 통해 기존 lexical guidance endpoint를 호출한다. checklist와 guidance는 따로 요청하며 각자 citation 의미를 검증한다. citation은 일반 참고자료이지 사례 직접 증거가 아니다. |
| Responsive CSS | `frontend/style.css`에는 dashboard, 상세, timeline, task, checklist의 현재 스타일과 breakpoint가 있다. prototype 전용 CSS는 `docs/prototypes/investigation-workspace/prototype.css`에 독립돼 있다. 두 스타일은 병합하지 않는다. |
| Chromium·axe | `tests/ui_accessibility_axe_pilot_28_1.mjs`는 API 상태, route, 목록에서 상세 DOM 미생성, checklist opt-in, 개인정보, viewport, axe를 검사한다. prototype의 200% equivalent overflow와 19px target 관측은 production 이식 전 별도 차단 조건으로 승격한다. |
| API·공개 projection | 공개 case projection은 `app/analyzer/incident_case_projection.py`에서 만들어지고 `app/api.py`가 사용한다. checklist adapter는 `app/investigation_checklist_api_36_3.py`, verified role provenance는 `app/investigation_role_snapshot_36_4.py`에 있다. 목록 projection은 source role이나 review priority를 주지 않는다. role/priority는 명시적 checklist 응답에서만 공개된다. |
| HTML report | `app/analyzer/html_report.py`는 독립 report projection에서 standalone HTML을 만든다. 화면 작업공간 redesign은 이 renderer, report projection, report 다운로드 결과를 변경하지 않는다. |

## production/prototype 비교

| 기능 | 현재 production 구현 | 승인 prototype 표현 | 이식 방법 | 재사용 데이터 | 필요한 UI projection | backend/schema 변경 여부 | privacy 위험 | 접근성 위험 | 회귀 테스트 | 구현 Phase |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 대시보드·검토 건 목록 | 요약 카드와 사례 목록을 기존 result view 안에 출력 | 결과 요약과 넓은 축약 검토 행을 분리 | 기존 result response를 유지하고 card hierarchy와 요약만 재배치; 전체 상세 subtree는 목록에서 만들지 않음 | `analysis_summary`, `case_summary`, case row의 현재 안전 표시값 | closed row projection; 고정 제목/요약 mapping, risk, time, counts, alias | 없음 | 원래 subject나 grouping의 자유 문자열을 그대로 노출할 위험 | 축약 목록 DOM, canary, stable case ordering, 320/200% | 36.6B/C |
| 독립 상세·route | hash route로 현재 memory case 선택, history scroll/focus 반환, 만료 안내 | 개요·활동 흐름·확인 작업·근거를 tab으로 나눈 독립 상세 | 기존 hash route 유지, view shell만 정돈; hash에는 opaque `case_ref`만 허용 | 현재 탭의 validated analysis response와 `caseByRef` | route token과 transient selected case view model | 없음 | URL·history에 원식별자 또는 분석 payload를 넣을 위험 | back, direct entry, expiry, focus, URL/history privacy | 36.6B/C |
| 위험도·확인 순서·로그 역할 | risk는 분석 projection, 역할과 priority는 checklist response 전까지 미요청 상태 | 세 값을 별도 label로 표시 | 원값만 표현; 미요청 상태는 미요청으로 표시하고 role/priority를 추정하지 않음 | 기존 risk; 명시적 POST 후 checklist v2의 closed enum | `risk_band`, `checklist_status`, 응답 후 `source_role`, `review_priority` | 없음 | category/risk/alias로 source role이나 priority를 유도할 위험 | 상태 분리, role fallback, risk 불변, text label | 36.6C/E |
| 활동 timeline | projection 순서의 `<ol>`, 각 항목 안에 시간·kind·사실 문구 | 사건 순서와 점선 비확정 관계를 별도 시각 계층으로 표시 | observation만 ordered item으로 두고 relation은 사건 카드로 복제하지 않는 별도 inline relation 표현 | `timeline` approved entry, existing timestamps and relation summaries | timestamp, closed observation kind, fixed display title, relation label | 없음 | raw evidence나 내부 rationale를 그대로 출력할 위험 | stable sort, no duplicated relation event, non-causation, screen-reader order | 36.6D |
| 확인할 작업 | checklist response를 번호 목록 및 disclosure로 출력 | compact 작업 선택 목록과 한 번에 하나의 선택 설명 | 기존 v2 `steps`, purpose mapping, citations를 재배치; 저장 checkbox나 완료 state 없음 | explicit POST의 validated v2 response | `not_requested/loading/error/refused/available`, selected step, safe citations | 없음 | 응답 자유 텍스트를 HTML로 처리하거나 자동 대응처럼 보일 위험 | explicit POST 0/1, response validation, no `innerHTML`, keyboard state | 36.6E |
| Guidance·근거·한계 | 별도 명시적 guidance 요청, citation/limitation disclosure | 접힌 근거 tab, 일반 참고와 직접 사례 증거 분리 | 기존 guidance/checklist citation과 fixed limitation mapping을 재사용; 내부 code는 기술 disclosure만 | validated guidance response, checklist citation subset, public limitation code | 고정 한국어 label과 safe text node | 없음 | URL, 원문, unapproved metadata와 내부 code의 기본 노출 | corpus digest/citation regressions, disclosure, canary, no auto request | 36.6E |
| 오류·만료·미지원 | 고정 API error와 expired-route view | state-specific empty/error guidance | 기존 error categories를 탭/panel에 통합하되 사용자 메시지를 고정 mapping으로 유지 | existing API states and expiry | closed state enum + fixed copy | 없음 | exception text를 user-facing message로 노출할 위험 | stale/not-found, timeout, rate/busy, recovery, no other-case fallback | 36.6B/E |
| 외부 report·SSE·기타 화면 | 독립 report download, SSE/live views and other workspace screens | 해당 없음 | 이식 대상에서 제외하고 기존 renderer/projection/runtime 경계를 그대로 소비 | 기존 outputs | 없음; redesign state를 다른 기능으로 전달하지 않음 | 없음 | UI view state가 public API, SSE, report로 새어나갈 위험 | API/SSE/report/guidance invariance | 각 단계 |

## Routing 후보와 결정

| 후보 | 서버 route 변경 | 뒤로 가기 | 직접 진입·새로고침 | 만료 처리 | URL privacy | 자동 checklist 방지 | 테스트 가능성 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Hash routing | 불필요; 현재 정적 shell에서 사용 중 | `pushState`/`popstate`로 목록 복귀와 focus 복원 가능 | shell은 열리지만 in-memory case가 없으므로 고정 만료 안내 | 기존 expired route 규칙을 사용, 다른 case fallback 금지 | opaque `case_ref`만 hash에 허용 | detail render와 POST handler 분리 | 현재 Playwright 계약을 확장 가능 |
| History API pathname | static host fallback/server route 설정 필요 가능 | 자연스러운 path history | 새로고침에 서버 fallback 필요, 현재 transient state와 맞지 않음 | server와 client 두 경계에서 처리해야 함 | opaque ref만 두면 가능하나 경로/server log 범위가 증가 | 별도 구현에서 보장 가능 | 현 shell과 배포 설정까지 검증 필요 |
| 동일 document view-state만 전환 | 없음 | 수동 state/history 연동이 추가로 필요 | URL deep link가 없어 새로고침과 직접 접근 의미가 약함 | 메모리 만료 시만 처리 | URL에 ref를 넣지 않을 수 있음 | 상태 전환과 요청 분리가 가능 | 브라우저 back 계약을 별도 구현해야 함 |

**결정: 현재 hash routing을 유지한다.** 이미 있는 `#/investigations/{opaque_case_ref}`와 history state scroll/focus 반환을 재사용하며 서버 route 변경을 피한다. history state에는 scroll/focus용 고정값 외에 분석자료·alias·role·citation을 저장하지 않는다. route에는 case_ref 외 어떤 category, role, alias, account, IP, hostname, path, raw text도 허용하지 않는다.

직접 진입 또는 새로고침에서 해당 탭의 검증된 in-memory case projection이 없거나 만료됐다면 고정 만료 view만 보여준다. 최신 결과를 새로 분석하지 않고, 다른 case로 fallback하지 않으며, checklist POST를 자동 요청하지 않는다.

## Closed UI projection과 privacy 경계

Production adapter는 기존 validated API response에서 화면 전용 closed object를 만든다. prototype의 정적 mock data와 HTML/CSS/JS는 import하거나 production payload로 복사하지 않는다. 모든 key와 enum은 allowlist며 unknown field/value는 거부한다.

허용할 최소 projection 후보:

- `case_ref`: 기존 형식 `c_` + 소문자 24자리 hex, request-scoped opaque ref
- 정수 display order는 현재 case ordering에서 가져오며 case identity가 아님
- 고정 mapping의 display title과 `authentication`, `web_request`, `relation`, `unknown` 등 현재 지원 category
- 기존 `HIGH/MEDIUM/LOW` risk band; 화면은 이를 재계산하지 않음
- checklist가 아직 호출되지 않았을 때 `not_requested`; 응답 성공 뒤에만 verified `source_role` 및 `review_priority`
- 허용된 KST display time과 기존 `<time datetime>`용 UTC 값, observation/relation/task/limitation counts
- 보호된 response-scoped subject alias (현재 계약이 제공하는 경우)
- closed timeline observation items와 별도 non-causal relation summary
- checklist의 closed status, `steps`, citation subset, limitation/uncertainty code의 fixed display mapping
- 고정 설명과 고정 refusal/expiry 안내

금지: raw log/parser source text, 실제 account/IP/hostname, filename/path, checkpoint, credential, 내부 exception, 원래 source identity, unrestricted metadata, analysis rationale 전문. public API가 제거한 값을 UI가 URL·DOM·ARIA name·history state·localStorage·sessionStorage·IndexedDB로 복구하거나 재저장하지 않는다. alias는 응답 간 case key나 correlation key로 사용하지 않는다.

UI projection은 backend/API schema를 새로 만들지 않는 frontend 내부 변환 계약이다. 현재 목록 응답은 source role과 review priority를 포함하지 않으므로 목록에서 실제 역할·우선순위를 꾸며내지 않는다. 역할과 priority는 checklist v2의 명시적 사용자 요청 이후에만 나타난다. Checklist 결과를 guidance 입력으로 넘기거나 analysis DTO, checkpoint, publication, SSE, report에 저장하지 않는다.

## Timeline 의미

- `<ol>`은 관찰된 activity만 결정된 projection sequence대로 표시한다. 동일 timestamp의 tie-break도 backend projection이 정한 순서를 따른다.
- 관계는 두 번째 event card가 아니라 해당 관찰들을 가리키는 별도 inline relation row로 표현한다.
- `분석상 연결 · 인과관계 미확정` 문구와 점선 등 비색상 표현을 함께 쓴다. 관계의 방향은 시간/규칙 연결이지 원인 주장이 아니다.
- 색상만으로 detection, observed fact, relation을 구분하지 않는다. visible label과 screen-reader order를 제공한다.
- 시간이 없는 사건은 정렬 의미를 새로 만들지 않고 별도 `시간 정보 없음` 항목으로 안전하게 나타낸다.
- Timeline은 HTML/CSS로만 구현한다. 외부 chart dependency, canvas-only chart 또는 workflow-progress stepper를 추가하지 않는다.

## Checklist presentation과 request 경계

상세 진입만으로는 checklist 결과를 만들거나 요청하지 않는다. `확인할 작업 불러오기` 명시적 버튼을 사용자가 직접 누른 순간에 기존 endpoint로 요청 하나를 보낸다. 클릭 외 hover, focus, route entry, tab selection, retry timer, prefetch는 요청을 보내지 않는다.

- 초기: 고정 안내와 명시 버튼, skeleton이나 예상 checklist 없음
- loading: 기존 버튼 disabled 및 polite status; focus를 강제 이동하지 않음
- available: numbered task chooser와 현재 선택 하나의 상세; 완료 checkbox/status 저장 없음
- refused: 승인 근거 부족이지 안전 판정이 아니라는 고정 설명과 기존 분석/승인 내부 경로 확인 안내
- unavailable/error/stale: fixed category/message, 재시도는 사용자 명시 동작만
- citation: 작업별 접힌 영역에서 일반 조사 참고자료이며 사례 직접 증거가 아닙니다. 사례 직접 증거와 구분함을 반복 없이 설명
- 자동 조치 버튼·shell/tool 명령·ticket/case mutation control 없음

기존 API request `{schema_version, case_ref}`, `investigation-checklist/v2`, error categories, lexical corpus digest/verifier, citation IDs를 변경하지 않는다. Review priority는 analysis risk와 시각적으로 별도 표시하며, checklist 요청을 위해 분석을 재실행하지 않는다.

## 200% reflow·target-size 차단 조건

Prototype 검수에서 발견된 두 문제는 구현 설계의 선행 차단 조건이다.

1. 실제 200% browser text zoom 또는 이에 상응하는 검증 가능한 reflow 조건에서 수평 overflow, clipping, overlap이 0이어야 한다. `overflow-x: hidden`으로 오류를 감추거나 좌우 콘텐츠를 자르지 않는다. 320 CSS px 기본 폭도 document와 주요 panel의 `scrollWidth <= clientWidth`로 확인한다.
2. Dashboard의 기존/예상 text link 19px target을 다시 측정한다. 클릭 영역은 글자 줄보다 커야 하며, focus outline을 포함한 실제 hit region과 인접 target 사이의 간격/오작동 여부를 browser bounding box 및 keyboard test로 확인한다. 최종 최소 크기는 구현 PR에서 공통 token과 WCAG/프로젝트 접근성 기준을 근거로 정하고 결과를 기록한다. prototype 값을 그대로 production 요구로 간주하지 않는다.
3. `overflow-x: hidden` 규칙 추가는 허용하지 않는다. layout은 wrap, grid collapse, min-width correction, content reflow로 해결한다.
4. Keyboard-only, focus visible, roving tab/tabpanel ARIA 연결, heading hierarchy, timeline reading order, labels beyond color, reduced-motion을 검증한다.
5. 각 상태의 axe violations는 0이어야 한다. axe 결과만으로 WCAG 2.2 AA 전체 적합성을 주장하지 않는다.

## 구현 phase와 rollback

각 단계는 별도 일반 커밋과 독립 테스트 결과를 남기고, 그 단계만 revert 가능한 작은 단위로 구현한다. 각 단계의 API, schema, analysis semantics, public projection, report, guidance corpus, dependencies, lockfiles는 그대로 둔다.

| Phase | 범위 | 완료 gate와 rollback 기준 |
| --- | --- | --- |
| 36.6B | closed UI projection validator와 hash navigation shell | allowed keys/enum, opaque URL, direct-entry expiry, back/focus, canary 통과. 개인정보, 다른 case 혼입, 자동 POST 발생 시 이 단계 revert. |
| 36.6C | 축약 dashboard와 독립 상세 개요 | 목록은 전체 detail DOM을 만들지 않고 case order/risk/alias/time/count를 보존. API output 및 목록 ordering 변화면 revert. |
| 36.6D | observation timeline과 relation 표현 | ordering 동일, relation 비인과적·중복 event 없음, SR order 유지. 순서·security meaning 변화면 revert. |
| 36.6E | 작업 선택/detail 및 progressive evidence + explicit checklist 연결 | 기존 POST 0 before click/1 per click, available/refused/error 분리, citation subset 검증 유지. auto-fetch, invalid citation, analysis mutation이면 revert. |
| 36.6F | 320px·200% reflow와 접근성 수용 | overflow/clipping/overlap 0, 19px link target 검증 완료, keyboard/ARIA/reduced-motion/axe gate 통과. 어느 blocker든 남으면 다음 단계로 진행하지 않음. |
| 36.6G | 새 화면 사용자 최종 수용 및 기존 화면 제거 결정 | 실제 새 production 화면의 새 SHA CI와 사용자 수용 후 별도 결정. 승인 전 구형 화면 제거 금지; 사용자 FAIL이면 이전 경로를 복구할 수 있도록 신규 view만 되돌림. |

Rollback trigger는 privacy canary leak, unsupported field 수용, URL/history persistence, automatic checklist/guidance request, analysis/case/risk mutation, API/SSE/report behavior change, relation causation claim, overflow/clipping, focus trap, keyboard-inaccessible state, axe violation, 외부 request/dependency 발생 중 하나다. 실패를 CSS clipping, assertion weakening, skip/xfail 또는 API/schema 확장으로 해결하지 않는다.

## 테스트 계획

- Closed UI projection: exact keys, missing/unknown keys, enum, byte/list cap, timestamp/case_ref validation
- Privacy canary: account, IPv4/IPv6, hostname, file/path, raw log, credential, exception이 route/DOM/ARIA/history/log/API/SSE/report/guidance에 없는지
- Case isolation: 두 case의 projection, role, checklist state가 섞이지 않음
- Routing: opaque hash only, back/focus/scroll, direct entry, stale/expired, 다른 case fallback 0, analysis rerun 0
- Request inventory: dashboard/detail/tab render 전 checklist/guidance POST 0; 버튼 한 번에 checklist POST 1; 자동 retry/prefetch 0; 외부 request 0
- Timeline: source ordering과 tie-break 보존, relation card duplication 0, causal wording 0, untimed entry safe, screen-reader order
- Checklist: explicit POST, loading/available/refused/unavailable/error/stale, v2 closed response, citation subset and refusal meaning
- Responsive: 1440/1024/768/390/320 CSS px, 200% reflow, no clipping, actual target hit area and spacing
- Accessibility: keyboard-only, visible focus, tab/panel ARIA, headings, reduced motion, non-color labels, axe 0
- Invariants: deterministic analysis/cases/risk/source role/review priority, checkpoint/publication, SSE replay, HTML report, guidance digest unchanged
- Regression: existing API/OpenAPI, schema 2/3, privacy/public alias, guidance/restricted report, full pytest, Chromium·axe, Node/Python syntax, `git diff --check`
- Dependency gate: `npm ci --ignore-scripts`, `uv sync --locked --dev`, `uv lock --check`; production package/lockfiles unchanged

Browser 자동 검사는 UI 상태의 계약 확인이며 사용자 수용·Safari·실기기 검수를 대체하지 않는다. 새 CI run은 구현 커밋 SHA에서 Linux full suite, TCP/JSONL/restricted report, Chromium·axe와 tracked-file invariant를 확인해야 한다.

## 이번 설계 완료 조건

문서와 문서 계약 테스트 통과 판정은 `PHASE_36_6_PRODUCTION_MIGRATION_DESIGN_CONDITIONAL_GO`다. 이는 설계 진입 가능성만 뜻하며 production 구현 승인이나 사용자 자료 승인이 아니다. 200% equivalent overflow 및 19px target 이슈는 36.6F에서 검증 전까지 차단 상태다.

- production 이식 미구현: `NOT_IMPLEMENTED`
- 실제 사용자 자료·조직 운영·자동 대응: `NO_GO`
- 모델 기반 AI: `NOT_TESTED`
- 실제 모바일 기기·Safari: `NOT_TESTED`
- Vector/VM 상태: 변경 없음
