# ER-2B — Evidence Review UI Integration Design & Security Gate

## 1. Executive Summary

ER-2A의 검증된 합성 Counterfactual 결과를 기존 사건 조사 화면과 섞지 않고 읽기 위한 UI 통합 계약을 설계했다. 최종 권고는 **Option B — 별도 Evaluation Workspace**다. 동일한 loopback 애플리케이션의 보안 헤더와 고정 자산 제공 방식을 재사용하되, 조사 데이터·라우트·상태·집계·API와 분리된 evaluation 전용 route, projection, DOM root, navigation entry와 rollback switch를 둔다.

화면의 질문은 “현재 고정 합성 Corpus에서 어떤 비교 상태가 관측됐고 어떤 항목은 비교할 수 없는가?”이다. 첫 화면은 합성 범위와 검증 상태를 먼저 보여주고, 30건의 상태 분포와 시나리오 목록으로 이어진다. 실제 사건, risk, 공격 성공 또는 운영 정확도를 표현하지 않는다. 이번 단계는 문서 및 계약 테스트뿐이며 UI/API/Production 코드는 변경하지 않는다.

## 2. Start SHA / CI

- 시작 SHA, local `main`, `origin/main`, GitHub `main`: `90804aa0f9998b1d85b40e40e52e98eb1d391236`
- Exact push CI Run `41863755252`: `push / completed / success`, head SHA 일치
- CI에서 complete regression, Linux checkpoint/process, TCP Syslog 기본·reliability·management, JSONL runtime, Restricted Report, Chromium/axe, tracked-file 검사가 실제 실행되어 성공
- GitHub Actions artifact: 0개
- 시작 working tree clean, ahead/behind `0/0`
- `v0.4.0` tag와 Release target: `eecd6ee1cda0545e34b01c42e1a2163a899bcc27`
- 변경 전 `uv run pytest -q`: `3768 passed, 2 warnings`; 기존 Starlette/httpx 및 AnyIO deprecation warning

## 3. Existing UI Architecture

### 3.1 FastAPI와 고정 자산

`app/api.py::create_app()`는 기본 local app에서 `/`, `/assets/style.css`, `/assets/app.js` 및 기능별 JavaScript를 literal route로 등록한다. `app/web_ui.py::_fixed_asset()`는 `frontend/` 아래 module-owned filename만 받고, `lstat`, symlink 거부, `O_NOFOLLOW`, inode 재검증, 파일별 160 KiB 상한을 적용한다. 응답은 `default-src 'none'`, same-origin script/style/connect, inline script/style 금지, frame 금지, `nosniff`, `no-referrer`, `no-store`를 사용한다. 임의 경로를 받는 static directory mount는 없다.

`app/local_web.py`는 Uvicorn을 `127.0.0.1`, single worker, proxy headers off, reload off로 실행한다. 이 loopback 수명 모델을 향후 Evaluation Viewer도 유지해야 한다.

### 3.2 조사 workspace와 route

`frontend/index.html`에는 sidebar 기반 workspace와 start/live/local/audit/results panel이 있다. 분석 성공 전 결과 navigation은 숨겨진다. `frontend/app.js`의 `workspaceNavigation`이 panel 표시, 제목, focus를 관리한다. 사례 상세는 `#/investigations/c_[24 lowercase hex]`만 허용하고 document memory에 현재 projection이 없거나 직접 진입한 경우 만료 화면을 표시한다. 목록·상세·뒤로가기에서 같은 in-memory case registry를 사용하며 URL에 분석 데이터는 넣지 않는다.

현재 investigation workspace projection은 `investigation-workspace-ui/v1` closed adapter를 거쳐 표시된다. 상세 shell은 `USE_WORKSPACE_DETAIL_SHELL_36_6B`가 false이면 기존 renderer로 되돌릴 수 있다. 검토 상태 UI도 `REVIEW_WORKFLOW_STATE_UI_ENABLED` 하나로 store와 asset 실행을 함께 끄며, document memory 밖에 저장하지 않는다.

### 3.3 UI 스타일, 반응형, 검증

현재 화면은 어두운 Cyberpunk 계열이지만 실무 화면으로서 sidebar, compact queue, native controls, 상태 텍스트, flat panels를 사용한다. 향후 Viewer는 기존 palette/type/navigation을 보존하고 색은 데이터 상태를 보조하는 데만 사용한다. KPI 아이콘 타일, rainbow chart, gradient, glow, 독립된 hero는 추가하지 않는다.

기존 브라우저 회귀는 Playwright/Chromium과 axe를 사용한다. 1440/1024/768/390/320px, 320px 또는 root font 200% reflow, keyboard navigation, focus 복귀, horizontal overflow, external request 0, console/page error 0, 명시적 checklist POST 계약 및 rollback OFF를 검사한다. Safari 자동화, 실제 모바일 및 screen reader 수동 검증은 Chromium/axe와 별도 상태로 기록한다.

## 4. ER-2A Report Data Contract

ER-2A producer는 `run_corpus()`와 `run_holdout()` 결과를 `build_report()`로 검증하여 `AnalystReport`를 만든다. `ScenarioProjection`의 UI 후보 필드는 corpus/scenario/detector/mutation, baseline·variant Parser/Detection, Comparison, closed Reason Codes뿐이다. Corpus projection은 각 상태 count, 분모, 비교 제외 수를 갖는다. Expected Label, Label Basis, facts, raw event, IP/account, timestamp, Evidence, owner/context는 projection에 없다.

현재 inventory는 Development 16, Holdout 14, 총 30이다. Comparison 총합은 `PRESERVED 7`, `LOST 10`, `GAINED 5`, `UNCHANGED_ABSENT 2`, `INCOMPARABLE 6`, `UNDETERMINED 0`이다. 이는 현재 snapshot의 회귀 사실이며 화면 상수로 하드코딩하지 않는다. summary는 scenario rows에서 재계산한 값과 producer의 corpus count가 정확히 맞을 때만 표시한다.

ER-2A Markdown은 사람이 읽는 최종 표현이다. 구조화된 신뢰 경계를 되살릴 수 없으므로 UI 입력으로 사용하지 않는다. **Markdown을 직접 파싱하지 않는다.** ER-2C가 별도 frozen 구조화 DTO와 canonical serialization을 정의하고 ER-2D가 그 DTO만 소비한다.

## 5. UI Integration Options

| 기준 | Option A — 조사 화면 추가 탭 | Option B — 별도 Evaluation Workspace | Option C — 별도 Local Report Viewer |
|---|---|---|---|
| 보안 경계 | 사건 projection·navigation과 가까워 혼합 위험 높음 | 같은 loopback shell 안에서 route/state/root를 분리 가능 | 조사 app과 가장 강하게 분리 가능 |
| 구현 복잡도 | 겉보기에는 낮으나 기존 case/detail 상태와 예외가 얽힘 | 중간; 전용 projection과 viewer shell 필요 | 중간~높음; 별도 entrypoint/asset lifecycle 필요 가능 |
| 유지보수 | 기존 workspace 변화마다 영향을 받음 | 공통 자산 보안과 테스트 harness 재사용 가능 | UI·보안 header·실행 안내가 중복될 수 있음 |
| 출처 혼동 | 가장 큼; 실제 case 탭처럼 보임 | route·header·scope banner로 명확히 분리 | 가장 낮음 |
| API 변경 | 기존 조사 API에 연결할 유혹이 큼 | 기존 조사 API 변경 없음; 전용 read-only source는 별도 승인 | 기존 조사 API 없음; snapshot 전달 계약 필요 |
| Privacy | case 상태/집계와 결합될 위험 | allowlist projection만 별도 memory에 설치 | 제한 projection만 제공하면 강함 |
| 접근성 | 기존 tab hierarchy가 복잡해짐 | 독립 h1/list/detail 구조로 단순화 가능 | 독립 구조 가능하지만 별도 shell 검증 필요 |
| Rollback | 기존 screen에서 탭 제거 필요 | 단일 nav/route feature flag로 격리 | viewer 실행 경로 자체를 비활성화 |
| 테스트 | 기존 investigation E2E 전체와 결합 | dedicated E2E + 기존 workspace 무변경 회귀 | 별도 E2E와 배포/실행 회귀 필요 |

Option A는 합성 결과가 사건의 한 분석 탭처럼 보이므로 기각한다. Option C는 장기적으로 강한 분리가 필요할 때 유효하지만 현재 고정 asset/CSP/loopback/browser harness를 중복시킬 가능성이 있다. Option B가 현재 구조에 가장 적합하며, 추후 같은 process에서도 충분한 격리를 증명하지 못하면 Option C로 승격한다.

## 6. Recommended Architecture

권고 구조는 아래와 같다.

```text
fixed synthetic corpora
→ existing ER replay/holdout
→ ER-2C closed SafeEvaluationProjection
→ canonical, bounded snapshot
→ ER-2D isolated UI adapter
→ Counterfactual Evidence Review workspace
```

- 별도 hash namespace 후보: `#/evaluation/counterfactual`; 기존 `#/investigations/...`와 겹치지 않는다.
- 별도 DOM root와 state owner를 사용한다. investigation case registry, review workflow store, risk summary, checklist registry를 참조하지 않는다.
- sidebar entry와 route는 `EVIDENCE_REVIEW_VIEWER_ENABLED` 같은 단일 production constant가 true일 때만 생성한다. OFF이면 asset/module/store/navigation item이 모두 없다.
- 최초 구현은 검증된 고정 synthetic snapshot만 읽는다. 사용자 path, 업로드, query, hash payload, arbitrary corpus root를 받지 않는다.
- 별도 evaluation read-only source가 필요하면 기존 `/api/v1/investigations*` 아래에 두지 않으며, route/schema/CSRF/same-origin/body-free GET 여부는 ER-2C에서 별도 승인한다. 이번 단계는 endpoint를 승인하지 않는다.
- 기존 FastAPI 조사 API, OpenAPI, Production analysis, report, checklist, guidance, SSE, checkpoint/publication은 바꾸지 않는다.

## 7. Information Architecture

화면명은 `Counterfactual Evidence Review`이며 제목 바로 아래에 `합성 평가 전용 · 실제 보안 사건 아님`을 항상 표시한다.

### Evaluation Summary

`Evaluation Scope: SYNTHETIC_ONLY`, Development/Holdout/전체 scenario count, 비교 가능/제외 count, Human Review, Operational Validation을 한 divided summary 영역에 표시한다. 아이콘 KPI 카드나 성공 색을 사용하지 않는다. count는 rows에서 계산하며 producer summary와 불일치하면 전체 화면을 unavailable로 닫는다.

### Comparison Distribution

원본 enum과 한국어를 함께 표시한다: `PRESERVED — 탐지 유지`, `LOST — 탐지 소멸`, `GAINED — 새로 탐지`, `UNCHANGED_ABSENT — 양쪽 미탐지`, `INCOMPARABLE — 비교 불가`, `UNDETERMINED — 판정 불확정`. 색상만으로 구분하지 않고 text, count, denominator를 제공한다. LOST는 회피 성공, GAINED는 실제 공격 발견, UNCHANGED_ABSENT는 안전으로 표현하지 않는다. 단일 색조의 bar/list 또는 semantic table을 사용하고 rainbow chart는 사용하지 않는다.

### Scenario List

허용 필드는 Corpus ID, Scenario ID, Detector ID, Mutation Type, baseline/variant Parser, baseline/variant Detection, Comparison, Reason Codes다. 검색은 bounded exact display strings, 필터는 closed enum, 정렬은 corpus/scenario 또는 closed state order만 사용한다. 필터/정렬 결과 count와 전체 count를 구분하고 원본 DTO나 summary를 변경하지 않는다.

데스크톱은 semantic table을 사용한다. 숫자는 tabular/right aligned, 상태는 원본 enum과 label을 병기한다. 좁은 화면에서는 각 scenario가 두세 줄의 description list row로 바뀌며 모든 허용 필드를 유지한다. 페이지 전체 horizontal scroll은 금지한다.

### Scenario Detail

목록 선택 후 같은 snapshot의 scenario를 보여준다. Baseline, Variant, Comparison, Reason Codes, Parser 한계, 비교 가능 여부, 고정 해석 제한만 표시한다. ER-1D가 아직 생성하지 않은 Feature Delta, Policy Predicate 평가, causal explanation은 빈 자리나 추정 문구로 만들지 않는다. 해당 영역은 “ER-1D 설명 자료 없음”으로 명시한다.

### Limitations

합성 입력 전용, 사람 독립 검토 미완료, 운영 정확도 미승인, 공격·침해 확정 아님, Parser 오류와 미탐지 구분, 자동 대응 없음이 첫 화면과 상세에서 접근 가능해야 한다. 모든 카드에 반복하지 않고 title summary와 detail limitation region에서 제공한다.

## 8. Data Boundary

ER-2C의 권장 closed schema는 report schema version, snapshot identity/digest, source scope, corpus summaries, scenario tuple, review/operational status를 가진다. scenario allowlist는 ER-2A `ScenarioProjection` 필드와 동일하며 자유형 설명을 추가하지 않는다.

계약 요구사항:

- closed key/enum/reason-code set, immutable DTO, duplicate JSON key와 non-finite 거부
- schema version exact match; unknown version은 fail-closed `UNSUPPORTED_REPORT_VERSION`
- 전체 30을 고정 상수로 가정하지 않고 source inventory count, row count, unique ID, corpus subtotal, state distribution의 상호 일치 검증
- snapshot digest/version을 UI state와 결합하고 route transition마다 현재 snapshot인지 확인
- 최대 corpus 2, scenario는 현재 producer 상한 32 이하, UI wire bytes와 field length에 bounded 상한
- row와 summary 불일치, corpus 혼합, duplicate/missing scenario, unknown state/reason은 projection 전체 거부
- UI는 `textContent`, DOM property, fixed option value만 사용하며 `innerHTML`, Markdown renderer, dynamic template HTML을 사용하지 않음
- Raw Log, account/IP/hostname, timestamp, local path, private owner/context, Expected Label, Label Basis, Evidence 객체를 DTO에 만들지 않음
- 오류에는 input, scenario value, path, exception repr을 반사하지 않고 fixed category만 제공

ER-2A Markdown 직접 파싱안은 기각한다. Markdown escaping은 presentation 안전성이지 schema provenance가 아니며 표 구조 변경, label text, 주석을 데이터로 오인할 수 있다. 구조화 DTO는 producer가 검증한 타입·enum·count를 보존하고 UI adapter가 다시 closed validation할 수 있다.

## 9. Synthetic/Production Isolation

- evaluation scenario는 investigation `cases`, dashboard summary, risk, review priority, review workflow count에 합산하지 않는다.
- evaluation route에서는 file/text/sample analysis, checklist, guidance, report download, SSE, live status를 자동 호출하지 않는다.
- Production 사건 상세, timeline, attack chain, report, notification, checkpoint/publication에 counterfactual 결과를 연결하지 않는다.
- evaluation 상태는 실제 운영 alert나 자동 대응 trigger를 만들지 않는다.
- 브라우저 storage, URL query/hash payload, clipboard, HTML report에 snapshot이나 상태를 자동 저장하지 않는다.
- viewer는 read-only다. filter/sort/selection은 document memory의 view state만 변경하고 projection을 수정하지 않는다.
- Human Review는 `INDEPENDENT_HUMAN_REVIEW_PENDING`, 운영은 `NOT_APPROVED`로 표시하며 승인처럼 보이는 green success treatment를 사용하지 않는다.

## 10. Threat Model

| 위험 | 공격 표면 / 실패 방식 | 차단 원칙 | 필수 자동 테스트 | 잔여 위험 |
|---|---|---|---|---|
| HTML/Markdown Injection | ID/reason을 HTML로 해석 | Markdown 입력 금지, textContent, closed chars | 무해한 `<canary>`가 text 또는 거부되고 element 생성 0 | 브라우저/DOM API 오용 가능 |
| DOM XSS | dynamic template/attribute sink | innerHTML 금지, fixed DOM builder, CSP 유지 | script/event attribute 실행 0, CSP 확인 | 향후 새 renderer review 필요 |
| Scenario ID 조작 | route/selector/label에 임의 ID | bounded ASCII ID, lookup map own-key 검사 | control/separator/oversize 거부 | 표시 ID는 여전히 synthetic provenance에 의존 |
| Prototype Pollution | `__proto__` 등 key로 object 변형 | plain closed DTO, Map 또는 own-property, unknown key 거부 | prototype canary 전후 동일 | third-party code 도입 시 재평가 |
| Schema 혼동 | v1 값을 다른 shape로 처리 | exact schema/version, no fallback coercion | unknown/missing/extra version 거부 | migration 시 dual schema 위험 |
| Source/Corpus 혼합 | development/holdout 또는 사건 데이터 합산 | corpus ID allowlist, unique tuple, subtotal reconciliation | cross-corpus duplicate/mismatch 전체 거부 | 잘못 서명된 producer 자체는 별도 문제 |
| Stale Evaluation Data | 이전 성공 화면이 최신처럼 남음 | snapshot identity 결합, 새 load 시작 시 old view stale/unavailable 처리 | A→B 지연 응답에서 A 표시 금지 | 사용자 screenshot의 시점 오해 |
| 비정상 대형 입력 | DOM/메모리 고갈 | producer/wire/field/scenario/DOM node 상한 | 32 허용 경계와 초과 거부, 기존 view 보존 금지 | 브라우저별 자원 차이 |
| 내부 Evidence 누출 | raw facts/context가 projection/DOM에 포함 | whitelist DTO, serialization/DOM canary scan | raw/IP/account/path/owner canary 0 | synthetic ID 자체의 의미 오해 |
| Debug Exception 노출 | stack/path/value가 error UI에 반사 | fixed error category와 사용자 문구 | thrown canary가 DOM/console에 없음 | 개발 도구의 local stack은 별도 |
| Reviewer Blindness 훼손 | Expected Label/Replay result를 blind review와 혼합 | Viewer를 Blind Packet으로 금지, reviewer workflow 링크 금지 | Expected Label/Label Basis field·text 0 | 공개 저장소 때문에 완전 blind 불가 |
| 실제 사건과 합성 데이터 혼동 | 같은 nav/style/count로 사건처럼 인식 | 별도 route/root, persistent synthetic banner, 조사 count 분리 | navigation/ARIA/source label 및 count independence | 사용자의 screenshot crop으로 banner 누락 가능 |

Security canary는 실제 공격 payload나 개인정보처럼 보이지 않는 합성 문자열을 사용한다. 외부 network, LLM, telemetry 요청은 0이어야 한다.

## 11. Accessibility & Responsive Design

- 목표 viewport: 1920, 1440, 1024, 768, 390, 320 CSS px와 320px 200% equivalent reflow.
- page h1은 화면명을, scope notice는 설명을 제공한다. summary와 distribution은 heading hierarchy 아래 semantic regions로 둔다.
- desktop list는 caption과 scope가 있는 semantic table, header scope, row selection의 accessible name을 사용한다. 640px 아래는 동일 정보를 `<dl>` 기반 row로 재배치하고 page horizontal scroll을 만들지 않는다.
- comparison state는 원본 enum, 한국어 label, count를 함께 표시한다. 색상은 보조일 뿐 의미의 유일 수단이 아니다.
- filter label/control 연결, native controls, 44px target, `:focus-visible`, logical tab order를 유지한다. 선택 후 detail h2 또는 row context로 focus를 이동하고 back 시 원래 row로 복귀한다.
- loading/empty/error/stale 갱신은 bounded `aria-live="polite"` region에서 한 번 알린다. 오류 stack이나 ID를 읽지 않는다.
- 200%에서 summary는 list, distribution은 wrapped list, scenario table은 row layout으로 바뀐다. clipping, overlap, text truncation, fixed-height container를 금지한다.
- axe는 initial, empty, populated, filtered-zero, detail, incomparable, execution-failed, stale, schema-error, rollback OFF 및 390/320/200% 상태에서 실행한다. keyboard, screen reader name, target size, reflow는 axe와 별도로 측정한다.
- Chromium 자동화 PASS를 Safari, 실제 모바일, VoiceOver/NVDA PASS로 확장하지 않는다. ER-2E에서 각각 `PASS/FAIL/NOT_TESTED`로 기록한다.

## 12. Failure States

| 상태 | 표시 계약 | 데이터 처리 |
|---|---|---|
| 초기 | scope와 목적, loading 전용 frame | 분석/네트워크 자동 실행 없음 |
| 자료 없음 | “설치된 합성 평가 snapshot 없음” | 0을 검증 성공처럼 표시하지 않음 |
| 검증 성공 | snapshot version과 전체 summary/list 표시 | count 재계산 일치 후 atomic install |
| 입력 무결성 오류 | 고정 `평가 자료 무결성을 확인할 수 없음` | 전체 snapshot 거부, detail 숨김 |
| 잘못된 Schema | 고정 schema error | fallback/coercion 금지 |
| 부분 결과 | 사용 가능한 보고서로 표시하지 않음 | 전체 atomic projection 거부 |
| Comparison 불가 | scenario 상태 `INCOMPARABLE`과 reason 표시 | 실패/미탐지 count로 합치지 않음 |
| 실행 실패 | `EXECUTION_FAILED`, `UNDETERMINED` 등 원래 상태 표시 | NOT_DETECTED로 치환 금지 |
| 미지원 Report Version | update가 필요하다는 고정 문구 | 기존 snapshot을 최신으로 남기지 않음 |
| Stale | stale banner와 controls disabled | old detail/count를 current로 표시 금지 |

새 snapshot 검증은 별도 temporary state에서 끝낸 뒤 한 번에 설치한다. 검증 실패 시 이전 성공 결과는 “last known good”로 계속 보여주지 않고 stale/hidden 처리한다. 사용자가 명시적으로 이전 snapshot을 다시 열 수 있는 기능은 이번 설계에 없다.

## 13. Rollback Strategy

`EVIDENCE_REVIEW_VIEWER_ENABLED` 단일 build-time constant를 권고한다. OFF이면 evaluation module을 import하지 않고 route handler, nav entry, store, DOM root 및 evaluation data fetch가 모두 없어야 한다. 기존 `USE_WORKSPACE_DETAIL_SHELL_36_6B`와 `REVIEW_WORKFLOW_STATE_UI_ENABLED`는 변경하지 않는다.

Rollback OFF 회귀는 기존 root assets, OpenAPI paths, investigation hash route, search/filter/sort, review workflow, checklist explicit POST, guidance, report, live monitoring, input-quality 화면이 기준선과 같음을 확인한다. 합성 evaluation data는 Production storage/checkpoint/publication에 쓰지 않으므로 migration이나 cleanup이 없어야 한다.

Rollback trigger는 source/corpus 혼입, unknown state 수용, stale snapshot 표시, privacy canary, DOM injection, external request, investigation API 호출, 자동 checklist/guidance 요청, keyboard trap, overflow, rollback OFF DOM/API 회귀다. 하나라도 발생하면 viewer flag를 OFF로 하고 ER-2D 변경을 revert한다.

## 14. ER-2C/D/E Roadmap

| Phase | 목표 / 허용 범위 | 시작 Gate | 필수 테스트 | 완료 / Rollback |
|---|---|---|---|---|
| ER-2C | ER replay DTO → frozen SafeEvaluationProjection, canonical bounded serialization; evaluation 모듈·테스트·문서만 | exact main CI, ER-2B 승인, clean 0/0 | closed schema, inventory/count reconciliation, duplicate/non-finite/version/size, canary, deterministic bytes, no API/UI | 안전 projection과 privacy 통과 시 GO; raw/private field, mismatch 수용 시 revert/NO_GO |
| ER-2D | 격리된 read-only Viewer, 별도 route/root/nav, feature flag; fixed frontend asset만 | ER-2C exact CI와 projection freeze | allowlisted asset, adapter 재검증, summary/list/detail, filters, failure states, investigation call 0, storage 0, rollback OFF | 별도 화면과 기존 workspace 무변경 통과 시 GO; 혼합·자동 요청·stale 성공 시 flag OFF/revert |
| ER-2E | Browser security, accessibility, responsive, Safari와 사용자 수용 | ER-2D exact CI, fixed synthetic fixture | Chromium/axe, keyboard/focus, 1920~320/200%, XSS/canary, external 0, Safari와 실제 기기는 별도, synthetic/incident 이해도 질문 | 자동/사용자 Gate 통과 후 제한 GO; 오해·privacy·overflow·rollback 실패 시 NO_GO |

각 phase는 별도 승인을 받고 작은 로컬 커밋으로 수행한다. ER-2C는 API를 승인하지 않으며, ER-2D에서 데이터 전달 방식이 필요하면 별도 보안 Gate를 먼저 연다.

## 15. Human Review Gate

현재 상태는 유지한다.

- Human Review: `INDEPENDENT_HUMAN_REVIEW_PENDING`
- Manual Approval: `MANUAL_APPROVAL_REQUIRED`
- ER-1D Implementation: `ER_1D_IMPLEMENTATION_HOLD`

Evaluation Viewer는 실제 detector 결과를 보여주므로 독립 reviewer용 Blind Packet으로 제공하지 않는다. Viewer 구현·자동 테스트·사용자 UI 수용은 30개 label의 독립 사람 검토나 승인 증거가 아니다.

## 16. Limitations

- 실제 UI, route, API, projection DTO, feature flag는 아직 구현하지 않았다.
- 현재 30건 합성 snapshot은 운영 정확도·회피율·공격 성공을 일반화하지 않는다.
- ER-1D Feature Delta/Policy Explanation은 없으며 UI에서 추정하지 않는다.
- 인증·다중 사용자 session이 없는 local app이므로 evaluation data는 고정 synthetic source에만 제한한다.
- Markdown report는 UI data source로 승인되지 않았다.
- Safari, 실제 모바일, screen reader, 사람 이해도는 이번 문서 테스트로 검증하지 않았다.
- security-analysis 의미 변경이 없으므로 새로운 외부 보안 연구는 수행하지 않았다. 기존 Production policy와 ER 계약을 그대로 표현한다.

## 17. Test Results

- 시작 exact CI Gate와 artifact/release/Git 상태 확인: 통과.
- 변경 전 전체 pytest: `3768 passed, 2 warnings`.
- TDD RED: 문서 파일과 docs index link가 없어서 신규 문서 계약 `3 failed` 확인.
- 문서 계약은 필수 18개 목차, 세 option, 구조화 DTO, 상태 enum, 위협 모델, viewport, roadmap, Human Review/HOLD/NO_GO 및 구현·승인 과장 금지를 검사한다.
- 신규 문서 계약: `3 passed`; ER/UI 관련 focused 회귀: `130 passed, 2 warnings`.
- 최종 전체 `uv run pytest -q`: `3771 passed, 2 warnings`. 경고는 기준선과 같은 Starlette/httpx 및 AnyIO deprecation이다.
- 순차 실행한 `uv run python -m app.evaluation`: 성공; synthetic boundary 79/79, risk 70/70, case 70/70, Linux process 합성 평가 21/21. 이는 ER-2B UI 검증이나 운영 성능 수치가 아니다.
- `uv lock --check`: 성공(58 packages), `git diff --check`: 성공. 변경 범위는 이 문서, `docs/index.md`, 문서 계약 테스트로 제한됨을 확인했다.

## 18. Final Decision

문서 계약과 전체 회귀가 통과하면 `ER_2B_EVIDENCE_REVIEW_UI_DESIGN_LOCAL_CONDITIONAL_GO`를 부여한다. 이는 별도 Evaluation Workspace의 아키텍처와 보안 계약에 대한 로컬 설계 승인일 뿐이다. 실제 UI/API 구현, 운영 연결, Production 배포, 사람 검토 완료 또는 ER-1D 구현 승인이 아니다.

실제 사용자 자료: `NO_GO` · 조직 운영: `NO_GO` · 자동 대응: `NO_GO`
