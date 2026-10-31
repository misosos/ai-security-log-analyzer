# Phase 36.10A-UI3 — Safari 화면 수용 준비 및 Navigation 회귀 종결

## 1. Executive Summary

UI1/UI2의 사이버펑크 조사 워크스페이스를 재작성하거나 Production 화면을 수정하지 않았다. 현재 Navigation 계약을 독립 실행 가능한 합성 Chromium E2E로 확인하고, Safari WebDriver로 시작 화면·Dashboard·Case 상세와 browser history를 실제 Safari 18.6에서 확인했다.

구형 `ui_workspace_navigation_28_4.mjs`는 현재 Case 상세로 이동한 뒤 Guidance를 요청하는 화면 구조와 다르게, Dashboard 안에서 두 개의 Guidance 컨트롤을 기대하며 첫 assertion에서 멈춘다. 이후 코드에는 이전 DOM 기반 사례 확장과 UI2 이전 sidebar 폭 등 더 많은 낡은 가정이 있다. 기존 파일은 보안 assertion을 지우거나 약화하지 않고 보존했다. 이를 대신해 현행 Dashboard/Case Detail 경계를 실제 API·합성 브라우저 요청으로 확인하는 `ui_navigation_closure_36_10a_ui3.mjs`를 추가했다.

Safari WebDriver 결과는 기술적 자동화 확인이다. 확대 단계별 시각 검수 및 사용자의 수용 승인은 아직 남아 `SAFARI_USER_ACCEPTANCE_PENDING`이다.

## 2. 시작 Gate

- Repository: `ai-security-log-analyzer`
- Branch: `main`
- 기준 HEAD / local main / origin main / GitHub main: `046a848db67c79c4cd3882c4777c7980cf00ef1f`
- 시작 Working Tree: clean, ahead/behind `0/0`
- GitHub Actions Run `41174684160`: exact SHA 일치, `push`, `completed / success`
- 필수 Lock/Python 3.12, 전체 회귀, Linux checkpoint/process 및 SSH, TCP Syslog, JSONL, Restricted report, Chromium/axe, tracked-file invariant 단계 모두 성공
- Artifact: 0개
- v0.4.0 tag/Release target: `eecd6ee1cda0545e34b01c42e1a2163a899bcc27`, 변경 없음

## 3. UI1/UI2 기준선 및 코드 조사

다음 과거 UI1/UI2 및 36.6C/D/E/F/G 계약 문서를 현재 코드와 대조했다. UI2의 CSS 측정 기준은 Desktop 1440px Sidebar 280px, nav 18.02px, body 17px, 페이지 제목 약 40px, 버튼 약 50px이며 320px 폭/200% equivalent reflow도 확인된 상태다. 이번 Phase에서 CSS/HTML은 수정하지 않았다.

현재 데이터 및 화면 경계는 다음과 같다.

```text
합성 샘플 분석 POST
  → 검증된 public 결과의 현재 탭 메모리 표시
  → Dashboard case_ref 링크
  → Hash route Case 상세
  → Overview / Timeline / Checklist / Evidence
  → 명시적 요청에서만 Checklist 또는 Guidance POST
```

기존 `investigation-workspace-ui/v1` 19-field projection, Hash navigation, Back/Forward, Case 격리, `unknown` Source-role, `undetermined` Priority, Checklist v2, 명시적 Guidance, CSP/Privacy, 36.6G `KEEP_LEGACY` 경계를 유지했다.

## 4. 기존 Navigation 스크립트 조사

### 실패 위치와 당시/현재 DOM 계약

`node tests/ui_workspace_navigation_28_4.mjs` 실행 결과는 다음과 같다.

```text
Error: GUIDANCE_MUST_BE_OPT_IN
at tests/ui_workspace_navigation_28_4.mjs:111
```

해당 assertion은 샘플 결과 Dashboard에서 `.guidance-request`가 2개라고 가정한다. 현행 구조에서는 Guidance 버튼이 Case Detail의 Evidence 탭에 생성되고 Dashboard에는 없다. 요청은 사용자가 해당 상세 컨트롤을 눌렀을 때만 전송된다. 따라서 기존 테스트 실패는 이 지점까지는 실제 요청 자동 발생이 아니라 이전 DOM 위치/개수에 대한 가정 불일치다.

기존 테스트의 나머지도 현재 계약과 다르다. line 150 이후 `.case-card > summary` 아래에 Guidance가 있다고 가정하고, line 144–148은 Dashboard의 `<details>`를 열어 펼쳐진 높이를 측정한다. 현재 Dashboard는 link에서 별도 Hash Detail route로 이동한다. line 324 이후 2000px Desktop Sidebar가 220–250px라고 요구하지만 UI2의 실제 Desktop 값은 280px다. 이 첫 assertion에서 실행이 중단되므로 기존 파일의 후속 assertion을 모두 실행했다고 주장하지 않는다. 정적 코드 대조로 stale 가정을 분리했다.

기존 보안 목적을 남기기 위해 해당 테스트의 assertion을 바꾸거나 삭제하지 않았다. 대신 현행 DOM을 정당화하는 별도 UI E2E를 만들었다. 기존 테스트는 역사적 참고 자료로 남으며 전체 성공 테스트로 기록하지 않는다.

### 활성 UI 회귀의 독립 계약

기존 활성 `tests/ui_accessibility_axe_pilot_28_1.mjs`는 이미 현행 계약을 실제로 확인한다. 이 테스트에서 Dashboard 진입 시 Guidance POST 0건, Case 상세의 Guidance 단일 컨트롤, 명시적 클릭 시 요청, 안전한 문자 렌더링, Case 간 Checklist 응답 격리, Hash route/Back/Forward, 만료·직접 진입 경계, 19-field projection, Renderer rollback을 검증한다.

새 `tests/ui_navigation_closure_36_10a_ui3.mjs`는 별도 임시 HOME, 로컬 Uvicorn 프로세스와 실제 합성 Sample API를 사용한다. 시나리오:

1. Start에서 Sample 분석을 한 번 실행하고 두 개의 Case reference를 얻는다.
2. Case A의 실제 Hash detail route로 이동한다.
3. Tasks/Evidence 탭, hover/focus 및 disclosure를 조작해도 Guidance/Checklist 요청이 0건임을 확인한다.
4. Guidance를 키보드로 명시 요청한다. 최소화된 request body shape를 검증하고 응답을 의도적으로 지연한다.
5. Browser Back/Forward로 Dashboard와 Case A route 복귀를 확인한다.
6. Case B로 이동한 다음 지연된 A 응답을 해제한다. B 화면에 A의 citation marker가 나타나지 않고 `<script>` 문자열이 실행되지 않음을 확인한다.
7. 새 탭에서 이전 분석의 Case reference를 열어 `review-route-expired` 상태인지 확인한다.
8. 존재하지 않는 형식 유효 Case reference도 만료 안내로 닫히는지 확인한다.
9. 외부 요청 0건, CSP 계약, document overflow 없음 및 임시 서버 종료를 확인한다.

## 5. Guidance / Checklist opt-in 및 Case isolation

| 동작 | Guidance POST | Checklist POST |
|---|---:|---:|
| 앱 시작 / 샘플 Dashboard | 0 | 0 |
| Case 상세 진입 | 0 | 0 |
| Tasks/Evidence 탭, hover, focus, disclosure | 0 | 0 |
| Guidance 버튼 명시 클릭 | 1 | 0 |

지연된 Guidance 요청은 Case A의 허용된 최소 `case` projection만 전송한다. 응답이 대기 중인 동안 Case B로 바꾸고 응답을 돌려도 B에 A의 도움말이 표시되지 않았다. 합성 `<script>PRIVATE_GUIDANCE_CANARY</script>`는 실행되지 않았고 Case B DOM에도 없다. Checklist의 명시적 요청·loading/error state·A/B 비동기 격리는 활성 25-state Browser 테스트가 별도로 검증한다.

Checklist/Guidance 결과는 분석 결과 자체의 변경이나 안전 판정으로 표현하지 않는다. 원문 로그, 계정 또는 내부 컨텍스트를 UI 요청에 추가하지 않는다.

## 6. Hash Route / Browser History / Dashboard / Detail

- 실제 Sample 분석은 POST 1회, 결과 Dashboard와 2개 synthetic case reference를 렌더링했다.
- 상세 선택은 해당 `case_ref` Hash route에 일치했다.
- Browser Back은 목록으로, Forward는 같은 Case 상세로 복귀했다.
- 이전 실행의 참조 또는 미존재 Case direct entry는 현재 분석 메모리로 연결되지 않고 만료 안내로 이동했다.
- Risk, Source-role, Review Priority, Timeline, Evidence 및 한계는 기존 projection·검증 경계를 그대로 사용한다.
- active Browser suite는 Dashboard 내용 불변, Timeline의 순서, case_ref와 detail identity 일치, Renderer rollback 및 Checklist 경계를 독립적으로 점검한다.

## 7. Chromium 실측 및 UI2 Responsive 계약

활성 Chromium/axe 회귀는 25개 상태와 외부 요청 0건으로 통과했다. 시작 화면, Dashboard, Case 목록/상세, Timeline, Evidence, Checklist/Guidance의 상태 및 responsive 검사에서 overflow/clipped/target-size 실패가 없었다. viewport는 1920×1080, 1440×900, 1280×800, 1024×768, 768×1024, 390×844, 320×568을 포함하며, 200% equivalent reflow는 root font size 32px 방식이다. 이는 브라우저 Page Zoom을 동일하게 재현하는 검사가 아니다.

UI2의 마지막 CI Run과 local Chromium 실측을 기준선으로 유지했다. UI3에서는 Chrome/axe 작업을 재실행하지 않고, 이 기록에서 별도의 실제 Safari 확인을 추가했다.

## 8. Safari 기술 smoke 및 사용자의 화면 수용 체크리스트

Safari WebDriver가 macOS에서 실제 Safari `18.6`을 시작했다. 1440×1000 window rectangle 설정 후 실제 CSS viewport는 `1440×948`, `devicePixelRatio=2`였다. computed metrics:

| Safari 측정 항목 | 실제 값 |
|---|---:|
| 1440 CSS px Sidebar | 280px |
| Navigation font | 18.02px |
| Body font | 17px |
| Start `#page-title` | 40.32px |
| document horizontal overflow | 없음 |
| sample Dashboard → Case Detail → Back → Forward | 동작 |

1920×1100 window rectangle에서는 CSS viewport `1920×1048`, DPR 2, Sidebar 280px, nav 18.02px, body 17px, main content 1640px, overflow 없음이었다. Safari 캡처는 `/tmp/ui3-safari-start-1440.png`, `/tmp/ui3-safari-dashboard-1440.png`, `/tmp/ui3-safari-case-detail-1440.png`, `/tmp/ui3-safari-case-detail-1920.png`에만 저장했고 저장소에는 포함하지 않았다.

1440 캡처를 시각적으로 검토했을 때 Sidebar의 현재 위치와 본문 제목이 구분되고, 요약 숫자에서 Case 목록으로 시선이 이어졌다. 샘플 상태 안내와 “침해나 공격 성공의 확정이 아니다”라는 경계 문구도 탐지 수치와 분리되어 보였다. 캡처에서 겹침이나 가로 잘림은 관찰되지 않았다. 이는 한 합성 화면의 검토 기록이며 전체 상태·확대 단계에 대한 사용자 수용 판정은 아니다.

이는 Safari 자동화 smoke이며 Safari 사용자 시각 수용 승인이 아니다. 실제 Safari Page Zoom 100/125/200 단계는 제어·검증하지 않았고 VoiceOver도 실행하지 않았다. Safari 자동화의 window rect는 사용자 화면의 배율 설정을 보증하지 않는다.

### 사용자 검수 절차

검수 주소: [http://127.0.0.1:8000/](http://127.0.0.1:8000/). 작업 시점 GET은 HTTP 200이었다. 로컬 서버가 종료되면 저장소 루트에서 `uv run uvicorn app.api:app --host 127.0.0.1 --port 8000`으로 시작해야 한다. 자동화가 서버를 실행한 것처럼 가장하지 않는다.

Safari에서 실제 주소를 열고 아래를 확인한다. 결과를 회신하기 전까지 상태는 `SAFARI_USER_ACCEPTANCE_PENDING`이다.

| 검수 | 확인 항목 | 사용자 결과 |
|---|---|---|
| A. 시작 화면 | Sidebar 폭/메뉴 판독, 설명 가독성, 3개 분석 카드 균형, 과도한 빈 패널·겹침 여부 | 미확인 |
| B. Dashboard | 요약, Case 목록, Risk/Role/Priority 텍스트 구분, 선택할 사례 이해 | 미확인 |
| C. Case 상세 | 제목, 활동 순서, Evidence/한계, Checklist 상태, 밀집도 | 미확인 |
| D. 100% zoom | 기본 배치, 가로 스크롤/잘림/겹침 없음 | 미확인 |
| E. 125% zoom | 메뉴·카드 줄바꿈 및 클릭 가능성 | 미확인 |
| F. 200% zoom | 내용 재배치, 수평 스크롤, 잘림 및 터치 영역 | 미확인 |

각 단계에서 이상 여부와 “수용” 또는 수정이 필요한 부분을 기록한다. Safari 수용은 사용자의 명시 응답 이후에만 완료 처리한다.

## 9. Privacy / CSP / Renderer

화면 검증은 합성 sample만 사용했다. Browser E2E는 외부 요청 0건을 확인했고, app HTML은 same-origin `script-src`/`connect-src`, inline script 금지 정책을 유지했다. Raw log, raw account, provenance/private context, token을 UI 또는 Safari screenshot에 넣지 않았다. Public projection 19개 필드, Checklist v2와 Guidance 요청 schema, API/분석 코드는 변경하지 않았다. `USE_WORKSPACE_DETAIL_SHELL_36_6B` 및 `KEEP_LEGACY` 롤백은 유지한다.

## 10. 테스트 결과

- 시작 exact-SHA GitHub CI Run `41174684160`: 필수 Linux/Chromium regression 성공
- `node tests/ui_workspace_navigation_28_4.mjs`: **실패 재현**, `GUIDANCE_MUST_BE_OPT_IN` (line 111). 이는 전체 구형 테스트 PASS가 아님.
- `node tests/ui_navigation_closure_36_10a_ui3.mjs`: PASS, sample POST 1, guidance POST 1, checklist POST 0, 2 references, 지연 A 응답의 B 격리, stale/invalid route 만료, 외부 요청 0, CSP 확인.
- `uv sync --locked --dev`: PASS.
- `uv lock --check`: PASS.
- `uv run pytest -q`: `3367 passed, 2 warnings` (113.83s).
- `python3 -m compileall -q app tests`: PASS.
- `node --check` (활성 UI, 구형 Navigation, UI3 E2E): PASS.
- `npm run test:a11y --silent`: 25 states PASS, external requests 0 (80.877s).
- `node tests/ui_navigation_closure_36_10a_ui3.mjs`: PASS. Browser 기반 실제 요청/응답, 지연, route 및 격리 검증 결과는 위에 기록.
- Playwright CLI wrapper도 시도했으나 이 환경에는 CLI가 요구하는 `/Applications/Google Chrome.app/Contents/MacOS/Google Chrome`이 없어 daemon 시작이 실패했다. 이는 Chromium 검증을 대체하지 않는다. 저장소의 활성 Playwright 기반 `npm run test:a11y`와 UI3 E2E는 별도로 정상 완료됐다.
- `node tests/ui_workspace_navigation_28_4.mjs`: 의도된 역사 테스트 실패를 재현했다. line 111의 `GUIDANCE_MUST_BE_OPT_IN`은 현행 Dashboard DOM에서 Guidance 버튼 두 개를 찾는 오래된 구조 기대다. 해당 파일은 수정하지 않았고 후속 assertions는 실행되지 않았다.
- `git diff --check`: PASS.

## 11. 검증 공백 및 롤백

- 사용자 Safari 화면 수용 및 100/125/200% Page Zoom: `USER_ACTION_REQUIRED` / `SAFARI_USER_ACCEPTANCE_PENDING`
- Safari VoiceOver 및 실제 모바일: `NOT_TESTED`
- 구형 Navigation 스크립트 전체 후속 assertions: stale first assertion 때문에 미실행; 현행 active suite와 UI3 독립 E2E가 현재 계약을 확인
- 조직 운영, 실제 사용자 로그, 자동 대응: `NO_GO`

이번 Phase에는 production 변경이 없다. Rollback할 application behavior는 없다. 테스트 추가가 문제를 일으키면 새 UI3 테스트와 문서 index 항목만 해당 커밋의 `git revert`로 되돌릴 수 있다. 기존 28.4 테스트와 UI1/UI2 문서는 수정하지 않는다.

## 12. 최종 판정

`PHASE_36_10A_UI3_AUTOMATED_CLOSURE_LOCAL_CONDITIONAL_GO`

Safari의 실제 자동화 smoke는 수행했으나 사용자의 시각 수용 승인은 완료되지 않았다. 상태는 계속 `SAFARI_USER_ACCEPTANCE_PENDING`이다.
