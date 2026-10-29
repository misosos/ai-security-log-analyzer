# Phase 36.6F — 조사 작업공간 반응형·접근성 수용 검증

## 범위와 시작 gate

이 기록은 Phase 36.6B–E production 조사 작업공간의 전체 반응형·접근성 회귀를 다룬다. 새 기능, backend/API/schema 변경, 분석 동작 변경, 사용자 최종 수용은 범위에 포함하지 않는다.

- 기준 SHA: `07736c2fe5afc755060b195077a2c4efd0cbd99f`
- 시작 Actions run: `40835247839` — 정확한 SHA의 `push / completed / success`
- 시작 artifact: 0
- 시작 branch와 local/remote SHA: `main`, 모두 기준 SHA와 일치; `origin/main...HEAD` 0/0
- 시작 working tree: clean
- 시작 run에서 Linux 전체 pytest, TCP Syslog, JSONL, restricted report, Chromium/axe, tracked-file invariant 통과
- `v0.4.0` tag와 Release target은 `eecd6ee1cda0545e34b01c42e1a2163a899bcc27` 유지

이번 작업 환경은 macOS Chromium이다. Linux 전용 검증은 시작 SHA의 CI 증거로만 기록하며 새 로컬 실행으로 취급하지 않는다.

## Baseline, RED와 수정

초기 `npm run test:a11y --silent` baseline은 기존 23개 Chromium/axe 상태에서 axe violation 0, 외부 요청 0으로 통과했다. 통합 수용 측정을 추가한 뒤 320 CSS px, 200% equivalent 상태에서 `REVIEW_DETAIL_200_PERCENT_REFLOW_FAILED`가 재현됐다.

실패 측정은 document 폭 320/320 CSS px, panel overflow 0, clipping 0이었지만, 접힌 모바일 내비게이션의 `#nav-results` 영역(272×88px, y=577.42–665.42)과 `#review-back-link`(272×99.19px, y=645.58–744.77)이 실제로 20px 겹쳤다. 원인은 접힌 `<details>` 아래 `.workspace-nav-list`에 명시된 flex display가 닫힌 상태에서도 메뉴 자식을 layout에 남기는 것이었다. 따라서 초기 실패는 threshold 문제가 아니라 실제 focus/click 영역 중첩이었다.

최소 CSS 수정은 모바일에서 닫힌 내비게이션 `<details>`의 직계 `.workspace-nav-list`를 숨기는 것이다. 기존 메뉴의 열린 상태, 44px target, 8px 간격은 유지한다. 추가 계약은 메뉴를 닫았을 때 자식 링크가 보이지 않고 다시 열었을 때 돌아오는지 확인한다.

동일한 200% 측정에서 닫힌 메뉴의 0×0 자식 target이 helper에 잡힌 후속 실패도 있었다. 측정 helper를 실제 표시 영역만 포함하도록 수정했다(숨김 조상, `display:none`, `visibility:hidden`, 0 크기 제외). 이 변경은 target 기준을 완화하지 않으며 접힌 자식은 독립적인 닫힘 계약으로 검사한다.

최종 Chromium 실행은 통과했다. 초기 수용 검사의 red는 320px/200% equivalent에서 접힌 nav 자식이 보이지 않게 숨겨지지 않아 nav와 복귀 링크가 20px 중첩된 것이었다. 수정 후 접힌 메뉴 목록은 숨겨지고, 열린 상태에서 요약 44px, 메뉴 target 최소 44.17px, 인접 gap 8px가 측정됐다.

추가 red는 390px Evidence 상태에서 select와 Guidance 버튼의 세로 간격이 6.39px인 실제 결함이었다. 버튼에 block 방향 8px 여백을 추가했다. 중간 실행에서 발견된 후속 실패는 숨겨진 0×0 target을 포함하거나, viewport media-query 변경 직전 메뉴 상태를 읽거나, target rect의 top/bottom을 빠뜨린 측정 코드 문제로 분류해 보정했다. 정상/오류 기준 및 44×44/8px 임계값은 유지했다.

## 전체 앱 반응형 및 확대 측정

검증 viewport: 1440×900, 1024×768, 768×1024, 390×844, 320×568 CSS px. 전체 문서/body, 주요 dashboard/detail/timeline/tasks/evidence/citation/checklist panel, clipping 및 visible target geometry를 측정한다. 320px의 200% equivalent는 root font-size를 200%(32px)로 올려 측정하며, 실제 browser zoom 200%와 동일하다고 주장하지 않는다.

최종 전체 상태 검사는 1440, 1024, 768, 390, 320px에서 `document`/`body` 가로 overflow 0, 대상 panel overflow 0, clipping 0, target 크기·간격 위반 0으로 통과했다. 320px/200% equivalent(root font-size 32px)에서도 측정 상태의 overflow, clipping, 44px 미달, 8px 미달은 0이었다. 측정 후 root 글자 크기를 복원하고, 접힌 메뉴와 열린 메뉴 상태를 따로 확인한다.

수정 전 200% equivalent에서 legacy renderer의 긴 timeline timestamp가 panel 폭을 넘는 문제도 재현됐다. 기존 timeline에 min-width와 안전한 줄바꿈을 적용했으며 사건 순서와 내용은 변경하지 않았다.

모든 target은 실제 DOMRect 기준 최소 44×44 CSS px, target 쌍 간 `targetGapPx` 기하학 기준 최소 8px로 검사한다. 같은 줄, 줄바꿈 줄, 대각선 분리와 겹침 검사를 유지한다. CSS 글자 높이를 target 크기로 대신하지 않는다. `overflow-x:hidden`을 추가하지 않았다.

## 키보드, ARIA, axe, 개인정보와 요청 불변

Chromium 테스트는 기존 axe 상태를 유지하고 검토 작업공간의 dashboard, 상세 탭, timeline, checklist 상태, evidence/guidance, disclosure 및 keyboard 흐름을 포함한다. 키보드 Tab/Shift+Tab, Enter/Space, tablist 이동, disclosure 열기·닫기와 focus 복귀는 자동 브라우저 동작 테스트로 분리 기록한다. axe 통과는 WCAG 2.2 AA 전체 준수 또는 스크린리더 수동 검수의 증거가 아니다.

기존 privacy canary, A/B 사례 전환과 비동기 응답 격리, direct-entry expiry, rollback을 유지한다. 상세 진입·탭 전환·hover/focus·back/forward의 checklist 자동 POST는 0이며 checklist와 guidance는 각자의 명시적 버튼에서만 요청한다. 기존 19필드 workspace projection, timeline projection, checklist v2, analysis, report, SSE, checkpoint, publication과 corpus/citation 검증 계약은 변경하지 않는다. `limitation_count`는 분석 한계 수로만 유지한다.

## 정적 자산과 rollback

`app/web_ui.py`의 160 KiB 정적 자산 상한과 고정 `/assets/app.js` 제공 경로를 유지한다. 신규 외부 asset/dependency는 추가하지 않는다. `USE_WORKSPACE_DETAIL_SHELL_36_6B`와 기존 renderer를 보존한다. 실제 asset 응답 상태·크기·보안 헤더 결과는 테스트 실행 후 기록한다.

## 검증 결과

| 항목 | 결과 |
| --- | --- |
| 시작 exact-SHA CI 및 artifact | PASS — 40835247839, 0 artifacts |
| Chromium/axe | 기존 23개 axe 상태와 workspace 통합 상태 통과; `states=23`, axe violation 0 |
| 외부 요청 | 0 |
| 1440/1024/768/390/320px | 전체 화면·주요 상태 overflow/clipping/overlap 0 |
| 320px 200% equivalent | root font-size 32px, 전체 앱 상태 검사 통과; 실제 browser zoom이 아님 |
| Target geometry | 측정 대상 최소 44×44px, 인접 target gap 최소 8px; 위반 0 |
| Keyboard / ARIA / focus | Tab/Shift+Tab, 활성화, 4-tab 키보드, disclosure, focus/ARIA 계약 자동검사 통과 |
| Privacy / async isolation / explicit request | canary 누출 0; 사례 격리; 자동 checklist/guidance 요청 0; 명시 요청 계약 통과 |
| npm / Python | `npm ci --ignore-scripts --no-audit --no-fund`, `uv sync --locked --dev`, `uv lock --check` 통과 |
| 전체 pytest | `3099 passed`, 경고 2개 (Starlette/httpx 및 anyio deprecation) |
| Node/Python 문법 | `node --check`, `uv run python -m compileall -q app tests` 통과 |
| TCP Syslog·JSONL·restricted report (macOS) | NOT_TESTED — Linux 전용; 시작 CI 증거와 새 SHA CI 필요를 구분 |
| `git diff --check` | 통과 |
| Safari·실제 모바일·VoiceOver | NOT_TESTED |
| 실제 사용자 자료·조직 운영·자동 대응 | NO_GO |
| 모델 기반 AI | NOT_TESTED |
| Vector/VM | USER_ACTION_REQUIRED / ISOLATION_BLOCKED |

합성 개발용 관측(운영 SLA 아님): workspace 전환 warm-up 10/sample 30에서 median 96.657ms, p95 101.272ms, max 101.289ms; 상세 DOM 153 nodes/7,920 bytes. Timeline은 5개 item, 37 nodes/3,524 bytes, 탭 전환 warm-up 10/sample 100에서 median 0.4ms, p95 0.6ms, max 0.6ms였다. Timeline 1/32/256건(각 100 samples) render median/p95/max는 0.7/0.8/0.9ms, 1.4/1.6/1.7ms, 6.9/7.7/8.5ms이며 adapter output 357/8,068/64,001 bytes였다. 서로 다른 환경·표본의 Phase 기준치와 성능 우열을 주장하지 않는다. 최종 Chromium/axe 스크립트 경과 시간은 약 94.9초였다.

`frontend/app.js`는 135,153 bytes로 파일별 160 KiB 제한보다 작다. 기존 Chromium/pytest 검사에서 고정 `/assets/app.js` 제공, CSP, `no-store`, `nosniff` 계약을 통과했다. 신규 외부 자산/dependency 및 lockfile 변경은 없다.

Checklist 상세 진입·탭 이동·hover/focus·back/forward·자동 재렌더링은 POST 0, 요청 버튼 1회는 POST 1, pending 중 연타 중복은 0이다. Guidance는 별도 명시 버튼만 사용한다. privacy canary, 사례 A/B 지연 응답 격리, 만료 route, 기존 renderer rollback, 분석 불변 검사가 통과했다.

## 남은 조건

이 단계의 자동검증은 사용자 수용 PASS가 아니다. Linux 전용 TCP/JSONL/restricted report는 macOS에서 실행하지 않았다. 새 커밋 SHA의 Ubuntu CI 성공과 별도 사용자 최종 수용 전에는 Phase 36.6G를 시작하지 않는다. Safari·실제 기기·VoiceOver는 `NOT_TESTED`다. 실제 사용자 자료·조직 운영·자동 대응은 `NO_GO`, 모델 기반 AI는 `NOT_TESTED`, Vector/VM은 `USER_ACTION_REQUIRED / ISOLATION_BLOCKED`다.
