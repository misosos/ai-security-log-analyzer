# ER-2E-R3 — Legacy Workspace Navigation Regression 복구

## 1. Executive Summary

`tests/ui_workspace_navigation_28_4.mjs`는 현재 조사 결과 카드가 `case-card > summary`를 가진 disclosure라고 가정했다. 현행 UI는 목록 카드의 명시적인 `상세 분석 보기` 링크를 통해 `#/investigations/c_<24 lowercase hex>` 상세 경로로 이동한다. 이 오래된 선택자는 제품 기능의 회귀가 아니라 테스트의 DOM/라우팅 가정이 낡은 것이었다.

테스트를 현재 사용자 흐름으로 바꾸고, 기존 합성 Guidance payload 최소화·요청 opt-in·safe text 렌더링·stale/refusal 처리·결과 불변성·Navigation 키보드·반응형·CSP·외부 요청 차단 assertion을 유지했다. 콘솔 수집에서 비활성 Live 상태의 일반 리소스 오류를 묵인하던 조건도 제거했다.

## 2. Start SHA / Exact CI

- Start SHA: `2bf52cf8896753c9b176b20263387c9f61543055`
- Exact CI: [`42172876864`](https://github.com/misosos/ai-security-log-analyzer/actions/runs/42172876864), `push / completed / success`, head SHA 일치
- Locked Python 3.12 회귀, 필수 Linux 검사, Restricted Report, Chromium/axe, tracked-file 검사가 모두 성공했다.
- Artifact: 0
- `main`, `origin/main`, GitHub `main`과 local HEAD 일치, ahead/behind `0/0`, 시작 tree clean
- `v0.4.0` Release target은 `eecd6ee1cda0545e34b01c42e1a2163a899bcc27`로 유지
- 사용자 제공 `AGENTS.md`와 Playwright 실행 지침을 확인했다.
- 시작 Gate: `ER_2E_R3_START_GATE_GO`

## 3. Legacy Test Failure Reproduction

수정 전 `node tests/ui_workspace_navigation_28_4.mjs`는 158행에서 30초간 실패했다.

```text
locator.focus: Timeout 30000ms exceeded
waiting for locator('#case-list .case-card').first().locator(':scope > summary')
```

이전 테스트는 카드 summary를 Enter로 열고 같은 카드 안에 Guidance와 Timeline이 있다고 기대했다. 현재 결과 목록은 `role=listitem` 카드와 `review-detail-link`를 제공하고, 상세는 Hash Route에서 별도 화면으로 표시된다. 따라서 이번 건은 테스트 노후화이며 제품 결함 증거는 없다.

추가 실행에서 발견된 오래된 가정도 갱신했다.

- 상세 내부 `details/summary` 타임라인 disclosure 대신 상세 화면의 탭과 `tabpanel` 활동 흐름
- 구형 상담 카드 내부 Guidance 대신 상세의 `근거와 한계` 탭 내부 명시적 요청 버튼 및 radio category
- 도구 그룹 disclosure를 무시한 Navigation의 Shift+Tab 한 단계 이동
- 와이드 사이드바 폭을 과거 220–250px로 고정한 측정값 (현행 화면은 320px)
- 비활성 Live의 404가 있으면 `Failed to load resource` 콘솔 오류를 건너뛰던 테스트 조건

## 4. Obsolete Selector Inventory

| 과거 가정 | 현재 계약 및 대체 검증 |
|---|---|
| `#case-list .case-card > summary` | `#review-case-link-0` 키보드 활성화, 정확한 `data-review-case-ref`, 상세 Hash Route, 상세 제목과 focus 확인 |
| `.timeline-disclosure > summary` | `workspace-timeline-tab-36-6d`의 키보드 활성화, 탭/패널 상태, 관찰·탐지·연결 행 및 인과관계 제한 문구 |
| 목록 카드에서 바로 Guidance 버튼 찾기 | 상세 진입 시 Guidance POST 0, `근거와 한계` 탭의 단일 요청 버튼, native Guidance category radio 확인 |
| Case card `open` 상태 | 상세 화면 표시/숨김, 실제 상세 참조, 목록 복귀 및 포커스 복원 |
| 과거 상세가 만든 레이아웃 좌표·카드 disclosure 높이 | 실제 표시된 사례 수·요약·상세 링크, overflow, 현행 navigation breakpoint와 현재 shell geometry |
| 결과 화면에서 도구 그룹 전 단계가 바로 결과 메뉴라고 가정 | audit 버튼에서 disclosure summary를 거쳐 결과 메뉴로 이동하는 실제 키보드 순서를 검사 |
| 이전 `<select>` | 이 스크립트는 검토 큐 전용 radio를 다시 정의하지 않는다. 별도 `ui_review_queue_36_13a.mjs`가 radio 값·기본값·정렬·필터·키보드를 검증한다. |

## 5. Current UI Contract

합성 Sample Analysis는 결과 대시보드와 검토 사례 두 건을 표시한다. 검토 사례는 안정된 참조를 가진 상세 링크로 열리며 브라우저 Hash에 본문이나 개인정보를 넣지 않는다. 상세 진입은 기존 분석 결과를 변경하거나 Guidance를 요청하지 않는다. 목록 복귀는 선택 링크에 포커스를 복원한다.

## 6. Investigation Detail Migration

회귀 스크립트는 첫 사례 참조가 `c_[0-9a-f]{24}` 형식인지 확인한 뒤 해당 상세 경로로 이동한다. 상세 route/ref 일치, 상세 header, 기본 Overview 탭, 상세 화면 focus를 검사한다. 목록 복귀 후 Hash가 제거되고 선택한 상세가 닫히며 목록 수와 Summary가 그대로이고 이전 링크에 focus가 돌아오는지 확인한다.

## 7. Guidance Contract

- 대시보드와 상세 진입만으로 Guidance 요청이 발생하지 않는다.
- 사용자의 Enter 조작으로 명시적 요청을 9회 실행하고 최소 필드 payload를 검사한다.
- 응답의 `<script>synthetic canary</script>`는 문자 그대로 표시되고 실행 Script node는 생성되지 않는다.
- 결과가 기존 탐지·관계·위험도·사례를 변경하지 않는다는 제한 문구를 확인한다.
- `EXPLAIN_RISK` 거부와 `NEXT_CHECKS` stale 응답의 문구 및 citation 비노출을 검사한다.
- category는 동적 native radio group에서 선택하며 이전 `<select>` selector를 복원하지 않는다.

Guidance endpoint는 Playwright route fixture로 격리되며 실제 외부 호출은 하지 않는다.

## 8. Timeline Contract

현행 상세의 활동 흐름 탭에서 확인된 사실, 탐지된 활동, 분석상 연결을 각각 구별하고 최소 다섯 행을 확인한다. 연결 표시는 “인과관계나 공격 성공을 확정하지 않습니다”라는 제한 문구와 함께 보여야 한다. 검토/탐지 결과는 침해 확정으로 해석되지 않는다.

## 9. Radio Group Regression

이 스크립트는 실제 Guidance category radio의 입력 수와 checked 선택 결과를 검사하고, 상세 작업 탭 간 ArrowRight 키보드 이동을 확인한다. Source 및 Review Queue의 여섯 정적 그룹, 정렬·검색·복수 필터 동작은 기존 독립 `tests/ui_review_queue_36_13a.mjs`가 유지한다. 해당 검증을 중복하거나 옛 `<select>` 구조를 재도입하지 않는다.

## 10. Security Assertions Preservation

수정 후에도 최소 Guidance 요청 필드와 사례 필드 allowlist, 상세 진입 시 자동 요청 금지, 합성 XSS canary의 text-only 렌더링, refusal/stale 보호, 결과 불변성, 원격 요청 0, CSP 확인, 샘플 POST 1회 및 Guidance 요청 11회가 유지된다. 일반 리소스 오류는 더 이상 Live 404 여부에 따라 필터링하지 않는다. `/api/v1/live/status` 404는 별도 카운트되며 정상 흐름에서 0이어야 한다.

테스트는 별도 프로필과 loopback 서버만 사용한다. 사용자 자료나 원격 서비스를 사용하지 않는다.

## 11. Browser Console Results

수정된 레거시 흐름을 Chromium과 WebKit 양쪽에서 독립 실행한다. 각각 Console Error, Page Error, HTTP 4xx/5xx, 비활성 Live status 404, 외부 요청을 실패 조건으로 기록한다. 의도적 보안 거부는 이 정상 사용 흐름에 섞지 않는다.

실행 후 결과를 아래에 기록한다.

| Browser | Legacy Flow | Console/Page/HTTP 오류 | 외부 요청 | 결과 |
|---|---|---:|---:|---|
| Chromium | 실행 완료 | 0 | 0 | PASS |
| WebKit | 실행 완료 | 0 | 0 | PASS |

각 엔진에서 `/api/v1/live/status`의 예기치 않은 404도 0이다. 테스트는 콘솔 오류를 필터링하지 않는다.

## 12. Keyboard/Focus

검토 사례 링크 Enter 활성화, 상세 제목으로 focus 이동, 상세 탭의 ArrowRight 이동, back link를 통한 목록 복귀 focus restoration, disclosure summary를 포함한 Navigation Tab 순서, 모바일 navigation Enter/Escape 및 focus-visible 검사를 수행한다.

## 13. Accessibility

아이콘 접근성, 버튼 accessible name, 상태 텍스트, native tab/tabpanel 탐색을 계속 검사한다. 별도 axe 스위트가 의미 있는 접근성 회귀를 검사하며, axe 자동 검사는 수동 Screen Reader 검수를 대체하지 않는다.

## 14. Responsive

브라우저 흐름은 320, 640, 767, 768, 1024, 1200, 1440, 1600, 2000px에서 Navigation 패널, overflow, breakpoint, focus를 검사한다. 특정 과거 카드 Y좌표나 이전 상세 disclosure의 높이를 요구하지 않는다. 실제 표시된 사례 수와 상세 링크 수 및 현재 shell의 폭·배치를 계속 검사한다.

## 15. RED/GREEN

- RED: 시작 버전은 기존 카드 summary selector에서 실패했다. 상세는 연결되어 있지만 DOM 전제가 폐기된 구현 구조였다.
- GREEN: 새 링크/Hash 상세 흐름, 실제 탭과 radio group, 목록 복귀, 현재 Navigation 순서 및 현행 shell 치수를 검증한다.
- 부가 오류 수집 조건도 수정하여 일반 resource console error를 무시하지 않게 했다.

## 16. Full Regression

검증 결과:

- Legacy Workspace Chromium 및 WebKit
- Review Queue Chromium 및 WebKit
- Review Workflow State Browser
- ER-2D-C Chromium/WebKit, Feature Flag OFF/ON
- ER-2E-R2 Console Recovery 및 Live Monitoring 활성/비활성 회귀
- `npm run test:a11y --silent`
- `uv run pytest -q`
- `uv run python -m app.evaluation`
- `uv lock --check`
- `uv run python -m compileall -q app tests`
- `git diff --check`

R3에서 직접 실행한 핵심 브라우저 결과:

- `node tests/ui_workspace_navigation_28_4.mjs`: Chromium PASS, sample POST 1, Guidance 11, 외부 요청/Console/Page/HTTP 오류/Live 404 모두 0
- `UI_BROWSER=webkit node tests/ui_workspace_navigation_28_4.mjs`: 동일 조건 PASS
- `node tests/ui_review_queue_36_13a.mjs` 및 `UI_BROWSER=webkit ...`: 둘 다 PASS, axe 위반 0
- ER-2D-C의 Chromium/WebKit OFF 및 ON 네 조합: 모두 PASS, OFF fetch 0, ON 외부 요청·POST·콘솔 오류 0, axe 0
- `node tests/ui_review_state_36_14d.mjs` 및 `node tests/ui_review_workflow_state_security_36_14e.mjs`: PASS, console/page 오류 0
- `npm run test:a11y --silent`: PASS, 25개 Live 상태 및 여러 viewport/200% reflow 검사 완료

Python 전체 회귀 및 Evaluation Runner:

- `uv run pytest -q`: `3881 passed, 2 warnings` (macOS Python 3.12)
- `uv run python -m app.evaluation`: 성공; Synthetic Boundary `79/79`, Risk `70/70`, Case `70/70`, Linux Process 합성 분류 `21/21`
- `uv lock --check`: 통과
- `uv run python -m compileall -q app tests`: 통과
- `git diff --check`: 통과
- 신규 문서 계약 테스트는 문서 생성 전 missing-file 실패(RED), 문서 작성 후 통과(GREEN)

R3 변경은 브라우저 테스트·문서·index·문서 계약 테스트에 한정된다. API/Production/UI 구현, CSP, Evaluation Snapshot/Pin 및 corpus는 수정하지 않았다.

## 17. Changed Files

테스트 복구, 문서 계약 테스트, 이 보고서 및 `docs/index.md`만 변경한다. 제품 구현, CSP, Snapshot JSON/Pin, API, corpus 및 분석 정책은 변경하지 않는다.

## 18. Remaining Limitations

자동 Chromium/WebKit 검증은 실제 Safari 기기·실제 Screen Reader 사용·모바일 실기기 수용 검수를 증명하지 않는다. UI Test는 고정 합성 사례와 격리된 API response만 사용한다.

## 19. User Acceptance Status

`ER_2E_USER_ACCEPTANCE_PENDING`. 실제 Safari, 모바일 실기기 및 수동 VoiceOver 검수 결과는 아직 제공되지 않았다.

## 20. Human Review Gate

`INDEPENDENT_HUMAN_REVIEW_PENDING`, `MANUAL_APPROVAL_REQUIRED`, `ER_1D_IMPLEMENTATION_HOLD`를 유지한다. 실제 사용자 자료·조직 운영·자동 대응은 계속 `NO_GO`다.

## 21. Final Decision

모든 필수 브라우저·접근성·Python 회귀가 통과했고 변경 범위가 테스트·문서뿐이므로 최종 판정은 `ER_2E_R3_LEGACY_BROWSER_REGRESSION_LOCAL_CONDITIONAL_GO`다. 이는 실제 Safari/모바일/VoiceOver 검수나 사용자 수용, 독립 사람 검토 또는 운영 승인을 의미하지 않는다.
