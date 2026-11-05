# ER-2E-R2 — WebKit CSP 호환 컨트롤 복구 기록

## 1. Executive Summary

R1에서 재현한 WebKit `27.2`의 `style-src` 오류는 테스트 도구 주입이 아니라 네이티브 `<select>` 렌더링에서 발생했다. R2는 기존 CSP를 그대로 유지하면서 여섯 개 정적 선택 컨트롤을 이름 있는 `fieldset`과 네이티브 radio group으로 바꿨다. 실제 WebKit과 Chromium에서 OFF/ON 시나리오를 다시 실행했으며 Evaluation Viewer, 검토 큐 검색·필터·정렬 및 검토 상태 회귀가 통과했다.

추가 브라우저 점검 중 상세 조사 흐름의 동적 도움말 주제 `<select>`와 검토 상태 컨트롤에서도 같은 WebKit 메시지가 재현되어 같은 radio group 방식으로 바꿨다. 기존 값·기본 선택·요청 payload는 유지했다. CSP를 완화하거나 콘솔 오류를 숨기지 않았다.

## 2. Start SHA / Exact CI

- 시작 SHA: `242dc4ae91e8a43429ef7f89098db11b8ac7bf27`
- Exact GitHub Actions: `42032167826`, `push / completed / success`, head SHA 일치
- 필수 Linux Regression, Restricted Report, Chromium/axe, Tracked-file 검사: 시작 CI에서 성공
- Artifact: 0
- `v0.4.0` Release target 유지: `eecd6ee1cda0545e34b01c42e1a2163a899bcc27`
- 시작 시 main/origin/main/GitHub main 일치, ahead/behind `0/0`

## 3. R1 미커밋 작업 보존

R2 시작 시 사용자가 보존하라고 지정한 R1 변경만 존재했다. R1의 `app/api.py` 및 `app/web_ui.py` Live Script 분기와 `tests/test_live_monitoring_ui.py` 활성/비활성 회귀를 기반으로 작업했다. 비활성 App은 고정 no-op Live Script를 제공하며, 활성 Service에는 기존 script bytes를 제공한다. `/api/v1/live/status`의 비활성 `404 / LIVE_MONITORING_NOT_ENABLED` 의미는 유지된다.

R1 문서의 원래 `ER_2E_R1_SECURITY_HOLD` 결과는 삭제하지 않았다. R2의 WebKit 후속 근거를 이 문서로 연결했다. R1의 초기 HTML 제공 경계도 유지된다. Feature Flag OFF의 `/` body는 현재 저장소의 `frontend/index.html` 원본 bytes이며 서버에서 동적 주입하지 않는다.

## 4. WebKit Root Cause Evidence

R1의 독립 진단은 WebKit `27.2`에서 빈 문서와 `<div>`에 0건, 네이티브 `<select>` 하나에 CSP 오류 1건을 관찰했다. axe 실행 전에도 앱 기본 화면의 여섯 선택 목록에 대응하는 여섯 오류가 있었다. 동일 CSP에서 외부 `appearance:none`을 적용해도 재현됐다. 이 R2는 같은 격리 원인 진단기를 다시 실행했고 결과는 `select=1`, `div=0`, 정책 변경 없음이었다.

R2의 기능 브라우저 검사에서는 네이티브 `<select>`가 남지 않도록 정적 HTML 및 사용자에게 노출되는 동적 조사 컨트롤도 radio group으로 마이그레이션했다. WebKit OFF와 ON 기본/정상 흐름에서 CSP console error가 0이었다. R1의 원인 진단 페이지는 의도적으로 `<select>`를 포함하므로 그 격리 진단에서 오류 1건이 계속 관찰되는 것은 기대 결과다. 이는 정상 앱 흐름의 오류로 집계하지 않았다.

## 5. 여섯 정적 컨트롤 목록

| 기존 컨트롤 | 유지한 값과 기본값 |
|---|---|
| `text-source` | `application`(기본), `ssh`, `access` |
| `review-queue-sort-36-13a` | `default`(기본), `risk`, `newest`, `oldest`, `title` |
| `review-queue-risk-36-13a` | `all`(기본), `HIGH`, `MEDIUM`, `LOW` |
| `review-queue-role-36-13a` | `all`(기본), `application`, `ssh`, `access`, `unknown` |
| `review-queue-priority-36-13a` | `all`(기본), `review_now`, `review_soon`, `review_later`, `undetermined` |
| `review-queue-state-36-14d` | `all`(기본), `unreviewed`, `in_review`, `reviewed`, `deferred` |

각 그룹은 `fieldset`/`legend` 및 레이블이 지정된 radio 입력을 사용한다. 정적 `<select>`는 남기지 않았다. 필터 패널은 기존 disclosure 안에 유지되며 선택 값은 radio의 `checked` 상태에서 읽는다.

## 6. 승인된 HTML 계약 개정

이전 커밋과 HTML bytes가 계속 동일하다는 요구를 이번 R2에서 해제했다. 접근성과 WebKit CSP 호환성을 위해 위 여섯 컨트롤 및 조사 상세에서 실제로 쓰이는 선택 컨트롤을 변경할 수 있다. 변경 후에도 OFF 응답은 `frontend/index.html`의 원본 파일 bytes 그대로 제공되며 동적 HTML 주입은 없다.

변경된 HTML은 컨트롤 마크업과 이름 지정된 그룹에 한정했다. Evaluation Navigation/DOM/JS/CSS/Snapshot Fetch는 OFF에서 계속 없고, 기존 CSP와 조사 기능은 유지된다. 정적 계약 테스트는 허용된 옵션 inventory와 `<select>` 부재를 검사한다.

## 7. Radio Group 및 JavaScript 마이그레이션

- 로그 텍스트 제출은 `text_source` radio 중 checked 항목을 읽어 기존 API의 `source` 필드로 보낸다. 누락 시 고정 기본값 `application`을 유지한다.
- 검토 큐 검색, 필터 조합, 정렬은 checked radio 값으로 계산한다. 필터 초기화는 각 그룹의 기존 기본값을 다시 선택한다.
- 필터 Chip 제거 후 해당 라디오에 포커스를 복원한다. 현재 검토 항목이 목록에서 사라지는 상태 변경에서는 검토 상태 필터로 포커스를 돌린다.
- 동적 검토 상태 그룹은 현재 값, 허용된 전이 및 기존 초기화 동작만 표시한다. 저장·비교·revision 계약은 변경하지 않았다.
- 상세 조사 도움말 주제 그룹은 기존 허용 category 값을 보존하고, 선택 category를 요청 body에 넣는다.
- fieldset 비활성화는 그룹 내 컨트롤 전체에 적용된다. 그룹에서 오류가 발생하면 현재 선택(또는 첫 radio)으로 포커스를 이동한다.
- radio는 네이티브 Tab/방향키 동작을 사용하고 라벨 조작 영역은 44px 이상이다.

## 8. CSP 및 Feature Flag OFF 보존

CSP는 수정하지 않았다. 다음 정책은 동일하게 유지된다.

`default-src 'none'`, `script-src 'self'`, `script-src-attr 'none'`, `style-src 'self'`, `style-src-attr 'none'`, `connect-src 'self'`, `worker-src 'none'`.

Inline style/event handler, `unsafe-inline`, `unsafe-eval`, wildcard 허용은 추가하지 않았다. OFF 응답은 변경된 정적 `index.html` 원본 bytes다. Evaluation route와 자산은 OFF에서 404이며 Hash 직접 입력으로 DOM이나 Fetch가 생성되지 않았다.

## 9. Live Monitoring R1 복구 보존

비활성 앱의 Live Script에는 상태 endpoint가 없으므로 기본 OFF, Evaluation OFF/ON 모두 정상 화면 로드 중 `/api/v1/live/status` 자동 요청이 0이었다. 활성 합성 Live Service를 쓰는 `npm run test:a11y --silent`의 25개 상태 흐름은 오류 없이 끝났고, 기존 status·SSE·Pause/Resume·Reconnect 회귀와 Python Live API/UI 테스트도 통과했다. API의 비활성 404 의미는 바꾸지 않았다.

## 10. TDD RED/GREEN

- RED: `tests/test_web_ui.py` 계약을 먼저 radio fieldset 구조, 각 고정 옵션, 기존 기본 선택 및 static select 부재를 요구하도록 변경했다. HTML 수정 전 focused test가 기존 `<select>` 의존을 지적하며 실패했다.
- GREEN: 정적 HTML과 JS를 radio group으로 바꾼 후 `tests/test_web_ui.py`, `tests/test_live_monitoring_ui.py`, 검토 상태 테스트가 통과했다.
- UI 색상 회귀 중 라디오 label이 밝은 배경/어두운 전경으로 렌더링되는 axe 대비 오류를 확인했다. 기존 테마 본문 색상으로 수정했고 입력 품질 브라우저 테스트의 axe 오류는 0이 됐다.
- 테스트의 사용자 동작은 select 선택에서 radio 선택으로 옮겼으며 assertions는 원래 값, count, 조합 결과 및 상태 전이를 계속 검증한다.

## 11. Chromium / WebKit 결과

로컬 macOS Playwright 브라우저: Chromium `156.0.8078.4`, WebKit `27.2`.

| Engine / Flag | 결과 |
|---|---|
| Chromium OFF | 오류/경고 0, Live status 요청 0, Evaluation 자산 직접 접근 404 |
| Chromium ON | 오류/경고 0, 페이지 오류 0, axe 위반 0, 외부 요청 0, 자동 POST 0 |
| WebKit OFF | 오류/경고 0, Live status 요청 0, Evaluation hash에서 DOM/Fetch 없음 |
| WebKit ON | 오류/경고 0, 페이지 오류 0, 외부 요청 0, 자동 POST 0, axe 0 |

Evaluation Viewer 매트릭스는 6개 viewport에서 overflow가 없었다. Chromium과 WebKit에서 200% reflow 및 axe를 실행해 각각 0 violation을 확인했다.

`node tests/ui_review_queue_36_13a.mjs` 및 `UI_BROWSER=webkit node tests/ui_review_queue_36_13a.mjs` 모두 `page_errors=0`, `console_errors=0`, axe 위반 0, 외부 요청 0으로 통과했다. 5개 반응형 크기와 200% 확대를 검사했다. WebKit/macOS의 기본 탭 이동 설정은 Tab으로 radio를 건너뛸 수 있으므로 해당 엔진 테스트는 native radio에 직접 focus한 뒤 Arrow 키 동작을 확인했다. 실제 Safari 키보드 수용 검수는 별도다.

`npm run test:a11y --silent`는 Chromium에서 기존 화면/Live 상태와 입력 품질, axe, 1920/1440/1280/1024/768/390/320px 및 200% reflow를 통과했다. 텍스트 입력 테스트는 `application` 요청을 실제로 제출하고, 격리 mock 응답으로 `ssh`, `access` 선택 값이 각각 JSON `source`로 전달됨을 확인했다. 기존 서버의 rate limit 의미는 테스트를 위해 변경하지 않았다.

## 12. 접근성 및 반응형

- `fieldset`/`legend`, 개별 radio label, 네이티브 방향키, 보이는 focus, 44px target을 사용한다.
- 필터 칩 제거와 Workflow 상태 갱신 후 포커스 복원을 검증했다.
- Chromium과 WebKit axe 0 violation.
- Browser 측정에서 가로 overflow 0, 긴 레이블 줄바꿈, 200% reflow를 확인했다.
- 실제 macOS Safari, 실제 iPhone/모바일, VoiceOver/Screen Reader 수동 검수는 `NOT_TESTED`다.

## 13. Evaluation 격리 / 무결성

ER-2D-C의 Chromium/WebKit OFF/ON 브라우저 테스트를 다시 실행했다. Snapshot file pin은 계속 `9f39bb5c814acf8627151681525c7d169e880feb8bd24dc106b5d87075559195`이고 고정 JSON은 수정하지 않았다. OFF에서 Evaluation route/자산 없음, ON에서 기존 Snapshot Validator와 30개 시나리오 검증을 유지했다. Network 요청은 same-origin으로 제한되어 외부 요청 0, 분석 POST 0이며 Stale 응답 취소 동작도 통과했다.

## 14. Full Regression

- 전체 `uv run pytest -q`: `3880 passed, 2 warnings` (R1 기준선 3880 passed).
- `uv run python -m app.evaluation`: 성공. Synthetic Boundary 79/79, Risk 70/70, Case 70/70, Linux Process 합성 평가 21/21.
- `uv lock --check`, `uv run python -m compileall -q app tests`, `git diff --check`: 성공.
- `npm run test:a11y --silent`: 성공. Chromium axe 0, 입력 품질 및 1920/1440/1280/1024/768/390/320px, 200% reflow.
- `tests/test_web_ui.py`, Live Monitoring 및 Review State focused pytest: `18 passed, 2 warnings`.
- 검토 큐 Chromium/WebKit: `page_errors=0`, `console_errors=0`, axe 0, 외부 요청 0, 5개 폭 및 200% reflow 통과.
- Workflow state security browser test: keyboard/filter, axe, responsive, privacy contract 통과; console/page errors 0.
- ER-2D-C Chromium/WebKit OFF/ON 4조합: 정상 console/page 오류 0, 외부 요청 0, 자동 POST 0, ON axe 0, 6 viewport와 200% reflow 통과.
- R1 root-cause diagnostic: WebKit `select=1`, `div=0`, CSP 변경 없음(예상 재현).

결과는 로컬 macOS이며 시작 Exact CI의 Ubuntu 결과와 구분한다.

`node tests/ui_workspace_navigation_28_4.mjs`는 현재 `<article>` 검토 카드 및 `#/investigations/...` 상세 경로와 맞지 않는 구형 `case-card > summary` 선택자를 사용해 통과하지 않았다. 따라서 해당 단일 구형 스크립트는 PASS로 기록하지 않는다. 현재 검토 큐 동작은 별도 Chromium/WebKit queue 테스트, 검토 상태/Workflow 테스트 및 전체 a11y suite로 검증했다.

## 15. Remaining Limitations / User Acceptance

- WebKit DevTools 최소 `<select>` root-cause fixture는 원인 재현용이므로 의도한 CSP 메시지 1건이 남는다. 정상 애플리케이션 흐름에는 native select가 없다. 구형 workspace-navigation 브라우저 스크립트의 카드 선택자는 갱신이 필요하다.
- WebKit `ui_review_queue`에서 플랫폼 기본 Tab 탐색 설정 차이를 고려해 직접 radio focus 후 Arrow 동작을 검사했다. 실제 Safari 보조기술 흐름은 검수자가 확인해야 한다.
- 실제 Safari/macOS, 실제 모바일, 수동 Screen Reader: `NOT_TESTED`.
- 사용자 수용: `ER_2E_USER_ACCEPTANCE_PENDING`.
- 독립 검토: `INDEPENDENT_HUMAN_REVIEW_PENDING`; Manual Approval `REQUIRED`; ER-1D Implementation `HOLD`.
- 실제 사용자 자료, 조직 운영, 자동 대응: `NO_GO`.

## 16. Final Decision

WebKit 오류 원인을 네이티브 선택 컨트롤로 좁힌 뒤 CSP를 그대로 두고 접근 가능한 radio group으로 교체했다. R1의 Live Status 복구와 OFF HTML 전달 경계, 기존 분석/검토 기능, Snapshot 및 Pin은 유지했다. 네 개 Engine/Flag 조합의 정상 흐름 console/page 오류는 0이고 Chromium/WebKit axe, 반응형, 검색·필터·정렬과 전체 Python 회귀도 통과했다.

**최종 판정: `ER_2E_R2_BROWSER_CONSOLE_RECOVERY_LOCAL_CONDITIONAL_GO`.** 이 판정은 자동 로컬 브라우저/회귀 검증 범위에 한정된다. 구형 `ui_workspace_navigation_28_4.mjs`는 현재 UI 구조와 맞지 않는 선택자 때문에 통과하지 않아 PASS로 보고하지 않는다. 이 별도 스크립트 외의 검토 큐/워크플로우 및 전체 a11y suite는 통과했다. 실제 Safari·모바일·Screen Reader 검수와 사용자 Acceptance는 미완료다.

다음 상태는 그대로 유지한다: `ER_2E_USER_ACCEPTANCE_PENDING`, `INDEPENDENT_HUMAN_REVIEW_PENDING`, `MANUAL_APPROVAL_REQUIRED`, `ER_1D_IMPLEMENTATION_HOLD`. 실제 사용자 자료·조직 운영·자동 대응은 `NO_GO`다.
