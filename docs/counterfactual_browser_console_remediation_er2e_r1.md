# ER-2E-R1 — 기존 브라우저 콘솔 오류 복구 기록

## 1. Executive Summary

이 작업은 ER-2E에서 발견된 두 정상 화면 오류를 분리 재현했다. Chromium의 비활성 Live Monitoring 상태 조회 404는 서버가 Live Service 설정을 알고 있는 경계를 사용해 제거했다. `/api/v1/live/status`의 404 계약은 유지했다.

WebKit의 CSP 메시지 6건은 테스트 도구나 Evaluation Viewer가 아니라 기본 HTML의 네이티브 `<select>` 요소만으로 재현됐다. 현재 `style-src 'self'; style-src-attr 'none'` 정책, Feature Flag OFF HTML 바이트 동일성, 이번 단계의 제한된 변경 범위를 모두 보존하면서 해당 네이티브 컨트롤 동작만 제거할 방법은 확인하지 못했다. CSP를 완화하거나 콘솔을 필터링하지 않았고, 전체 콘솔 오류 0건 조건은 충족되지 않았다.

**최종 판정: `ER_2E_R1_SECURITY_HOLD`**. Chromium OFF의 Live 404는 복구했지만 WebKit 기본 페이지의 6건이 남아 있다.

## 2. Start SHA / Exact CI

- 시작 SHA: `242dc4ae91e8a43429ef7f89098db11b8ac7bf27`
- Exact CI: `42032167826`, `push / completed / success`, head SHA 일치
- Locked Python 3.12, 필수 Linux 검사, Restricted Report, Chromium/axe, tracked-file 검사: 성공
- Artifact: 0
- Local/main/origin/GitHub main: 동일 SHA, ahead/behind `0/0`, 시작 트리 clean
- `v0.4.0` 유지, Release target: `eecd6ee1cda0545e34b01c42e1a2163a899bcc27`
- 로컬 브라우저: Chromium `156.0.8078.4`, WebKit `27.2`; macOS 로컬 실행 결과

## 3. Baseline Errors

수정 전 `node tests/ui_counterfactual_evidence_review_er2d_c.mjs` 재현:

| Browser / Flag | Console 및 응답 관측 |
|---|---|
| Chromium OFF | `GET /api/v1/live/status` 404와 이에 따른 console error 1건 (수집기에서는 HTTP 404와 console을 각각 기록해 총 2개 항목) |
| Chromium ON | 초기 로드와 Viewer 흐름에서 오류 0 |
| WebKit OFF | 네이티브 select 관련 CSP console error 6건, Live 404 진단 1건 및 HTTP 404 항목 |
| WebKit ON | 기본 HTML 로드 시 CSP console error 6건; Viewer 진입에서 추가 오류 0 |

WebKit 기본 페이지 6건은 `frontend/index.html` 275행의 로그 종류 select, 검토 큐의 정렬·위험도·역할·우선순위·검토 상태 select에 각각 대응했다. Browser `pageerror`는 없었다. axe가 실행되기 전에도 6건이 있었다.

## 4. Browser 분리 실험 및 Root Cause

Playwright WebKit `27.2`에서 실제 앱의 axe 미실행 기본 페이지가 6건을 재현했다. axe 실행 전후 오류 수는 `6 → 6`이었고 axe 위반 수는 0이었다. Evaluation ON은 Viewer로 이동하기 전 6건이 있었으며, Viewer 진입이 오류를 추가하지 않았다.

격리한 Loopback 최소 문서에서 동일 CSP를 적용했다. 빈 문서 `0`, `<div>` `0`, 네이티브 `<select>` `1` CSP 오류였다. 자체 CSS를 제공해 `appearance:none` 및 `-webkit-appearance:none`을 지정해도 오류 1건이 남았다. 따라서 애플리케이션에 `style` 속성이나 동적 `.style` 변경이 없고, axe 주입 전부터 재현되며, WebKit의 네이티브 select 내부 스타일 처리와 `style-src-attr 'none'`의 충돌로 판단했다. 이는 CSP 위반이 페이지 작성 코드의 인라인 스타일을 허용했다는 뜻이 아니라 WebKit이 네이티브 컨트롤을 처리하며 보고하는 정책 메시지다.

### Root-cause 실험표

| 실험 | 결과 |
|---|---|
| A1 기본 페이지, axe 미실행 | WebKit 6건, Chromium 0건 |
| A2 WebKit 기본 페이지에 axe 실행 | 실행 전 6, 실행 후 6; axe 0 violation |
| A3 Evaluation ON 진입 전후 | 기존 6건, Evaluation에서 추가 0건 |
| A4 동일 CSP 최소 페이지 | 빈 문서/`div` 0, `<select>` 1 |
| A5 동일 CSP + 외부 `appearance:none` | `<select>` 오류 1 유지 |

검증되지 않은 CSP 변경, 메시지 무시, 테스트 도구 오류로의 재분류는 하지 않았다.

## 5. Security Contracts

- CSP 값은 변경하지 않았다.
- Feature Flag OFF의 `/` 응답 body는 원본 `frontend/index.html` bytes와 동일함을 기존 회귀 테스트로 유지했다.
- Evaluation Viewer HTML/JS/CSS, Snapshot 및 Trusted Pin을 변경하지 않았다.
- Live Monitoring 비활성 404의 상태 코드와 `LIVE_MONITORING_NOT_ENABLED` 의미를 유지했다.
- Production Parser/Detector, Risk/Correlation, Investigation API, Corpus/Label은 변경하지 않았다.

## 6. Live Status 404 Root Cause와 대안

`frontend/live-monitoring.js`의 끝에서 `refreshStatus()`를 무조건 호출했고, 비활성 기본 App은 해당 endpoint에 `LIVE_MONITORING_NOT_ENABLED` 404를 반환했다. Playwright는 정상 페이지 로드 중 HTTP 오류 응답과 브라우저의 “Failed to load resource” 오류를 관측했다.

| 대안 | 평가 |
|---|---|
| A. 사용자가 Live 영역에 진입할 때만 조회 | 메뉴는 서비스 상태 확인 뒤에만 노출되는 기존 계약이다. 진입을 가능하게 하려면 Navigation/상태 흐름 변경이 필요하고, 비활성 서버에서 사용자가 열면 404가 다시 발생할 수 있다. |
| B. App 설정에 따른 고정 JS Asset 제공 | 선택. 서버는 이미 `live_monitoring_service` 유무를 안다. HTML body와 API 의미를 유지하며, 서비스 미설정 시 같은 고정 Route에서 실행 가능한 빈 주석 스크립트를 제공한다. 추가 협상 요청이 없다. 설정된 서비스에는 기존 고정 JS bytes를 제공한다. |
| C. 404를 성공 응답으로 바꾸거나 클라이언트에서 삼킴 | 거부. API 상태 의미를 흐리거나 요청 자체를 남긴다. |

## 7. Selected Fix

`app/api.py`에서 Asset Handler를 App 인스턴스의 `live_monitoring_service is not None`에 결속했다. `app/web_ui.py`는 엄격한 Boolean 설정을 받아 비활성 시 고정 no-op JavaScript 응답, 활성 시 기존 안전한 고정 Asset을 반환한다. 이는 사용자 입력 기반 동적 코드나 파일 선택을 만들지 않는다.

활성 서비스가 없는 경우 `/api/v1/live/status`는 직접 호출 시 계속 404이며, 브라우저 기본 로드에서는 이 endpoint 요청이 발생하지 않는다. 활성 Live Monitoring의 실제 script 응답 및 status/SSE 계약은 기존 Live 테스트에서 검증한다.

## 8. TDD RED/GREEN

- RED: 기존 브라우저 테스트에 정상 화면의 console warning/error, page error, HTTP 404, request failure 및 Live status 요청을 모두 수집하고, 정상 흐름 오류 0을 요구했다. 수정 전 Chromium OFF는 404/console 오류를 재현했다. WebKit OFF는 여섯 CSP 위치를 재현했다.
- GREEN: 비활성 Asset은 상태 조회 URL을 포함하지 않고 Chromium OFF 정상 로드에서 status fetch 0, HTTP/console/page 오류 0을 확인했다. 활성 설정은 기존 Live Monitoring JavaScript bytes를 그대로 반환한다.
- WebKit 전체 기준은 GREEN이 아니다. 미해결 6건을 남겨 최종 Gate는 HOLD다.

## 9. HTTP / Live Regression

`tests/test_live_monitoring_ui.py`는 비활성 no-op Asset, API 404 의미 보존, 활성 서비스의 기존 JS bytes 반환을 확인한다. `tests/test_live_http.py`의 기존 활성/비활성 status, SSE 및 Loopback 테스트도 재실행했다.

기존 `npm run test:a11y --silent`은 정적 `app.api:app`(Live Service 없음)에 Live Status를 모의 응답으로 주입해 Live UI를 검사하던 하네스 불일치가 있었다. 이후 하네스를 임시 합성 Live Service가 구성된 App Factory로 실행하고, 비활성 상태만 격리된 mock 404로 분리했다. 25개 상태 시나리오에서 콘솔 진단이 비어 있고, 외부 요청은 0이었다. 이 하네스 변경은 앱 보안 검사를 느슨하게 하지 않으며 비활성/활성 서비스 테스트를 실제 서버 구성과 일치시킨다.

## 10. Feature Flag OFF Preservation

새 Route, HTML variant, CSP, Snapshot 또는 Viewer 자산을 추가하지 않았다. 기본 `/` body의 bytes 동일성, Evaluation DOM/route 부재, 기존 조사 화면 유지 계약을 보존했다. 비활성 Live JS Route는 200 고정 JavaScript 응답이지만 상태 API는 계속 404다.

## 11. Browser Results

| Browser / Flag | 수정 후 정상 흐름 결과 |
|---|---|
| Chromium OFF | Console warning/error 0, Page Error 0, Live status 요청 0 |
| Chromium ON | Viewer 흐름 Console warning/error 0, Page Error 0, axe violation 0, 외부 요청 0, 자동 POST 0 |
| WebKit OFF | CSP Console error 6, Page Error 0, Live status 요청 0 |
| WebKit ON | Viewer 전체 흐름 후에도 CSP Console error 6 (초기 6, 신규 0), Page Error 0, 외부 요청 0, 자동 POST 0 |

WebKit의 axe 격리 실험에서 axe는 0 violation이었고 추가 콘솔 오류는 없었다. WebKit 전체 정상-flow 오류 0 조건은 충족하지 않는다. Chromium/WebKit Viewer 지연 응답 재검사에서는 이전 요청 취소 1건을 별도 Request Failure 상태로 수집했다(`net::ERR_ABORTED` 또는 WebKit `cancelled`). 이는 테스트 중 실제 취소 경계와 일치하며 콘솔/Page Error나 HTTP 실패로 처리하지 않는다. 다른 요청 실패는 허용하지 않는다.

## 12. Accessibility / Responsive

R1은 화면 컨트롤을 재구성하지 않아 기존 접근성 의미를 변경하지 않았다. 기존 Chromium axe 및 responsive 회귀를 다시 실행한다. WebKit의 6개 CSP 오류가 남으므로 전 브라우저 콘솔 Gate는 실패다. 실제 Safari, 실제 모바일, VoiceOver/Screen Reader는 별도 사용자 검수 전까지 `NOT_TESTED`다.

## 13. Full Regression

시작 기준선 `uv run pytest -q`: `3879 passed, 2 warnings`; R1 종료 `uv run pytest -q`: `3880 passed, 2 warnings` (macOS). Evaluation Runner 성공: Synthetic Boundary `79/79`, Risk `70/70`, Case `70/70`, Linux Process 합성 분류 `21/21`. `uv lock --check`, `uv run python -m compileall -q app tests`, `git diff --check`, `npm run test:a11y --silent` 성공. Chromium OFF/ON browser checks 성공. WebKit OFF/ON browser acceptance는 각기 기본 문서의 CSP 오류 6건 때문에 실패한다. WebKit 최소 원인 진단은 예상 결과를 확인해 성공 종료했다. 로컬 결과는 시작 SHA의 GitHub Ubuntu CI와 별개다.

## 14. Remaining Limitations

현재 요구사항은 WebKit 네이티브 select CSP 로그 0건을 요구하면서 동시에 CSP 보존과 기본 HTML body bytes 동일성을 요구한다. 최소 페이지 실험으로 이 조합에서 select 자체가 오류를 내고, CSS 외부화/`appearance:none`만으로 제거되지 않음을 확인했다. 허용된 파일 범위에서 HTML 컨트롤을 바꾸지 않고는 이 로그를 제거할 수 없어 보안 정책을 낮추는 선택을 하지 않았다. 이를 해결하려면 새로운 승인 Gate에서 HTML/control 계약과 body-byte 불변 조건을 함께 재검토해야 한다.

## 15. User Acceptance / Governance

- 실제 Safari: `NOT_TESTED`
- 실제 모바일: `NOT_TESTED`
- 수동 Screen Reader: `NOT_TESTED`
- 사용자 Acceptance: `ER_2E_USER_ACCEPTANCE_PENDING`
- 독립 검토: `INDEPENDENT_HUMAN_REVIEW_PENDING`
- Manual Approval: `MANUAL_APPROVAL_REQUIRED`
- ER-1D 구현: `ER_1D_IMPLEMENTATION_HOLD`
- 실제 사용자 자료 / 조직 운영 / 자동 대응: `NO_GO`

## 16. Final Decision

Live Status 404 자동 요청은 App 구성에 따라 비활성화하고, API의 기존 404 의미와 활성 Monitoring을 보존했다. 그러나 WebKit 정상 화면에 남은 native-select CSP 메시지 6건 때문에 전체 Console/Page Error 0 조건은 실패한다.

**`ER_2E_R1_SECURITY_HOLD`** — 실제 페이지 콘솔을 숨기거나 CSP를 완화하지 않았다. WebKit 호환 대안과 Feature OFF body-byte 계약을 별도 Gate에서 함께 결정해야 한다.

### ER-2E-R2 후속 기록

R2에서 승인된 정적 HTML 컨트롤 변경으로 body-byte 동일성 요구를 현재 커밋의 원본 `frontend/index.html` 제공 계약과 구분했다. 기존 6개 native select와 조사 상세에서 재현된 동적 select를 accessible radio group으로 옮겨 CSP를 유지한 WebKit 정상 화면 오류를 제거했다. R1 Live Status 수정은 그대로 보존했다. 원래 R1 HOLD 판정은 당시 증거 기록으로 유지하며, 후속 검증 결과는 [ER-2E-R2 복구 기록](counterfactual_webkit_csp_control_migration_er2e_r2.md)을 참조한다.
