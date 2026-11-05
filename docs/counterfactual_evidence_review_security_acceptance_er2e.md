# ER-2E — Evaluation Viewer 보안·접근성 검수

## 1. Executive Summary

ER-2D-C의 브라우저 검증기와 격리 Viewer를 다시 검수했다. 자동 검증은 로컬 합성 데이터 범위에만 적용한다. 실제 Safari, 모바일 기기, Screen Reader와 사용자 수용은 별도 수동 확인이 필요하다.

## 2. Start SHA / Exact CI

- 시작 SHA: `37806d87959dc4827699ed03bd1f5bd23d8ff237`
- Exact CI: `42022697606`, event `push`, head SHA 일치, `completed / success`
- Locked Python 3.12 Regression, Linux 필수 검사, Restricted Report, Chromium/axe, Tracked-file 검사 성공
- Artifact: 0
- 시작 local/main/origin/GitHub main 일치, clean, ahead/behind `0/0`
- `v0.4.0` tag 유지, Release target `eecd6ee1cda0545e34b01c42e1a2163a899bcc27`

## 3. Evaluation Viewer Baseline

기준 Viewer는 30개 고정 합성 시나리오, Schema v1, 최대 128 KiB, Snapshot 전체 File Pin `9f39bb5c814acf8627151681525c7d169e880feb8bd24dc106b5d87075559195`를 사용한다. Corpus, Snapshot과 Pin은 이번 단계에서 수정하지 않았다.

## 4. Feature Flag OFF/ON

OFF는 기본값이며 `/`의 원본 HTML bytes와 기존 조사 화면을 보존한다. Chromium에서 Evaluation Hash를 직접 입력해도 Evaluation DOM·Navigation·Fetch가 없었고 Snapshot·Validator·Viewer JS·CSS 고정 경로는 404였다.

ON은 명시적인 loopback App Factory 설정으로 검사했다. 평가 Navigation·별도 DOM root·자산이 제공되고 Snapshot은 기존 HTTP Admission을 통과해야 했다. Restricted Linux Audit Mode와 동시 활성화는 기존 테스트에서 거부되는 계약을 재검증한다. 일반 `app.local_web`은 OFF를 유지한다.

## 5. HTTP Admission

ER-2D-B 회귀에서 Host/Port·중복 Host·Origin 및 `null`·Forwarded Host·Fetch Metadata·비 Loopback Peer·Query·GET Body·미지원 Method·임의 Path·고정 오류·CSP·no-store·nosniff·CORS 부재를 검사한다. 정상 응답만 고정 합성 bytes를 제공한다. Host/Origin 검사는 사용자 인증이 아니다.

## 6. Browser Validator

고정 same-origin URL에서 `credentials: omit`, `cache: no-store`, `redirect: error`를 사용한다. 스트림을 읽으며 128 KiB를 제한하고 UTF-8·HTTP 상태·MIME·출처·스키마·고정 inventory·closed enum·Reason Code·집계·Outcome 정합성을 검사한 뒤 전체 데이터를 한 번에 설치한다. Web Crypto가 없거나 secure context 조건이 성립하지 않으면 거부한다.

## 7. Snapshot Integrity

검증은 전체 응답의 신뢰된 File Pin과 Body의 `snapshot_sha256`을 분리한다. 두 Digest는 서명이나 외부 출처 인증이 아니다. 공격자가 JS와 자산을 함께 바꾸는 경우까지 보호한다고 주장하지 않는다.

## 8. Comparison Semantics

네 Outcome과 Detection 조합·`OUTCOME_*` 근거를 변조한 경우, 모순되거나 누락·혼합된 근거가 차단되는지 재검사한다. `INCOMPARABLE`, `UNDETERMINED`, Parser `REJECTED`, `EXECUTION_FAILED`를 음성 탐지 또는 안전으로 바꾸지 않는다. UI의 집계는 검증된 행을 바탕으로 만든다.

## 9. Snapshot Lifecycle

정상 재확인 중 이전 행·상세가 제거되는지, 실패 시 고정 오류와 빈 결과가 나타나는지, 화면 이탈 시 요청 취소와 세대 무효화가 적용되는지 검사한다. 시나리오에는 지연된 이전 요청 뒤 재진입하여 새 요청이 완료된 후 이전 요청 응답이 화면을 덮지 못하는 경쟁 검사가 포함된다.

## 10. Synthetic/Production Isolation

Evaluation은 별도 root·선택·검색 상태를 사용한다. Production Investigation Registry, Case Count, Risk, Checklist, Guidance, Timeline, Attack Chain, Report, Live Monitoring, SSE, Checkpoint 및 Publication에 연결하지 않는다. Browser 테스트에서 평가 흐름이 외부 요청·POST·조사 상태 변경을 유발하지 않는지 검사한다.

## 11. Privacy/XSS

고정 Snapshot 필드 allowlist와 Canary를 검사한다. 화면 렌더링은 `createElement`와 `textContent` 기반이다. HTML 문자열 삽입·동적 코드 실행·Browser Storage 사용을 금지한다. 잘못된 응답은 표시하거나 일부 행을 설치하지 않는다.

## 12. Keyboard/Focus

Chromium에서 Tab/Enter, Scenario 상세 진입, Escape, 상세를 닫은 뒤 원래 Scenario 버튼으로 Focus 복원을 검사했다. 화면을 나갈 때 Evaluation 결과를 폐기한다. 사용자 또는 보조기술을 사용한 수동 검증은 완료하지 않았다.

## 13. Accessibility

Chromium axe 데스크톱·모바일 검사에서 위반 0. 기존 조사 UI의 `npm run test:a11y`도 성공했다. Semantic table, 좁은 화면 description list, label, live status, 상태 텍스트와 visible focus를 포함한다. 자동 axe는 수동 Screen Reader·실사용 검수를 대체하지 않는다.

## 14. Responsive

격리 Chromium에서 1920, 1440, 1024, 768, 390, 320px 및 320px 200% 동등 reflow를 검사했다. 문서 가로 overflow 0, 잘림 0으로 종료했다. 1024px 이하에서 description list, 데스크톱에서 table이 보이는지도 검사했다. 이 결과는 해당 Chromium 테스트 프로파일에 한정된다.

## 15. Chromium

사용 명령: `node tests/ui_counterfactual_evidence_review_er2d_c.mjs`. 고정 합성 Snapshot 30행, summary, 검색·필터·정렬, radio filter 키보드, 상세, invalid·stale·지연 응답 경계를 검사했다. ON Viewer 흐름의 외부 요청 0, 자동 POST 0, page/new console error 0, axe 위반 0. 기본 OFF 화면에서는 기존 `/api/v1/live/status`가 없는 `create_app()` 환경의 404 console 진단 2건을 확인했다. OFF HTML을 바꾸지 않고 이 기존 진단은 Viewer 기능과 구분해 기록한다.

## 16. WebKit

Playwright WebKit이 로컬에 설치되어 자동 실행했다. 초기 Viewer 로드, 검증, 분포, 검색, radio filter, 키보드와 6개 폭의 흐름을 확인했다. 변조 본문 Route interception은 WebKit이 Content-Length가 맞지 않는 mock 응답을 네트워크 오류로 처리하므로 `UNAVAILABLE` 상태에서 결과가 숨겨지는 것을 검사했다. Chromium은 동일한 경우 외에 invalid body와 axe도 검사했다. WebKit에서는 평가 화면이 동적 `<select>`를 만들 때 기존 CSP 아래 추가 콘솔 경고 12건이 발생하는 것을 재현했다(RED). 동적 `<select>`를 접근 가능한 native radio group으로 바꾼 뒤 Viewer 진입에서 신규 경고가 0건으로 줄었다. WebKit 세션에는 원래 조사 화면에서 발생하던 `style-src` CSP 경고 6건이 남았다. 총 콘솔 경고가 0이라고 주장하지 않는다. WebKit axe 및 200% 확대는 `NOT_TESTED_CSP`; 이 테스트 주입은 CSP에 의해 차단된다. 실제 Safari 검수도 아니다.

## 17. Safari Manual Status

`NOT_TESTED` — 실제 macOS Safari에서 사람이 직접 탐색하지 않았다.

## 18. Mobile Manual Status

`NOT_TESTED` — 실제 iPhone/iPad 및 모바일 Safari 기기 검수는 수행하지 않았다.

## 19. Screen Reader Manual Status

`NOT_TESTED` — VoiceOver 또는 다른 Screen Reader로 수동 탐색하지 않았다.

## 20. TDD RED/GREEN

기존 Viewer에서 사람이 읽을 수 있는 축약 문구만 보여주고 명시된 governance code를 노출하지 않는 문제를 browser assertion으로 재현해 RED를 확인했다. Summary에 `INDEPENDENT_HUMAN_REVIEW_PENDING` 및 `NOT_APPROVED`와 설명 문구를 함께 표시하여 GREEN으로 수정했다. WebKit에서 Evaluation UI가 추가 CSP console 경고를 내던 동적 `<select>` 구현도 재현 후 radio group으로 바꾸어 Evaluation 진입에서 새 경고가 없음을 확인했다. State semantics는 바꾸지 않았다.

## 21. Defect and Repair Log

| 발견 사항 | 영향 | 수정 | 회귀 근거 |
|---|---|---|---|
| 검토 대기 및 운영 미승인 상태 코드가 UI에 표시되지 않음 | 사용자가 상세 상태 계약을 확인하기 어려움 | 기존 한국어 설명 옆에 고정 상태 코드를 표시 | Chromium browser assertion |
| 이전 단계에서 320px·200% reflow 긴 분포 행 overflow 발견 | 좁은 화면에서 내용이 viewport 밖으로 나감 | 평가 CSS에 줄바꿈 처리 추가 | Chromium 6 viewport/200% reflow |
| Viewer의 동적 `<select>`가 WebKit에서 추가 CSP console 경고 12건 유발 | Browser console 진단이 늘고 필터 UI가 해당 엔진에서 CSP와 충돌 | `<fieldset>`/native radio group으로 필터 제공 | WebKit 신규 console 12 → 0; Chromium axe |

탐지 정책, Corpus, Snapshot 및 Pin 변경은 없었다.

## 22. Full Regression

- 시작 기준 전체 pytest: 3877 passed, 2 warnings (macOS)
- ER-2E 변경 후 전체 pytest: 3879 passed, 2 warnings (macOS)
- `uv run python -m app.evaluation`: 성공; synthetic boundary 79/79, risk 70/70, case 70/70, Linux process 21/21. 모두 기존 합성 평가 범위다.
- `uv lock --check`, `uv run python -m compileall -q app tests`, `git diff --check`: 성공
- 기존 `npm run test:a11y --silent`: 성공
- Browser: Chromium ON 0 console/page errors·0 axe·0 outbound·0 POST. OFF hash/fetch 검사는 성공하나 기존 `/api/v1/live/status` 404 console 2건. WebKit ON에서는 Viewer가 추가하는 console/page error 0, 시작 페이지에서 기존 CSP console 6건; axe와 200% 확대는 NOT_TESTED.
- GitHub Exact CI는 시작 SHA에서 성공. 신규 로컬 커밋은 Push 전이므로 해당 커밋의 GitHub CI는 아직 없음.

## 23. User Acceptance Checklist

별도 [사용자 수용 체크리스트](counterfactual_evidence_review_user_acceptance_er2e.md)를 제공한다. 각 항목은 기본 `NOT_TESTED`이며 사람이 수행한 실제 확인만 기록해야 한다.

## 24. Rollback

기본 Feature Flag OFF에서는 Evaluation Route·자산·Navigation·DOM·Fetch가 없다. Chromium OFF 검사는 hash 입력과 직접 자산 요청을 확인한다. 기존 일반 Launcher의 OFF 기본값을 유지한다.

## 25. Remaining Security Limitations

Safari·실제 기기·수동 보조기술 검수는 남아 있다. Digest는 서명이 아니며 로컬 동등 권한 공격자를 막지 않는다. 자동화 테스트는 사용자 이해도나 운영 탐지 정확도를 입증하지 않는다.

## 26. Human Review Gate

`INDEPENDENT_HUMAN_REVIEW_PENDING`, `MANUAL_APPROVAL_REQUIRED`, `ER_1D_IMPLEMENTATION_HOLD` 유지. 실제 사용자 자료·조직 운영·자동 대응은 `NO_GO`다.

## 27. Final Decision

자동 보안 검증과 전체 회귀가 통과하면 `ER_2E_AUTOMATED_SECURITY_LOCAL_CONDITIONAL_GO`를 부여한다. 실제 Safari·모바일·Screen Reader 및 사용자 검수는 별도로 `ER_2E_USER_ACCEPTANCE_PENDING`으로 둔다. 해결되지 않은 보안 실패가 있으면 `ER_2E_SECURITY_HOLD`다.
