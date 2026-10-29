# Phase 36.7B — Checklist UI 상태별 사용자 재검수

## 시작 Gate

- 기준 SHA: `e145cebb5b424f49f4a368b124c8e20a9a1c15f2`
- 시작 당시 branch: `main`; `HEAD`, local `main`, `origin/main`, GitHub `main`이 모두 기준 SHA와 일치했다.
- 시작 당시 working tree: clean; `origin/main...HEAD` ahead/behind `0/0`.
- GitHub Actions run `40869511998`: 기준 SHA, `push / completed / success`.
- Artifact: 0개.
- Locked Python 설치, 전체 pytest, Linux TCP Syslog smoke/reliability/management, JSONL, restricted report, Chromium/axe, tracked-file invariant 단계: 모두 성공.
- `v0.4.0` tag와 Release target은 `eecd6ee1cda0545e34b01c42e1a2163a899bcc27`로 유지됐다.

## 검수 환경과 자료

- 실제 production UI/API를 `uv run python -m app.local_web --port 18765 --no-browser`로 실행했다. 서버는 `127.0.0.1`에만 바인딩했다.
- HOME과 Chromium은 임시 검수 환경을 사용했다. 브라우저는 Chromium, device scale factor 1, desktop 기본 zoom 100%였고 CSS viewport는 1440×1100, 390×844, 320×568이었다.
- 합성 sample API에서 얻은 기존 예시만 사용했다. 실제 사용자 로그, 자격 증명, 조직 자료, 운영 checkpoint, 외부 API/LLM은 사용하지 않았다.
- 첫 desktop available 검수에서는 checklist POST를 실제 loopback API로 보냈다. 실제 응답은 HTTP 200, `investigation-checklist/v2`, `status=available`, 4개 steps였고 UI 상태도 `available`이었다.
- 나머지 refused/unavailable/stale 및 주입된 렌더 오류·재시도 화면은 브라우저 테스트 계층에서만 만든 `TEST_ONLY_MOCK`이다. 이는 서버 동작이나 실제 API 상태를 증명하지 않는다. 390/320px의 available 화면도 실제 available 응답 형식을 이용한 테스트 전용 재생(Mock)이다.
- UI 캡처는 저장소 바깥 `/tmp/phase-36-7b-review.dJU22A/captures/`에 저장했다. 캡처는 합성 데이터만 포함하며 repository에 추가하지 않았다. 캡처별 viewport, source, HTTP/response/UI status는 `capture-manifest.json`과 `capture-13.json`에 기록했다.

### 검수 캡처

| 번호 | 화면 | viewport | 데이터 출처 및 응답 | UI 상태 | 캡처 파일 |
|---:|---|---|---|---|---|
| 1 | Desktop available 성공 | 1440×1100 | 실제 loopback API, HTTP 200 `available` | `available` | `01-desktop-available-1440.png` |
| 2 | Desktop 작업 상세 선택 | 1440×1100 | 실제 응답 | `available` | `02-desktop-selected-task-1440.png` |
| 3 | Desktop citation 펼침 | 1440×1100 | 실제 응답 | `available` | `03-desktop-citation-expanded-1440.png` |
| 4 | Desktop refused | 1440×1100 | `TEST_ONLY_MOCK`, HTTP 200 `refused` | `refused` | `04-desktop-refused-TEST_ONLY_MOCK.png` |
| 5 | Desktop unavailable | 1440×1100 | `TEST_ONLY_MOCK`, HTTP 503 `UNAVAILABLE` | `unavailable` | `05-desktop-unavailable-TEST_ONLY_MOCK.png` |
| 6 | Desktop stale | 1440×1100 | `TEST_ONLY_MOCK`, HTTP 404 `NOT_FOUND` | `stale` | `06-desktop-stale-TEST_ONLY_MOCK.png` |
| 7 | Desktop 렌더 오류 | 1440×1100 | `TEST_ONLY_MOCK`, 유효한 available 뒤 테스트 전용 렌더 예외 | `error` | `07-desktop-render-failure-TEST_ONLY_MOCK.png` |
| 8 | Desktop 재시도 성공 | 1440×1100 | `TEST_ONLY_MOCK`, 명시 재시도 뒤 HTTP 200 `available` | `available` | `08-desktop-retry-success-TEST_ONLY_MOCK.png` |
| 9 | Mobile available | 390×844 | `TEST_ONLY_MOCK` (실제 응답 형식 재생) | `available` | `09-mobile-390-available-TEST_ONLY_MOCK.png` |
| 10 | Mobile 작업 상세 선택 | 390×844 | `TEST_ONLY_MOCK` (실제 응답 형식 재생) | `available` | `10-mobile-390-task-detail-TEST_ONLY_MOCK.png` |
| 11 | Mobile unavailable | 390×844 | `TEST_ONLY_MOCK`, HTTP 503 `UNAVAILABLE` | `unavailable` | `11-mobile-390-unavailable-TEST_ONLY_MOCK.png` |
| 12 | 320px 렌더 오류 | 320×568 | `TEST_ONLY_MOCK`, 테스트 전용 렌더 예외 | `error` | `12-mobile-320-render-failure-TEST_ONLY_MOCK.png` |
| 13 | 320px 작업 상세·citation | 320×568 | `TEST_ONLY_MOCK`, available 응답 모양 | `available` | `13-mobile-320-task-citation-TEST_ONLY_MOCK.png` |

## 자동 검증 결과 — 사용자 응답과 별도 기록

- `npm run test:a11y --silent`: 기존 상태와 checklist/workspace 상태 24개 완료, axe 위반 0, 외부 요청 0.
- 1440/1024/768/390/320px와 320px root font 32px의 200% equivalent reflow 검사에서 document/body/panel 수평 overflow, clipping, target size/gap 실패는 0이었다. 이는 Chromium의 root-font 기반 자동 검사이며 native browser zoom, Safari 또는 실제 기기 검증이 아니다.
- Checklist 상태 자동 계약: 실제 `available`, 테스트 전용 렌더 오류, refused, unavailable, stale, timeout, rate limit, 네트워크 오류, 잘못된 응답/citation, 재시도, 반복 클릭 차단 및 사례 간 늦은 응답 격리가 통과했다.
- 실제 available 응답은 명시적 클릭 뒤 POST 1회, 작업 선택 4개, 상태 `available`, 오류 문구 없음, 검증된 SSH role 및 `review_soon` 표시를 보였다.
- 주입한 렌더 예외는 상태 `error`, 부분 작업 0개, role `역할 미확인`, priority `확인 순서 미정`으로 끝났다. 내부 예외는 UI에 나타나지 않았고 재시도는 별도 명시 클릭으로만 발생했다.
- 검사 브라우저 요청은 loopback 외 0건이었다. 첫 캡처 실행에서는 sample URL 요청 9회 중 최초 요청만 실제 API로 전달하고 같은 합성 응답을 8회 테스트 계층에서 재생했다. checklist URL 요청 10회 중 실제 available 요청은 1회였고 나머지는 테스트 Mock이었다. 추가 320px 캡처는 별도 실제 sample API 요청 1회와 checklist Mock 1회를 사용했다. 자동 tab/hover/focus 요청은 없었다.
- Phase 36.7A 자동 검증은 이전 기술 커밋의 결과다. 이번 검수의 `npm run test:a11y` 출력은 별도 실행 증거이며 사용자 응답을 대체하지 않는다.

## 이번 기록의 로컬 검증

- `uv run pytest -q`: `3101 passed`, 기존 dependency deprecation warning 2개.
- `npm run test:a11y --silent`: `states=24`, axe 위반 0, 외부 요청 0.
- `uv sync --locked --dev` 및 `uv lock --check`: 통과.
- `git diff --check`: 통과.
- `node --check frontend/app.js`, `node --check tests/ui_accessibility_axe_pilot_28_1.mjs`, `uv run python -m compileall -q app tests`: 통과.
- API/frontend/분석 코드, package 및 lockfile 변경: 0. 기존 36.6G 사용자 기록과 36.7A 기술 기록도 수정하지 않았다.
- Linux 전용 acceptance는 이번 macOS 로컬 실행에서 재실행하지 않았다. 이는 기준 SHA의 성공 Ubuntu CI와 별개로 `NOT_TESTED`다.

## 사용자 검수 — 8개 응답 원문

질문은 한 항목씩 실제 캡처를 보여준 뒤 진행했다. 사용자는 각 질문에 `PASS`로 답했다. 질문 사이의 사이트 링크 요청은 검수 응답으로 집계하지 않았다.

| 항목 | 화면/상태 | 최초 사용자 응답 | FAIL 이유 | 수정·재검수 | 최종 사용자 응답 |
|---|---|---|---|---|---|
| 1/8 Available 정상 표시 | Desktop 1440, 실제 API available | `PASS` | — | 수정 없음 | `PASS` |
| 2/8 작업 상세와 Citation | Desktop 1440, 실제 API available 및 citation 펼침 | `PASS` | — | 수정 없음 | `PASS` |
| 3/8 Refused 상태 | Desktop 1440, `TEST_ONLY_MOCK` | `PASS` | — | 수정 없음 | `PASS` |
| 4/8 Unavailable 상태 | Desktop 1440, `TEST_ONLY_MOCK` | `PASS` | — | 수정 없음 | `PASS` |
| 5/8 Stale 상태 | Desktop 1440, `TEST_ONLY_MOCK` | `PASS` | — | 수정 없음 | `PASS` |
| 6/8 렌더링 실패 및 복구 | Desktop 1440, 예외 및 재시도 `TEST_ONLY_MOCK` | `PASS` | — | 수정 없음 | `PASS` |
| 7/8 390px 모바일 상태 표시 | Chromium 390×844, Mock available/unavailable | `PASS` | — | 수정 없음 | `PASS` |
| 8/8 320px 최소 너비 | Chromium 320×568, Mock task/citation/error | `PASS` | — | 수정 없음 | `PASS` |

## Phase 36.7A 불일치 후속 확인

36.7A에서 수정한 원인은 checklist 렌더 경로에서 citation renderer의 lexical scope 오류가 발생해 유효한 응답의 일부 DOM이 반영된 뒤 오류 UI가 함께 보이던 것이었다. 이번 검수에서 실제 API available 응답은 작업 목록·성공 안내·`available` 상태로 일관되게 나타났다. 별도 테스트 전용 예외에서는 부분 결과 없이 오류 안내만 나타났으며, 명시 재시도 후 available 화면이 복구됐다.

따라서 관찰한 available/error 불일치는 이번 자동 검증 및 사용자 화면 검수 범위에서 재현되지 않았다. API/schema, checklist v2, 기존 projection, 분석 결과, role provenance, risk 및 review priority 의미는 변경하지 않았다. 기술 안정화 확인과 사용자 수용은 서로 다른 결과로 기록한다.

## 판정 및 경계

- Desktop: 사용자 6/6 PASS.
- Mobile Chromium CSS viewport: 사용자 2/2 PASS.
- 판정: `PHASE_36_7B_CHECKLIST_UI_USER_ACCEPTED` — 검수 당시 synthetic production UI와 위 Chromium 화면에 한정.
- `refused/unavailable/stale`은 실제 서버 응답 수용이 아니라 각각 표시된 `TEST_ONLY_MOCK` 화면의 사용자 평가다. 실제 API 응답별 운영 검증으로 확대하지 않는다.
- 실제 모바일 기기, Safari, VoiceOver: `NOT_TESTED`.
- Phase 36.6G 원본 사용자 수용 기록과 Phase 36.7A 기술 기록은 변경하지 않았다. `KEEP_LEGACY` renderer와 rollback switch도 유지한다.
- 실무 운영 적합성은 평가하지 않았다. 실제 사용자 자료·조직 운영·자동 대응은 `NO_GO`, 모델 기반 AI는 `NOT_TESTED`, Vector/VM은 `USER_ACTION_REQUIRED / ISOLATION_BLOCKED`다.
- 분석 재실행, checkpoint/publication/SSE 변경, 외부 요청, dependency/API/schema 변경은 없었다.
