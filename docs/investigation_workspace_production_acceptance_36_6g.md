# Phase 36.6G — Production 조사 작업공간 사용자 수용 검수 준비

## 시작 gate

- 기준 SHA: `073576b4b8f3e87cfffe284dedf21b630f5d6cf6`
- branch / HEAD / local `main` / `origin/main` / GitHub `main`: 모두 기준 SHA
- `origin/main...HEAD`: behind 0 / ahead 0
- GitHub Actions run `40844445317`: `push / completed / success`
- 필수 Linux 회귀, 전체 pytest, TCP Syslog, JSONL, restricted report, Chromium·axe, tracked-file invariant: 성공
- artifact: 0개
- `v0.4.0` peeled tag 및 Release target: `eecd6ee1cda0545e34b01c42e1a2163a899bcc27`

## 검수 환경

- 실제 production frontend와 API를 `uv run python -m app.local_web --port 18765 --no-browser`로 실행했다.
- 서버는 `127.0.0.1:18765`에만 바인딩됐다. 격리 HOME은 `/tmp/iw36g-home-wtvj6ava`였고, 검수 후 정리했다.
- Playwright Chromium headless, device scale factor 1, CSS viewport 1440×900 / 390×844 / 320×568를 사용했다. desktop 캡처는 기본 zoom 100%다.
- 입력은 제품의 기존 합성 sample API뿐이다. 실제 사용자 로그·credential·기존 checkpoint·production 설정은 사용하지 않았다.
- 브라우저 요청은 `http://127.0.0.1:18765`에만 전송됐다. 화면 캡처 후 서버와 브라우저를 종료했다.
- 캡처는 저장소 밖 `/tmp/iw36g-captures/`에 있다. PNG를 repository에 추가하지 않았다.

## 캡처 목록

Desktop 1440px:

- `01-desktop-dashboard-1440.png` — Dashboard 전체
- `02-desktop-card-crop-1440.png` — 첫 검토 건 카드 확대
- `03-desktop-overview-1440.png` — 상세 개요
- `04-desktop-timeline-1440.png` — 활동 흐름
- `05-desktop-tasks-before-1440.png` — 작업 요청 전
- `06-desktop-tasks-response-1440.png` 및 `06-desktop-tasks-available-verified-1440.png` — 명시 요청 응답 뒤 화면
- `07-desktop-task-selected-1440.png` — 선택 작업 상세
- `08-desktop-evidence-1440.png` — 근거와 한계
- `09-desktop-citation-disclosure-1440.png` — citation disclosure
- `10-desktop-guidance-result-1440.png` — 별도 명시 요청 후 guidance
- `11-desktop-checklist-other-case-1440.png` — 두 번째 검토 건 요청 상태
- `12-desktop-return-list-1440.png` — 목록 복귀

Mobile CSS viewport:

- 390×844: `mobile-390-dashboard.png`, `mobile-390-nav-open.png`, `mobile-390-overview.png`, `mobile-390-timeline.png`, `mobile-390-tasks.png`, `mobile-390-evidence.png`
- 320×568: `mobile-320-dashboard.png`, `mobile-320-nav-open.png`, `mobile-320-overview.png`, `mobile-320-timeline.png`, `mobile-320-tasks.png`, `mobile-320-evidence.png`

캡처 목록과 요청 inventory는 `/tmp/iw36g-captures/capture-manifest.json`에 있다. 파일은 사용자 수용 결과가 아니라 화면 준비 자료다.

## 준비 중 확인된 화면 상태

검증된 합성 사례에서 명시적 checklist POST를 보냈을 때 API는 HTTP 200 및 `available` 응답을 반환하고 4개 또는 3개의 작업을 포함했다. 화면에는 작업 목록이 나타났지만 상태 문구는 `점검표를 준비하지 못했습니다`라는 오류로 표시됐다. 이 응답/화면 불일치는 production 코드 변경 없이 그대로 기록한다. 따라서 응답 후 캡처를 정상적인 일관된 available UI라고 해석하지 않는다. Refused/unavailable 상태는 이번 합성 sample 요청에서 실제로 발생하지 않았으므로 캡처 상태는 `NOT_TESTED`다.

브라우저 요청 inventory: sample 분석 POST 3회(화면마다 1회), checklist POST 2회(명시적 클릭 2회), guidance POST 1회(명시적 클릭 1회); hover/focus/tab/back 동작으로 인한 추가 요청은 관측되지 않았다. 이는 사용자 검수 응답이 아니다.

## 사용자 수용 기록 — Desktop

각 항목은 사용자가 실제 화면을 검토한 뒤 답하기 전까지 `NOT_TESTED`다. 자동 검증이나 과거 prototype 응답으로 채우지 않는다.

| 항목 | 화면 | 최초 응답 | FAIL 이유 / 제안 | 수정·재검수 | 최종 응답 |
|---|---|---|---|---|---|
| 1/12 Dashboard 첫인상 | `01-desktop-dashboard-1440.png` | NOT_TESTED | — | 없음 | NOT_TESTED |
| 2/12 검토 건 목록 | `01-desktop-dashboard-1440.png`, `02-desktop-card-crop-1440.png` | NOT_TESTED | — | 없음 | NOT_TESTED |
| 3/12 카드 정보 밀도 | `02-desktop-card-crop-1440.png` | NOT_TESTED | — | 없음 | NOT_TESTED |
| 4/12 위험도와 확인 순서 | `02-desktop-card-crop-1440.png`, `03-desktop-overview-1440.png` | NOT_TESTED | — | 없음 | NOT_TESTED |
| 5/12 상세 화면 구조 | `03`–`10-desktop-*-1440.png` | NOT_TESTED | — | 없음 | NOT_TESTED |
| 6/12 활동 흐름 | `04-desktop-timeline-1440.png` | NOT_TESTED | — | 없음 | NOT_TESTED |
| 7/12 정보 중복 | `03-desktop-overview-1440.png`, `04-desktop-timeline-1440.png` | NOT_TESTED | — | 없음 | NOT_TESTED |
| 8/12 확인할 작업 | `05`–`07-desktop-*-1440.png` | NOT_TESTED | — | 없음 | NOT_TESTED |
| 9/12 근거와 한계 | `08-desktop-evidence-1440.png` | NOT_TESTED | — | 없음 | NOT_TESTED |
| 10/12 오류 및 미지원 상태 | 응답 상태 캡처; refused/unavailable은 실제 생성되지 않음 | NOT_TESTED | — | 없음 | NOT_TESTED |
| 11/12 화면 용어 | Dashboard 및 상세 캡처 | NOT_TESTED | — | 없음 | NOT_TESTED |
| 12/12 전체 선호 | 새 UI 및 기존 renderer 비교 필요 | NOT_TESTED | 기존 renderer의 별도 실행/비교를 아직 수행하지 않음 | 없음 | NOT_TESTED |

## 사용자 수용 기록 — Mobile

Chromium CSS viewport만 준비했다. 실제 휴대전화 검수로 기록하지 않는다.

| 항목 | 화면 | 최초 응답 | FAIL 이유 / 제안 | 수정·재검수 | 최종 응답 |
|---|---|---|---|---|---|
| 1/6 390px Dashboard | `mobile-390-dashboard.png` | NOT_TESTED | — | 없음 | NOT_TESTED |
| 2/6 390px 카드 | `mobile-390-dashboard.png` | NOT_TESTED | — | 없음 | NOT_TESTED |
| 3/6 390px 상세 탭·내비게이션 | `mobile-390-nav-open.png`, `mobile-390-overview.png` | NOT_TESTED | — | 없음 | NOT_TESTED |
| 4/6 390px 콘텐츠 | `mobile-390-timeline.png`, `mobile-390-tasks.png`, `mobile-390-evidence.png` | NOT_TESTED | — | 없음 | NOT_TESTED |
| 5/6 320px 핵심 기능 | `mobile-320-*` | NOT_TESTED | — | 없음 | NOT_TESTED |
| 6/6 모바일 전체 선호 | 390px 및 320px 화면 | NOT_TESTED | — | 없음 | NOT_TESTED |

## 자동 검사와 사용자 판단

준비 단계의 문서 변경 후 `uv run pytest -q`는 `3099 passed`, 기존 warning 2개로 통과했다. `npm run test:a11y --silent`는 `states=23`, axe violation 0, 외부 요청 0으로 통과했다. `uv sync --locked --dev`, `uv lock --check`, `git diff --check`도 통과했다. Chromium 자동검증 및 화면 캡처는 사용자 판단을 대체하지 않는다. 36.6F 전체 반응형·접근성 결과는 기준 SHA의 CI 기록으로만 참조한다. 실제 Safari native zoom, VoiceOver, 실제 모바일 기기는 `NOT_TESTED`다. 전체 사용자 수용은 `PHASE_36_6G_PRODUCTION_USER_ACCEPTANCE_PENDING`이다.

기존 renderer switch `USE_WORKSPACE_DETAIL_SHELL_36_6B`와 구형 renderer는 유지한다. renderer 제거에 대한 사용자의 별도 결정은 아직 받지 않았다.

실제 사용자 자료·조직 운영·자동 대응은 `NO_GO`, 모델 기반 AI는 `NOT_TESTED`, Vector/VM은 `USER_ACTION_REQUIRED / ISOLATION_BLOCKED`로 유지한다. 새 production UI의 사용자 수용은 실제 자료나 운영 승인을 뜻하지 않는다.
