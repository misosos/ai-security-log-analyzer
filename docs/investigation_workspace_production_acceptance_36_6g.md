# Phase 36.6G — Production 조사 작업공간 사용자 수용 기록 확정

## 기록 확정 Gate

- 확정 작업 시작 기준 SHA: `8a689e154a80b680df8b3b9d9962852fe6f51126`
- 검증 Actions run `40855159728`: exact SHA `8a689e154a80b680df8b3b9d9962852fe6f51126`, `push / completed / success`
- artifact: 0개
- 성공 단계: locked Python 설치, 전체 pytest, Linux TCP Syslog·JSONL·restricted report, Chromium·axe, tracked-file invariant
- 시작 시 `HEAD`, local `main`, `origin/main`, GitHub `main` 일치; ahead/behind `0/0`
- 시작 시 미커밋 변경은 이 수용 기록 문서 하나뿐이었다.
- `v0.4.0` 및 Release target: `eecd6ee1cda0545e34b01c42e1a2163a899bcc27` 유지
- 최종 커밋은 문서 경로만 stage하는 로컬 문서 커밋으로 제한한다.

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
| 1/12 Dashboard 첫인상 | `01-desktop-dashboard-1440.png` | PASS | — | 수정·재검수 없음 | PASS |
| 2/12 검토 건 목록 | `01-desktop-dashboard-1440.png`, `02-desktop-card-crop-1440.png` | PASS | — | 수정·재검수 없음 | PASS |
| 3/12 카드 정보 밀도 | `02-desktop-card-crop-1440.png` | PASS | — | 수정·재검수 없음 | PASS |
| 4/12 위험도와 확인 순서 | `02-desktop-card-crop-1440.png`, `03-desktop-overview-1440.png` | PASS | — | 수정·재검수 없음 | PASS |
| 5/12 상세 화면 구조 | `03`–`10-desktop-*-1440.png` | PASS | — | 수정·재검수 없음 | PASS |
| 6/12 활동 흐름 | `04-desktop-timeline-1440.png` | PASS | — | 수정·재검수 없음 | PASS |
| 7/12 정보 중복 | `03-desktop-overview-1440.png`, `04-desktop-timeline-1440.png` | PASS | — | 수정·재검수 없음 | PASS |
| 8/12 확인할 작업 | `05`–`07-desktop-*-1440.png` | PASS | — | 수정·재검수 없음 | PASS |
| 9/12 근거와 한계 | `08-desktop-evidence-1440.png` | PASS | — | 수정·재검수 없음 | PASS |
| 10/12 오류 및 미지원 상태 | `06-desktop-tasks-available-verified-1440.png`; refused/unavailable/stale 상태는 실제 생성되지 않음 | NOT_TESTED | 실제 refused/unavailable/stale 화면이 준비되지 않음 | 재검수 없음. 이후 종합 사용자 보고는 별도 집계 | NOT_TESTED |
| 11/12 화면 용어 | Dashboard 및 상세 캡처 | PASS | — | 수정·재검수 없음 | PASS |
| 12/12 전체 선호 | `03-desktop-overview-1440.png`, `13-desktop-legacy-renderer-1440.png` | PASS | — | 수정·재검수 없음 | PASS |

## 사용자 수용 기록 — Mobile

Chromium CSS viewport만 준비했다. 실제 휴대전화 검수로 기록하지 않는다.

| 항목 | 화면 | 최초 응답 | FAIL 이유 / 제안 | 수정·재검수 | 최종 응답 |
|---|---|---|---|---|---|
| 1/6 390px Dashboard | `mobile-390-dashboard.png` | PASS | — | 수정·재검수 없음 | PASS |
| 2/6 390px 카드 | `mobile-390-dashboard.png` | PASS | — | 수정·재검수 없음 | PASS |
| 3/6 390px 상세 탭·내비게이션 | `mobile-390-nav-open.png`, `mobile-390-overview.png` | PASS | — | 수정·재검수 없음 | PASS |
| 4/6 390px 콘텐츠 | `mobile-390-timeline.png`, `mobile-390-tasks.png`, `mobile-390-evidence.png` | PASS | — | 수정·재검수 없음 | PASS |
| 5/6 320px 핵심 기능 | `mobile-320-*` | PASS | — | 수정·재검수 없음 | PASS |
| 6/6 모바일 전체 선호 | 390px 및 320px 화면 | PASS | — | 수정·재검수 없음 | PASS |

## 자동 검사와 사용자 판단

준비 단계의 문서 변경 후 `uv run pytest -q`는 `3099 passed`, 기존 warning 2개로 통과했다. `npm run test:a11y --silent`는 `states=23`, axe violation 0, 외부 요청 0으로 통과했다. `uv sync --locked --dev`, `uv lock --check`, `git diff --check`도 통과했다. Chromium 자동검증 및 화면 캡처는 사용자 판단을 대체하지 않는다. 실제 Safari native zoom, VoiceOver, 실제 모바일 기기는 `NOT_TESTED`다. 사용자 응답은 Desktop 12/12 PASS, Mobile 6/6 PASS이며, 이는 실제 합성 production UI와 Chromium 화면 범위의 사용자 수용이다.

기존 renderer switch `USE_WORKSPACE_DETAIL_SHELL_36_6B`와 구형 renderer는 유지한다. 사용자는 `KEEP_LEGACY`를 선택했으며, 새 production UI는 기본 화면으로 계속 사용한다. 이번 단계에서 구형 renderer를 삭제하거나 제거 작업을 진행하지 않는다. 추후 별도 Phase에서 제거 여부를 다시 검토할 수 있다.

검수 중 checklist endpoint가 실제 `available` 응답을 반환했으나 화면에는 “점검표를 준비하지 못했습니다. 기존 분석 결과는 그대로 유지됩니다.”라는 오류 문구가 작업 선택 항목과 함께 표시됐다. 해당 화면을 사용자에게 보여주고 Desktop 10/12 및 전체 선호 검수를 진행했다. 실제 refused/unavailable/stale 응답 상태는 synthetic endpoint에서 생성되지 않아 `NOT_TESTED`로 남긴다. 이 표시 불일치는 사용자 수용 응답과 별도로 추적할 기술적 후속 항목이며, 이번 검수에서는 production을 수정하지 않았다.

판정: `PHASE_36_6G_PRODUCTION_UI_USER_ACCEPTED` — Desktop 12/12 및 Mobile 6/6 사용자 PASS. 적용 범위는 검수한 합성 production UI와 Chromium CSS viewport다. 실제 운영 승인, Safari/VoiceOver/실기기 검증 또는 기존 renderer 제거 승인을 뜻하지 않는다.

### 종합 사용자 보고와 상태별 미검증의 구분

사용자는 Desktop 전체에 대해 최종 종합 결과 `12/12 PASS`, Chromium 모바일 CSS viewport 전체에 대해 `6/6 PASS`를 명시적으로 보고했다. 이는 사용자가 검수한 합성 production 화면과 흐름의 수용 판정이다. Desktop 10/12의 상태별 최초 결과는 실제 refused/unavailable/stale 화면이 준비되지 않아 `NOT_TESTED`였으며, 그 상태별 검증 결과는 여전히 `NOT_TESTED`다. 종합 12/12 PASS를 실제 오류 응답 상태별 검증으로 확장하지 않는다. Desktop 10/12에 대해 기록되지 않은 재검수 절차를 만들어내지 않는다.

기술 후속 상태는 `CHECKLIST_UI_STATE_INCONSISTENCY_OPEN`, 오류 상태별 수동 수용 검증은 `ERROR_STATE_MANUAL_ACCEPTANCE_NOT_TESTED`다. 이 문자열들은 문서 추적용이며 API/schema 상태 enum이 아니다.

## 후속 기술 작업 — Phase 36.7A

`Phase 36.7A — Checklist Available/Error UI State Consistency Fix`에서 아래를 별도 TDD로 조사·수정한다. 이번 기록 확정에서는 원인을 확정하거나 production 코드를 바꾸지 않았다.

- 실제 `available` 응답과 현재 화면 조합 재현
- 성공·실패 상태가 함께 렌더링되는 원인 추적
- 예외 발생 때 부분 렌더링된 checklist 정리
- 응답 검증과 DOM 반영 경계를 유지하면서 성공/오류 UI 일관성 보장
- explicit POST 1회 계약과 비동기 사례 격리 유지
- refused/unavailable/stale 상태 회귀
- TDD RED→GREEN 및 새 SHA Ubuntu CI 확인

이번 기록 커밋에서 변경한 것은 수용 문서뿐이다. Checklist 기능, renderer, API/schema, 분석 결과 및 개인정보 경계는 변경하지 않았다.

## 기록 확정 로컬 검증

- `uv run pytest -q`: `3099 passed`, 기존 deprecation warning 2개 (178.38초)
- `uv lock --check`: 통과
- `git diff --check`: 통과
- 변경 경로: 이 수용 기록 문서 1개만
- API/frontend/분석 코드와 dependency/lockfile 변경: 0
- Chromium/axe 재실행은 문서 전용 변경이므로 생략했다. 시작 SHA의 성공 CI와 이번 로컬 문서 검증은 별도 증거다.

실제 사용자 자료·조직 운영·자동 대응은 `NO_GO`, 모델 기반 AI는 `NOT_TESTED`, Vector/VM은 `USER_ACTION_REQUIRED / ISOLATION_BLOCKED`로 유지한다. 새 production UI의 사용자 수용은 실제 자료나 운영 승인을 뜻하지 않는다.
