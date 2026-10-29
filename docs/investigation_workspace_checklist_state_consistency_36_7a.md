# Phase 36.7A — Checklist 상태 표시 일관성 수정

## Gate와 범위

- 시작 기준: `4edafe2a5bda2b2792b02896a9648caa13000bc2`
- GitHub Actions: Run `40857535502`, exact SHA `push / completed / success`, artifact 0개
- 기준 CI에서 전체 pytest, Linux TCP Syslog·JSONL·restricted report, Chromium·axe 및 tracked-file invariant가 성공했다.
- `v0.4.0` tag와 Release target은 `eecd6ee1cda0545e34b01c42e1a2163a899bcc27`이다.
- 작업 시작 시 `main`은 기준 SHA와 일치하고 working tree는 clean이었다.
- 범위는 Checklist 응답의 표시 일관성, 렌더 실패 시 부분 UI 제거, 관련 회귀 검증으로 한정했다. API·schema·분석·projection 계약은 변경하지 않았다.

## 결함 재현과 RED

브라우저 테스트는 격리된 임시 HOME과 loopback 서버에서 고정 합성 sample을 분석하고, Checklist 버튼을 명시적으로 눌렀다. `CHECKLIST_REAL`은 checklist 요청을 실제 production API에 전달했다. 통합 suite의 반복 sample 호출이 API rate limit을 소진하지 않도록 첫 합성 분석 응답만 테스트 프로세스 안에서 cache해 후속 화면 테스트에 재사용하며, production limit이나 응답은 변경하지 않는다. 통제된 렌더 예외는 같은 사례의 두 번째 명시 요청에서 기존 v2 형식의 테스트 응답으로 주입한다.

수정 전 실제 응답은 HTTP 200, `investigation-checklist/v2`, `available`, 유효한 4개 step, `source_role=ssh`, `review_priority=review_soon`이었다. 버튼 전 요청은 0건, 명시 클릭 후 POST는 1건이었다. 작업 선택 버튼 4개가 DOM에 생겼지만 `data-checklist-state=error`와 `점검표를 준비하지 못했습니다`가 동시에 표시되어 `CHECKLIST_REAL_AVAILABLE_UI_STATE_MISMATCH`로 실패했다. 이 결과가 수정 전 RED이다.

테스트 전용 stack 위치 계측은 예외를 `frontend/app.js:1866`으로 특정했다. `renderChecklistCitation`은 `renderWorkspaceDetailShell`의 지역 함수인데 바깥 함수 `renderWorkspaceChecklistPanel`의 `renderSelectedTask`에서 직접 이름을 참조했다. lexical scope에 없는 함수 참조가 실제 citation 렌더링 중 `ReferenceError`를 일으켰다. 이는 유효한 응답 검증이나 API 계약 실패가 아니었다.

예외가 나기 전에 기존 구현은 `controller.onValidated(checklist)`로 역할과 확인 순서를 변경하고, 안내와 master-detail 목록을 실제 output에 append한 뒤 citation을 렌더링했다. catch는 오류 상태와 실패 문구를 더했지만 앞서 추가한 요소와 검증 label을 제거하지 않아 성공·오류가 함께 보였다.

## 최소 수정

- citation renderer를 기존 상세 화면에서 checklist controller callback으로 전달해 기존 안전한 text-node 렌더 함수를 재사용한다.
- checklist의 안내, 작업 목록, 첫 선택 상세, citation은 detached staging element에 먼저 구성한다. 요청 identity를 다시 확인한 다음 validated role/priority를 반영하고 output을 교체한다.
- 예외 시 현재 요청에 한해 output을 비우고 `onReset()`으로 role/priority 및 citation 영역을 초기 상태로 돌린 뒤 고정 오류 안내만 보인다.
- HTTP 오류와 validation 실패도 메시지 DOM을 준비한 뒤 현재 요청 여부를 확인하고 상태·화면을 함께 갱신한다. `refused`, `unavailable`, `stale`, 일반 오류의 기존 구분은 유지한다.
- 320px, 200% equivalent에서 task detail disclosure summary 폭이 43 CSS px였던 기존 자동 검사를 확인했다. 실제 44×44 target 계약을 유지하기 위해 summary에 `min-width: 44px`를 추가했다. overflow나 간격 기준은 완화하지 않았다.
- 테스트는 성공 안내·역할·우선순위가 기존 UI의 실제 헤더 위치에 있는지 확인한다. 분석 불변 비교에서는 checklist 탭의 동적 표현(role/priority, checklist citation slot)을 제외하고 기존 분석 본문을 비교하며, 두 표현의 올바른 값은 별도 assertion으로 검사한다.

## 수정 후 자동 검증

- 실제 합성 API available 응답: explicit POST 1건, UI status `available`, 4개 작업 버튼, 검증된 SSH 역할과 `우선 확인`, 오류 문구 없음.
- 테스트 전용 두 번째 explicit 요청에서 렌더 예외 주입: POST 1건, UI status `error`, 작업 부분목록 0개, 역할 `역할 미확인`, 확인 순서 `확인 순서 미정`, 내부 예외 canary 비노출.
- 체크리스트의 자동 요청은 0건이다. 재시도는 버튼 클릭에 따른 별도 요청으로만 실행했다.
- Refused, unavailable, 404 stale, timeout, rate limit, 통신 실패, 반복 클릭 차단, retry, invalid response/citation 및 async 사례 격리 시나리오가 브라우저 모음에서 검증된다.
- Chromium·axe 전체 실행: 23개 기존 상태, axe 위반 0, 외부 요청 0. 1440/1024/768/390/320px 및 320px root-font 32px equivalent reflow에서 overflow·clipping 0; target 최소 크기 44px와 간격 8px 검사 통과.
- 명시적 분석 결과 비교에서 checklist 표시 외 분석 본문은 변경되지 않았다. API/schema 및 frozen projection 계약 변경은 없다.
- `uv sync --locked --dev`, `uv lock --check`, `uv run pytest -q`: `3101 passed`, 기존 dependency deprecation warning 2개.
- `node --check frontend/app.js`, `node --check tests/ui_accessibility_axe_pilot_28_1.mjs`, `git diff --check` 통과.
- `frontend/app.js`는 135,820 bytes로 고정 160 KiB 상한(163,840 bytes) 안에 있다. Dependency와 lockfile 변경은 없다.
- 이번 로컬 실행은 macOS이므로 Linux 전용 TCP Syslog·JSONL·restricted report acceptance는 새 SHA 기준 `NOT_TESTED`이며, 기준 SHA CI 결과와 구분한다. 새 커밋의 Ubuntu CI는 별도 확인이 필요하다.

## 수용 범위와 남은 작업

- Phase 36.6G의 desktop 12/12 및 Chromium mobile CSS viewport 6/6 사용자 수용 기록은 바꾸지 않았다.
- 이번 `available` 및 제어된 렌더 오류 화면은 자동 검증 상태다. 사용자의 오류 화면 재검수는 `NOT_TESTED`; `USER_ACCEPTED`라고 주장하지 않는다.
- Refused/unavailable/stale에 대한 기존 자동 시나리오는 통과했지만 이번 수정 화면에 대한 수동 사용자 평가는 별도다.
- Safari·실제 모바일·VoiceOver: `NOT_TESTED`.
- 실제 사용자 자료·조직 운영·자동 대응: `NO_GO`.
- 모델 기반 AI: `NOT_TESTED`.
- Vector/VM: `USER_ACTION_REQUIRED / ISOLATION_BLOCKED`.
- 기존 renderer와 `USE_WORKSPACE_DETAIL_SHELL_36_6B` rollback switch는 유지한다.

판정: `PHASE_36_7A_CHECKLIST_UI_STATE_CONSISTENCY_LOCAL_CONDITIONAL_GO`. 이는 로컬 자동 검증 결과이며 새 SHA의 GitHub CI 성공이나 오류 화면의 사용자 수용을 뜻하지 않는다.
