# Phase 36.6E-CI-FIX — Chromium 탭 간격 검사 복구

## 시작 gate와 CI 실패

- 기준/시작 SHA: `611811ac2ba39272c33c3e91566a0eb7f747f419`
- branch `main`; 시작 working tree clean; local `HEAD`, `main`, `origin/main`, GitHub remote `main`이 모두 기준 SHA와 일치
- `origin/main...HEAD`: behind 0 / ahead 0
- Actions run [40828907926](https://github.com/misosos/ai-security-log-analyzer/actions/runs/40828907926), job `123298296537`: `push / completed / failure`, artifact 0개
- CI 오류: `WORKSPACE_TASK_TAB_TARGET_SPACING_FAILED scenario=CHECKLIST_REAL kind=Error line=48`
- 전체 pytest와 Linux checkpoint·SSH·TCP Syslog·JSONL·restricted report 단계는 성공했다. Chromium 접근성 단계에서 중단되어 뒤의 tracked-file 검사는 실행되지 않았다.
- `v0.4.0` tag와 Release target은 `eecd6ee1cda0545e34b01c42e1a2163a899bcc27`이다.

## 재현과 원인

실패한 원래 검사는 1440/1024/768/390/320px 순회가 끝난 뒤 320px에서 `evidence.left - tasks.right >= 8`만 비교했다. 탭 목록은 `flex-wrap: wrap`이고 CSS `gap: .5rem`을 사용한다. 가로로 인접한 탭은 이 계산으로 검사할 수 있지만, 탭이 다음 행으로 이동하면 수평 차이는 실제 행 간격을 나타내지 않는다.

macOS에서 변경 전 `npm run test:a11y --silent`를 그대로 재실행해 통과했다. Playwright Chromium `156.0.8078.4`에서 탭의 실제 사각형과 computed style을 기록했다. Linux CI 로그에는 사각형 좌표가 없고 artifact도 없으므로 **CI 시점의 Linux 탭 배치를 직접 관찰할 수 없다**. 따라서 해당 실행에서 실제로 탭이 다른 행으로 나뉘었는지는 확정하지 않는다. 다만 허용된 wrapping을 가로 전용 계산이 잘못 판정하는 반례를 재현했고, 실패 검사의 기하학적 가정이 부정확한 것은 확인했다.

## TDD 및 수정

CI의 원래 assertion은 지정한 Ubuntu/Chromium 실행에서 RED였다. macOS 동일 실행은 통과해 환경 간 배치 차이가 재현되지는 않았다. production CSS는 수정하지 않았다.

브라우저 검사에 bounding rectangle 두 개의 최소 edge-to-edge 유클리드 거리를 계산하는 `targetGapPx` 계약을 추가했다. 이 검사는 같은 행의 수평 간격, 줄바꿈 행의 수직 간격, 대각선 간격을 측정하며 겹치는 사각형은 0으로 판정한다. 8px은 그대로 유지한다. 정상 8px 수평·수직 배치, 겹침, 8px 미만 수평·수직·대각 배치, 기존 수평 검사에서는 실패하지만 8px 행 간격인 wrapping 반례를 검사한다. 반례의 최초 좌표를 작성할 때 수평 간격을 8px로 잘못 설정해 계약 테스트가 RED였고, 실제 줄바꿈의 수평 간격이 음수인 좌표로 고친 후 테스트가 통과했다.

다음으로 production UI를 바꾸지 않고 새 측정 검사를 실행했다. 같은 행 및 wrapping 모두 실제 최소 간격 8px 이상이고 각 tab target은 44×44px 이상이어야 통과한다. 각 viewport에서 top/bottom/left/right/width/height와 computed row/column gap, flex-wrap, font-size만 출력한다.

## macOS 재검증 측정

아래는 macOS Chromium의 실제 CSS viewport 측정이며 개인정보나 DOM text를 포함하지 않는다. 기본 글자 크기는 16px, computed row/column gap은 `8px`, `flex-wrap`은 `wrap`이었다.

| CSS 폭 | 확인할 작업 tab 사각형 | 근거와 한계 tab 사각형 | 배치 및 최소 간격 |
| ---: | --- | --- | --- |
| 1440 | x 465.437–567.234, y 130.828–179.406 | x 575.234–677.031, 같은 행 | 수평 8px |
| 1024 | x 421.906–523.703, y 129.328–177.906 | x 531.703–633.500, 같은 행 | 수평 8px |
| 768 | x 417.437–519.234, y −8.687–39.891 | x 527.234–629.031, 같은 행 | 수평 8px |
| 390 | x 235.953–361, y 259.766–308.344 | x 29–361, 다음 행 | 수직 8px |
| 320 | x 29–156, y 315.937–364.516 | x 164–291, 같은 행 | 수평 8px |

320px에서 root font-size를 200% equivalent인 32px로 설정했을 때 네 탭은 한 열로 배치됐고 row/column gap은 16px, 각 target은 206×94.188px였다. 가로 overflow는 0이었다. 390px 화면에서 허용된 wrapping이 발생하며 행 간격 8px이 보존됨을 확인했다. 전체 브라우저 회귀에서 axe 위반은 0, 외부 요청은 0이었다.

## 검증 결과와 한계

- `npm run test:a11y --silent`: 통과, 기존 23 states, axe 위반 0, 외부 요청 0
- viewport: 1440/1024/768/390/320px, 320px 200% equivalent reflow 통과
- tab target: 모두 44×44px 이상, 인접 tab 최소 기하 간격 8px 이상
- keyboard tab/panel 동작, checklist explicit POST, asynchronous case isolation, privacy canary 및 기존 renderer rollback 회귀 포함
- 전체 pytest: 3,099 passed (기존 warning 2개)
- `uv sync --locked --dev`, `uv lock --check`, Node 문법, `git diff --check`: 통과
- Linux 전용 회귀는 실패한 시작 CI에서 Python/Linux 단계는 통과했다. 복구 변경 뒤 Linux 재검증은 아직 실행되지 않아 새 변경 기준 `NOT_TESTED`다.
- dependency와 lockfile은 바뀌지 않았다. 고정 static asset 상한 160 KiB는 이번 실패 원인이 아니며 그대로 유지한다.
- 실제 Safari·모바일 기기 검수는 `NOT_TESTED`. 이번 복구는 Phase 36.6F가 아니다.
- 실제 사용자 자료·조직 운영·자동 대응 `NO_GO`; 모델 기반 AI `NOT_TESTED`; Vector/VM `USER_ACTION_REQUIRED / ISOLATION_BLOCKED`.

## 다음 단계 gate

로컬 커밋은 Ubuntu CI 성공을 대신하지 않는다. 이 커밋은 사용자가 직접 push한 뒤 새 exact SHA에서 `push / completed / success`, artifact 0, Linux 전체 회귀, Chromium/axe, tracked-file 불변을 확인해야 한다. 그 전에는 Phase 36.6F를 시작하지 않는다.
