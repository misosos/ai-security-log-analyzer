# Phase 36.5D — PatternFly prototype 모바일 사용자 수용

## 시작 gate

- 시작 SHA, local `main`, `origin/main`: `3be75a1aac36411f93ce4bffab7f19b8da7fd2ea`
- branch: `main`; 시작 tree clean; `origin/main...HEAD`: behind 0 / ahead 0
- exact SHA CI: [run 40713415279](https://github.com/misosos/ai-security-log-analyzer/actions/runs/40713415279), `push / completed / success`
- CI artifact: 0
- `package.json`, `package-lock.json`, `pyproject.toml`, `uv.lock`: 시작 시 변경 없음

Phase 36.5C 결과를 보존한다: desktop 및 전체 선호 11개 `PASS`, 모바일 `NOT_TESTED`, 전체 판정 `PROTOTYPE_ACCEPTANCE_NOT_TESTED`. prototype은 계속 production에 미이식 상태다.

## 검수 환경과 실제 화면

정적 prototype을 loopback 서버에서 열고 Chromium으로 고정 합성 데이터만 렌더링했다. `deviceScaleFactor=1`로 두고 브라우저 기본 zoom 100%에서 CSS viewport의 `innerWidth`를 확인했다.

- 390px: 정확히 `390×844` CSS px
- 320px: 정확히 `320×568` CSS px
- dashboard와 상세의 개요·활동 흐름·확인할 작업·근거와 한계를 각 viewport에서 렌더링
- 실제 모바일 기기나 Safari는 사용하지 않음
- full-page 화면과 상단 viewport crop을 검수 화면으로 제시
- axe 검사 직후 포커스가 skip link에 남아 작업 화면 캡처에 겹치는 현상을 발견했다. 사용자에게 잘못된 화면을 제시하지 않도록 axe와 별도로 새 페이지에서 재캡처했고, prototype 코드는 바꾸지 않았다.

검수 화면 보관 경로:

- `docs/prototypes/investigation-workspace/screenshots/mobile-36_5d/390-dashboard.png`
- `docs/prototypes/investigation-workspace/screenshots/mobile-36_5d/390-detail-overview.png`
- `docs/prototypes/investigation-workspace/screenshots/mobile-36_5d/390-detail-timeline.png`
- `docs/prototypes/investigation-workspace/screenshots/mobile-36_5d/390-detail-tasks.png`
- `docs/prototypes/investigation-workspace/screenshots/mobile-36_5d/390-detail-evidence.png`
- `docs/prototypes/investigation-workspace/screenshots/mobile-36_5d/320-dashboard.png`
- `docs/prototypes/investigation-workspace/screenshots/mobile-36_5d/320-detail-overview.png`
- `docs/prototypes/investigation-workspace/screenshots/mobile-36_5d/320-detail-timeline.png`
- `docs/prototypes/investigation-workspace/screenshots/mobile-36_5d/320-detail-tasks.png`
- `docs/prototypes/investigation-workspace/screenshots/mobile-36_5d/320-detail-evidence.png`

## 사용자 응답

각 항목은 한 번씩 질문했다. 최초 FAIL이 없어 수정이나 재검수는 없었다.

| 항목 | 최초 응답 | FAIL 사유 | 수정 전 테스트 | 수정 | 재검수 | 최종 응답 |
| --- | --- | --- | --- | --- | --- | --- |
| 1/6 — 390px dashboard 구조 | PASS | 해당 없음 | 해당 없음 | 없음 | 해당 없음 | PASS |
| 2/6 — 390px 카드 가독성 | PASS | 해당 없음 | 해당 없음 | 없음 | 해당 없음 | PASS |
| 3/6 — 390px 상세 탐색 | PASS | 해당 없음 | 해당 없음 | 없음 | 해당 없음 | PASS |
| 4/6 — 390px 상세 콘텐츠 | PASS | 해당 없음 | 해당 없음 | 없음 | 해당 없음 | PASS |
| 5/6 — 320px 최소 폭 | PASS | 해당 없음 | 해당 없음 | 없음 | 해당 없음 | PASS |
| 6/6 — 모바일 전체 선호 | PASS | 해당 없음 | 해당 없음 | 없음 | 해당 없음 | PASS |

사용자 응답은 자동 viewport·axe 검사와 별도 기록했다. 화면 이해도 응답을 자동 검사로 대체하지 않았다.

## 자동 검증

- 정확한 CSS viewport: 390×844 및 320×568 확인
- dashboard 및 상세 탭 상태 10개에서 document/body/main 수평 overflow: 0
- 200% equivalent 추가 검사: 좁은 CSS viewport 195px 및 160px에서 root font-size를 200%로 설정했을 때 body/document 폭이 640px가 되어 넘침이 관찰됨. 이는 통과로 기록하지 않는다.
- axe: 10개 모바일 상태에서 violation 0
- 키보드: 탭 ArrowRight 이동 시 `활동 흐름` 탭이 선택되고, 작업 버튼 선택 시 `aria-pressed=true`
- 색상 외 상태 정보: 위험도·역할·활동은 text label도 함께 렌더링
- 대시보드의 `관련 검토 건 보기` 텍스트 링크 높이는 19px로 측정됐다. 다른 주요 상세 화면 상호작용의 최소 측정 크기는 24px였다. axe 위반과는 별개인 target-size 관측치이며, 코드 변경은 하지 않았다.
- 외부 요청 0, API 요청 0, console error 0
- 테스트용 loopback 서버를 종료함

자동 200% equivalent 검사에서 관찰된 overflow와 링크 target 크기는 사용자 PASS 응답과 혼동하지 않도록 별도 한계로 남긴다. 이 단계의 수용 질문은 고정 viewport의 실제 화면을 대상으로 했다.

## 테스트와 변경 범위

- `npm ci --ignore-scripts`: 성공, 5 packages 설치, npm audit 취약점 0
- `uv sync --locked --dev`: 성공
- `uv lock --check`: 성공
- Node prototype 문법 검사: 성공
- `git diff --check`: 통과
- 전체 pytest: `3085 passed`, 기존 deprecation warning 2개
- dependency/lockfile 변경 없음
- production frontend, backend, API, schema, analysis pipeline 변경 없음
- 사용자 응답이 모두 PASS라 prototype CSS/JS는 수정하지 않음

## 판정과 남은 경계

사용자의 6/6 최종 응답은 모두 `PASS`이므로 모바일 prototype 사용자 수용 판정은 **`PROTOTYPE_USER_ACCEPTED`**다. 이는 디자인 prototype에 한정된다. 자동 200% equivalent reflow에서 발견된 overflow와 19px 텍스트 링크 target은 별도 기술 관측치로 남아 있으며, production 통합 전에 별도 이식 설계에서 재검토해야 한다.

- 실제 모바일 기기: `NOT_TESTED`
- Safari: `NOT_TESTED`
- production 이식: 미승인 / 미구현
- 실제 사용자 자료·조직 운영·자동 대응: `NO_GO`
- 모델 기반 AI: `NOT_TESTED`
- Vector/VM 차단 상태: 변경 없음

## 완료 후 사용자 확인

완료 보고 뒤 사용자가 `PASS`라고 응답했다. 이를 모바일 수용 결과에 대한 추가 확인으로 기록한다. 기존 6개 문항의 응답을 대체하거나 별도 문항으로 세지 않으며, 6/6 PASS 판정은 그대로 유지한다.
