# Phase 36.5C — PatternFly 조사 작업공간 prototype 사용자 검수

## 범위와 시작 gate

검수 대상은 production과 분리된 정적 합성 prototype이다. production UI, API, schema, 분석 pipeline은 수정하지 않았다.

- 시작 SHA / local `main` / `origin/main`: `bae1b1f03012d4be2d6dc177d241ba06cac32df6`
- branch: `main`; 시작 working tree clean; `origin/main...HEAD`: behind 0 / ahead 0
- exact-SHA GitHub Actions: [CI run 40704513861](https://github.com/misosos/ai-security-log-analyzer/actions/runs/40704513861), `push`, `completed`, `success`
- CI jobs: locked Python regression, full pytest, Linux TCP Syslog smoke/reliability/management, JSONL runtime, restricted report, Chromium accessibility pilot, tracked-file check 모두 성공
- CI artifact: 0
- `v0.4.0` tag와 Release target: `eecd6ee1cda0545e34b01c42e1a2163a899bcc27`

Phase 36.5B의 사용자 검수는 1/12 최종 `FAIL`, 나머지 `NOT_TESTED`로 중단했다. 이번 단계는 그 검수를 대신해 새 정적 prototype의 화면을 시각 검토했다. 검수용 웹서버는 loopback에서만 사용했고, 실제 사용자 자료·기존 checkpoint·production 설정에 접근하지 않았다.

## 화면과 고정 합성 데이터

실제 prototype HTML/CSS/JS를 Chromium에서 같은 고정 합성 데이터로 다시 렌더링했다. 전체 화면을 먼저 제시하고, 대시보드 카드와 타임라인에는 판단을 돕는 확대 crop을 추가했다. crop은 원본 전체 화면을 대체하지 않는다.

| 화면 | 전체 screenshot |
| --- | --- |
| 1440px dashboard | `docs/prototypes/investigation-workspace/screenshots/01-dashboard-1440.png` |
| 1440px overview | `docs/prototypes/investigation-workspace/screenshots/02-overview-1440.png` |
| 1440px activity timeline | `docs/prototypes/investigation-workspace/screenshots/03-timeline-1440.png` |
| 1440px tasks | `docs/prototypes/investigation-workspace/screenshots/04-tasks-1440.png` |
| 1440px evidence and limitations | `docs/prototypes/investigation-workspace/screenshots/05-evidence-1440.png` |
| 390px dashboard | `docs/prototypes/investigation-workspace/screenshots/06-dashboard-390.png` |
| 390px detail | `docs/prototypes/investigation-workspace/screenshots/07-detail-390.png` |

검수 중 추가한 crop:

- `docs/prototypes/investigation-workspace/screenshots/01-dashboard-cards-crop.png`
- `docs/prototypes/investigation-workspace/screenshots/03-timeline-crop.png`

비교용 기존 production 화면의 캡처는 prototype 산출물에 없어서 새로 만들거나 prototype 화면을 이전 화면처럼 꾸미지 않았다. 마지막 선호 질문은 사용자가 앞서 본 기존 화면과 현재 prototype을 비교해 응답하도록 했다.

## 사용자 응답

각 화면을 보여준 뒤 한 질문씩 진행했다. 최초 응답과 최종 응답은 같으며 FAIL에 따른 수정은 없었다.

| 항목 | 최초 응답 | 수정 | 재검수 | 최종 응답 |
| --- | --- | --- | --- | --- |
| 1/12 dashboard 첫인상 | PASS | 없음 | 해당 없음 | PASS |
| 2/12 목록 가독성 | PASS | 없음 | 해당 없음 | PASS |
| 3/12 카드 여백과 밀도 | PASS | 없음 | 해당 없음 | PASS |
| 4/12 시각적 위계 | PASS | 없음 | 해당 없음 | PASS |
| 5/12 상세 화면 구조 | PASS | 없음 | 해당 없음 | PASS |
| 6/12 활동 흐름 | PASS | 없음 | 해당 없음 | PASS |
| 7/12 중복과 정보량 | PASS | 없음 | 해당 없음 | PASS |
| 8/12 확인할 작업 | PASS | 없음 | 해당 없음 | PASS |
| 9/12 근거와 한계 | PASS | 없음 | 해당 없음 | PASS |
| 10/12 용어 | PASS | 없음 | 해당 없음 | PASS |
| 11/12 모바일 | NOT_TESTED | 없음 | 해당 없음 | NOT_TESTED |
| 12/12 전체 선호 | PASS | 없음 | 해당 없음 | PASS |

사용자 이해도 응답은 자동 검사 결과와 별개다. 11/12를 자동 검사로 PASS 처리하지 않았다.

## 자동 검증

- `npm ci --ignore-scripts`: 성공; 5개 package 설치, audit 취약점 0
- 재렌더링: 요청된 7개 화면 생성
- viewport matrix: 1440×900, 1024×768, 768×1024, 390×844, 320×568에서 dashboard/detail 모두 수평 overflow 0
- 200% equivalent reflow: 720 CSS px + 200% root font-size에서 detail overflow 0. Native browser zoom 검수는 아님
- axe: viewport, 기본 화면, 탭 상태 포함 15개 상태에서 violation 0
- 외부 요청 0, API 요청 0
- keyboard: 탭 ArrowRight 이동과 작업 선택 동작 통과
- prototype 생성은 local static HTTP server에서만 이뤄졌으며 테스트 후 server를 종료했다.
- 전체 pytest: `3085 passed`, 기존 deprecation warning 2개
- production frontend·API·schema·analysis files: 변경 없음
- `package.json`, `package-lock.json`, `pyproject.toml`, `uv.lock`: 변경 없음

자동 axe 검사는 수동 사용성 판단이나 WCAG 2.2 AA 전체 적합성 검수를 대신하지 않는다.

## 판정과 남은 경계

최종 응답에 `NOT_TESTED`가 있으므로 판정은 **`PROTOTYPE_ACCEPTANCE_NOT_TESTED`**다. 12/12 전부 PASS 또는 production 이식 승인으로 기록하지 않는다. prototype은 production에 이식되지 않았고, 다음 단계에서 별도 이식 설계와 회귀 범위를 정해야 한다.

- Safari: `NOT_TESTED`
- production UI 통합: 미승인 / 미구현
- 실제 사용자 자료·조직 운영·자동 대응: `NO_GO`
- 모델 기반 AI: `NOT_TESTED`
- Vector/VM: 기존 차단 상태 유지
