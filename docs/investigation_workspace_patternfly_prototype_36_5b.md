# Phase 36.5B — PatternFly 기준 정적 작업 공간 prototype

## 사용자 검수 중단 기록

Phase 36.5B 사용자 수용 검수는 완료하지 않았습니다. 1/12 최초 응답은 `FAIL`이었고, 첫 번째 화면 조정 뒤 핵심 정보 구분은 나아졌다는 응답이 있었지만 이후 사용자가 최종 1/12 결과를 `FAIL`로 정정했습니다. 확정된 마지막 상태는 1/12 `FAIL`, 2/12–12/12 `NOT_TESTED`입니다. `USER_COMPREHENSION_GO`, Phase 36.5B PASS 또는 production GO로 기록하지 않습니다.

실패에서 확인된 문제는 카드 안쪽 여백, 카드 간격, 제목·label·metadata·설명·action의 typographic hierarchy, 설명 줄 길이와 답답한 밀도였습니다. 첫 보정 결과와 이후 정정된 FAIL은 모두 보존합니다. 첫 보정은 독립 checkpoint `24edaff2627a8ff26b5ab70f7c6d52fdc566e32b` (`fix: improve investigation card scanability`)로 저장했습니다. 이 checkpoint는 사용성 수용 PASS를 뜻하지 않습니다.

이제 production UI 변경을 더 진행하지 않고 PatternFly 6를 primary reference로 삼은 정적 합성 prototype을 먼저 검토합니다. 사용자의 디자인 방향 승인 전에는 prototype을 production에 이식하지 않습니다.

## Dirty tree 분류와 checkpoint

시작 당시 dirty 파일은 `frontend/app.js`, `frontend/index.html`, `frontend/style.css`, `tests/ui_accessibility_axe_pilot_28_1.mjs`, `tests/web_ui_behavior.cjs`였습니다. 변경은 모두 검토 건 카드 정보 위계와 spacing/wrapping 계약에 해당했습니다. API, schema, 분석 결과, privacy projection, checklist 호출, dependency·lockfile 변경은 없었습니다. 출처 불명·무관 변경은 발견되지 않았습니다.

새 spacing 계약은 수정 전 `REVIEW_CARD_SPACING_FAILED`로 실패했습니다. 공통 `.case-card { padding: 0 }` 규칙이 같은 specificity의 카드 padding을 덮는 결함을 확인하고, 카드 전용 selector와 spacing만 조정했습니다. Chromium 검사에서 좌우 padding 44px, 상하 40px, 카드 gap 20px, 배지 간격 8px, 요약 line-height 1.6, 2줄 clamp, 작업 버튼 간격 16px, 요약 폭 약 62ch를 확인했습니다. 320 CSS px와 200% equivalent 글자 확대에서 overflow 없이 padding·줄바꿈이 유지됐습니다.

Checkpoint 검증은 focused Python UI/API 61개 통과, Chromium·axe 23개 상태 위반 0, 외부 요청 0, `git diff --check` 통과였습니다. 전체 pytest는 checkpoint 커밋 시점에는 실행하지 않았습니다. prototype을 추가한 뒤 전체 suite는 `3085 passed, 2 warnings`로 통과했습니다. 기존 Phase 36.5A 기준 결과도 3,085 passed였습니다.

## PatternFly 선택과 라이선스

PatternFly 6는 공식 HTML/CSS core와 component guidance를 제공해 enterprise page shell, card, status label, compact description list, tabs와 timestamp의 시각적 관계를 한 기준으로 참고할 수 있습니다. 현재 공식 component 문서는 PatternFly 6.7.0을 표시합니다. [Page](https://www.patternfly.org/components/page/html/), [Card](https://www.patternfly.org/components/card/html/), [Description list](https://pf6.patternfly.org/components/description-list/), [Label](https://www.patternfly.org/components/label/html/), [Tabs](https://www.patternfly.org/components/tabs/html/), [Timestamp](https://www.patternfly.org/components/timestamp/html/)를 참고했습니다. Progress Stepper는 workflow 진행률 의미를 timeline에 잘못 부여할 수 있어 사용하지 않았습니다.

공식 [PatternFly HTML/CSS core repository](https://github.com/patternfly/patternfly)는 MIT license를 표시하며 저장소의 [`LICENSE.txt`](https://raw.githubusercontent.com/patternfly/patternfly/main/LICENSE.txt)는 Red Hat, Inc. 2019 저작권과 MIT 조건을 명시합니다. prototype은 PatternFly 소스나 asset을 복사하지 않고 anatomy와 visual rhythm만 참고했습니다. PatternFly 상표·Red Hat 제품 branding, package, CDN, 외부 font/icon/style은 사용하지 않았습니다.

| PatternFly reference | Prototype 적용 |
| --- | --- |
| Page | masthead, navigation rail, main content와 page heading을 분리 |
| Card | dashboard 검토 건을 넓은 행형 card로 배치 |
| Label | severity, review priority, source role을 독립된 label로 표시 |
| Description list | 결과 요약과 상세 지표를 compact row로 구성 |
| Tabs | 개요·활동 흐름·확인할 작업·근거와 한계를 탭으로 전환 |
| Timestamp | `<time datetime>`과 기본 KST, 펼쳐 보는 UTC |
| Progress Stepper | 사용하지 않음. 사건 시간순서는 `<ol>` timeline으로 표현 |

## Prototype 구조

- `docs/prototypes/investigation-workspace/index.html`: 넓은 단일 열 검토 건 목록, compact metric, 보고서 보조영역
- `docs/prototypes/investigation-workspace/detail.html`: 독립 상세 예시와 네 개의 실제 전환 탭
- `docs/prototypes/investigation-workspace/prototype.css`: prototype 전용 CSS custom property로 색상, spacing, type scale, radius, shadow와 content width 관리
- `docs/prototypes/investigation-workspace/prototype.js`: 키보드 화살표/Home/End 탭 이동과 하나씩 펼쳐지는 선택 작업 설명
- `docs/prototypes/investigation-workspace/README.md`: loopback 정적 실행 방법

작업 탭은 master-detail 안을 선택했습니다. 한 번에 선택 작업 하나의 방법·근거만 보여줘 accordion을 연속으로 펼친 문서형 화면을 피합니다. 모든 내용은 고정 합성 문자열입니다. API, production JS/CSS, storage와 분석 상태는 사용하지 않습니다.

## 변경 전 문제와 prototype 해결 방식

| 확인된 문제 | Prototype 대응 |
| --- | --- |
| 목록 카드의 정보가 촘촘하고 경계가 약함 | 한 줄 전체 폭 카드, 세 그룹 label, 명확한 heading과 compact metadata |
| 큰 metric box가 화면을 분절 | 숫자 중심 compact definition rows |
| timeline이 활동 카드 또는 workflow처럼 보일 위험 | 시간순 `<ol>`과 관찰 종류 text label, 분리된 점선 관계 설명 |
| 작업이 긴 동일 카드로 반복 | 짧은 master list와 선택 작업 한 건의 세부 panel |
| citation과 내부 code가 주요 관찰과 경쟁 | 별도 탭, technical metadata disclosure |
| 영어 제목·내부 code 노출 | 기본 한국어 summary, technical disclosure에만 원문과 code |
| 페이지 간격·폭이 viewport에 맞지 않음 | token 기반 responsive grid와 단일 열 breakpoint |

## Token과 시각 기준

Prototype의 `:root` token은 배경·surface·border·text·action·severity·warning·focus, 4px 단계 spacing, type scale, line-height, radius, subtle shadow와 1,280px content max를 정의합니다. 본문은 16px system font와 1.5–1.65 line-height를 사용하고, 카드 내부 padding은 24px, 목록 사이 간격은 20px, 긴 문장은 72ch 안에서 제한합니다. 개별 component에 값이 반복되지 않게 CSS variable을 참조합니다.

## Responsive·접근성·외부 경계

두 화면은 semantic header, aside/nav, main, heading과 list를 사용합니다. 상세 tabs는 `tablist`/`tab`/`tabpanel`, `aria-selected`, roving tabindex와 arrow/Home/End 키보드 이동을 갖습니다. 활동 흐름은 시간순 `<ol>`이며 색상 외에 text label을 제공합니다. 작업 상세는 저장되는 checkbox가 아닌 `aria-pressed` 선택 button이고, citation·기술 정보는 native disclosure입니다. focus ring, skip link, reduced-motion 설정을 포함합니다.

Prototype은 외부 요청·API 호출·browser storage·production import를 만들지 않습니다. 화면 검수에 쓰는 데이터는 고정 합성 사례입니다. 자동 axe 통과는 사용자 이해도나 WCAG 2.2 AA 전체 적합성 검수를 뜻하지 않습니다.

## Prototype 검증 결과

격리된 Chromium에서 loopback 정적 서버만 사용했습니다. prototype의 CSS와 JS를 불러와도 외부 요청 0건, API 요청 0건이었습니다. dashboard와 detail 각각 1440×900, 1024×768, 768×1024, 390×844, 320×568에서 document/body 수평 overflow가 없었습니다. detail은 720 CSS px viewport와 200% root font-size 확대에서도 overflow가 없었습니다. 이는 200% equivalent reflow 자동 검사이며 native browser zoom 수동 검수는 아닙니다.

Keyboard 확인은 tab focus, ArrowRight 이동, 선택된 tab과 panel 전환, 작업 선택 전환으로 수행했습니다. dashboard, detail overview, timeline, tasks, evidence, 모바일 detail, 320px의 detail 세 panel에서 axe violation은 각각 0이었습니다. 상세 화면 DOM은 198개 node, 직렬화 HTML은 11,572 bytes였습니다. 이 수치와 viewport 관측은 작은 합성 prototype 개발 측정이며 운영 SLA가 아닙니다. 테스트 과정에서 대비 부족과 brand 링크 accessible-name mismatch가 발견되어 prototype 내부 색상 token과 aria-label만 조정한 후 재검증했습니다.

Screenshot 크기와 경로:

| 화면 | PNG 크기 |
| --- | ---: |
| Dashboard 1440 | 1440×1319 |
| Detail overview 1440 | 1440×969 |
| Timeline 1440 | 1440×1249 |
| Tasks 1440 | 1440×1060 |
| Evidence 1440 | 1440×1271 |
| Dashboard 390 | 390×1875 |
| Detail 390 | 390×1527 |

외부 network, model, 실제 자료, browser storage는 사용하지 않았습니다. 사용성 수용 검수는 아직 시작하지 않았습니다.

Screenshots:

- `docs/prototypes/investigation-workspace/screenshots/01-dashboard-1440.png`
- `docs/prototypes/investigation-workspace/screenshots/02-overview-1440.png`
- `docs/prototypes/investigation-workspace/screenshots/03-timeline-1440.png`
- `docs/prototypes/investigation-workspace/screenshots/04-tasks-1440.png`
- `docs/prototypes/investigation-workspace/screenshots/05-evidence-1440.png`
- `docs/prototypes/investigation-workspace/screenshots/06-dashboard-390.png`
- `docs/prototypes/investigation-workspace/screenshots/07-detail-390.png`

## 상태와 비목표

- Prototype: 자동 확인 뒤 사용자 디자인 검토 대기
- Production UI: 변경 없음. 사용자의 prototype 승인 전 이식 금지
- Phase 36.5B: 수용 미완료, 1/12 `FAIL`, 나머지 `NOT_TESTED`
- 실제 사용자 자료·조직 운영·자동 대응: `NO_GO`
- 모델 기반 AI: `NOT_TESTED`
- Safari: `NOT_TESTED / USER_HOME_ISOLATION_BLOCKED`
- Vector/VM: 기존 `USER_ACTION_REQUIRED / ISOLATION_BLOCKED` 유지

이 prototype은 실제 로그 운영, incident 판정 또는 대응 기능을 승인하지 않습니다.
