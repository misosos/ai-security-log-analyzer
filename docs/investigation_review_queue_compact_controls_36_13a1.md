# Phase 36.13A1 — 검토 큐 컨트롤 정보 밀도 개선

## 판정

`PHASE_36_13A1_COMPACT_QUEUE_CONTROLS_LOCAL_CONDITIONAL_GO`

Production UI·브라우저 자동 검증은 로컬에서 완료했다. 이 문서는 Phase 36.13B의 사용자 수용 기록이 아니다. 새 화면의 사용자 재검수 전 상태는 `USER_ACCEPTANCE_NOT_TESTED`다. Ubuntu CI, Safari, 실제 모바일 기기, 실제 사용자 자료 및 조직 운영은 이번 로컬 작업에서 승인하지 않았다.

## 시작 기준과 사용자 피드백

- 시작 SHA: `6e9923e7c634c070665a1ba75fcabf845c7a176b`
- exact push CI: [Run 41327008707](https://github.com/misosos/ai-security-log-analyzer/actions/runs/41327008707), `push / completed / success`
- 시작 시 branch `main`, clean tree, local HEAD/local main/origin/main 일치, ahead/behind `0/0`을 확인했다. v0.4.0 tag와 Release target은 기존 SHA `eecd6ee1cda0545e34b01c42e1a2163a899bcc27`이었다.
- Phase 36.13B의 1/12 최초 응답은 사용자의 `FAIL`로 보존한다. 이유: 검색·필터·정렬은 필요하지만 모든 컨트롤과 큰 초기화 버튼이 상시 노출되어 결과보다 복잡해 보였다.
- 문항 2–12는 `NOT_TESTED`로 보존한다. 기존 화면을 사용자 PASS로 기록하지 않았고 검수를 계속하지 않았다.

## 변경 이유와 실무 참고

검토 건이 많을 때 검색·필터·정렬은 triage에 유용하지만, 작은 결과 목록에서 세부 필터를 계속 펼쳐 놓으면 카드보다 도구가 시각적 우선권을 갖는다. Microsoft Sentinel incident 목록은 상태·심각도 같은 기준으로 목록을 좁히고, Elastic Security Alerts는 검색 및 필터 컨트롤로 경보를 탐색한다. 이 제품 문서는 대량 triage에서 탐색 도구가 쓰이는 근거로만 참고했다. 화면이나 자산을 복사하지 않았고, 해당 제품들의 구체적 배치가 이번 UI 설계와 같다고 주장하지 않는다. [Microsoft Sentinel incident triage](https://learn.microsoft.com/en-us/azure/sentinel/incident-navigate-triage), [Elastic Security alert filtering](https://www.elastic.co/docs/solutions/security/detect-and-alert/manage-detection-alerts)

## 화면 정보 구조

변경 전에는 검색·위험도·역할·확인 순서·정렬·큰 초기화 버튼이 같은 영역에 모두 펼쳐져 있었다. 변경 후 기본 화면에는 `검토 건`과 전체 건수, 검색, `필터` 버튼과 활성 필터 수, 정렬만 둔다. 위험도·로그 역할·확인 순서는 사용자가 필터 버튼을 눌렀을 때 패널에 표시된다. 값은 선택 즉시 적용되며 별도 적용 버튼은 두지 않았다. `닫기`는 패널만 접고 현재 조건을 유지한다. 적용 조건은 compact chip으로 나타나며 각각 제거할 수 있다. 전체 초기화는 조건이 있을 때만 작은 보조 버튼으로 나타난다. 기본 순서에서는 결과 수를 간단히 표시하고, 조건을 적용하면 전체 수와 표시 수를 함께 표시한다.

`필터` 버튼은 `aria-expanded`와 `aria-controls`를 제공한다. Escape와 닫기 버튼으로 패널을 닫을 수 있고, 닫으면 버튼에 focus를 돌려준다. 각 chip 제거 버튼에는 조건을 식별하는 접근성 이름을 제공한다. 검색어 자체는 chip, 로그, URL 또는 DOM 속성에 복제하지 않는다.

## 기능·보안 계약

- 검색 허용 필드, AND 결합, stable sort, 시간 누락 처리, 세션 내 상세 왕복 상태 유지, 새 분석 초기화 등 Phase 36.13A 동작 계약을 유지했다.
- 검색 대상은 닫힌 안전 projection의 제목·유형·검증된 역할·요약이다. raw log, 계정, IP, hostname, path, `case_ref` 및 숨겨진 필드는 검색하거나 표시하지 않는다.
- 필터와 정렬은 현재 메모리 projection의 표시 순서만 바꾼다. parser, detection, relation, risk, case, report, API schema, checklist, input-quality summary는 변경하지 않는다.
- URL, local/session storage, IndexedDB, cookie에 검색·필터 상태를 저장하지 않는다. 목록 조작 및 route 이동으로 checklist POST를 보내지 않는다. 명시적인 checklist 조작 계약은 그대로다.
- 외부 UI 라이브러리·외부 asset·외부 요청을 추가하지 않았다. `innerHTML`로 검색어나 응답 값을 삽입하지 않는다.

## TDD·화면 검증

새 기본 밀도 assertion을 먼저 추가한 뒤 기존 상시 노출 UI에서 `QUEUE_COMPACT_DEFAULT_DENSITY_FAILED`를 재현했다. 패널·칩·접근성 계약을 구현한 후 `node tests/ui_review_queue_36_13a.mjs`가 `REVIEW_QUEUE_36_13A_PASS`로 통과했다. 자동 검증은 사용자 수용 응답을 대신하지 않는다.

격리된 Chromium에서 실제 앱의 synthetic sample API를 사용하고, 전용 임시 HOME/XDG 경로 및 loopback 서버로 캡처했다. 화면에는 `TEST_ONLY_SYNTHETIC_STATE`를 표시했다. 검수 캡처 과정은 sample POST 2회, checklist POST 0회, API 요청 4회, 외부 요청 0회, console/page error 0회였다. 320px reflow는 viewport 320px 및 root font 32px의 equivalent 상태로 확인했다.

캡처 파일은 모두 `docs/images/review-queue-36-13a1/` 아래에 있다.

1. `01-desktop-default-1440.png` — 기본 toolbar 및 첫 카드
2. `02-desktop-filter-panel-1440.png` — 필터 패널 열림
3. `03-desktop-two-chips-1440.png` — 활성 조건 두 개
4. `04-desktop-empty-1440.png` — 조건에 맞는 결과 없음
5. `05-mobile-default-390.png` — 390px 기본 toolbar
6. `06-mobile-filter-panel-390.png` — 390px 필터 패널
7. `07-mobile-chips-320.png` — 320px chip 줄바꿈
8. `08-mobile-reflow-320-200-equivalent.png` — 320px, 200% equivalent reflow

캡처는 고정 합성 sample의 결과이며 사용자 자료가 아니다. 카드 본문에는 기존 합성 fixture의 고정 날짜가 표시된다. 이 날짜는 실제 로그 시각을 뜻하지 않는다.

## 결과와 한계

- E2E에서 기본 패널 접힘, 필터 수와 개별 chip, 닫기/Escape focus 복귀, 검색·필터·정렬·초기화, detail 왕복 및 checklist POST 0을 검증했다.
- Phase 36.12C의 10개 synthetic UI 시나리오도 fresh isolated loopback server/HOME별로 재검증했다. 첫 묶음 실행은 하나의 서버를 재사용해 기존 요청 제한에 걸렸으므로 결과로 채택하지 않았다. `text-none`과 `parser-incompatible`의 고정 `PARSER_INCOMPATIBLE` 응답에서 발생하는 단일 분석 resource console 오류는 동일한 오류 계약으로 harness에 허용했다. 이 분류는 HTTP 400, 고정 오류 코드, 분석 요청 오류 1건 및 그 외 browser error 0건을 모두 요구하며 API를 변경하지 않는다.
- 기존 E2E axe 결과는 위반 0, 외부 요청 0, console/page error 0이었다. 1440/1024/768/390/320px과 320px 200% equivalent에서 가로 넘침 0을 검사했다. 실제 target은 CSS 최소 44px로 맞춘다.
- 합성 100-card fixture: DOM 452 nodes, 렌더 HTML 12,629 bytes. 현재 `frontend/app.js` 158,424 bytes, `frontend/review-queue-ui-36-13a.js` 10,950 bytes, `frontend/style.css` 74,903 bytes다. warm-up 5회 후 20회 측정에서 초기 렌더는 median/p95/max `0.3/0.6/0.6ms`, 검색 `0.1/0.2/0.2ms`, 복합 필터 `0.1/0.1/0.2ms`, 위험도 정렬 `0.1/0.2/0.2ms`, 제목 정렬 `0.7/0.9/0.9ms`, 초기화 `0.1/0.2/0.2ms`였다. 수치는 개발 환경의 관측치이지 운영 SLA가 아니다.
- 새 화면은 사용자 재검수 전이다. Phase 36.13B 검수를 새 화면으로 1/12부터 다시 시작해야 한다. Safari와 실제 모바일 기기는 `NOT_TESTED`; Ubuntu Linux 검증은 새 커밋 전이므로 `NOT_TESTED`다.
- rollback은 dashboard에 연결된 review queue CSS/DOM/adapter 변경을 되돌려 이전 renderer로 복원한다. 기존 검토 결과 projection과 API에는 migration이 없다.

실제 사용자 자료, 조직 운영, 자동 대응은 계속 `NO_GO`다. 모델 기반 AI는 사용하지 않았다.
