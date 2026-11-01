# Phase 36.13A — 검토 큐 검색·필터·정렬

## 목적과 범위

검토 건이 많을 때 이미 승인된 브라우저 메모리 projection에서 항목을 찾고 정렬하도록 dashboard 목록에 검색, 필터, 정렬을 추가한다. 이 기능은 분석 결과의 탐색만 돕는다. Detection, relation, risk, case, checklist, report, checkpoint, publication, SSE 또는 API schema를 변경하지 않는다.

## Projection과 검색 범위

목록은 `investigation-workspace-ui/v1`의 기존 19개 필드 projection을 사용한다. 원본 response의 전체 객체를 검색하거나 직렬화하지 않는다. 검색 corpus는 표시용 `display_title`, 고정 category label, 검증된 source role의 고정 한국어 label, 고정 안전 요약만 메모리에서 결합한다. `case_ref`, 사용자·계정, IP, hostname, 로그 원문, 경로, checkpoint, timestamp, citation은 검색 대상에서 제외하며 숨겨진 DOM이나 data attribute로 복제하지 않는다.

검색은 앞뒤 공백 제거, Unicode NFKC 정규화와 locale 비의존 소문자 변환을 거친 부분 문자열 비교다. 입력은 100 UTF-16 code unit 이내이고 제어·방향 제어 문자는 제거한다. 검색어는 HTML, URL, logger 또는 저장소에 기록되지 않는다. 결과 highlight는 제공하지 않는다.

## 필터 및 정렬 의미

- 위험도는 기존 `HIGH`, `MEDIUM`, `LOW` 값만 비교한다.
- 역할은 `application`, `ssh`, `access`, `unknown`만 비교한다. 상세 checklist를 명시적으로 요청하기 전 projection 역할은 `unknown`이다. 입력 파일 종류로 사례 역할을 추정하지 않는다.
- 확인 순서는 기존 `review_now`, `review_soon`, `review_later`, `undetermined`를 재사용한다. checklist 검증 응답 전에는 `undetermined`로 둔다. unknown/undetermined는 낮은 위험이나 검토 불필요를 의미하지 않는다.
- 검색과 세 필터는 AND 결합이며 결과 수는 전체 항목 수와 표시 항목 수를 함께 나타낸다. 0건이면 조건 안내와 초기화 버튼을 표시하고, 분석 결과가 없거나 안전하다는 뜻이 아니라고 설명한다.
- 정렬은 기본 검토 순서, 위험도 높은 순, 최근 관찰 순, 오래된 관찰 순, 제목 순이다. 동률은 기존 표시 순서를 보존한다. 최근/오래된 순은 projection 검증을 통과한 종료 관찰 UTC 값을 사용하고, 종료 시각이 없거나 불완전한 항목은 양방향 정렬 모두 마지막에 둔다. 시작 시각만 있는 항목의 종료 시각은 추정하지 않는다. 기본 정렬은 기존 카드 순서를 보존한다.

위험도와 확인 순서는 별개다. 필터는 항목을 숨겨 볼 뿐 데이터를 삭제하거나 risk/priority를 변경하지 않는다.

## 상태 수명과 개인정보

검색·선택 값은 현재 문서 메모리에만 둔다. 새 분석, 결과 초기화, stale projection 만료 시 기본 상태로 돌아간다. 같은 분석 세션에서 상세 화면에 갔다가 뒤로 돌아오면 상태를 유지한다. reload 또는 직접 stale route 진입 시 이전 목록 상태를 복구하지 않는다. URL, localStorage, sessionStorage, IndexedDB, cookie, checkpoint, report 저장은 사용하지 않는다.

상세 링크는 기존 opaque `case_ref` hash route를 유지한다. 목록·검색·필터·정렬은 추가 API 요청을 하지 않으며 checklist POST는 기존의 명시적 사용자 동작에서만 발생한다. 입력 품질 요약은 별도 dashboard 영역에 남는다. `PARSER_INCOMPATIBLE` 및 legacy response 동작은 기존 UI 계약을 따른다.

새 `review-queue-ui-36-13a.js`는 기존 개별 정적 자산의 160 KiB 상한 때문에 별도 same-origin 고정 asset으로 제공한다. 파일 경로는 기존 `_fixed_asset` 경계 안의 literal allowlist route만 추가했다. API schema와 CSP는 바뀌지 않았다. 자산 크기: `app.js` 158,424 bytes, 검토 큐 helper 6,471 bytes, stylesheet 71,497 bytes.

## 검증

TDD 브라우저 계약은 UI 컨트롤 부재로 먼저 `QUEUE_CONTROLS_MISSING`에 실패했다. 이어 static asset 상한으로 `app.js`가 제공되지 않는 상태를 확인해 로직을 별도 asset으로 분리하고 기존 fixed asset 경로를 확장했다.

Production UI 합성 sample에서 검색, risk/role/priority 필터, AND 결합, 시간·제목 정렬, reset, 상세 route와 뒤로 복원을 확인했다. sample 경로에서 API 요청은 분석 2건뿐이고 checklist POST 0건, 외부 요청 0건, 브라우저 오류 0건이었다. Playwright Chromium·axe 위반은 0건이었다. 1440, 1024, 768, 390, 320 CSS px와 320 px에서 200% equivalent reflow에 가로 overflow가 없고 컨트롤 target 높이는 최소 44 CSS px였다.

별도 100건 합성 projection fixture는 초기 render, 검색, 복합 필터, risk sort, title sort, reset을 각각 5회 warm-up 후 20회 측정했다. Chromium 개발 환경 관측치는 다음과 같으며 운영 SLA가 아니다.

| 작업 | median ms | p95 ms | max ms |
|---|---:|---:|---:|
| 초기 렌더 | 0.3 | 0.5 | 0.5 |
| 검색 반영 | 0.0 | 0.1 | 0.1 |
| 복합 필터 | 0.0 | 0.1 | 0.1 |
| 위험도 정렬 | 0.1 | 0.1 | 0.2 |
| 제목 정렬 | 0.6 | 0.7 | 0.8 |
| 전체 초기화 | 0.1 | 0.1 | 0.2 |

Fixture 관측: DOM 444 nodes, HTML 12,057 bytes, 검색 길이 상한 100 UTF-16 code units. 역할별 필터 25건, priority별 필터 25건, 복합 조건 1건, NFKC·한글 정규화 검색, tie 안정성, 종료 시각 기준 정렬과 무시각 마지막 배치, privacy canary 미노출을 확인했다. 종료 시각 정렬 입력은 역순의 종료 시각과 시작 시각을 사용해 key 선택을 검증했다.

고정 frontend 자산 크기: `app.js` 158,424 bytes, 검토 큐 helper 6,543 bytes, stylesheet 71,497 bytes. 기존 자산 상한을 높이지 않았다.

기존 입력 품질/UI navigation·API·parser·checklist·report 회귀와 전체 자동화는 별도 실행 결과로 기록한다. macOS Chromium의 responsive reflow 검증은 실제 모바일 기기 검증이 아니다. Safari, 실제 모바일, 새 커밋의 Ubuntu CI는 `NOT_TESTED`다.

## Rollback 및 다음 단계

변경을 되돌리려면 이 Phase 커밋을 revert한다. 검색·필터 자산 route와 마크업을 제거하면서 기존 `app.js`의 review queue 연결을 함께 되돌린다. 기존 API, Parser, 분석 규칙은 변경하지 않았다.

Phase 36.13B에서는 합성 상태 사용자 수용 검수를 진행한다. 검토 완료 저장, 담당자, 메모 또는 서버 저장은 별도 설계가 필요하다.

실제 사용자 자료, 조직 운영과 자동 대응은 계속 `NO_GO`다. 모델 기반 AI는 사용하지 않았다.

## 최종 판정

`PHASE_36_13A_REVIEW_QUEUE_CONTROLS_LOCAL_CONDITIONAL_GO`는 로컬 계약 통과 시에만 사용한다. Ubuntu CI 및 사용자 수용 검수 전 production 운영 승인으로 해석하지 않는다.
