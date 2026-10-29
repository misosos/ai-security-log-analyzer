# Phase 36.6E — 확인 작업·근거·명시적 점검표 이식

## 시작 gate

- 시작 SHA: `05c5bc73b1ae81d6e8b943f18ed5f1e715434f87`
- branch: `main`; 시작 시 working tree clean
- local `HEAD`, `main`, `origin/main`, GitHub remote `main`이 모두 시작 SHA였고 `origin/main...HEAD`는 0/0
- GitHub Actions run `40823601898`: exact SHA, `push / completed / success`, artifact 0개
- locked 설치, 전체 pytest, Linux checkpoint·SSH·TCP Syslog·JSONL·restricted report, Node·Chromium·axe, tracked-file 불변 단계 성공
- `v0.4.0` tag와 Release target은 `eecd6ee1cda0545e34b01c42e1a2163a899bcc27` 유지

## 범위와 기존 계약

Phase 36.6D 상세 화면에 `확인할 작업`과 `근거와 한계` 탭을 추가했다. 기존 `개요`, `활동 흐름`, dashboard, API, HTML report, 분석 pipeline, checklist v2 응답 schema는 유지했다. 이전 상세 렌더러와 `USE_WORKSPACE_DETAIL_SHELL_36_6B` rollback switch도 남아 있다.

`investigation-workspace-ui/v1`의 19개 필드와 `investigation-workspace-timeline-ui/v1`은 변경하지 않았다. 분석 한계 수는 기존 projection의 `limitation_count`만 사용하며 오직 **분석 한계**로 표시한다. 작업 수는 checklist 응답 전 표시하지 않는다. `unverified_items`, `limitations`, checklist steps를 합산하거나 서로 바꾸어 쓰지 않는다.

Checklist 요청은 기존 `POST /api/v1/investigations/checklist`와 `{schema_version: 1, case_ref}` 형식을 사용한다. 응답은 기존 `validateChecklistResponse`를 통과한 `investigation-checklist/v2`만 화면에 반영한다. 기존 source role과 review priority는 검증된 응답이 도착한 뒤에만 일시적인 화면 상태로 표시하고 frozen projection이나 risk에는 기록하지 않는다. `unknown`과 `undetermined`는 낮은 위험·안전·검토 불필요가 아니다.

## 작업 선택과 상태

요청 전에는 고정 안내와 `확인할 작업 불러오기`만 표시한다. task list는 생성되지 않으며 task count도 표시하지 않는다. 버튼을 한 번 누르면 기존 opaque case reference로 POST 한 건을 보내고, 응답이 검증된 경우 번호형 작업 목록과 선택된 작업 하나의 상세를 표시한다. 선택은 `aria-pressed`로 표현하며 키보드 Enter로 바꿀 수 있다. 선택 변경은 로컬 화면 상태만 바꾼다. 완료 checkbox, 완료율, 저장, 실제 대응 동작은 없다.

화면 상태는 기존 응답·오류를 다음처럼 제한된 UI 상태로 매핑한다.

| 화면 상태 | 의미와 표현 |
| --- | --- |
| `not_requested` | 요청 전. 작업 개수나 결과를 추정하지 않음 |
| `loading` | 요청 처리 중. 버튼 비활성화, polite live status 제공 |
| `available` | 검증된 작업만 표시 |
| `refused` | 승인 근거 부족. 안전 판정이 아니며 기존 분석과 승인된 내부 경로 확인 안내 |
| `unavailable` | 응답 또는 승인 근거 검증 불가. 위협 부재를 뜻하지 않음 |
| `error` | timeout·rate limit·busy 및 일반 요청 오류. 고정 문구와 명시적 재시도 |
| `stale` | 기존 `NOT_FOUND`. 최신 분석에서 다시 선택하도록 안내 |

오류 본문과 예외 문자열은 출력하지 않는다. 재시도는 사용자가 버튼을 다시 누른 경우만 가능하다. 중복 클릭은 요청이 진행되는 동안 차단한다.

## 근거·citation·guidance

근거 탭은 projection의 분석 한계 수와 고정된 해석 설명을 사용한다. 원본 증거와 원문 로그는 화면에 넣지 않는다. 한계 상세는 safe mapping에 포함된 문구만 표시하며 그 외 자유 문자열은 숨긴다. 상세 기술 정보와 citation ID는 접근 가능한 `<details>`에 둔다.

Checklist citation은 해당 task의 검증된 `citation_ids`에 연결한다. ID subset·중복·응답 전체 citation 사용 여부는 기존 validator가 확인하며, 목적 코드는 고정 한국어 mapping으로만 표시한다. citation 제목·요약은 DOM text로 표시하고 HTML로 해석하지 않는다. 사용자에게 일반 조사 참고자료이며 해당 검토 건의 직접 증거가 아닙니다라고 분명히 알린다.

Guidance는 기존 `renderGuidance`, `validateGuidanceResponse`, corpus digest 및 endpoint를 재사용한다. `근거 도움말 보기`를 눌렀을 때만 POST한다. Tab 선택·focus·hover·disclosure만으로 요청하지 않으며, checklist 결과를 guidance 입력으로 보내거나 결과를 서로 합치지 않는다.

## 비동기 사례 격리

각 요청은 화면을 만든 analysis generation, 동일한 frozen projection 객체, 동일한 validated case object, 현재 opaque route reference 및 최신 요청 번호를 확인한 후에만 DOM을 갱신한다. 사례 전환·상세 재진입·목록 복귀·분석 초기화 뒤 늦게 도착한 응답은 버린다. 오래된 shell은 DOM에서 제거되고 다른 사례의 역할·우선순위·작업·citation·상태로 재사용되지 않는다. Guidance 요청에도 동일 화면 identity guard를 적용했다.

브라우저 검증에서 사례 A의 checklist 응답을 300ms 지연시키고 응답 전에 사례 B로 이동했다. 요청은 A의 reference 한 건으로 유지됐고, 응답 후에도 B는 `not_requested`, `역할 미확인`, `확인 순서 미정`을 유지했으며 A의 작업 내용은 B 화면에 나타나지 않았다.

## TDD와 검증

Production 변경 전 추가한 browser contract는 기존 shell에 task/evidence 탭이 없어 `WORKSPACE_TASKS_EVIDENCE_TABS_MISSING`으로 실패했다(RED). 구현 후 탭·panel ARIA 연결, request 전 task 미생성, 버튼 연타 시 POST 1회, master-detail 선택, keyboard 선택, 별도 risk/role/priority, citation 의미, 분석 한계 count, 명시적 guidance 요청 및 async A→B 격리를 확인했다.

Browser contract는 available·refused·stale·timeout·rate limit·unavailable·closed-schema 오류·citation subset 오류를 검사한다. 잘못된 응답은 고정 unavailable 안내로 닫히며 canary가 DOM에 나타나지 않는다. 기존 `renderChecklist`와 `renderGuidance` 경로는 삭제하지 않았고 rollback 회귀도 유지한다.

Chromium·axe는 기존 23개 상태와 작업/근거의 새 상태를 검사했다. 완료 실행은 `external_requests=0`이었고 axe 위반은 0이었다. 작업 선택은 키보드로 가능하고 탭은 ArrowLeft/ArrowRight/Home/End를 사용한다. checklist 요청 전에는 탭 전환·상세 이동·목록 복귀에서 POST가 없고, explicit 버튼 클릭은 1회당 POST 1건이다. 브라우저에서 최초 클릭은 1건, 연속 3회 DOM click도 1건, 사례 A→B 늦은 응답 경쟁은 A용 1건으로 기록했다. Guidance 요청도 별도 버튼 클릭 1건으로만 발생한다.

320px 포함 1440/1024/768/390/320 CSS viewport에서 task panel의 가로 overflow가 없었다. 320px·200% equivalent reflow에서도 overflow가 없고 작업 선택 대상은 44px 이상이었다. 이는 Chromium 자동 측정이며 Safari 또는 실제 모바일 검수가 아니다.

## 정적 asset 상한

신규 UI를 포함한 `frontend/app.js`는 128 KiB fixed asset 상한보다 커 브라우저에서 `/assets/app.js`가 404가 되는 것을 확인했다. 안전 경계를 고정된 bounded asset으로 유지하면서 상한을 160 KiB로 조정했고 문서와 기존 oversized asset 테스트는 새 상한을 따르도록 유지했다. 현재 앱 스크립트는 160 KiB 이내이며 request 경로가 파일 선택에 영향을 주지 않는다. 외부 자산·dependency는 추가하지 않았다.

## 성능 관측

합성 Chromium benchmark는 warm-up 10회 후 100회 측정했다. 아래 값은 개발 환경의 관측치이며 운영 SLA나 최악 지연 보장이 아니다.

- projection 준비 (고정 projection 합성 1/32/256 cases, warm-up 10/표본 100):
  - 1: median/p95/max `0.2/0.3/0.3 ms`, input `5,396 B`, output `663 B`
  - 32: `0.7/0.8/1.0 ms`, input `172,672 B`, output `21,185 B`
  - 256: `4.1/4.4/4.5 ms`, input `1,381,376 B`, output `169,473 B`
- Timeline projection/render proxy 1/32/256개: projection `0.1/0.2/0.3`, `0.4/0.6/0.6`, `2.9/3.1/3.8 ms`; render `0.7/0.8/0.9`, `1.5/1.8/1.9`, `8.4/9.0/9.2 ms` median/p95/max. 이는 task 개수 benchmark가 아니다.
- 검증된 단일-step checklist response는 `910 B`, task panel은 24 descendant DOM node와 2,207 serialized HTML bytes였다. Tasks↔Evidence panel 전환은 warm-up 10회/표본 100회 `0.1/0.1/0.2 ms` median/p95/max였다. 실제 API 대기시간은 이 UI-only 값에 포함하지 않는다.
- checklist v2는 steps 최대 5개로 제한하므로 32/256 task를 생성해 측정하지 않는다. 1/32/256은 cases projection 처리와 별도로 구분한다.
- dashboard↔detail 관측은 기존 route loop에서 2회 warm-up/8회 표본으로 `96.258/100.459/100.459 ms`였다. 이는 36.6C 동일 실행 기준 route 수치가 아니므로 직접 비교 성능 개선·악화 결론에 사용하지 않는다.

## 파일 제공·검증 범위

`frontend/app.js`가 기존 128 KiB 제공 상한을 넘으면서 고정 asset 제공기가 수정됐다. `app/web_ui.py` 상한은 160 KiB로 제한된 상태다. API route/schema, OpenAPI, SSE, report, guidance corpus, checkpoint, publication, 분석 DTO와 projection schema는 변경하지 않았다.

로컬 Chromium·axe/browser test는 macOS에서 실행했다. Linux 전용 TCP Syslog·JSONL·restricted report acceptance는 새 변경 SHA의 CI가 아직 없으므로 이번 로컬 단계에서는 `NOT_TESTED`로 기록한다. 시작 SHA의 CI 성공은 이번 커밋의 CI 증거로 간주하지 않는다.

## 남은 작업과 상태

- 36.6F: 320px·200% reflow·접근성·target-size 최종 수용
- 36.6G: 새 작업공간의 사용자 최종 수용과 기존 renderer 제거 여부 결정
- Safari·실제 모바일: `NOT_TESTED`
- 실제 사용자 자료·조직 운영·자동 대응: `NO_GO`
- 모델 기반 AI: `NOT_TESTED`
- Vector/VM: `USER_ACTION_REQUIRED / ISOLATION_BLOCKED`

이번 Phase는 제한된 합성 데이터에서 검증된 조사 안내를 명시적으로 요청해 표시하는 UI 이식이며 실제 조직 운영 승인이 아니다.
