# Phase 36.12C — 입력 품질 UI 사용자 수용 검수

## 결과

판정: `PHASE_36_12C_INPUT_QUALITY_UI_USER_ACCEPTED_LOCAL_CONDITIONAL_GO`

10개 화면 이해도 질문에 사용자가 모두 `PASS`로 응답했다. 기능/UI 수정은 없었으며, 기록용 브라우저 하네스만 추가했다. 이번 판정은 격리된 로컬 Chromium 합성 검수 범위다. 이 기록을 운영 승인으로 해석하지 않는다.

## 기준 커밋과 검수 환경

- 검수 대상 SHA: `63fb8181c6e943b17c93c662aca1f3d6df34686d`
- 대상 커밋: `feat: show deterministic log input quality summary`
- exact push CI run: [41285919625](https://github.com/misosos/ai-security-log-analyzer/actions/runs/41285919625) — `push / completed / success`
- 검수 시작 시 main/local main/origin main/GitHub main이 대상 SHA였고 작업 트리가 clean, ahead/behind `0/0`이었다.
- run의 전체 pytest는 `3588 passed, 2 warnings`; TCP Syslog 기본·Linux reliability·management, JSONL Linux acceptance, Restricted Report Linux smoke, Chromium/axe `states=25 external_requests=0`, tracked-file 불변 검사가 성공했고 artifact는 0개였다.
- `v0.4.0` tag와 GitHub Release는 모두 기존 target `eecd6ee1cda0545e34b01c42e1a2163a899bcc27`을 가리켰다.
- 실제 Production UI와 API를 사용하고 loopback 주소, 전용 임시 HOME/data, 격리 Chromium profile을 사용했다. 입력은 합성 fixture뿐이었다. 외부 요청은 모두 차단했고 관측치는 0건이다.
- test-only projection을 사용한 화면에는 `TEST_ONLY_SYNTHETIC_STATE`를 표시했다. 이 fixture는 실제 API 결과를 뜻하지 않는다.

## 상태별 화면 생성

- 파일 `complete`: 기존 3개 파일 계약으로 실제 업로드 요청을 보냈고 실제 API가 반환한 요약을 표시했다.
- 파일 source 혼합 `partial`: 실제 파일 분석 응답의 품질 projection만 same-origin 테스트 route에서 합성 상태로 바꾸었다. aggregate는 `partial`; application은 `complete`, SSH는 `partial`, access는 `none`이다. 화면에 기존 분석 카드 1건도 함께 남아 요약과 결과가 분리됨을 확인했다. `TEST_ONLY_SYNTHETIC_STATE` 표기.
- 텍스트 `complete`: 실제 텍스트 분석 경로와 단일 application source로 확인했다.
- 텍스트 `partial`: 실제 분석 응답에 test-only projection을 사용해 인식/미인식 혼합 상태를 표시했다. `TEST_ONLY_SYNTHETIC_STATE` 표기.
- 텍스트 `none`: 같은-origin 합성 projection으로 표시했다. 실제 API의 입력 호환성 결과와 혼동되지 않도록 `TEST_ONLY_SYNTHETIC_STATE` 표기.
- 텍스트 `empty`: 실제 API는 빈 입력에 대해 기존 입력 검증을 유지하므로 empty 성공 summary를 생성하지 않는다. 제한된 UI fixture projection으로 화면 의미만 검수했고, `TEST_ONLY_SYNTHETIC_STATE`를 표시했다.
- `PARSER_INCOMPATIBLE`: 실제 텍스트 API의 HTTP 400과 오류 응답 summary를 확인했다. 오류 및 제한 summary만 보이고 dashboard와 사례는 표시되지 않았다. 성공 결과로 바뀌지 않았다.
- legacy response: 실제 성공 응답에서 품질 필드만 제거한 test-only response를 사용했다. 기존 dashboard는 표시되고 품질 요약은 생성되지 않았다. `TEST_ONLY_SYNTHETIC_STATE` 표기.

## 사용자 이해도 질문과 최초 응답

화면을 먼저 보여주고 각 질문을 한 번에 하나씩 진행했다. 최초 응답과 최종 응답이 동일하며 FAIL/NOT_TESTED 응답은 없었다.

| # | 검수 주제 | 최초 응답 | 최종 응답 |
|---|---|---|---|
| 1 | 기능 목적: 입력 형식 인식 범위이며 안전/공격 판정이 아님 | PASS | PASS |
| 2 | 모두 인식이 안전 또는 무위협 판정이 아님 | PASS | PASS |
| 3 | 일부 인식이 일부 침해를 뜻하지 않음 | PASS | PASS |
| 4 | 인식 실패가 위협 없음/탐지 없음이 아님 | PASS | PASS |
| 5 | empty가 정상·안전 상태가 아님 | PASS | PASS |
| 6 | 줄 수와 인식 수가 탐지/공격/위험도 건수가 아님 | PASS | PASS |
| 7 | source별 상태는 독립적임 | PASS | PASS |
| 8 | 이유 category는 집계이며 원문/직접 증거가 아님 | PASS | PASS |
| 9 | 요약은 탐지·관계·위험도·사례와 별도 정보임 | PASS | PASS |
| 10 | 합성 검증, 개인정보 비표시, 운영 승인 아님 | PASS | PASS |

FAIL 및 재검수: 없음. NOT_TESTED 사용자 문항: 없음.

## 화면 캡처

각 링크는 전체 화면을 먼저 포함한다. 혼합/none/empty/legacy projection 캡처는 test-only 표시를 화면에 포함한다.

- 1440px 파일 업로드 모두 인식: [화면](images/input-quality-36-12c/file-upload-complete-1440.png)
- 1440px 파일 업로드 일부 인식: [화면](images/input-quality-36-12c/file-partial-1440.png)
- 1440px 사유 disclosure 열림: [화면](images/input-quality-36-12c/file-reasons-open-1440.png)
- 1440px 텍스트 모두 인식: [화면](images/input-quality-36-12c/text-complete-1440.png)
- 1440px 텍스트 일부 인식: [화면](images/input-quality-36-12c/text-partial-1440.png)
- 1440px 텍스트 인식하지 못함, test-only: [화면](images/input-quality-36-12c/text-none-fixture-1440.png)
- 1440px 텍스트 분석할 내용 없음, test-only: [화면](images/input-quality-36-12c/text-empty-fixture-1440.png)
- 1440px 실제 `PARSER_INCOMPATIBLE`: [화면](images/input-quality-36-12c/parser-incompatible-1440.png)
- 390px 파일 일부 인식: [화면](images/input-quality-36-12c/file-partial-390.png)
- 390px reason disclosure: [화면](images/input-quality-36-12c/file-reasons-open-390.png)
- 320px 텍스트 인식하지 못함, test-only: [화면](images/input-quality-36-12c/text-none-320.png)
- 320px, root font 32px equivalent reflow: [화면](images/input-quality-36-12c/text-none-320-200-equivalent.png)

## 개인정보, 보안, 분석 불변

- 합성 canary는 응답이든 test-only 상태든 화면, DOM text, 접근성 이름, title 및 검사된 data attribute에 나타나지 않았다.
- 원문 로그, 계정, IP, hostname, 파일명/경로, 원 로그 timestamp, command/URL/query, credential/token, 예외 repr은 품질 UI 출력에 나타나지 않았다.
- HTML은 기존 안전 DOM helper와 `textContent` 기반 rendering을 사용한다. 외부 요청은 0건이며 외부 AI/모델 호출은 하지 않았다.
- 결과 화면 이동으로 새 분석 API 요청을 보내지 않았다. 기존 navigation/checklist 계약 및 명시적 checklist POST 경로는 별도 회귀 테스트로 유지됐다.
- Parser, request/response schema, detection, relation/correlation, risk, case, review priority, checklist, report, checkpoint, publication, SSE에는 변경이 없었다.
- `PARSER_INCOMPATIBLE` 검수에서 서버의 HTTP 400은 유지됐다. Chromium은 이 의도된 API 400 응답으로 `console_errors=1`(resource category)을 기록했다. JavaScript page error는 0, 외부 요청은 0이었다. 따라서 해당 오류 상태를 포함해 전체 console error 0이라고 주장하지 않는다.
- 자동 대응 0, 실제 조직 로그 0, 모델/Gemini/embedding 요청 0.

## 접근성, 반응형, 자동 검증

- `npm run test:a11y --silent`: 25 state, axe 위반 0, `external_requests=0`; 1440/1024/768/390/320 및 equivalent 200% reflow 검사 성공.
- UI Navigation E2E: 통과, CSP 확인, 외부 요청 0, 미요청 checklist POST 0, back/forward route 동작 유지.
- UI 품질 focused E2E: 통과, `axe_violations=0`, `external_requests=0`. 키보드 Space로 details disclosure를 열고 `:focus-visible`을 확인했다.
- 수용 화면 브라우저 검증: 1440/1024/768/390/320px에서 수평 overflow 0. 320px equivalent 200%에서는 root font 32px, 품질 패널이 viewport 안에 있고 document width 320px로 확인했다. 합성 테스트 배너는 하네스 스타일에서만 줄바꿈 처리했다.
- 390px disclosure: 키보드 열기 성공, focus-visible 표시.
- UI screenshot harness의 rendering 관측은 상태별 warm-up 5회 후 10회 측정이다. 1440px에서 complete 35 DOM nodes/1119 bytes, file partial 47/1538, text none 31/1163, disclosure open 47/1546; JS clock 관측 median 0–0.1ms, p95 0.1–0.2ms, max 0.1–0.2ms였다. 이는 개발용 renderer 측정이며 브라우저 전체 paint SLA가 아니다.
- Phase 36.12B의 30 measured-sample benchmark도 재실행했다. complete: median/p95/max 0.3/0.4/0.4ms, DOM 42, HTML 1431 bytes; partial: 0.3/0.3/0.3ms, DOM 42, 1469 bytes; disclosure open: 0.2/0.3/0.4ms, DOM 32, 1280 bytes; text none: 0.2/0.3/0.3ms, DOM 32, 1299 bytes. 각 상태 warm-up 5회, 측정 30회, viewport 1440px였다. 측정은 합성 화면의 개발용 관측치다.
- 일반 검증: `uv sync --locked --dev`, `uv lock --check`, `npm ci --ignore-scripts`, Python compile, Node syntax, `git diff --check` 성공.
- Python full suite: `3588 passed, 2 warnings`.
- focused input-quality/API/parser/SSH/live/checklist/navigation/restricted-report suite: `344 passed, 2 warnings`; 추가 checklist+SSH focused run `67 passed, 2 warnings`; restricted report focused `32 passed`.
- Evaluation: synthetic boundary `79/79`, Linux evaluation `21/21`, risk `70/70`, case `70/70`, Phase 36.1 `44/44`, Phase 36.2 `24/24`; parser evaluation 기준 `195/200` 기록도 보존됐다.
- TCP Syslog base, management, JSONL runtime smoke 성공. TCP Syslog Linux reliability, JSONL Linux acceptance, Restricted Report Linux smoke는 대상 SHA의 exact CI에서 성공했으나 현재 로컬 검수 커밋은 아직 Ubuntu CI가 없다.

## 제한 및 운영 경계

- 이 사용자 수용은 합성 자료 기반 격리 Chromium 화면 검수다. 새 로컬 커밋의 Ubuntu CI 검증은 `NOT_TESTED`이며, macOS에서 Linux 전용 smoke를 대신했다고 주장하지 않는다.
- Safari: `SAFARI_NOT_TESTED / USER_HOME_ISOLATION_BLOCKED`. 실제 모바일 기기: `NOT_TESTED`.
- 입력 인식 상태는 로그 수집 완전성, 위협 여부, 탐지 정확도 또는 데이터 신뢰도를 의미하지 않는다.
- 실제 사용자 자료: `NO_GO`; 조직 운영: `NO_GO`; 자동 대응: `NO_GO`; 모델 기반 AI: `NOT_TESTED`.
- 다음 단계에서는 새 커밋의 exact-SHA Ubuntu CI를 확인한 뒤, 별도 승인된 Phase에서 실제 조사자 이해도 피드백과 Safari/실기기 경계를 다룬다.
