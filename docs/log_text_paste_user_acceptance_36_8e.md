# Phase 36.8E — 텍스트 직접 입력 사용자 수용 기록

## 판정

`PHASE_36_8E_TEXT_PASTE_USER_ACCEPTED`

사용자는 검수 질문 1–6, 8–10에 `PASS`라고 응답했습니다. 7/10은 최초 응답이 `NOT_TESTED`였고, 화면 검수 순서가 끝난 뒤 사용자가 후속으로 `PASS`라고 응답했습니다. 최초 `NOT_TESTED`와 후속 `PASS`를 모두 보존하며, 최종 문항 결과는 사용자의 명시적인 후속 응답 `PASS`입니다. 이 판정은 합성 데이터와 검수 당시 Chromium production UI 범위에 한정됩니다.

## 시작 Gate

- 기준 SHA: `0e6d314c8217dad1550350675a9d06fb796baf60`
- GitHub Actions Run: [40917009391](https://github.com/misosos/ai-security-log-analyzer/actions/runs/40917009391)
- 시작 확인: branch `main`; HEAD, local `main`, `origin/main`, GitHub `main`이 모두 기준 SHA와 일치; ahead/behind `0/0`; working tree clean.
- Run: exact SHA, `push / completed / success`, artifact 0개.
- 필수 Linux pytest, TCP Syslog, JSONL, restricted report, Chromium/axe 및 tracked-file invariant 단계가 성공한 것을 확인했습니다.
- `v0.4.0` tag와 Release target은 `eecd6ee1cda0545e34b01c42e1a2163a899bcc27`로 유지됐습니다.

## 검수 환경 및 범위

- 실제 FastAPI production app을 loopback `127.0.0.1:18767`에서 실행했습니다. 검수 주소: `http://127.0.0.1:18767/`.
- Chromium `156.0.8078.4`, device scale factor 1, 기본 zoom 100%를 사용했습니다.
- 격리된 임시 HOME에서 실행했습니다. 합성 fixture는 `sample_logs/brute_force.log`, `sample_logs/ssh_auth.log`, `sample_logs/web_shell.log`입니다.
- 외부 origin 요청과 browser page error는 관측되지 않았습니다. 실제 사용자·조직 자료, 실제 credential, 외부 SIEM/API/LLM, 자동 대응은 사용하지 않았습니다.
- 서버는 현재 검수 편의를 위해 실행 중입니다. 로컬 브라우저에서 위 loopback 주소를 열 수 있습니다.
- 최종 캡처와 manifest는 저장소 밖 `/tmp/phase-36-8e-user-review.N2VWKu/`에 있습니다. Manifest: `/tmp/phase-36-8e-user-review.N2VWKu/capture-manifest.json`.
- 추가 실제 SSH 상세/Timeline/Checklist 및 Access/보고서 캡처는 `/tmp/phase-36-8e-review.73gYoU/`에 있습니다. 이미지 파일은 저장소에 추가하지 않았습니다.
- 200% equivalent는 320 CSS px viewport에서 root font-size를 16px에서 32px로 설정해 검사했습니다. 이는 브라우저 native zoom이나 실제 모바일 기기 검증이 아닙니다.

## 사전 자동 검증 — `AUTOMATED_VERIFIED`

| 경로/상태 | 실제 출처 | 결과 |
|---|---|---|
| Application 텍스트 분석 | `REAL_LOOPBACK_API` | HTTP 200, 합성 fixture 결과 1 case / 2 independent observations |
| SSH 텍스트 분석 | `REAL_LOOPBACK_API` | HTTP 200, 1 case / 0 independent observations |
| SSH Checklist | `REAL_LOOPBACK_API` | 명시적 요청 POST 200, `available`, 4 steps; 요청 전 자동 POST 없음 |
| Access 텍스트 분석 | `REAL_LOOPBACK_API` | HTTP 200, 0 cases / 2 independent observations; 빈 사례를 안전 판정으로 취급하지 않음 |
| 기존 세 파일 업로드 | `REAL_LOOPBACK_API` | 기존 multipart endpoint HTTP 200; 텍스트 전용 범위 안내는 표시되지 않음 |
| 텍스트 HTML 보고서 | `REAL_LOOPBACK_API` | 명시적 다운로드 완료, 파일명 `investigation-report.html`; 보고서에 부분 입력 범위 안내 확인 |
| 잘못된 합성 SSH 형식 | `REAL_LOOPBACK_API` | HTTP 400, 고정 복구 안내 표시 |
| 빈 텍스트 입력 | `CLIENT_VALIDATION` | API 요청 없이 클라이언트 오류 표시 |
| 모드 전환/입력 정리 | `CLIENT_VALIDATION` | 취소 시 입력 보존, 승인 시 입력 정리 |
| Mock 상태 | `TEST_ONLY_MOCK` | 사용자 수용 화면에는 사용하지 않음 |

실제 파일 API와 텍스트 API의 호출은 서로 분리됐습니다. 보고서 다운로드는 자동으로 실행되지 않았습니다. 실제 테스트 관측 결과는 Application 1/2, SSH 1/0, Access 0/2였으며 예상 fixture 범위와 일치했습니다.

## 사용자 질문 및 원본 응답

아래 원본 응답은 사용자가 각 화면을 확인한 뒤 보낸 문자열입니다. 이유를 포함하지 않은 응답에 별도 이유를 만들어 붙이지 않았습니다.

| 번호 | 실제 제시 화면 및 출처 | 사용자 원본 응답 | 결과 |
|---|---|---|---|
| 1/10 입력 방식 전환 | Desktop 파일 기본 화면 및 텍스트 입력 화면; `REAL_LOOPBACK_API` assets, 모드 동작은 `CLIENT_VALIDATION` | `PASS` | `USER_ACCEPTED` |
| 2/10 Application 로그 분석 | Desktop Application 결과 및 범위 안내; `REAL_LOOPBACK_API`, HTTP 200 | `PASS` | `USER_ACCEPTED` |
| 3/10 SSH 로그와 조사 사례 | SSH 사례 Overview, Timeline, 요청 전 Tasks; `REAL_LOOPBACK_API` | `PASS` | `USER_ACCEPTED` |
| 4/10 Checklist | SSH 사례 Checklist; 명시적 POST 뒤 실제 `available`, HTTP 200, 4 steps; `REAL_LOOPBACK_API` | `PASS` | `USER_ACCEPTED` |
| 5/10 Access 로그 분석 | Access 결과; 0 case / 2 independent; `REAL_LOOPBACK_API`, HTTP 200 | `PASS` | `USER_ACCEPTED` |
| 6/10 HTML 보고서 | Access 분석의 다운로드 화면 및 보고서 범위 안내; `REAL_LOOPBACK_API` | `PASS` | `USER_ACCEPTED` |
| 7/10 오류와 복구 | 빈 입력 `CLIENT_VALIDATION`과 잘못된 형식 실제 API HTTP 400 `REAL_LOOPBACK_API` 화면 | 최초 `NOT_TESTED`; 검수 순서 종료 뒤 후속 `PASS` | 최초 기록 보존, 최종 `USER_ACCEPTED` |
| 8/10 390px 입력 화면 | Chromium 390×844 CSS viewport 캡처 | `PASS` | `USER_ACCEPTED` |
| 9/10 320px 입력·결과 화면 | Chromium 320×568 CSS viewport 캡처 | `PASS` | `USER_ACCEPTED` |
| 10/10 200% equivalent | 320×568 CSS viewport, root font-size 32px 캡처 | `PASS` | `USER_ACCEPTED` |

7/10은 최초에는 사용자 평가가 미완료였으나, 이후 사용자가 명시적으로 `PASS`라고 응답해 최종 결과에 반영했습니다. 최초 `NOT_TESTED`는 이력으로 남깁니다. Client validation과 실제 HTTP 400 응답은 별도로 표시했습니다. 4/10의 Checklist `available`은 Mock이 아니라 합성 사례에 대한 실제 로컬 API 응답입니다.

## 캡처 목록

전체 파일명, viewport, 출처, HTTP 응답, UI 상태, 질문 번호 및 생성 시각은 위 manifest에 기록했습니다. 주요 사용자 검수 캡처는 다음과 같습니다.

- Desktop 입력: `01-file-default.png`, `02-text-input-desktop.png`, `03-application-input-desktop.png`
- Desktop 실제 결과/오류: `05-application-result.png`, `06-ssh-result.png`, `07-ssh-case-overview.png`, `08-ssh-timeline.png`, `09-ssh-checklist-not-requested.png`, `10-ssh-checklist-actual.png`, `11-access-result.png`, `12-access-html-report-download.png`, `19-wrong-format-error.png`
- Mobile/equivalent: `08-input-390.png`, `09-input-320.png`, `07-application-case-detail-320.png`, `10-input-320-equivalent-200.png`, `06-application-result-320-equivalent-200.png`
- 클라이언트 오류: `11-empty-input-client-error.png`; 형식 오류 API 응답: `12-wrong-format-api-error.png`.

## 개인정보, 접근성 및 회귀

- 합성 입력 canary가 결과 UI, 오류 안내, 보고서, URL/storage 또는 외부 요청으로 확산되지 않는지 자동 검증했습니다. textarea와 명시적으로 보낸 loopback 요청 본문은 입력 원문이 존재할 수 있는 허용 경계입니다.
- 브라우저 외부 요청 0건, page error 0건을 기록했습니다. 검수 캡처에 민감 원문은 포함되지 않았습니다.
- `npm run test:a11y --silent`: 25개 상태, axe violation 0, 외부 요청 0. viewport 및 equivalent reflow 자동 검사 통과.
- `uv run pytest -q`: 3169 passed, 2 warnings.
- `uv sync --locked --dev`, `uv lock --check`, `node --check frontend/app.js`, `python3 -m compileall -q app tests` 성공.
- 파일/텍스트 입력, Checklist, Timeline, Guidance, HTML 보고서와 기존 renderer 동작은 검수 중 유지됐습니다. 기존 renderer 결정은 `KEEP_LEGACY`이며 `USE_WORKSPACE_DETAIL_SHELL_36_6B`를 변경하지 않았습니다.
- 이 자동 검증은 사용자 평가를 대신하지 않습니다. 오류/복구 문항의 최초 `NOT_TESTED`는 이력으로 남겼고, 후속 사용자 응답은 `PASS`입니다.

## 미검증 범위 및 보안 경계

- 실제 사용자 자료, 실제 조직 운영, 자동 대응: `NO_GO`.
- 모델 기반 AI: `NOT_TESTED`.
- Safari, VoiceOver, browser native zoom, 실제 모바일 기기: `NOT_TESTED`.
- Vector/VM: `USER_ACTION_REQUIRED / ISOLATION_BLOCKED`.
- OS-level hard memory cap 및 강제 종료 후 secure erase는 보장하지 않습니다.
- 자동 테스트는 실제 운영 적합성이나 사용자 검수를 증명하지 않습니다.

## 최종 상태

사용자 10개 문항 최종 응답은 모두 `PASS`입니다. 필수 로컬 자동 검증도 통과했으므로 판정은 `PHASE_36_8E_TEXT_PASTE_USER_ACCEPTED`입니다. 이는 실제 사용자 자료, 조직 운영, 자동 대응 또는 실제 모바일/Safari/VoiceOver 검증을 승인하지 않습니다. 기존 renderer는 `KEEP_LEGACY`로 유지합니다.
