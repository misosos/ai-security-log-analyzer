# Phase 36.8C — Frontend 로그 텍스트 직접 입력

## 1. 범위와 시작 Gate

이 Phase는 Phase 36.8B의 로컬 텍스트 API를 production Frontend에 연결한다. Backend, API schema, Parser, Detector, Correlation, Risk, Case projection은 변경하지 않았다. 기존 파일 업로드와 조사 작업공간을 보존했다.

| 확인 | 결과 |
|---|---|
| 기준 SHA | `871e7370aa91dc07508ee44a1e07a6c70ab2a668` |
| 기준 Run | `40901906174` |
| branch / HEAD / local main / origin/main | `main` / 기준 SHA 일치 |
| GitHub main 및 ahead/behind | 기준 SHA 일치 / 0·0 |
| CI | `push / completed / success` |
| artifact | 0개 |
| 필수 CI job | pytest, TCP Syslog, JSONL, restricted report, Chromium·axe, tracked-file 성공 |
| `v0.4.0` Release target | `eecd6ee1cda0545e34b01c42e1a2163a899bcc27` 유지 |

## 2. 입력 방식과 입력 수명

`내 로그 분석`에 입력 방식 radio를 추가했다. 기본 선택은 파일 업로드이며 기존 `application_file`, `ssh_file`, `access_file` 세 파일 필수 계약과 `/api/v1/investigations` multipart 요청을 유지한다. 텍스트 모드에서는 세 파일 필드셋을 숨기고 비활성화해 그 필드의 필수 조건이 제출을 막지 않게 했다.

텍스트 모드는 고정된 source 값을 가진 select와 다중 행 textarea를 사용한다. 표시명은 `애플리케이션 인증 로그`, `SSH 인증 로그`, `웹 접근 로그`이며 API enum은 각각 `application`, `ssh`, `access`다. 사용자 문자열로 enum을 만들지 않는다. UTF-8 바이트, 줄 수와 줄별 바이트 수를 숫자로만 표시하며 32 KiB 텍스트, 96 KiB JSON 요청, 512줄, 한 줄 2048바이트를 클라이언트에서 편의상 검사한다. 서버 검증은 계속 최종 권한이다.

모드 전환 시 현재 모드에 입력이 있으면 폐기 확인을 받는다. 취소 시 입력과 선택을 보존하고, 승인 시 이전 입력과 해당 오류를 지운다. 입력 지우기와 내비게이션을 통한 입력 화면 이탈, 페이지 이탈 때 textarea를 비운다. 서버 오류 시에도 최소 보존을 우선해 입력을 지우며 고정 오류 안내와 필드 연결을 표시한다. 성공 시 textarea를 비운다. 브라우저 메모리나 OS 메모리의 물리적 secure erase는 보장하지 않는다. Storage, Clipboard API 자동 읽기, 자동 제출 및 자동 저장은 사용하지 않는다.

## 3. 요청과 응답 검증

텍스트 분석은 submit 동작에서만 `POST /api/v1/investigations/text`로 보낸다. 요청은 same-origin, `credentials: "omit"`, `Accept` 및 `Content-Type: application/json`이며 JSON은 `schema_version`, `source`, `log_text` 세 필드만 갖는다. URL, query, hash에는 로그를 넣지 않는다. pending 중 중복 submit과 입력 모드·source·textarea 변경을 막는다. 전역 pending 및 request-generation guard를 기존 요청과 공유한다. 사용자가 진행 중 화면을 떠나면 늦은 응답을 현재 화면에 표시하지 않는다.

성공 응답은 먼저 bounded JSON으로 읽고 다음 closed envelope를 검증한다.

- 정확한 top-level 키: `schema_version`, `input_scope`, `result`
- schema version `"1"`
- scope 키: `mode`, `source`, `notice_code`
- mode `text`, 제출한 source와 일치, notice `PARTIAL_SINGLE_SOURCE`
- `result`만 기존 `validateInvestigationResponse(..., "local")`에 전달
- 보고서에 텍스트 범위 안내가 있는지 검증

검증이 전부 성공한 뒤 기존 Dashboard, 상세 화면, Timeline, Tasks, Evidence, Checklist, Guidance, HTML 보고서 download 경로를 사용한다. API의 입력 source는 사용자가 선택한 로그 종류로만 표시하며 검증된 사례 source role로 쓰지 않는다. `risk`와 checklist의 review priority를 합치지 않는다.

오류는 Backend의 `_TEXT_ERRORS` 고정 코드·HTTP status·한국어 문구·복구 안내·retryable·field 조합을 닫힌 Frontend 표와 비교한다. `field`는 `source`, `log_text`, `null`만 허용한다. 파일 endpoint 오류 검증기와 혼합하지 않는다. 응답 계약이 잘못되면 기존 공통의 안전한 오류 요약을 사용하고 원문·내부 예외를 출력하지 않는다.

## 4. 부분 범위와 HTML 보고서

텍스트 결과 Dashboard에 선택 source 표시와 고정 범위 안내를 추가했다.

> 입력한 로그 범위에서만 분석한 결과입니다. 다른 로그나 누락된 시간대에 발생한 활동은 포함되지 않을 수 있습니다.

같은 안내가 포함된 Backend 보고서는 기존 `report_export` closed validator를 통과한 뒤 Blob URL 생성·다운로드·revoke 경로를 재사용한다. 보고서 HTML을 DOM에 삽입하거나 미리보기로 실행하지 않는다. 파일 업로드와 sample 결과에는 텍스트 전용 안내를 표시하지 않는다. 결과 없음은 안전 판정이 아니며, 관계 미발견은 공격 경로 부재의 증거가 아니고, 탐지는 침해 확정이 아니라는 기존 의미를 유지한다.

## 5. TDD, 테스트와 실제 API 결과

Browser/DOM renderer 계약에 텍스트 UI·명시적 POST·closed envelope·scope mismatch 거부·오류 field mapping·성공 후 입력 삭제·모드 취소/승인 전환·입력 화면 이탈 삭제를 추가했다. production 코드를 바꾸기 전에 해당 테스트를 실행해 `file upload remains the default mode` assertion으로 RED를 확인했다. 당시 텍스트 입력 방식 control이 없어 테스트가 실패했다. 구현 후 같은 focused test가 통과했다. 기존 테스트 assertion은 삭제하거나 약화하지 않았다.

실제 Chromium 테스트는 격리된 임시 HOME과 loopback `app.api:app` 서버, repository의 합성 로그를 사용했다. Endpoint 가로채기 없이 실제 Backend API에 연결했다.

| 입력 | 실제 API 결과 | UI 확인 |
|---|---|---|
| Application | HTTP 200, 1 case, 2 independent observations | 선택한 source 범위 표시 |
| SSH | HTTP 200, 1 case, 0 independent observations | scope 및 보고서 안내, textarea 삭제 |
| Access | HTTP 200, 0 cases, 2 independent observations | 실패/안전 판정으로 오해하지 않고 독립 관찰 유지 |
| 기존 파일 업로드 | HTTP 200, 기존 endpoint POST 1회 | 텍스트 범위 안내 없음 |

텍스트 report의 범위 안내와 request body의 정확한 세 필드를 확인했다. 화면을 열거나 source를 바꾸기 전 POST 0건, submit 시 1건을 확인했다. Node DOM harness에서는 scope/source 불일치 응답이 결과를 부분 렌더링하지 않고 거부됨을 확인했다. Backend 36.8B 테스트가 각 source의 입력 의미, 오류, limiter, privacy와 분석 통합을 검증하며, 이번 Phase의 전체 pytest에도 포함된다.

`npm run test:a11y --silent`: 25개 기존 상태와 새 입력·실제 text API 상태 axe violation 0, 외부 요청 0. 새 입력 화면에서 UTF-8 byte counter(`보안`은 6 bytes), 줄 수, 지우기 동작과 target geometry를 확인했다. 1440/1024/768/390/320px 및 320px root font 200% equivalent reflow에서 가로 overflow, panel overflow, clipping, target size·간격 위반은 0이었다. 첫 측정에서 모바일 입력 방식 선택 target 사이 4px 간격과 200% 상태에서 숨겨지지 않은 파일 input clipping이 발견됐다. gap을 8px로 수정하고 비활성 file fieldset을 실제로 숨겨 다시 검사해 통과했다. 실제 Browser zoom, Safari, VoiceOver, 실제 모바일은 검증하지 않았다.

## 6. 개인정보와 기존 기능

로그 내용은 textarea와 명시적 요청 body 외에 UI 숫자나 오류에 복제하지 않는다. console 출력, data attribute, URL, browser storage, 외부 네트워크 또는 LLM 전송을 추가하지 않았다. 원문을 결과 화면에 주입하지 않고 DOM에는 고정 설명과 검증된 결과 projection만 표시한다. 입력 요청 실패·화면 이탈은 기존 성공 결과와 섞이지 않으며 늦은 요청 결과는 generation으로 폐기한다.

기존 file multipart endpoint와 세 파일 필수 입력, sample 분석, Dashboard·Overview·Timeline·Tasks·Evidence·Checklist·Guidance 및 HTML report 경로를 유지했다. `USE_WORKSPACE_DETAIL_SHELL_36_6B`와 `KEEP_LEGACY`를 바꾸지 않았다. API, schema, analysis pipeline, dependency, lockfile은 변경하지 않았다.

## 7. 검증 및 산출물

- 시작 exact-SHA CI: `40901906174`, 성공, artifact 0
- TDD: 신규 DOM 계약 RED 후 GREEN
- focused Frontend/API 회귀: `99 passed` (초기 구현 검증)
- 최종 전체 테스트: `uv run pytest -q` — `3157 passed`, 기존 warning 2개
- Chromium·axe: `npm ci --ignore-scripts --no-audit --no-fund` 후 `npm run test:a11y --silent` 성공
- 환경/lock: `uv sync --locked --dev`, `uv lock --check` 성공
- 문법: Node 3개 스크립트 `--check`, Python `compileall` 성공
- app.js: 149,889 UTF-8 bytes, 160 KiB 제한 이내
- 변경된 Frontend: `frontend/index.html`, `frontend/app.js`, `frontend/style.css`
- 변경된 검증: `tests/web_ui_behavior.cjs`, `tests/test_web_ui.py`, `tests/ui_accessibility_axe_pilot_28_1.mjs`
- 이 문서: `docs/log_text_paste_frontend_36_8c.md`
- dependency·lockfile 변경 0, Backend/API 변경 0
- `git diff --check`은 최종 문서 포함 후 수행

이 실행 환경은 macOS다. 시작 SHA의 Ubuntu CI는 성공했지만 새 코드 SHA의 Linux CI는 아직 실행하지 않았다. 실제 Safari/native zoom, VoiceOver, 실제 모바일 기기는 `NOT_TESTED`다. 실제 사용자 로그·조직 운영·자동 대응은 `NO_GO`, 모델 기반 AI는 `NOT_TESTED`로 유지한다.

## 8. 판정과 다음 단계

판정은 로컬 검증 범위의 `PHASE_36_8C_TEXT_PASTE_FRONTEND_LOCAL_CONDITIONAL_GO`다. 새 코드 SHA의 GitHub Actions와 사용자 수용은 별도다. 다음은 `Phase 36.8D — Text Input Security & End-to-End Validation`에서 종합 보안·동등성 검증을 수행한다.
