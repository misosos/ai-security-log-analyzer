# Phase 36.12A — 보안 로그 입력 품질 요약 Backend Core

## 목적과 범위

빈 탐지 결과가 입력 해석 실패를 가리는 문제를 줄이기 위해, 파일 업로드와 텍스트 붙여넣기에 source별 입력 레코드 인식 요약을 추가한다. 이 값은 기존 Detection, Correlation, Risk, Case, Report 내용을 변경하지 않는 별도 관측 정보다.

이번 변경은 backend response projection과 그 구조를 검증하는 비표시 UI 호환성 확인까지만 수행한다. 입력 품질을 화면에 표시하는 UI는 Phase 36.12B 대상이다.

## 시작 Gate

- Branch `main`, 시작 SHA `b2556dccf544a5248a0b1730793578061e6bab63`
- Local/main/origin/GitHub SHA 일치, working tree clean, ahead/behind `0/0`
- exact push Run [41279516055](https://github.com/misosos/ai-security-log-analyzer/actions/runs/41279516055): completed/success, artifact 0
- `v0.4.0` tag와 Release target은 `eecd6ee1cda0545e34b01c42e1a2163a899bcc27`

## DTO와 고정 분류

`app/input_quality_36_12a.py`의 frozen, strict, `extra=forbid` 모델은 다음을 제공한다.

- `InputQualitySummary` — `schema_version="1"`, source, 전체·비공백·인식·미인식·무시 행 수, 인식 상태, 고정 사유 count, 고정 한계 코드
- `InputQualityProjection` — 고정 source 순서의 `by_source` 및 source별 수치 합계인 `aggregate`
- `InputQualityReasonCounts` — `unsupported_format`, `invalid_timestamp`, `invalid_address`, `invalid_port`, `invalid_header`, `incomplete_record`, `blank_line`, `ignored_record`, `other_rejected`

Parser가 이유를 안전하고 정확히 구분하지 못하면 `other_rejected`로 둔다. 사유 문자열, 행 번호, 입력 값은 DTO에 포함하지 않는다.

정상 완료된 summary는 `recognized_lines + unrecognized_lines + ignored_lines == total_lines`와 `blank_line == total_lines - nonempty_lines`를 강제한다. 인식 상태는 비공백 입력이 없으면 `empty`, 모든 비공백 행이 인식되면 `complete`, 일부 인식이면 `partial`, 인식 행이 없으면 `none`이다. 공백 행은 `ignored_lines`에 포함된다.

`complete`는 입력 형식이 처리됐다는 뜻이며 탐지 완전성·수집 완전성·안전 상태를 뜻하지 않는다. `none`은 형식 인식이 없었다는 의미이며 위험 판단이 아니다.

## Parser·API 경로

평가기는 기존 Parser Registry를 호출한다. 기존 File API preflight와 Text API validation 과정에서 얻은 parser 판정을 bounded counter에 누적하고, 분석 worker를 별도로 재실행하지 않는다. 원본 행이나 `NormalizedEvent`를 summary에 보관하지 않는다. 기존 pipeline은 기존처럼 staged file을 읽어 분석한다.

- 파일 업로드: `application`, `ssh`, `access` summary와 전체 aggregate를 제공한다.
- 텍스트 입력: 선택한 단일 source summary와 해당 입력 aggregate를 제공한다.
- parser-incompatible 입력: 기존 `PARSER_INCOMPATIBLE` fail-closed 응답을 유지하고, 분석을 실행하지 않은 채 bounded quality projection을 오류 응답에 첨부한다.
- request byte/line/UTF-8/control-character/JSON 중복 key/NaN 제한 오류는 기존 fixed error 응답을 유지한다. 이 경우 전체 입력 품질 완료를 주장하지 않는다.

Local investigation response는 기존 `schema_version="2"`를 유지한다. 새 additive field는 자체 `schema_version="1"`을 가진다. Text envelope/checklist/report/checkpoint/publication/SSE 계약은 변경하지 않았다. 기존 UI는 새 구조를 엄격히 검증한 뒤 표시하지 않고 무시한다. Phase 36.12B에서 별도 시각 표시를 설계한다.

## Privacy와 분석 의미 불변

DTO, 오류 응답, `repr`, JSON에는 raw line, account, IP, hostname, filename/path, timestamp, URL/query, credential/token, canary, line number 또는 자유 형식 예외가 없다. 내부 parser 예외는 고정 category로만 축약한다. API의 기존 staged-file byte/line 상한, 파일 모드, fail-closed admission을 유지한다.

Production Parser 자체의 허용 문법, Detector/Correlation/Risk/Case/Report projection 로직은 수정하지 않았다. 품질 summary는 탐지 수, 관계, risk level/confidence, case 및 review priority를 변경하지 않는다.

## 지원 입력과 한계

Source별 판정은 기존 Registry와 API contract만 따르며 새로운 fallback이나 자동 형식 추정을 추가하지 않는다. RFC 5424 제한 SSH profile은 기존 `ssh2:` 문법 그대로다. 별도 Linux Audit 입력은 추가하지 않는다.

평가할 수 있는 것은 요청에 실제 들어온 물리 행의 parser disposition뿐이다. 수집 과정에서 빠진 로그, 원천 시스템의 기록 완전성, 공격 탐지 정확도는 측정하지 않는다. 전체 입력 크기·UTF-8·multipart 등의 request-level 실패에서는 요약이 제공되지 않을 수 있다.

## 검증과 합성 성능 관측

신규 tests는 성공/미지원/무시/공백/혼합 상태, ISO SSH와 제한 RFC 5424, Combined Access, 잘못된 timestamp/address/port/header, CRLF/마지막 LF 없음, 512행 상한, source isolation, 결정성, canary 비노출과 API fail-closed 동작을 검증한다.

`tests/benchmark_input_quality_36_12a.py`는 synthetic-only로 512행 인식/미인식/혼합 입력과 3-source aggregate의 입력 byte 및 median/p95/max 시간을 출력한다. 이는 개발용 합성 관측치이며 운영 SLA가 아니다.

현재 macOS 로컬 관측(25 samples, 3 warmups):

| 시나리오 | 입력 byte | median / p95 / max (ms) |
| --- | ---: | ---: |
| 512 recognized | 27,135 | 8.011 / 8.150 / 8.251 |
| 512 unrecognized | 5,119 | 0.533 / 0.587 / 0.603 |
| 512 mixed | 16,117 | 4.604 / 4.774 / 4.888 |
| 3-source aggregate (510 lines) | 35,697 | 14.701 / 17.327 / 17.582 |

최종 macOS 로컬 관측(25 samples, 3 warmups)은 위 표와 같다. 단일 개발용 합성 측정이며 운영 SLA가 아니다.

## 검증 결과

- 신규 품질·Parser·Text/File API·Live·Restricted Report·Checklist focused: `459 passed, 2 warnings`
- 전체 pytest: `3588 passed, 2 warnings` (기준 3563에서 신규 테스트 25개 추가)
- 기존 합성 평가: boundary `79/79`, Linux Audit process-category evaluator `21/21` (macOS에서 실행한 합성 분류 평가, Linux host acceptance 아님), Risk `70/70`, Case `70/70`
- Phase 36.1: `44/44`, 개인정보 누출 0, 분석 mutation 0; Phase 36.2: `24/24`
- UTC와 `Asia/Seoul`에서 시간/parser/quality focused: 각 `98 passed, 2 warnings`
- TCP Syslog basic·management smoke, JSONL runtime smoke: 통과. Smoke는 synthetic-only이며 Linux acceptance는 아님.
- Chromium/axe: `25 states`, `external_requests=0`; UI3 Navigation E2E: 외부 요청 0, CSP 확인
- `uv sync --locked --dev`, `uv lock --check`, Python compile, Node syntax 및 `git diff --check`: 통과
- Linux 전용 Restricted Report smoke, TCP bounded reliability Linux 모드, JSONL Linux acceptance: 이 macOS 세션에서 실행하지 않아 `NOT_TESTED`; Ubuntu push CI 확인 전 Linux 검증 완료 또는 production GO로 표현하지 않는다.

첫 전체 suite 실행은 README 길이 계약 초과 때문에 문서 테스트 2건이 실패했다. README에 새 문서 링크를 짧게 통합하고 설명을 간결히 한 뒤 해당 문서 테스트 `5 passed`와 최종 전체 suite가 통과했다. 기존 assertion은 변경하지 않았다.

기존 parser, detection, correlation, risk, case, report contract tests도 전체 회귀에 포함됐다. 사용자 자료·조직 운영·자동 대응은 `NO_GO`로 유지한다.

## UI와 다음 단계

Phase 36.12B는 분석 결과와 분리된 입력 품질 영역에 source별 처리 수, recognition state, 한계 문구를 제시하고 `complete`를 안전 신호로 오해하지 않도록 해야 한다. 이번 Phase에서는 public API에 포함했지만 UI에 표시하지 않는다.

## 운영 승인 상태

이 로컬 합성 검증은 실제 사용자 자료, 조직 운영, 자동 대응을 승인하지 않는다. 모두 `NO_GO`로 유지된다. Model/Gemini/embedding/외부 API는 사용하지 않았다.
