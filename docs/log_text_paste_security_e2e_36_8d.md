# Phase 36.8D — 텍스트 입력 보안 및 End-to-End 검증

## 1. 판정 범위

현재 판정은 로컬 macOS 합성 데이터 검증에 한정한다. 실제 사용자 자료, 조직 운영, 자동 대응 승인이 아니며 사용자 수용 검수도 아니다.

## 2. 시작 Gate 및 환경

- 기준 SHA: `c3df478737758953427b0de57b7e722576df9040`
- GitHub Actions Run: `40911477565`
- 원격 `main`, 로컬 `main`, `HEAD`: 모두 기준 SHA 일치, ahead/behind `0/0`
- Run: `push / completed / success`, 정확한 head SHA 일치, artifact `0`
- Linux Python regression, TCP Syslog, JSONL, restricted report, Chromium/axe 및 tracked-file 단계: 성공
- `v0.4.0` tag 대상과 Release target: `eecd6ee1cda0545e34b01c42e1a2163a899bcc27`
- 실행 환경: macOS, Python 3.12, 실제 loopback FastAPI와 격리 Chromium; 개인정보 검증은 합성 canary만 사용

이 CI는 시작 SHA의 Linux 검증 증거다. 새 로컬 커밋 SHA의 CI 결과를 대신하지 않는다.

## 3. 기존 검사 범위와 보완점

기준 테스트는 strict JSON/schema 및 UTF-8, source별 단일 분석, 기본 크기 초과, 실제 chunked body 제한, loopback/Host/Origin/proxy/query, 공유 파일·텍스트 rate/concurrency admission, worker timeout/cancellation, private temp mode와 cleanup, API/report/logger canary, OpenAPI, Linux Audit 경로 비노출을 검사했다. Browser 검사는 실제 loopback text API의 세 source, 기존 3파일 업로드, POST opt-in, report scope, 입력 초기화 및 반응형·axe 상태를 확인했다.

추가한 검사는 정확한 입력 경계 바로 아래/경계/초과, 본문 수신 timeout과 slot 반환, app 인스턴스별 limiter 범위, 직접 기존 pipeline 대비 closed public 의미 비교, 실제 text 결과에서 checklist와 다운로드를 잇는 Browser 흐름, browser storage와 canary 비노출이다. 검증 전 모든 신규 검사에 인위적인 RED를 요구하지 않았다. 최초 Browser 추가 assertion은 SSH checklist가 `available`일 것이라고 잘못 가정해 실패했다. 실제 API는 `refused`를 반환했고 기존 API/validator 계약과 UI 모두 이를 정확히 표시했다. assertion을 실제 계약의 허용 상태와 UI 응답 일치로 수정했으며 Production 코드는 변경하지 않았다.

## 4. 단일 source 의미 비교

각 synthetic fixture를 동일 source 설정으로 직접 `analyze_with_source_role_snapshot`에 전달하고, 기존 case projection과 Text API 결과의 안전한 의미 필드를 비교했다. 비교 대상은 case/independent count, 위험도별 집계, supported detection/relation count, case 위험도·신뢰도·관찰·관계 수, 지원 탐지/관계 label, Timeline 길이·sequence·category·시간 상태·표시 label·비식별 evidence, 그리고 사례가 존재하는 경우 opaque checklist ref와 검증된 source role이다. 임의 ref/alias 문자열의 동일성은 요구하지 않았다.

현재 fixture 결과는 Application `1 case / 2 independent observations`, SSH `1 / 0`, Access `0 / 2`였다. Access의 사례 0개는 정상 분석 결과이며 안전 판정으로 해석하지 않는다. 파일 업로드와 Text 단일 source 결과 전체를 동등하다고 비교하지 않았다. 별도로 실제 세 파일 업로드는 기존 API에서 HTTP 200 및 기존 응답 계약을 유지했다.

이 비교는 공개된 결정적 의미의 parity 검사다. 분석기 내부 전체 이벤트 객체를 출력하거나 개인정보 원문을 assertion 진단에 복사하지 않는다.

## 5. Backend 입력 경계

| 항목 | 검증 방법 | 기대/실제 | 결과 |
|---|---|---|---|
| JSON 닫힌 계약·중복 key·UTF-8·lone surrogate·NaN/Infinity·root type·schema·source | 기존 및 보완 실제 TestClient 오류 사례 | 고정 error contract, 분석 전 거부 | PASS |
| 텍스트 32 KiB·한 줄 2048 UTF-8 bytes | 허용 application 형식의 정확한 경계와 초과를 validator에서 검사 | 경계 허용, +1 byte 거부 | PASS |
| 줄 수 512 | 형식이 유효한 512/513 줄 synthetic 입력 | 512 허용, 513 거부 | PASS |
| JSON wire 96 KiB | 실제 chunk 누적 함수에 정확한 크기와 +1 전달 | 정확한 한도 허용, 초과 거부 | PASS |
| chunked request | Content-Length 없이 여러 chunk 전송 | 실제 수신 누적 한도 적용 | PASS |
| body timeout | 지연 `Request.receive`와 축소된 테스트 timeout | `BODY_TIMEOUT`, 분석 미실행, admission slot 반환 | PASS |
| worker timeout/cancellation/failure | 기존 격리 worker 테스트 | 프로세스 종료, staging 제거, slot 반환 | PASS |
| loopback/Host/Origin/proxy/query | 실제 API 요청 | 비로컬/잘못된 헤더·query 거부 | PASS |
| DEL 및 Unicode bidi | 실제 synthetic SSH API 입력과 safe response/logger 검사 | 제어 문자 거부, bidi 원문은 public projection/logger에 미노출 | PASS |

정확한 body cap 검사는 bounded reader 경계 단위 시험이다. ASGI 서버가 handler에 넘기기 전에 개별 chunk 메모리를 할당할 수 있으며 이 코드가 그 선행 할당을 통제한다고 주장하지 않는다. OS 수준 hard memory cap은 제공되지 않는다.

## 6. 공유 limiter와 요청 격리

기존 테스트는 한 app 인스턴스에서 File 3회 + Text 3회 뒤 차단, Text 6회 뒤 File 차단, 양방향 동시 분석 차단을 확인한다. 정상 종료, worker timeout 및 취소 뒤 slot 반환을 검사했다. 보완 테스트는 서로 다른 app 인스턴스의 quota가 독립된다는 기존 계약을 확인했다. 별도 endpoint quota 우회 증거는 없다. 서로 다른 app 인스턴스 사이 전역 quota 공유를 보장하지 않는다.

## 7. 임시 파일과 Worker

실제 요청 worker 경계 테스트는 요청별 고정 파일명, directory `0700`, file `0600`, 요청 입력 바이트 및 worker 실패 후 제거를 확인한다. 성공 분석과 기존 failure/timeout/cancellation 회귀도 통과했다. 요청 생성 시 이미 검증한 단일 source만 worker에 전달된다. 입력 거부는 staging/분석 전에 발생한다. 강제 OS 종료 뒤 orphan cleanup과 저장 매체 secure erase는 보장하지 않는다.

## 8. Privacy canary

API 합성 canary는 성공 response, HTML report 및 logger에서 제거됨을 기존 backend 회귀로 확인했다. 새 Chromium E2E는 텍스트 입력과 명시적 request body에만 `TEXT_E2E_PRIVATE_CANARY`를 허용하고, response/report, 표시된 DOM, console/page error, URL, localStorage, sessionStorage 및 IndexedDB에는 나타나지 않는지 검사했다. Browser E2E에서 외부 요청은 0이었다. 테스트 진단은 상태 enum·숫자만 출력하고 입력 문장을 출력하지 않는다.

원문은 사용자가 입력한 textarea와 사용자가 명시적으로 보낸 동일-origin request body에 존재할 수 있다. 브라우저/OS 메모리의 물리 삭제는 보장하지 않는다. URL, history, storage, error UI, 결과 UI, HTML report 및 외부 네트워크로의 복제는 허용하지 않는다.

## 9. Frontend 상태 격리 및 실제 loopback E2E

실제 Chromium 흐름은 SSH synthetic log를 입력하고 명시 submit → 실제 Text API response/envelope 확인 → scope Dashboard 표시와 입력 삭제 → HTML report를 실제 다운로드하고 canary 부재 확인 → 상세 진입 → Tasks 탭 진입 시 checklist POST 0 → 버튼 클릭 뒤 checklist POST 1 → checklist v2 응답 상태와 UI 상태 일치 확인을 수행했다. 현재 SSH fixture의 checklist 결과는 `refused`이며 UI는 `refused`, task 0개, 준비 실패 문구 없음으로 일치했다. 별도의 실제 checklist available 회귀는 4개 task/available 상태를 확인했다.

Browser storage에는 local/session/IndexedDB record가 없었다. 모드 전환 취소/승인, 성공·실패 후 기존 결과 분리, 입력 화면 이탈 및 페이지 이탈 초기화는 기존 DOM/Browser 계약으로 계속 검사한다. 분석 값은 Frontend에서 재계산하지 않고 closed response validator 통과 후 기존 renderer에 전달된다.

## 10. Checklist와 Report

Text API의 실제 사례 ref만 Checklist registry에 연결되고 별도 POST 전에는 요청되지 않는다. checklist v2의 case binding, source role provenance, 응답 비변경 및 citation ID subset은 기존 회귀와 보완 assertion으로 확인했다. Access의 사례 0개에서 ref나 Checklist를 만들어내지 않는다.

실제 Text response의 HTML report는 단일 source 범위 안내를 포함하며 기존 다운로드 경로로만 내려받았다. 브라우저에서 다운로드한 보고서는 canary를 포함하지 않았다. 기존 세 파일 report에는 텍스트 전용 안내가 없다. 원문을 DOM preview로 실행하지 않았으며 다운로드 시 분석 재실행/추가 요청은 없다.

## 11. 접근성 및 기존 회귀

- `npm run test:a11y --silent`: 기존 25개 Browser/axe 상태 성공, 새 loopback Text/Checklist/Report 흐름 성공, axe violation `0`, 외부 요청 `0`
- 1440/1024/768/390/320px 및 320px root-font 기반 200% equivalent: overflow/clipping/target geometry 위반 `0`
- 입력·Dashboard·Timeline·Tasks·Evidence·Checklist 기존 Browser 상태 및 최소 target/간격 계약 유지
- 전체 `uv run pytest -q`: `3164 passed`, warning 2개 (기존 Starlette/httpx 및 AnyIO deprecation)
- 최신 focused backend/file/UI/report 회귀: `132 passed`, warning 2개
- 추가 TCP Syslog core/runtime, JSONL adapter, restricted analyst report/fault 회귀: `150 passed` (macOS)
- `uv sync --locked --dev`, `uv lock --check`, Node syntax, `git diff --check`: 성공
- Frontend static asset: `frontend/app.js` 149,889 bytes; 160 KiB ceiling 유지
- Backend, API/OpenAPI, Frontend production code, analysis, dependency/lockfile 변경: `0`
- 본 검증은 Chromium이며 browser native zoom, Safari, VoiceOver, 실제 모바일 기기는 `NOT_TESTED`

로컬 필수 회귀와 Browser E2E가 통과해 판정은 `PHASE_36_8D_TEXT_INPUT_SECURITY_E2E_LOCAL_CONDITIONAL_GO`다. 이는 macOS의 합성 입력·loopback·Chromium 범위에 한정된다. 새 커밋의 Ubuntu CI 및 실제 사용자 수용은 아직 검증하지 않았다.

## 12. 실행 결과

- Baseline focused: 120 passed; 기존 warning 2개
- 추가 backend focused: 64 passed; 기존 warning 2개
- Browser/axe: 25 states, axe violations 0, 외부 요청 0; loopback text/File/checklist/report 추가 시나리오 성공
- `uv sync --locked --dev`: 성공
- `uv lock --check`: 성공
- Node 문법: 성공
- Python focused suite: 성공
- 전체 `uv run pytest -q`: `3169 passed`, warning 2개 (기존 Starlette/httpx 및 AnyIO deprecation)

## 13. 잔여 한계 및 경계

- 새 로컬 커밋 SHA의 GitHub Ubuntu CI는 실행하지 않았고 push하지 않는다. 시작 SHA CI는 성공했으나 신규 커밋 증거가 아니다.
- Linux 전용 TCP Syslog, JSONL 및 restricted report acceptance는 이번 macOS 환경에서 재검증하지 않음; 시작 SHA CI에서만 Linux 성공 증거가 있다. macOS focused regression은 위와 같이 별도 통과했다.
- hard OS memory cap, forced-termination orphan cleanup, secure erase는 보장하지 않는다.
- 사용자 수용은 이 Phase 범위에 포함되지 않는다.
- 실제 사용자 자료·조직 운영·자동 대응: `NO_GO`
- 모델 기반 AI: `NOT_TESTED`
- Safari·VoiceOver·실제 모바일 기기: `NOT_TESTED`
- Vector/VM: `USER_ACTION_REQUIRED / ISOLATION_BLOCKED`

## 14. 다음 단계

검증 가능한 경우 다음은 `Phase 36.8E — Text Input Production UI User Acceptance`다. 합성 로그만으로 실제 production UI의 붙여넣기·결과 범위 안내·오류 상태·파일 업로드와의 사용성 차이를 사용자가 검수해야 한다. 이번 자동화 결과를 사용자 PASS나 운영 GO로 간주하지 않는다.
