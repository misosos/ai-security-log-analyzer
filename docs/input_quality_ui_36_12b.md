# Phase 36.12B — 입력 품질 요약 Production UI

## 목적과 범위

분석 결과가 비어 있거나 적을 때 조사자가 **로그 형식을 인식한 범위**와 탐지 결과를 혼동하지 않도록 결과 요약 아래, 검토 건 목록 위에 요청 단위 `로그 인식 상태`를 표시합니다. 상세 사례에는 반복하지 않습니다. 이 화면은 안전 여부, 탐지, 위험도, 수집 완전성을 판정하지 않습니다.

Phase 36.12A의 schema version `1` DTO와 response projection을 그대로 읽습니다. Backend/API schema, 요청 형식, parser, detection, relation, risk, case, review priority, checklist, report, checkpoint, publication, SSE에는 변경이 없습니다.

## 상태와 표시 문구

| response `recognition_status` | 화면 문구 | 설명 |
| --- | --- | --- |
| `complete` | 모두 인식 | 비어 있지 않은 입력 형식을 모두 인식했습니다. 안전하거나 위협이 없다는 뜻은 아닙니다. |
| `partial` | 일부 인식 | 일부 줄을 해석하지 못해 분석 범위가 제한될 수 있습니다. 인식한 줄의 분석 결과는 유지됩니다. |
| `none` | 인식하지 못함 | 비어 있지 않은 입력이 있었지만 지원 형식으로 해석하지 못했습니다. 탐지 없음이나 안전 판정이 아닙니다. |
| `empty` | 분석할 내용 없음 | 분석할 비어 있지 않은 줄이 없습니다. 정상 또는 안전을 뜻하지 않습니다. |

항상 표시하는 한계 문구는 `로그 인식 상태는 입력 형식의 처리 범위이며, 탐지 결과·위험도·안전 여부를 뜻하지 않습니다.`입니다. `complete`는 중립적인 cyan 계열 정보 표시를 사용하며 성공·안전을 뜻하는 초록색 상태를 쓰지 않습니다.

집계 숫자는 response 값을 그대로 표시합니다: 전체 입력 줄, 인식, 인식하지 못함, 무시됨. 인식 비율은 새로 계산하지 않습니다. Source 상세의 `인식/비어 있지 않은 입력 줄`은 API 집계 count만 표시합니다.

## Source와 reason 표시

파일 업로드는 aggregate를 먼저 보이고 application, ssh, access를 source별로 분리해 표시합니다. 이유 count도 각 source 아래에서만 공개합니다. 텍스트 입력은 요청의 단일 source만 표시하며 존재하지 않는 source를 0으로 만들지 않습니다.

Source에 0보다 큰 이유 count가 있을 때에만 닫힌 `<details>/<summary>`를 표시합니다. 이유 mapping은 36.12A의 고정 9개 category를 모두 반영합니다.

| 고정 category | 한국어 label |
| --- | --- |
| `unsupported_format` | 지원하지 않는 형식 |
| `invalid_timestamp` | 올바르지 않은 시각 |
| `invalid_address` | 올바르지 않은 주소 |
| `invalid_port` | 올바르지 않은 포트 |
| `invalid_header` | 올바르지 않은 헤더 |
| `incomplete_record` | 완성되지 않은 레코드 |
| `blank_line` | 빈 줄 |
| `ignored_record` | 무시된 기록 |
| `other_rejected` | 기타 거부 |

`기타 거부`는 구체적인 Parser 오류로 해석하지 않습니다. 원문이나 행 번호를 UI에서 다시 분석하거나 추론하지 않습니다.

## 전체 Parser 거부, malformed 및 legacy response

`PARSER_INCOMPATIBLE`는 기존 오류 상태로 유지됩니다. 오류 response가 검증된 품질 projection을 포함한 경우에만 오류 영역 안에서 요약을 보여줍니다. 분석 dashboard, 검토 건, risk 또는 report가 만들어졌다고 표현하지 않습니다. 오류 response에 품질 필드가 없으면 UI는 요약을 만들지 않습니다.

품질 필드가 없는 구버전 local response도 기존 닫힌 response 검증을 유지하면서 표시를 생략하고 dashboard/workspace를 계속 표시합니다. 알려지지 않은 필드, 상태·reason, count invariant 위반은 기존 고정 오류로 거부합니다. 이전 결과를 새 분석, 빈 입력 또는 만료 상세 route에 재사용하지 않습니다.

## Privacy, 접근성, 반응형

Renderer는 이미 schema 검증된 상태·category·count만 사용하고 텍스트 노드를 생성합니다. 응답 값을 HTML로 삽입하지 않습니다. 입력 원문·사용자·주소·hostname·파일명·시각·경로·token·예외 문자열은 품질 영역에 들어가지 않습니다. 결과 화면 렌더는 새로운 API 요청을 하지 않습니다. Checklist의 명시적 POST만 기존 버튼 흐름을 사용합니다.

Disclosure는 실제 HTML `details/summary`이며 키보드로 열고 닫을 수 있습니다. 상태는 텍스트로 표시합니다. 결과 목록이나 사례 카드에는 중복 렌더링하지 않습니다. 1440, 1024, 768, 390, 320 CSS px와 320 CSS px/200% equivalent에서 가로 overflow와 count 카드 내부 overflow를 확인했습니다.

기존 `/assets/app.js`가 static asset 상한 160 KiB에 근접해 있어 UI renderer를 별도 **same-origin 고정 경로** `/assets/input-quality-ui-36-12b.js`로 분리했습니다. 새 경로도 기존 CSP 및 고정 asset allowlist를 사용하고 asset 상한을 올리지 않습니다. 외부 CDN, 폰트, 라이브러리 또는 네트워크 요청은 추가하지 않았습니다. 각 asset은 160 KiB 미만입니다.

## 검증

- `tests/ui_input_quality_36_12b.mjs`: 실제 loopback API와 Chromium을 이용해 파일 complete, 파일 mixed/partial 전체 거부, 텍스트 complete/partial/none/empty, 9개 reason label, 0 count 숨김, disclosure 키보드 동작, malformed reason/status/count, canary 비노출, legacy response, history, 상세 사례 비반복, 만료 route, 결과 이동 추가 요청 없음 및 CSP 경계를 확인합니다.
- axe: 입력 품질 포함 desktop, mobile, 열린 disclosure 상태에서 위반 0건. 전체 기존 a11y suite의 25 states와 `external_requests=0`도 별도 실행합니다.
- 최종 전체 회귀: `uv run pytest -q` — 3,588 passed, 기존 warning 2개.
- Focused 회귀: 입력/API/parser/live/checklist/restricted report/web UI 356 passed, 기존 warning 2개; triage/checklist/verified-role/JSONL determinism 131 passed; TCP Syslog/JSONL runtime modules 144 passed.
- 합성 평가: 입력 품질 corpus 79/79, Linux process evaluation 21/21, risk 70/70, case 70/70, Phase 36.1 triage 44/44, Phase 36.2 checklist 24/24. 기존 parser 평가는 195/200 (ignored 2, rejected 3; unexpected parse/rejection 0)로 기준과 동일합니다.
- `npm run test:a11y --silent`: 25 states, `external_requests=0`; 입력 품질 browser E2E: desktop/mobile/disclosure axe 0 violations, `external_requests=0`; UI3 navigation closure도 `externalRequests=0`, CSP 통과 및 checklist의 기존 explicit POST 계약을 확인했습니다.
- `npm ci --ignore-scripts`, `uv sync --locked --dev`, `uv lock --check`, `python3 -m compileall -q app tests`, Node syntax checks 및 `git diff --check` 통과. `pyproject.toml`, `uv.lock`, `package.json`, `package-lock.json`은 변경되지 않았습니다.
- 로컬 합성 smoke: TCP Syslog 기본·management 및 JSONL runtime smoke 통과. JSONL Linux acceptance와 Restricted Report Linux smoke는 macOS에서 Linux platform guard로 실행되지 않아 Linux 검증은 `NOT_TESTED`입니다.
- synthetic DOM benchmark (Chromium, 1440px, warm-up 5, sample 30):

| 상태 | Median / p95 / max | DOM node | `outerHTML` UTF-8 bytes |
| --- | --- | ---: | ---: |
| 파일 3-source complete | 약 0.2 / 0.3 / 0.3 ms | 42 | 1,431 |
| 파일 3-source mixed/partial | 약 0.2 / 0.3 / 0.4 ms | 42 | 1,469 |
| 텍스트 none | 약 0.2 / 0.3 / 0.3 ms | 32 | 1,299 |
| reason disclosure open | 약 0.2 / 0.3 / 0.3 ms | 32 | 1,280 |

이 benchmark는 합성 DOM clone/reflow 관측이며 운영 SLA가 아닙니다. 숫자는 macOS Chromium 개발 환경에서 관측한 값입니다.

고정 asset별 크기(UTF-8 bytes)는 `app.js` 157,901, 입력 품질 renderer 4,775, `style.css` 70,152입니다. 기존 160 KiB 고정 asset 상한을 변경하지 않았고 새 renderer는 자체 same-origin asset으로 전달됩니다.

## 한계와 다음 단계

새 commit의 Ubuntu CI는 사용자가 push하기 전이므로 `NOT_TESTED`입니다. Safari 및 실제 모바일 기기 확인도 `NOT_TESTED`입니다. 자동 axe 검사는 수동 screen reader/사용자 이해도 검수를 대체하지 않습니다. 실제 사용자 자료, 조직 운영, 자동 대응은 계속 `NO_GO`; 모델 기반 AI는 사용하지 않았습니다.

Phase 36.12C에서는 합성 시나리오를 사용해 네 상태와 source별 처리 count가 “안전 여부”나 “탐지 count”로 오해되지 않는지 사용성 검수를 권고합니다. Production UI 표시 자체도 새 Ubuntu CI와 이해도 검수 전에는 승인되지 않습니다.

## Rollback

UI 변경을 되돌릴 때 `frontend/app.js`, `frontend/input-quality-ui-36-12b.js`, `frontend/index.html`, `frontend/style.css`, 고정 static asset route 및 관련 UI tests/docs를 이 Phase commit에서 함께 되돌립니다. API projection 및 분석 pipeline에는 이 Phase의 변경이 없습니다.
