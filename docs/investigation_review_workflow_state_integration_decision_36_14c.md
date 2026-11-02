# Phase 36.14C — 검토 상태 연결 경계 결정

## 결정과 범위

결정: **`NO_API`, `NO_SQLITE`, `NO_WEB_STORAGE`**. 다음 36.14D는 분석 결과와 동일한 수명인 브라우저 document-memory store를 고정 JavaScript 모듈로 연결한다. Phase 36.14B Python core는 production request path에 연결하지 않고 상태 enum·전이·revision 계약을 확인하는 executable reference로 유지한다. durable analysis snapshot의 보존·재개·삭제가 별도 설계 및 승인되기 전에는 상태 영속화를 다시 열지 않는다.

이 문서는 36.14A의 저장 권고와 36.14B core 경계를 바탕으로 네 가지 연결 선택지를 결정한다. 신규 API, UI, 저장 파일·DB, Web Storage, dependency 및 lockfile은 추가하지 않는다. 합성 contract vector는 Python core와 향후 JavaScript store 사이의 의미만 고정하며 frontend는 fixture나 Python 모듈을 import하지 않는다.

## 시작 Gate 증거

- branch `main`, clean working tree, local HEAD/local `main`/`origin/main`/GitHub `main` 모두 `91a70431b6ac36d4ccf355280f93593b21eeca0c`; `origin/main...HEAD` `0/0`.
- 정확한 [push run 41421022043](https://github.com/misosos/ai-security-log-analyzer/actions/runs/41421022043): `head_sha` 일치, event `push`, `completed/success`.
- `Locked Python 3.12 regression`의 전체 pytest와 필수 Linux checkpoint/process, TCP Syslog, JSONL, Restricted Report, Chromium·axe, tracked-file 검사 단계가 실제 실행되어 전부 성공. artifact `0`.
- `v0.4.0` peeled tag 및 GitHub Release target 모두 기존 `eecd6ee1cda0545e34b01c42e1a2163a899bcc27`.

## 재조사한 현재 수명 모델

아래는 코드에서 확인된 현재 사실이다. 향후 희망 동작을 현재 기능으로 간주하지 않는다.

| 사실 | 코드/계약 근거 |
| --- | --- |
| 분석 결과와 19-field workspace projection은 현재 브라우저 document memory에 설치됨 | `frontend/app.js`의 `currentInvestigation`, `caseByRef`, `workspaceDetailGeneration`, projection 설치 (`renderCaseOverview`) |
| 새 결과 설치 전 이전 사례 projection과 queue를 비움 | `frontend/app.js`의 `clearPreviousResult()`가 `caseByRef` 및 `reviewQueue`를 초기화 |
| 상세 route는 `#/investigations/{case_ref}`이며 현재 memory projection 조회 | `frontend/app.js`의 `reviewRouteRef()`/`openReviewCase()`; `docs/investigation_workspace_projection_navigation_36_6b.md` |
| reload/direct-entry/stale ref에서 결과를 복원하거나 분석을 재호출하지 않고 만료 view 표시 | `showExpiredReviewRoute()` 및 Phase 36.6B navigation 계약 |
| `case_ref`는 `c_[0-9a-f]{24}` request-scoped opaque ref; 분석 간 안정 ID가 아님 | `app/investigation_checklist_api_36_3.py`, `app/models/investigation_sample_api.py`, Phase 36.14A 설계 |
| Python 36.14B store는 memory-only로 독립 구현됐고 요청 경로에서 호출되지 않음 | 별도 core 모듈; 이번 gate HEAD에서 API/frontend import 없음 |
| checklist POST는 사용자가 상세 화면의 명시 버튼을 누른 뒤 발생 | `frontend/app.js` `CHECKLIST_ENDPOINT` click handler; 목록 이동은 POST하지 않음 |
| 로그인 사용자 또는 browser-session identity를 현재 investigation API가 제공하지 않음 | local investigation routes는 `create_app()`의 local admission 경로에 등록되며 사용자 인증 dependency를 받지 않음. 별도 optional Linux Audit API security는 이 public local-analysis flow의 session identity가 아님 |
| durable analysis snapshot/resume API가 없음 | file/text/sample 응답은 분석 projection을 반환하지만 reload 뒤 재개할 snapshot ID/load 계약은 정의하지 않음 |

현재 API는 loopback/local admission 보호를 제공할 수 있지만, loopback 허용은 서로 다른 탭이나 클라이언트를 식별·인증하는 browser session binding과 같지 않다. 선택적인 Linux Audit authentication은 다른 API 경로의 보안 기능이며 검토 상태의 소유권을 증명하지 않는다.

## 저장·연결 방식 비교

| 방식 | projection 수명과 reload/direct entry | 탭·사용자 혼입 및 인증 binding | CSRF/same-origin mutation | stale/CAS | privacy 잔존·삭제 | snapshot 없는 orphan | 테스트·rollback |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 서버 Python memory store를 위한 임시 API | 서버 상태는 reload 후 남을 수 있지만 projection은 사라져 상태를 적용할 대상이 없음 | 인증/session binding 부재. 동일 server process에 도달하는 서로 다른 탭·클라이언트가 ref를 재사용하거나 상태를 읽고 바꾸어 섞일 수 있음 | same-origin POST/PATCH mutation을 새로 만들며 loopback 요청도 CSRF·DNS rebinding 경계를 검토해야 함 | CAS 구현 가능하지만 어느 사용자/analysis generation의 revision인지 인증되지 않음 | process 종료 때 사라지지만 종료 전 프로세스 전역 잔존 | **높음** | route/OpenAPI/권한 회귀와 운영 process topology를 시험해야 함. 제거는 route와 registry 동시 rollback 필요 |
| 브라우저 document-memory store | projection과 같은 수명. reload/direct entry는 둘 다 만료 | document/tab별 독립; 사용자 인증을 가장하지 않으며 교차 탭 공유 없음 | 추가 network mutation 없음; 브라우저의 명시 조작만 동기 메모리 변경 | 동일 tab 안의 정수 revision으로 결정적 거부 가능; 다중 탭 합의 불필요 | document 종료·새 분석·결과 제거 때 소멸 | 없음: projection과 같이 소멸 | 단위·브라우저 테스트가 단순. 별도 JS module/adaptor 한 범위 rollback 가능 |
| `sessionStorage` / `localStorage` | reload 후 상태만 복원 가능하나 분석 projection은 복원 불가 | session은 탭 복제 등 lifecycle 차이가 있고, local은 origin 내 여러 탭이 공유·경합. 둘 다 사용자 인증이 아님 | API mutation은 없지만 같은 origin JS가 저장값을 읽고 조작 가능 | 여러 key update 원자성/충돌 감지 부족; 직접 versioning 필요 | profile 종료·사이트 data 삭제까지 남고 backup/복구에 영향 | **높음**: 표시 projection 없는 상태 레코드가 남음 | reload·멀티탭·손상·cleanup 검증 및 별도 rollback 필요 |
| SQLite 등 durable 서버 저장 | 저장은 되지만 projection 재개 계약이 없어 reload 결과를 만들 수 없음 | server 공용 DB일 경우 인증/tenant/session binding 없이는 혼입 위험 | mutation API와 CSRF/same-origin 보호 필요 | transaction 및 CAS는 가능하지만 ownership binding을 대신하지 않음 | DB/WAL/backup/삭제 페이지·파일 권한·보존기간 검토 필요 | **높음** | crash, lock, backup, corruption, migration 회귀가 필요; 파일/DB rollback 및 삭제 절차 부담 |

현재 수명 모델에서 document-memory만 결과와 상태가 함께 살아 있고 함께 만료된다. 따라서 편의상 상태만 남기는 방식은 선택하지 않는다. 공정한 다중 사용자 기록, 감사 증적, reload 재개 요구가 이후 승인되면 먼저 분석 snapshot 및 사용자/session binding을 설계해야 하며, 그때 저장 기술을 다시 비교한다.

## Contract vector

`tests/fixtures/investigation_review_state_v1_contract.json`은 오직 합성 opaque reference를 가진 version 1 fixture다. `tests/test_review_state_contract_vector_36_14c.py`가 fixture의 closed key set을 확인하고 Phase 36.14B Python core에 대해 allowed transition 전체, same-state 거부, reset 전용 복귀, 초기 revision/CAS, unknown analysis/case, generation 분리, 128 case 상한 및 고정 오류 category를 실행한다.

vector의 state projection allowlist는 정확히 다음뿐이다.

```text
schema_version, analysis_ref, case_ref, review_state, revision
```

원문, account, IP, hostname, path, timestamp, 제목, 위험도, note, fingerprint는 vector와 state projection에 포함하지 않는다. fixture는 production code가 읽지 않으며 향후 JS 구현도 fixture import가 아니라 동일 의미의 JS 전용 테스트로 비교한다.

## 36.14D 브라우저 연결 계약

다음 단계는 별도 고정 JavaScript module 및 기존 queue adapter 경계 안에서 구현한다.

1. 검증된 새 analysis response 설치 시 document-memory에 새 `analysis_ref` generation 하나를 만든다. `crypto.getRandomValues`에서 128-bit 값을 만들어 `a_` + 32 lowercase hex 형식으로 변환한다. 생성 기능을 사용할 수 없으면 workflow controls를 unavailable로 두고 안전하지 않은 fallback을 쓰지 않는다.
2. 같은 response에서 검증된 `c_[0-9a-f]{24}`만 등록한다. null/missing/duplicate ref를 다른 키로 추측하지 않는다. 세대당 최대 128개; 초기 상태는 모두 `unreviewed`, revision 0.
3. 명시적 사용자 상태 선택/초기화만 상태를 바꾼다. 현재 document-memory 연산이 성공한 뒤 UI 성공을 표시한다. 저장 서버는 없으므로 이를 “서버 저장됨”이나 지속 저장으로 표현하지 않는다.
4. 검색·필터·정렬, 목록/상세 route 이동, checklist 조회/응답은 상태를 변경하지 않는다. checklist POST는 기존 explicit click만 유지한다.
5. 새 분석 response 교체와 명시적 결과 제거 시 state map을 폐기한다. reload/direct entry/stale route는 기존 만료 안내를 유지하고 상태 복구·분석 재요청을 하지 않는다.
6. 상태를 URL/hash/history state, report, checklist body, API response, clipboard, checkpoint, publication, SSE 또는 Web Storage에 자동 포함하지 않는다. Tab별 상태는 독립이며 cross-tab 동기화를 주장하지 않는다.
7. `reviewed`는 해결·안전·오탐·조치 완료가 아니고 `deferred`는 낮은 위험·무시 가능·검토 불필요가 아니다. 상태 filter는 표시 subset만 바꾼다. 상태·risk·review priority를 의미와 시각 위계에서 분리한다.
8. 신규 integration은 기존 compact queue를 되돌릴 **단일 rollback switch** 아래 둔다. switch off 시 36.13A1 compact queue 렌더러와 기존 projection이 동작하고 상태 module을 사용하지 않는다. route/analysis response에는 migration이 없다.

## GO / NO_GO / rollback

| Gate | GO | NO_GO / rollback |
| --- | --- | --- |
| 이번 36.14C | vector/Python core 일치, 네 방식의 경계 기록, API·storage·production schema 불변 | fixture drift, cross-generation 재사용, API/저장 추가 또는 문서 계약 실패 시 결정 보류 |
| 36.14D | 새 세대·ref binding·상태 전이·reset·memory 수명·rollback switch의 JS tests 통과; queue, checklist, risk 및 analysis invariant 유지 | 상태 자동 변경, stale route 복원, URL/storage leak, 성공 false indication이면 UI integration 비활성화하고 compact queue로 rollback |
| 향후 durable 재검토 | 실제 승인된 snapshot resume 요구, 사용자/session ownership, retention/deletion, CSRF, multi-client CAS와 corruption 처리 설계 | snapshot 없이 상태만 남기거나 인증/삭제 소유권이 unresolved면 계속 `NO_API/NO_SQLITE/NO_WEB_STORAGE` |

## 한계 및 미검증

36.14C는 UI나 API를 실제로 연결하지 않는다. document-memory 수용성, 모바일/접근성 및 사용자 이해도는 36.14D 이후 별도 검증해야 한다. 이 작업 환경은 macOS이므로 새 SHA의 Ubuntu CI 및 Linux 전용 process/smoke 결과는 `NOT_TESTED`; Safari와 실제 모바일 기기도 `NOT_TESTED`다. 시작 exact SHA의 CI Linux/browser gate 성공은 baseline evidence이며 이번 미푸시 변경의 검증으로 대체하지 않는다. 실제 사용자 자료·조직 운영·자동 대응은 계속 `NO_GO`; 모델 기반 AI는 사용하지 않는다.

## TDD 및 로컬 검증 기록

- contract tests를 먼저 추가한 뒤 실행해 vector fixture 부재로 `3 errors`, decision document 부재로 `1 failure`를 확인했다. vector 작성 후 JSON transition pair를 Python set에 넣은 테스트 자체의 `TypeError`가 한 번 발생해 pair를 tuple로 바꿨고, 의미 계약이나 assertion은 완화하지 않았다.
- vector + 36.14A/B + compact queue 관련 focused tests: `289 passed, 2 warnings`; 최종 vector/문서 계약 focused tests는 `40 passed`.
- 전체 `uv run pytest -q`: 최종 `3630 passed, 2 warnings`.
- 합성 boundary `79/79`, Linux process 합성 평가 `21/21`, risk/case `70/70` 각각, Phase 36.1 `44/44`, Phase 36.2 `24/24`.
- TCP Syslog basic 및 management smoke, JSONL runtime smoke: 통과. Chromium/axe: `25 states`, `external_requests=0`.
- Queue browser E2E: `checklist_posts=0`, `external_requests=0`, page/console errors 0, axe violations 0. Navigation E2E: route만으로 checklist POST 0, external requests 0, CSP 확인.
- `uv sync --locked --dev`, `uv lock --check`, Python compile, Node syntax, `git diff --check`, privacy/secret/path/conflict scan 통과. README는 수정하지 않았으며 16,781 bytes다. dependency 및 lockfile 변경 없음.
- Linux 전용 TCP reliability 및 Restricted Report 새 로컬 SHA 실행은 macOS에서 하지 않아 `NOT_TESTED`; Ubuntu 재검증은 새 SHA push CI가 필요하다. Safari와 실기기 모바일도 `NOT_TESTED`.
