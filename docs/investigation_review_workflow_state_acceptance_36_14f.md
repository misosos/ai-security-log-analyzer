# Phase 36.14F — 검토 진행 상태 UI 사용자 이해도·수용 검수

## 판정

최종 판정은 `PHASE_36_14F_REVIEW_WORKFLOW_STATE_USER_ACCEPTED`다. 사용자는 실제 Production UI renderer로 만든 합성 화면을 본 뒤 12개 문항에 모두 `PASS`로 응답했다. `FAIL`, `NOT_TESTED`, Production 수정 및 재검수는 없었다.

이 판정은 격리된 Chromium 합성 화면에서 검토 진행 상태의 의미와 사용 흐름을 이해할 수 있다는 사용자 수용 결과다. Production 운영 승인, 실제 조직 workflow 승인, 안전·해결 판정 또는 영속 저장 승인이 아니다.

## 대상과 시작 Gate

- 대상 SHA: `b7149a8bfb09c60dc3acbfd31b0402071dfb0b7c`
- exact push CI: [41453278845](https://github.com/misosos/ai-security-log-analyzer/actions/runs/41453278845)
- 검수 시작 시 branch는 `main`, working tree는 clean, HEAD/local main/origin main/GitHub main은 대상 SHA와 일치했고 behind/ahead는 `0/0`이었다.
- exact run은 대상 SHA의 `push / completed / success`였다. 전체 pytest는 `3637 passed, 2 warnings`였고 Linux TCP Syslog 기본·reliability·management, JSONL Linux acceptance, Restricted Report, Chromium/axe와 tracked-file 검사가 실제 실행되어 성공했다.
- Chromium/axe 표식은 `states=25 external_requests=0`, artifact는 0개였다.
- `v0.4.0` tag와 GitHub Release target은 기존 `eecd6ee1cda0545e34b01c42e1a2163a899bcc27`을 유지했다.

## 합성 fixture와 격리 방식

Production FastAPI와 Production UI를 loopback 주소에서 실행했다. Chromium은 task 전용 임시 user-data directory와 임시 HOME/XDG 경계를 사용했고, 종료할 때 서버와 브라우저 process를 정리했다. 실제 사용자 로그, checkpoint, 사용자 브라우저 profile 또는 실제 조직 자료는 사용하지 않았다.

검수 화면은 기존 sample 분석 결과를 기반으로 했다. 여러 상태와 서로 다른 역할·확인 순서를 한 화면에서 보여주기 위해 same-origin test-only route에서 검증된 사례 projection 하나를 합성 복제해 3개 사례로 만들고, 사용자가 명시적으로 checklist 버튼을 누르는 흐름으로 세 역할과 확인 순서를 설치했다. Production renderer, route, 검토 상태 document memory store와 상태 control은 실제 코드를 사용했다. 화면에는 다음 고정 안내를 표시했다.

> 합성 예시입니다. 실제 조직 환경이나 사용자의 보안 상태를 나타내지 않습니다.

각 화면 생성 run에서 sample POST는 1건, 사용자가 명시적으로 수행한 checklist POST는 3건이었다. 검토 상태 변경으로 발생한 상태 API 요청과 자동 checklist POST는 0건이었다. 요청 body나 원문은 기록하지 않았고, 외부 요청은 `external_requests=0`이었다.

## 보여준 화면

화면은 임시 directory에 생성해 사용자에게 전체 화면을 먼저 보여주고 필요한 상태 control 또는 카드 문맥을 함께 제시했다. binary screenshot과 임시 profile은 repository에 커밋하지 않는다.

1. 1440px 초기 검토 큐와 합성 안내
2. 카드의 검토 상태 control 및 서로 다른 역할·확인 순서
3. 같은 `검토함` 상태이지만 위험도가 다른 두 사례
4. `검토 중`, `검토함`, `나중에 확인`이 함께 보이는 목록
5. 상세 화면의 `검토함` 상태
6. 고위험 사례 상세 화면의 `나중에 확인` 상태
7. `검토 전 → 검토 중 → 검토함 → 나중에 확인 → 상태 초기화` 뒤 목록
8. 검토 상태 filter panel과 `검토함` 1건 결과 및 전체 상태 집계
9. `나중에 확인` filter 결과 0건과 “분석 결과가 없다는 뜻은 아닙니다” 안내
10. 상세에서 `검토함`을 `검토 중`으로 바꾼 뒤 목록에 이어진 상태
11. 390px 목록, 390px 상세, 320px 목록
12. 1440px의 서로 다른 세 검토 상태와 390/320px 보조 화면

고정 sample의 시각은 합성 fixture 시각이며 실제 사용자 로그 시각이 아니다. DevTools, 개인 경로, browser bookmark 또는 실제 profile 정보는 화면에 포함하지 않았다.

## 문항별 최초·최종 응답

질문은 화면을 먼저 보여준 뒤 한 번에 하나씩 진행했다. 대소문자만 다른 직접 응답과 한글 키가 접두된 명백한 `PASS` 입력은 원문을 보존하고 의미를 `PASS`로 정규화했다. 9번 화면을 보여주기 전에 도착한 선행 `pass`는 문항 응답으로 사용하지 않았고, 화면을 제시한 뒤 받은 별도 `pass`만 9번 최초 응답으로 기록했다.

| # | 검수 주제 | 최초 응답 원문 | 정규화 | 재검수 | 최종 |
|---:|---|---|---|---|---|
| 1 | 기능 목적: 보안 판정이 아닌 작업 진행 표시 | `PASS` | PASS | 없음 | PASS |
| 2 | 카드 정보와 상태 control의 목록 가독성 | `PASS` | PASS | 없음 | PASS |
| 3 | 검토 상태와 위험도·확인 순서 구분 | `pASS` | PASS | 없음 | PASS |
| 4 | 네 상태가 안전·공격 성공을 뜻하지 않음 | `pass` | PASS | 없음 | PASS |
| 5 | `검토함`이 해결·안전·무해를 뜻하지 않음 | `pass` | PASS | 없음 | PASS |
| 6 | `나중에 확인`이 낮은 위험·무시 가능을 뜻하지 않음 | `pass` | PASS | 없음 | PASS |
| 7 | 명시적 상태 변경과 workflow 상태만 초기화 | `ㅔpass` | PASS | 없음 | PASS |
| 8 | 상태 filter·집계가 재분석·삭제를 하지 않음 | `pass` | PASS | 없음 | PASS |
| 9 | filter 0건이 분석·보안 관찰 없음이 아님 | `pass` | PASS | 없음 | PASS |
| 10 | 목록과 상세의 상태 연속성 | `pass` | PASS | 없음 | PASS |
| 11 | document memory 수명과 새 분석·reload 후 미복원 | `pass` | PASS | 없음 | PASS |
| 12 | 복잡도를 과도하게 높이지 않는 전체 유용성 | `pass` | PASS | 없음 | PASS |

최종 응답은 `12/12 PASS`다. 최초 `FAIL` 0건, 최종 `FAIL` 0건, 사용자 문항 `NOT_TESTED` 0건이며 재검수 이력은 없다.

## 자동 검증과 사용자 검수의 구분

Phase 36.14E의 contract vector, CAS, generation 격리, storage·network 부재, 분석 불변성, keyboard/focus, viewport/reflow와 axe 자동 검증은 이 사용자 응답의 선행 안전 근거다. 자동 결과를 사용자 `PASS`로 변환하지 않았다. 이번 문서의 12개 PASS는 화면을 본 사용자의 직접 응답만 기록한다.

수용 화면 생성 과정에서도 검토 상태는 document memory에만 있었고 상태 API, Web Storage, SQLite 또는 파일 저장을 사용하지 않았다. 새 분석과 reload 뒤 상태를 복원하지 않으며 상태가 URL, report, clipboard, checklist body 또는 analysis response에 포함되지 않는 기존 계약을 바꾸지 않았다. 검토 상태는 detection, relation, risk, case, review priority, checklist 및 report를 변경하지 않는다.

## 개인정보·모바일 판단 범위

- 화면과 접근 가능한 UI에는 원문 로그, 실제 account, IP, hostname, 사용자 파일 경로, credential, token, 내부 `analysis_ref` 또는 opaque `case_ref`를 추가하지 않았다.
- 390px 목록·상세와 320px 목록을 11번 전에 사용자에게 보여줬고, 사용자는 저장 범위 문항과 최종 유용성 문항에 PASS했다. 이는 합성 Chromium viewport 사용자 판단이다.
- 자동 Chromium의 320px 및 200% equivalent reflow 검증은 Phase 36.14E에서 수행됐다. 실제 모바일 기기는 `NOT_TESTED`다.
- Safari는 `NOT_TESTED`다. 실제 screen reader 발화도 `NOT_TESTED`다. Chromium 화면 검수로 이를 대체하지 않는다.
- 새 수용 기록 커밋의 Ubuntu CI는 push 전이므로 `NOT_TESTED`다. 기준 SHA의 exact Ubuntu CI 성공만 시작 Gate 근거로 사용했다.

## 완료 후 회귀 검증

- Phase 36.14A–F focused pytest: `48 passed`.
- 전체 pytest: `3638 passed, 2 warnings`. 기존 Starlette/httpx와 AnyIO deprecation warning 2개만 유지됐다.
- workflow 상태 security E2E: `REVIEW_WORKFLOW_STATE_SECURITY_36_14E_SMOKE_PASS`; contract 전이 16쌍, 동일 revision 경쟁 성공 1·stale 거부 1, 1440/1024/768/390/320px overflow 0, workflow 상태 API 0, 명시 checklist POST 1, 외부 요청 0, page/console error 0.
- Phase 36.14D UI E2E: `REVIEW_STATE_36_14D_PASS`; 상태 API 0, 자동 checklist POST 0, 외부 요청 0, axe 위반 0.
- Phase 36.13A queue E2E: `REVIEW_QUEUE_36_13A_PASS`; checklist POST 0, 외부 요청 0, axe 위반 0. UI navigation closure는 sample POST 1, guidance POST 1, checklist POST 0, 외부 요청 0과 CSP를 확인했다.
- Phase 36.12B input-quality E2E: `UI_INPUT_QUALITY_36_12B_PASS external_requests=0 axe_violations=0`.
- 25-state Chromium/axe 최종 clean run: `states=25 external_requests=0`; 320px equivalent 200% reflow에서 overflow·clipping·target failure 0. 첫 두 로컬 시도는 각각 서로 다른 `REAL_GUIDANCE_STALE_OR_MUTATED`와 `live-empty` timeout으로 중단됐고, 잔여 Chromium/server가 없음을 확인한 동일 assertion의 세 번째 격리 실행은 전체 통과했다. 테스트 assertion이나 timeout은 변경하지 않았다.
- 합성 evaluator: `79/79`; Linux process 합성 evaluator: `21/21`; risk/case: 각각 `70/70`. Phase 36.1은 `fixtures=44`, privacy leak 0, analysis mutation 0; Phase 36.2는 `fixture_count=24`, status/citation/semantic 지표 100%였다.
- TCP Syslog 기본 smoke, management smoke 및 JSONL runtime smoke가 통과했다. Linux-only reliability/acceptance smoke는 로컬 macOS 결과로 대체하지 않았으며 기준 SHA의 exact Ubuntu CI 성공만 기록한다.
- `uv sync --locked --dev`, `uv lock --check`, `npm ci --ignore-scripts`, Python compile, 전체 frontend/test Node syntax, `git diff --check`, 변경 파일 credential·개인 경로·conflict marker 검사와 dependency/lockfile 불변 검사가 통과했다. README는 변경하지 않았고 `16,781` UTF-8 bytes로 17,000-byte 계약 이내다.
- Phase 36.1 evaluator를 파일 경로로 처음 호출했을 때 repository import root가 없어 `ModuleNotFoundError`가 발생했다. 같은 evaluator를 지원되는 module 호출로 즉시 재실행해 위 `44/44` 결과를 확인했으며 코드나 환경은 변경하지 않았다.

## 변경과 운영 경계

수용 과정에서 Production Python, API, frontend JavaScript/CSS/HTML, dependency 및 lockfile은 변경하지 않았다. 변경은 이 수용 기록, 문서 계약 테스트와 docs index 링크뿐이다.

실제 사용자 자료: `NO_GO`; 조직 운영: `NO_GO`; 자동 대응: `NO_GO`. 모델 기반 AI는 이 기능과 검수에 사용하지 않았다. 검토 상태는 작업 보조 metadata이며 보안 판정, 대응 결정 또는 조직 workflow 승인을 의미하지 않는다.
