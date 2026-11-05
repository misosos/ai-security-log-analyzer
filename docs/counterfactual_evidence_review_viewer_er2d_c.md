# ER-2D-C — 격리된 합성 근거 검토 화면

## 1. Executive Summary

고정 합성 snapshot을 browser에서 독립 검증하고 별도 workspace에서 읽기 전용으로 탐색한다. 실제 사건·운영 탐지·독립 사람 검토의 승인이 아니다.

## 2. Start SHA / CI

시작 `6dfdb97d9df05b1a641f84425327bba80f8393be`, exact push CI `42015723289` completed/success, 필수 Linux·Restricted Report·Chromium/axe·tracked-file 성공, artifact 0. HEAD/main/origin/main/GitHub main 일치, clean, behind/ahead 0/0, v0.4.0 target `eecd6ee1cda0545e34b01c42e1a2163a899bcc27`.

## 3. Existing Architecture

ER-2D-B의 고정 snapshot `frontend/evaluation-snapshot-v1.json`, file SHA-256 pin 및 local admission을 변경하지 않는다. 원래 `index.html`, `app.js`, style 및 조사 상태를 보존한다. Server는 고정 asset reader로 ON 자산을 제공한다.

## 4. Feature Flag Integration

기존 `EVIDENCE_REVIEW_VIEWER_ENABLED` 및 `create_app()` 명시적 ON을 사용한다. OFF의 `/` bytes는 원래 HTML 그대로이고 snapshot·validator·viewer JS/CSS 경로가 없다. ON에서는 기존 고정 HTML에서 고정된 세 marker를 확인해 nav·별도 main·script/style link를 삽입한다. CSP, fixed asset allowlist와 외부 의존성 금지를 유지한다. Live service가 없을 때 ON HTML의 기존 live status script를 제외하여 미활성 서비스 자동 요청을 방지하며, live service가 구성되면 해당 script를 유지한다.

## 5. Browser Validator

`evaluation-snapshot-validator-v1.js`는 fixed same-origin GET, credentials omit, no-store, redirect error, 200과 정확한 MIME을 요구한다. ReadableStream 누적 128 KiB 제한 후 UTF-8 strict, file pin, canonical syntax, closed schema, inventory, enum/reason, parser/detection/outcome 및 count를 검증한다. 완전한 검증 전 화면에 내용을 설치하지 않는다.

## 6. Trusted Pin

JS에 별도 고정한 전체 파일 SHA-256 `9f39bb5c814acf8627151681525c7d169e880feb8bd24dc106b5d87075559195`을 원본 bytes와 비교한다. Body `snapshot_sha256`과 분리한다. 둘은 서명이 아니며 공격자가 신뢰된 code와 asset을 함께 변경하면 출처 인증을 제공하지 않는다.

## 7. Canonical JSON Compatibility

Python `ensure_ascii=True`, sorted ASCII schema keys, compact separators, 마지막 LF 및 body digest scope에 맞춘 JS canonicalizer를 사용한다. UTF-16 surrogate·비ASCII escape, ASCII control/string escape, boolean/null, array 순서, 안전한 정수와 key sorting을 Python/JS golden vector로 검사한다. float 및 비ASCII object key는 schema 밖이므로 거부한다. JSON.parse 이후 재직렬화가 원본 전체와 정확히 같아야 하므로 root/nested/escaped duplicate key를 포함한 비canonical 입력은 수용되지 않는다.

## 8. Corpus Inventory

별도 JS metadata에 development/holdout manifest digest와 30개 corpus·scenario·detector·mutation tuple을 결속한다. 현재 16/14건은 회귀 관측치이며 총건수만으로 승인하지 않는다. 행별 corpus·고유 ID 및 모든 corpus summary를 재계산한다.

## 9. Comparison Integrity

Outcome 네 조합과 해당 OUTCOME reason 하나만을 요구하고 모순 reason을 거부한다. INCOMPARABLE·UNDETERMINED를 미탐지로 바꾸지 않는다. REJECTED는 detector NOT_EVALUATED 및 INCOMPARABLE을 요구한다. Browser는 private evidence나 실 detector를 재실행·독립 입증하지 않는다.

## 10. UI Information Architecture

`Counterfactual Evidence Review`, 상시 `합성 평가 전용 · 실제 보안 사건 아님`, 평가 범위·양 corpus·전체·비교 가능/제외·독립 검토·운영 승인 상태, 여섯 비교 분포를 표시한다. 데스크톱 semantic table, 좁은 화면 description list, scenario detail과 `ER-1D 설명 자료 없음` 및 해석 제한을 제공한다.

## 11. Search/Filter/Sort

Scenario ID·detector·mutation 검색, corpus·detector·comparison 필터, corpus/scenario 또는 comparison 정렬은 AND 결합한다. 입력 상한 64자, client memory에서만 적용하고 전체 분모와 필터 결과를 구분하며 조건 초기화와 빈 결과를 제공한다.

## 12. Snapshot Lifecycle

NOT_LOADED, LOADING, VERIFIED, INVALID, STALE, UNAVAILABLE, UNSUPPORTED_VERSION을 구분한다. 명시적 재확인 시 기존 snapshot을 폐기하고 전체 재검증 후 atomic install한다. AbortController와 generation으로 이탈·늦은 응답을 무시하며 실패 시 고정 메시지만 표시하고 detail을 제거한다. view state는 snapshot closure와 결속된다.

## 13. Synthetic/Production Isolation

별도 root, state, 검색 및 선택을 사용한다. 조사 registry, risk, checklist, guidance, report, SSE, live·checkpoint·publication에 snapshot을 삽입하지 않는다. Snapshot은 browser storage, clipboard, URL에 자동 저장하지 않으며 외부 network, LLM, 자동 분석 POST를 호출하지 않는다.

## 14. Privacy Security

Snapshot의 allowlist 밖 raw log, account/IP, path, expected label, label basis, private owner/context를 화면에 내보내지 않는다. DOM은 createElement/textContent/replaceChildren만 사용한다. CSP를 유지하고 HTML insertion·eval·inline event handler가 없다. 동시 code/pin 변경에 대한 인증 및 실제 공격·침해 판정은 제공하지 않는다.

## 15. Accessibility

Heading·nav·label·semantic table 및 mobile description list, keyboard, focus-visible, 상세 focus와 Escape/목록 복귀 focus, polite live status, 44px controls, 텍스트 병기 및 reduced-motion CSS를 사용한다. 자동 axe는 별도 수동 screen reader 검사를 대체하지 않는다.

## 16. Responsive Design

1920/1440/1024/768/390/320px과 320px 200% equivalent reflow를 합성 Chromium에서 검사한다. 긴 ID 및 상태는 줄바꿈하며 좁은 화면에 table 대신 description list를 사용한다. Horizontal overflow를 hidden으로 감추지 않는다.

## 17. TDD RED/GREEN

시작 전체 pytest 3871 passed, 2 warnings. ON nav/root 및 validator 부재로 신규 서버 계약 2 failed, OFF 1 passed를 확인한 뒤 구현했다. 최초 browser에서 nav 닫힘, main landmark 및 200% 긴 상태 overflow를 발견해 수정했다. Python/JS golden vector, duplicate key 및 outcome 변조 시험을 별도로 실행한다.

## 18. Browser Tests

격리 임시 Chromium profile과 loopback 합성 서버에서 실제 snapshot 30건, desktop 및 mobile axe, 6개 viewport·200% overflow, 검색/AND filter/정렬·상세/키보드 Escape/focus, invalid 후 이전 결과 제거와 delayed response 이탈을 검사했다. 외부 요청, POST, page/console 오류 및 axe 위반은 0이다. 기존 조사 UI의 `npm run test:a11y`도 성공했다. Safari/WebKit, 실제 모바일, 수동 screen reader는 NOT_TESTED다.

## 19. Full Regression

로컬 macOS 전체 pytest는 3877 passed, 2 warnings, 신규 집중 pytest는 6 passed다. 기존 Evaluation Runner, `uv lock --check`, compileall, `git diff --check`, 신규 및 기존 Chromium/axe가 성공했다. 시작 GitHub Ubuntu CI와 로컬 검증을 구분한다. 새 커밋의 CI는 사용자 push 이후에만 확인할 수 있다.

## 20. Local ON Execution Guide

Source checkout에서 포트 8000이 사용 가능할 때 다음 명시적 명령을 실행하고 `http://127.0.0.1:8000/`에서 `합성 평가`를 선택한다. 종료는 Ctrl+C다. 일반 `uv run python -m app.local_web`는 OFF다.

```bash
uv run python -c 'import uvicorn; from app.api import create_app; uvicorn.run(create_app(enable_evidence_review_viewer=True, evidence_review_port=8000), host="127.0.0.1", port=8000, workers=1, proxy_headers=False, reload=False)'
```

정적 소스·합성 fixture pin이 일치해야 하며 설치된 dependency/OS 및 동시 로컬 변조를 pin이 인증하지 않는다.

## 21. Rollback

서버 기본 OFF 또는 명시적 ON 제거로 JSON·JS·CSS route, navigation, evaluation root 및 fetch가 모두 사라진다. 기존 HTML bytes와 조사 UI/API를 사용한다. 검증 실패 시 일부 데이터나 이전 결과를 남기지 않는다.

## 22. ER-2E Entry Requirements

사용자 push, exact SHA push CI 성공과 artifact 0, browser validator contract, UI·privacy·production isolation을 확인한 뒤 별도 승인으로 ER-2E를 시작한다. Safari, 실제 모바일, 수동 screen reader 및 사용자 수용을 각기 검증한다.

## 23. Human Review Gate

`INDEPENDENT_HUMAN_REVIEW_PENDING`, `MANUAL_APPROVAL_REQUIRED`, `ER_1D_IMPLEMENTATION_HOLD` 유지. Viewer는 독립 label-blind packet이 아니다. 실제 사용자 자료·조직 운영·자동 대응은 `NO_GO`다.

## 24. Limitations

Digest와 pin은 신뢰된 설치물의 변경 감지이며 서명이 아니다. Browser는 Python replay의 private evidence를 재검증하지 않는다. Source checkout이 없는 bundle ON, Safari/WebKit, 실제 모바일 및 수동 screen reader는 이 단계의 미검증 범위다. Node의 package module-type 경고는 테스트 환경 경고이며 dependency/lockfile을 변경하지 않았다.

## 25. Final Decision

필수 검사 통과 시 `ER_2D_C_ISOLATED_EVIDENCE_REVIEW_VIEWER_LOCAL_CONDITIONAL_GO`: 고정 합성 자료의 로컬 viewer에만 해당한다. 사람 독립 검토, 실환경 정확도, 실제 운영 또는 ER-1D 구현 승인이 아니다.
