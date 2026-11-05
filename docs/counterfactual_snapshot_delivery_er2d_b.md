# ER-2D-B — 고정 합성 Snapshot 서버 전달

## 1. Executive Summary

ER-2C 합성 snapshot을 별도의 코드 pin과 비교해 고정 local asset으로 제공한다. 기본 OFF이며 ON은 명시적으로 구성한 `create_app()`에서만 사용한다. Viewer·browser validator·navigation은 없다.

## 2. Start SHA / Exact CI

시작 `4ffe56e335330f7791ce9a87eb3f368dcfce7db8`, HEAD/main/origin/main/GitHub main 일치, clean, behind/ahead 0/0. Run `42008316764` push/completed/success, 전체 regression, 필수 Linux, Restricted Report, Chromium/axe 및 tracked-file 성공, artifact 0. v0.4.0 tag 및 Release target `eecd6ee1cda0545e34b01c42e1a2163a899bcc27`.

## 3. ER-2D-A Approved Architecture

고정 Synthetic Corpus → ER-2C offline replay/검증 → canonical JSON → 별도 code pin → 조건부 local asset route. HTTP 요청에는 replay·decoder를 사용하지 않는다. Browser 검증은 후속 단계다.

## 4. Snapshot Generation Procedure

검토된 고정 corpus에서 `uv run python -m app.evaluation.counterfactual_safe_projection_cli`를 실행해 `frontend/evaluation-snapshot-v1.json`을 명시적으로 생성한다. ER-2C `decode_snapshot()`과 `encode_snapshot()`으로 동일한 canonical bytes, inventory, ER-2A-R1 outcome 및 manifest를 검증하고 동일 입력 반복 결과와 privacy allowlist를 확인한다. 현재 13,783 bytes이며 마지막 LF 하나다. 재생성 시 코드 pin과 소스·fixture 목록을 함께 사람이 검토한다.

## 5. Asset and Pin Contract

전체 파일 SHA-256 `9f39bb5c814acf8627151681525c7d169e880feb8bd24dc106b5d87075559195`를 `app/evaluation_snapshot_delivery.py` 코드 상수로 고정한다. Body의 `snapshot_sha256`과 구별되며 HTTP 입력이나 asset 내부에서 expected pin을 읽지 않는다. Version 1, 합성 scope, 두 manifest와 fixture는 offline 결과 및 pin에 결속된다. Pin은 서명이나 동일 권한 공격자에 대한 출처 인증이 아니다.

## 6. Feature Flag

`EVIDENCE_REVIEW_VIEWER_ENABLED = False`; `create_app(enable_evidence_review_viewer=True, evidence_review_port=<1024..65535>)`만 ON이다. bool만 허용하고 port를 정확히 요구하며 Linux Audit restricted mode와 함께 켜지 않는다. 일반 local launcher를 바꾸지 않았으므로 일반 실행은 OFF다. OFF는 route 미등록·직접 GET 404·OpenAPI path 없음이다. ON에서도 새 UI·navigation은 없다.

## 7. HTTP Delivery

ON일 때 고정 `GET /assets/evaluation-snapshot-v1.json`, 성공 200, `application/json; charset=utf-8`, `no-store`, `nosniff`, 기존 CSP 및 referrer policy를 사용한다. 전송되는 body는 pin 검증한 단일 descriptor bytes 그대로다. 임의 query/body/path, 다른 method, 오류 자료는 제공하지 않고 고정 404 또는 framework 405를 반환한다. 외부 CORS 허용 헤더는 없다.

## 8. Localhost Admission

기존 `classify_local_request()`의 loopback peer, forwarded header, Host/Origin 및 cross-site 검사를 사용하고, ASGI server 주소와 명시적으로 구성한 127.0.0.1/port, 정확한 단일 Host를 추가 확인한다. 같은 Origin 또는 부재만 허용하고 null/cross-origin을 거부한다. Fetch Metadata가 있으면 site·mode·dest를 각각 제한한다. Host는 사용자 인증이 아니며 다른 로컬 프로세스를 인증하지 않는다.

## 9. File Integrity and TOCTOU

고정 root 아래 directory descriptor를 O_DIRECTORY/O_NOFOLLOW로 연 뒤 literal 파일에 대해 lstat 해당 `stat(..., follow_symlinks=False)`, O_NOFOLLOW open, regular file, device/inode, bounded read, 전후 metadata와 현재 directory entry 및 file SHA-256을 확인한다. 검증한 bytes를 다시 열지 않고 응답한다. Symlink·부분 읽기·교체·비정상 크기·누락은 404다. 동일 권한 공격자가 코드·pin을 같이 수정하거나 source 검증 사이를 교묘히 경쟁하는 경우의 완전한 방어는 아니다.

## 10. Replay Zero Boundary

HTTP 요청은 합성 asset, 두 고정 manifest, 합성 fixture 31개 및 replay의 정적 import 의존성 소스 37개의 고정 bytes와 code pin을 대조한다. 이는 파일 digest 검사이며 `run_corpus`, `run_holdout`, `build_report`, `build_snapshot`, `decode_snapshot` 및 평가 CLI는 호출하지 않는다. 동시 요청에서도 동일하게 검사한다. 응답 시간과 메모리는 측정하지 않았고 운영 SLA를 주장하지 않는다.

## 11. Snapshot Lifecycle

누락·변경·empty·oversized·symlink·directory·부분 읽기·file replacement·manifest 또는 source/fixture pin 불일치 시 전체 404, 이전 성공 결과나 자동 재생성 없음. replay의 정적 import 의존성을 source version에 포함하며 변경 시 명시적인 재검토 및 pin 갱신이 필요하다. 무관한 검토 상태 core는 요청 경로에서 읽지 않는다. 동적 import, 신뢰된 전달 코드 자체와 설치된 dependency 및 OS는 이 pin의 인증 범위 밖이다.

## 12. Synthetic/Production Isolation

고정 합성 bytes만 read-only 반환하며 Investigation Registry, case/risk count, checklist, guidance, report 및 live monitoring을 읽거나 변경하지 않는다. 실제 조직 자료, 사용자 경로, 네트워크 URL은 입력받지 않는다.

## 13. Privacy Security

별도 합성 snapshot allowlist 및 raw bytes 검사로 원문 로그, account/IP, label basis, expected label, owner/context, 경로 비노출을 확인한다. 고정 오류는 원문 예외와 경로를 반사하지 않는다. Network 차단 테스트는 합성 TestClient 요청에서 수행했고 OS 전체의 모든 네트워크 활동을 증명하지 않는다.

## 14. TDD RED/GREEN

기준선 3824 passed, 2 warnings. route·flag 미구현 상태에서 8 failed RED 후 구현했다. 고정 asset은 실제 CLI 생성 및 decoder roundtrip으로 확인했다. 추가 admission·tamper·격리 회귀는 구현 중 확장했다. 첫 전체 회귀는 무관한 검토 상태 core 소스를 광범위한 pin 목록에 포함해 기존 격리 테스트 1건이 실패했다. pin을 replay의 정적 import 의존성으로 좁힌 뒤 해당 테스트가 통과했다.

## 15. HTTP Security Matrix

신규 테스트는 OFF/ON·strict bool/port·restricted conflict, exact bytes·headers, cross-origin/null/forwarded/잘못된 Host/중복 Host/peer, Fetch Metadata, query/body/메서드, missing/empty/oversize/symlink/directory, manifest/fixture/source 변조, replacement·partial read, 다중 요청 및 replay 0을 검사한다. 실제 loopback Uvicorn 정상 Host와 위조 Host도 검사한다. 파일 교체 주입과 부분 읽기는 격리된 임시 디렉터리에서 수행한다.

## 16. Full Regression

신규 전달 테스트 47 passed, ER-2C·ER-2A-R1·기존 local API/UI 집중 회귀 220 passed(추가 테스트 전). 최종 전체 pytest 3871 passed, 2 warnings. Evaluation Runner synthetic boundary 79/79, risk/case 각 70/70, Linux process 합성 분류 21/21. 기존 Chromium·axe `npm run test:a11y --silent` 성공, external_requests=0. 첫 전체 회귀의 1건 실패와 수정은 14절에 기록했다. 시작 CI는 Ubuntu이고 로컬 테스트는 macOS다. 합성 Linux 분류를 로컬 Linux host 검증으로 표현하지 않는다.

## 17. ER-2D-C Browser Consumer Contract

향후 browser는 response bytes bound, strict UTF-8/duplicate key, closed schema/version/enum, corpus inventory, outcome/reason, count, body digest 및 별도 신뢰된 JS/version metadata pin, stale response를 독립 검증한다. JSON 자체 또는 같은 response header의 digest를 독립적인 신뢰 anchor로 취급하지 않는다.

## 18. Rollback

기본 flag OFF면 서버 route가 등록되지 않는다. 변조·privacy·Host/Origin 실패, replay 또는 조사 데이터 혼합이 발견되면 OFF로 두고 새 route 제거 시 기존 조사 API/UI 경로로 돌아간다.

## 19. Known Limitations

서버는 runtime에 68개 source/fixture 파일과 두 manifest 및 asset을 읽어 digest를 확인하므로 I/O가 생긴다. 이 비용은 측정하지 않았다. source checkout 파일이 없는 bundle 환경에서 ON은 검증되지 않았으며 기본 OFF다. 정적 import 검사로 동적 의존성이나 설치된 dependency를 증명할 수 없다. 신뢰된 소스 파일 검사 전후의 동시 로컬 변조를 원자적으로 봉쇄하지 않고, pin과 코드 동시 교체에 대한 서명이 없다. Browser·Safari·모바일·screen reader·사용자 수용은 이번 단계에서 검증하지 않았다.

## 20. Human Review Gate

`INDEPENDENT_HUMAN_REVIEW_PENDING`, `MANUAL_APPROVAL_REQUIRED`, `ER_1D_IMPLEMENTATION_HOLD` 유지. 실제 사용자 자료·조직 운영·자동 대응 `NO_GO`. 합성 결과는 blind review packet이 아니다.

## 21. Final Decision

필수 회귀 성공 시 `ER_2D_B_FIXED_SNAPSHOT_DELIVERY_LOCAL_CONDITIONAL_GO`: 서버 합성 자료 전달에 한정하며 Browser Validator·Viewer·운영 사용 승인과 다르다. ER-2D-C는 사용자 push 후 정확한 SHA CI와 별도 시작 Gate가 필요하다.
