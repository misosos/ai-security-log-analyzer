# ER-2D-A — 합성 Snapshot 전달 보안 설계

## 1. Executive Summary

권고는 **Option A: 고정 합성 JSON asset**, 별도 Evaluation Workspace, 기본 OFF다. 명시적 사전 생성과 검증된 버전 결속을 전제로 하며, 이 문서는 전달 경로를 구현하지 않았다. 서버·브라우저 검증의 구체적 구현은 각각 별도 승인과 Gate가 필요하다. Viewer는 독립 검토자의 Blind Packet을 대체하지 않는다.

## 2. Start SHA / Exact CI

시작 `f3b93d90528e861bc0af5c3b20abec690a541d24`: HEAD/local main/origin/main/GitHub main 일치, clean, behind/ahead 0/0. Run `41962397819` push/completed/success, Linux regression·TCP·JSONL·Restricted Report·Chromium/axe·tracked-file 성공, artifact 0. v0.4.0 tag 및 Release target `eecd6ee1cda0545e34b01c42e1a2163a899bcc27` 유지.

## 3. Existing ER-2C Snapshot Architecture

`counterfactual_safe_projection._produce()`는 고정 corpus의 `run_corpus()`/`run_holdout()`을 실행하고 ER-2A `build_report()`의 R1 outcome/reason, inventory, count 검증을 거친다. `build_snapshot()`은 safe allowlist body와 body SHA-256을 만들고, `encode_snapshot()`은 `decode_snapshot()`을 호출한다. Decoder는 JSON·digest 검증 후 `_produce()`를 재실행해 현재 body와 전체 비교한다. Snapshot의 `_view()`도 decoder를 호출한다. 이번 로컬 CLI 확인의 출력은 13,783 bytes, 상한 128 KiB다. 현 schema v1, 두 corpus, 현재 30건은 실제 보안 사건이나 운영 정확도가 아니다.

## 4. Current FastAPI/Web Security Boundary

`app/api.py:create_app()`은 `/`와 `/assets/...`를 각각 고정 등록하고 일반 경로를 mount하지 않는다. `app/web_ui.py:_fixed_asset()`은 literal 이름, lstat, O_NOFOLLOW, fstat device/inode 및 일반 파일·크기 확인을 수행하며 파일 상한은 160 KiB다. CSP `default-src 'none'`, `connect-src 'self'`, `worker-src 'none'`, `nosniff`, `Cache-Control: no-store`를 사용한다. `app/local_web.py:_server()`는 `127.0.0.1`, 지정 port, worker 1, proxy headers/reload off다. 기존 상세 route와 projection은 document memory/hash에 속한다. 기존 local admission은 일부 API에 적용되므로 새 정적 전달에 Host/Origin 검사가 이미 적용된다고 가정하지 않는다. 기존 브라우저 harness는 Chromium/axe·navigation·external request·명시적 checklist 동작을 검증한다.

## 5. Delivery Options

| 기준 | Option A 고정 합성 JSON asset | Option B 전용 read-only local endpoint | Option C 별도 local viewer |
|---|---|---|---|
| 보안·출처 | 버전 고정 자산·별도 기대 digest 및 OFF route 차단 필요 | loopback과 별도 Host/Origin/method 검증 필요 | 조사 프로세스와 분리 가능; 별도 origin/서버 보호 필요 |
| 복잡도·유지 | 명시적 생성·고정 allowlist, 재생성 검토 필요 | 응답 lifecycle·동시성·오류 처리 필요 | 실행·포트·배포 및 CSP 구현 중복 |
| 성능·운영 | 요청은 고정 bytes; 사전 replay 수행 | 요청마다 replay 시 비용·DoS 위험; 사전 검증 immutable cache 필요 | 시작·별도 프로세스 비용, 미측정 |
| 출처 혼동·privacy | synthetic banner, 고정 공개 필드; Blind Packet과 분리 | 동일 조건과 조사 API 분리 필요 | 별도 실행으로 혼동 감소, 배포 실수 가능 |
| 접근성·검증 | 기존 브라우저 harness와 독립 workspace | 동일 harness와 HTTP security matrix | 독립 keyboard/axe 및 설치 검증 추가 |
| rollback | 단일 flag OFF에서 asset 자체 404 | flag OFF에서 endpoint 자체 404 | viewer 실행 경로 비활성 |

A는 유지보수 가능한 최소 후보로 선택한다. B의 후보 URL은 `/api/evaluation/v1/snapshot`이며 이 단계에서 route를 승인·구현하지 않는다. GET만 허용, body/query/path 추가 금지, `application/json; charset=utf-8`, no-store/nosniff, exact Host·같은 Origin 검증, permissive CORS 금지, concurrency/timeout 제한이 필요하다. browser의 GET에는 Origin이 없을 수 있으므로 부재를 무조건 악성 또는 동일 출처로 단정하지 않는다. Host·peer 검증, Fetch Metadata가 있을 때의 보수적 정책, 테스트 가능한 명시적 로컬 사용자 흐름을 함께 적용한다. C는 같은 프로세스 분리가 입증되지 않으면 재검토한다.

## 6. Trust Boundary

네 판단을 분리한다: **Structural Validity**는 closed schema/type/제한; **Semantic Consistency**는 inventory/count/outcome/reason; **Snapshot Integrity**는 body digest; **Trusted Source Binding**은 배포 버전과 별도 고정 expected digest 및 신뢰된 프로그램 자산의 결속이다. Digest는 서명이 아니다. 본문과 digest를 함께 바꾸면 self-hash만으로 탐지할 수 없다. 별도 pinned digest도 공격자가 실행 파일과 모든 자산을 함께 바꾸면 인증이 아니다. 이 설계는 신뢰된 로컬 설치물, OS 계정 및 동일 사용자 프로세스 무결성을 전제로 하며 사용자 인증, 악성 로컬 프로세스 방어 또는 서명된 공급망을 주장하지 않는다.

정적 asset은 승인된 고정 corpus와 코드 버전에서 로컬 생성·ER-2C decoder 재검증하고 deterministic bytes 및 별도의 배포 metadata에 고정한 expected digest를 함께 코드 리뷰한다. source 또는 fixture 변경 시 snapshot과 pin을 함께 재생성·재검토하며 불일치 시 unavailable이다. 합성 결과만 별도 검토 후 저장소 추적 후보로 삼고 실제 자료는 제외한다. GitHub CI artifact 업로드·Release 변경은 하지 않는다. 공개 결과가 reviewer blindness를 훼손할 수 있으므로 검토자에게 제공하지 않고 공개 저장소에서의 완전 blind 불가능성을 명시한다.

## 7. Replay/Decoder Cost

`build_snapshot()`은 실제 corpus replay 1회를 포함한다. `encode_snapshot()`은 decoder를 부르고 decoder는 replay를 다시 수행한다. `Snapshot._view()`도 매 접근 decoder를 실행한다. 이 작업에서 시간·메모리 수치는 측정하지 않았다. `HTTP GET → 전체 Corpus Replay → 전체 Decoder 재실행`을 금지한다. 사전 생성·검증 이후 고정 bytes만 전달하고 HTTP 요청 및 브라우저 검증 시 Python replay를 하지 않는다. 캐시는 provenance 증명이 아니다. corpus, policy, schema, producer, pin 또는 asset 변경, 검증 실패, 재시작 시 불일치는 무효화하고 자동 재생성하지 않는다. 생성·pin 갱신은 개발자가 명시적으로 수행하고 변경을 검토한다.

## 8. Feature Flag Contract

`EVIDENCE_REVIEW_VIEWER_ENABLED`는 향후 default OFF 서버 설정과 UI build 조건에 결속한다. OFF에서는 route/endpoint가 등록되지 않아 직접 GET도 404, navigation·evaluation DOM root·state owner·fetch·evaluation JS 및 JSON asset 노출이 없어야 한다. UI 메뉴 숨김만으로는 불충분하다. ON에서도 검증된 고정 synthetic bytes만 노출하고 임의 파일·URL·corpus를 받지 않는다. 스위치와 분기 자체는 별도 후속 단계에서 구현한다.

## 9. Browser Validation Contract

브라우저는 bounded byte stream 최대 128 KiB를 읽고 UTF-8 strict, depth/collection 제한, duplicate JSON key 거부 가능한 파서, exact version·closed root 및 scenario field·enum/reason·corpus allowlist를 확인한다. `JSON.parse`만으로 duplicate를 사후 탐지했다고 주장하지 않는다. 각 corpus의 고정 inventory·manifest pin, scenario 유일성, count 분모·subtotal·전체 합계·excluded 및 outcome/reason 결합을 독립 재계산한다. 현재 30건이나 분포를 임의 상수로 강제하지 않고 버전 결속된 inventory를 검증한다.

`crypto.subtle.digest('SHA-256', bytes)`와 `TextEncoder`로 Python의 `ensure_ascii=True`, sorted key, compact separator, body에서 digest 제외, UTF-8 canonical bytes를 재현한다. escaping·순서·숫자·Unicode 및 duplicate 차이는 Python/JS 공통 golden vector로 증명해야 한다. secure context 및 API 사용 가능 여부를 feature-detect하고 불가하면 UNAVAILABLE; 약한 hash나 무검증 fallback은 없다. W3C [Secure Contexts](https://www.w3.org/TR/secure-contexts/)의 loopback potentially trustworthy 조건과 [Web Cryptography](https://www.w3.org/TR/webcrypto/)의 digest 계약을 확인하되 실제 browser 지원은 별도 테스트한다. Python decoder가 브라우저에서 replay된다고 가정하지 않는다. 별도 pin과 asset이 같은 변경 가능한 실행물에 있다면 동시 변조 방어는 제공하지 않는다.

## 10. Snapshot Lifecycle

| 상태 | 처리 |
|---|---|
| NOT_LOADED | synthetic 안내, 이전 데이터 없음 |
| LOADING | 명시적 진입 시 요청; 이전 결과는 stale 표시 후 숨김, partial UI 금지 |
| VERIFIED | digest·schema·pin·전체 일관성 검증 후 한 번에 설치 |
| INVALID | 고정 오류, 이전 결과를 최신처럼 표시하지 않음 |
| STALE | generation/version 불일치, 기존 선택·상세 비활성 및 숨김 |
| UNAVAILABLE | OFF, asset 부재, API 미지원 또는 실패 시 고정 오류 |
| UNSUPPORTED_VERSION | 정확한 version 외 거부, fallback 없음 |

요청 generation counter와 snapshot ID를 view state에 결속한다. 새 요청이나 화면 이탈 시 이전 요청을 취소·무효화하고, 지연·중복 응답은 현재 token 확인 후 무시한다. 교체 시 이전 선택·필터 상세를 정리한다. 브라우저 storage 자동 저장, URL/hash에 본문·private evidence 기록, clipboard 자동 복사를 금지한다.

## 11. Synthetic/Production Isolation

별도 route/navigation, data projection, state owner, DOM root, scenario selection, filtering, summary, browser storage 및 error state를 둔다. 조사 case/risk count, checklist, guidance, timeline, report, live monitoring, registry, attack chain, SSE, checkpoint, publication과 연결하지 않는다. 외부 network·LLM·자동 대응 없음. `합성 평가 전용 · 실제 보안 사건 아님`을 상시 표시하고 `INDEPENDENT_HUMAN_REVIEW_PENDING`, `NOT_APPROVED`를 승인 색이나 운영 성공으로 표현하지 않는다.

## 12. Threat Model

| 위험 / 공격 표면 | 실패 방식 | 방어 수단 | 자동 검증 | 잔여 위험 |
|---|---|---|---|---|
| Localhost request abuse·DNS Rebinding·Host | 원격 사이트가 loopback 요청 또는 다른 Host로 접근 | loopback peer, 단일 exact `127.0.0.1:port` Host, forwarded header 거부, no permissive CORS | 변형 Host·중복 Host·peer·rebinding synthetic 요청 거부 | 악성 로컬 사용자 및 브라우저 구현 차이는 미해결 |
| Origin/CORS·의도하지 않은 GET | cross-origin GET 도달 또는 응답 읽기 | cross-origin Origin 거부, absent Origin 정책과 Fetch Metadata, GET 부작용 0 | Origin 부재/일치/불일치, no ACAO, GET side effect 0 | Origin 없는 비브라우저 요청의 사용자 신원은 증명 불가 |
| Snapshot tampering | JSON·digest 동시 조작 | separate version pin, body digest, trusted installation | 본문·digest 동시 변조 및 pin 불일치 거부 | 같은 권한의 자산·pin 동시 변경은 방어 불가 |
| Summary·Comparison·Corpus 혼합 | count만 맞춘 잘못된 결과 | closed inventory와 행별 state/reason 재계산 | 재해시된 forged summary·outcome·corpus 거부 | 브라우저 검증이 replay의 실제 결과를 재증명하지 않음 |
| DOM XSS·HTML Injection | scenario ID를 markup으로 삽입 | textContent, 고정 DOM builder, CSP | 무해한 canary element/script 실행 0 | 브라우저 또는 새 renderer 결함 |
| prototype pollution | 객체 key가 prototype 수정 | closed key, own-property, Map/null prototype | `__proto__` canary 전후 prototype 동일 | 추가 라이브러리 도입 시 재평가 |
| 비정상 JSON·oversized | duplicate/nonfinite·자원 고갈 | strict parser·byte/depth/collection cap | duplicate, 128 KiB+1, malformed 거부 | 네트워크 buffering 구현도 별도 상한 필요 |
| Stale Response·schema migration | 지연 응답이 현재 view 덮어씀 | request token·atomic install·exact version | 지연 A/B, 변경 중 이탈, unknown version | 중단 후 사용자 screenshot의 시점 오인 |
| private evidence/IP/account/label basis | projection 또는 오류로 노출 | allowlist·fixed error·no exception repr | 구조 검사 및 무해한 privacy canary | 모든 미래 필드의 안전성 자동 보장 불가 |
| Reviewer Blindness·Production 사건 혼합 | 결과를 blind reviewer에게 제공하거나 case로 집계 | reviewer 분리, 고정 banner, 별도 state | blind 문서/경로 비연결, 조사 count 불변 | 공개 저장소에서 기술적 blind 불가 |

CORS는 브라우저의 응답 접근 제어이며 요청 자체가 발생하지 않는다는 보장이 아니다. [WHATWG Fetch 표준](https://fetch.spec.whatwg.org/)의 origin/CORS 모델과 [OWASP Host Header 검사 지침](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/17-Host_Header_Injection/)을 근거로 Host·Origin·무부작용을 별도로 검증한다.

## 13. Security Test Matrix

| 계층 | 후속 필수 검증 |
|---|---|
| Python | 고정 corpus generation, digest, ER-2A-R1 outcome/reason, inventory, privacy allowlist/canary, 128 KiB·32 scenario 제한 |
| HTTP/Delivery | OFF 직접 route/asset 404, ON 고정 bytes, unknown route, invalid method, query/path/body injection, Host/Origin/peer, Content-Type, CSP/nosniff, no-store, external network 0, oversized/corrupt 거부, 동시 요청 시 replay 0 |
| Browser | initial/verified/invalid/digest mismatch/stale/unsupported version, INCOMPARABLE/UNDETERMINED, duplicate·prototype·XSS canary, keyboard/focus, axe, 1920/1440/1024/768/390/320px, 200% reflow, external request 0, console/page error 0 |
| 수동 | Safari, 실제 모바일, screen reader와 사용자 수용을 각자 PASS/FAIL/NOT_TESTED로 기록; 자동 axe가 대체하지 않음 |

이 표는 향후 테스트 요구사항이며 현재 viewer PASS 증거가 아니다.

## 14. Recommended Architecture

Option A의 데이터 흐름: 고정 synthetic corpus → 명시적 offline `build_snapshot`/`encode_snapshot` → 검증된 canonical asset 및 별도 pin → server flag ON일 때 literal `/assets/evaluation-snapshot-v1.json` 후보 GET → browser bounded 검증 → 별도 read-only root. 이 경로는 제안이며 현재 route는 없다. 잠재 파일은 후속 `app/web_ui.py`, `app/api.py`의 literal route/flag, 별도 snapshot asset 및 pin, `frontend` viewer/adapter와 테스트다. 파일 변경은 ER-2D-B/C에서 각각 승인한다.

생성 시점은 명시적 개발 단계, 로드 시점은 feature ON과 명시적 viewer 진입이다. 유효 기간은 배포된 producer/corpus/schema/pin이 동일한 동안이며 어떤 불일치도 UNAVAILABLE로 처리한다. 서버는 유효한 peer 및 Host, Origin이 존재하면 동일 origin, 요청 method/path/query/body 정책을 검증한다. Browser는 구조·의미·digest·pin을 검증한다. 설치물의 authenticity와 동시 로컬 파일 교체에 대한 기존 한계는 남는다.

## 15. Rollback

불일치, privacy 누출, XSS, 조사 상태 혼합, stale 표시, external request 또는 accessibility 회귀 시 단일 flag OFF로 asset/route/UI를 모두 차단한다. 기존 조사 route, search/filter, checklist, risk, report 및 navigation은 유지되어야 한다. 서버 OFF direct GET과 기존 E2E를 함께 확인한다.

## 16. ER-2D-B/C and ER-2E Roadmap

| Phase | 시작 Gate | 범위·완료 Gate / rollback |
|---|---|---|
| ER-2D-B Safe Delivery | 사용자 별도 승인, exact SHA CI 성공·clean·artifact 0 | 고정 asset/pin, server OFF/ON, strict Host/Origin/method 및 HTTP 보안 테스트; 실패 시 OFF |
| ER-2D-C Browser Validation | B exact CI 성공, schema·pin·delivery 보안 승인 | browser strict validator, 별도 read-only root, lifecycle 및 isolation 테스트; 실패 시 OFF |
| ER-2E Browser Security & User Acceptance | C exact CI 성공, 격리 synthetic 환경 | browser·axe·keyboard·viewport·privacy·rollback, Safari/실기기와 사람 검수 별도 기록; 실패 시 NO_GO/OFF |

어느 단계도 이 설계 성공으로 자동 승인되지 않는다.

## 17. Human Review Gate

`INDEPENDENT_HUMAN_REVIEW_PENDING`, `MANUAL_APPROVAL_REQUIRED`, `ER_1D_IMPLEMENTATION_HOLD` 유지. Viewer는 label-blind review 자료가 아니다. 실제 사용자 자료·조직 운영·자동 대응 `NO_GO`.

## 18. Limitations

현재 delivery route, viewer, browser adapter, feature flag는 구현하지 않았다. Snapshot 크기는 기존 로컬 관측치이고 성능 SLA가 아니다. ER-2C의 manifest 전후 검사는 검사 사이에 교체 후 복원되는 공격을 원천 차단하지 않는다. Static asset의 별도 pin은 코드와 자산을 모두 수정할 수 있는 공격자에 대한 서명 대체가 아니다. Safari, 실제 모바일, screen reader 및 사용자 수용은 NOT_TESTED. 이 문서는 웹 보안 의미를 구현하거나 탐지 정책을 변경하지 않는다.

## 19. Test Results

시작 전체 pytest `3822 passed, 2 warnings`. 문서 계약 RED: 문서 부재로 2 failed; GREEN 2 passed. ER-2C·ER-2A-R1·ER-2B·신규 문서 focused 67 passed. 종료 전체 pytest `3824 passed, 2 warnings`; 순차 Evaluation Runner는 synthetic boundary 79/79, risk/case 각 70/70, Linux process 합성 분류 21/21이다. 로컬 결과는 macOS이며 Linux 합성 분류를 Linux host 검증으로 표현하지 않는다. 시작 exact push CI는 Ubuntu다.

## 20. Final Decision

모든 문서 계약과 회귀가 통과하면 `ER_2D_A_SNAPSHOT_DELIVERY_DESIGN_LOCAL_CONDITIONAL_GO`. 이는 Option A의 조건부 설계 결정이며 전달 경로, API, Viewer, 실제 운영 또는 ER-1D 구현 승인이 아니다.
