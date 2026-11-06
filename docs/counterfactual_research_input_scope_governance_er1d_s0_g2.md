# ER-1D-S0-G2 — 연구 입력 범위 및 Governance 개정 제안

## 1. Executive Summary

고정 합성 30건을 불변 회귀 기준으로 유지하면서 사용자 정의 합성 로그를 향후 별도 승인된 연구 입력으로 다루는 정책을 제안한다. 실제 권한 있는 로컬 로그는 별도 Privacy/Security Gate의 후속 연구 후보이며 운영 Live 연결은 `NO_GO`다. 이번 문서는 설계·결정 자료다. 새 입력, Mutation, 설명 실행 코드나 정책 승인을 만들지 않는다. `SOLO_RESEARCH_POLICY_PROPOSED`, `PROPOSED_NOT_APPROVED`, `SOLO_RESEARCH_AUTHORIZATION_PENDING`; Tier 1/2 및 `S1 착수 HOLD`다.

## 2. Exact Start Gate

시작 SHA `cadae46e60c6c4d2951c08894c7e659f642b329a`, Exact CI `42232477133`: push / completed / success, head 일치, Locked Python 3.12 회귀·Linux·Restricted Report·Chromium/axe·tracked-file 성공, Artifact 0. 시작 HEAD/local main/origin main/GitHub main 일치, clean, ahead/behind 0/0. `v0.4.0` tag와 Release target `eecd6ee1cda0545e34b01c42e1a2163a899bcc27` 불변. `AGENTS.md` 및 보안 분석·검증 지침 확인; `ER_1D_S0_G2_START_GATE_GO`. 변경 전 로컬 macOS pytest 3890 passed, 2 warnings. GitHub CI는 Ubuntu다.

## 3. 기존 고정 Corpus 제한의 사용성 한계

[ER-1A](counterfactual_corpus_er1a.md), [ER-1B](counterfactual_detector_replay_er1b.md), [ER-1C-R](counterfactual_independent_review_er1c_r.md)은 고정 입력의 재현성과 검토 기준을 제공한다. 그러나 사용자 자신의 새로운 합성 입력에서 가설을 실험하는 인터페이스는 제공하지 않는다. 새로운 입력은 고정 Corpus의 정답·검토·성능 보증을 상속하지 않는다.

## 4. 입력 Tier 0–3

| Tier | 범위와 목적 | 상태 및 경계 |
|---|---|---|
| 0 Fixed Synthetic Corpus | ER-1A Development 16, ER-1C Holdout 14; 고정 Manifest·fixture·Expected Label·digest의 회귀와 Replay | 그대로 불변. 신규 입력 자동 추가·성능 합산 금지. 독립 검토 PENDING |
| 1 User-Defined Synthetic Logs | 사용자가 만든 합성 입력의 명시적 Baseline/Mutation/Variant 실험 후보 | 자기 선언을 믿지 않고 잠재적 민감 비신뢰 자료로 취급. 별도 정책·입력 Security Gate·구현 승인 전 비활성 |
| 2 User-Authorized Local Logs | 사용자가 분석 권한을 가진 실제 로컬 로그의 후속 가능성 | 이번 단계 미승인. 권한 검증의 한계와 Privacy/Security·사용자 승인 Gate 필요; 실제 사용자 자료 현재 NO_GO |
| 3 Operational Live Logs | 운영 Collector, SIEM, 원격 자동 수집, 지속 감시, 자동 대응·정책 변경 | `NO_GO` |

고정 Corpus와 신규 입력의 결과를 같은 근거 수준으로 표시하지 않는다. Tier 1/2는 기본 Expected Label 없음, 독립 검토 없음, 실행별 입력·설정 provenance 필요다. Tier 0은 고정 bytes/manifest의 회귀 Label 계약을 가진다. 신규 입력을 기존 정확도·재현율·공격 회피율 분모에 합산하지 않으며, 별도 정답과 평가 프로토콜 없이는 이러한 지표를 계산하지 않는다.

## 5. 사용자 정의 합성 로그 계약

후속 사용 흐름 후보: 사용자 명시적 Source 선택 → bounded 입력 검증 → Parser disposition → Baseline 분석 → 명시적 Mutation 선택 → 격리된 Variant 재분석 → Evidence 결속과 비교 가능성 검증 → bounded 설명과 제한. Baseline과 Variant는 독립 실행과 별도 Run Owner를 사용한다. 사용자 정의 입력에는 자동 Expected Label을 만들지 않는다.

후보 Source는 `application`, `ssh`, `access`다. 현재 Parser registry는 각각 인증, SSH 인증, Apache CLF/Combined 및 Nginx default combined의 제한된 접근 로그를 지원한다. Application/SSH의 Brute/Spray 연구는 해당 형식과 인증 실패·시각·계정·IP, Parser 상태 및 scope가 유효한 경우에만 후속 검증한다. Access Parser는 `http_request`, `user=None`을 생산하고 remote user를 계정으로 승격하지 않는다. 따라서 Access를 Brute/Spray의 인증 실패 근거로 취급하지 않고 해당 Detector 설명은 unsupported/NOT_EVALUATED로 보류한다. Access 대상의 다른 탐지 설명은 별도 정책·Evidence 승인 전 대상 밖이다.

Tier 1의 후보 입력 경계는 closed source set, UTF-8 strict, bounded body·행 수·행별 bytes·처리 시간, 허용 형식, JSON envelope의 duplicate key/비정상 숫자·잘못된 Content-Type 거부, Parser PARTIAL/REJECTED 구분 및 fail closed다. 파일 입력 후보는 `.log`/`.txt`의 일반 UTF-8 텍스트로 제한하고 확장자만 신뢰하지 않으며 archive·바이너리는 거부한다. 파일 선택으로 읽은 제한된 bytes만 받는 방식을 검토하고 서버의 임의 경로를 입력받지 않는다. 승인 전 구체적 수치는 기존 관련 경계보다 임의로 완화하지 않고 측정·테스트로 확정한다. JSON 중복 key 검사는 JSON envelope에 적용하며 일반 텍스트 로그 자체를 JSON으로 간주하지 않는다. 유효하지 않은 입력이나 변형 target에 부분 Claim을 내지 않는다.

## 6. 향후 로컬 로그 지원 조건

Tier 2는 실제 계정·IP·호스트·인증 내용, 불완전 Parser, 동의·권한 확인, 보관·삭제 및 Label 부재의 위험이 있다. 시스템은 사용자 선언만으로 권한이나 모든 민감정보의 부재를 증명할 수 없다. 사용자가 자료를 제공할 정당한 권한을 확인하고, 별도 명시적 승인, 위협 모델, 데이터 최소화·암호화·접근 제한·수명/삭제, 오류·crash 처리, 개인정보 보호 및 보안 Gate를 통과해야 한다. 이는 향후 검토 조건이지 Tier 2 승인이나 실제 침해 판정·운영 탐지 성능의 근거가 아니다.

## 7. Existing Input API 재사용 가능성

실제 구현은 [app/api.py](../app/api.py), [app/local_investigation_api.py](../app/local_investigation_api.py), [frontend/app.js](../frontend/app.js), [app/parser/registry.py](../app/parser/registry.py)에 있다. 아래 수치는 현재 Investigation 계약이며 ER 연구의 승인된 한도가 아니다.

| 경로 | 현재 확인된 검증과 처리 | 연구에서의 판단 |
|---|---|---|
| `POST /api/v1/investigations/text` | loopback·query 거부, 단일 `application/json`과 UTF-8 charset/identity encoding, bounded body 96 KiB, strict UTF-8, duplicate JSON key·비정상 숫자 거부, 정확한 schema v1/source/log_text. 텍스트 32 KiB, 512줄, 한 줄 2048 bytes, 제어 문자·CR 검사 및 입력 품질/호환성 검사 | 검증 원칙과 테스트를 검토·재사용할 수 있다. 기존 endpoint는 worker 분석 후 Investigation/report 및 checklist registry에 연결되므로 연구 입력 경로로 그대로 호출하지 않는다. |
| `POST /api/v1/investigations` | loopback·query 거부, multipart 3개 지정 필드 application/ssh/access 필수, 요청 96 KiB·각 32 KiB·합계 80 KiB·각 512줄·한 줄 2048 bytes, strict UTF-8, archive signature/제어 문자 검사, input quality, upload 10초·worker 10초, 동시 1 및 rate 제한 | bounded streaming·입력 품질과 별도 worker의 원칙은 후보. 세 파일을 요구하고 결과를 checklist registry에 결속하므로 연구 workspace와 재사용 경로를 별도 검증해야 한다. |
| 공통 임시 처리 | `TemporaryDirectory` mode 0700, 생성 파일 `O_EXCL`/`O_NOFOLLOW` mode 0600; 정상 scope 종료 시 cleanup | filename을 사용자 경로로 사용하지 않는 방식을 참조한다. 강제 종료·crash 시 cleanup이 보장된다고 주장하지 않고 잔존 처리 Gate가 필요하다. |
| 별도 legacy `analyze_logs` | `.log`/`.txt`, 각 10 MiB 검사이나 전체 파일을 먼저 읽고 임시 파일에 기록한 뒤 legacy 분석한다. | 위 local endpoint 제한과 혼동하지 않는다. 연구 입력의 bounded streaming·격리 보증으로 채택하지 않는다. |

Frontend는 텍스트에서 Source radio와 클라이언트 byte/line 검사 후 `/api/v1/investigations/text`를 호출하고, 파일 모드는 세 파일의 FormData를 `/api/v1/investigations`로 전송한다. UI 검사는 서버 검사를 대체하지 않는다. 공통 helper의 직접 재사용은 부작용·scope·오류 계약을 검증하고 별도 승인된 경우에만 가능하며, private helper를 안전한 공개 API로 단정하지 않는다.

기존 `counterfactual_mutation.py`는 application/ssh의 synthetic-only 7종, fixture 최대 8192 bytes·64줄 및 엄격한 parameter/행 전제조건을 갖는다. 이는 고정 Corpus 계약이지 임의 사용자 입력에 대한 일반 검증기가 아니다. 기존 Corpus loader는 경로·symlink·크기 및 closed manifest를 검사한다. 사용자 파일 경로를 승인하는 계약이 아니다.

## 8. Research/Production 격리

고정 Corpus·사용자 연구 입력·Investigation은 각각 별도 source identity, state owner, output 및 저장 경계를 가진다. 기존 Investigation registry, Checklist, Risk, Timeline, Report, Live/SSE/자동 대응에 쓰지 않는다. 기본 오프라인이며 외부 네트워크·LLM 0, 명시적 요청 없는 자동 분석 0. Production API/UI 또는 Feature Flag로 암묵 활성화하지 않는다. 새 입력을 고정 Manifest/Fixture/Label/Trusted Digest에 추가하지 않는다. 새로운 사용자 자료를 본 프로젝트의 공개 평가 점수나 독립 검토 결과로 취급하지 않는다.

## 9. Mutation 및 Provenance

후속 후보는 기존 7종인 실패 행 제거·추가, Timestamp/Account/Source IP 변경, 행 순서 변경, Format 손상이다. 각 실행은 사용자가 허용된 종류와 안전한 scenario-local target 참조를 명시적으로 선택하고, 원본을 변경하지 않은 격리 사본에 적용한다. Baseline/Variant bytes 및 입력·설정·정책 digest와 source/parser profile을 제한된 내부 provenance에 결속하고 각각 Parser를 재검증하며 별도 Detector 실행 및 범위·Evidence 비교 가능성을 검사한다. target 오류·조건 미충족·변조는 전체 또는 해당 Claim을 fail closed한다.

행을 안전하게 선택하는 UX, 민감 target의 비노출, 각 형식에서의 mutation precondition 및 추가 값이 합성인지 검증하는 방법은 미설계·미승인이다. 현 `apply_mutation()`은 그대로 사용자 데이터를 안전하게 처리한다고 단정할 수 없다. 하나의 변형으로 여러 feature가 바뀌면 관측들을 분리하고 유일한 원인을 주장하지 않는다.

## 10. 네 계층 Explanation 계약

[ER-1D-P](counterfactual_sensitivity_explanation_design_er1d_p.md)의 A 입력 변형, B 검증된 Feature Delta, C 현행 Production Predicate, D 실제 Detector Observation을 유지한다. Brute는 같은 source IP와 알려진 동일 account의 selected-window, Spray는 같은 IP 실패의 whole-span이다. 현재 SafeFacts target IP aggregate로 Brute window를 증명하지 않는다. Owner/Evidence 결속이나 Parser completeness가 부족하면 해당 Claim은 NOT_EVALUATED 또는 기존 비교 상태로 보류한다. Parser REJECTED/실패를 Detector NOT_DETECTED로 바꾸지 않고 INCOMPARABLE/UNDETERMINED를 보존한다. 미지원 source·policy는 설명하지 않는다.

`compare_runs()`는 Label provenance가 없으면 `UNDETERMINED`를 반환한다. 신규 입력은 독립 Label을 기본 보유하지 않으므로 Label provenance를 거짓으로 채우거나 기존 비교 결과를 outcome으로 바꾸면 안 된다. Label 없이 가능한 관측 비교가 필요하다면 기존 Replay 공개 계약을 바꾸거나 우회하지 않는 별도 의미·스키마·승인 Gate를 먼저 정의해야 하며, 현재는 구현 가능성이 미확정이다.

## 11. Restricted Adapter Feasibility

[G1](counterfactual_solo_research_governance_er1d_s0_g1.md)의 `FEASIBLE_ONLY_WITH_RESTRICTED_ADAPTER`는 동일 실행 bundle의 owner·context와 Evidence를 검증할 수 있는 코드 독해상의 후보이지 검증된 구현이 아니다. Tier 0도 fixed bytes·source·parser disposition·policy 및 context 수명과 membership을 검증해야 한다. Tier 1에서는 추가로 비신뢰 입력 검증, source/provenance, 별도 Baseline/Variant owner, 불완전 Parser, 원문 수명·미노출을 검증해야 한다. 사용자 입력 지원이 owner 결속 문제를 해결하지 않는다. Private Context는 결과나 public DTO에 내보내지 않는다. Production 또는 Replay 공개 계약 변경이 필수라면 해당 후보 HOLD다.

## 12. Privacy 및 Security Threat Model

Tier 1도 민감정보를 포함할 수 있다. 입력은 외부 LLM, 서버 로그, Console, exception, 외부 네트워크에 보내지 않으며 기본 영구 저장하지 않는 설계를 요구한다. memory-only 우선, 임시 저장이 불가피하면 비공개 디렉터리·고정 이름·배타 생성·symlink 차단·최소 수명·정상/오류 cleanup을 검증한다. crash·강제 종료 후 잔존 가능성, OS·백업·스왑·브라우저 및 사용자 사본까지 삭제를 보장할 수 없음을 명시하고 후속 보안 Gate에서 잔존 탐지·처리 방침을 정한다. Digest는 무결성과 재현성을 돕지만 저엔트로피 입력의 추측·연결 가능성이 있어 개인정보 제거·서명·권한 증명이 아니다. Digest도 제한 접근·수명 정책을 적용한다. 합성 선언 및 canary 검사가 모든 민감정보 탐지를 보증하지 않는다.

### 사용성·보안 검증 매트릭스

아래는 후속 테스트 계획이며 현재 구현·PASS가 아니다. 오류 시 원문과 예외를 반사하지 않고 해당 Claim 또는 전체 결과를 보류한다.

| 시나리오 | 기대 동작 / Fail-closed 조건 |
|---|---|
| 정상 사용자 정의 SSH 로그 | 승인된 profile·scope·충분한 Parser/Evidence일 때만 두 실행 관측; 원본 미출력 |
| 정상 Application 인증 로그 | 같은 계약으로 재분석; Label 없는 결과는 기존 Label provenance 조건 보존 |
| 지원하지 않는 Access Log 탐지 범위 | Brute/Spray NOT_EVALUATED; HTTP 요청을 인증 실패로 변환 금지 |
| UTF-8 오류 | 입력 전체 거부, replacement decoding 금지 |
| 입력 크기 초과 / 행 수 초과 | 읽는 중 상한 초과 즉시 중단, 절단 결과로 분석 금지 |
| 누락 Timestamp / 누락 Account | Parser 상태와 scope 보존; 필수 Predicate NOT_EVALUATED, 0/False 대입 금지 |
| Parser PARTIAL | subset 한계 표시, 전체 완전성 필요한 비교/Claim 보류 |
| Parser REJECTED | Detector NOT_EVALUATED, 비교 불가; 미탐지로 표현 금지 |
| Unknown Source | closed set 거부, 임의 parser fallback 금지 |
| Invalid Mutation Target | 적용 전 거부, 원본 및 기존 결과 불변 |
| 다른 Source의 Baseline/Variant | SOURCE_SCOPE_MISMATCH/INCOMPARABLE, 수치 비교 금지 |
| 서로 다른 Policy Version | POLICY_MISMATCH/INCOMPARABLE, 같은 정책으로 표시 금지 |
| Brute/Spray 집계 범위 혼동 | scope mismatch 보류; target IP count를 selected-window로 사용 금지 |
| Run Owner 교차 결합 | owner 불일치 거부, output Claim 없음 |
| Evidence Membership 불일치 | binding 실패, UNDETERMINED 또는 해당 Claim 보류 |
| Raw Log/Account/IP canary 노출 | allowlist·출력 검사; 하나라도 노출 시 즉시 HOLD |
| 입력의 예기치 않은 서버 저장 | 기본 영구 저장 0 및 임시 수명 검증; 예상 밖 저장 시 HOLD |
| 외부 네트워크 호출 | network 차단 fixture에서 호출 0; 시도 발견 시 HOLD |
| 고정 Corpus 변조 | digest/inventory 불일치로 전체 거부, 자동 갱신 금지 |
| 사용자 정의 입력의 Label 오염 | 기본 Label 없음, 고정 Label과 회귀 분모 변경 0 |
| 탐지 결과와 설명 Claim의 모순 | 기존 결과 유지하고 Claim 보류; outcome/reason 재작성 금지 |

추가로 duplicate JSON key, Content-Type, line length, path traversal, symlink/file replacement, 처리 timeout, 임시 cleanup 실패, 자동 분석·LLM 호출, 개인정보가 포함된 예외 및 결과 저장소 오염을 합성 canary로 검증한다. 예외를 삼켜 PASS로 기록하지 않는다.

## 13. 기존 Governance 충돌 분석

[ER-1D-P §14–15](counterfactual_sensitivity_explanation_design_er1d_p.md)는 독립 사람 검토와 수동 승인 전 구현 금지, [ER-1C-R §13](counterfactual_independent_review_er1c_r.md)은 30건 검토·이견·digest·독립성·승인을 요구한다. [G0 §5·9–10](counterfactual_explanation_readiness_audit_er1d_g0.md)은 owner-bound 집계 등 미확보 근거와 구현 HOLD를 기록한다. [S0 §3·5·9·10](counterfactual_solo_research_track_er1d_s0.md)과 [G1 §3·7·9–11](counterfactual_solo_research_governance_er1d_s0_g1.md)은 고정 합성 격리 및 별도 정책 결정을 요구한다. 사용자 입력 확대는 이 경계와 충돌하므로 현행 상태에서 허용되지 않는다. 승인된 후속 결정이 각 문서의 적용 관계와 범위를 전향적으로 명시해야 하며 과거 판단을 삭제하지 않는다.

## 14. 수정된 정책 개정 제안

G1 Option B의 “고정 합성 Corpus만 사용하는 격리된 연구용 프로토타입”을 다음으로 확대하는 안: “고정 합성 Corpus를 불변 회귀 기준으로 유지하고, 별도 입력 보안 계약을 충족한 사용자 정의 합성 로그를 연구 범위에 추가할 수 있는 격리된 오프라인 프로토타입.” 사용 권한이 있는 로컬 로그는 **별도의** Privacy/Security 및 명시적 입력 승인 Gate 이후에만 후속 검토한다. 이 문구는 `PROPOSED_NOT_APPROVED`이며 Tier 1/2의 허용 또는 S1 착수를 승인하지 않는다.

정책 승인 전 프로젝트 소유자의 권한과 적용 가능한 외부 의무를 확인한다. 결정 기록에는 기준 SHA, 적용 Tier·실행/파일·데이터 수명, 금지 범위, 기존 정책과 충돌 해소, 검증 수준, 중단·롤백, 만료/재검토 조건을 명시해야 한다. 독립 검토 상태와 Production Gate는 변경하지 않는다.

## 15. G3/S1–S6 로드맵

| 단계 | 선행조건 / 금지 변경 | 필수 검증과 완료 판단 / 남은 HOLD |
|---|---|---|
| G3 Authorization Decision | 권한·외부 의무 확인 후 소유자 실제 결정. 자동 승인 생성 금지 | 정책 개정·대상 Tier·만료·범위 기록; 미승인 시 전체 구현 HOLD |
| S1 Safe Aggregate | G3와 별도 S1 승인, 고정 Tier 0 격리·허용 파일 확정; Production/Replay 계약 변경 금지 | 같은 실행 owner·membership, Brute/Spray scope, privacy/network 반증. 승인 범위 통과만 기록; 다음 단계 별도 승인 |
| S2 Feature Delta | S1 결과와 별도 승인; 다른 scope 값 혼합 금지 | provenance·동일 scope/version·다중 변화 반증. Tier 1 자동 확장 금지 |
| S3 Policy Predicate | S2와 별도 승인; 정책·Detector 변경 금지 | 현행 Predicate와 NOT_EVALUATED, 정책 불일치·누락 검증. Production 승인 없음 |
| S4 Bounded Explanation | S3와 별도 승인; private/label 출력 및 유일 인과 주장 금지 | 네 계층 binding, Claim 모순·canary·재현성. 독립 검토는 PENDING |
| S5 User-Defined Synthetic Input Pilot | S1–S4의 해당 근거와 별도 Tier 1 입력 Security Gate·정책 승인; Investigation 경로 연결·고정 Corpus 수정 금지 | §5/§9/§12 전체, hostile input·수명·Label 부재·scope 테스트. S1–S4 결과를 사용자 입력에 자동 일반화하지 않는다 |
| S6 Authorized Local Log Feasibility | 별도 Tier 2 정책·권한·Privacy/Security 및 명시적 사용자 승인; 운영 Live 연결 금지 | 데이터 수명·권한 한계·민감정보·사고 대응·오류 처리 검토. 현재 실제 사용자 자료 NO_GO |

각 단계는 정확한 기준 SHA/성공 CI와 허용 파일, 중단·롤백, 연구 결과의 미검증 상태를 별도 Gate로 확인한다. 이전 단계 성공은 다음 단계나 운영을 자동 승인하지 않는다.

## 16. 사용자 승인 필요사항

소유자 권한과 외부 의무가 확인된 뒤에만, G3에서 수정된 정책 문구 및 적용 Tier, 고정 Corpus 불변, 유효기간, 허용 파일·데이터 수명·네트워크·출력 경계, 기존 HOLD와 충돌 해소, 실패 시 중단·롤백을 명시적으로 결정한다. Tier 1 입력 승인과 Tier 2 실제 로그 승인은 별도다. 이 G2 요청은 소유자 승인 날짜·서명·S1/S5 실행 허가가 아니다.

## 17. 검증 및 한계

변경 전 전체 pytest 3890 passed, 2 warnings. 문서 계약 RED: 문서·색인 부재로 3 failed. G2와 G1/S0/G0/P 문서 계약 GREEN 16 passed. 변경 후 전체 `uv run pytest -q` 3893 passed, 2 warnings. `uv run python -m app.evaluation`: Synthetic Boundary 79/79, Risk 70/70, Case 70/70, Linux Process 합성 21/21. `uv lock --check`, `uv run python -m compileall -q app tests`, `git diff --check` 성공. 고정 합성 테스트는 운영 성능, 독립 사람 검토, 입력이 민감하지 않음 또는 사용자 권한을 증명하지 않는다. 초기 연구 근거와 observable mapping은 [ER-0](evidence_research_er0.md), 코드별 미확보 근거는 [G0](counterfactual_explanation_readiness_audit_er1d_g0.md)를 참조한다.

## 18. 최종 판정

`ER_1D_S0_G2_INPUT_SCOPE_AMENDMENT_PROPOSAL_LOCAL_CONDITIONAL_GO`는 설계 및 정책 제안 완료에만 적용한다. `SOLO_RESEARCH_POLICY_PROPOSED`, `SOLO_RESEARCH_AUTHORIZATION_PENDING`, `INDEPENDENT_HUMAN_REVIEW_PENDING`, `MANUAL_APPROVAL_REQUIRED`, `ER_1D_IMPLEMENTATION_HOLD`, `ER_2F_USER_ACCEPTANCE_PENDING` 유지. 실제 사용자 자료·조직 운영·자동 대응은 `NO_GO`. Tier 1/2 및 S1 실행은 승인되지 않았다.
