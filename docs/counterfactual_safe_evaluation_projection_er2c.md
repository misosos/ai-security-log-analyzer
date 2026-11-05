# ER-2C — Safe Evaluation Projection

## 1. Executive Summary

고정 합성 replay의 ER-2A 검증 결과를 읽기 전용 canonical JSON snapshot으로 표현한다. 운영 데이터, 실제 사건, API/UI, 자동 대응에 연결하지 않는다.

## 2. Start SHA / CI

시작 SHA `db8a3bd776b1f4bd4364aeadbac48a0a866e43b5`, push CI `41959843787` completed/success, 필수 Linux·Restricted Report·Chromium/axe·tracked-file 성공, artifact 0. HEAD/main/origin/main/GitHub main 일치, behind/ahead 0/0. v0.4.0 tag와 Release target `eecd6ee1cda0545e34b01c42e1a2163a899bcc27`.

## 3. Resumed Draft Inventory

기존 untracked projection, CLI, test 세 파일의 시작 SHA-256은 각각 `4616a6ddde62245e6b6367b244997267a9c5807baa169deff49df2906ec2bd0f`, `ce7d8b9226d2f4c2e2f702bd141890ba465acd9c117436fb1afa028f48d63b3b`, `bc75da92e5799906aa9fe20bdf22a8f61921fc4ede1849cad179e3423cc6466c`로 일치했다. 기존 replay, digest, canonical encoder, decoder 및 CLI를 재사용하고 구조화 불변 접근·collection 상한·manifest 전후 확인과 테스트를 보강했다.

## 4. ER-2A-R1 Trust Boundary

`run_corpus()`와 `run_holdout()`을 `build_report()`로 검증한다. R1의 outcome/reason 검사와 scope에 따른 INCOMPARABLE/UNDETERMINED를 유지하며 직접 구성된 외부 report를 받아들이지 않는다. Snapshot decoder는 현재 고정 producer를 재실행하고 결과 전체를 비교한다. 이는 producer와 같은 실행 환경의 검증이며 독립적인 외부 출처 인증은 아니다.

## 5. Safe Projection Schema

Closed root: `schema_version`, `evaluation_scope`, `snapshot_sha256`, `human_review_status`, `operational_validation`, `corpora`, `summary`, `scenarios`. 상수는 각각 version 1, SYNTHETIC_ONLY, INDEPENDENT_HUMAN_REVIEW_PENDING, NOT_APPROVED. Scenario는 corpus_id, scenario_id, detector_id, mutation_type, baseline/variant parser 및 detection state, comparison_state, reason_codes만 포함한다. 원문·계정·IP·시각·경로·label basis·expected label·private owner/evidence는 포함하지 않는다.

## 6. Corpus/Scenario Integrity

고정 Development 16, Holdout 14는 현재 회귀 기준이다. 실제 inventory, 중복, 누락, detector·mutation·policy 및 각 corpus summary는 기존 build_report가 검증한다. Manifest SHA-256을 포함하고 development manifest를 replay 전후 비교하며 holdout manifest와 holdout replay digest를 대조한다. Decoder는 현재 producer 결과와 일치하지 않는 재해시된 입력도 거부한다.

## 7. Comparison/Reason Consistency

ER-2A-R1의 DETECTED/NOT_DETECTED outcome 매핑과 해당 OUTCOME reason 검사를 재사용한다. Parser 불완전, scope 또는 binding 부족은 INCOMPARABLE/UNDETERMINED로 남긴다. 현 corpus의 비교 합계는 PRESERVED 7, LOST 10, GAINED 5, UNCHANGED_ABSENT 2, INCOMPARABLE 6, UNDETERMINED 0이다.

## 8. Snapshot Identity

`snapshot_sha256`은 자기 필드를 제외한 canonical body의 SHA-256이다. 이 값은 변경 감지에 사용하며 서명, 외부 출처 또는 사람 검토의 증명이 아니다. 공격자가 내용과 digest를 함께 변경할 수 있다.

## 9. Canonical JSON

UTF-8 ASCII-escaped Unicode, sorted keys, separators `,`와 `:`, 마지막 LF 하나, non-finite 금지. 시간, random identity 및 임시 경로를 포함하지 않는다.

## 10. Strict Decoder

UTF-8 strict, duplicate key, non-finite, version, root, digest, 128 KiB, depth 8, list 32 및 object 64개 key 상한을 검사한다. 정수 길이 제한을 두며 Boolean을 version의 integer로 취급하지 않는다. 이어 현재 producer가 생성한 closed body와 canonical bytes를 비교해 필드·enum·inventory·집계·상태 및 manifest의 임의 변경을 전체 거부한다. 오류는 INVALID_PROJECTION, UNSUPPORTED_REPORT_VERSION, SNAPSHOT_DIGEST_MISMATCH, RESOURCE_LIMIT 중 고정 범주다.

## 11. Immutable DTO

Snapshot은 frozen dataclass의 immutable canonical bytes를 보유한다. 검증 후 노출하는 corpora/scenarios는 tuple이고 nested mapping은 read-only다. 호출자가 받은 구조를 변경해도 snapshot bytes가 바뀌지 않는다.

## 12. Privacy/Security

직렬화 필드 allowlist와 고정 producer 비교, 합성 canary 및 network 차단 테스트를 수행한다. 단순 문자열 검사만으로 개인정보 보호 전체를 증명하지 않는다. 오류에 원문 exception을 반사하지 않는다.

## 13. CLI

`uv run python -m app.evaluation.counterfactual_safe_projection_cli`는 고정 corpus만 실행하고 stdout에 JSON을 출력한다. 임의 인수는 거부하고 실패 시 stderr에 고정 코드만 출력하며 부분 JSON을 내보내지 않는다. 자동 파일 저장은 없다.

## 14. TDD RED/GREEN

재개 시 ER-2A-R1과 초안 focused 45 passed. 불변 구조화 접근과 32행 초과의 RESOURCE_LIMIT 테스트는 수정 전 실패하고 수정 후 통과했다. manifest 변경 주입은 수정 전 수용되어 실패했고 전후 검증 추가 후 거부했다. Focused ER-2C/ER-2A/Replay/Holdout 102 passed.

## 15. Full Regression

ER-2C/ER-2A/Replay/Holdout focused 107 passed. 최종 전체 pytest 3822 passed, 2 deprecation warnings. Evaluation: synthetic boundary 79/79, risk 및 case 각각 70/70, Linux process 합성 평가 21/21. 로컬 실행은 macOS이며 시작 CI는 Ubuntu다. 합성 분류 평가를 Linux 호스트 검증이나 운영 성능으로 해석하지 않는다.

## 16. ER-2D Entry Requirements

별도 구현 승인, 사용자 push와 exact CI, browser-side 독립 schema/digest/count 검증, stale 거부, 안전한 read-only delivery 및 synthetic/production 격리가 필요하다. textContent를 사용하고 dynamic HTML과 browser storage 자동 저장을 금지한다. Python decoder만으로 브라우저를 승인하지 않는다.

## 17. Human Review Gate

INDEPENDENT_HUMAN_REVIEW_PENDING, MANUAL_APPROVAL_REQUIRED, ER_1D_IMPLEMENTATION_HOLD를 유지한다. 실제 사용자 자료·조직 운영·자동 대응은 NO_GO다.

## 18. Limitations

Decoder는 매 호출 실제 고정 corpus의 replay를 수행하므로 offline 평가 환경과 corpus가 필요하고 비용이 든다. 이는 임의 JSON viewer가 아니다. Snapshot digest는 보안 서명이 아니다. Manifest 전후 검사는 검사 사이에 파일이 바뀌었다가 복원되는 동시 변조를 원천 차단하지 못한다. 신뢰할 수 있는 고정 소스와 격리된 실행 환경이 필요하다. 독립 사람 검토, 외부 인증, 운영 정확도와 브라우저 보안은 검증하지 않았다.

## 19. Final Decision

모든 필수 회귀 통과 시 `ER_2C_SAFE_EVALUATION_PROJECTION_LOCAL_CONDITIONAL_GO`. 합성 오프라인 projection 범위의 판정이며 UI 구현이나 운영 배포 승인이 아니다.
