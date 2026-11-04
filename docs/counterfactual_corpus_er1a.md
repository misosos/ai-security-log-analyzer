# ER-1A — 합성 반사실 Corpus와 입력 변형 계약

## 1. 목적과 범위

**판정: `ER_1A_COUNTERFACTUAL_CORPUS_LOCAL_CONDITIONAL_GO`**. ER-1A는 합성 입력, 제한된 byte 변형, 독립 기대값, 기존 Loader/Parser 사전 검증을 제공한다. 이는 실험 입력의 준비 단계다. Detector 재실행과 baseline/variant 비교 엔진은 아직 구현하지 않았다.

### ER-0 요구사항 보존

ER-0의 최종 ER-1 요구사항을 축소하지 않는다. ER-1A에서 완료한 요구는 closed synthetic manifest, 고정된 7종 byte mutation, baseline과 variant의 분리된 Loader/Parser 실행, 입력 사실 검증, 독립 behavioral-pattern label 확인, bounded/privacy-safe 결과다. ER-0가 요구한 Brute private window/context와 run owner 결속, Password Spray whole-span 소비자 재실행, detector 실행 차원, 비교 차원, cross-run binding, 완전한 fixed reason-code 결과, canonical result 비교, 독립 reviewer/holdout 절차 및 ER-1 평가 집계는 **ER-1B로 이관**한다. ER-1B에서도 ER-0 요구를 생략하거나 완화하지 않는다.

ER-1A의 `PATTERN_PRESENT/ABSENT`는 입력 사실에 현재 프로젝트 정책을 독립 계산한 behavioral-pattern label이다. Detector 결과가 아니며, 실제 공격/회피/침해/탐지 정확성을 나타내지 않는다. 실제 사용자 자료, 조직 운영, 자동 대응은 계속 `NO_GO`다.

## 2. 시작 Gate와 baseline

- 대상 저장소: `misosos/ai-security-log-analyzer`
- 시작 SHA: `5e201c5459f09a245393ad0c0faa8d428189f1c0`
- Exact GitHub Actions run: [41794418978](https://github.com/misosos/ai-security-log-analyzer/actions/runs/41794418978), `push / completed / success`, head SHA 일치
- 필수 regression, Linux TCP Syslog/JSONL/Restricted Report, Chromium·axe, tracked-file 검사가 실행되어 성공; artifact 0개
- 작업 시작 시 branch `main`, clean tree, local HEAD/main/origin/main/GitHub main 동일, ahead/behind 0/0
- `v0.4.0` tag와 Release target은 `eecd6ee1cda0545e34b01c42e1a2163a899bcc27` 유지
- 변경 전 순차 baseline: `uv run pytest -q` — 3,657 passed, 기존 deprecation warning 2개. 이어 `uv run python -m app.evaluation` — synthetic boundary 79/79, Brute 11 TP/0 FP/0 FN/58 TN, Spray 2 TP/0 FP/0 FN/67 TN, parser 195/200 (ignored 2, rejected 3, unexpected 0), correlation 6/6·3/3·1/1, risk 70/70, case 70/70, Linux process synthetic classification 21/21.

## 3. 현재 Production 정책 경계

현재 구현 확인 기준은 `app/analyzer/pipeline.py`, `app/detector/brute_force.py`, `app/detector/password_spray.py`, `app/main.py`, Parser registry, `app/evaluation/detector_accuracy.py`다.

| 정책 | 입력 scope와 조건 | ER-1A 독립 label에 반영한 의미 |
|---|---|---|
| Brute Force (`brute_force_production_v1`) | 동일 source IP와 알려진 동일 계정의 선택 sliding window, 5회 이상 실패, window 폭 60초 이하 | IP 전체 실패 feature와 선택 account window를 혼동하지 않는다. 같은 IP·계정별 timestamp를 정렬해 qualifying 5-event window가 있는지 계산한다. |
| Password Spraying-like (`password_spray_whole_span_production_v1`) | 같은 IP의 전체 실패 집계, 실패 4회 이상, 알려진 계정 3개 이상, 전체 min/max span 60초 이하 | 선택 window가 아니라 해당 IP의 전체 failure span을 계산한다. 평가용 sliding prototype은 적용하지 않는다. |

두 임계값은 프로젝트의 현재 휴리스틱이며 NIST/MITRE 표준 임계값이 아니다. Brute의 private `BruteWindowContext`와 `AnalysisRunOwner`는 이 단계에서 실행/직렬화하지 않는다. Password Spray의 correlation anchor unresolved 상태도 해결하지 않는다. 기존 detector accuracy corpus 및 label은 수정하지 않았다.

## 4. Corpus 구조와 입력 문법

신규 `sample_logs/counterfactual/`는 `manifest.json`과 그 manifest가 모두 참조하는 `.log` fixture로만 구성한다. 총 16개 scenario: application 13개, SSH 3개; detector별 8개씩. 기존 `sample_logs/detector_accuracy/`는 읽기 전용 기준선이며 변경하지 않았다.

Corpus에는 조건 충족/미충족, 정확히 60초 경계, 한 실패 제거/추가, 늦은 timestamp noise, 계정·IP 변경, 순서 변경, partial account, 손상 timestamp를 포함한다. 모든 주소는 IANA 문서용 `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` 범위이고 계정은 `synthetic_user_NN` 형식이다. 비밀번호, token, hostname, 실제 로그는 없다. Application은 현재 parser의 authentication 형식, SSH는 제한된 RFC 5424 OpenSSH 형식을 사용하며 RFC 3164 추측 지원을 만들지 않는다.

경계 예시는 Brute 5회/60초 `PATTERN_PRESENT`, 실패 1개 제거 후 4회 `PATTERN_ABSENT`, 80초 span의 미탐지 predicate다. Spray는 4회/3계정/60초 `PATTERN_PRESENT`, 4회 미만·3계정 미만 또는 80초 whole-span의 predicate 미충족을 포함한다. 이런 label은 합성 입력과 현재 명시 정책의 관계만 가리킨다.

## 5. Manifest schema와 독립 기대값

### 독립 라벨

`app/evaluation/counterfactual_corpus.py`의 version 1 closed schema는 root의 `schema_version`, `data_scope`, `scenarios`와 scenario별 `scenario_id`, `detector_id`, `source`, `baseline_fixture_id`, `mutation_type`, `mutation_target`, `mutation_parameters`, expected Parser disposition/event facts/behavioral pattern, operational context, label basis, policy ID, comparison scope를 허용 목록으로 검사한다. 이 구현은 label 계산용 합성 대상 주소 및 baseline 독립 facts/label도 같은 closed scenario 레코드에 둔다.

검증은 duplicate JSON key, NaN/Infinity, 잘못된 UTF-8, 알 수 없는 key/enum/policy, 중복 scenario ID, 절대/상위 경로, symlink, root escape, 잘못된 파일 종류, fixture 8 KiB·64줄 초과, manifest 128 KiB 초과, 최대 32 scenario 위반을 고정 오류 category로 거부한다. manifest와 fixture는 repository 내 고정 corpus root에서만 읽는다. 자동 정규화나 경로 추측을 하지 않는다.

라벨은 정규화된 Parser 출력의 **입력 사실**과 별도 계산으로 검증한다. Brute label 계산은 알려진 사용자별 실패 시각의 5개 조합이 60초 이내에 드는지, Spray label 계산은 target IP 실패 수·계정 수·전체 min/max 폭을 검사한다. Detector를 호출해 라벨을 만들거나 manifest를 조정하지 않는다. `operational_context`는 전부 `UNVERIFIED`로 분리한다. 독립 reviewer/holdout이 아직 없으므로 이는 독립된 현실 정확도 평가가 아니다.

## 6. Mutation 계약

`app/evaluation/counterfactual_mutation.py::apply_mutation`은 제한된 UTF-8 bytes만 읽고 새 bytes를 반환한다. 원본 fixture를 덮어쓰지 않고 normalized event, feature dictionary, detector result, private context를 직접 수정하지 않는다.

| Mutation | 변경과 사전 조건 |
|---|---|
| `remove_failure_row` | 지정된 실패 row 하나 제거 |
| `add_failure_row` | 지원 source 문법으로 synthetic account/IP/timestamp 실패 row 하나 추가 |
| `change_timestamp` | 지정된 실패 row timestamp를 같은 source의 유효 문법으로 바꿈 |
| `change_account` | 지정 row의 synthetic account를 변경 |
| `change_source_ip` | 지정 row IP를 허용된 documentation address로 변경 |
| `reorder_rows` | permutation으로 row 순서만 변경; 각 row bytes 및 timestamp 보존 |
| `damage_format` | application account field 제거(partial) 또는 SSH timestamp 손상(rejected) |

각 mutation은 타입·정확한 parameter allowlist·row target·기존 실패 row 조건을 확인하고, unsupported/malformed/precondition 실패를 fixed category로 반환한다. 잘못된 입력을 보정하지 않는다. 하나의 직접 입력 변경은 count, unique account/IP, 시간 범위 등 여러 파생 사실을 바꿀 수 있으므로 각 실행에서 Parser facts를 다시 계산한다. 직접 변경한 필드와 재계산된 facts, policy predicate를 문서의 label basis에서 구분한다. 변형이 결과 변화의 유일한 실제 원인이라는 인과 주장은 하지 않는다.

## 7. Parser 사전 검증과 준비 API

`load_corpus()`는 전체 manifest와 fixture allowlist를 검증한다. `prepare_scenario()`는 baseline bytes와 variant bytes를 별도의 temporary directory에 쓰고 각자 기존 `app.analyzer.pipeline.load_normalized_logs()`를 실행한다. 변형은 Parser를 통과한 뒤가 아니라 입력 bytes에서 수행된다.

Parser disposition은 ER-0의 closed dimension을 따른다.

- `VERIFIED`: 모든 line이 지원 source/profile에서 기대 event type·필수 사실로 parse됨
- `PARTIAL`: 일부 event는 parse됐지만 전체 줄/필수 account 사실이 완전하지 않음. Detector 미탐지로 세지 않는다.
- `REJECTED`: parser가 malformed input을 거부하거나 usable event를 만들지 못함
- `NOT_EVALUATED`: Parser를 실행하지 않은 경우의 일반 계약 값. 현재 `prepare_scenario()`는 baseline/variant parser 실행을 요구하므로 corpus의 정상 variant 상태로는 허용하지 않는다.

지원 parser의 record 거부 `ValueError`는 `REJECTED`로 분류한다. 예상 밖 실행 예외는 `parser_execution_failed` fixed error로 중단되며 `REJECTED` 또는 no detection으로 바뀌지 않는다. 오류, repr, 반환 객체에는 raw line/account/IP/path가 포함되지 않는다. 반환된 `PreparedScenario`는 bounded ID, fixed status, 집계 사실만 가지며 `detector_execution`과 `comparison_status`는 모두 `NOT_EVALUATED`다. ER-1A 경계에서 의미상 각각 `DETECTOR_NOT_RUN`, `COMPARISON_NOT_RUN`이며, 어떤 detector output도 라벨 생성에 사용하지 않는다.

## 8. ER-1A 완료와 ER-1B 이관

| ER-0 ER-1 요구 | ER-1A 상태 | ER-1B 요구 |
|---|---|---|
| closed synthetic corpus/manifest, safe fixture loading, 7 byte mutations | 완료 및 테스트 | 그대로 유지·확장 검토 |
| independent positive/negative/undetermined input-pattern labels | 입력 사실로 검증; 실행 결과 라벨 아님 | 독립 reviewer/holdout와 provenance 강화 |
| Parser disposition과 facts 확인 | baseline/variant 기존 Loader·Parser 사전 검증 | partial scope 비교 가능성, completeness evidence, reason mapping |
| Detector 실행 및 3개 판정 dimension | **미실행** | fresh owner/context로 baseline/variant pipeline 재실행, `DETECTOR_NOT_RUN` vs execution failure 분리 |
| Brute 선택 window/private context와 IP 전체 feature 구분 | Production 구현을 조사하고 독립 label 계산만 수행 | Production selector/evidence/owner consumer 계약을 실제 새 run에 재검증 |
| Spray Production whole-span / evaluation window 분리 | whole-span label만 계산; prototype 미사용 | whole-span Production 재실행; 다른 후보는 별도 정책으로 분리 |
| Comparison `PRESERVED/LOST/GAINED/UNCHANGED_ABSENT/INCOMPARABLE/UNDETERMINED` | **미생성** | parser/label/config/scope provenance 일치 후 fail-closed 비교 |
| cross-run/context binding, canonical redacted result, 실행 결정성 | 준비 결과 반복 결정성과 원본 fixture 불변 확인 | run owner 및 evidence binding, canonical output 및 전체 privacy/network 검증 |
| ER-0 fixed reason-code 집합과 bounded metrics | mutation/manifest/parser 핵심 fixed error만 사용 | ER-0 schema-versioned full reason codes와 분모/metric 요구를 구현 |

따라서 ER-1A는 ER-0의 요구를 축소하지 않는다. 완성된 detector 반사실 분석기, 회피 성공 분석 또는 Production detector 평가를 주장하지 않는다.

## 9. Privacy와 security

고정 corpus 외 임의 path, 사용자 홈, network, subprocess, API/LLM 접근은 없다. 모듈은 `app/evaluation/`에만 있으며 Production API/UI에 연결되지 않는다. raw logs는 temporary parser input으로만 존재하고 public result나 error에 반환되지 않는다. 임시 디렉터리 종료 시 OS 파일 삭제 보장은 하지 않으며 secure erase를 주장하지 않는다.

기대 사실은 bounded counts/span, 정책 label, synthetic scenario ID만 담는다. 예외는 `CounterfactualCorpusError`의 fixed category만 표시한다. canary/원문 문자열을 error/repr에 반사하지 않는다. NIST log handling 지침을 인용하더라도 이 harness를 포렌식 도구나 custody 보증으로 표현하지 않는다. 모델, Gemini, embedding, 외부 API, 자동 대응은 사용하지 않는다.

## 10. Research Basis

자료 확인일: 2026-11-04. 외부 자료는 근거의 출처, 분석 재현성, 관측 한계를 정리하는 데 사용했고 detector 조건으로 복사하지 않았다.

- NIST [SP 800-92, Guide to Computer Security Log Management](https://csrc.nist.gov/pubs/sp/800/92/final) 및 [SP 800-86, Guide to Integrating Forensic Techniques into Incident Response](https://csrc.nist.gov/pubs/sp/800/86/final): 로그 관리·분석 및 조사 근거 보존의 배경이다. 본 프로젝트의 synthetic test는 NIST 인증이나 forensic custody가 아니다.
- MITRE ATT&CK [T1110.001 Password Guessing](https://attack.mitre.org/techniques/T1110/001/), [T1110.003 Password Spraying](https://attack.mitre.org/techniques/T1110/003/), [DET0551](https://attack.mitre.org/detectionstrategies/DET0551/), [DET0487](https://attack.mitre.org/detectionstrategies/DET0487/): 개념과 관측 맥락 참고다. MITRE는 5회/60초 또는 4회/3계정/60초를 승인하지 않는다.
- IETF [RFC 5424](https://datatracker.ietf.org/doc/html/rfc5424): SSH fixture는 repository의 제한된 RFC 5424 profile을 따르기 위해 참고했다. parse 가능한 timestamp는 원천 clock 정확성의 증거가 아니다.
- 현재 코드 근거: `app/analyzer/pipeline.py`, `app/detector/brute_force.py`, `app/detector/password_spray.py`, `app/parser/registry.py`, `app/parser/auth_log.py`, `app/parser/ssh_auth.py`, `app/evaluation/detector_accuracy.py`, 기존 `docs/evidence_research_er0.md`.

외부 자료에서 온 원칙과 이번에 제안한 사항을 구분한다. 현재 Production heuristic은 프로젝트 정책일 뿐 일반 보안 표준이 아니다. 운영 데이터, 시계 오차, replay/중복 전달, NAT/shared egress, 계정 정규화, source authenticity는 여기서 검증되지 않았다.

## 11. TDD와 테스트 결과

- 문서 계약 테스트를 문서 작성 전에 실행: 문서 파일 부재와 docs index 링크 부재로 **2 failed** (예상 RED).
- 기존 전체 기준선은 시작 Gate 절 참조. Full pytest와 기존 evaluation은 순차 실행했다.
- 신규 focused: `uv run pytest -q tests/test_counterfactual_corpus_er1a.py` — **24 passed**. 포함: 정상/비정상 manifest, duplicate key/NaN/UTF-8, traversal/symlink/size cap, 7 mutation bytes 변화 및 원본 불변, supported application/SSH Parser 상태, independent label 충돌, deterministic preparation, canary와 fixed error, 예상 밖 Parser 예외 분리.
- 완료 후 ER-1A + ER-0 + detector accuracy + parser/privacy 회귀, 전체 `uv run pytest -q`, 기존 `uv run python -m app.evaluation`, compile, `git diff --check` 결과를 커밋 직전 기록한다. 기존 evaluation 수치를 ER-1 결과와 합산하지 않는다.
- 기존 detector accuracy corpus/labels, Production parser/detector, API/UI, dependency/lockfile, workflow 변경은 없다.

## 12. ER-1B 진입 조건과 미해결 위험

ER-1B는 별도 scope와 테스트 설계를 먼저 고정한 뒤 시작한다. 각 baseline/variant에 새 Loader→Parser→Detector 실행 및 새 private owner/context를 만들고, Brute selected window와 whole-IP facts를 독립적으로 검증한다. Spray는 Production whole-span만 기본 비교하고 evaluation-only sliding을 섞지 않는다. Parser status, detector status, comparison status를 독립 closed dimension으로 유지하고, partial/rejected/exception/incomplete provenance는 fail-closed한다. source, policy/parser version, scope, independent label provenance가 맞지 않으면 비교하지 않는다. ER-0 fixed reason code, output byte determinism, stdout/stderr, filesystem/network/privacy canary, bounded runtime/metrics를 별도 검증한다.

미해결: label reviewer와 holdout 부재, source clock 신뢰도, event duplicate/replay, 운영 계정/NAT context, partial input의 동등 비교 기준, parser format 손상 후 어떤 사실이 남는지의 일반화. `PATTERN_ABSENT`는 미탐지 또는 안전을 뜻하지 않는다. Parser `REJECTED`는 Detector false negative가 아니다. 입력 조건 변화가 결과를 바꾼 단독 인과 원인임을 주장할 수 없다.

## 13. 최종 판정

**`ER_1A_COUNTERFACTUAL_CORPUS_LOCAL_CONDITIONAL_GO`** — 합성 corpus/closed manifest, 7 byte mutation, Application/SSH Parser prevalidation, independent input-pattern labels, fixed privacy/error boundary와 원본 불변성 테스트를 로컬에서 확인했다. ER-0의 나머지 pipeline 실행·comparison 요구는 ER-1B에 남아 있다. 새 커밋의 원격 Ubuntu 결과는 push 전 `NOT_TESTED`이며, Safari/실제 모바일은 이 backend 평가 단계에서 해당하지 않는다.

실제 사용자 자료: `NO_GO`; 조직 운영: `NO_GO`; 자동 대응: `NO_GO`; 운영 탐지 정확도 승인 아님.
