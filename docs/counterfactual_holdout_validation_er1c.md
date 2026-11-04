# ER-1C — 독립 라벨 감사 및 합성 Holdout 검증

## 1. Executive Summary

ER-1C는 ER-1A 개발 corpus 16건의 입력 사실·정책 label 계약을 다시 검사하고, 별도로 작성한 14건의 합성 holdout을 현재 Production Loader → Parser → Detector 경로에 재생했다. 기대 label은 holdout bytes와 명시된 정책 조건으로 먼저 작성·감사했다. Detector replay는 이 감사를 통과한 뒤에만 수행하며 replay 결과로 label을 수정하지 않는다.

판정 범위는 고정 synthetic corpus에서의 자동 계약 검증과 실행 재현성이다. 실제 탐지 정확도, 공격 회피율, 공격 의도, 침해 여부 또는 운영 효능을 평가하지 않는다. 자동화 계약은 `AUTOMATED_CONTRACT_VALIDATED`; 독립 사람 검토는 `INDEPENDENT_HUMAN_REVIEW_PENDING`이다.

이 결과는 운영 탐지 정확도 또는 운영 환경의 공격 회피 성능을 의미하지 않는다.

## 2. Start Gate

- 저장소: `misosos/ai-security-log-analyzer`, branch `main`
- 기준 SHA 및 local HEAD, local `main`, `origin/main`, GitHub `main`: `f17ed6f0c1ff5e8e1a11e21ad69772fcb5c22bc6`
- exact [push CI Run 41810925590](https://github.com/misosos/ai-security-log-analyzer/actions/runs/41810925590): 정확한 head SHA, `completed / success`. 전체 pytest, Linux TCP Syslog, JSONL acceptance, Restricted Report, Chromium·axe, tracked-file 검사가 성공했고 artifact는 0개였다.
- 시작 tree clean, `origin/main...HEAD` behind/ahead `0/0`
- `v0.4.0` tag와 GitHub Release target은 `eecd6ee1cda0545e34b01c42e1a2163a899bcc27` 유지
- 시작 기준 ER-0·ER-1A 파일 변경 없음

이는 변경 전 Gate 증거다. 새 커밋의 Ubuntu CI 결과를 의미하지 않는다.

## 3. Existing ER-0 / ER-1B Contract

ER-0의 Observation, Evidence, Claim, Uncertainty 네 개념과 Parser·Detection·Comparison의 독립 상태 차원을 따른다. 기존 `app.models.schemas.Evidence`는 내부 Detector의 구조화 값이며, 출처 무결성이나 독립 label provenance를 자동 증명하지 않는다.

ER-1B는 `app/evaluation/counterfactual_replay.py`에서 baseline과 variant를 각각 새 Production 분석 입력으로 실행한다. ER-1C는 replay 로직을 복제하지 않고 내부 `_replay_prevalidated_scenario()` 경계를 재사용한다. 각 입력은 별도 임시 입력과 새 분석 실행/owner를 사용하며 private owner/context는 결과에 직렬화하지 않는다. `PreparedScenario`와 ER-1B 결과 계약은 바꾸지 않았다.

Production 정책은 현 코드와 ER-0 조사에 맞춰 고정했다.

| Detector | 검증 대상 정책 | 범위 경계 |
|---|---|---|
| Brute Force | 같은 source IP·알려진 동일 계정의 선택 sliding window, 실패 5회 이상, UTC span 60초 이하 | 선택 window Evidence와 동일 IP 전체 feature는 서로 다른 범위다. |
| Password Spraying-like | 같은 IP 전체 실패 집합, 실패 4회 이상, 알려진 계정 3개 이상, 전체 span 60초 이하 | Production whole-span이다. 평가용 sliding prototype은 사용하지 않는다. |

이 숫자는 현재 프로젝트의 평가 가능한 정책 조건이지 보편 표준이나 외부 권고 임계값이 아니다. `PATTERN_PRESENT`는 합성 입력에서 정책의 관찰 조건이 성립했다는 뜻일 뿐 실제 공격이 아니다. `PATTERN_ABSENT`는 안전을 뜻하지 않는다.

## 4. Holdout Design

경로는 `sample_logs/counterfactual_holdout/`이며 기존 `sample_logs/counterfactual/`를 수정하지 않았다. Holdout에는 독립 fixture 14개가 있다. 동일 ID 또는 동일 bytes를 가진 ER-1A fixture는 loader가 거부한다.

| 구분 | 시나리오 수 |
|---|---:|
| Brute Force | 7 |
| Password Spraying-like | 7 |
| Application | 9 |
| SSH | 5 |
| Baseline Parser VERIFIED | 14 |
| 변형 Parser VERIFIED / PARTIAL / REJECTED | 11 / 2 / 1 |

입력 조합은 단순한 계정·IP·시간 치환 복제가 아니다. 여기에는 Brute 선택 계정 window를 유지하면서 같은 IP의 다른 계정 noise를 늘리는 경우, SSH에서 60초 경계를 넘나드는 경우, 서로 다른 두 Brute 계정이 각각 window를 만족하는 경우, Spray에서 중복 계정 하나를 새 세 번째 계정으로 바꾸는 경우, 정확히 60초인 세 계정 입력 순열, 실패 행 제거로 4회 경계를 벗어나는 경우가 포함된다. 나머지 변형은 행 추가, 시간/계정/IP 변경, 순서 변경, 형식 손상이다.

Manifest는 ER-1A closed scenario schema를 재사용하고 root metadata에 `schema_version=1`, `data_scope=synthetic-only`, corpus ID, label provenance, 사람 검토 상태를 둔다. 알려진 입력 변형 7종을 모두 포함한다. 모든 IP는 IANA 문서용 주소 대역이고 계정명은 합성 식별자다. 실제 credential, hostname 또는 사용자 로그는 없다.

## 5. Independent Label Audit Method

각 시나리오의 baseline/variant 기대 사실과 `PATTERN_PRESENT`·`PATTERN_ABSENT`·`PATTERN_UNDETERMINED` label은 replay 전에 입력 행과 ER-0의 공개된 정책 조건으로 작성했다. 이 작성 단계에서는 Production Detector 출력이나 ER-1B Comparison 결과를 읽지 않는다. 정책 판정은 별도 단순 입력 사실 oracle이며 Production detector 함수를 기대값 생성기로 호출하지 않는다. Parser 사실은 기존 source Parser로 독립 사전 검증한다.

`audit_scenario()`는 baseline과 변형 bytes 각각에 대해 Parser disposition, bounded event facts, 입력 사실 기대값, 독립 pattern 기대값을 검사한다. 오류는 fixed reason code로만 표현한다. `run_holdout()`은 전체 audit가 `AUTOMATED_CONTRACT_VALIDATED`인 경우에만 replay를 진행한다. Audit mismatch는 label을 자동 보정하지 않고 중단시킨다.

ER-1A 개발 corpus도 별도로 `audit_development_corpus()`에서 독립 Parser/fact-oracle 준비 계약을 검사한다. Holdout CLI의 `development_corpus_audit` 요약과 `holdout` 결과는 별도 영역으로 출력하며, 개발 corpus 요약은 신규 holdout replay 분모에 합산하지 않는다.

## 6. Corpus Provenance and Hashes

Manifest와 fixture digest는 `sample_logs/counterfactual_holdout/hashes.json`에 기록한다. sidecar의 `manifest_sha256`와 fixture ID별 SHA-256이 검증 대상이다. `hashes.json` 자신은 자기 해시 순환을 피하기 위해 제외된다. 해시 sidecar에는 schema version, manifest SHA-256 및 fixture ID별 SHA-256만 있다. 이 digest는 저장소에서 이후의 변경을 탐지하는 기준이지, 외부에 사전 등록했다는 증거가 아니다. 블라인드 리뷰가 완료됐다고 주장하지 않는다.

고정 Manifest SHA-256:

`392127d5ad7fb61cfca361d0b9c21a6c349d94313c14bd3c1f4ead48f9393739`

Fixture SHA-256:

| Fixture ID | SHA-256 |
|---|---|
| `er1c_bf_app_61_to_60_base` | `1b5b04e97c8347954dc149c7e992a45f14fbd25943308b876a1ef60371e219ad` |
| `er1c_bf_app_partial_missing_user_base` | `adf6f9333a7014348946a5b9cc79db2ebac430b56362b4961933d06c420cb475` |
| `er1c_bf_app_subject_membership_change_base` | `0d2fd4b3fbb1aac729cb6986cd970aa2d045ea26f19f1e2ef0f290b51419aa93` |
| `er1c_bf_app_window_with_late_ip_noise_base` | `03607adc43c7b1173c04908e58f8cc0c965de2c80b053350c554ac69b4a34c9e` |
| `er1c_bf_ssh_61_second_crossing_base` | `c890676cf47ca0c45616a1f69605a875024416d668bdab0c3749546785fd3df5` |
| `er1c_bf_ssh_rejected_timestamp_base` | `dd6777707094fd0d855fc062a5e25b4ba3b71a5c0ce046c89ce7992bf54a0a87` |
| `er1c_bf_ssh_two_qualifying_accounts_base` | `f0b4bebd94355be02217ea88c276b06f93a8e6c16bf7e78f785e73b8071daa5c` |
| `er1c_spray_app_absent_permutation_base` | `e41c23b9d1871efbadf4f531097f1964bae40cd56d19e2ad9636d26011e6a2c7` |
| `er1c_spray_app_exact60_permutation_base` | `e36d9b5c495cbcf0947ada999740ff2471e26fb83d07ebc9f3bba8fcb35eaf84` |
| `er1c_spray_app_partial_account_base` | `8000172aa8cca6406a613715e31d7226accb39d8c5cca5d90480bcffbd7d3283` |
| `er1c_spray_app_remove_boundary_base` | `4d52296cc682d31474b772692fc8bdb1316d55e605ade9b8c1add47224f0f1db` |
| `er1c_spray_app_third_account_added_base` | `4f86f390e92fb1d0b3273c2db5dd05b75c8b09532816a751b829aecbfe2ce37f` |
| `er1c_spray_ssh_fourth_failure_at60_base` | `82f169826589c55a0f9e3e41ba80f44a6f9d5dff0f8206f1ba3d32585454ddb8` |
| `er1c_spray_ssh_span_61_base` | `14f83c5c81c6c126d9c983132fc1a8ea199acd86d2037739a7d110906de5a311` |

## 7. Parser / Detector / Comparison Validation

Baseline과 변형 모두 Parser 사전 검증에 사용한 bytes와 실제 Production replay에 전달한 bytes가 같음을 테스트에서 계수했다. Production 분석 진입점은 각 실행에 새 private run owner를 만든다. 각 케이스는 baseline/variant가 독립이고, REJECTED 변형은 Detector `NOT_EVALUATED`다.

ER-0 Comparison Dimension을 그대로 사용한다. 파서의 일부만 검증된 입력은 전체 범위에 대한 탐지 음성으로 취급하지 않는다. Subject, source, policy, parser profile, completeness 또는 evidence scope가 서로 다르면 결과 key의 부재만으로 LOST를 만들지 않는다. Parser REJECTED는 `NOT_EVALUATED` / `INCOMPARABLE`이다. Detector 실행 실패는 `NOT_DETECTED`로 변환되지 않는다.

## 8. Result Distribution

Holdout 분모는 14개 scenario다. Parser 및 Detector 집계는 baseline과 variant를 별도로 세므로 각 입력측 분모도 14다. Comparison 분모는 scenario 14다.

| 차원 | Baseline | Variant |
|---|---|---|
| Parser | VERIFIED 14 | VERIFIED 11, PARTIAL 2, REJECTED 1 |
| Detection | DETECTED 10, NOT_DETECTED 4 | DETECTED 7, NOT_DETECTED 6, NOT_EVALUATED 1 |
| Independent label | MATCH 14, MISMATCH 0 | MATCH 11, MISMATCH 0, NOT_EVALUATED 3 |

| Comparison | 건수 |
|---|---:|
| PRESERVED | 3 |
| LOST | 4 |
| GAINED | 3 |
| UNCHANGED_ABSENT | 1 |
| INCOMPARABLE | 3 |
| UNDETERMINED | 0 |

실행 실패 0, 입력 사실 검증 실패 0, label mismatch 0이다. `NOT_EVALUATED` label 3건은 variant parser가 PARTIAL 2건, REJECTED 1건인 데서 비롯되며 detector false negative로 세지 않는다.

## 9. Mismatch and Incomparable Analysis

자동 input fact 및 정책 pattern audit는 holdout 14건에서 mismatch가 없었다. Comparison 제외 3건 중 1건은 Parser REJECTED에 따라 fail-closed 처리했고 2건은 Parser completeness/scope가 baseline과 같지 않아 입력 범위 불일치로 제외했다 (`INPUT_SCOPE_MISMATCH`). 누락된 대상 결과를 임의로 false로 채우지 않았다.

이는 label correctness의 외부 독립 검토가 아니다. 향후 mismatch가 생기면 label을 replay에 맞추지 않고 bytes·Parser facts·정책 계산을 별도 조사하며, 원인과 기존/수정 digest 및 집계 차이를 기록한 뒤에만 재판정한다.

## 10. Reproducibility

고정 corpus loader는 두 개의 승인된 corpus 경계만 전제로 하며, Holdout 경로는 코드에 고정되어 CLI에서 사용자 root/path를 받지 않는다. JSON은 UTF-8 strict, duplicate key 및 NaN/Infinity 거부다. symlink, traversal, 비정확한 파일 inventory, 과대 입력, 잘못된 fixture bytes 및 manifest/fixture hash mismatch는 거부한다. 출력은 schema version과 정렬 key를 가진 canonical JSON이며 64 KiB 상한, 고정 상태·reason code를 사용한다. 실행 시각, temp path, raw row, account, IP, timestamp 및 exception 원문은 출력하지 않는다.

두 차례 독립 holdout CLI 실행은 canonical JSON bytes가 같았다. Hash manifest에서 `hashes.json` 자체를 제외하는 점은 명시적이며, 저장소 커밋 자체가 외부 신뢰 서명이나 blind holdout 보장을 제공하지는 않는다.

## 11. Privacy / Security

- 합성 로그만 사용. 예약 주소와 synthetic account label만 포함한다.
- 네트워크 연결을 시도하지 않았고, 외부 API/LLM 경로는 없다. socket connect를 차단·계수한 테스트도 0회였다.
- Parser prevalidation에 쓰인 bytes와 재생 bytes를 같은 것으로 계수하고, 임시 입력은 run별이며 실행 뒤 제거된다.
- 모든 fixture를 명시적으로 allowlist 하고 symlink, path escape, unknown/extra file을 거부한다.
- 오류 category는 고정 코드이며 입력값·경로·raw line·예외 문자열을 반사하지 않는다.
- Manifest의 label basis는 저장소 내 audit 입력으로 유지하되 자유형 설명은 결과 JSON에 반사하지 않는다. 결과는 closed provenance와 상태만 직렬화한다.
- Production Parser/Detector, Risk/Correlation, API/UI, 기존 accuracy corpus, dependency/lockfile 및 workflow는 수정하지 않았다.

## 12. External Independent Review Status

- 자동 검사: `AUTOMATED_CONTRACT_VALIDATED`
- 외부 또는 독립 사람 검토: `INDEPENDENT_HUMAN_REVIEW_PENDING`

Codex가 만든 label을 같은 실행에서 다시 확인한 것은 사람의 독립 검토가 아니다. reviewer, 승인 날짜, 서명, 사전 등록 또는 blind holdout 완료를 주장하지 않는다. ER-1D 전에 별도 검토자가 fixture 의미와 policy oracle을 replay 결과와 분리해 검토하고, 의견·변경 이력을 남기는 절차가 필요하다.

## 13. Research Basis

- NIST, [SP 800-86: Guide to Integrating Forensic Techniques into Incident Response](https://csrc.nist.gov/pubs/sp/800/86/final), final 2006. 2026-11-04 확인. 사용 범위는 증거 수집·처리·분석의 기록과 한계 구분 원칙에 한정하며 이 문서의 detector threshold를 정당화하지 않는다.
- MITRE ATT&CK, [T1110.001 Password Guessing](https://attack.mitre.org/techniques/T1110/001/) 및 [T1110.003 Password Spraying](https://attack.mitre.org/techniques/T1110/003/), 2026-11-04 확인. 이들은 행동 분류의 참고이며 로그에서 식별할 수 있는 입력 행과 연결해 제한적으로 사용했다. ATT&CK 설명을 탐지 기준·공격 확정·계정 탈취의 근거로 옮기지 않았다.
- 실제 관측 가능 사실은 저장된 synthetic bytes, 현재 Application/RFC 5424 OpenSSH Parser 결과, `NormalizedEvent`의 지원 fields, ER-1A fact schema다.
- BF 5/60과 Spray 4/3 계정/60초 조건은 현재 repository policy이며, 이번 실험에서 새로 제안한 운영 임계값도 외부 표준도 아니다.

## 14. Limitations

- 14 holdout 시나리오는 제한된 수의 사람이 직접 작성한 합성 예시다. 통계적으로 일반화할 수 없다.
- 사람의 독립 검토가 미완료이고 외부 사전 등록/서명/blind holdout이 없다.
- Parser 입력 검증은 fixture 문법과 관측 가능한 fields에 한정되며, 원본 수집 완전성·로그 진실성·실제 사건을 보증하지 않는다.
- `PATTERN_PRESENT`는 정책 조건 패턴, `PATTERN_ABSENT`는 이 scope에서의 부재 패턴일 뿐이다. 탐지 ≠ 침해, 상관 ≠ 인과, 미탐지 ≠ 안전이다.
- 다중 파생 특징 변화를 하나의 유일한 원인으로 설명하지 않는다. 원인 귀속은 ER-1D 연구 항목이다.
- 이번 실행은 macOS 호스트에서 수행됐다. 새 ER-1C 변경의 Ubuntu CI 및 기타 OS 실행은 아직 없다.

## 15. ER-1D Entry Requirements

1. 사람의 독립 라벨 검토 방법과 변경/승인 기록 형식을 먼저 승인한다.
2. 이 고정 corpus hash와 결과를 ER-1D 기준선으로 보존하고 어떤 label 수정도 이력·diff·결과 비교 없이 수행하지 않는다.
3. 원인 분석은 직접 변경 입력, 재계산된 특징, 변경된 detector condition, 실제 output observation을 분리한다.
4. `INCOMPARABLE`, `UNDETERMINED`, PARTIAL 및 REJECTED를 탐지 음성으로 축약하지 않는다.
5. Production Detector 및 API/UI는 별도 명시적 보안 Gate 없이 수정하지 않는다.
6. 합성-only, 외부 네트워크 0, canonical output privacy, full regression을 계속 요구한다.

## 16. Test Results

TDD에서 holdout 모듈이 없을 때 신규 focused test는 `ModuleNotFoundError: app.evaluation.counterfactual_holdout`로 실패했다. 구현 후 문서 계약은 문서와 색인 링크가 없을 때 2건 실패했다. 추가로 요구된 실패 행 제거 변형이 corpus에 없다는 계약 검사 실패를 확인했고, Detector replay 전에 독립 입력 사실을 기준으로 14번째 scenario를 추가하고 hash를 기록했다. 기존 label을 replay 결과에 맞춰 변경하지 않았다.

검증 기록은 전체 순차 재실행 후 업데이트한다. 시작 baseline은 `uv run pytest -q`: 3,706 passed, 기존 deprecation warning 2건. baseline `uv run python -m app.evaluation`: boundary 79/79, risk/case 각 70/70, synthetic Linux process evaluator 21/21. 이 baseline 숫자를 ER-1C 결과와 합산하지 않는다.

## 17. Final Decision

최종 판정은 모든 focused/전체 회귀 및 `uv run python -m app.evaluation`의 종료 결과를 기록한 뒤 확정한다. 조건 충족 시 `ER_1C_SYNTHETIC_HOLDOUT_LOCAL_CONDITIONAL_GO`는 자동화된 합성 holdout 검증에만 적용한다. 이는 외부 독립 검증, Production 탐지 성능, 실제 사용자 자료 분석, 조직 운영 또는 자동 대응 승인이 아니다.

실제 사용자 자료: `NO_GO`

조직 운영: `NO_GO`

자동 대응: `NO_GO`
