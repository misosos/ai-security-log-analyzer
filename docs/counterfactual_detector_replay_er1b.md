# ER-1B — 반사실 합성 입력 Production Detector 재실행

## 1. Executive Summary

ER-1B는 ER-1A의 16개 합성 시나리오를 각기 새 입력으로 로드하고, 현재 Production 분석 진입점에서 baseline과 변형본을 각각 실행한다. Parser, Detection, Comparison 상태는 분리되며 불완전하거나 서로 다른 범위의 결과는 fail-closed로 비교를 제한한다. 출력은 원문이나 내부 식별자를 포함하지 않는 bounded canonical JSON이다.

이는 합성 corpus에 대한 동작 특성화 결과다. 공격 회피 성공, 실환경 정확도, 보안 통제 효과를 측정하지 않는다.

## 2. Start SHA / CI Gate

- 시작 SHA 및 원격 `main`: `1915c69da39e132ff6643f44fbac38a434202036`
- exact Push CI: `41806294492`, 동일 SHA, `push / completed / success`
- 필수 regression, Linux TCP/JSONL/Restricted Report, Chromium·axe, tracked-file 검사가 완료되어 성공했고 artifact는 0개였다.
- 시작 시 branch `main`, working tree clean, local/main/origin/GitHub SHA 일치, ahead/behind `0/0`이었다.
- `v0.4.0` tag와 Release target은 `eecd6ee1cda0545e34b01c42e1a2163a899bcc27`에 유지된다.
- ER-0 및 ER-1A 파일은 변경하지 않았다.

## 3. Existing ER-0 / ER-1A Contract

ER-0의 네 개 개념(Observation, Evidence, Claim, Uncertainty)과 Parser/Detection/Comparison 차원 및 closed reason code를 따른다. ER-1A는 16개 고정 시나리오, Application 13개·SSH 3개, 일곱 byte mutation, 독립 입력 사실 기반 label과 Parser 사전 검증을 제공한다. ER-1A의 `PreparedScenario`는 계속 Detector 미실행 상태를 표현하며, ER-1B 결과는 별도 DTO로 만든다.

현 Production Brute Force는 IP별 전체 feature와 구분되는 같은 IP·알려진 동일 계정의 선택 window에서 실패 5회 이상, 60초 이하 조건을 사용한다. Password Spraying-like는 같은 IP 전체 실패 집합에서 4회 이상, 알려진 대상 계정 3개 이상, 전체 span 60초 이하를 사용한다. 평가용 sliding prototype은 적용하지 않았다. 이 threshold는 프로젝트 정책이지 표준상 보편 임계값이 아니다.

## 4. Replay Architecture

`app/evaluation/counterfactual_replay.py`는 고정 corpus loader와 기존 byte mutation만 호출한다. baseline과 variant bytes를 서로 다른 임시 디렉터리에 써서 read-back 일치를 검사하고, 각각 `app.main.analyze_with_source_role_snapshot()`에 전달한다. corpus는 최대 32개로 제한되며 canonical output은 64 KiB 이하이다. CLI는 `uv run python -m app.evaluation.counterfactual_replay_cli`로 고정 corpus만 실행하고 인자를 받지 않는다.

임시 입력 경로는 각 실행에만 사용되고 결과·오류·stdout/stderr에 출력되지 않는다. ER-1B 모듈은 `app/evaluation/` 아래 offline evaluation 전용이며 API, UI 또는 사용자 파일 입력 경로에 연결되지 않는다.

## 5. Fresh Run / Owner Binding

각 진입점 호출은 Production 코드에서 새 `AnalysisRunOwner`를 만들고 반환 분석 결과에 결속한다. replay는 매 run의 `run_owner.is_bound_to(analysis)` 및 source-role snapshot 결속을 확인한다. Brute Force가 탐지되면 해당 run의 비공개 `BruteWindowContext`가 동일 owner에 속하고 evidence membership이 맞는지 검사한다. baseline과 variant owner 객체가 같은 경우 계약 오류다. private context와 owner는 결과 DTO에 직렬화하지 않는다.

## 6. Parser & Detection States

Parser 상태는 각 입력별로 보존한다.

| 상태 | 의미 |
|---|---|
| `VERIFIED` | 해당 합성 fixture의 정의된 행·필드 Parser 검증 완료 |
| `PARTIAL` | 일부 행 또는 필수 field가 누락·불완전 |
| `REJECTED` | 사용 가능한 정규화 입력 범위가 없음 |
| `NOT_EVALUATED` | Parser 미실행 |

Detection 상태:

| 상태 | 의미 |
|---|---|
| `DETECTED` | 지정 Production detector가 실행 완료되어 true 반환 |
| `NOT_DETECTED` | 지정 detector가 실제 실행되어 false 반환 |
| `NOT_EVALUATED` | Parser 거부 등으로 실행하지 않음 |
| `EXECUTION_FAILED` | Production 실행이 완료되지 않음 |

REJECTED는 `NOT_EVALUATED` detector를 강제한다. 예외는 fixed reason으로 바꾸며 NOT_DETECTED가 되지 않는다. PARTIAL에서 detector를 실행하더라도 결과는 parsed subset 범위뿐이다. 예기치 않은 Parser 실행 예외는 REJECTED로 둔갑하지 않고 고정 execution-failure 결과로 남는다.

## 7. Evidence Binding

현재 공개 `Evidence` DTO는 Production detector의 구조화 근거다. ER-1B는 그 DTO를 외부 결과로 복제하지 않고 내부 검증에만 사용한다. Brute evidence는 owner-bound window context로 검증하며 Spray evidence는 detector type, 고정 evidence 종류, source, 계산된 feature와 시간 span을 대조한다. `RunObservation`에는 비교에 필요한 고정 메타데이터만 들어가고 opaque subject repr은 가려진다.

비교 가능한 DETECTED/NOT_DETECTED 판정에는 정상 완료, 지정 subject, 동일 detector/policy/source/profile/scope, label provenance 및 evidence binding이 필요하다. Reason code는 ER-0 closed set에서만 허용한다.

## 8. Comparison Rules

비교 순서는 Boolean 차이보다 선행하는 계약 검증을 포함한다.

| 결과 | 조건 |
|---|---|
| `PRESERVED` | 검증된 동일 범위에서 양쪽 DETECTED |
| `LOST` | 검증된 동일 범위에서 baseline DETECTED, variant NOT_DETECTED |
| `GAINED` | 검증된 동일 범위에서 baseline NOT_DETECTED, variant DETECTED |
| `UNCHANGED_ABSENT` | 검증된 동일 범위에서 양쪽 NOT_DETECTED |
| `INCOMPARABLE` | 알려진 policy/source/profile/scope/subject 불일치 또는 REJECTED |
| `UNDETERMINED` | 실행 불완전, evidence binding 또는 label provenance 부족 |

입력 scope, subject, completeness, binding이 확인되지 않으면 LOST/GAINED로 결론내리지 않는다. PARTIAL은 parsed subset만 의미한다. PARTIAL/VERIFIED 비교는 입력 범위 불일치, PARTIAL끼리도 결손 동등성이 증명되지 않으면 UNDETERMINED다. REJECTED는 Detection `NOT_EVALUATED`, Comparison `INCOMPARABLE`이다. Target subject가 결과 map에 없으면 false를 생성하지 않는다. 실행 오류는 NOT_DETECTED가 아니다.

## 9. Canonical Output

`ReplayReport`의 공개 필드는 schema version, scenario/detector/policy/profile, 세 차원의 고정 상태, 고정 reason code, 사전 작성된 bounded pattern label, label 검증 상태, 허용된 집계 사실이다. 원문, account, IP, hostname, timestamp, 경로, event/evidence 객체, owner/context, exception repr은 제외한다. JSON은 key 정렬·고정 separators·고정 newline·NaN 금지로 생성하며 실행 시각과 private run identity를 포함하지 않는다.

## 10. Synthetic Corpus Results

검증 실행은 **16개** ER-1A 시나리오 전부를 처리했다. 아래 분모는 각 차원별 전체 16 시나리오이며 baseline/variant Parser와 Detection은 별도 집계다.

| 차원 | 결과 |
|---|---|
| Baseline Parser | VERIFIED 16, PARTIAL 0, REJECTED 0, NOT_EVALUATED 0 |
| Variant Parser | VERIFIED 13, PARTIAL 2, REJECTED 1, NOT_EVALUATED 0 |
| Baseline Detection | DETECTED 13, NOT_DETECTED 3, NOT_EVALUATED 0, EXECUTION_FAILED 0 |
| Variant Detection | DETECTED 6, NOT_DETECTED 9, NOT_EVALUATED 1, EXECUTION_FAILED 0 |
| Comparison | PRESERVED 4, LOST 6, GAINED 2, UNCHANGED_ABSENT 1, INCOMPARABLE 3, UNDETERMINED 0 |
| Independent label check | Baseline MATCH 16; variant MATCH 13, NOT_EVALUATED 3, MISMATCH 0 |

비교 제외 합계는 INCOMPARABLE과 UNDETERMINED로 정의하며 3건이다. 이 수치는 corpus 내부 characterization이며 정확도·회피율·실환경 탐지 성능으로 일반화할 수 없다. Format damage는 Parser 거부로 처리됐고 Detector false negative로 집계하지 않았다.

## 11. TDD / Security Tests

구현 전 functional contract test는 comparator 모듈 부재로 실패했고, 문서 계약 테스트는 문서와 index 링크 부재로 2건 실패했다. 구현 후 ER-1B replay focused tests는 20 passed, ER-1A와 합친 focused 검증은 45 passed였다(최종 재실행 결과는 완료 보고에 기록). 테스트는 여섯 comparison outcome, 차원 충돌, partial/rejected, 실행 오류, provenance/binding, policy/profile/source/scope/subject 불일치, 16개 Production replay, 다른 temp 입력 경로 및 owner, 원본 격리, canonical 반복 일치, stdout/stderr 비노출, socket 연결 시도 0을 다룬다.

테스트는 합성 corpus만 로드한다. 외부 API/LLM/network 호출은 금지되며 네트워크 연결 시도는 테스트에서 차단·계수한다. 실제 사용자 자료: `NO_GO`. 조직 운영: `NO_GO`. 자동 대응: `NO_GO`.

### Research Basis 및 Observable Evidence Mapping

ER-0에서 확인한 [NIST SP 800-92](https://csrc.nist.gov/pubs/sp/800/92/final), [NIST SP 800-86](https://csrc.nist.gov/pubs/sp/800/86/final), [MITRE ATT&CK T1110.001](https://attack.mitre.org/techniques/T1110/001/), [T1110.003](https://attack.mitre.org/techniques/T1110/003/) 및 [RFC 5424](https://datatracker.ietf.org/doc/html/rfc5424)를 재사용한다. 이들은 로그 분석의 출처·한계와 관련한 배경이지 5회/60초, 4회/3계정/60초를 표준 임계값으로 정당화하지 않는다.

관측 매핑은 합성 bytes → 기존 Loader/Parser → 새로 생성된 Production normalized event/features → run-bound detector result/evidence → closed comparison state다. 가능한 주장은 해당 합성 run에서 현재 정책 조건이 관측됐는지에 한정된다. 실제 source authenticity, 수집 완전성, 공격자 정체 또는 변형이 유일 원인인 인과 주장은 할 수 없다.

## 12. Limitations

- Corpus는 작고 합성·프로젝트 작성 label이며 독립 reviewer/holdout이 없다.
- 실행 환경은 현재 개발 호스트이며 Linux 전용 런타임 검증을 대신하지 않는다.
- Production parser와 detector를 재실행하는 characterization이지 독립적인 탐지 정확도 평가가 아니다.
- `LOST`/`GAINED`는 정의된 fixture proposition 변화만 말한다. Counterfactual Change ≠ Real-world Evasion Success.
- Parser rejection은 detector false negative가 아니다. Detection 부재는 안전을 의미하지 않는다.
- Correlation은 인과관계가 아니며 로그인 성공은 계정 침해 증거가 아니다.
- 새 판정 상태는 실제 사용자 로그의 출처 진위, 수집 완전성, 운영 통제를 보증하지 않는다.

## 13. ER-1C 진입 조건

ER-1C 이전에 독립 reviewer가 detector 출력과 분리된 label basis를 검토하고, 고정 corpus version·policy/parser provenance·비교 대상 분모를 승인해야 한다. Mutation별 다중 파생 특징과 subject 변경의 비교 가능성도 검토한다. ER-1C는 보류·비교 불가 결과를 설명하는 report 단계로 한정하고, 운영 API/UI 연결이나 정책 변경은 별도 승인 없이는 금지한다.

NIST 및 MITRE 자료와 기존 parser/evaluation contract는 관측 사실과 해석 한계를 구분하는 배경 원칙으로만 사용한다. 이는 이 corpus의 threshold를 표준 기준으로 승인하지 않는다. Observable Evidence Mapping은 합성 bytes → 기존 source parser → production normalized facts/features → owner-bound detector evidence → 제한된 comparison state로 이어진다. 운영 telemetry와 사용자 환경은 이 검증 범위 밖이다.

## 14. Test Results

시작 기준선은 순차 실행했다: `uv run pytest -q` **3,683 passed, 2 warnings**, 다음 `uv run python -m app.evaluation` 성공(합성 boundary 79/79, risk/case 각 70/70, Linux process 분류 합성 21/21). 경고는 기존 Starlette/httpx 및 AnyIO deprecation이다.

- TDD RED: 구현 전 replay contract tests는 comparator module import 부재로 실패했다. 문서 테스트는 문서 부재와 index link 부재로 **2 failed**.
- 구현 후 ER-1A/ER-1B/doc focused: **47 passed**; ER-0 문서와 기존 detector accuracy 테스트까지 포함한 확장 focused 회귀: **75 passed**. Parser 사전검증과 실제 Production 실행에 전달된 두 입력의 bytes 동일성도 검사했다.
- 최종 전체 `uv run pytest -q`: **3,706 passed, 2 기존 deprecation warnings** (macOS, Python 3.12).
- 순차 `uv run python -m app.evaluation`: 성공; synthetic boundary 79/79, risk 70/70, case 70/70, Linux process synthetic evaluator 21/21. 이는 ER-1B replay 수치가 아니다.
- ER-1B CLI: 16개 실행; canonical 결과 반복 byte-equality는 focused test에서 검증.
- 네트워크 연결 시도: **0** (socket connect/connect_ex 차단 test). CLI stdout/stderr 및 예외 canary 비노출 검사 통과.
- `uv lock --check`, Python compile, `git diff --check`, 변경 범위 검사, 고정 corpus CLI 실행 모두 성공했다. dependency·lockfile 변경은 없다. Linux host runtime smoke와 새 SHA Ubuntu CI는 로컬 push 전 `NOT_TESTED`다.

## 15. Final Decision

`ER_1B_COUNTERFACTUAL_REPLAY_LOCAL_CONDITIONAL_GO` — 합성 입력을 기존 Production 경로에서 분리 재생하고, 근거 검증 뒤 비교하는 offline evaluation 범위에 한정한다. 새 커밋의 Ubuntu CI는 push 전 미검증이다. Push하지 않았다. 운영 탐지 정확도 승인, 실제 사용자 자료 사용, 조직 운영 또는 자동 대응 허가는 아니다.
