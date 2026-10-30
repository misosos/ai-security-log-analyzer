# Phase 36.9G-R2-R2-R1 — 신뢰된 분석 Provenance 경계 보완

## 1. Executive Summary

R2-R2에서 새 `AnalysisRunOwner`가 만든 빈 `_OwnedAnalysisResult`에 과거 실행의 `results`를 복사한 뒤 새 Context를 붙이면 Case가 생성되는 결함을 재현했다. 원인은 mapping 발급자만 확인하고 Detector·Correlation·Risk가 실제 현재 실행에서 만든 객체인지 확인하지 않은 점이다.

이번 수정은 실행 Owner가 각 신뢰된 단계에서 실제 결과 객체를 기록하고 다음 단계가 같은 객체를 소비하도록 연결한다. Detector 결과 → Correlation 결과 → Risk 결과 → 최종 private mapping 순서를 강제하고, 과거 결과를 새 Owner의 실행 결과로 봉인하는 경로를 거부한다. 공개 `analyze()`는 기존 plain `dict` 반환을 유지한다. 이 계약은 신뢰된 내부 호출 흐름에서의 우발적인 재사용·재포장을 방지하며, 같은 Python 프로세스에서 private 메서드와 객체를 의도적으로 위조하는 코드에 대한 암호학적 인증은 아니다.

판정은 로컬 테스트와 회귀가 끝난 뒤 기입한다. 실제 사용자 자료와 운영환경은 승인하지 않는다.

## 2. 시작 Gate 및 Dirty Tree 보존

- 기준 SHA: `5e4d2f8c7e5c1fa27d2e68acee8179149e003c07`
- GitHub Actions Run `41051522852`: exact SHA, `push`, `completed/success`, artifact 0개. Python 3.12/lock, 전체 회귀, Linux process/checkpoint·SSH, TCP Syslog, JSONL, restricted report, Chromium/axe, tracked-file 검사 성공.
- 시작 branch `main`; HEAD/local main/origin main 일치; ahead/behind `0/0`; v0.4.0 target `eecd6ee1cda0545e34b01c42e1a2163a899bcc27` 유지.
- 시작 시 dirty tree는 R2-R2에서 남긴 `tests/test_analysis_owner_closure_36_9g_r2_r2.py`, `docs/analysis_owner_independent_closure_36_9g_r2_r2.md`, `docs/index.md`뿐이었다. 세 파일을 보존했고 기존 HOLD 기록을 수정하지 않았다.

## 3. 기존 HOLD 및 RED 재현

기존 RED는 정상 A 결과의 `results`를 새 B Owner의 owned mapping으로 복사하고 B 이벤트의 새 Context와 결합한 후 Case projection을 호출했다. 기존 동작은 Case 1개 생성이었다. 이는 mapping 소유권과 결과 출처를 혼동한 것이다.

수정 후 RED 테스트는 정상 B 실행으로 Case가 만들어지는 것을 먼저 확인한 뒤, B의 owned mapping 안에 A의 deep-copied `results`를 넣고 실제 Case projection을 호출해 Adapter가 거부하는지 확인한다. 추가 stage provenance 테스트는 B의 Detector 산출물을 A 결과로 대체하거나 A의 Correlation relation을 끼우는 경우를 각각 거부한다. 기존 보안 assertion을 완화하지 않는다.

## 4. Trust Boundary와 보호 범위

| 경계 | 데이터/책임 | 신뢰 의미 |
|---|---|---|
| A. 외부 입력 | Text/File/API 로그와 source metadata | 비신뢰 입력. 기존 Parser·입력 검증 적용 |
| B. 정규화 | `NormalizedEvent` | Parser가 관측한 필드. 신원·침해·인과의 증명은 아님 |
| C. 내부 실행 | Detector, Brute Window, Correlation, Risk | 현재 실행의 산출물을 단계별로 연결 |
| D. 내부 소비자 | Case adapter/assembler, Report, Checklist, Live | 완성된 실행 결과와 해당 Context만 사용 |
| E. 공개 출력 | plain Analysis, API, CLI, Report, SSE | private Owner/Context/provenance 미노출 |

정상 독립 재분석은 입력 값이나 이벤트 객체를 공유해도 새 Owner로 별도 계산하므로 허용한다. 잘못된 내부 재사용은 한 실행의 결과 객체를 다른 실행의 결과로 대체하거나 끼워 넣는 것이다. 악의적인 동일 프로세스 코드는 Python private 메서드를 직접 호출하거나 객체를 저수준 조작할 수 있다. 이를 방어하는 격리·암호학적 경계는 이번 변경에 포함되지 않는다.

## 5. Mapping Ownership과 Result Provenance

`_OwnedAnalysisResult`는 mapping 객체가 어느 Owner에 결속됐는지를 나타낸다. 이것만으로 mapping 안의 값이 그 실행에서 계산됐다는 증거가 되지 않는다. 이번 변경은 `AnalysisRunOwner`가 보유한 단계별 private 참조를 통해 실제 산출물의 연속성을 검사한다.

- Detector가 만든 subject `features`/`detections`와 detection slot 객체를 Owner에 한 번 결속한다.
- Correlation은 같은 Detector 객체 집합을 확인한 뒤 현재 결과 entry와 correlation mapping을 기록한다.
- Risk 단계는 같은 entry/correlation을 확인하고 해당 실행의 risk mapping 및 level을 기록한다.
- 최종 private mapping은 Risk까지 완성된 동일 분석 mapping만 봉인한다.
- Wrapper와 Case adapter는 Owner의 final binding 검증을 거친다. Brute Context는 실행 Owner와 Detection Evidence·실제 실패 membership을 별도로 확인한다.

이는 객체 참조 연속성에 기반한 내부 provenance다. 내부 mapping의 모든 중첩 값을 불변으로 만들거나 악의적인 코드의 in-place mutation을 암호학적으로 탐지한다는 보장은 아니다. Consumer는 기존 closed-schema/Evidence/Context 검증도 계속 수행한다.

## 6. 실제 호출 그래프

```text
Text/File/Sample input
  → Parser / NormalizedEvent
  → detect_attacks_with_context (Owner가 Detector 산출물 결속)
  → correlate_attacks (Detector identity 확인, Brute Context gate, Correlation 산출물 결속)
  → assess_risk[_with_metadata] (Risk 산출물 결속)
  → _create_analysis_result (최종 private mapping 봉인)
  → Source-role wrapper
  → Case adapter / assembler
  → Report / Checklist projection
  → 공개 plain dict / 닫힌 DTO
```

Static의 `_analyze_normalized_logs_with_context()`가 Owner를 만들고 위 단계를 수행한다. `analyze()`는 최종 결과를 `dict(result)`로 복사해 기존 공개 반환 계약을 유지한다. `analyze_with_source_role_snapshot()`은 private wrapper에 실행 Owner와 Window Context를 담는다. Restricted report도 같은 detector→correlation→risk→seal 순서를 사용한다. Live accumulator는 Proposal 검증 후 Proposal detector 산출물로 새 Owner를 결속하고, correlation/risk 이후 해당 Proposal 결과를 봉인한다. 공개 projection에는 Owner가 포함되지 않는다.

## 7. 설계 후보와 선택

| 후보 | 장점 | 한계/판정 |
|---|---|---|
| A. Trusted Analysis Factory | 입력부터 모든 단계를 하나의 실행 함수로 제한 | 기존 Static/Live/Restricted 진입점을 크게 재구성할 위험. 이번 범위보다 넓음 |
| B. Finalized private snapshot | 소비자는 완성 결과만 받음 | snapshot 생성이 임의 dict를 허용하면 기존 결함을 반복 |
| C. Consumer의 필드 비교 강화 | 변경이 작음 | 값 비교만으로 복사·재포장 출처를 증명할 수 없음 |
| D. 내부 호출 신뢰 범위 명시 | 검증 가능한 보장과 임의 코드 실행을 분리 | 의도적 same-process 위조 방어는 제공하지 않음 |

채택은 A의 핵심인 **신뢰된 단계 생성 순서**와 B의 **최종 private 봉인**을 기존 파이프라인 경계에 최소 적용하고, D에 따라 보장 범위를 명시하는 방식이다. 새 UUID/hash, 전역 registry, public run ID는 추가하지 않았다. 기존 mapping을 받아 Owner를 발급하는 공개 승격 API도 없다.

## 8. Owner·Context·Analysis 결속

Owner는 내부 분석 실행마다 새로 생성된다. `select_brute_window_contexts` 및 Detection은 해당 Owner를 받아 Context를 만든다. `detect_attacks_with_context`는 완성된 Detector 결과를 Owner에 한 번 기록한다. Correlation 및 Risk 결속은 순차적이며 재호출·교체 시 실패한다. `_create_analysis_result(analysis)`는 correlated analysis의 동일 객체와 Risk까지 기록된 references를 요구한다.

기존 R2-R2의 결과 재포장 재현에서는 B의 owned mapping이 A의 deep-copied `results`를 가리키게 바뀌면 Adapter의 `run_owner.is_bound_to(analysis)` 확인이 실패하므로 Case가 생성되지 않는다. 별도 stage 재사용 테스트에서는 B Detector output에서 A Detection 객체로 교체하거나 B Correlation 안의 relation을 A 객체로 교체하면 각각 provenance 검사에서 거부된다. B를 정상 독립 분석하면 새 산출물로 봉인되어 Case 생성이 가능하다.

## 9. Case Adapter 및 Correlation

Case adapter는 `AnalysisWithSourceRoleSnapshot`의 Analysis/Owner binding을 확인하고, Context가 있을 때 Context owner, subject, 실제 실패 membership, Brute Evidence를 검사한다. Owner의 bound 검사만으로 모든 공개 필드를 허용하지 않으며 기존 closed result schema 및 Case validation을 유지한다.

Brute correlation은 현재 실행의 Detector가 만든 Brute detection identity와 Owner 결속 Context가 모두 확인된 경우에만 Context endpoint를 사용한다. 기존 정책은 그대로다: 같은 IP·계정, 선택 Window 마지막 실패를 endpoint로 하고, 성공은 엄격히 이후 60초 이내여야 한다. 다른 일반 Authentication 및 Spray 관계는 기존 함수를 유지한다. 이 관계는 시간상 관측을 나타내며 침해나 인과를 단정하지 않는다.

## 10. Live와 Source-role

Live Proposal마다 별도 Owner를 만들고, 현재 proposal의 detection mapping만 결속한다. 그 결과를 correlation/risk에 전달한 뒤 봉인한다. proposal 실패는 기존 stage 오류 계약으로 처리한다. Source-role snapshot은 기존처럼 실제 Analysis 객체 identity에 별도로 결속된다. Owner는 Role을 증명하지 않으며 `unknown`을 승격하지 않는다.

## 11. 공개 계약·Privacy·기존 분석 의미

공개 Analysis의 `results`/`global_correlation`, Detection Evidence schema, Case DTO, Report/Checklist 및 Renderer 계약은 변경하지 않는다. `AnalysisRunOwner`, Context, 원문 계정, raw log, event membership을 public JSON/Report에 넣지 않는다. 오류 메시지는 기존 고정 코드 사용을 유지한다.

Brute Window 정책(계정별 5회, 60초, Candidate C 선택)은 바뀌지 않는다. 전체 IP feature 및 Password Spray 의미도 변경하지 않는다. 기대 범위는 예시상 전체 IP 6회/70초와 Brute Window 5회/20초의 분리다. Risk 산식과 Case rule은 수정하지 않았다.

## 12. 검증 및 평가

### 시작 기준선

- 전체 pytest: `3353 passed, 2 warnings` (macOS/Python 3.12)
- 기존 평가 기준: 36.9C Historical Brute `TP 3 / FP 0 / FN 1 / TN 3`; Current `TP 4 / FP 0 / FN 0 / TN 3`; 36.9D Candidate C `17/0/1/5`; Whole-span `9/0/9/5`.

### 수정 후

기존 R2-R2 재현, R2-R1 ownership, 36.9F/36.9E/36.9D focused 묶음은 초기 실행에서 `88 passed, 2 warnings`였다. 최종 코드의 추가 검사에서는 기존 실행의 내부 Correlation relation을 끼워 넣는 경우와 Detector feature를 바꾸는 경우도 포함했고, 관련 focused 묶음은 `58 passed, 2 warnings`였다.

- 전체 pytest: `3362 passed, 2 warnings` (macOS/Python 3.12; 시작 기준 3353개 통과 항목에서 순증 9개)
- `uv sync --locked --dev`, `uv lock --check`, `python3 -m compileall -q app tests`, `git diff --check`: 성공
- `npm run test:a11y --silent`: 성공, Chromium viewport 및 text/file/checklist 경로 출력에 실패 없음
- `uv run python -m app.evaluation`: Boundary `79/79`, Risk `70/70`, Case `70/70`, Linux process `21/21`; parser `195/200` 및 나머지 지표는 기존 의미 유지
- Detector Accuracy CLI text/json: 46개 corpus, Brute Current `TP 4 / FP 0 / FN 0 / TN 3`; 다른 6 detector 지표도 기준선과 동일
- Brute Window CLI text/json: 24개 corpus; Candidate C `TP 17 / FP 0 / FN 1 / TN 5`, Whole-span `TP 9 / FP 0 / FN 9 / TN 5`; operational false-alert 후보 정책별 2건 유지

Ground Truth, fixture ID, historical 기록은 변경하지 않았다. 로컬 macOS 검증은 시작 SHA의 GitHub Linux CI와 구분한다. 새 로컬 변경분에 대한 GitHub exact-SHA CI는 아직 실행되지 않았다.

## 13. 한계·Rollback·후속 Closure

Owner는 프로세스 내부 capability이지 외부 인증 토큰이 아니다. Python의 private 상태는 리플렉션으로 조작될 수 있다. 단계 결속은 cross-stage 객체 교체를 탐지하지만, 내부 호출자가 참조 객체를 의도적으로 변조하고 private 메서드를 직접 호출하는 행위를 완전 방어하지 않는다. 이를 넘어서는 위협에는 격리된 worker/직렬화 경계의 별도 설계가 필요하다.

Rollback은 이 Phase에서 바꾼 stage provenance 결속과 관련 테스트만 되돌린다. Brute Window 정책, 이전 Phase의 HOLD/RED 자산 및 무관한 사용자 변경은 되돌리지 않는다. 다음 독립 Closure에서는 정확한 새 SHA CI, 재포장 우회, 정상 Static/Live/API/Case/Correlation, 개인정보 및 전체 회귀를 재검증한다.

## 14. 최종 판정

로컬 합성 범위 판정: **`PHASE_36_9G_R2_R2_R1_TRUSTED_PROVENANCE_LOCAL_CONDITIONAL_GO`**. 기존 재포장 RED와 추가 Cross-stage 재사용 검사가 거부됐고 정상 독립 실행의 Case/correlation이 유지됐다. 이 판정은 새 커밋에 대한 exact-SHA GitHub CI 성공이나 별도 독립 Closure를 대신하지 않는다.

실제 사용자 자료 `NO_GO`, 조직 운영 `NO_GO`, 자동 대응 `NO_GO`, 실환경 정확도 `UNVERIFIED`, 모델 기반 AI `NOT_TESTED`, Safari/VoiceOver/모바일 `NOT_TESTED`, Vector/VM `USER_ACTION_REQUIRED / ISOLATION_BLOCKED`, OS hard CPU/memory cap 및 secure erase 미보장, Renderer `KEEP_LEGACY`.
