# ER-2A — 오프라인 보안 근거 검토 보고서

## Executive Summary

ER-1B/ER-1C의 기존 합성 Replay 결과를 검증한 뒤, 안전한 필드만 결정적으로 Markdown으로 투영하는 읽기 전용 기능이다. 새로운 분석이나 보안 설명 추론은 수행하지 않는다.

| 항목 | 값 |
|---|---|
| Evaluation Scope | `SYNTHETIC_ONLY` |
| Development Corpus | 16건 |
| Holdout Corpus | 14건 |
| 전체 | 30건 |
| Human Review | `INDEPENDENT_HUMAN_REVIEW_PENDING` |
| Operational Validation | `NOT_APPROVED` |

전체 수치는 두 Corpus의 개별 결과를 단순 합산한 것이며 통합 Replay나 독립 성능 점수가 아니다.

## Start SHA and CI

- 시작 SHA: `b0dcb03f59bceca041959c07dd3108fa4ac8a6e8`
- Exact Push CI: `41858074188`, `push / completed / success`, head SHA 일치
- 필수 Linux, Restricted Report, Chromium/axe, tracked-file 단계 성공; artifact 0개
- 시작 시 local HEAD/main/origin/main/GitHub main 일치, clean, ahead/behind 0/0
- `v0.4.0` tag 및 Release target은 `eecd6ee1cda0545e34b01c42e1a2163a899bcc27` 유지

## Existing Replay Architecture

`counterfactual_replay.run_corpus()`는 ER-1A 16건을 기존 Production 분석 진입점으로 재생한다. `counterfactual_holdout.run_holdout()`는 ER-1C Holdout 14건을 동일한 Replay/Comparison 경로로 검증한다. 각 결과는 Parser, Detection, Comparison 상태와 기존 closed Reason Code, 독립 label 검증 상태를 가진다. ER-2A는 이 결과 DTO를 소비하며 Parser/Detector를 다시 구현하지 않는다.

## Report Projection Contract

`app/evaluation/counterfactual_analyst_report.py`는 고정 Corpus inventory와 결과 ID의 완전성·중복 여부, DTO/schema, closed enum 및 Reason Code, 집계 분모·재계산 결과, holdout audit 상태를 검사한다. 검증 실패는 고정 오류 범주로 종료하며 부분 보고서를 내보내지 않는다. 보고 Projection에는 보고에 필요한 whitelist 필드만 남기고, Expected Pattern Label 및 Label Basis는 폐기한다.

검증 상태 및 Reason Code는 기존 원본 값 그대로 보존한다. Parser `REJECTED`/`NOT_EVALUATED`와 Detection 조합, 비교 상태 및 label-validation 일관성을 검사한다. 출력은 UTF-8 128 KiB 이내이며 Markdown 표 구분자를 escape하고 제어문자·자유 문자열 주입을 거부한다.

CLI `uv run python -m app.evaluation.counterfactual_analyst_report_cli`는 인자 없이 실행하며 Markdown을 stdout으로만 출력한다. 알 수 없는 인자는 거부하고 출력 파일을 생성하지 않는다.

## Corpus Summary

각 분모는 해당 Corpus의 scenario 수다. Parser/Detection은 Baseline과 Variant를 각각 집계한다.

### Development — 분모 16

| 차원 | Baseline | Variant |
|---|---|---|
| Parser | VERIFIED 16 | VERIFIED 13, PARTIAL 2, REJECTED 1 |
| Detection | DETECTED 13, NOT_DETECTED 3 | DETECTED 6, NOT_DETECTED 9, NOT_EVALUATED 1 |
| Label Validation | MATCH 16 | MATCH 13, NOT_EVALUATED 3 |
| Comparison | PRESERVED 4, LOST 6, GAINED 2, UNCHANGED_ABSENT 1, INCOMPARABLE 3, UNDETERMINED 0 | — |
| 비교 제외 | 3/16 | — |

### Holdout — 분모 14

| 차원 | Baseline | Variant |
|---|---|---|
| Parser | VERIFIED 14 | VERIFIED 11, PARTIAL 2, REJECTED 1 |
| Detection | DETECTED 10, NOT_DETECTED 4 | DETECTED 7, NOT_DETECTED 6, NOT_EVALUATED 1 |
| Label Validation | MATCH 14 | MATCH 11, NOT_EVALUATED 3 |
| Comparison | PRESERVED 3, LOST 4, GAINED 3, UNCHANGED_ABSENT 1, INCOMPARABLE 3, UNDETERMINED 0 | — |
| 비교 제외 | 3/14 | — |

Holdout Comparison 분포(상태 순서 PRESERVED / LOST / GAINED / UNCHANGED_ABSENT / INCOMPARABLE / UNDETERMINED): `3 / 4 / 3 / 1 / 3 / 0`.

위 값은 시작 시 재생한 기존 DTO와 일치하는지 런타임에 재검증한다. 보고서는 이 값을 고정 출력하지 않는다.

## Scenario Review Table

개별 표는 Corpus ID, Scenario ID, Detector ID, Mutation Type, Baseline/Variant Parser 및 Detection 상태, Comparison 상태, Reason Codes만 표시한다. 전체 30건을 Corpus ID와 Scenario ID로 정렬한다. Expected Label, Label Basis, raw 사실 및 분석 입력은 포함하지 않는다. 따라서 이 문서는 별도 보안 분석가의 결과 열람용이며 독립 검토용 **Blind Packet을 대체하지 않는다**.

## Comparison State Interpretation

| 원본 상태 | 한국어 표시 | 해석 제한 |
|---|---|---|
| `PRESERVED` | 탐지 유지 | 해당 합성 비교 범위에서 양쪽 탐지 |
| `LOST` | 탐지 소멸 | 공격 회피 성공을 뜻하지 않음 |
| `GAINED` | 새로 탐지 | 새로운 공격의 발견을 단정하지 않음 |
| `UNCHANGED_ABSENT` | 양쪽 미탐지 | 안전을 뜻하지 않음 |
| `INCOMPARABLE` | 비교 불가 | 동일 범위 비교가 성립하지 않음 |
| `UNDETERMINED` | 판정 불확정 | 근거가 부족해 판정 보류 |

## Incomparable and Undetermined Handling

두 상태는 합쳐서 실패로 세지 않는다. 각 scenario에는 Replay가 생성한 기존 closed Reason Code를 그대로 표시한다. 보고 계층은 새 코드 또는 원인 설명을 생성하지 않는다. 실행 실패는 `EXECUTION_FAILED`로 유지하고 `NOT_DETECTED`로 치환하지 않는다. Parser 불완전성은 미탐지가 아니다.

## Security and Privacy

- Raw Log, IP, 계정, timestamp, local path, Evidence 객체, private owner/context, 예외 원문은 보고서에 포함되지 않는다.
- 실제 사용자 파일 경로나 Corpus 경로를 받지 않는다. 네트워크·LLM·API 호출이 없다.
- Report는 기존 replay DTO의 읽기 전용 projection이며 탐지·risk·case·label을 변경하지 않는다.
- 보고서의 Reason Code는 원래 DTO의 closed set으로만 제한된다.

## Determinism

실행 시각, random ID, 절대 경로, 임시 경로, private owner를 출력하지 않는다. 시나리오와 state 행 순서는 고정되며 같은 Corpus/코드의 Markdown bytes가 같아야 한다. 출력 크기 상한을 넘으면 출력하지 않고 고정 오류로 종료한다.

## Test Results

- TDD RED: 구현 전 `counterfactual_analyst_report` 모듈 부재로 기능 계약 수집 실패, 문서 계약은 문서 파일 부재로 실패 확인.
- 신규 report + 문서 계약 focused: **12 passed**; ER-1A/1B/1C/1C-R/ER-0 및 detector accuracy 포함 확장 focused: **137 passed**.
- 시작 기준선 전체 pytest: **3,756 passed, 2 warnings**.
- 기존 report-independent Replay/Comparison 분포는 위 Corpus Summary와 같다.
- 시작 기준선 전체 pytest: **3,756 passed, 2 warnings**. 종료 전체 `uv run pytest -q`: **3,768 passed, 2 warnings** (기존 Starlette/httpx 및 AnyIO deprecation).
- 종료 `uv run python -m app.evaluation`: 성공; synthetic boundary 79/79, risk 70/70, case 70/70, Linux process 합성 평가 21/21. 이 수치는 ER-2A replay가 아니다.
- 신규 CLI 인자 거부 및 stdout Markdown 계약, 두 번 독립 실행한 byte equality: 통과. `uv lock --check`, `uv run python -m compileall -q app tests`, `git diff --check` 통과. 변경 범위는 report 모듈/CLI, 문서/index, 신규 테스트만 포함하며 dependency·lockfile·Production 분석 경로는 변경하지 않았다.

## Human Review Status

`INDEPENDENT_HUMAN_REVIEW_PENDING`; `MANUAL_APPROVAL_REQUIRED`; `ER_1D_IMPLEMENTATION_HOLD`. ER-2A 보고서는 사람 검토를 대신하지 않으며 Blind Packet과 섞지 않는다. 기존 label과 실제 detector 결과의 구분을 유지한다.

## ER-2B Entry Requirements

ER-2B는 별도 승인된 UI 표현 단계로 다룬다. UI 연결 전에는 API/UI 공개 경계, 접근성, 개인정보, rollback 및 사용자 수용 조건을 별도로 승인해야 한다. 이 문서나 CLI를 이유로 UI·운영 연결이 승인된 것은 아니다.

## Limitations

- 30건은 작고 합성된 프로젝트 corpus이며 운영 정확도·공격 회피율을 일반화하지 않는다.
- Parser incompleteness, Detection result, Comparison state는 서로 다른 차원이다.
- 입력 변형과 결과 변화의 유일한 인과 원인을 확정하지 않는다.
- 공격 의도·침해 여부를 판정하지 않으며 자동 대응을 수행하지 않는다.
- 독립 Human Review 미완료; 실제 자료·조직 운영·자동 대응은 `NO_GO`.

## Final Decision

`ER_2A_OFFLINE_EVIDENCE_REPORT_LOCAL_CONDITIONAL_GO`는 합성 Replay 결과의 읽기 전용 Markdown 표현, 분포 검증, 결정성 및 개인정보 경계에 한한다. 운영 탐지 승인이나 ER-1D 설명 엔진 승인으로 해석하지 않는다.
