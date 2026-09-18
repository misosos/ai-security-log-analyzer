---
name: security-testing
description: Validate changes to parsing, detection, correlation, risk, evidence, and analysis contracts through unit, pipeline, scenario, and full-regression testing. Use when security-analysis behavior or its consumers change.
---

# Security Testing

Use this workflow when changing parsing, normalization, Detection, Correlation, Risk Assessment, Evidence, or a contract consumed by the analysis pipeline, reports, API, UI, LLM adapter, or tests.

## 1. Establish the Baseline

Before changing code, run:

```bash
uv run pytest
```

Record or inspect:

- the total pass and fail result;
- which tests and testing layers fail;
- existing working-tree changes;
- whether each failure already existed;
- whether a failure indicates an implementation bug or an incomplete contract migration.

Do not hide a failing baseline. Determine whether it is related to the requested work.

## 2. Identify the Changed Contract

Classify the changed output or behavior:

- parser output;
- normalized event;
- detection result;
- evidence;
- correlation;
- risk factors;
- top-level analysis result;
- report, API, UI, or LLM representation.

Find the producer and trace applicable consumers:

```text
producer
→ pipeline
→ risk
→ report
→ API / UI
→ LLM input
→ tests / fixtures
```

## 3. Unit Test

Use unit tests to verify the rule implemented by one function or tightly bounded component. Cover as applicable:

- positive and negative cases;
- threshold and time-window boundaries;
- time ordering;
- user, IP, and source isolation;
- malformed or missing data;
- evidence and rationale;
- uncertainty semantics.

Unit tests must protect the security meaning, not merely mirror implementation details.

## 4. Pipeline Test

Use pipeline tests to verify connections and contracts between layers. Check:

- parsing and normalization;
- detector and correlator invocation;
- per-IP grouping;
- separation of global correlation;
- transfer into risk context;
- the result shape exposed to consumers.

`results` must remain per-IP analysis. `global_correlation` must remain whole-log analysis that cannot be attributed to one IP. Do not place a special global key in `results`, and do not automatically convert global correlation into an individual IP's risk.

## 5. Scenario Test

Use sample logs to verify end-to-end security meaning. Include as applicable:

- normal activity;
- representative detections;
- boundary conditions;
- cross-source flows;
- multi-IP or global flows;
- cases close to false positives;
- final results that do not overstate attack success or causation.

## 6. Full Regression Test

Before completion, run:

```bash
uv run pytest
```

- Do not stop after only a related test file passes.
- Compare the final result with the baseline.
- Report the cause and impact of any new failure.
- Report tests that could not run and explain why.

## 7. Intentional Contract Migration

When a contract intentionally changes:

1. Confirm that the new architecture is intentional.
2. Define the canonical producer contract.
3. Find every consumer.
4. Update the implementation.
5. Update unit, pipeline, and scenario tests.
6. Run the full regression suite.
7. Search for remaining uses of the old contract.

Do not:

- revert a correct new architecture only to satisfy an old test;
- change only the producer and leave consumers behind;
- update tests to a new shape while leaving real consumers behind;
- support old and new contracts simultaneously without a concrete need and removal condition;
- accidentally change existing security semantics during migration.

## 8. Prohibited Test Fixes

Do not make tests pass by:

- weakening assertions;
- deleting meaningful negative or boundary tests;
- deleting functionality;
- adding unconditional skips or xfails;
- swallowing exceptions and treating the operation as successful;
- using meaningless mocks to bypass the actual integration path;
- testing only implementation details instead of observable behavior;
- changing a detection into proof of compromise or a correlation into proof of causation.

## 9. Completion Criteria

Confirm that:

- the relevant tests at each applicable layer pass;
- the full regression result is known;
- producer and consumer contracts agree;
- evidence and rationale are preserved;
- per-IP and global scopes are preserved;
- risk and confidence retain distinct meanings;
- new failures are distinguished from baseline failures;
- remaining limitations are reported.
