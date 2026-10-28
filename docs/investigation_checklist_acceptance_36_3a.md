# Phase 36.3A — investigation checklist API/UI acceptance

**Result:** User comprehension is **10/10 final PASS** for the synthetic checklist UI shown in Safari 18.6. The API/UI remains **CONDITIONAL_GO**: this is local synthetic evidence, and no new Ubuntu CI run was performed for this acceptance commit. Real user logs, organization operation, automatic response, and model-based explanation remain **NO_GO / NOT_TESTED** as applicable.

Later Phase 36.4 adds verified source-role labels through response schema v2. This 36.3A user review did not test that addition and is not being counted as role-label acceptance; see [Phase 36.4 record](investigation_checklist_verified_role_36_4.md).

## Start gate and remote evidence

- Start SHA and local/origin `main`: `44cdfb439513c412a3c9a30dc11657a463451978`; branch `main`, clean tree, ahead/behind `0/0` before this acceptance work.
- Push run [40518020614](https://github.com/misosos/ai-security-log-analyzer/actions/runs/40518020614): exact head SHA, `push`, `completed/success`.
- Locked Ubuntu installation and full pytest passed: **3,059 passed**, two existing warnings.
- TCP Syslog smoke, reliability and management; JSONL Linux acceptance; restricted-report Linux smoke; Chromium/axe; and tracked-file immutability passed. Fixed completion markers were present for the TCP and JSONL smoke/reliability/management stages.
- Chromium/axe covered **23 states**, with zero axe violations and `external_requests=0`. CI artifacts: **0**.
- v0.4.0 tag and Release target remain `eecd6ee1cda0545e34b01c42e1a2163a899bcc27`.

## Synthetic product-path checks

The actual app was served on IPv4 loopback with a task-private temporary `HOME` and `XDG_CONFIG_HOME`; only its synthetic sample and checklist routes were requested. No monitor, default configuration, checkpoint, user log, or report input was used. Vector, models, providers, embedding, and external services were not called.

In the isolated Safari run, loading the sample and opening its case produced **0** checklist requests. One explicit button activation produced **1** `POST /api/v1/investigations/checklist`. The browser compared the case-analysis DOM before and after the request with the checklist section removed; it was unchanged. The response showed `review_priority=undetermined`, the fixed explanation for unknown source role, category-only output, limitations, and approved general-knowledge citations. The citation text states that it is not direct evidence of this case.

The refusal display used a test-only fixed unsupported-category adapter through the real app route and real UI renderer. It showed the existing fixed refusal: checklist evidence is insufficient, refusal is not a safety/non-risk finding, check deterministic results and approved internal evidence, and do not speculate. No production code or data was changed to create this test result.

One intermediate Safari server restart did not explicitly set a private `HOME`. It was stopped as soon as noticed. Only the synthetic sample/checklist UI routes had been requested; no monitor/config/checkpoint/user-file route was called. To preserve the review gate, the affected item 7–10 captures and answers were excluded and repeated with the task-private `HOME`. No user data was accessed. The final item 7–10 answers below refer only to the isolated recaptures.

## User comprehension

Each item was presented individually using actual Safari UI captures from the product route, with synthetic content. Answers below are user responses; automated tests were not substituted for them.

| Item | Topic | Initial response | Fix / recheck | Final response |
|---|---|---|---|---|
| 1/10 | Function purpose | PASS | — | PASS |
| 2/10 | Risk vs review priority | PASS | — | PASS |
| 3/10 | Checklist vs automatic response | PASS | — | PASS |
| 4/10 | Citation vs case evidence | PASS | — | PASS |
| 5/10 | Uncertainty and limitations | PASS | — | PASS |
| 6/10 | Refusal and next steps | PASS | — | PASS |
| 7/10 | Unknown role / undetermined priority | **FAIL** | Regression assertion failed before the UI change. Added fixed explanation; first rescore sequence on a capture without explicit temporary HOME was `FAIL`, then `PASS`, and was excluded. The same changed UI was then recaptured under temporary HOME and rescored. | **PASS** |
| 8/10 | No original identifiers in assistance | PASS | — | PASS |
| 9/10 | Existing analysis unchanged | PASS | — | PASS |
| 10/10 | Synthetic-only support status | PASS | — | PASS |

The initial item 7 FAIL is retained. The final isolated recapture explicitly says the public case projection has no log role, the role was not guessed, `undetermined` does not mean low risk or no review is needed, and the existing analysis should be checked. No risk, detection, relation, case, or API semantics changed.

## UI change and regression

Before the copy change, the existing Playwright/Chromium contract was extended to require the unknown-role explanation on the real API state. `npm run test:a11y` failed with the fixed category `CHECKLIST_UNDETERMINED_EXPLANATION_MISSING`. The minimum UI copy was then added next to the rendered `undetermined` priority in `frontend/app.js`. It is inserted as a text node, only for that priority; no source role is inferred and no output schema changed.

The updated browser contract passed in the full 23-state run. It also checked no checklist request before activation, the explicit request count, analysis text unchanged, keyboard-focusable button, fixed error/refusal rendering, 320 CSS px and 200% text scaling without horizontal overflow, zero axe violations, and zero external requests. This automated Chromium result is distinct from Safari and from user comprehension.

## Privacy, invariance, and failure handling

The inherited API/UI privacy tests place synthetic account, IPv4/IPv6, hostname, filename/path, raw-line, credential-shaped, exception, and HTML-shaped canaries in internal/test fault states. They verify closed request/response and OpenAPI bodies, fixed validation errors, safe logs/status, and public API/SSE/UI/report/guidance boundaries. Phase 36.3 tests also cover stale/not-found, duplicate/invalid JSON, corpus/citation and serialization failure, timeout/cancellation, rate/concurrency limits, recovery, and that the analyzer is not rerun. No canary appeared in acceptance captures, status, request/response summaries, or CI-facing output.

The complete browser and API regression preserves detection, relation, risk, case, checkpoint, publication, SSE cursor/replay, guidance, report, TCP/JSONL runtime, schema 2/3, and `subject_alias` contracts. The isolated Safari API check confirmed the rendered analysis text did not change around the checklist request. The broader state invariance claims are backed by automated regression, not by a user screenshot.

## Safari and accessibility status

Safari 18.6 was used to view the actual synthetic available and refused UI states and obtain the captures reviewed by the user. Safari was launched against a task-private temporary app `HOME`; checklist request counts were 0 before the click and 1 after, with unchanged analysis DOM. This is not a complete manual accessibility audit.

- Chromium/axe: 23 states, zero violations, zero external requests. This is not a WCAG 2.2 AA conformance claim.
- Safari screen review: available, refused, undetermined, privacy, analysis-boundary, and synthetic-support messages were shown.
- Safari keyboard-only end-to-end, native 200% browser zoom, stale/timeout/rate-limit recovery, Web Inspector review, and VoiceOver: **NOT_TESTED**.
- VoiceOver reading order/announcements: **NOT_TESTED**.

## Verification

- TDD UI regression before copy change: failed with `CHECKLIST_UNDETERMINED_EXPLANATION_MISSING`; the updated real API browser state passed.
- Phase 36.1/36.2/API focused pytest: **89 passed**, two existing deprecation warnings. Acceptance documentation contract: **2 passed**.
- Full pytest before the record existed: **3,059 passed, 2 failed**; both failures were the new documentation contract's expected missing-file/missing-link assertions. No production or pre-existing test failed in that run. Final full pytest after the record: **3,061 passed**, two existing warnings.
- Phase 36.1 evaluator: **44 fixtures**, schema/refusal/citation 100%, privacy leaks 0, analysis mutation 0. Phase 36.2 evaluator: **24/24**, required citation completeness and semantic-support precision/completeness 100%, invalid/forbidden citations and unsupported claims 0, benign false refusal 0.
- Existing deterministic evaluations: synthetic boundary **79/79**, Linux process **21/21**, risk **70/70**, case **70/70**. Focused Phase 36.1/36.2/API/UI/docs/33.1 tests under both `TZ=UTC` and `TZ=Asia/Seoul`: **129 passed** each, with the same two existing warnings.
- `npm ci --ignore-scripts --no-audit --no-fund` and `npm run test:a11y`: **23 states**, zero axe violations, `external_requests=0`; the live `checklist_real` state passed with the added explanatory copy. Chromium checked no request before the explicit button, unchanged analysis text, fixed error/refusal output, keyboard-focusable control, 320 CSS px and 200% text scaling without horizontal overflow.
- `uv sync --locked --dev`, `uv lock --check`, Python compile, Node syntax, and `git diff --check` passed. Dependency and lockfiles are unchanged. Final privacy scan is recorded in the completion summary.

## Acceptance-environment measurement

The test-only endpoint benchmark used **10 warm-ups and 100 samples** with synthetic data. Observed median / p95 / max (ms): corpus load **10.657 / 29.771 / 79.854**; lexical retrieval plus DTO **44.584 / 86.316 / 425.913**; checklist generation **83.920 / 163.765 / 258.973**; output validation **41.182 / 86.997 / 304.247**; endpoint total **140.995 / 239.534 / 276.846**. Input was 63 bytes, request 60 bytes, internal result 991 bytes, HTTP response 2,328 bytes, and corpus 14,833 bytes. Canonical response SHA-256: `2b26d6fba6d3ff4e73a0b9e48d87e60bfc726ed5150d146010bbf2f299a46e21`. Safari DOM update latency sampling was not collected: **NOT_TESTED**. These are small local synthetic measurements, not an operational SLA or worst-case latency guarantee.

Small synthetic development measurements are not operational SLAs. Full Safari accessibility, VoiceOver, other analysts, real organizational data, and production workloads remain unverified. 실제 사용자 로그와 organization operation remain **NO_GO**; automatic response remains **NO_GO**; model-based AI remains **NOT_TESTED**. Vector/VM stays `USER_ACTION_REQUIRED / ISOLATION_BLOCKED`.
