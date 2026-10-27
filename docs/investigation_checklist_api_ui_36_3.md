# Phase 36.3 — read-only investigation checklist API and explicit UI

**Current result:** `CONDITIONAL_GO` for the synthetic/read-only API and explicit case-detail interaction. Phase 36.3A user comprehension is **10/10 final PASS** for the actual captured Safari UI, including the added explanation for unknown source role and `undetermined` priority. The acceptance is recorded in [Phase 36.3A](investigation_checklist_acceptance_36_3a.md). A new Ubuntu CI run for this acceptance change and a full Safari accessibility/VoiceOver review have not run. This is not approval for real organizational logs or operations.

## Scope and gate

The start commit was `fb265eb745c121d0c4da5c13e114b8f476e527c9`. Push run [40497883911](https://github.com/misosos/ai-security-log-analyzer/actions/runs/40497883911) was `push / completed / success` for that exact SHA. Locked Python setup, all 3,040 pytest tests, existing TCP Syslog smoke/reliability/management, JSONL Linux acceptance, restricted-report smoke, Chromium/axe, and tracked-file checks passed. It emitted no artifacts. The v0.4.0 release and peeled tag still point to `eecd6ee1cda0545e34b01c42e1a2163a899bcc27`.

The Phase 36.2A user comprehension result remains **8/8 final PASS** for captured synthetic internal checklist wording only; item 6's initial refusal-output FAIL and its corrected recheck remain recorded. This Phase 36.3 integration is new and was not part of that user comprehension result.

## Endpoint contract

The default local app exposes only `POST /api/v1/investigations/checklist`; there is no checklist GET route. The request body is exactly `{"schema_version":1,"case_ref":"c_<24 lowercase hex>"}`. It accepts no category, analysis fields, free question, prompt, source text, or original log. Request bytes are capped at 512. Strict UTF-8 JSON parsing rejects duplicate keys, non-finite numbers, bool-as-int, missing or extra keys, invalid opaque references, and malformed Unicode. OpenAPI declares the exact closed request object and the closed `investigation-checklist/v1` response.

The sample and local analysis responses attach random case references for at most 128 cases. A new analysis replaces the current in-memory registry; entries expire after 15 minutes. References are opaque request-scoped handles and are not stable tracking or correlation keys. Older, unknown, and over-cap references return the same fixed `NOT_FOUND` response. The registry stores only category-level SafeInvestigationDTO input fields; it does not retain raw logs, subject aliases, account/IP/hostname, path, exact time, checkpoint, or report material.

A dedicated server adapter reads the trusted internal case projection and copies only allowlisted detection/relation codes, bounded count buckets, risk band for DTO compatibility, fixed limitation codes, and fixed corpus digest. It ignores `subject_ip`, account fields, timestamps, evidence text, display rationale, `subject_alias`, and user-supplied fields. The analysis path does not run again for checklist requests.

The current deterministic case projection does not preserve application/SSH source attribution. The adapter therefore sets `source_role=unknown`; it does not infer a role from a detection. This is the explicit unknown source role boundary. A directly supported observation category can still receive its fixed category checklist and lexical citations. The deterministic review priority remains `undetermined` whenever source role is unknown; it is separate from, and cannot change, the existing risk band. Unsupported or unknown observation categories still produce a fixed refusal. This narrow category-only behavior is covered by a regression test; it does not claim source attribution.

## Response and user meaning

The response has only `schema`, `status`, `review_priority`, `priority_meaning`, `category`, `steps`, `explanation`, `uncertainty_codes`, `limitation_codes`, `citations`, `citation_meaning`, and `generated_by`. `generated_by` is always `deterministic_lexical_template`. It contains no HTML or Markdown. Output is capped at 8 KiB, with at most five steps, eight citations, four uncertainty codes, and sixteen limitation codes.

The response keeps these meanings explicit:

- `priority_meaning=analyst_review_order_only_not_security_risk`: review ordering is a separate analyst aid and is not the existing security risk.
- `citation_meaning=general_reference_not_case_evidence`: citation titles and fixed summaries describe approved general investigation knowledge, not evidence that an attack occurred in this case.
- Refusal text states that the accepted corpus cannot support a checklist, this is not a safe/non-risk finding, the existing deterministic result should be checked, original evidence belongs in an approved internal path, and no guess should be made before supporting evidence is reviewed.

Corpus digest, lexical retrieval, approved section/category, and the citation verifier are checked for each explicit request. Digest, retrieval, or response validation faults fail closed. No partial checklist is returned.

## Limits and lifecycle

The endpoint caps the request at 512 bytes, response at 8 KiB, active work at two requests, global rate at 30 calls/minute, and each current case at five calls/minute. Checklist processing has a three-second response timeout. Fixed error codes cover invalid request, not found, rate limit, busy, timeout, and unavailable. Inputs, internal exception strings, and private case fields are not logged or copied into errors. A timed-out or disconnected client's bounded worker remains counted until it finishes; it cannot mutate analysis, and a later request succeeds after capacity is released. There is no automatic retry.

The endpoint only reads the already registered safe DTO projection and approved corpus. Analysis unchanged: it does not invoke detection, relation, risk, case assembly, checkpoint, publication, SSE replay, TCP/JSONL runtime, HTML reporting, or Phase 33.4 guidance. Regression tests verify that analysis is not called again, deterministic outputs are unchanged, and subsequent requests recover after injected corpus, serialization, timeout, and cancellation faults.

## UI behavior

Each eligible case detail has an explicit **조사 점검표 보기** button. The API request occurs only after that explicit click. Rendering a case, selecting it, hovering, navigating, or loading the page does not call the endpoint. A click sends exactly the schema version and opaque checklist reference with `POST`; cookies are omitted. The UI has keyboard-focusable control, `aria-live` progress/result messaging, disabled loading state, retry through the same button, and fixed stale, refusal, timeout, rate-limit, and unavailable wording.

The detail separates existing risk from the review priority, and shows category, checklist steps, explanation, uncertainty/limitations, and citation summaries. When priority is `undetermined`, the UI now explicitly says the public case projection has no log role, no role was guessed, this does not mean low risk or no review is needed, and existing analysis should be checked. It says citations are general reference material rather than case evidence. Refusal is explicitly not a safety finding. Dynamic content is inserted with DOM nodes and `textContent`; no `innerHTML`, external link, external request, or automatic download was added. The existing schema 2/3 live UI and `subject_alias` presentation remain unchanged. Cases beyond the bounded current registry show no checklist button.

Chromium/axe covered 23 states, including initial/no-call, loading, available, refused, stale, timeout, rate-limited, unavailable, retry success, and a live local API request. Axe reported zero violations and `external_requests=0` (external requests: zero). Narrow viewport and 200% text scaling checks passed. This is an automated accessibility check, not a WCAG 2.2 AA certification. Safari 18.6 was used for actual synthetic available/refused UI captures and 10-item comprehension review. Safari keyboard-only completion, native 200% zoom, stale/timeout/rate-limit recovery, Web Inspector review, and VoiceOver remain `NOT_TESTED`.

## Determinism and development measurement

Repeated requests for one fixed synthetic case returned byte-identical response content; canonical response digest: `2b26d6fba6d3ff4e73a0b9e48d87e60bfc726ed5150d146010bbf2f299a46e21`. The endpoint response omits request ID, case reference, and timestamps. UTC/Asia-Seoul checks remain byte-identical through the inherited Phase 36.2 output contract.

`tests/benchmark_investigation_checklist_api_ui_36_3.py` used 10 warm-ups and 100 samples on this development machine. The isolated final run measured milliseconds (median / p95 / max): corpus load **6.768 / 8.964 / 10.562**; lexical DTO preparation **25.546 / 29.721 / 35.482**; checklist generation **49.653 / 56.791 / 60.572**; output validation **24.913 / 28.798 / 32.163**; endpoint total **92.933 / 100.836 / 140.503**. Input was 60 bytes, response 2,328 bytes, internal checklist JSON 991 bytes, and approved corpus 14,833 bytes. The same fixed response canonical SHA-256 was `2b26d6fba6d3ff4e73a0b9e48d87e60bfc726ed5150d146010bbf2f299a46e21`. This small synthetic development measurement is not an operational SLA or load guarantee.

## Verification and remaining gates

Initial TDD checks failed because the API module and route did not exist. The first integration pass also caught two contract issues before completion: the old sample-response equality test did not account for intentionally random request-scoped refs, and OpenAPI did not infer a body from the raw `Request`; the test was migrated to assert stable content plus distinct refs, and the exact closed OpenAPI body was added. Unknown source-role behavior was then pinned by a failing test before the checklist boundary was adjusted to permit only category-supported templates while keeping priority `undetermined`.

The Phase 36.2 refusal phrase was aligned to the user-reviewed wording: “안전 또는 비위험 판정이 아닙니다.” No dependency, `uv.lock`, or `package-lock.json` change was made. The API/UI use no LLM, Gemini, embedding, vector database, or external API.

Regression history: the first full-suite run after adding the route exposed stale exact-route/OpenAPI assertions and one public-response equality assertion that treated request-scoped random refs as analysis data. Those tests were migrated to include the explicitly requested POST and to compare the analysis fields separately while checking that refs rotate. A later full-suite run had one transient Hypothesis 200 ms deadline overrun in the existing arbitrary-output-byte test (267.91 ms on the first sample, 26.43 ms on the repeat); the test passed standalone and the subsequent complete suite passed without changing its assertion or deadline.

Current limits:

- Phase 36.3 API/UI is `CONDITIONAL_GO` pending a fresh SHA's Ubuntu/Linux CI and the remaining Safari accessibility checks, including VoiceOver.
- Phase 36.3A captured UI comprehension: **10/10 final PASS**; item 7's initial FAIL is retained and the fixed UI explanation was rechecked. See the acceptance record for the intermediate responses and the isolated `HOME` recapture.
- Original Phase 36.3 implementation full regression: **3,059 passed**, existing warning count **2**. The Phase 36.3A acceptance revision full regression: **3,061 passed**, the same two existing warnings. The preceding transient Hypothesis deadline event and route-contract migrations are recorded above.
- Phase 36.1 evaluation: **44 fixtures**, schema/refusal/citation 100%, privacy leaks 0, analysis mutation 0. Phase 36.2 evaluation: **24/24**, required citation completeness and semantic-support precision/completeness 100%, invalid/forbidden citations 0, unsupported claim 0, benign false refusal 0.
- Existing evaluations: synthetic **79/79**, Linux **21/21**, risk/case **70/70**; UTC and Asia/Seoul evaluation JSON was byte-identical.
- Chromium/axe: **23 states**, zero axe violations and `external_requests=0`. Safari 18.6 captured actual synthetic available/refused screens and user comprehension reached 10/10; keyboard-only completion, native zoom, several Safari error states, Web Inspector, and VoiceOver remain `NOT_TESTED`. Neither automated axe nor this limited Safari review establishes WCAG 2.2 AA conformance.
- `npm ci --ignore-scripts`, `uv sync --locked --dev`, `uv lock --check`, Python/Node syntax, `git diff --check`, and changed-file privacy/dependency scans passed. Dependency and lockfiles are unchanged.
- Real user logs, actual organization logs, and organizational operation remain `NO_GO`.
- Automatic account/IP/file/process response remains `NO_GO`.
- Automatic response remains `NO_GO`.
- Model-based explanation remains `NOT_TESTED`; this integration is deterministic and lexical only.
- Vector/VM remains `USER_ACTION_REQUIRED / ISOLATION_BLOCKED`; this phase did not alter or validate it.
- The source-role provenance gap remains; unknown role is kept unknown and review priority remains undetermined.
- Long-duration operational load and use by other analysts are `NOT_TESTED`.
