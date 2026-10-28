# Phase 36.4 — verified source role in the investigation checklist

## Decision

**Status: `CONDITIONAL_GO` for synthetic local use pending a new Ubuntu CI run.** The checklist may receive a source role only when the normalized observations captured in the same analysis pass unanimously identify one allowed role for that case. It never infers role from detection, relation, risk, alias, identifier value, raw event text, citation, UI, or `case_ref`. Missing, unsupported, mixed, or mismatched data yields `unknown`.

The checklist remains an analyst aid. Detection, relation, risk, case, checkpoint, publication, SSE, and guidance are not recomputed or modified. Real user material, organizational operation, automatic response, and model-based AI remain `NO_GO` or `NOT_TESTED` as applicable. Vector/VM remains `USER_ACTION_REQUIRED / ISOLATION_BLOCKED` and is unrelated to this work. Safari remains `NOT_TESTED / USER_HOME_ISOLATION_BLOCKED`; no Safari profile, VoiceOver, keyboard setting, or zoom check was retried.

## Start Gate

- Start SHA, local `main`, and `origin/main`: `a25b7c93d950c99b60db1fb402aa7ddeb993e30b`; clean tree and ahead/behind `0/0`.
- Exact push run [40620451274](https://github.com/misosos/ai-security-log-analyzer/actions/runs/40620451274): `completed/success`, exact head SHA. All pytest (`3063 passed`, 2 existing warnings), TCP Syslog smoke/reliability/management, JSONL Linux acceptance, restricted report, Chromium/axe, and tracked-file checks passed. The JSONL marker was `COLLECTOR_JSONL_LINUX_ACCEPTANCE_PASS roles=2 runs=80 synthetic=1 leaks=0`; Chromium/axe covered 23 states with `external_requests=0`.
- CI artifacts: 0. The v0.4.0 tag and Release target remain `eecd6ee1cda0545e34b01c42e1a2163a899bcc27`.
- TDD first added source snapshot, fallback, case-isolation, DTO enum, and API schema tests. Before implementation the focused run had 7 failures: the new snapshot module was absent (six import cases) and the sample endpoint still returned `investigation-checklist/v1` without a role. The failure evidence was test-only and contained synthetic values.

## Source Role Provenance

`app.main.analyze_with_source_role_snapshot` loads normalized events once, runs the same deterministic analysis function once, and captures only a bounded closed role set from each parsed `NormalizedEvent.source`. There is no second file read or parser run for the checklist. Mapping is exact:

| Normalized event `source` | Checklist role |
|---|---|
| `application` | `application` |
| `ssh` | `ssh` |
| `access_log` | `access` |
| missing, unsupported, or invalid source metadata | `unknown` |

The role candidate comes only from that source field. To associate source observations with an internal case, the snapshot uses the case's existing canonical subject membership as a private join key; the IP value is not converted into a role, copied into the checklist DTO, logged, or returned. Every source observation associated with that subject must have the same recognized role. Repeated same-role observations are allowed; any mixed, unsupported, absent, or invalid role makes the whole case role `unknown`. A role from another subject is kept separate. This conservative membership rule can return `unknown` when unrelated sources share a case subject.

`AnalysisSourceRoleSnapshot` stores an immutable mapping of canonical internal subject membership to frozen role sets and redacts `repr`. It is bound to the exact analysis object. `bind_projection` then binds each result to the exact frozen projection and case object. The trusted API adapter accepts the role only if analysis, projection, and case object identities all match. A stale analysis, replaced case/projection, identity mismatch, or adapter failure falls back to `unknown`; unknown or forged public case references continue to receive the existing fixed not-found response. The registry stores only the final closed DTO fields and an opaque request-scoped case reference.

## Snapshot Consistency

Case lookup, role validation, and DTO field construction use the same analysis result and projection object. The local-upload worker captures role metadata in the same worker process that parsed the staged synthetic/user-selected inputs; it returns only the safe bounded checklist fields beside the already-projected response. Sample and local calls with legacy injected analyzers that do not supply a source snapshot remain `unknown`.

Simultaneous cases bind independently, preventing cross-case role mixing. Source role is not a sort, deduplication, case merge, or correlation key. A stale registry reference still fails before checklist work; checklist requests do not update registry case data. No checkpoint, queue, publication, or SSE cursor is consulted or written.

## API and UI Contract

The request remains the closed `{schema_version, case_ref}` object; the client cannot send role or metadata. The response added two closed fields and therefore explicitly moved from `investigation-checklist/v1` to `investigation-checklist/v2`:

- `source_role`: `application`, `ssh`, `access`, or `unknown`.
- `source_role_label`: one fixed Korean label: `애플리케이션 로그`, `SSH 인증 로그`, `접근 로그`, or `역할 정보 미확인`.

The output has no observation ID, filename, path, checkpoint, timestamp, original identifier, or free-form source metadata. The UI shows a role label only for a validated known role. For `unknown`, it retains a fixed explanation that role was not guessed and that this does not mean low risk or no review is needed. The existing explicit button remains the only checklist request trigger. Existing priority wording, non-safety refusal explanation, citation-not-case-evidence explanation, text-node rendering, and no-prefetch behavior remain.

`review_priority` follows the Phase 36.1 rule without modification. Previously missing role metadata forced `undetermined`; a verified role can now let the existing rule evaluate the already-present category/code/completeness and return its existing review suggestion. A role alone cannot produce `review_now` or create a detection, and the existing risk score/band does not change. The response schema bump is documented in OpenAPI, frontend response validation, and contract tests. No GET route, API request field, public case projection field, SSE event, guidance input, report field, or HTML field was added.

## Privacy

Synthetic canaries cover account, IPv4, IPv6, hostname, input filename, absolute path, raw line, rationale, credential-like text, internal exception text, and another case's role. Only the closed role enum and its fixed Korean label may be public. Subject identity is used only inside the role snapshot's membership association and is never serialized. Snapshot and bound-role `repr` values are redacted. Unsupported parser source labels become `unknown`; arbitrary metadata is not reflected.

## Analysis Invariance

The wrapper calls the same `_analyze_normalized_logs` implementation as the existing analysis path, once, and returns the original analysis object unchanged plus private role metadata. Checklist construction remains downstream and read-only. The same analysis can be compared byte/canonically before and after checklist requests for detections, relations, risk, case, public projection, checkpoint, publication, SSE replay cursor, and Phase 33.4 guidance state. Existing API/UI/report/guidance projections receive no source-role metadata. Role presence only enters the existing SafeInvestigationDTO input and public checklist response.

## Verification

The focused Phase 36.4/API/UI/36.1/36.2 tests passed (`111 passed`, 2 existing Starlette/httpx deprecation warnings); the Phase 36.4 unit set was subsequently expanded for parallel binding and analysis parity. The final full suite passed (`3083 passed`, the same 2 existing warnings). The 44 Phase 36.1 fixtures reported schema/refusal/citation 100%, privacy leaks 0, analysis mutation 0. The 24 Phase 36.2 fixtures reported status match 24/24, required citation completeness and semantic-support precision/completeness 100%, forbidden/invalid citations 0, unsupported claims 0, and benign false refusals 0. Existing synthetic evaluation passed 79/79; Linux evaluation passed 21/21; risk and case evaluations each passed 70/70.

The same verified-role response was repeated three times across UTC/Asia-Seoul and remained byte-identical; its canonical SHA-256 was `243b7e53e4c209952cf52ca4947b3b3068405eb7bf2bb9b39881df2087b6abb5`. The `unknown` fallback is repeated in focused unit coverage. Parallel binding of different synthetic cases kept their roles isolated. The response was 2,384 bytes for a 60-byte request.

`uv run python -m tests.benchmark_investigation_checklist_verified_role_36_4` used 10 warm-ups and 100 samples. It temporarily raised only the in-process synthetic benchmark rate caps to exercise the endpoint repeatedly. Measurements (ms, median / p95 / max): case lookup **0.0015 / 0.0018 / 0.0027**; 64-event source-role snapshot capture **0.3440 / 0.7463 / 1.0022**; snapshot identity check **0.0003 / 0.0005 / 0.0005**; role validation and safe adapter **0.0073 / 0.0077 / 0.5958**; lexical retrieval and verified citations **12.5655 / 13.8586 / 16.4105**; safe DTO validation **12.5521 / 14.5764 / 17.7649**; checklist generation **50.6850 / 56.4480 / 60.5362**; response validation **0.0593 / 0.1095 / 0.5660**; endpoint total **76.3887 / 89.2402 / 101.0936**. These are small synthetic development measurements, not an operational SLA, capacity limit, or worst-case guarantee.

Chromium/axe passed 23 states with zero axe violations and `external_requests=0`. `npm ci --ignore-scripts`, `uv sync --locked --dev`, and `uv lock --check` passed. Safari was not rerun; its status remains `NOT_TESTED / USER_HOME_ISOLATION_BLOCKED`.

## Limitations

- The source association uses the case's internal subject membership because the current deterministic case projection groups observations on that subject. It is conservative across all parsed events for that subject; it does not prove every event contributed to the detection.
- `access` is retained as a safe source role, but the existing lexical retrieval corpus does not gain new access-specific evidence or checklist claims.
- A same-analysis object identity is an in-process consistency guard, not a durable snapshot identifier or cross-request identity.
- Phase 36.3A's 10/10 comprehension result covered the earlier UI, not these new role labels. No new human role-label comprehension review was performed.
- New SHA Ubuntu CI is pending. Safari remains `NOT_TESTED / USER_HOME_ISOLATION_BLOCKED`; model/provider use remains `NOT_TESTED`; Vector/VM remains `USER_ACTION_REQUIRED / ISOLATION_BLOCKED`.
- Actual user data, organizational operation, remote collection, and automatic response remain `NO_GO`.

## Phase 36.4A Follow-up — Analysis Invariance Wording

During the 36.4A user review, item 7 initially received `FAIL` because the available checklist screen did not explicitly say that the checklist leaves detection, relation, risk, and case results unchanged. The UI now includes that fixed explanation, and the browser contract fails with `CHECKLIST_ANALYSIS_INVARIANCE_EXPLANATION_MISSING` if it is absent. The contract failed before the UI wording was added and passed afterward.

The updated screen was not shown to the user again: user retest is `NOT_TESTED`. The old UI's full comprehension review is not complete; it will be repeated against the redesigned screen in Phase 36.5B after Phase 36.5A. This follow-up does not establish Phase 36.4A acceptance or production GO. Safari remains `NOT_TESTED / USER_HOME_ISOLATION_BLOCKED`; actual user data, organizational operation, and automatic response remain `NO_GO`; model-based AI remains `NOT_TESTED`.
