# Phase 36.0 — AI-assisted security investigation triage design

**Status: design plus Phase 36.1 internal deterministic reference; no model call or public integration.** The Phase 36.1 module is synthetic/test-only and does not alter authoritative results. No LLM, Gemini, embedding, Ollama, external API, model/runtime download, or installation was used. See [Phase 36.1 implementation record](deterministic_investigation_triage_36_1.md).

No automatic action is permitted: there is no tool, command, or system-side action path in this design.

## Decision

Phase 36.1 implemented an **LLM-free deterministic case review-priority reference**, its closed DTO/output validator, and fixed citation-verified checklist text. This is internal/test-only with no user-facing integration. Any later suggestion must remain separate from the existing risk band/score, detection, relation, case state, publication, SSE revision, or checkpoint.

Phase 36.1 adds a fixed review-priority reference. Phase 36.2 adds category-scoped fixed checklist and explanation templates only when a directly relevant Phase 33.1 citation is verified. Unsupported categories return a fixed refusal. Both are internal synthetic-tested outputs, not user-facing integrations. Similar-case grouping and response recommendations are deferred. Automated response is prohibited. This decision does not approve an LLM, model provider, production data, or organizational use. See the [Phase 36.2 semantic checklist record](lexical_investigation_checklist_36_2.md).

The deterministic pipeline remains authoritative. AI assistance, if a later gate approves it, can only be a labeled analyst aid. A missing, refused, invalid, timed-out, or failed assistance result leaves existing analysis unchanged and usable.

## Goals and Non-goals

Goals: help an analyst choose a case to review, show why the suggestion was made, communicate uncertainty, and later suggest evidence-based non-executable checks. The analyst decides whether to use any suggestion.

Non-goals: create or suppress detections; change relation, risk, or case state; assert compromise, cause, or impact without observed evidence; close, block, isolate, lock, delete, or otherwise act on a case or system; execute commands or tools; ingest raw logs; infer source identity; contact a provider automatically; add a public API/SSE/UI integration in this phase; or make any claim of SOC efficacy.

## Current Evidence

- Phase 33.1 provides deterministic lexical retrieval over a digest-pinned approved corpus and a citation verifier. It returns evidence candidates, not an answer or detection. Structure, identity, and digest validation do not prove semantic support.
- Its fixed evaluation retains one known over-citation: the failure-then-success query also retrieved a relation-lifecycle section that was not the expected evidence for that fixture. This remains a regression case; no result is reclassified to hide it.
- Phase 33.4 connects bounded lexical guidance on explicit request and does not feed analysis results. It has fixed request/response bounds and citation verification.
- The existing Gemini helper is not the production default. Its historical audit found that helper input can include IP identifiers and that output is free text without a closed citation validator. This design does not activate, reuse, or claim to repair that helper.
- Embedding production integration remains `NO_GO`; local LLM execution remains blocked. No candidate model/runtime is tested here.
- Phase 35.4B is **paused, not cancelled**, with `USER_ACTION_REQUIRED` due to Ubuntu VM malfunction and `ISOLATION_BLOCKED`/resource evidence outstanding. **Vector was not run.** Phase 36 is independent and supplies no substitute evidence for Vector, the VM, or collection safety. No VM, snapshot, or artifact state is changed. Prior transient runtime failures remain `UNEXPLAINED_NON_REPRODUCED` where their records say so.

## Architecture

```text
deterministic case result (unchanged)
    ├── existing authoritative analysis/publication
    └── explicit analyst request (future gate)
          → allowlisted SafeInvestigationDTO
          → approved lexical retrieval and citation verification
          → optional assistance producer
          → strict whole-response validator
          → separate, clearly labeled analyst suggestion
```

The Phase 36.1 reference uses deterministic rules, not a model. Before any later model call, the exact system policy text and input/output schema version must be pinned by a content digest and reviewed; policy/schema changes require a new digest and evaluation. A later model must be an isolated optional producer behind the same input/output contracts. It has no filesystem, network, shell, or tool capability. Failure is confined to the assistance branch. No automatic request is made on case creation, page load, API/SSE update, or background schedule.

The Phase 36.1 internal scope is a review-priority reference plus bounded fixed checklist/explanation templates. The priority is not severity or risk. The module is not connected to a product surface. Phase 36.2 requires semantic citation review and synthetic contract evaluation before any retrieval-backed expansion; model-generated explanation is not required.

## Safe Investigation DTO

Build a dedicated allowlist DTO; do not pass a public projection, model, `asdict`, arbitrary mapping, raw rationale, or full case object. The candidate closed input is `safe-investigation/v1`:

| Field | Closed value |
| --- | --- |
| `schema_version` | integer `1`; booleans rejected |
| `request_id` | request-scoped opaque random identifier; not a case identity |
| `source_role` | `application`, `ssh`, `web`, `unknown` |
| `observation_categories` | `authentication`, `web_request`, `process_execution`, `relation`, `risk`, `case_lifecycle`, `unknown` |
| `detection_codes` | exact stable code strings copied from the reviewed current detector enum inventory; no arbitrary string and no code inference; unsupported codes refuse |
| `relation_codes` | exact stable code strings copied from the reviewed current relation enum inventory; no arbitrary string and no code inference; unsupported codes refuse |
| `risk_band` | exact existing coarse risk-band enum; no score or rationale |
| `case_status` | exact existing case lifecycle enum |
| `event_count_bucket` | `0`, `1`, `2_5`, `6_20`, `21_plus` |
| `time_window_bucket` | coarse enum such as `under_5m`, `5_60m`, `over_60m`, `unknown`; no timestamp |
| `evidence_completeness` | `complete`, `partial`, `conflicting`, `unknown` |
| `limitation_codes` | bounded unique reviewed enum list |
| `verified_citation_ids` | bounded IDs returned by the Phase 33.1 verifier for this request and matching the current corpus digest/category |

Unknown fields, missing required fields, duplicate keys, invalid enums, non-finite numbers, free strings outside bounded opaque IDs, and values outside explicit byte/item limits are rejected. Phase 36.1 freezes supported role/category/detection/relation/limitation enums in code; unknown values fail closed. No account, IP, hostname, file path, checkpoint, source identity, exact timestamp, raw log, user free-text question, credential, exception, internal rationale, HTML, URL search result, or unrestricted metadata is included. Values are omitted when not required; they are not inferred. Request IDs are short-lived correlation handles, not global case IDs.

Phase 36.1 fixes serialized input at 4 KiB, bounded category lists and 8 citation IDs. These are project limits, not standards or performance claims. There is no model token budget because this reference has no model.

## Output Schema

The later optional response contract is `investigation-assistance/v1`. It is a closed JSON object with exactly these top-level fields:

```json
{
  "schema_version": 1,
  "request_id": "request-scoped opaque value",
  "case_ref": "request-scoped opaque value",
  "review_priority": "review_soon",
  "priority_reasons": [{"code": "evidence_incomplete", "citation_ids": ["approved-section-id"]}],
  "investigation_steps": [{"template_code": "confirm_time_range", "text": "Check whether the relevant time range is covered.", "citation_ids": ["approved-section-id"]}],
  "explanation": {"text": "A separate review suggestion based on the supplied categories.", "citation_ids": ["approved-section-id"]},
  "uncertainty": ["source_coverage_unknown"],
  "limitation_codes": ["no_source_identity"],
  "generated_by": "deterministic_reference",
  "status": "available"
}
```

Enums: `review_priority` is `review_now`, `review_soon`, `review_later`, or `undetermined`; status is `available`, `refused`, or `unavailable`. `generated_by` is a fixed approved implementation identifier, not model-supplied text. The model cannot return `risk_score`, `risk_band`, detection, relation, case mutation, action, or arbitrary citation content. `case_ref` is request-local and expires with the request; no stable cross-case link is created.

Validation is all-or-nothing. Reject duplicate JSON keys, `NaN`/`Infinity`, unknown/missing keys, wrong types including bool-as-int, invalid enums, oversized JSON, overlong text, excessive list counts, duplicate list values where disallowed, citation IDs outside the verified input subset, and any claim lacking an allowed citation. Security claims in reason, step, and explanation text all require a citation. A citation must also match the request category; existence alone is insufficient. The known Phase 33.1 over-citation remains a semantic evaluation failure candidate, even if structural verification passes.

All text is bounded plain text. Reject HTML, Markdown links, script-like markup, URLs, command/tool syntax, and account/IP/hostname-like identifiers. Do not truncate or repair invalid output; discard the entire response and return a fixed unavailable/refused category. Render as escaped plain text only. A schema validator cannot prove a claim true or prove prompt-injection resistance.

Phase 36.1 fixes response caps at 8 KiB total UTF-8 JSON, 4 priority reasons, 5 investigation steps, 4 uncertainty codes, 8 distinct citation IDs, and 512 UTF-8 bytes per text. These are synthetic contract limits, not service capacity claims.

## Retrieval and Citation Boundary

Use only the Phase 33.1 digest-verified approved corpus and deterministic lexical retrieval. Do not use embeddings, vector databases, dynamic web search, user cases as corpus entries, or raw-log retrieval. Reuse the citation verifier. A result is eligible only when corpus digest, document/section identity, approval state, category, and citation integrity match. Retrieval output is a knowledge candidate, not telemetry and not evidence that an event occurred.

Every generated factual security claim must cite one or more verified IDs supplied in the same request. Invalid, stale, category-mismatched, or unsupported citations reject the whole response. Citation presence is a structural condition; human semantic-support review is a separate measure. Preserve the existing one over-citation fixture without changing the 33.1 baseline.

## Threat Model

| Threat | Design controls | Failure boundary / residual risk |
| --- | --- | --- |
| Log-based indirect prompt injection | Raw logs are excluded; safe enums/codes are data; no free-text question | Approved labels may still be misleading; output validation is not injection immunity |
| Detection code treated as command | Codes are allowlisted data; no tool/action interface | A later renderer or consumer could misuse text; keep DTO consumers explicit |
| Corpus poisoning | Static approved corpus, pinned digest, reviewed changes | Reviewer or upstream-source compromise remains possible |
| Citation laundering / unsupported claim | Verified input-subset citations, category check, semantic evaluation | Valid citation syntax does not prove the cited text supports the claim |
| Severity inflation or dilution | Priority has separate enum and rationale; cannot write risk | Analysts may over-trust priority wording |
| Privacy reconstruction / cross-case linking | No identifiers, exact times, stable case IDs, or user question; request-local alias | Coarse categories can still reveal context in very small populations |
| Malicious Unicode / output injection | Strict bounded text policy, reject control/bidi policy violations, plain-text escaped render | Unicode screening is incomplete; avoid treating normalization as semantic repair |
| Duplicate JSON key / malformed output | Strict parser with duplicate-key and non-finite rejection | Parser implementation must be tested at byte and nesting limits |
| Denial of service / excessive resources | Explicit request, byte/item limits, one bounded job, timeout, no retry | Scheduler/model runtime resource bounds require later isolated proof |
| Model timeout/crash/provider abuse | Optional worker; fixed unavailable status; no automatic fallback | A later runtime/provider may fail or retain transient data; separate gate required |
| Analyst over-reliance | Persistent “assistance, not finding” label and uncertainty/limitations; no auto-action | Human factors require direct user acceptance, not automated tests |
| Authority expansion to response | No action fields, tools, filesystem/network/shell, or auto-response | Future scope changes need a new gate |
| Embedding leakage/poisoning | Lexical-only for the first path; no case corpus | Future embedding requires separate data and supply-chain gate |

Logs and evidence are untrusted data, not instructions. Prompt wording alone is not an enforcement boundary. The future model must have no tools or side-effect permissions. The output is untrusted and must be validated at the application boundary. Injection success must be evaluated separately; passing a finite fixture set is not a general resistance claim.

## Evaluation Contract

Create at least 36 fixed synthetic (합성) cases, with no real logs or identifiers. Keep deterministic-analysis expected values separate from assistance expected values. Include:

1. brute force; 2. password spray; 3. failed-then-success relation; 4. path traversal; 5. suspicious process execution; 6. incomplete evidence; 7. conflicting observations; 8. benign-like activity; 9. stale case; 10. high risk with incomplete evidence; 11. low risk with repeated activity; 12. unsupported category; 13. prompt-injection phrase in a synthetic evidence label; 14. 개인정보 account/IP/host/path canaries as rejected input; 15. malformed DTO; 16. unknown DTO field; 17. duplicate JSON key; 18. invalid citation; 19. valid but category-mismatched citation; 20. over-citation regression; 21. citation-free claim; 22. HTML/Markdown/URL output; 23. command/tool request; 24. severity inflation; 25. severity minimization; 26. Unicode confusable/bidi case; 27. `NaN`/`Infinity`; 28. maximum valid input; 29. input cap + 1; 30. maximum output; 31. output cap + 1; 32. excessive list count; 33. duplicate citation; 34. timeout; 35. crash; 36. unavailable corpus digest; 37. retrieval conflict; 38. resource boundary and concurrency.

Required acceptance targets for a future model gate: schema validation 100%; invalid citation 0; unsupported claim 0 on the labeled synthetic set; privacy leak 0; tool/action request 0 executed; injection execution 0; deterministic refusal 100% for invalid/out-of-scope input; analysis mutation 0. Report citation completeness against per-case required citations. Review-priority agreement is measured against a separately versioned deterministic reference policy, not the existing risk score. Korean explanation meaning and analyst comprehension require separate blinded manual review; automated string tests cannot mark them PASS. Include benign controls and false-refusal rate; do not count empty output or blanket refusal as success. Results are finite synthetic evidence, not production efficacy. The synthetic contract requires **privacy leak 0**, **unsupported claim 0**, **invalid citation 0**, **analysis mutation 0**, **tool/action 0**, and **injection execution 0**.

## Tool Comparison

| Candidate | Privacy / egress | Supply chain / resources | Structure, citation, failure | Decision |
| --- | --- | --- | --- | --- |
| Deterministic template/reference | No model egress; bounded categories only | Repository code; low additional runtime cost | Fully testable and deterministic; fixed citation rules | **Implemented for Phase 36.1; internal only** |
| Local LLM | Can be local after setup, but input still crosses a model boundary | Model and native runtime supply chain, RAM/CPU, isolation not closed; prior local execution gates remain blocked | Structured output still needs validation; timeout/crash isolation required | NOT_TESTED; later gate only |
| Existing Gemini helper | Provider egress; historical input projection may include IP | Pinned SDK does not close provider/model handling or data retention | Free-text output; no closed citation validation; not default path | Not selected; no call |
| Hosted external LLM | Direct third-party data transfer | Provider, model revision, retention, region, outage, and contract need separate review | Structured response does not establish factual support; network failure | NO_GO for this design |
| Embedding retrieval | Corpus/query representation may leak or be poisoned depending on store | Model/index supply chain and resource/storage boundary | Retrieval rank is not semantic support; verifier still required | Production `NO_GO`; not used |

Only deterministic template/reference is exercised in 36.1. All other candidates are `NOT_TESTED` for this feature. The existing Gemini helper is not silently used as a fallback.

## Research Basis

Research checked 2026-10-27. NIST AI 600-1 frames generative AI risk management across the AI RMF functions; this design translates that into bounded data, explicit failure behavior, evaluation, and human review rather than claiming compliance. OWASP guidance says prompt separation and screening are layers, not an authorization boundary, and recommends treating model output as untrusted at downstream boundaries. OWASP also describes vector/embedding risks including poisoning, leakage, and access-control problems; the first design therefore remains lexical-only. MITRE ATT&CK is a knowledge base describing observed adversary tactics and techniques; a mapping or citation is contextual reference, not proof that a case exhibits the behavior.

Official sources:

- [NIST AI RMF Generative AI Profile, NIST AI 600-1](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf), July 2024; [NIST AI RMF page](https://www.nist.gov/itl/ai-risk-management-framework), checked 2026-10-27.
- [OWASP LLM Prompt Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html), checked 2026-10-27.
- [OWASP LLM05:2025 Improper Output Handling](https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/), checked 2026-10-27.
- [OWASP LLM08:2025 Vector and Embedding Weaknesses](https://genai.owasp.org/llmrisk/llm082025-vector-and-embedding-weaknesses/), checked 2026-10-27.
- [MITRE ATT&CK Get Started](https://attack.mitre.org/resources/) and [Enterprise techniques](https://attack.mitre.org/techniques/), checked 2026-10-27.
- Project evidence: [Phase 33.0 design](local_ai_investigation_assistant_33_0.md), [Phase 33.1 lexical retrieval](local_ai_lexical_retrieval_33_1.md), and [Phase 33.4 guidance](local_investigation_guidance_33_4.md); repository state checked 2026-10-27.

These sources inform design controls; they do not establish that a future model or this project is secure.

## Roadmap

| Phase | Scope | Gate |
| --- | --- | --- |
| 36.0 | This design, closed DTO/output and threats/evaluation contract | `PHASE_36_1_READY` only for LLM-free reference work |
| 36.1 | SafeInvestigationDTO, deterministic review-priority reference, citation-verified fixed checklist, strict output validator, 44 synthetic evaluation cases | No model; internal/test-only; see implementation record |
| 36.2 | Lexical-retrieval checklist templates and citation semantic review | No model; existing corpus digest/verifier; human semantic review |
| 36.3 | Compare isolated local model/provider only after separate supply-chain, privacy, resource, and egress gate | No automatic Gemini fallback; synthetic input only |
| 36.4 | Explicit analyst action, bounded API/concurrency/size and plain-text UI | Separate privacy/security and direct user acceptance; no automatic request |

Similar-case grouping and response recommendations require later independent gates. Automated parser application, automated response, and analysis mutation remain prohibited.

## Limitations

Phase 36.1 is a deterministic internal reference, not a model evaluation or user study. No model or runtime was called, installed, or downloaded. The finite synthetic suite cannot prove semantic correctness, analyst performance, or operational suitability. Korean semantic quality remains `NOT_TESTED`; Phase 33.1 over-citation remains a regression. Real user data, organizational operation, automatic response, external hosted processing, production embedding, and remote collection remain `NO_GO`. Phase 35.4B remains paused pending user VM action; Vector was not run, and this phase does not validate Vector or replace its isolation gate. Crash/SIGKILL/power-loss recovery, provider retention, long-duration load, and model resource behavior remain `NOT_TESTED`.
