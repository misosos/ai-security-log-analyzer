# Phase 33.4 — verifiable local investigation guidance

**Implementation disposition: `CONDITIONAL_GO`; Phase 33.4A acceptance disposition: `NO_GO`.** The Phase 33.1 deterministic lexical baseline is connected to a loopback-only read-only endpoint and an explicit case-detail action. This is a cited knowledge lookup, not a generated explanation or a security decision. The exact-SHA Ubuntu CI passed, but 33.4A found a synthetic IP canary in the existing public case/report response and stopped before Safari manual review. See [33.4A acceptance](local_investigation_guidance_acceptance_33_4a.md).

## Gate and baseline

- Start SHA: `e803e4c3c25416863213e94eae3c09bf6fc8347b`; local and `origin/main` matched on clean `main`, ahead/behind `0/0`.
- Push CI [run 40150892112](https://github.com/misosos/ai-security-log-analyzer/actions/runs/40150892112) completed successfully for that exact SHA. Locked install, Ubuntu full regression, Phase 33 checks, Node/Chromium accessibility, and axe passed; artifact count was 0. The v0.4.0 tag peeled to `eecd6ee1cda0545e34b01c42e1a2163a899bcc27`, and its release target was unchanged.
- Before edits, sandboxed pytest produced 2,637 passed and 12 environment-denied Unix-socket/loopback failures. The same pre-change suite outside the sandbox passed **2,649 tests**, with two existing dependency deprecation warnings.
- Test-first API/UI checks initially failed: the guidance endpoint returned 404, and no opt-in case-detail action existed.

## Contract

The endpoint is `POST /api/v1/investigations/guidance`. It is available from the local investigation app only and applies the existing loopback request policy. The body has a closed schema: version, category, pinned corpus digest, and a minimized public case projection. There is no free-form question field. Supported categories are the existing `QueryCategory` enum.

The case projection copies only review order, approved detection/relation display labels, existing risk and confidence levels, and bounded observation/relation counts. It excludes subject, timeline, timestamps, evidence, rationale, and raw input. A deterministic `c_` reference is SHA-256 over the canonical safe projection, truncated to 24 hex characters. The server recomputes it; a mismatch returns `STALE`. This reference binds the submitted public fields but is not an authentication token or a claim that the client DTO is authoritative.

Batch cases can combine application, SSH, and access observations and have no single source role. The existing frozen `SafeEvidence` now allows `source_role=None` to preserve that unknown scope. Retrieval uses no role to produce analysis; category eligibility and approved labels are still validated. No source role is invented.

The adapter creates a fresh safe evidence projection and calls Phase 33.1 retrieval over the unchanged **18 sections**, corpus digest `fe7cc8cbd77319c4ce9a1af731da004eeffc08d272c0ee04174db96eb2897ac6`, and existing score threshold/top-k rules. It then calls the Phase 33.1 citation verifier against the active corpus before projecting title, approved section text, citation ID, and repository source reference. A digest or citation mismatch fails closed. Search results are never returned to analysis, detection, correlation, risk, or case builders.

The successful response is closed to schema version, fixed status, fixed boundary message, verified citations, and corpus digest. Statuses are `AVAILABLE`, `REFUSED`, and `STALE`; transport/integrity failures use fixed `GuidanceErrorResponse` codes. Raw requests, private DTO fields, exception strings, and source paths are not echoed or logged. The route has an 8 KiB request cap, 6 KiB response cap, two-second timeout, one active request, and 12 requests per 60 seconds. It performs no network access, file search, tool execution, or corpus update.

The only UI action is inside the collapsed investigation case detail. A user chooses one of the fixed topics and presses **근거 도움말 보기**. There is no automatic request, prefetch, URL/storage cursor, or external link. Citation sources are rendered as text using `textContent`; help states are separate for available, refused, stale, and unavailable. The UI repeats closed-schema and digest validation and leaves focus and scroll where they are.

The separate schema 2 and schema 3 live-monitor screens, including application and SSH role selection, remain unchanged. The batch guidance endpoint does not attach to live publication or SSE.

## Privacy and threat boundary

| Threat | Control and observable check | Residual boundary |
| --- | --- | --- |
| Client supplies private values or prompt injection | No question field; unknown fields and unapproved labels rejected before retrieval; fixed error does not echo body | A local caller can submit fabricated *safe* labels; help has no authority and does not affect analysis |
| Case identifier altered or replayed | Reference recomputed over allowlisted case summary; mismatch returns fixed `STALE` | The deterministic reference is not a signed session token; returned text is generic corpus material |
| Corpus tampering or citation forgery | Trusted digest check plus Phase 33.1 `validate_result`; failure returns fixed unavailable response | Static corpus still requires reviewed manifest changes in a future change |
| HTTP/DOM injection | Closed response, bounded text, no links, plain `textContent`; Chromium injected-script string remained text | Automatic axe/browser checks are not a WCAG conformance claim |
| Resource exhaustion | 8/6 KiB request/response, 18-section bounded corpus/index, 2 s timeout, one active request and rate cap | Timeout and process-level fault behavior still needs operational review; no SLA is claimed |
| Privacy in logs/analysis | Endpoint receives no raw request question, does not call analysis/Gemini, has no logging of payload, and errors are fixed | Trusted analysis state still contains sensitive data under its pre-existing boundary |

## Validation and performance

- Focused endpoint, adapter, stale/refusal, corpus mismatch, citation tamper, private-canary, duplicate-key, request-limit, deterministic timezone, and source-neutral SafeEvidence tests passed.
- API tests verified that a real public sample case is reduced to allowlisted fields, that analysis is not called, and that the sample analysis response is identical before and after guidance.
- The loopback Chromium workflow verified no request before explicit keyboard activation, minimized request keys, safe text rendering of a synthetic script string, distinct refusal/stale states, keyboard focus, and widths 320/640/1024/1440 CSS px. No external requests or console errors were observed. `npm ci` and the bounded Chromium axe suite passed; no serious or critical violations were reported in the guidance state.
- In-process Python benchmark command: `uv run python tests/benchmark_local_guidance_33_4.py`. It uses 5 warm-ups and 30 samples for corpus load, index build, retrieval, and citation verification; endpoint uses 5 warm-ups and 7 samples to stay within the endpoint's request-rate cap.
- Final local run: 18 sections, 14,833 corpus bytes, 25,279 resident index bytes; request 387 bytes, response 1,182 bytes, 2 citations. Warm-up 5; 30 samples per corpus/index/retrieval/verification stage and 7 endpoint samples. Median/p95/max: corpus load 2.132/4.327/6.183 ms; index build 0.930/0.979/1.043 ms; retrieval 0.105/0.130/0.200 ms; citation verification 0.012/0.013/0.013 ms; in-process endpoint 4.594/4.955/4.955 ms.
- Chromium click-to-DOM run used one warm-up and eight measured clicks; the final run was 48.4/51.6/51.6 ms median/p95/max, with a 420-byte request and 460-byte response. These synthetic local figures are not an operational SLA or worst-case guarantee.
- TestClient in-process checks create no listening socket; the real loopback browser suite verified listener shutdown. No persistent temp files, background polling, SSE slots, or child processes were introduced by the guidance route.

Safari, VoiceOver, real 200% zoom, and manual user acceptance were not performed (`NOT_TESTED`). The automated UI checks do not establish WCAG 2.2 AA compliance.

## Phase boundary

Phase 33.1 lexical retrieval is the sole production search baseline. Phase 33.2 embedding remains `NO_GO`; Phase 33.3 local LLM remains `STORAGE_SETUP_BLOCKED`. No LLM, embedding, vector database, or Gemini helper is called or changed. The assistant is read-only evidence lookup; detection, correlation, risk, and cases remain authoritative and unchanged. Final approval is blocked by the public case/report privacy exposure recorded in 33.4A, followed by exact-SHA Ubuntu CI and manual Safari review after a separately reviewed fix.
