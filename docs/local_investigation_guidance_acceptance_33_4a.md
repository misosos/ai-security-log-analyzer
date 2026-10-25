# Phase 33.4A — local investigation guidance acceptance

**Final disposition: `NO_GO`.** The exact-SHA CI and loopback checks passed, but a synthetic IP canary was returned by the existing public investigation response. The privacy gate therefore failed and Safari manual acceptance was stopped before it began. No production code or analysis semantics were changed in this acceptance pass.

## Exact-SHA remote evidence

- Start and reviewed SHA: `098e652f41963ad18dc2d1ffa623c7ed772a52d8`; parent: `e803e4c3c25416863213e94eae3c09bf6fc8347b`.
- Branch `main`, clean tree, local and `origin/main` equal, ahead/behind `0/0` before review.
- Push run [40159254345](https://github.com/misosos/ai-security-log-analyzer/actions/runs/40159254345): event `push`, exact head SHA, `completed/success`.
- Ubuntu job passed locked dependency verification and installation, Python compilation, Linux checkpoint/setup checks, bounded Schemathesis, and `uv run pytest -q`: **2,661 passed, 2 existing deprecation warnings**. The complete run includes the committed Phase 33.4 API, retrieval, and documentation tests.
- CI installed pinned Node and Chromium, checked executable hashes, and passed the bounded Chromium accessibility pilot. Guidance state reported `guidance []`; the run reported `external_requests=0`. This is automated Chromium evidence, not Safari evidence or a WCAG 2.2 AA claim.
- GitHub artifact API reported **0 artifacts**.
- `v0.4.0` tag object remained `855a92827a605805b62c627ed719958620150ec4`; peeled target and public Release target remained `eecd6ee1cda0545e34b01c42e1a2163a899bcc27`.

## Local synthetic preflight

The available host reported macOS 15.7.7, arm64, and Safari 18.6. A temporary HOME, loopback-only app server, and generated synthetic application/SSH/access files were used. No actual user logs, monitor configuration, checkpoint, or credentials were read. The application fixture included synthetic account, IP, and hostname canaries.

- Health: `PASS`.
- Synthetic local analysis: HTTP 200; one case returned.
- Guidance request: one direct loopback request; HTTP 200; status `AVAILABLE`; two citations; corpus digest matched the pinned 18-section corpus.
- Existing analysis fields (`analysis_summary`, `case_summary`, `cases`) were equal before and after the guidance request.
- Privacy canary: **`FAIL`**. The synthetic IP canary was present in the existing analysis response at `cases[].subject`, `cases[].timeline[].subject`, and `report_export.html`. The field path is recorded without the canary value. The guidance adapter's minimized request projection itself omits `subject`, but that does not make the full case screen safe for this acceptance scenario.
- External request count for the scripted preflight: 0. Safari/Web Inspector network inspection was not performed.

This is an observed exposure from the existing public case/report projection when its synthetic IP is used as a subject. This acceptance pass did not change that projection. Because the screen displays the analysis result before guidance, manual Safari review was stopped at the privacy gate.

## Safari manual acceptance

No Safari page was opened for manual interaction after the automated privacy failure. User answers were not collected. These items are all `NOT_TESTED`:

| Item | Status |
| --- | --- |
| Understand the purpose of “근거 도움말” | `NOT_TESTED` |
| Understand that no help is requested before explicit activation | `NOT_TESTED` |
| Distinguish explanation from cited source | `NOT_TESTED` |
| Understand that guidance does not change analysis | `NOT_TESTED` |
| Understand refusal, stale, and temporary-error next steps | `NOT_TESTED` |
| Keyboard-only navigation and activation | `NOT_TESTED` |
| Safari 200% zoom and minimum window width | `NOT_TESTED` |
| VoiceOver labels and states | `NOT_TESTED` |
| Web Inspector JS/CSP/MIME, external requests, and privacy | `NOT_TESTED` |
| Direct measurement at exactly 320 CSS px | `NOT_TESTED` |

Chromium UI/axe results remain automated evidence only. No user answer is inferred from them.

## Cleanup and retained boundaries

The loopback server was stopped; its listener was confirmed closed. The temporary HOME, generated log files, and isolated temporary uv cache were removed. No model, embedding, runtime, external network, or persistent repository artifact was created. The existing guidance endpoint remains lexical-only; Phase 33.2 embedding is `NO_GO`, Phase 33.3F remains `STORAGE_SETUP_BLOCKED`, and Gemini remains separate and unused.

Before repeating Safari acceptance, the public case/report privacy exposure needs a separately reviewed minimal fix and regression coverage. This record does not approve production rollout. Exact-SHA CI after any fix and all manual Safari checks remain outstanding.
