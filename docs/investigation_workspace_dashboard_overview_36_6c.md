# Phase 36.6C — dashboard and overview migration

## Gate and scope

The work resumed from `235f0f0a7f85b6b52d9699f5f69f521656c435ad` on `main`, with a clean tree and `origin/main...HEAD` at 0/0. Push run `40813067070` was completed successfully for that exact SHA; the required Linux, pytest, Chromium/axe, tracked-file, and zero-artifact checks were recorded as successful. The `v0.4.0` tag and Release still target `eecd6ee1cda0545e34b01c42e1a2163a899bcc27`.

This phase adds the result dashboard, review-incident cards, and an independent detail overview. Timeline, task details, citation/limitation disclosure, checklist response UI, backend/API/schema changes, new dependencies, and removal of the previous renderer remain out of scope. The existing rollback switch remains `USE_WORKSPACE_DETAIL_SHELL_36_6B` in `frontend/app.js`.

## Projection and count semantics

The internal closed schema remains `investigation-workspace-ui/v1`, with the existing 19 fields unchanged. Cards and detail overview reuse the immutable per-case projection created from the validated case response. Risk, source role, review priority, title, time range, summary, and per-case counts are read from that projection; missing role and priority remain `unknown` and `undetermined`.

The API's validated aggregate `independent_observation_count` is labelled **독립 관찰**. It is not shown as “추가 확인 필요”. Existing aggregate values retain their respective meanings: supported detections as confirmed activities, supported relations as connected activities, case count as review cases, and independent observations as independent observations. No projection 필드 is added or repurposed.

Per-case `limitation_count` is displayed only as **분석 한계** and equals that projection's `limitations.length`. It is not a count of unverified items, follow-up activities, or tasks. `unverified_items` are not merged with `limitations`; `task_count` is not presented as a count because the current projection does not represent actual task availability. The dashboard and overview therefore do not display an **추가 확인 필요 항목 수** metric. Computing that metric would require a separate contract review and a new approved projection field; no such field is introduced here. Missing values are not rendered as zero.

The summary cards use the validated aggregate fields from the same validated response snapshot used to construct the closed per-case projections. Card and overview values for a case use the identical frozen projection object held for that case reference. Tests check aggregate labels/values against validated API counts and detail labels/values against the corresponding projection.

## UI and navigation

The dashboard has a single-column review list, four compact aggregate metrics, safe status badges, a bounded summary, KST display range, observation/relation counts, and an explicit detail link. The overview has a title, separate risk/priority/role badges, KST range, safe summary, confirmed activity and relation counts, and **분석 한계**. It states that detections and relations do not establish compromise or causation and that the additional-confirmation count is not available in this phase.

The existing hash route is unchanged. Dashboard-to-detail, back/forward, stale direct entry, focus, case isolation, and explicit checklist behavior retain the Phase 36.6B contracts. Entering the detail view does not issue checklist or analysis requests. The existing renderer remains available through the one-switch rollback path; no storage migration is needed.

## TDD and verification evidence

Before completing the implementation, browser contracts failed with `WORKSPACE_DASHBOARD_CASES_NOT_SINGLE_COLUMN`; the focused source-contract test also failed because the old dashboard label implied a follow-up count. The fix makes the list one column despite the older higher-specificity grid rule, and labels the validated aggregate **독립 관찰**. The detail contract checks that `limitation_count` appears as **분석 한계**, matches the frozen projection, and is never relabelled as a task or follow-up count.

The browser checks cover dashboard structure and counts, one-column cards, detail projection values, no detailed DOM duplication in the list, canary privacy, route isolation, rollback, keyboard navigation, zero automatic checklist requests, viewport overflow, 200% equivalent reflow, and actual link hit area and spacing. Chromium·axe checked 23 UI states with zero violations and zero external requests. The dashboard/card/overview regression confirmed the validated aggregate counts, case projection counts, fixed refusal/status semantics, privacy canaries, and no checklist POST during navigation.

The required responsive matrix is 1440, 1024, 768, 390, and 320 CSS px; horizontal overflow was zero. A 200% equivalent text reflow check is separate from the viewport checks and passed without clipping. The 19px text-link target issue from prototype review is checked using the link's actual bounding rectangle, focus, and distance from adjacent content; the measured target met the 44px minimum with at least 8px separation. Checklist request count for dashboard, focus/hover, route, history, and overview remained **POST 0**. This is Chromium evidence, not Safari evidence.

The synthetic development benchmark used 10 warm-ups and 100 projection samples per batch: 1 case median/p95/max 0.1/0.2/0.3 ms, 5,406 input bytes and 663 output bytes; 32 cases 0.6/0.8/0.9 ms, 172,992 input bytes and 21,185 output bytes; 256 cases 4.0/4.3/4.3 ms, 1,383,936 input bytes and 169,473 output bytes. The route loop used 2 warm-ups and 8 measured transitions (median/p95/max 84.056/100.314/100.314 ms). Dashboard size was 175 descendant DOM nodes and 10,288 serialized HTML bytes; overview shell size was 32 nodes and 2,171 HTML bytes; loaded app JS/CSS transfer estimate was 230,261 bytes. These small synthetic browser measurements are development observations, not an operational SLA or worst-case guarantee.

## Remaining work and status

Phase 36.6D remains responsible for timeline and task presentation; 36.6E for evidence/limitations and explicit checklist UI; 36.6F for final 320px, 200% reflow, accessibility, and target-size acceptance; 36.6G for user acceptance and the decision about removing the old renderer.

Safari, real mobile devices, production organization data, organizational operation, automatic response, and model-based AI remain `NOT_TESTED` or `NO_GO` as applicable. The prototype's previous user acceptance does not approve production operation. Vector/VM remains `USER_ACTION_REQUIRED / ISOLATION_BLOCKED`.
