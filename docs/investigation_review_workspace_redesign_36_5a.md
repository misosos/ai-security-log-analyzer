# Phase 36.5A — investigation review workspace redesign

**Status: `CONDITIONAL_GO` for the synthetic local UI pending a new SHA Ubuntu CI run and Phase 36.5B user review.** This change reorganizes the existing presentation only. It does not change analysis facts, API schemas, source-role provenance, privacy projection, checklist meaning, or deterministic ordering.

새 SHA의 Ubuntu CI와 새 UI 사용자 검수 전에는 최종 GO가 아닙니다. 실제 자료·조직 운영·자동 대응은 NO_GO; 실제 사용자 자료는 계속 NO_GO입니다. 모델 기반 AI는 NOT_TESTED입니다.

## Why the workspace changed

The previous result page rendered every case detail inside the result list. With two cases, both timelines, evidence, limitations, and next-step content were present at once. The list had no clear boundary from detail, column heights left empty space, and KST/UTC and caution text repeated. Internal values such as `review_soon` and limitation codes could appear beside user-facing evidence. A long sequence of event cards did not communicate a time flow, and the checklist resembled DTO text rather than work an analyst could perform. Korean and English headings were mixed, making it hard to answer what happened, why to review it, and what to check next.

The UI calls an investigation case a **검토 건**. This is a presentation label only; the API and internal investigation-case contract remain unchanged.

## List and independent detail view

결과 목록과 독립 상세 화면을 분리합니다.

The dashboard now shows summary metrics and compact 검토 건 cards. Cards contain a human-readable activity title, existing risk label, deterministic list position, a note that the source role is available only after the explicit checklist request, a compact KST range, activity/relation counts, a two-line explanation, and a `상세 분석 보기` link. The list does not render timelines, checklist results, citation cards, full limitations, or internal codes. Detail DOM is created only for the selected case.

Selecting a card opens `#/investigations/{opaque_case_ref}` in the same tab. The hash uses only the existing opaque `c_` reference. The current result remains in tab memory; browser history state stores only a boolean marker, list scroll position, and a constrained focus-element ID. It does not store the analysis. Back navigation restores the list and attempts to restore scroll and focus. A direct or refreshed detail route with no in-memory result shows a fixed expired-state message and a return action. Checklist calls remain explicit and are never made by route entry, hover, or prefetch.

## Detail structure and meaning

The detail view starts with back navigation, the selected review number, and a mode label (`합성 예시` or `로컬 분석`). Its compact summary separates the existing risk from list position and from the checklist's optional review-priority suggestion. The four small metrics summarize observed activities, related flows, work items, and items needing more confirmation.

The activity flow is an ordered HTML list styled as a vertical timeline. Each item includes a text label for the event category and a semantic `<time>` with a machine-readable UTC `datetime`; the default visible time is KST. Exact timestamps, including UTC, are available in a disclosure. Related events are marked `분석상 연결 · 인과관계 미확정`, with a dashed line treatment in addition to text. The UI preserves the server-provided sequence; it does not sort, join, or infer events.

Confirmed content and items that need further checking are separate lists, each showing at most three entries initially. Longer lists offer an explicit expand/collapse control. Checklist steps are numbered task cards, not checkboxes; there is no saved completion state. The user must press `확인할 작업 불러오기` to send the existing bounded POST. Each step's purpose and citations are inside `왜 확인하나요?`. The response retains the existing invariant notice: `이 점검표는 기존 탐지·관계·위험도·사례 결과를 변경하지 않습니다.`

Citation and limitation detail uses **progressive disclosure**. The collapsed summary gives counts and a `근거와 한계 보기` action. Expanded content distinguishes general reference material from evidence about this case. Citation IDs and internal codes are further hidden under technical details. Existing enum values are mapped to fixed Korean labels; unknown values use a generic safe activity label rather than exposing raw internal strings. Risk remains an existing analysis value and is never recomputed by the UI.

## Privacy and analysis invariance

개인정보 노출과 분석 결과 변경은 허용하지 않습니다. 검증 결과는 privacy leak 0, 분석 불변입니다.

The detail route is keyed only by the existing opaque case reference. Renderers use text nodes/textContent, not HTML parsing. No analysis payload is persisted in localStorage, sessionStorage, or IndexedDB. The checklist request body and `investigation-checklist/v2` response contract are unchanged. The UI does not add API calls, network destinations, dependencies, or background fetches.

The frontend consumes existing values and renders the same case order, source role, review priority, checklist status/steps, citation IDs, limitation codes, aliases, checkpoint/publication state, SSE cursor, and guidance corpus digest. The view transition itself does not call analysis, alter checkpoint/publication/SSE state, or change the report. Synthetic browser checks compare the analysis text before and after checklist interaction and verify no checklist POST before the explicit action.

## Responsive and accessibility behavior

The detail content uses a natural single-column flow, with a narrow responsive summary grid and no fixed-height content panels. The timeline is an `<ol>` with text labels and line styling, so color is not the only distinction. Native `<details>/<summary>` disclosures preserve keyboard interaction. Route entry focuses the global page heading, and browser Back restores focus to the originating card link where possible. Reduced-motion preferences are respected. Layout rules collapse at the existing narrow viewport breakpoint and allow Korean text and badges to wrap.

Chromium/axe automated checks cover the dashboard, one selected detail, checklist loading/available/refused/unavailable/error states, route expiry, and the existing application states. They do not establish full WCAG 2.2 AA conformance or Safari behavior. Safari remains `NOT_TESTED / USER_HOME_ISOLATION_BLOCKED`; Safari, VoiceOver, native browser zoom, and physical-device 320 CSS-pixel checks were not run in this phase.

## Performance and DOM measurements

The browser pilot uses 10 warm-up route transitions followed by 30 measured list-to-detail-and-back transitions. In the local Chromium synthetic run, transition time was **98.985 / 102.876 / 112.150 ms** (median/p95/max); one selected detail contained **153 DOM nodes** and serialized to **7,920 bytes**. These are local synthetic development observations, not an operational SLA, latency guarantee, or capacity limit. The list contract asserts that no detailed case subtree, timeline, citation/technical disclosure, or checklist result is rendered for either card. Chromium/axe covered **23 states**, with **0 violations** and `external_requests=0`.

운영 SLA가 아닙니다.

## Gate and remaining limits

The change keeps external chart dependencies at zero. `npm ci --ignore-scripts` must finish before Chromium/axe is started so package installation cannot race browser access. The pre-change browser contract failed because the list rendered full detail under each case; the revised contract requires a compact list, one selected detail, explicit route transition, and no automatic checklist request.

Actual user materials, organizational operation, and automated response remain **NO_GO**. Model-based AI remains **NOT_TESTED** and is not called by this UI. Vector/VM status is unchanged: `USER_ACTION_REQUIRED / ISOLATION_BLOCKED`. Phase 36.4A's older UI comprehension is not promoted to acceptance of this redesign; a new Phase 36.5B user review is required. Final GO also requires a successful Ubuntu CI run for the new commit.
