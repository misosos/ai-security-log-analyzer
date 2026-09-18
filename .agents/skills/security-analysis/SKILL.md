---
name: security-analysis
description: Research, design, or modify deterministic security detections, correlations, risk criteria, and ATT&CK mappings from observable log telemetry. Use for new security behavior or semantic changes, not ordinary refactoring or presentation-only work.
---

# Security Analysis

Use this workflow for a new Detection or Correlation; a meaningful change to a threshold, time window, security semantic, or Risk Assessment criterion; interpretation of a new log source or telemetry; a mapping between an attack technique and observable behavior; a new or changed MITRE ATT&CK mapping; or a design decision based on current security operations practice.

Do not use it for a simple rename, formatting, presentation-only UI/CSS work, an obvious serialization fix, a mechanical migration that retains the existing contract, or a straightforward refactor that preserves security behavior.

## 1. Research

- First inspect the telemetry available from the current parsers, schemas, fixtures, and tests.
- Before implementation, perform web research for every task in this skill's scope. Do not rely only on existing model knowledge.
- Use this source priority:
  1. Primary or authoritative sources: MITRE ATT&CK, CISA, NIST, official vendor or product documentation, Microsoft Learn and Microsoft Security, Google and Mandiant, AWS security and logging documentation, and official documentation for the product being analyzed.
  2. Established security research: Mandiant, Microsoft Security, CrowdStrike, Palo Alto Unit 42, Elastic Security, Splunk Security Research, and other established security research organizations.
  3. Supporting research: peer-reviewed papers, conference publications, and reputable technical research.
- For product implementation facts such as log fields, event semantics, timestamp behavior, and authentication behavior, prefer official documentation for the relevant product and version over general security writing.
- Do not use personal blogs, SEO content, or unattributed detection rules as the core design basis.
- For each source, assess authority, publication or last-updated date, current technical validity, product or log-version relevance, and whether the finding can map to actual telemetry.
- Do not choose a source only because it is newer. Resolve differences according to the role of each source and prefer applicable official product documentation for implementation-specific facts.
- Separate an attack description from signals observable in collected logs.
- Record which facts from each source affected the design and how they affected it.
- Do not treat a technique name or a security document's prose as a detection condition.

## 2. Translate Research into Observable Signals

Use this sequence:

```text
Security research
→ attack or behavior description
→ required telemetry
→ fields available in this repository
→ observable pattern
→ deterministic condition
→ structured Evidence
→ bounded conclusion
```

For each proposed signal, determine:

- which source and parser produce it;
- which fields are required;
- the aggregation key;
- the time window;
- the basis for any threshold;
- whether event ordering matters;
- behavior when fields are missing or parsing fails.

If required telemetry is unavailable:

- do not pretend the current logs can establish the condition;
- explain whether the parser or schema must be extended first;
- if a limited heuristic is still appropriate, reflect that limitation in its name and conclusion.

Never infer unobserved attack success, attacker intent, causation, or credential reuse.

Repeated claims across multiple sources do not make a fact observable in the current logs. Limit conclusions to what the available telemetry establishes.

## 3. Classify Detection or Correlation

Use Detection when a single event or explicit aggregation of events satisfies a deterministic rule.

Use Correlation when calculating a relationship between two or more events or detections. State the join conditions, such as time order, identity, source, and target.

For every correlation, determine:

- whether it is per-IP;
- whether multi-IP, multi-user, or cross-source behavior makes it global;
- whether the result preserves that a relationship is not proof of causation.

Keep per-IP results in `results`. Keep analysis that cannot be attributed to one IP in `global_correlation`. Do not use a special IP key inside `results`, and do not automatically apply global correlation to an individual IP's risk.

## 4. Define the Result and Evidence Contract

Before implementation, define or confirm:

- the detection or correlation type;
- positive and negative result shapes;
- evidence `type`, `value`, and `source`;
- timestamp or time range;
- rationale;
- analysis scope;
- downstream risk, report, API, UI, and LLM consumers.

Evidence must make the conclusion reproducible. Rationale must not make a stronger claim than the evidence supports. Detection must remain distinct from confirmed compromise, and correlation must remain distinct from causation.

## 5. Implement Minimally

- Implement the decision in the deterministic Python pipeline.
- Keep thresholds and time windows explicit.
- Prefer the existing small-function structure.
- Do not delegate detection decisions or evidence generation to the LLM.
- Treat an ATT&CK mapping, if present, as optional metadata after evidence-based analysis, never as the reason the rule fires.
- Avoid abstractions that are unnecessary for the current project size or hide the security logic from a learner.

### Thresholds and Time Windows

- Do not choose plausible-looking numbers without investigating their basis.
- Classify every new or meaningfully changed threshold or time window as one of:
  - a value directly stated by a standard or official recommendation;
  - vendor detection guidance;
  - a heuristic informed by research;
  - an engineering heuristic selected for this project's evaluation.
- Cite the supporting source when the value comes from a standard, official recommendation, vendor guidance, or research.
- If no universal authoritative value exists, do not present the chosen value as authoritative. Make it configurable when appropriate and explain its false-positive and false-negative tradeoffs.

## 6. Unit Test

Cover the cases that apply:

- positive and negative cases;
- immediately below, exactly at, and immediately above a threshold;
- time-window boundary and outside-window cases;
- event ordering;
- isolation between different users, IPs, or sources;
- missing fields;
- evidence values, timestamps, and time ranges;
- conclusions that do not overstate compromise, success, intent, or causation.

## 7. Pipeline Integration Test

Verify the complete relevant path:

```text
raw log
→ parser
→ normalized event
→ detection or correlation
→ risk context and result contract
```

Check timezone normalization, IP grouping, cross-source relationships, per-IP/global scope separation, and whether every affected consumer reads the contract correctly.

## 8. Scenario Test

Use realistic sample logs to cover:

- a representative suspicious scenario;
- a normal or benign scenario;
- an attack-like case that does not meet the conditions;
- distributed or cross-source behavior when relevant;
- both facts established by the logs and facts that remain unconfirmed.

## 9. False-Positive and Limitation Review

Before completion, answer:

- Can normal operations produce the same pattern?
- Could NAT, proxies, shared accounts, scanners, or health checks affect the result?
- Which missing telemetry limits the conclusion?
- How could the behavior evade this analysis?
- What does the result not prove?
- Which additional logs should an analyst inspect?

## 10. Regression and Handoff

- Follow the layered workflow in the `security-testing` skill and run the full regression suite.
- In the completion report, include the following sections for work that used this research workflow.

### Research Basis

For each core source, record:

- source organization;
- document or page title;
- publication or last-updated date, when available;
- the fact used from the source;
- how that fact affected the design.

Do not treat a list of links as a sufficient Research Basis.

### Observable Evidence Mapping

Show the implemented mapping:

```text
Research finding
→ Required telemetry
→ Repository field or event
→ Detection or Correlation condition
```

### Limitations

State:

- facts the current logs cannot establish;
- false-positive possibilities;
- false-negative or evasion possibilities;
- additional telemetry that would be required.

Also report the basis and classification of thresholds and time windows used by the implementation.
