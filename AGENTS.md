# AI Security Log Analyzer

## Project Purpose

- Build a security analysis system that collects and normalizes multiple log sources, then analyzes them through a workflow resembling real SOC operations.
- This is not a demo that only searches for attack strings with regular expressions.
- Prefer explainable structures and detection logic that are useful in current security operations.
- Keep the code practical and learnable. Do not imitate unnecessary enterprise architecture.
- Prioritize observable evidence and testable security meaning over the number of features.

## Architecture

Preserve this analysis pipeline:

```text
Logs
→ Parsing / Normalization
→ Detection
→ Correlation
→ Risk Assessment
→ AI Explanation
→ API / UI
```

Separate result scopes explicitly:

```python
{
    "results": {
        "<ip>": {...},
    },
    "global_correlation": {
        ...,
    },
}
```

- `results` contains per-IP analysis.
- `global_correlation` contains whole-log analysis that cannot be attributed to one IP.
- Do not mix special IP keys such as `_global_correlation` into `results`.
- Do not automatically apply global correlation to an individual IP's risk. Introduce such behavior only with an explicit model and supporting evidence.

## Layer Responsibilities

### Loading

- Read logs from files or other input sources.
- Do not make detection decisions in this layer.

### Parsing / Normalization

- Convert source-specific logs into the common event schema.
- Normalize timestamps and timezones explicitly.
- Do not add meaning that is not observable in the source log.

### Detection

- Evaluate single events or explicit event aggregations with deterministic rules.
- Keep thresholds, time windows, and analysis scope explainable.
- Return structured evidence.
- Never represent a detection as confirmed compromise.

### Correlation

- Calculate deterministic temporal or logical relationships among events.
- Never represent correlation as causation.
- Keep per-IP correlation separate from global correlation.

### Risk Assessment

- Evaluate likelihood, impact, confidence, and account context separately from detection.
- Preserve evidence and rationale.
- Context such as a privileged account must not trigger a detection by itself.
- Keep confidence distinct from risk level.

### AI Explanation

- Explain only results produced by the deterministic pipeline.
- Do not create or modify detections, correlations, evidence, or risk values.
- Do not invent attack success, attacker intent, credential reuse, or attack chains.
- State uncertainty and log limitations explicitly.

### API / UI

- Represent the analysis contract accurately.
- Do not reinterpret security semantics in the presentation layer.
- Migrate API and UI consumers when the result schema changes.

### Models

- Express contracts between layers clearly.
- Preserve evidence and uncertainty without loss.

## Security Analysis Invariants

- Deterministic analysis creates facts and evidence; the LLM only explains those results.
- Detection is not confirmed compromise.
- Correlation is not causation.
- An HTTP 200 response is not proof of exploit success or data exfiltration.
- A successful login is not proof of account compromise.
- Absence of a successful login record is not proof that an attack failed.
- Authentication failures against multiple accounts do not prove reuse of the same credential.
- Absence of a detection does not prove safety.
- Do not infer attacker intent or attack success when the logs do not establish them.
- Keep evidence and rationale structured. A rationale must be derivable from its evidence.
- Translate security research into observable telemetry before implementation.
- MITRE ATT&CK names may be optional classification metadata, but they do not replace evidence and are not proof of detection, compromise, or causation.

## Evidence-Based Security Research

- Perform web research before implementing work that adds or changes security meaning. This includes new Detection or Correlation behavior, meaningful threshold or time-window changes, interpretation of a new log source or telemetry, changes to Risk Assessment criteria, mappings between attack techniques and observable behavior, MITRE ATT&CK mappings, and design decisions based on current security operations practice.
- Do not require web research for changes that preserve security semantics, such as simple renames, formatting, presentation-only UI/CSS work, obvious serialization fixes, mechanical migrations that retain the existing contract, or straightforward refactors.
- Prefer primary and authoritative sources: MITRE ATT&CK, CISA, NIST, official vendor or product documentation, and official security research from the relevant provider. For implementation-specific facts such as log fields, event semantics, timestamps, and authentication behavior, prefer documentation for the actual product and version.
- Use established security research or reputable academic and conference research as supporting evidence when primary sources are insufficient. Do not use personal blogs, SEO content, or unattributed detection rules as the core design basis.
- Evaluate a source by authority, publication or update date, current technical validity, product or log-version relevance, and whether its claims map to available telemetry. Recency alone does not override more applicable official documentation.
- Do not copy research findings directly into code conditions. Map them through required telemetry, repository fields and events, deterministic conditions, structured evidence, and a bounded conclusion.
- If required telemetry is unavailable, explain the gap, the parser or schema extension needed, and what the current data can establish. Do not implement the behavior as though it were observable.
- Do not present thresholds or time windows as authoritative without evidence. Distinguish standards or official recommendations, vendor guidance, research-informed heuristics, and project evaluation heuristics. When no universal value exists, identify the value as configurable and explain false-positive and false-negative tradeoffs.
- Completion reports for researched security work must include a substantive Research Basis, an Observable Evidence Mapping, and Limitations. A list of links alone is insufficient.

## Coding Conventions

- Read the existing implementation and identify related contracts and consumers before changing code.
- Prefer small functions and explicit data flow.
- Keep the structure simple and appropriate for the current project size.
- Avoid unnecessary frameworks, base classes, registries, generic abstractions, and abstractions that hide security conditions or thresholds.
- Respect the existing internal dataclass and API Pydantic boundary. If it changes, inspect and update its consumers.
- Use timezone-aware datetimes.
- Do not modify unrelated files.
- Preserve existing user changes in the working tree.
- Explain the reason and impact before a large refactor.
- Add a dependency only when it is necessary.
- Follow the existing Python style. Do not introduce a formatter or linter policy without an explicit decision.

## Contracts and Migrations

- Before changing a schema or return structure, find its producer and every consumer.
- Check the pipeline, risk assessment, reports, API, UI, LLM adapters, fixtures, and tests as applicable.
- Do not revert an intentional architecture improvement merely because an old test expects the previous contract.
- When a contract change is intentional, migrate the implementation and tests consistently to the new contract.
- Do not add dual contracts or temporary compatibility layers without a demonstrated need and a removal condition.
- State the reason and limitations when changing existing security semantics.

## Testing

Use pytest through uv:

```bash
uv run pytest
```

- Run the test suite before a change to establish the baseline.
- Distinguish pre-existing failures from failures introduced by the change.
- During development, run the closest relevant tests.
- Run the full regression suite before completing a change.
- Do not weaken assertions, remove meaningful tests, delete functionality, or add unconditional skips or xfails merely to make tests pass.
- Do not restore an obsolete architecture only to satisfy old tests.
- Report tests that could not run and any remaining failures honestly.

## Dependency Management

- Manage the Python environment and dependencies with uv.
- Use `uv add` to add dependencies and the appropriate development dependency group for development-only tools.
- Use `uv remove` to remove dependencies.
- Use `uv sync --dev` to synchronize the development environment.
- Keep `pyproject.toml` and `uv.lock` consistent.
- Do not edit `uv.lock` manually.
- Do not add a dependency when the standard library or an existing dependency is sufficient.

## Secrets and Data Safety

- Do not read, print, expose, or commit `.env` values, API keys, tokens, or credentials.
- Protect `.env` and `.env.*` files.
- Do not place real credentials or sensitive operational logs in sample logs or test fixtures.
- Consider sensitive-data exposure before including raw logs in errors or LLM prompts.
- Do not add transmission of logs to an external AI or API without an explicit design decision.

## Repository Safety and Completion Reports

- Do not use destructive Git commands.
- Do not commit or push unless explicitly requested.
- On completion, explain:
  - what the problem was;
  - why the chosen change was made;
  - which files changed;
  - how the analysis structure or contract changed;
  - which tests ran and their results;
  - which limitations remain.
