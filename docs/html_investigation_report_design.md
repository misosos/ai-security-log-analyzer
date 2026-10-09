# Local HTML Investigation Report Design

Phase 6.2 구현 변경: 모든 원래 HTTP path와 full query는 보고서에서 제외한다. Path Traversal의 승인된 pattern·method·status·size만 남기고 요청 경로는 고정 개인정보 보호 문구로 표시한다. Report-local 계정 별칭, standalone HTML, 6열 표와 CSP style hash `sha256-dugVI89wFmxndpbiVjFenLmRw4HSK3Dw6k21+aq5/dY=`는 유지한다. 자세한 사용자 경계는 [privacy migration](public_analysis_privacy.md)을 참고한다.

## 1. Decision and product boundary

This document defines a future, privacy-bounded investigation report for a
security analyst, SOC analyst, detection engineer, or small-team
security/infrastructure operator performing initial batch triage.

The report is a local or controlled-environment batch investigation artifact.
It is not a SIEM, EDR, real-time monitor, incident verdict engine, automatic
response system, web dashboard, or replacement for source-log review. A
detection is not confirmed compromise, a correlation is not causation, an
HTTP 200 response is not proof of file disclosure, and a successful login is
not proof of account compromise.

The initial phase produced design documentation and documentation contract
tests. The approved projection and renderer phases added the immutable
projection types, strict builder, and pure standalone renderer. The delivery
phase adds only a secure local file writer and the explicit `--html-report
PATH` CLI option. It does not add a template, frontend, route, endpoint,
JavaScript, external CSS bundle, dependency, or browser auto-open behavior.

## 2. Current architecture findings

The existing runtime path is:

```text
input files
→ source-specific loaders and parsers
→ NormalizedEvent objects
→ per-IP DetectionResult objects
→ per-IP and global correlation
→ per-IP risk assessment
→ CLI, API, or LLM consumer
```

The public analysis result has two scopes:

```text
analysis
├── results: {<ip>: per-IP analysis}
└── global_correlation: whole-input relationships
```

Each per-IP result contains features, detections, per-IP correlation,
`risk_factors`, and `risk_level`. `DetectionResult` contains
`is_detected`, `detection_type`, and a list of `Evidence`; each `Evidence`
contains `type`, scalar `value`, `source`, and optional timestamp metadata.
The risk contract keeps likelihood, impact, and confidence separate and
preserves their existing rationale.

The current CLI reads these objects directly. Its supported authentication
and path-traversal evidence is now rendered through explicit type, source,
cardinality, and value checks. The proposed HTML report may use the same
underlying evidence contract as a reference, but must not invoke the CLI,
capture stdout, or parse CLI text.

The existing general API has its own Pydantic response boundary. It explicitly
copies detection evidence but currently exposes correlation, risk factors,
and global correlation through broad dictionaries. The separate Linux Audit
API demonstrates a stricter boundary: frozen response models expose validated
counts while excluding normalized events and process details. Neither API
schema is the HTML report schema.

The LLM adapter serializes per-IP detections, risk factors, and correlation.
Linux Audit process aggregates and review summaries are intentionally kept
outside that input. The HTML report must not reuse the LLM serializer, call an
LLM, or transmit report data to any provider.

Linux Audit normalized objects can contain argv, PROCTITLE, raw records,
executables, paths, process and identity IDs, source scope, and event IDs. The
CLI and dedicated Linux Audit API already reduce these to separately supplied
aggregate/review counts for public presentation. V1 HTML may consume only
equivalent validated count summaries, never the underlying objects.

## 3. Operator workflow and V1 scope

The intended workflow is:

```text
log files
→ existing loaders/parsers
→ existing deterministic analysis
→ explicit immutable report projection
→ pure standalone HTML rendering
→ standalone local HTML file
→ analyst review
```

V1 is one UTF-8 HTML file that opens directly in a browser without an active
web server. It has no CDN, external font, external script, external image,
analytics, network request, JavaScript framework, or other remote resource.
It contains no JavaScript. Static presentation rules may be placed in one
fixed inline style block authorized by its CSP hash; there is no CSS bundle.

For the same validated projection and renderer version, output bytes must be
deterministic. V1 must not read the clock, generate a random identifier, or
derive metadata from source filenames. If report metadata is approved later,
it must be an explicit, validated projection input and its effect on
determinism must be documented. The report remains separate from both API and
LLM contracts.

## 4. Information architecture

The report is deliberately compact and text-first:

1. **Report scope and limitations** — classification, input scope, supported
   observations, and statements about what the report cannot establish.
2. **Summary cards** — exact counts defined in section 5.
3. **Investigation review table** — one row per analyzed subject.
4. **Per-IP investigation details** — one section per subject in the same
   order as the table.
5. **Detection evidence** — typed, directly observed, allowlisted values.
6. **Correlations** — supported existing event relationships only.
7. **Risk assessment reasons** — existing risk, likelihood, impact, and
   confidence values and approved existing rationale.
8. **Interpretation limits** — bounded statements tied to displayed
   observation types.
9. **Suggested next investigation steps** — static, bounded analyst actions,
   not automated conclusions or response actions.
10. **Optional Linux Audit aggregate** — count-only and present only when a
    separately validated aggregate was supplied.

Decorative charts are out of scope. A future implementation may add a visual
only when it communicates a relationship more clearly than the summary cards,
table, or short evidence lists and does not add a new metric.

## 5. Immutable report projection

The implemented projection is a route-independent contract:

```text
InvestigationReportProjection (frozen)
├── schema_version: fixed literal
├── classification: fixed "Sensitive — Security Investigation Data"
├── summary: ReportSummaryProjection
├── subjects: tuple[InvestigationSubjectRow, ...]
└── linux_audit: LinuxAuditAggregateProjection | None

InvestigationSubjectRow (frozen)
├── review_order: positive integer
├── subject_ip: canonical IP string
├── primary_detection_display_name: fixed label | None
├── notable_correlation_display_name: fixed label | None
├── review_reason: bounded fixed-format summary
├── detections: tuple[DetectionDisplayItem, ...]
├── correlations: tuple[CorrelationDisplayItem, ...]
├── risk_assessment: RiskAssessmentProjection
├── unsupported_detection_observed: bool
├── unsupported_correlation_observed: bool
├── limitations: tuple[InterpretationLimitationItem, ...]
└── next_steps: tuple[FixedNextStepItem, ...]

CorrelationDisplayItem (frozen)
├── correlation_type: supported fixed identifier
├── display_name: supported fixed label
├── account_alias: "Account " + positive integer
└── time_delta_seconds: finite non-negative number
```

Every projection object must be immutable. The builder must explicitly read,
validate, and copy each allowlisted scalar. It must not retain references to
input lists, dictionaries, dataclasses, Pydantic objects, or normalized
events. Building or rendering a report must not reorder or mutate the analysis
result, `DetectionResult`, `Evidence`, correlation objects, or Linux Audit
summaries.

The projection is separate from `NormalizedEvent`, `DetectionResult`, raw
correlation dictionaries, Linux Audit context/process objects, API schemas,
LLM input, and CLI strings. The following are prohibited at this boundary:

- `asdict()`, `vars()`, `__dict__`, or generic recursive serialization;
- arbitrary dictionary or list passthrough;
- embedding a complete internal object;
- copying unknown fields for forward compatibility;
- parsing CLI stdout;
- using `repr()` or exception text as report content.

`build_investigation_report_projection()` accepts the completed analysis and
the optional existing process aggregate, shared-memory review summary, and
session-process review summary as explicit arguments. It performs no loading,
parsing, analysis, I/O, environment access, clock access, randomness, API/LLM
call, or CLI invocation. Malformed required input fails projection with one
fixed, bounded operator message outside the HTML. It must not fall back to
dumping the rejected value or producing a partially populated report.

### 5.1 Assessment rationale

`AssessmentDimensionProjection` contains only an existing level and approved
existing rationale entries. The builder maintains a closed catalog of current
deterministic rationale text and bounded numeric templates. It copies a
rationale only after its exact/static form or typed interpolation contract is
validated. Unknown rationale is a projection contract failure; arbitrary
rationale strings are not passed through.

The report must not recalculate risk, likelihood, impact, or confidence and
must not introduce a threshold, score, ATT&CK mapping, incident label, or
success verdict.

### 5.2 Report-local account aliases

The projection builder assigns aliases across the whole report before it
builds subject projections. It first validates every account value required by
a supported positive correlation, collects the distinct exact source strings,
sorts them by their strict UTF-8 byte sequences, and enumerates that canonical
set from one:

```text
first canonical account  → Account 1
second canonical account → Account 2
…
```

This ordering does not depend on dictionary iteration, subject order, or raw
event arrival order. Exact duplicate source strings receive the same alias
everywhere in one report; distinct valid source strings receive distinct
aliases. No Unicode normalization, case folding, hashing, truncation, or
source-derived prefix/suffix is used. Consequently an alias contains no
original-name fragment, length, hash, or other reversible/stable derivative.
The same validated projection input therefore produces the same alias
assignment.

A valid account is an exact `str`, contains at least one non-whitespace
character, contains only valid Unicode scalar values, encodes with strict
UTF-8, and contains no control character. A missing or malformed account in a
supported positive correlation aborts projection with the fixed bounded
contract-failure message; it is never converted with `str()` or placed in an
error. Unsupported detection/correlation objects are not inspected for an
account value.

The allocator must verify that the number of aliases equals the number of
distinct valid accounts and that every source account resolves to exactly one
alias. An alias overwrite, duplicate alias, cardinality mismatch, or other
collision is a projection contract failure with the same bounded error. For
valid Unicode strings, strict UTF-8 is injective, so such a collision indicates
an implementation/contract defect rather than a case to resolve by guessing.

Only alias strings enter the immutable projection. The temporary source-name
to alias mapping must not be retained by the projection or renderer. Aliases
are report-local correlation references—not real identities and not stable
cross-report identifiers. Adding or removing an account may renumber aliases
in a later report.

## 6. Summary contract

`ReportSummaryProjection` has these exact fields:

| Field | Type | Meaning |
|---|---|---|
| `analyzed_subject_count` | non-negative strict integer | Number of canonical per-IP entries projected from `analysis["results"]`. |
| `high_risk_subject_count` | non-negative strict integer | Subjects whose existing `risk_level` is `HIGH`. |
| `medium_risk_subject_count` | non-negative strict integer | Subjects whose existing `risk_level` is `MEDIUM`. |
| `low_risk_subject_count` | non-negative strict integer | Subjects whose existing `risk_level` is `LOW`. |
| `supported_detection_observation_count` | non-negative strict integer | Positive, validated supported detection results across all subjects; each supported `DetectionResult` counts once. |
| `supported_correlation_observation_count` | non-negative strict integer | Positive, validated supported per-IP correlation records across all subjects; each record counts once. |
| `linux_audit_process_observation_count` | non-negative strict integer or absent | Process execution observation count from a separately supplied validated aggregate. |
| `shared_memory_review_observation_count` | non-negative strict integer or absent | Count from a separately supplied `SharedMemoryExecutionReviewSummary`. |
| `session_process_co_observation_count` | non-negative strict integer or absent | Count of qualifying session-process co-observation relations from a separately supplied `SessionProcessReviewSummary`. |

Strict integer excludes booleans. Required invariants are:

- `HIGH + MEDIUM + LOW == analyzed_subject_count`;
- summary detection and correlation counts equal the sums of the per-subject
  projected collections;
- each optional Linux Audit value is absent unless its corresponding process
  aggregate, shared-memory review summary, or session-process review summary
  was separately supplied; absence is not silently represented as zero;
- supplied Linux Audit counts are non-negative and retain existing aggregate
  invariants: process outcomes and both completeness partitions sum to the
  process count; session-process outcomes sum to their process count; and
  linked/containing counts stay within their existing process and session
  bounds. Cross-summary bounds, such as shared-memory review observations not
  exceeding process observations, apply whenever both corresponding summaries
  are supplied.

These are observation counts. They are not counts of unique attackers,
incidents, compromised systems, successful attacks, or unique processes.
`session_process_co_observation_count` is not proof of physical session
identity, direct user execution, or causation.

When at least one Linux Audit summary is supplied,
`LinuxAuditAggregateProjection` copies only these optional strict integer
counts: process observation; process success/failure/unknown; argv and path
complete/incomplete; shared-memory review observation; session-process
co-observation and process observation; session-process
success/failure/unknown; session-linked shared-memory observation; and
sessions containing a shared-memory observation. It retains no Linux Audit
event, context, process, path, identifier, or source object.

Raw `global_correlation` is excluded from V1. It contains cross-IP/account
relationships and Linux Audit scope details that require their own future
privacy projection. Therefore the V1 correlation count is explicitly a
supported **per-IP** count and global observations are neither mixed into a
subject nor used to alter risk.

## 7. Investigation review table

The exact columns are:

| Column | Contract |
|---|---|
| 조사 순서 | One-based integer assigned after deterministic sorting. |
| 분석 대상 IP | Canonical IP string. |
| 위험도 | Existing `HIGH`, `MEDIUM`, or `LOW` value, unchanged. |
| 주요 탐지 | Lexicographically first supported detection display name, or `관찰 없음`. |
| 주요 상관관계 | Lexicographically first supported correlation display name, or `관찰 없음`. |
| 신뢰도 | Existing confidence level, unchanged. |

The builder must not modify `risk_level`. Rows and detail sections use this
deterministic ascending sort key:

1. risk rank: `HIGH`, `MEDIUM`, `LOW`;
2. subjects with a supported positive correlation before subjects without;
3. confidence rank: `HIGH`, `MEDIUM`, `LOW`;
4. primary detection display name, case-insensitive lexical order, with no
   observation after a named detection;
5. canonical IP numeric order: address family, then packed address bytes.

After sorting, rows are enumerated `1..N`; that integer is `review_order` and
is displayed as `조사 순서`. It is only an operator-navigation aid. It is
not a new risk, severity, priority score, confidence value, security
conclusion, or verdict, and it must not be used by detection, correlation, or
risk logic.

Primary/notable selection is lexical presentation tie-breaking, not a claim
that one observation is more severe. The projection retains `review_reason`
for its existing contract, but the HTML table does not render it because the
six retained columns already provide the useful navigation context.

## 8. Detection and correlation display contracts

Internal identifiers remain unchanged. Display-name mappings are explicit:

| Internal identifier | Analyst-facing label |
|---|---|
| `brute_force` | `Brute Force` |
| `password_spraying_like` | `Password Spraying-like` |
| `path_traversal` | `Path Traversal` |
| `failed_to_successful_login` | `Failed Login → Successful Login` |
| `brute_force_to_successful_login` | `Brute Force → Successful Login` |

No label is guessed for an unknown identifier. A positive unsupported
detection produces only the bounded notice `Unsupported detection type was
omitted from this report.` It contributes neither evidence nor the supported
detection count. Unsupported correlations are omitted and represented by an
equivalent bounded notice; their raw identifier or values are not rendered.

### 8.1 Typed detection evidence

Evidence is matched by `Evidence.type`, never list position. Each positive
result must also have its exact expected detector source, cardinality,
distinct types, and value types validated before projection.

`BruteForceEvidenceProjection`:

| Field | Source evidence type | Type / constraint | Display label |
|---|---|---|---|
| `failed_attempt_count` | `multiple_login_failures` | non-negative strict integer | Failed attempts |
| `target_account_count` | `single_target_user` | non-negative strict integer | Target accounts |
| `time_window_seconds` | `failures_within_short_window` | finite non-negative integer or float | Time window |

The result must contain exactly these three evidence types from
`brute_force_detector`.

`PasswordSprayingLikeEvidenceProjection`:

| Field | Source evidence type | Type / constraint | Display label |
|---|---|---|---|
| `failed_attempt_count` | `multiple_login_failures` | non-negative strict integer | Failed attempts |
| `target_account_count` | `multiple_target_users` | non-negative strict integer | Target accounts |
| `time_window_seconds` | `failures_within_short_window` | finite non-negative integer or float | Time window |

The result must contain exactly these three evidence types from
`password_spray_detector`. The label must retain “-like”; this telemetry does
not establish reuse of the same password.

`PathTraversalEvidenceProjection`:

| Field | Source evidence type | Type / constraint | Display label |
|---|---|---|---|
| `matched_pattern` | `path_pattern` | approved `../` or `..\\` | Matched pattern |
| `http_method` | `http_method` | bounded uppercase token or absent | HTTP method |
| `response_status` | `http_status_code` | non-negative strict integer or absent | Response status |
| `response_size_bytes` | `http_response_size` | non-negative strict integer or absent | Response size |

The detector's optional evidence type set from `path_traversal_detector` must
validate before copying these named fields; list position is not used.
`url_decoded_path` and `url_decoded_query` are validated as internal strings
but are never copied into the report projection. Their omission must not be
represented as missing detector evidence. Seconds display with `seconds` and
response size displays with `bytes`; numeric values are not rounded or
reinterpreted.

### 8.2 Typed per-IP correlation fields

A supported correlation projection contains only:

- the mapped display label;
- the deterministic report-local account alias allocated under section 5.2;
- finite non-negative `time_delta_seconds` when supplied by the existing
  correlation;
- static interpretation limitation and next-step identifiers.

Original account names, event timestamps, correlation rationale strings,
source-IP collections, and other raw dictionary fields are not copied. Only
`is_correlated is True` records with a supported exact type and expected typed
fields qualify. Correlation remains an observed temporal/logical relationship,
not causation or proof of compromise.

## 9. Evidence, assessment, limitation, and next step

Each subject detail keeps four concepts visually and structurally separate:

- **Evidence** is a typed value directly observed in supported detector or
  correlation output: counts, durations, approved matched pattern, HTTP method,
  response status, and response size.
- **Assessment** is the existing risk, likelihood, impact, confidence, and
  their validated existing rationale. The report does not recompute it.
- **Limitation** is approved static text describing what the available logs do
  not establish. For example, HTTP status does not establish file disclosure,
  a successful login does not establish account compromise, and a
  Password Spraying-like observation does not establish credential reuse.
- **Next step** is a bounded suggestion for analyst follow-up, not a new
  detection or automatic response.

Next steps use this closed allowlist. The projection stores the fixed
`next_step_id` and its exact corresponding fixed text; a renderer must not
rewrite either value.

| Supported type | `next_step_id` | Fixed analyst-facing text |
|---|---|---|
| `brute_force` | `review_authentication_failures` | 관찰된 시간대의 인증 실패 기록을 검토하고, 해당 활동이 승인된 출발지 또는 프로세스와 일치하는지 확인하십시오. |
| `password_spraying_like` | `review_cross_account_authentication` | 관련 계정 별칭의 IdP 인증 기록을 검토하고, 예상된 관리자 또는 자동화 활동인지 확인하십시오. |
| `path_traversal` | `review_traversal_response_context` | 관찰된 요청에 대한 애플리케이션, 리버스 프록시 및 파일 접근 텔레메트리를 검토하고, 응답 내용이나 파일 접근이 기록되었는지 확인하십시오. |
| `failed_to_successful_login` | `review_login_transition` | 상관된 로그인에 대한 IdP, MFA, 장치 및 세션 기록을 검토하고, 예상된 로그인인지 확인하십시오. |
| `brute_force_to_successful_login` | `review_brute_force_login_transition` | Brute Force 관찰과 상관된 로그인 전후의 인증, MFA, 장치 및 세션 기록을 검토하십시오. |

The implemented limitation catalog is likewise fixed and type-driven. It
contains only bounded statements that detection is not compromise,
Password Spraying-like does not establish credential reuse, traversal status
does not establish file disclosure, correlation is not causation, and a
successful login does not establish account compromise. The renderer places
the three general limitations—detection is not compromise, correlation is not
causation, and successful login is not attack success—once in the report-level
scope section. Subject sections omit those generic IDs and render only the
Password Spraying-like or Path Traversal-specific limitation IDs.
The two subject-specific fixed mappings are:

- `spraying_like_not_credential_reuse` → `Password Spraying-like 관찰만으로
  동일한 인증정보가 재사용되었다고 판단할 수 없습니다.`
- `path_traversal_not_file_disclosure` → `HTTP 응답과 경로 탐색 패턴만으로
  파일 접근 또는 데이터 노출이 이루어졌다고 판단할 수 없습니다.`

Next steps use explicit report-only purpose precedence:
authentication-failure verification, cross-account authentication review,
correlated-login verification, then traversal-response review. Within the
correlated-login purpose, `review_login_transition` takes precedence over the
semantically overlapping `review_brute_force_login_transition`. The renderer
selects at most one step per purpose and at most three steps per subject while
retaining each selected projection item's fixed ID/text pair unchanged. Thus a
Brute Force plus successful-login subject shows the authentication failure
source/time-window step and the correlated login MFA/device/session step,
without also showing the overlapping composite step. Input order cannot affect
the displayed order. An unsupported type gets no next step and only the
bounded omission notice from section 8. No LLM
generates or rewrites these values, and no log text, rationale, exception, or
internal object text is copied into them. The allowlist contains no command,
system mutation, automatic block of an account/IP, claim of compromise,
malicious intent, or attack success. Every step is limited to evidence review
and verification by an analyst.

All fixed operator UI, fixed next-step guidance, and type-specific limitation
text are Korean. Established security display names and grades—including
Brute Force, Password Spraying-like, Path Traversal, `HIGH`, `MEDIUM`, `LOW`,
IdP, and MFA—remain unchanged where they are clearer. Translation is an
explicit fixed-ID/allowlist contract in the projection; neither the projection
nor renderer performs fuzzy matching or automatic translation of arbitrary
data, and no LLM is used. The renderer only applies deterministic selection,
de-duplication, and HTML escaping to projected display text. Privacy selection
and redaction remain the projection boundary's responsibility, not the
renderer’s.

Evidence values appear once in the evidence section. Existing assessment
rationale appears once in assessment. A limitation and a next step each appear
once per applicable concept; the same sentence is not copied into several
sections.

## 10. Privacy policy

Every V1 report is classified `Sensitive — Security Investigation Data`.
Excluding raw logs does not make it non-sensitive: IP addresses can identify
systems or people, and correlations can disclose behavior and relationships.

### 10.1 Allowlist

- The current subject IP is displayed because it is the report's analysis
  subject.
- Account references may be shown only through the deterministic report-local
  aliases in section 5.2. The original value and source-to-alias mapping are
  not retained in the projection. Aliases use sequential labels only; hashes
  and source-derived fragments are prohibited.
- HTTP method, status, and response size are allowed.
- The approved matched traversal pattern is allowed; the original HTTP path
  is always omitted and displayed only as a fixed privacy notice.
- Typed authentication failure/target counts and time windows are allowed.
- Existing risk, likelihood, impact, and confidence values and approved
  rationale contracts are allowed.
- Separately supplied, validated Linux Audit aggregate counts are allowed.

### 10.2 Exclusions

The following must not enter the projection or rendered HTML:

- all original HTTP request paths and full query strings;
- raw log lines;
- credentials, passwords, tokens, cookies, authorization headers, session
  identifiers, keys, or connection strings;
- Linux Audit argv, PROCTITLE, raw records, executable, PATH, CWD, PID/PPID,
  UID/GID/AUID/session ID, node, source instance, and event ID;
- normalized Linux Audit events or process/shared-memory observation objects;
- temporary paths, upload filenames, file digests, exception strings,
  `repr()` output, and tracebacks;
- original account names in HTML text, metadata, comments, element IDs, CSS
  classes, data attributes, filenames, exceptions, and renderer errors;
- arbitrary global-correlation content;
- LLM input/output or any LLM transmission.

The HTML must make no external network request. Privacy tests seed private
canaries into excluded source locations and confirm absence from the
projection, HTML, API output, and LLM input. Phase 6.2 intentionally migrates
the deprecated legacy API nested values and LLM prompt input to safe
projections; the trusted analysis calculation remains unchanged.

### 10.3 Storage, sharing, and deletion

Generate the report only in an operator-selected, access-controlled local
directory. Use restrictive directory access and create the final file with
owner-only permissions where the platform supports them. Do not place it in a
web root, broadly synchronized folder, public issue, chat, or source-control
tree. Share only with authorized recipients through an organization-approved
protected channel, and remind recipients that copied files retain the same
classification.

Retention and deletion follow the organization's legal, regulatory,
contractual, evidence-preservation, and incident-response requirements. This
design intentionally defines no universal retention duration. When authorized
retention ends, remove the report and managed copies/backups using the
organization's approved deletion process. Consider browser download/history,
recent-file lists, backups, and synchronized copies when handling the file.

## 11. Rendering security contract

`app.analyzer.html_report.render_investigation_report_html()` accepts only the
exact `InvestigationReportProjection` runtime type and returns one complete
HTML document as `str`. It performs no file, environment, clock, randomness,
network, analysis, CLI, API, or LLM access and does not mutate the projection.
It uses `\n` for every line ending and includes one final newline, so the same
projection and renderer version produce byte-identical UTF-8 encoding.

All report-derived text is untrusted and must be escaped for its exact HTML
text context before insertion. No report data may be inserted as HTML, URL,
CSS, JavaScript, tag name, attribute name, event handler, or unquoted
attribute. There is no unsafe HTML passthrough and no inline event handler.

Use `<!doctype html>`, `<html lang="ko">`, and an early
`<meta charset="utf-8">`. Add a meta-delivered CSP before the static style
block. The required policy shape is:

```text
default-src 'none';
base-uri 'none';
form-action 'none';
object-src 'none';
script-src 'none';
script-src-attr 'none';
style-src 'sha256-dugVI89wFmxndpbiVjFenLmRw4HSK3Dw6k21+aq5/dY=';
style-src-attr 'none';
img-src 'none';
font-src 'none';
connect-src 'none';
media-src 'none';
frame-src 'none';
worker-src 'none';
manifest-src 'none'
```

The renderer calculates the reproducible SHA-256 hash from the UTF-8 bytes of
its exact, constant inline style block and places that digest in the fixed
policy above. The hash authorizes only those renderer-owned CSS bytes; any CSS
change necessarily changes the digest. Projected or other dynamic data never
enters CSS, so the style hash cannot authorize data-derived style content. Do
not add `report-uri`/`report-to`, because CSP reporting would make a network
request.
Do not claim `frame-ancestors` or `sandbox` protection from the meta policy;
browsers do not support those directives in `<meta>`. The file has no forms,
links requiring network access, scripts, media, frames, manifests, or images.
Add `<meta name="referrer" content="no-referrer">` as defense in depth.

Sensitive values must not appear in HTML comments, metadata, titles derived
from input, element IDs, CSS classes, `data-*` attributes, filenames, or source
maps. Fixed structural IDs/classes may be used only when they contain no input
or sensitive value. CSP and escaping reduce rendering risk; neither makes the
report non-sensitive.

Rendering failure raises `InvestigationReportRendererError` with one fixed
bounded message, never internal exception text, rejected fields, or object
dumps. The renderer does not write a file.

`app.analyzer.html_report_file` implements the separate filesystem boundary.
`validate_html_report_target()` accepts an exact CLI string without expanding
environment variables or `~`. V1 accepts relative and absolute paths, rejects
empty values, `..` components, `~`-prefixed components, and every suffix other
than exact lowercase `.html`. Every explicitly supplied parent component must
already be a real directory and not a symlink. The destination must not exist,
including as a broken symlink, directory, FIFO, socket, or device; missing
parents are not created.

`write_investigation_report_html()` accepts only an exact `str` and a frozen
`ValidatedHtmlReportTarget`. It encodes strict UTF-8, creates one private
temporary sibling, applies mode `0600` where supported, writes without newline
conversion, flushes and file-`fsync`s, then uses a same-directory hard link to
publish the complete inode under the requested name without replacing an
existing entry. The temporary name is removed after publication. A write or
publication failure raises `InvestigationReportFileError` with one fixed
path-free message and performs bounded cleanup of only the known temporary
file and, when applicable, the just-published same inode. It never logs HTML,
paths, or internal exception text and never retries creation.

This is the strongest no-overwrite publication contract implemented with the
portable Python standard-library operations available to this project; a
filesystem that does not support the required hard link fails closed. It does
not eliminate every time-of-check/time-of-use race: an ancestor or parent can
be replaced after validation on a concurrently modified filesystem, and the
directory entry itself is not directory-`fsync`ed. Operators must select an
access-controlled directory that untrusted users cannot rename or modify.

## 12. Empty, unsupported, and malformed states

The exact bounded presentation semantics are:

| State | Presentation |
|---|---|
| No supported detections | `지원되는 탐지 관찰 없음` followed once by `이는 악의적 활동의 부재를 입증하지 않습니다.` |
| No supported per-IP correlations | `지원되는 상관관계 없음` followed by the same bounded absence limitation only if it has not already appeared in the report-level section. |
| No Linux Audit input/aggregate | Omit Linux Audit cards and section; state `이 보고서에는 Linux Audit 집계가 제공되지 않았습니다.` in report scope. |
| Supplied Linux Audit aggregate with zero observations | Show explicit zero counts and `제공된 집계에서 Linux Audit 프로세스 관찰이 생성되지 않았습니다.` |
| Unsupported detection/correlation | Show only the bounded omission notice defined in section 8; do not show the unknown identifier or evidence. |
| Malformed internal input or projection | Abort report creation, remove partial output, and return a fixed projection/rendering failure message outside the HTML. |

Empty-state language must not characterize the system as benign or issue an
incident/compromise verdict. Absence of a supported observation is limited to
the analyzed input and current deterministic rules.

## 13. Compact wireframe

```text
┌─────────────────────────────────────────────────────────────────────┐
│ Local Security Investigation Report       SENSITIVE                 │
│ Scope • limitations • Linux Audit aggregate supplied/not supplied   │
├─────────────────────────────────────────────────────────────────────┤
│ Subjects │ HIGH │ MEDIUM │ LOW │ Detections │ Correlations          │
│ [optional: process obs │ shared-memory obs │ session-process obs]   │
├─────────────────────────────────────────────────────────────────────┤
│ INVESTIGATION REVIEW                                                │
│ Order │ Subject/IP │ Risk │ Primary detection │ Correlation │ Conf. │
│ 1     │ 192.0.2.10 │ HIGH │ Brute Force       │ Brute…Login │ HIGH  │
├─────────────────────────────────────────────────────────────────────┤
│ SUBJECT: 192.0.2.10                                                 │
│ Evidence          │ Assessment                                      │
│ Failed attempts 5 │ Risk HIGH • Likelihood HIGH • Impact …          │
│ Targets 1         │ Existing validated reasons                      │
│ Window 16 seconds │                                                  │
│ Correlation: Brute Force → Successful Login • Account 1             │
│ Limitations: relationship is not causation or proof of compromise   │
│ Next steps: review approved identity-provider/MFA/device telemetry  │
├─────────────────────────────────────────────────────────────────────┤
│ OPTIONAL LINUX AUDIT AGGREGATE — counts and limitations only        │
└─────────────────────────────────────────────────────────────────────┘
```

Details may use native `<details>`/`<summary>` for low-density expansion
without JavaScript. All subject details remain present in the file and follow
the deterministic table order.

## 14. Implementation boundary and sequence

The approved delivery sequence is:

1. **Implemented in the projection phase:** frozen, route-independent
   projection types and a strict builder that copies only the scalar allowlist
   in this document.
2. **Implemented in the projection phase:** projection unit tests, privacy
   canaries, ordering/count invariants, non-mutation tests, and API/LLM
   isolation tests.
3. **Implemented in the renderer phase:** a pure renderer from the immutable
   projection to deterministic UTF-8 standalone HTML, with escaping, CSP, and
   no-network tests.
4. **Implemented in the delivery phase:** strict output validation, private
   temporary-file creation, restrictive permissions, bounded failure cleanup,
   and no-overwrite hard-link publication.
5. **Implemented in the delivery phase:** `--html-report PATH` reuses the
   existing normalized logs, analysis, and optional Linux Audit count-only
   summaries. It builds the projection once, renders once, writes once, then
   prints the privacy-hardened text report followed by the fixed confirmation
   `HTML investigation report created.`

The file is finalized before any text report is printed. Projection,
rendering, or file-creation failure therefore exits non-zero with the fixed
message `HTML investigation report could not be created.` and prints no
partial text report. The CLI never prints HTML or the destination path, never
opens a browser, and does not call the LLM. Omission of `--html-report`
preserves the existing CLI flow while withholding raw account/path/query text.

Usage is explicit:

```bash
uv run python -m app.main --html-report investigation.html
```

Automated tests parse the resulting standalone document and verify its CSP,
structure, content boundaries, and absence of remote resources. No compatible
browser automation tool was available in the verified development environment,
so actual browser/CSP-console and narrow-viewport acceptance was not performed
or claimed.

V1 does not add a web dashboard, active server, API route, existing-response
field, LLM integration, JavaScript, or frontend framework.

## 15. Test plan

Projection, renderer, filesystem, and CLI tests cover the applicable items
below:

- exact projection fields and rejection of extra/internal fields;
- deterministic subject, detection, and correlation ordering and tie breaks;
- risk-count partition and detail-to-summary count invariants;
- every supported detection/correlation display mapping;
- evidence matched by type rather than position;
- strict cardinality, source, value-type, finite-number, and bool rejection;
- same-account alias consistency and different-account alias separation;
- alias assignment independent of subject, dictionary, and event input order;
- malformed-account and alias-collision bounded failure behavior;
- no account hashes/fragments and no original-name privacy canary in HTML,
  metadata, comments, IDs, classes, data attributes, filenames, or errors;
- exact fixed next-step mappings for every supported detection/correlation,
  stable de-duplication/order, unsupported-type omission, and privacy-canary
  exclusion from next-step text;
- full query, raw log, credential/token/cookie/header, Linux Audit private
  field, path/filename/digest, exception, traceback, and private-canary
  exclusion;
- HTML text/attribute escaping using adversarial Unicode and markup payloads;
- exact CSP shape, valid static-style hash, no remote resource, no JavaScript,
  no event handler, and no report/CSP network endpoint;
- Phase 6.2 intentionally changes the deprecated legacy API nested schema and
  LLM prompt input to privacy-safe projections; versioned case JSON remains
  unchanged apart from the report HTML payload's fixed path notice;
- no input object/list/dictionary mutation;
- byte-for-byte deterministic rendering for the same projection;
- restrictive file permissions where supported;
- removal of temporary/partial output after projection, rendering, write,
  flush, and finalization failure;
- every empty, zero, unsupported, and malformed state in section 12;
- the complete existing regression suite.

Documentation contract tests should protect these decisions by section and
key invariant. They should not require every prose sentence or freeze harmless
wording.

## 16. Research basis

Sources were accessed on **2026-10-07**. External sources inform rendering and
handling safeguards only; they do not define this project's detection,
correlation, risk, evidence, count, sorting, or display-name semantics.

| Organization / source | Publication or update | Guidance used | Effect on this design |
|---|---|---|---|
| OWASP, [Cross Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html) | Living official cheat sheet; page does not state a publication date | Untrusted values require context-appropriate output encoding; variables should not be placed in script, comment, style, tag-name, or other dangerous contexts. | All projected text is HTML-escaped into text nodes only; data is prohibited from comments, CSS, scripts, URLs, tag names, and attribute names. |
| OWASP, [Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) | Living official cheat sheet; page does not state a publication date | Tokens, passwords, secrets, some personal data, paths, and internal addresses require exclusion or special handling; logs need restricted access, output encoding/sanitization, protected storage, and policy-driven disposal. | The report uses a scalar allowlist, report-local account aliases, explicit exclusions, owner-restricted storage guidance, controlled sharing, and organization-specific retention/deletion. |
| MDN, [`default-src`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/default-src), [`style-src`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/style-src), [`script-src`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/script-src), and [`<meta http-equiv>`](https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/meta/http-equiv) | `default-src` last modified 2025-07-04; other pages are living MDN references | `default-src 'none'` blocks resource loading by default; scripts can be disabled; an exact inline style block can be hash-authorized; a standalone file can carry CSP in a meta element. | V1 has a deny-by-default meta CSP, no scripts/network resources, and one deterministic hash-authorized static style block. Unsupported meta directives are not claimed. |
| NIST, [SP 800-92, Guide to Computer Security Log Management](https://csrc.nist.gov/pubs/sp/800/92/final) | Published 2006-09; final history 2006-09-13 | Organizations need sound, maintained log-management practices; guidance covers infrastructure and robust processes rather than prescribing one universal implementation. | Storage, access, sharing, retention, and deletion are explicitly governed by the operator's organizational requirements; this project does not invent a universal retention period. |

## 17. Design limitations

V1 intentionally omits raw global correlations, raw evidence queries, account
identifiers, Linux Audit details, and timelines. This reduces investigative
context and means the analyst must return to protected source systems for
deeper review. Report-local aliases do not anonymize the report because
subject IPs, counts, risk, and relationships remain sensitive. Static next
steps cannot
replace local operating procedures or evidence preservation requirements.

The report does not improve telemetry coverage and cannot establish facts the
current logs do not contain. Normal administration, shared addresses, proxies,
NAT, scanners, shared accounts, and health checks may resemble observed
patterns; missing or manipulated logs may hide activity. No threshold or time
window changes are proposed in this design.
