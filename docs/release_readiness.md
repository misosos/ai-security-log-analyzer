# Repository Release Readiness

## Decision scope

This audit evaluates the repository at commit `07863a0ce570ad1d6d32a479c8dae954779d9383` before the documentation/entry-point corrections in this release commit. It verifies deterministic repository behavior in the locked development environment. It does not approve any Linux host, certificate, firewall, proxy, service account, journald policy, secret store, or operational process.

Status meanings:

- **Repository verified**: implementation and automated tests establish the stated repository contract.
- **Reference only**: a reviewed artifact exists but is not installed or exercised as a real service.
- **Host acceptance required**: the control depends on the target Linux host or operator policy.
- **Intentionally unsupported**: the repository deliberately provides no such facility.

## Evidence matrix

| Area | Repository evidence | Automated verification | Current status | Remaining operator validation |
|---|---|---|---|---|
| Dependency lock | `pyproject.toml`, `uv.lock`, Python `>=3.12` | `uv lock --check`; locked import/compile smoke | Repository verified | Run the organization's approved vulnerability/license review without changing the lock implicitly. |
| Imports and startup | `app.api:app`, `app.main`, production factories | Import smoke; default API and factory tests | Repository verified | Confirm the target interpreter, filesystem layout, and service working directory. |
| Default CLI | `uv run python -m app.main`; root wrapper delegates to it | Real synthetic CLI execution and CLI tests | Repository verified | Supply only approved logs and protect terminal/report output. |
| Linux Audit CLI | Repeatable `--linux-audit PATH` plus aggregate process review | Real two-fixture execution; parser/fixture/privacy tests | Repository verified | Bound host input size and protect lifecycle correlation identities printed by the general report. |
| Default API | `/api/health`, `/api/analyze` with three optional multipart fields | API/OpenAPI and cleanup tests | Repository verified | Keep it on a trusted development boundary; it has no authentication and is not production approved. |
| Gated Linux Audit API | Default absent; explicit `/api/analyze-linux-audit` composition | Endpoint, fixture, projection, error, and isolation tests | Repository verified | Use only the production composition behind the approved edge. |
| Authentication / authorization | Canonical bearer validator and `linux-audit:analyze` permission | Fixed 401/403, digest-comparison, non-disclosure tests | Repository verified | Generate, deliver, inventory, rotate, and revoke the credential operationally. |
| Upload bounds | Four files, 10 MiB each, 20 MiB total, 64 KiB reads | Boundary, archive/binary, duplicate, cleanup tests | Repository verified | Enforce the 24 MiB edge envelope before framework multipart parsing. |
| Concurrency | Per-app non-queuing limiter, configured range 1–4 | Deterministic capacity/cancellation/isolation tests | Repository verified | Measure memory/CPU; account for workers and replicas multiplying capacity. |
| Access audit | Immutable allowlisted event and exactly one terminal attempt | Category, privacy, sink-failure, cancellation tests | Repository verified | Define audit-store ownership, monitoring, access, integrity, incident hold, retention, and deletion. |
| Secret bootstrap | Absolute private regular file, bounded read, existing token validator | Filesystem, permissions, encoding, race-reduction tests | Repository verified | Validate real ownership, parent directory permissions, systemd delivery, and rotation procedure. |
| Journald sink | Explicit fixed-field native adapter; no fallback | Projection, transport failure, cancellation, close tests with fakes | Repository verified | Verify real journald acceptance, storage bounds, persistence, forwarding, reader access, and loss alerts. |
| Lifespan / readiness | Production-owned sink and `/internal/readiness` | State transition, isolation, failure, no-OpenAPI tests | Repository verified | Restrict probe to loopback; test graceful and abrupt termination behavior on Linux. |
| systemd reference | `deploy/systemd/ai-security-log-analyzer.service` | Static directive and cross-layer contract tests | Reference only | Run `systemd-analyze verify`, install deliberately, inspect sandbox and loopback binding. |
| Nginx reference | `deploy/nginx/ai-security-log-analyzer.conf` | Static route/TLS/resource/cross-layer tests | Reference only | Run `nginx -t`, load real certificates, scan TLS, verify public denials and upstream behavior. |
| Privacy | Count-only dedicated response, bounded errors/audit, no Linux Audit LLM input | Canary, repr, OpenAPI, CLI/API and cleanup tests | Repository verified | Control access to CLI output, application logs, journal, crash reports, backups, and uploaded source files. |
| Temporary cleanup | Context-managed upload staging and lifespan ownership | Success/failure/cancellation cleanup tests | Repository verified | Inspect behavior under SIGKILL, power loss, filesystem exhaustion, and host crash. |
| LLM isolation | Optional Gemini explanation functions are not wired to CLI/APIs | Provider-not-called and Linux Audit input-isolation tests | Repository verified | If invoked separately, approve provider/data policy and configure credentials outside Git. |
| Regression suite | Security semantics, consumers, deployment and CI contracts | 1,150 tests pass after CI changes | Repository verified | Require the first remote GitHub Actions run to pass, then re-run on the supported host before promotion. |
| Frontend / streaming / detailed evidence | No implemented frontend, streaming ingestion, or protected detail API | Empty placeholders are not imported; route inventory | Intentionally unsupported | Design separately before claiming or exposing these capabilities. |
| Real Linux production host | Not represented by the macOS repository test environment | Static references and deterministic fakes only | Host acceptance required | Complete every item in the deployment acceptance checklist. |

## Acceptance evidence

- The default CLI completed with the repository's application, OpenSSH, and web fixtures and produced the existing per-IP detection, correlation, and risk report.
- The repeatable Linux Audit CLI completed with the shared-memory and session/process synthetic fixtures. It reported 32 process observations with outcomes 28/2/2, 6 shared-memory observations, 2 session co-observations, and 5 session-linked process observations with outcomes 3/1/1.
- The default API route set remained exactly `/api/health` and `/api/analyze`; the Linux Audit and readiness paths remained absent from its OpenAPI document.
- The secured production-app tests exercised explicit authentication, authorization, bounded staging, non-queuing concurrency, terminal access audit, count-only response projection, readiness, and sink ownership using deterministic fakes. They did not contact Gemini or require systemd, journald, Nginx, root, or a network listener.
- Deployment artifact tests match the application endpoint, readiness path, credential filename, environment names, loopback/proxy trust, 24 MiB edge envelope, one worker, capacity one, endpoint-only proxying, and public route denials.

## Audit findings and technical debt

The release audit corrected two misleading repository entry surfaces: the root launcher no longer prints a scaffold greeting and now delegates to the supported CLI, and package metadata no longer uses a placeholder description. The root README was empty and is now the bounded operator/developer entry point.

Two warnings remain in the locked test environment. They originate from installed dependency code, not repository calls: FastAPI's `TestClient` re-export warns that the current Starlette/httpx integration is deprecated in favor of `httpx2`, and Starlette refers to a deprecated AnyIO `BlockingPortal` alias. They are not current functional failures. Do not suppress them globally; evaluate a mutually supported FastAPI/Starlette/httpx migration in a dedicated dependency-update change with the full API/security suite.

The direct `pandas` dependency has no current import in `app/` or `tests/`. It predates this audit and is not a deployment dependency introduced by the Linux Audit work. Removal should be a separate dependency-contract decision followed by lock regeneration and full regression, rather than an unreviewed release-doc change.

Tracked empty placeholders remain at `frontend/`, `docs/architecture.md`, `docs/evaluation.md`, and `app/detector/suspicious_file.py`. They are neither imported nor advertised as implemented. Ignored local bytecode and Finder metadata are not tracked release artifacts.

No new detection, correlation, threshold, time window, risk semantic, ATT&CK mapping, response evidence, or LLM data flow was introduced by this audit.

## Repository CI boundary

`.github/workflows/ci.yml` now enforces the locked repository contract for pull requests, pushes to `main`, and manual runs. It has `contents: read` permission only, uses one bounded Ubuntu 24.04 job, pins Python 3.12.7 and uv 0.11.26, disables dependency caching, compiles the project and tests, runs the complete suite, and verifies that tracked files did not change. The first remote run must still succeed before the release candidate is remotely verified.

The workflow does not receive application secrets, enable the production endpoint, start listeners or host services, publish artifacts, or deploy. GitHub Actions does not validate the target host's TLS, Nginx, journald persistence, firewall, credential delivery, retention, deletion, or workload capacity, and therefore cannot approve production activation.

The CI design was checked against the [GitHub Actions workflow syntax](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax), [GitHub secure-use guidance](https://docs.github.com/en/actions/reference/security/secure-use), [GitHub concurrency guidance](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/control-workflow-concurrency), [actions/checkout v7.0.1 release](https://github.com/actions/checkout/releases/tag/v7.0.1), [setup-uv v10.2.0 release](https://github.com/astral-sh/setup-uv/releases/tag/v10.2.0), and [Astral's GitHub Actions integration guide](https://docs.astral.sh/uv/guides/integration/github/), accessed 2026-10-07. Full action SHAs were verified directly against the official repository tags.

## External activation gate

Before any production activation, the accountable operator must complete the checklist in [Linux Audit API deployment security](linux_audit_api_deployment_security.md), including at least:

- dedicated service identity, deployment-root ownership, and private credential source;
- credential generation, delivery, rotation, emergency revocation, and rollback;
- certificate issuance/renewal, TLS scan, firewall and loopback-only Uvicorn verification;
- trusted proxy header handling and public route-denial checks;
- live 401, 403, 413, 429, audit-failure, restart-loop, and successful fixture acceptance across TLS;
- real journald allowlist, loss, persistence, forwarding, integrity, access, backup, retention, deletion, and incident-hold checks;
- graceful restart/shutdown plus abrupt termination and staging-remnant inspection;
- peak memory, CPU, temporary storage, latency, connection, rate, and concurrency measurements;
- monitoring, alerting, incident-response ownership, rollback, and release evidence approval.

Repository release candidate: **PASS**

Production Linux host activation: **NOT APPROVED until the external checklist is completed**
