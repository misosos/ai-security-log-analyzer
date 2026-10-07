# AI Security Log Analyzer

AI Security Log Analyzer normalizes several log formats, applies deterministic detections and correlations, assesses per-source-IP risk, and presents evidence with explicit uncertainty. It is intended for learning, review, and bounded operational analysis—not as an autonomous incident verdict. An observation, detection, correlation, successful login, or HTTP 200 response is not by itself proof of compromise, causation, exploit success, or data exfiltration.

## What it currently does

The implemented pipeline is:

```text
logs → loading and normalization → detection → correlation
     → per-IP risk assessment → report or API projection
```

Supported inputs and analysis are:

- Application authentication logs in the repository's timestamped `LEVEL EVENT key=value` format.
- OpenSSH authentication records for accepted and failed password/public-key activity.
- Common/combined-style web access records.
- Linux Audit compound events grouped by source, node, and Audit event ID, including authentication/session records and process telemetry assembled from `SYSCALL`, `EXECVE`, `PROCTITLE`, `CWD`, and `PATH` records.
- Deterministic brute-force, password-spraying-like, and decoded path-traversal observations.
- Authentication failure-to-success, detection-to-success, multi-IP authentication, Linux Audit session lifecycle, login/start co-observation, and session/process co-observation relationships. Correlation is not causation.
- A shared-memory privileged-execution review count when a successful root-context syscall and an executable below `/dev/shm/` or `/run/shm/` are co-observed. This does not establish malware, a unique process, or compromise.
- Per-IP `LOW`, `MEDIUM`, or `HIGH` risk derived from separate likelihood and impact inputs, with a separate confidence assessment and evidence-based rationale. Global correlations are not automatically added to an IP's risk.

Gemini support exists as an optional explanation boundary in `app/analyzer/llm.py`. It can build prompts only from deterministic per-IP results and cannot create or alter detections, correlations, evidence, or risk. It is not called by the CLI, the default API, or the secured Linux Audit API. Linux Audit process/session/shared-memory telemetry is excluded from LLM input.

## Architecture

| Layer | Responsibility |
|---|---|
| Loader | Reads configured files and groups Linux Audit compound records; it does not detect attacks. |
| Parser | Normalizes source fields and timezone-aware timestamps without inventing unavailable facts. |
| Detector | Applies explainable, deterministic conditions and returns structured evidence. |
| Correlation | Relates observable events by explicit scope and time; per-IP and global results remain separate. |
| Risk | Assesses likelihood, impact, confidence, and account context without treating context alone as a detection. |
| Report / LLM | Prints deterministic results or optionally explains them; the LLM is not an analysis authority. |
| API | Exposes the legacy analysis contract and, only through explicit production construction, a count-only Linux Audit contract. |
| Production boundary | Adds bearer authorization, bounded staging, concurrency, access audit, secret bootstrap, readiness, and reference systemd/Nginx controls. |

## Requirements and setup

- Python 3.12 or newer, as declared in `pyproject.toml`.
- [uv](https://docs.astral.sh/uv/) for the locked environment.
- Linux, systemd, journald, Nginx, certificates, and host policy are required only for the reference production deployment of the secured Linux Audit API. Development and unit tests are supported without those services through deterministic fakes.

```bash
git clone <repository-url>
cd ai-security-log-analyzer
uv sync --dev
uv run pytest
```

No production secret belongs in Git, `.env`, a command argument, or this README.

## CLI

Run the synthetic default application, SSH, and access-log analysis:

```bash
uv run python -m app.main
```

The root compatibility entry point runs the same CLI:

```bash
uv run python main.py
```

Add one or more Linux Audit files with a repeatable option. This verified example uses repository synthetic fixtures:

```bash
uv run python -m app.main \
  --linux-audit sample_logs/linux_audit_shared_memory_execution_contract_synthetic.log \
  --linux-audit sample_logs/linux_audit_session_process_co_observation_contract_synthetic.log
```

Each supplied Linux Audit path must name a distinct, non-empty regular file. Read and validation failures return a non-zero CLI error that identifies the input position without echoing its path. Process execution, shared-memory, and session/process review output is aggregate-only: it does not print argv, executable paths, CWD, `PROCTITLE`, raw process records, PID, UID, or GID. The broader CLI report can print synthetic authentication/session correlation fields such as account, Audit session ID, and timestamps; do not treat the CLI as an identity-free interface.

## Default development API

Start the default development application with:

```bash
uv run uvicorn app.api:app --reload
```

Its application routes are:

- `GET /api/health`
- `POST /api/analyze`, accepting optional multipart fields `application_file`, `ssh_file`, and `access_file`

Each legacy upload is a non-empty `.log` or `.txt` file no larger than 10 MiB. The response contains per-IP results, global correlations, and `ai_summary: null`; it does not call Gemini. This legacy endpoint has no authentication and is not approved as a public production service.

The default app does **not** register `/api/analyze-linux-audit` or `/internal/readiness`, and its OpenAPI schema contains neither route.

## Secured Linux Audit API

The dedicated `POST /api/analyze-linux-audit` route is registered only by explicit secured app construction. It requires bearer authentication, the `linux-audit:analyze` permission, an explicit audit sink, and a per-app capacity limit. The repeatable multipart field is `linux_audit_files`; staging permits at most four files, 10 MiB per file, 20 MiB total content, and reads in 64 KiB chunks. It rejects empty, duplicate, binary/archive, non-UTF-8, and unsupported inputs and cleans request-scoped temporary files.

The response contains only an analysis UUID, fixed `completed` status, and process/shared-memory/session count summaries. It never returns normalized events, argv, paths, identities, raw evidence, risk, or an AI summary, and it never calls Gemini. Capacity exhaustion is an immediate bounded 429 after authentication and authorization; there is no analysis queue. Exactly one privacy-bounded terminal access-audit attempt precedes each response.

The production factory target is:

```text
uvicorn app.deployment.asgi:create_linux_audit_api_app --factory
```

It reads only `CREDENTIALS_DIRECTORY`, `LINUX_AUDIT_API_PRINCIPAL_ID`, and `LINUX_AUDIT_API_MAX_CONCURRENT_ANALYSES`; bearer content is read only from the fixed systemd credential file `linux-audit-api-operator-token`. The production-only `GET /internal/readiness` route returns only `ready` or `not_ready`, uses `Cache-Control: no-store`, and is excluded from OpenAPI. It must remain internal.

See [Deployment security and host acceptance](docs/linux_audit_api_deployment_security.md) before using the production factory. The reference artifacts are [systemd service](deploy/systemd/ai-security-log-analyzer.service) and [Nginx configuration](deploy/nginx/ai-security-log-analyzer.conf).

## Privacy boundaries

Internally, normalized Linux Audit process events may retain syscall outcome, architecture/syscall identifiers, exit code, PID/PPID, UID/GID variants, command/executable, terminal, audit key, argv and completeness, CWD, PATH objects and completeness, `PROCTITLE`, and raw compound records. They are needed for deterministic parsing and review and must be treated as sensitive.

- The CLI projects process telemetry to fixed aggregate counts, subject to the correlation-output caveat above.
- The dedicated Linux Audit API projects only fixed counts and an analysis UUID.
- The legacy API accepts no Linux Audit upload field.
- Linux Audit process evidence is not sent to the LLM.
- API response and access-audit boundaries explicitly copy allowlisted scalars; they do not generically serialize internal objects.
- Request staging is temporary and cleaned after success, failure, or cancellation; it is not an archival store.

Never upload real sensitive logs to an untrusted deployment. Never commit credentials, production logs, private keys, or copied operational evidence.

## Testing

The final repository audit and CI contract completed **1,152 passing tests** in the locked environment. Important suites cover loaders/parsers, detections, correlations, risk, CLI/reporting, API/OpenAPI, Linux Audit staging and cleanup, orchestration, strict projection, bearer authorization, concurrency, access auditing, secret bootstrap, journald projection, application lifespan/readiness, deployment-reference contracts, and the CI workflow itself.

```bash
uv run pytest
uv run pytest -q tests/test_release_readiness_documentation.py
```

Tests use synthetic fixtures. They do not validate a real host's TLS certificates, firewall, systemd credential delivery, journald persistence/forwarding, Nginx runtime behavior, retention policy, or workload capacity.

## Continuous integration

`.github/workflows/ci.yml` runs on pull requests, pushes to `main`, and manual dispatch. A single Ubuntu 24.04 job uses immutable action SHAs, read-only repository permission, Python 3.12.7, and uv 0.11.26 with caching disabled. It checks the lock, performs a locked development sync, compiles `app`, `tests`, and `main.py`, runs the complete regression, and fails if tests modify tracked files.

CI does not receive application secrets, enable production routes, start services, publish artifacts, or approve a Linux production host. The first remote Actions run must pass before this commit is remotely verified.

## Deployment status

The repository is a release candidate; a Linux production host is **not approved** by repository tests alone. The systemd and Nginx files are reviewed references, not installed configuration. An operator must validate service identity and permissions, credential generation/delivery/rotation, TLS and certificate renewal, loopback binding, proxy-header trust, body/rate/connection limits, real journald storage and access policy, retention/deletion, graceful restart, monitoring, rollback, and load/memory behavior on the target Linux host.

The formal evidence and remaining gates are in [Release readiness](docs/release_readiness.md).

## Known limitations

- No implemented frontend and no real-time/streaming ingestion.
- File-based batch loading; large grouped Linux Audit inputs can increase memory use.
- No stable process identity across PID reuse and no process tree, ancestry, or causation model.
- No protected detailed-evidence API or raw-log retrieval endpoint.
- The limiter is process-local; workers and replicas multiply effective capacity.
- One static bearer token has no expiry, distributed revocation, or dual-token rotation window and remains replayable if stolen.
- Multipart parsing may begin before handler-level authentication/capacity checks; an upstream body limit remains mandatory.
- The journald adapter does not prove durable persistence, forwarding, retention, or exactly-once delivery.
- No automatic production activation, service installation, TLS provisioning, firewall management, or retention enforcement.
- `frontend/`, `docs/architecture.md`, `docs/evaluation.md`, and `app/detector/suspicious_file.py` are empty placeholders, not supported features.

## Documentation

- [Release readiness](docs/release_readiness.md)
- [Linux Audit process execution](docs/linux_audit_process_execution.md)
- [Shared-memory execution review](docs/shared_memory_execution_review.md)
- [Session/process co-observation](docs/linux_audit_session_process_review.md)
- [Linux Audit API boundary](docs/linux_audit_api_design.md)
- [Linux Audit API security design](docs/linux_audit_api_security_design.md)
- [Deployment security and acceptance](docs/linux_audit_api_deployment_security.md)

Security findings should include observable evidence, affected input/route, reproduction steps using synthetic data, and privacy impact. Do not include real credentials or sensitive operational logs in an issue, test, or sample.
