# Linux Audit API Production Deployment Security Contract

## 1. Purpose, scope, and current deployment gap

This document defines the production deployment contract for the default-disabled `POST /api/analyze-linux-audit` endpoint. It is a design and acceptance plan, not a deployed configuration. The boolean feature gate is not authentication, and neither the gate nor the application bearer check replaces the network, TLS, resource, secret, or audit controls in this document.

Repository inspection on 2026-10-07 found no startup command in the empty `README.md`; no Dockerfile, Compose, Kubernetes, systemd, Nginx, Caddy, ingress, TLS, CORS, `TrustedHost`, proxy-header, rate-limit, readiness, or deployment workflow configuration; and no `.env.example`. `uvicorn` and `python-dotenv` are dependencies, but no production host, port, worker count, TLS termination, proxy trust, or secret-delivery policy is configured. The only health route is public `GET /api/health`, which returns `{"status": "ok"}` and does not establish readiness.

The current application contract is narrower and already implemented:

- `create_app()` leaves the Linux Audit endpoint absent by default.
- Enabling requires an exact `LinuxAuditApiSecurityConfig` and explicit async `LinuxAuditApiAccessAuditSink`; contradictory or missing inputs fail during app construction.
- The endpoint requires bearer authentication and `linux-audit:analyze` authorization.
- Staging accepts at most four files, 10 MiB per file and 20 MiB total staged content using 64 KiB reads.
- Each app instance owns a non-queuing limiter with `max_concurrent_analyses` in the range 1–4.
- One privacy-bounded terminal access-audit emission is attempted before each application response; sink failure replaces the pending response with a fixed 500.
- Raw uploaded Linux Audit files remain request-scoped and are not retained by the application.

Production activation remains prohibited until every control in the Section 13 checklist has an owner and passes acceptance testing; Section 16 assigns the threat-specific ownership boundary.

## 2. Deployment topology comparison and V1 selection

| Option | TLS and public binding | Early resource controls | Proxy trust and auditability | Operations and scaling | Residual risk |
|---|---|---|---|---|---|
| A. Public Uvicorn | Uvicorn would own public TLS or expose plaintext if misconfigured | Uvicorn has connection/task limits, but no repository contract for multipart edge rejection or endpoint rate policy | No separate trust hop, but certificate renewal, public hardening and access logging move into the app service | Simple locally; broadens the application server's production responsibility | A mistaken `0.0.0.0` or TLS option exposes the bearer endpoint directly; rejected for V1 |
| B. Loopback Uvicorn behind Nginx | Nginx owns public TCP/443 and TLS; Uvicorn binds loopback only | Nginx can reject body, header, slow-client, rate and connection excess before FastAPI | Exact loopback proxy addresses can be allowlisted; edge and application audits remain separate | One host and systemd are practical for the current small repository; worker multiplication is explicit | Host compromise affects both tiers; Nginx configuration and certificate automation require operator ownership |
| C. Uvicorn behind Caddy or another managed-TLS proxy | Managed certificate acquisition and renewal reduce certificate operations | Body and connection controls vary; rate limiting may require plugins or a separate gateway | Still requires exact proxy trust and header stripping | Attractive for a small service, but the repository has no chosen plugin/version contract | Plugin provenance and feature differences complicate a deterministic first acceptance suite |
| D. Containerized app behind ingress/API gateway | Platform ingress normally owns TLS and public exposure | Mature gateways can enforce distributed body/rate/connection policy | Trust depends on ingress identity, network policy and stripped headers | Fits replicas and managed secrets, but no container or orchestrator exists here | Misconfigured ingress, replica multiplication and platform complexity exceed the current V1 footprint |

The V1 reference topology is:

```text
Operator client
→ public Nginx TLS listener
→ loopback-only Uvicorn, one worker
→ explicitly enabled and secured FastAPI app
→ app-local limiter and explicit journald audit sink adapter
```

Nginx is selected because its official modules cover the required TLS, body, header, timeout, request-rate and connection controls without adding application code. This is a reference deployment, not a claim that Nginx alone makes the service secure. Uvicorn must never be publicly bound in this topology.

## 3. Network binding and TLS contract

### Public and private listeners

- Nginx alone owns the public listener on TCP/443.
- Uvicorn binds only to `127.0.0.1` on a fixed non-public port. A later Unix-domain-socket variant is acceptable after equivalent permission and proxy-header tests.
- Host firewall policy denies remote access to the Uvicorn port even if a future service command is accidentally broadened.
- Public plaintext HTTP is disabled. If a platform requires a port-80 listener, it rejects API requests without redirecting the bearer-bearing request. A redirect is not relied on because the credential has already crossed the plaintext connection.
- The proxy-to-Uvicorn hop may use plaintext HTTP only while both processes share one controlled host and Uvicorn is loopback/firewall restricted. A private container or cross-host hop requires TLS or mTLS appropriate to that boundary.

### TLS profile

- TLS 1.3 is preferred and TLS 1.2 is the minimum compatibility version. SSLv2, SSLv3, TLS 1.0 and TLS 1.1 are disabled.
- Cipher and curve configuration follows a reviewed current Mozilla/OWASP-compatible profile for the installed Nginx and TLS-library versions; this document does not freeze a cipher list that will become stale.
- The deployment owner obtains and renews a certificate for the exact public DNS name and monitors renewal and expiry. Failure to load a valid certificate or private key prevents the public listener from starting.
- Certificate private keys are owned by the deployment administrator, readable only by the Nginx master/service identity that requires them, and never committed to the repository. The public certificate is not secret.
- HTTPS responses use `Cache-Control: no-store`. HSTS is enabled only after HTTPS and certificate renewal have passed acceptance tests; `includeSubDomains` and preload require separate domain-wide review.
- Application code does not claim to enforce end-to-end TLS when termination is upstream.

## 4. Trusted proxy, forwarded headers, and Host

- Nginx removes inbound `Forwarded` and `X-Forwarded-*` values and constructs the approved values itself.
- Uvicorn proxy-header processing may be enabled only with an explicit `forwarded-allow-ips` list containing the actual loopback connector (`127.0.0.1` and `::1` only if both are used). Wildcard trust is prohibited.
- Nginx uses an exact `server_name`, rejects unknown Host/SNI values in a default server, and forwards a canonical Host. A later application hardening phase should add an exact `TrustedHost` allowlist as defense in depth without changing endpoint semantics.
- Direct requests to Uvicorn are denied by binding and firewall policy. If they become possible, their forwarded headers remain untrusted.
- Client IP is not an authentication factor, authorization input, audit principal, or application rate-limit key. A forwarded client address is informational only after the proxy chain and privacy purpose have been approved.
- Container networks may assign proxy addresses dynamically. A container deployment must use a stable network/CIDR controlled only by the proxy or a Unix socket; it must not replace the allowlist with `*` for convenience.

## 5. Edge request-body, header, timeout, and connection controls

The following numbers are V1 operational defaults selected for this repository. They are not Linux Audit standards, universal security values, or evidence that the parser is safe. Operators must measure legitimate uploads and resource use before changing them.

| Control | V1 reference value | Contract and rationale |
|---|---:|---|
| Total HTTP request body | 24 MiB | Allows bounded multipart boundaries and part headers above the application's 20 MiB content ceiling without weakening that ceiling. Nginx rejects larger bodies before proxying where possible. |
| Normal request-header buffer | 1 KiB | Sufficient for ordinary fixed headers; larger individual lines use only the bounded large-header buffers. |
| Large request-header buffers | 2 × 8 KiB | Bounds request-line/header growth while accommodating the canonical bearer and multipart boundary. Each line still must fit a buffer. |
| Header read timeout | 10 seconds | Limits slow header delivery. |
| Body read inactivity timeout | 15 seconds | Nginx `client_body_timeout` is between successive reads, not a total upload deadline. |
| Upstream connect timeout | 2 seconds | A loopback application should connect promptly. |
| Upstream send inactivity timeout | 30 seconds | Bounds stalls while forwarding the accepted request. |
| Upstream response inactivity timeout | 120 seconds | `proxy_read_timeout` is between reads, not an absolute analysis deadline. |
| Absolute request budget | 180 seconds | Must be enforced by a later tested application/platform deadline because stock Nginx inactivity timers are not a total deadline. Until implemented, this remains a production gate. |
| Keep-alive idle timeout | 15 seconds | Limits idle connection occupancy. |
| Requests per keep-alive connection | 100 | Periodically releases per-connection resources. |
| Endpoint connections being processed | 4 per Nginx instance | A shared, endpoint-global connection zone rejects excess without using spoofable client IP as identity. |
| Uvicorn total concurrent connections/tasks | 16 for the whole app | A final backstop, not a replacement for endpoint limits; excess uses Uvicorn's documented 503 behavior. |

The application continues to enforce four files, 10 MiB per file and 20 MiB total content. The 24 MiB edge limit is intentionally higher because HTTP multipart framing is not included in the application's staged-content sum. It must not be reduced to exactly 20 MiB, which could reject valid requests based on boundary and header overhead.

An edge body rejection returns HTTP 413 with JSON content type and the fixed body `{"error":{"code":"EDGE_REQUEST_BODY_TOO_LARGE","message":"Request body exceeds the deployment limit."}}`. The body contains no proxy name, upstream address, filesystem path, filename or limit counter. Header and timeout rejection use the proxy's reviewed bounded 400/408/414/431/504 behavior with version disclosure disabled; later acceptance tests fix the exact supported responses.

## 6. Edge request-rate policy

The reference Nginx instance applies a shared endpoint-global leaky-bucket zone to `/api/analyze-linux-audit` at an average of 6 requests per minute with a burst of 2 and `nodelay`. Excess requests are rejected rather than queued. The same location limits four concurrently processed connections. Rejections return HTTP 429 with JSON content type and the fixed body `{"error":{"code":"EDGE_REQUEST_RATE_LIMITED","message":"Request rate is currently limited."}}`; no queue depth, rate counter, client address, worker count or topology is disclosed, and no arbitrary `Retry-After` is emitted.

These are conservative V1 operational defaults for a single operator and must be tuned from approved load measurements. Nginx does not know the authenticated application principal before proxying, so this is deliberately global rather than a claim of per-user fairness. Client-IP keying is not used. One Nginx shared-memory zone coordinates its own worker processes, but multiple proxies do not share state and multiply the effective rate and connection allowance. A distributed gateway becomes necessary before horizontal proxy scaling can claim a global rate limit.

The edge rate policy complements, but does not replace, the application's authenticated process-local concurrency limiter. Conversely, the app limiter cannot prevent unauthenticated multipart receipt or parsing.

## 7. Worker, replica, memory, and capacity calculation

The effective application analysis capacity is:

```text
effective concurrent analyses
= Uvicorn worker count
× max_concurrent_analyses per app instance
× replica count
```

Each Uvicorn worker imports and constructs its own app, prepared bearer digest, limiter and audit-sink adapter. Multiple containers or hosts multiply those objects again. Python worker processes do not generally share loaded memory; loader grouping, normalized logs and staged parsing memory therefore multiply with concurrent analyses and workers. The shared threadpool is also process-local, and an analysis occupies a worker's app limiter slot while its synchronous loader/orchestration runs in that worker's threadpool.

The initial V1 recommendation is one Nginx instance, one Uvicorn worker, one replica and `max_concurrent_analyses=1`, giving effective capacity 1. The endpoint connection limit of 4 allows authentication and bounded rejection traffic without authorizing four analyses. Add workers, replicas, or a higher app limit only after fixture-based 20 MiB peak RSS, CPU, temporary storage, threadpool latency and audit-sink load tests establish headroom. Edge connection/rate controls and host memory/cgroup limits must be recalculated together.

Every worker writes through its own sink adapter to a multi-process-safe sink. Process-local capacity is never described as fleet-global capacity.

## 8. Secret delivery, generation, rotation, and revocation

### Delivery option comparison

| Method | Benefits | Risks and V1 decision |
|---|---|---|
| Environment variable containing token | Common and simple | May leak through process inspection, diagnostics, inherited environments or deployment tooling; not selected |
| Mounted plaintext secret file | Portable, permissionable and avoids process arguments | Source/mount permissions and lifecycle must be managed; acceptable portable fallback |
| OS service credential | Service-scoped runtime file and lifecycle integration | Depends on service manager/version; selected reference using systemd credentials |
| Container secret | Integrates with an orchestrator and read-only mounts | No container platform exists in this repository; future equivalent |
| External secret manager | Central rotation, policy and audit potential | Adds network availability, bootstrap identity and SDK/agent concerns; future stronger option |

The V1 reference uses a systemd service credential. Deployment bootstrap reads the credential from `$CREDENTIALS_DIRECTORY`, constructs `SecretStr` and the explicit `LinuxAuditApiSecurityConfig`, initializes the audit sink, and calls `create_app(...)`. The token itself is never an environment value or command-line argument. A portable deployment may use a read-only mounted file under an equivalent service-specific credential directory.

The credential source is administrator-owned with mode `0400`; its parent directory is not traversable by unrelated users. The systemd runtime credential is accessible only to the service identity and is removed with the service lifecycle according to the service-manager contract. Valid credential content is at most 44 bytes: exactly 43 ASCII Base64URL characters plus at most one terminal LF. The loader removes only that LF and rejects CRLF, other whitespace, extra lines, padding, Unicode, non-canonical encoding or a decoded length other than 32 bytes. Missing/invalid credentials fail before traffic is accepted.

No credential is committed to Git, `.env`, proxy configuration, documentation, health/readiness output, process arguments, shell tracing, crash reports, logs or audit fields. A path to a service-managed credential may be non-secret, but the bootstrap must not print file content or validation input.

### Implemented route-independent bootstrap primitive

Phase 3Y-L implements `load_linux_audit_api_security_config()` in `app/bootstrap/linux_audit_api.py`. Its frozen input contains only an explicitly caller-supplied absolute `pathlib.Path`, principal ID and analysis-concurrency limit; its representation hides all three values. It never reads an environment variable, scans a credential directory or enables/registers an API route. A later deployment entry point remains responsible for deriving an absolute systemd credential path and passing the resulting existing `LinuxAuditApiSecurityConfig` to `create_app(...)`.

The loader accepts only a regular file with an exact permission mode of `0400` or `0600`. It rejects relative paths, symlinks, directories, FIFOs, sockets, devices, executable bits and every group/other permission bit without changing ownership or mode. It deliberately does not impose a portable owner-identity check; correct file ownership and parent-directory traversal permissions remain deployment preflight responsibilities.

The implementation performs `lstat`, opens read-only with `O_RDONLY` plus `O_CLOEXEC` and `O_NOFOLLOW` when the host exposes those flags, then checks the open descriptor with `fstat`. Pre-open and open device/inode identities must match and both views must be private regular files. If an optional flag is unavailable, the lstat/fstat checks remain active but are not claimed to provide an equivalent kernel guarantee. These checks reduce symlink and replacement races; they do not eliminate TOCTOU, ancestor-directory replacement or concurrent in-place content modification.

The named 128-byte file ceiling is an application operational bound, not a Linux Audit or systemd standard. The bounded loop buffers at most 129 bytes so growth is detected without an unbounded read. Content uses strict ASCII, accepts the canonical 43-character token with no newline or exactly one final LF, and rejects CRLF, multiple/embedded newlines, NUL, spaces, tabs, empty input and oversized content. The decoded token is wrapped in `SecretStr` and passed through the existing `LinuxAuditApiSecurityConfig` preparation validator; the bootstrap does not define a second bearer policy.

Filesystem, encoding, format and bootstrap failures use fixed machine codes and messages without path, basename, errno, metadata, principal, token, digest or validation detail. The file descriptor is closed after every opened-file outcome, and the supplied file is never deleted, renamed, chmodded or rewritten. A mutable read buffer is cleared as a best effort, but Python immutable `bytes` and `str`, `SecretStr`, allocator copies and crash/process memory cannot be securely zeroized by this component. No route or `create_app()` integration is included in this phase.

### Generation and lifecycle procedure

1. An authorized operator uses an approved OS or secret-manager CSPRNG to generate exactly 32 random bytes.
2. The tool encodes them as canonical unpadded Base64URL and writes the 43-character result directly to the protected credential source without printing it to a terminal, ordinary log or shell trace. No literal token appears in a command line or shell history.
3. A second authorized check verifies owner/mode, exact byte contract, decoded length and canonical re-encoding without displaying the value.
4. Initial deployment loads the credential, prepares configuration and sink, then passes readiness acceptance before Nginx sends traffic.
5. Routine rotation creates a new protected credential, restarts/redeploys all app instances in a coordinated maintenance window, verifies the new credential through a bounded acceptance request, inventories every instance, and securely destroys stale runtime/source copies under the approved policy.
6. Emergency revocation removes proxy traffic, replaces the credential, restarts every instance, verifies that the old credential is rejected, checks audit records for suspected use, and records the incident owner.
7. Rollback may restore the prior credential only while it remains uncompromised and access-controlled; a compromised token is never restored.

The current application supports one token, no dual-token grace period, no token expiry, no live reload and no distributed revocation. Rotation therefore requires coordinated restart/redeployment and can cause a bounded interruption. Static bearer credentials remain replayable until replaced. Hashing at application startup does not strengthen weak source material.

## 9. Production access-audit sink

### Sink comparison

| Sink | Multi-worker and bounds | Integrity/access operations | V1 position |
|---|---|---|---|
| Local JSON Lines file | Append can be explicit, but concurrent writers, rotation, permissions, partial writes and injection require custom code | Application/operator must own all rotation, locking, verification and shipping | Not selected for V1 |
| syslog/journald | Local multi-process service, structured fields, service identity, rotation/storage controls and restricted readers | Persistence, rate limits, sealing and forwarding still require explicit host policy | Selected V1 reference: native structured journald adapter |
| Remote security collector | Central access, correlation and retention can be stronger | Network outage/latency interacts with the application's fail-closed runtime and needs authenticated transport/buffering policy | Future destination after local acceptance |

The route-independent adapter is implemented in `app/security/linux_audit_api_journald.py`. It accepts only the exact immutable `LinuxAuditApiAccessAuditEvent` and maps it explicitly to bounded journald fields. It will not accept generic dictionaries or use `asdict()`, `vars()`, `__dict__` or recursive serialization. The fixed journald allowlist is `MESSAGE`, `PRIORITY`, `SYSLOG_IDENTIFIER`, `LINUX_AUDIT_EVENT_SCHEMA_VERSION`, `LINUX_AUDIT_AUDIT_EVENT_ID`, `LINUX_AUDIT_ANALYSIS_ID`, `LINUX_AUDIT_TIMESTAMP_UTC`, `LINUX_AUDIT_PRINCIPAL_ID`, `LINUX_AUDIT_ENDPOINT`, `LINUX_AUDIT_HTTP_METHOD`, `LINUX_AUDIT_RESULT_CATEGORY`, `LINUX_AUDIT_HTTP_STATUS`, `LINUX_AUDIT_FILE_COUNT`, `LINUX_AUDIT_UPLOAD_SIZE_BUCKET` and `LINUX_AUDIT_DURATION_BUCKET`. No caller can add another journal field, and client-supplied fields beginning with the trusted-field prefix `_` are never submitted.

Every journal value is a validated scalar with no NUL, newline or control character and a maximum UTF-8 length of 256 bytes; the complete native-protocol datagram is limited to 4096 bytes. These are V1 application operational bounds, not journald or Linux Audit standards. Bearer material, request headers, filenames, content type, paths, raw/normalized evidence, process/session identity, exceptions, tracebacks, response bodies and limiter state remain excluded. The fixed `MESSAGE`, notice `PRIORITY=5`, identifier and schema version carry no uploaded evidence.

Sink initialization verifies the native local journald Unix datagram transport by opening it explicitly, and the production factory fails with a fixed bounded initialization error if it is unavailable. There is no logger, syslog, file, stdout/stderr, memory or network fallback. Tests inject a private deterministic transport boundary, but no default sink or singleton is constructed at import time. This adapter is not yet wired into `create_app()` or a deployment entry point; enabled app construction continues to require an explicitly supplied sink. Runtime failure will therefore preserve the existing `500 LINUX_AUDIT_ACCESS_AUDIT_FAILED` boundary once the deployment entry point supplies this sink.

Submission is direct and bounded: at most eight operations may be in flight, there is no event queue and no automatic retry. A synchronous send is offloaded with `asyncio.to_thread()` and awaited with a three-second application timeout. Cancelling or timing out the awaiting coroutine cannot guarantee termination of an already-running blocking send; the sink enters a failed state, the detached operation is bounded by the transport timeout, and cancellation still propagates. A send that completed near cancellation may therefore have reached journald even though the caller did not observe completion, and retrying externally can create duplicates. The sink does not claim exactly-once delivery.

`close()` is explicit, bounded and idempotent. After success it stops new submissions permanently; during close it waits up to five seconds for owned submissions and closes the native socket. Emit-after-close, submission, initialization and shutdown failures use fixed messages without event or transport details. Close does not claim to flush, fsync, persist, forward or delete journal records. Cancellation of close propagates and a later close may complete cleanup.

An `emit()` success means only that the local socket submission call completed without its bounded transport reporting failure. It does not guarantee durable media and does not prove journald acceptance, no later rate-limit drop, remote receipt, retention, integrity, backup or analyst review. Journald storage may be volatile, persistent or disabled and forwarding is a separate host policy. Production policy must explicitly configure persistent storage and size bounds, monitor dropped messages and storage exhaustion, restrict readers, audit access to the journal, test rotation, and decide whether Forward Secure Sealing and authenticated remote forwarding meet the organization's integrity requirements.

## 10. Audit retention and deletion policy template

No universal retention number is defined. Before production activation, the operator must approve and version a policy containing all of the following:

| Policy item | Required decision |
|---|---|
| Purpose | Operational/security purpose for retaining each allowlisted field |
| Duration | Justified retention period and review date; not copied from a generic standard |
| Access roles | Named operational/security roles, approval path and periodic review |
| Integrity | Sealing/signing, write permissions, verification cadence and alert owner |
| Storage | Local journal namespace and any approved remote destination |
| Bounds | Maximum storage use, free-space reserve, rotation and dropped-event monitoring |
| Backups | Whether audit data is backed up, encryption/access rules and restore tests |
| Deletion | Normal deletion schedule, method and accountable operator |
| Legal/regulatory | Applicable contractual, legal and jurisdictional requirements |
| Incident hold | Authorized hold trigger, scope, review and release process |
| Verification | Evidence that primary, backup, export and stale copies were deleted |

Production activation is prohibited until this policy is supplied. Audit records are not raw Linux Audit evidence. Uploaded files and staging directories remain request-scoped and are not retained by the application or copied into the audit store.

## 11. Liveness and readiness

The existing `/api/health` is only a lightweight liveness signal: the process/event loop can answer a request. Its fixed body remains unchanged and contains no secret, principal, sink path, limit, worker count or configuration detail. Public exposure is unnecessary; Nginx should restrict health probing to the local deployment monitor.

V1 needs a separate internal readiness contract in a later implementation. The reference is an internal-only readiness endpoint or equivalent service-manager probe that returns only a fixed ready/not-ready status and verifies:

- security configuration was prepared successfully;
- enabled/disabled route registration matches deployment intent;
- the per-app limiter exists with validated configuration;
- the audit sink completed startup initialization;
- secret/bootstrap and deployment preflight completed.

Readiness does not upload a file, run analysis, reveal endpoint enablement details publicly, disclose principal/secret/sink path, or claim that journald persistence and a remote collector are healthy unless the sink contract can actually verify them. It is reachable only over loopback or a restricted management path and is not proxied on the public API host. This phase does not add the endpoint.

## 12. Startup, rollout, and shutdown

### Startup and rollout

1. Validate Nginx configuration, certificate chain/key match, exact hostname, TLS profile, body/header/time/rate/connection limits and loopback upstream.
2. Load the service credential through deployment bootstrap without printing it; validate its exact canonical contract.
3. Initialize the journald adapter and required host logging policy.
4. Construct the enabled app with exact security config and sink. Any config, sink or contradictory feature-state error terminates startup before listening.
5. Start one Uvicorn worker on loopback with explicit proxy allowlist, concurrency ceiling, keep-alive and graceful-shutdown settings.
6. Complete internal readiness checks, then permit Nginx to route traffic.
7. Run bounded HTTPS authentication, error, upload, audit and privacy acceptance. Roll back traffic if any gate fails.

There is no development bypass, generated fallback token, unauthenticated degraded mode or sink-optional production mode.

### Shutdown

- Nginx stops admitting new endpoint requests before Uvicorn shutdown.
- Uvicorn receives graceful termination and uses an initial 60-second operational drain budget, subject to load-test adjustment.
- Active requests either finish or are cancelled at the bounded deadline. Cancellation continues to release limiter capacity and staging resources and attempts the existing bounded cancellation audit event.
- A future sink adapter flush/close operation has a separate bounded five-second budget and must not print event or secret data on failure.
- The service verifies that no owned staging directory is retained and removes the service-manager credential through normal service teardown.

An abrupt kill, kernel panic, power loss or host crash can interrupt cleanup, audit delivery and graceful drain. Temporary-directory hygiene and journal recovery must be checked on restart; the application cannot guarantee cleanup or terminal audit persistence after process death.

## 13. Production activation checklist

Every item is mandatory. A missing or failed item prohibits endpoint enablement.

- [ ] TLS proxy is configured and current TLS/certificate acceptance passes.
- [ ] Uvicorn is loopback/private only and firewall verification shows no public app port.
- [ ] Exact trusted proxy allowlist and forwarded-header stripping are configured.
- [ ] Exact Host/SNI policy is configured and unknown values are rejected.
- [ ] Body, header, slow-read, upstream, keep-alive and connection limits are configured.
- [ ] Global endpoint rate/burst rejection is configured and measured.
- [ ] Bearer credential is securely generated and delivered without argv, environment-value or log exposure.
- [ ] Rotation, emergency revocation, instance inventory and rollback runbooks exist.
- [ ] Security configuration and fail-closed app construction succeed.
- [ ] Worker × app limit × replica effective capacity and peak resource budget are approved.
- [ ] Explicit audit sink initializes; runtime failure behavior is accepted.
- [ ] Retention, access, integrity, storage, backup and verified deletion policy is approved.
- [ ] Liveness and internal readiness behavior is accepted without information disclosure.
- [ ] Default-disabled app and OpenAPI behavior are verified.
- [ ] Enabled endpoint rejects missing/invalid authentication and unauthorized access.
- [ ] Bounded 401, 403, edge/application 413, edge/application 429 and 500 paths are tested.
- [ ] End-to-end privacy-canary acceptance and no-LLM verification pass.
- [ ] Backup/restore and audit-log integrity responsibilities have named owners.
- [ ] Capacity, certificate, audit drop/storage and service-failure monitoring/alert ownership is assigned.
- [ ] Incident-response contact and escalation path are assigned.

## 14. Later reference implementation plan

No listed file is created in this phase. A later implementation should add small, reviewable units in this order:

1. Deployment entry point that derives the approved absolute systemd credential path, invokes the implemented route-independent loader and passes its security config to `create_app(...)` without logging values.
2. Deployment composition that constructs the implemented native structured journald sink and supplies it explicitly to `create_app(...)`.
3. Internal readiness contract and app lifespan hooks for journald sink initialization/close.
4. Nginx reference template with placeholders for DNS name, certificate/key references, trusted loopback upstream and approved policy identifiers.
5. systemd service/credential template with non-secret placeholders and one-worker/loopback defaults.
6. Deployment environment template containing only safe non-secret values; no token placeholder that resembles a usable credential.
7. Operator runbook for certificate, secret rotation/revocation, audit retention/deletion and incident response.
8. Ordinary pytest contract tests plus a separate local Nginx/systemd acceptance harness.

Safely committable defaults are the 24 MiB edge body ceiling, documented timeout/rate/connection starting points, one worker, app analysis capacity 1, fixed public error bodies and placeholder names. DNS names, network ranges, certificate/key locations, credential sources, principal ID, retention duration, alert destinations and incident contacts remain deployment-specific placeholders requiring approval.

## 15. Deployment acceptance-test plan

### Ordinary pytest tests

- Default `app.api:app` remains disabled and default OpenAPI is unchanged.
- Enabled bootstrap without credential, malformed credential, config or sink fails before serving.
- Secret reader accepts only the exact optional-LF/canonical token contract and never returns it in repr/errors.
- Capacity formula helper rejects bool/invalid values and computes worker × app limit × replica exactly.
- Journald adapter accepts only the immutable audit event and explicitly maps the allowlist.
- Sink initialization/runtime failure preserves startup/runtime fail-closed behavior.
- Liveness and readiness bodies are fixed and disclose no configuration, principal, secret or sink path.
- Graceful cancellation preserves staging cleanup, limiter release and one cancellation-audit attempt.
- Privacy boundary and LLM non-invocation remain unchanged.
- Existing `/api/health`, `/api/analyze`, CLI, parser, analysis and OpenAPI tests pass.

### Local proxy/service integration tests

- Socket inspection proves Uvicorn is loopback/private only and Nginx is the sole public listener.
- Public plaintext HTTP is rejected; valid HTTPS succeeds; invalid/expired/mismatched certificates fail.
- Unknown Host/SNI and spoofed forwarded headers are rejected or ignored; trusted proxy headers produce the approved scheme/host only.
- A request above 24 MiB receives the fixed edge 413 without reaching FastAPI; legitimate multipart overhead below 24 MiB reaches the unchanged application 20 MiB enforcement.
- Oversized headers, slow headers/body, stalled upstream, keep-alive and connection ceilings behave as documented.
- Average/burst excess receives fixed edge 429 without an analysis queue; multiple proxy limitation is documented.
- One-worker capacity is 1; test deployments verify the formula across controlled workers/replicas and measure peak RSS/CPU/temp usage.
- Service credentials have approved source/runtime permissions and are absent from process arguments, environment-value dumps, logs, health/readiness and crash diagnostics.
- Routine rotation accepts the new token and rejects the old token on every instance; emergency revocation and allowed rollback are rehearsed.
- Journald startup failure blocks readiness; runtime failure yields fixed 500; concurrent workers do not corrupt records.
- Journal rotation, storage ceiling, dropped-message alerting, access audit, integrity verification, backup restore and retention/deletion dry run pass under the approved policy.
- Graceful shutdown drains or cancels within bounds and cleans owned staged files; abrupt termination limitation is recorded.
- End-to-end privacy canary does not enter public/proxy/audit output, and no LLM provider is called.

The integration suite requires an isolated local proxy/service environment and must not run against a live production endpoint by default.

## 16. Threat model and ownership

| Threat | Asset and trust boundary | V1 mitigation | Residual risk | Owner |
|---|---|---|---|---|
| Plaintext bearer interception | Credential across client/public network | TLS-only listener; plaintext API rejection; HSTS after validation | Compromised client/proxy endpoint can still capture bearer | Network/TLS owner |
| Public Uvicorn exposure | App server and bypassed edge controls | Loopback bind plus host firewall and socket acceptance | Host/network-policy error may reopen port | Service owner |
| Spoofed forwarded headers | Scheme/host/client metadata | Proxy strips inbound values; explicit Uvicorn proxy allowlist | Compromised trusted proxy can forge values | Network owner |
| Oversized multipart body | Bandwidth, spool disk and parser memory | 24 MiB edge ceiling plus unchanged app 20 MiB content limit | Chunked/protocol implementation defects remain | Proxy and app owners |
| Slow upload | Connections, proxy buffers and spool resources | Header/body inactivity and absolute-budget gate | Slow traffic within thresholds consumes resources | Proxy owner |
| Request flood | Proxy/app availability | Global rate/burst and connection limits; app capacity | Distributed sources and multiple proxies multiply allowance | Operations owner |
| Worker/replica multiplication | CPU, RAM and analysis capacity | Explicit formula; initial 1×1×1; load approval | Unreviewed autoscaling exceeds budget | Capacity owner |
| CPU/memory exhaustion | Loader/parser/threadpool and host | Bounded files/body/concurrency, one worker, host monitoring | Valid worst-case content may remain expensive | App/capacity owners |
| Secret in argv/environment/log | Credential confidentiality | Service credential file; no token argv/env/log; scans | Host root or diagnostic tooling can access process memory | Secret owner |
| Stale token after rotation | Authorization boundary | Coordinated restart and complete instance inventory | No live revoke/expiry or dual-key transition | Secret owner |
| Audit-log tampering | Accountability and investigation | Restricted journald, access audit, optional sealing/remote copy | Privileged host compromise may tamper before forwarding | Logging owner |
| Audit storage exhaustion | Availability and fail-closed API | Storage/free-space bounds, rotation and alerts | Sink failure intentionally makes endpoint unavailable | Logging/operations owners |
| Over-retention | Principal/activity privacy | Approved purpose/duration and periodic review | Copies/backups may outlive primary | Privacy owner |
| Failed deletion | Privacy/legal obligations | Scheduled deletion plus verification across backups/exports | Offline or incident-held copies require tracking | Data-governance owner |
| Proxy misconfiguration | All edge controls | Versioned template, config test and acceptance checklist | Valid syntax can still encode unsafe policy | Network/security reviewers |
| Health/readiness disclosure | Deployment/security metadata | Fixed minimal bodies and internal readiness route | Network ACL error may expose status | Service owner |
| Abrupt termination | Cleanup and audit completeness | Request-scoped temp, persistent journal, restart hygiene | In-flight event and temp cleanup cannot be guaranteed | Operations owner |
| Compromised proxy or host | Credentials, uploads, responses and audit | Least privilege, restricted keys/secrets, host monitoring | A fully privileged compromise defeats local controls | Platform/security owners |

## 17. Non-goals and known limitations

This phase does not create a deployment entry point, proxy or systemd configuration, containers, certificates, environment secret loading, readiness routes, rate-limit code or endpoint behavior. The route-independent secret-file loader and journald sink primitive do not make the endpoint production-ready by themselves.

Nginx inactivity timeouts are not absolute request deadlines. A single proxy's shared rate zone is not distributed. The application limiter, sink and memory are process-local. The reference host shares fate between proxy and app. Journald acceptance is not proof of durable or remote storage. Static bearer authentication has no expiry, replay resistance or individual-human identity. Loopback plaintext is appropriate only for the stated single-host boundary. Numeric edge controls are V1 operational defaults requiring measurement, not standards or attack verdicts.

## 18. Official research basis

All sources below were actually reviewed on **2026-10-07**. General guidance informed the contract but does not prove a future deployment is secure.

| Organization | Document and reviewed section | Exact URL | Fact used | Does not guarantee |
|---|---|---|---|---|
| FastAPI | *About HTTPS*, TLS termination and proxy forwarded headers | https://fastapi.tiangolo.com/deployment/https/ | A public TLS termination proxy commonly handles certificates and forwards plain HTTP to a private app; forwarded trust must be configured | Correct Nginx policy, certificate renewal, private binding or end-to-end TLS |
| FastAPI | *Behind a Proxy*, proxy forwarded headers | https://fastapi.tiangolo.com/advanced/behind-a-proxy/ | `X-Forwarded-*` interpretation must be limited to trusted proxy senders | That wildcard proxy trust is safe in this topology |
| FastAPI | *Deployments Concepts*, replication/process memory and previous steps | https://fastapi.tiangolo.com/deployment/concepts/ | Worker processes have independent memory and deployment pre-start steps need explicit ownership | Safe worker count or capacity for this loader |
| FastAPI | *Server Workers*, multiple workers | https://fastapi.tiangolo.com/deployment/server-workers/ | Multiple Uvicorn workers run parallel app processes | Shared limiter, sink or memory across workers |
| FastAPI | *FastAPI in Containers*, one process per container guidance | https://fastapi.tiangolo.com/deployment/docker/ | Orchestrated replicas generally favor one process per container | That this repository should adopt containers now |
| Uvicorn | *Settings*, HTTP, resource limits and timeouts | https://www.uvicorn.org/settings/ | Explicit bind, proxy allowlist, concurrency, keep-alive and graceful-shutdown settings are available | Edge body/rate policy or distributed capacity |
| Python Software Foundation | *os — Miscellaneous operating system interfaces*, `open`, `lstat`, `fstat`, descriptor flags | https://docs.python.org/3/library/os.html | `os.open` provides low-level read-only descriptors; descriptors are non-inheritable; `lstat` does not follow the final symlink; `fstat` inspects the opened object; optional flags depend on the host C library | Complete path-race prevention, ancestor safety, ownership policy or secret-memory erasure |
| Python Software Foundation | *stat — Interpreting stat results*, file-type and permission helpers | https://docs.python.org/3/library/stat.html | `S_ISREG` distinguishes regular files and `S_IMODE` exposes permission/special bits for a portable mode policy | The correct deployment owner or parent-directory access policy |
| Python Software Foundation | *pathlib — Object-oriented filesystem paths*, pure path properties | https://docs.python.org/3/library/pathlib.html | `Path.is_absolute()` validates the explicit path form without resolving a symlink into an acceptable target | Filesystem identity stability or safe secret discovery |
| Nginx | *Configuring HTTPS servers* | https://nginx.org/en/docs/http/configuring_https_servers.html | TLS 1.2/1.3 configuration and restricted private-key access belong to the TLS server | Certificate automation or a secure reviewed cipher policy forever |
| Nginx | *ngx_http_core_module*, client body/header and timeout directives | https://nginx.org/en/docs/http/ngx_http_core_module.html | `client_max_body_size` produces 413; header buffers and client timeouts are configurable | That 24 MiB and chosen timeouts fit real traffic |
| Nginx | *ngx_http_proxy_module*, proxy buffering and read timeout | https://nginx.org/en/docs/http/ngx_http_proxy_module.html | Buffered bodies can be read before upstream; `proxy_read_timeout` is between reads, not a total deadline | An absolute request deadline |
| Nginx | *ngx_http_limit_req_module*, leaky bucket, burst and status | https://nginx.org/en/docs/http/ngx_http_limit_req_module.html | Shared zones enforce a defined request rate; `nodelay` avoids delay and rejection status is configurable | Distributed limits across proxy instances or authenticated identity |
| Nginx | *ngx_http_limit_conn_module*, connection counting and status | https://nginx.org/en/docs/http/ngx_http_limit_conn_module.html | Processed connections can be bounded with configurable rejection status | Pre-header connection protection or global multi-proxy capacity |
| Mozilla | *Web Security Guidelines*, HTTPS, HSTS and current TLS profile selection | https://infosec.mozilla.org/guidelines/web_security | HTTPS is mandatory and the TLS profile must match the supported client population | Correct application-specific deployment or certificate operation |
| Mozilla | *SSL Configuration Generator* | https://ssl-config.mozilla.org/ | Current generated server profiles should be reviewed rather than freezing stale cipher text | Future-safe configuration without version review |
| OWASP | *Transport Layer Security Cheat Sheet*, strong protocols and API HTTP policy | https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html | Prefer TLS 1.3, allow TLS 1.2 for compatibility, disable older protocols, and reject plaintext API use | That TLS termination protects a compromised endpoint |
| OWASP | *REST Security Cheat Sheet*, HTTPS, generic errors, audit logging and 413 | https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html | REST credentials require HTTPS; errors must be bounded; 413 represents excessive payload | Exact edge JSON schema or rate values |
| OWASP | *File Upload Cheat Sheet*, authorization, storage and upload limits | https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html | Authorized upload services need size limits, least privilege and untrusted filename/content-type handling | That accepted Linux Audit text is authentic or harmless |
| OWASP API Security Project | *API4:2023 Unrestricted Resource Consumption*, prevention | https://api-security.owasp.org/editions/2023/en/0xa4-unrestricted-resource-consumption/ | Bound upload size, execution resources and interaction frequency according to business need | Universal numeric limits for this repository |
| OWASP | *Logging Cheat Sheet*, protection, monitoring and disposal | https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html | Restrict and monitor log access, detect tampering, protect transport and delete according to policy | A universal retention period or journald durability |
| OWASP | *Secrets Management Cheat Sheet*, lifecycle, TLS and backup | https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html | Secret lifecycle includes secure delivery, rotation, backup/restore and emergency procedures | That a static bearer is non-replayable or centrally revoked |
| NIST | *SP 800-92 Guide to Computer Security Log Management*, infrastructure and processes | https://csrc.nist.gov/pubs/sp/800/92/final | Log infrastructure, operational processes, protection and organizational policy are separate responsibilities | Step-by-step FastAPI/journald configuration or current retention law |
| NIST | *Key Management Guidelines*, lifecycle and organizational planning | https://csrc.nist.gov/Projects/Key-Management/Key-Management-Guidelines | Generation, distribution, replacement, compromise response and destruction require owned procedures | That a bearer token is a cryptographic key or that 43 characters is a NIST requirement |
| systemd | *Credentials* | https://systemd.io/CREDENTIALS/ | Service credentials are delivered as service-scoped files through `$CREDENTIALS_DIRECTORY` | Application parsing, source-file policy or zero residual copies |
| systemd | *journald.conf*, storage, bounds, rate limit, retention and sealing | https://www.freedesktop.org/software/systemd/man/journald.conf.html | Persistent/volatile storage, size bounds, retention, rate limiting and sealing require explicit configuration | That `emit()` is durable, remotely received or never dropped |
| systemd | *journalctl*, access and sealing-key operations | https://www.freedesktop.org/software/systemd/man/journalctl.html | Journal readers are privilege-controlled and sealing verification keys must be handled separately | Organizational access approval, remote integrity or deletion verification |
| systemd | *Journal Native Protocol*, serialization and local socket transport | https://systemd.io/JOURNAL_NATIVE_PROTOCOL/ | Native entries use bounded field/value records over the local journal socket; client fields beginning with `_` are ignored as trusted fields | Durable acceptance, forwarding, retention or exactly-once delivery |
| systemd | *systemd.journal-fields*, user journal fields | https://github.com/systemd/systemd/blob/main/man/systemd.journal-fields.xml | `MESSAGE`, `PRIORITY` and `SYSLOG_IDENTIFIER` have defined meanings, while user fields are not automatically validated by journald | Safety of application-provided field values or host storage policy |
| Python Software Foundation | *Coroutines and Tasks*, `asyncio.to_thread`, cancellation and `wait_for` | https://docs.python.org/3/library/asyncio-task.html | Blocking I/O can be offloaded without blocking the event loop and cancellation propagates to the awaiting task | Termination of a blocking function already running in a worker thread or prevention of duplicate delivery |
