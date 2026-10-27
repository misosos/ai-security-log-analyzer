# Phase 35.4 — Vector isolated JSON Lines integration plan

Status after Phase 35.4A: official x86_64 GNU archive checksum and member inspection passed, and the planned disk budget is numerically closed. No Vector executable or config validation was run. The environment is macOS arm64, without a disposable Ubuntu VM or independently verified OS-level egress deny, so execution remains `ISOLATION_BLOCKED`.

Evidence checked 2026-10-27. This is a design and entry gate only. **Vector was not downloaded, installed, unpacked, or executed.** No user logs, Vector configuration, external process, or production connection was used. Vector execution is `NOT_TESTED`.

## Decision

**Phase 35.3 synthetic Ubuntu acceptance: `GO` for the bounded JSONL runtime acceptance scope only.** The exact push run passed its full regression and the dedicated Linux step. This does not approve Vector execution, real data, organization operation, or remote collection.

**Next step: `PHASE_35_4_ISOLATED_SYNTHETIC_PILOT_DESIGN_READY`; execution remains `ISOLATION_BLOCKED` until every entry criterion below is independently evidenced.** The only candidate is Vector v0.60.0, in a disposable Ubuntu 24.04 x86_64 environment. This platform is selected because the matching official GNU x86_64 artifact is recorded in the existing manifest and the acceptance CI ran on Ubuntu; the CI does not prove the Vector binary or its filesystem behavior.

The fixed Vector source commit is `0d0b35865036f8b5c2f0104d9744fa84985ffff1`. The existing [artifact manifest](artifacts/vector_0_60_0_manifest.json) is the source of the platform artifact's filename, compressed size, and SHA-256; this plan does not override those values. The selected Linux GNU x86_64 archive entry records 58,655,370 bytes and SHA-256 `89a9f134dcc35a6fbba9cb8ad0fec2d4802657bba6cb1c374a30660ef9456bdc`.

## Candidate Platform

The single candidate is **Ubuntu 24.04 x86_64** using the manifest's Linux GNU x86_64 archive. No ARM64 run is planned in this phase. The current Ubuntu CI provides Linux runtime acceptance evidence only; it does not establish the host architecture, artifact execution compatibility, or filesystem type for Vector. The isolated environment must verify `x86_64` and Ubuntu release before any acquisition. A mismatch stops the run.

Checksum agreement is not a detached signature, SBOM, attestation, reproducible-build proof, or source-to-binary provenance. The current disposition `CHECKSUM_ONLY_ACCEPTED_FOR_ISOLATED_PILOT` is limited to one disposable, synthetic, isolated experiment; it is not a general supply-chain approval. Three credential-shaped binary string findings remain `UNRESOLVED`; they are neither declared secrets nor cleared findings.

## Current Evidence

- Start and target commit: `5cdf941291204a48edace62a25c1e1fbe3350a75`, branch `main`, clean tree; `origin/main...HEAD` was `0 behind / 0 ahead` after push.
- Exact GitHub Actions push run: [40452774780](https://github.com/misosos/ai-security-log-analyzer/actions/runs/40452774780), `completed/success`, exact head SHA. It was a `push` run, not `workflow_dispatch` or an earlier SHA.
- Locked environment setup, lock verification, Python compile, Linux checkpoint recovery/ownership, unified monitor, full regression (**2,934 passed, 2 existing warnings**), TCP Syslog smoke, bounded TCP reliability, TCP management, JSONL runtime acceptance, restricted report and benchmark, Node/Chromium/axe, and tracked-file immutability steps all succeeded. Run artifact count: **0**. `v0.4.0` tag and Release target remain `eecd6ee1cda0545e34b01c42e1a2163a899bcc27`.
- `Verify collector JSONL runtime on Linux` ran after full pytest and completed successfully. Its exact marker occurred once: `COLLECTOR_JSONL_LINUX_ACCEPTANCE_PASS roles=2 runs=80 synthetic=1 leaks=0`.
- The committed harness fixes two roles × eight scenarios × five first-attempt subprocesses = 40 per role and 80 total. Scenarios are readiness, SIGINT, SIGTERM, normal stop, immediate stop, accepted record pending analysis, malformed recovery, and queue-full shutdown. It has no retry loop.
- In addition, the harness checks two concurrent connections and rejects a third; progress while another connection is partial; split UTF-8; 30 reconnects per role; pure decoder 32-record success and atomic 33-record refusal; and a separate 256-record soak per role. Successful soak assertions require received, validated, queued, parser-recognized, and analyzed counts of 256, with rejected, malformed, and dropped counts zero.
- Queue-full checks require exactly 256 accepted, at least one rejected overflow, `DEGRADED`, fixed `JSONL_RUNTIME_QUEUE_FULL`, no analysis success, and 256 queued records accounted as dropped at shutdown. It is not accepted as a timeout or success.
- Cleanup checks require stopped runtime, no child/worker/listener/connection task/queued event or queued byte, no positive FD delta when `/proc/self/fd` is available, and successful same-port rebind. The harness captures bounded RSS and timing for its private result but emits neither numeric value in the CI log; `leaks=0` is the checked aggregate. Ubuntu filesystem/mount type and numeric FD/RSS baselines were not recorded. IPv6 was not tested.
- CI output contained only the fixed JSONL completion marker for this harness. It did not upload artifacts. Synthetic child outputs and temporary state remained outside artifacts.

Evidence is bounded to that harness and runner. It is not a long-duration soak, an RSS limit, a filesystem durability result, or a Vector integration test. The exact workflow did not execute Vector.

## Topology

```text
one synthetic input file (read-only)
  → Vector v0.60.0 file source
  → minimal allowlist transform
  → one JSON object + LF per event
  → loopback JSONL runtime (one fixed role)
  → existing role parser
  → deterministic analysis
  → bounded in-memory result
```

The JSONL runtime is the trusted adapter boundary. Collector metadata is not a sender identity. The listener remains loopback-only and this topology has no public API, SSE, UI, HTML, guidance, or restricted-report connection. A successful TCP write is not an analyzer analysis acknowledgement.

## Configuration Contract

The eventual configuration is a generated, reviewable, version-pinned candidate for one role (`application` or `ssh`) and one explicit synthetic file. It must not use globs, recursive discovery, actual HOME, system log directories, or arbitrary source metadata. No configuration is executed in this phase.

- Disable Vector's API explicitly. Validate healthcheck and external telemetry behavior against the fixed v0.60.0 source/config, then disable them; a default is not assumed from a newer version.
- Disable disk buffers. Use one explicitly bounded memory buffer with a full-buffer policy that blocks or fails visibly; do not silently drop. The proposed design cap is 16 MiB, pending validation that this exact v0.60.0 configuration is accepted and has the intended semantics.
- Use a dedicated private state/checkpoint directory, separate from file-monitor checkpoints, with restrictive ownership and mode. Config and executable are read-only; one synthetic input is read-only; writable state and bounded temporary storage are the only writable paths.
- Remove source path, host, and unnecessary metadata before serialization. Keep only the six closed adapter fields: `schema_version`, `source_role`, `payload`, `collector_instance_alias`, `sequence_hint`, and `retry_hint`. The role must equal the runtime's configured role. Alias is a bounded synthetic label, not authentication; sequence and retry hints do not establish identity, ordering, deduplication, or exactly-once delivery.
- Encode exactly one JSON object followed by LF. No arbitrary metadata map, shell/tool invocation, remote config, dynamic download, or user-authored transform is allowed.
- Run as a dedicated non-root UID/GID with no Docker socket, host shared directories, report/checkpoint access, or broad `/proc`, `/sys`, device access. Candidate controls include dropped capabilities, `no_new_privs`, read-only root, private bounded tmp, and process/FD/CPU/memory/disk limits.
- Deny external egress independently at the disposable environment boundary. Do not infer egress denial from Vector configuration. Permit only the required loopback connection, and verify no non-loopback listener/socket before and after.

Offline validation is planned as `vector validate --config-yaml <single-private-config> --skip-healthchecks --deny-warnings`, after external egress has already been denied. Use one explicit file path, never a glob, config directory, default `/etc/vector` path, or environment interpolation; do not pass `--dangerously-allow-env-var-interpolation`. This command is for static config correctness/topology checks, not wire or delivery proof. Before execution, verify each flag against the hash-verified v0.60.0 binary's local `validate --help` and pinned source. If that exact command starts a listener or attempts network access, stop. Any validation failure is a hard stop and its raw output must pass through a fixed-category wrapper. Do not use a mutable online config/schema service. The official [Vector CLI reference](https://vector.dev/docs/reference/cli/) and [configuration validation guide](https://vector.dev/docs/administration/validating/) were checked 2026-10-27; their descriptions are documentation evidence, not binary-execution evidence.

## Wire Acceptance

Capture bytes at the receiving test boundary and compare them byte-for-byte with expected fixtures. The expected record is UTF-8 JSON with the exact six keys and one LF delimiter; there is no RFC 6587 prefix. The core limits remain payload **8,192 bytes**, line **65,536 bytes including LF**, and at most **32 records in one decoder feed**. A 33-record feed must fail atomically without partial acceptance.

Fixtures must include ASCII, Korean, escaped newline, UTF-8 multibyte boundaries, duplicate-key rejection at the adapter, no NaN/Infinity, no extra key, and payload/line exact-limit and limit+1 cases. Also test fragmented writes, multi-record writes, reconnect/retry duplication, rename/create rotation, copytruncate, Vector/runtime restart, unavailable listener, memory-buffer full, state corruption, invalid source UTF-8, oversized source line, and fail-closed metadata stripping. Do not treat a socket `write()` boundary as a record boundary.

Rotation and restart cases must record replay/duplicate/loss counts. The file source's progress/checkpoint plus TCP sink write does not provide an analyzer acknowledgement. If the analyzer is unavailable, the tested full-buffer behavior must be visible and bounded; recovery can replay or duplicate, and a successful write followed by analyzer failure can lose an event. No exactly-once or lossless claim is allowed.

## Isolation Gate

No execution occurs unless all are independently checked in a disposable Ubuntu 24.04 x86_64 VM or equivalently isolated environment:

1. Re-fetch only the fixed official artifact in a task-owned temporary area; compare its byte count and SHA-256 to the existing manifest and official checksum. Do not execute before checking archive members for traversal, symlink/hard-link, set-id, unexpected payload, and permission hazards.
2. Run as non-root with an immutable artifact, read-only config/input, private state/temp, no repository or real HOME access, and no host-shared folder or container socket.
3. Apply external egress deny outside Vector and independently probe it. If deny cannot be proven, status is `ISOLATION_BLOCKED`.
4. Set CPU, memory, PID, open-file, disk, and wall-time bounds. Capture process/socket/file inventory before and after. Check no external bind, child, listener, socket, or temporary state remains; cleanup is not secure erase.
5. Keep the memory buffer bounded and disk buffer disabled. Any need for disk buffering, privileged/root execution, remote endpoint, or external service is `NO_GO` for this pilot.
6. Scan safe projections and captured outputs for canaries. Never print raw Vector or analyzer output; report only fixed stage/category and safe counts.

Phase 35.4A measured the compressed archive at 58,655,370 bytes, regular-member expanded size at 160,893,403 bytes, and extracted `bin/vector` at 160,680,968 bytes. Including a second read-only binary/license staging copy, bounded state, buffers, synthetic input, capture and test output, the planned peak is 482,025,136 bytes including 15% margin. Require at least 1.25 GiB free at start and retain at least 512 MiB. These are preflight calculations, not Ubuntu runtime measurements; recheck quotas and free space in the disposable environment.

## Resource Budget

Proposed limits for the later disposable run are one source file, one role, one Vector process, one analyzer runtime, at most two loopback connections, 128 Vector memory-buffer events with an 8 MiB conservative serialized-line allowance (candidate only; subject to config validation), analyzer queue 256 events/1 MiB, payload 8,192 bytes, JSONL line 65,536 bytes, and bounded runtime/history limits already enforced by Phase 35.2/35.3. These are test limits, not capacity or SLA claims.

Disk reserve is numerically planned by Phase 35.4A but must be checked against the disposable Ubuntu volume. Execution remains blocked by missing OS isolation and independently verified egress deny.

## Failure Semantics

The test plan distinguishes collector file checkpoint, Vector buffer admission, socket write, JSONL validation, queue admission, parser recognition, and completed analysis. Counters at one layer do not imply success at the next. Queue full, malformed/oversized input, metadata-strip failure, state corruption, listener outage, restart, and timeout must fail visibly without raw text. No automatic retry is added by the analyzer; Vector retries may create duplicates. The analyzer has no durable spool and cannot restore prior in-memory work after restart.

Before and after each case, enumerate only the isolated process's files and sockets. Remove temporary artifacts and state at the end; do not claim secure deletion.

## Privacy and AI Boundary

Only synthetic input with explicit canaries is allowed. Raw payload may exist in the synthetic source, Vector memory/event/transform/buffer, loopback bytes, and the trusted parser boundary. Disk buffer is off. Source path/host metadata is stripped before the adapter; status, errors, ordinary logs, public API/SSE/UI/HTML, restricted reports, and lexical guidance receive no raw payload or collector metadata. CI artifacts remain disabled.

Vector's checksum-only artifact disposition and the three `UNRESOLVED` credential-shaped strings remain visible risks. Neither is cleared by this plan. AI, Gemini, embedding, and local LLM are not called. AI does not select role, frame records, strip metadata, establish trust, or generate/execute Vector config or parser code.

Actual user data, organization operation, remote collection, TLS/mTLS, durable spool/replay, and exactly-once/lossless delivery remain `NO_GO` or unsupported.

## Phase 35.4 Entry Criteria

Phase 35.4A closed the pinned archive byte/checksum and metadata inventory and added synthetic expected-wire decoder fixtures. A later execution request must still close all of these:

- disposable Ubuntu 24.04 x86_64 isolation and independently verified egress deny;
- repeat artifact byte/checksum verification in the disposable Ubuntu environment and confirm expanded disk quota;
- execute fixed v0.60.0 config validation under egress deny; confirm config fields and the 8 MiB memory-buffer bound;
- capture actual source path/host metadata stripping and compare exact six-key JSONL bytes with fixtures;
- analyzer test runtime bound to the fixed loopback endpoint, one selected role;
- capture-based expected-wire comparison and 8,192/65,536/32-record boundaries;
- rotation, copytruncate, retry/duplicate, restart, full-buffer, unavailable-listener, corrupt-state, and cleanup results;
- non-root permissions, resource limits, process/socket/file inventory, canary scan, and no artifact upload;
- explicit re-acceptance of checksum-only provenance for this single synthetic isolated run while retaining the three unresolved string findings.

If any prerequisite is missing, do not acquire or run Vector: report `ISOLATION_BLOCKED` or `PRECONDITION_PENDING`. Even a successful bounded experiment would not approve production integration, real data, organization rollout, remote collection, or AI-assisted parser changes.
