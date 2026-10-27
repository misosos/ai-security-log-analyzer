# Phase 35.0 — 기업형 로그 수집 연동 아키텍처 설계

후속 상태: Phase 35.3은 Vector가 아닌 별도 JSON Lines loopback runtime을 synthetic application/SSH payload로 기존 in-memory deterministic pipeline에 연결했다. 이는 외부 collector 또는 Vector 실행을 뜻하지 않는다. Linux/Vector 통합 `NOT_TESTED`, 실제 자료·조직 운영 `NO_GO`. [검증 기록](collector_jsonl_runtime_35_3.md).

조사 기준일: **2026-10-26**. 공식 문서와 고정 릴리스 메타데이터의 정적 비교다. collector binary/container/plugin을 **설치·다운로드·실행하지 않았다**. 실제 사용자 자료나 실제 로그를 읽지 않았다. 프로젝트 코드와 dependency도 변경하지 않았다.

## Decision

**Vector 0.60.0은 첫 합성 연동 후보라는 설계상 `CONDITIONAL_GO`를 유지하되, native socket framing은 기존 analyzer listener와 `INCOMPATIBLE`이다. Phase 35.2에서 별도 closed JSON Lines adapter의 pure core를 구현했다. Vector custom VRL 경로는 정적으로 구성 가능해 보이나 `CUSTOM_FRAMING_UNPROVEN`이며 실제 Vector 연동은 `NOT_TESTED`다.**

이는 Vector 설치·실행 승인이나 제품 지원 판정이 아니다. Binary signature/SBOM/provenance는 미확인이다. checksum-only 잔여 위험은 disposable synthetic 격리 pilot에만 조건부 수용 가능하다고 판단했으며, 격리 통제 별도 gate 전에는 Vector를 실행하지 않는다. 정확한 wire bytes, rotation, buffer, egress 차단, 권한 및 privacy는 실행 검증 전까지 미확정이다. 외부 도구의 기능만으로 우리 환경의 안전성·무유실·exactly-once를 추론하지 않는다.

Phase 35.2 core 구현은 Vector checksum-only provenance 잔여 위험을 해소하거나 Vector 실행을 승인하지 않는다. Credential-shaped scan의 `UNRESOLVED` 3건도 그대로 유지한다. Linux 및 실제 Vector 연동은 `NOT_TESTED`; 실제 사용자 자료·조직 운영은 `NO_GO`다. [Pure core 계약·검증 기록](collector_jsonl_adapter_core_35_2.md).

Phase 34 종료 상태:

- 합성 loopback 관리 pilot: GO (Phase 34.5 정확한 SHA의 CI와 사용자 수용 근거에 한함).
- 사용자 안내 이해도: 최종 10/10 PASS. 최초 FAIL 항목 5, 7, 10과 문구 수정·재확인 기록은 [Phase 34.5 수용 기록](loopback_tcp_syslog_management_acceptance_34_5.md)에 보존한다.
- 실제 사용자 자료와 조직 운영: NO_GO.
- 인증 없는 원격 수집: NO_GO; TLS/mTLS 미지원.
- durable spool 미지원, exactly-once·무유실 미보장.
- crash·SIGKILL·전원 장애 복구: NOT_TESTED.
- 과거 macOS SSH/SIGTERM 단발 실패: UNEXPLAINED_NON_REPRODUCED.
- 과거 Ubuntu smoke 실패는 내부 stage가 기록되지 않았다. 이를 readiness marker race와 같은 원인으로 단정하지 않는다.
- Phase 34.2 application/SIGTERM의 Ubuntu 실패도 marker race가 원인이었다고 소급 단정하지 않는다. 수정 SHA에서의 후속 성공은 실패 원인 증명이 아니다.

## Current Evidence

시작 gate는 main, clean tree, local/origin 정확한 시작 SHA 86813527316b345029823a0b6b1a4ed7a3acac90, ahead/behind 0으로 확인했다. push run [40315288012](https://github.com/misosos/ai-security-log-analyzer/actions/runs/40315288012)은 정확한 SHA에서 completed/success였다. Ubuntu locked install, 전체 pytest 2867 passed / 기존 warning 2개, SSH checkpoint ownership와 unified monitoring, TCP 기본 smoke, bounded reliability, management, restricted report, Chromium·axe 14 states와 external_requests=0, tracked-file 불변이 성공했다. 완료 표식은 TCP_SYSLOG_SMOKE_COMPLETE roles=2 subprocesses=4 synthetic=1, TCP_SYSLOG_LINUX_RELIABILITY_PASS roles=2 runs=80 synthetic=1 leaks=0, TCP_SYSLOG_MANAGEMENT_SMOKE_PASS roles=2 synthetic=1 leaks=0였다. CI artifact는 0개였다. v0.4.0 tag 및 Release target은 eecd6ee1cda0545e34b01c42e1a2163a899bcc27이었다.

이 증거는 Phase 34의 자체 loopback pilot에만 해당한다. Fluent Bit, Vector, OpenTelemetry Collector는 이 단계에서 실행하지 않았으며 그 어떤 비교 내용도 프로젝트 검증 결과가 아니다. 현재 analyzer는 자체 RFC 6587 decoder와 loopback runtime을 가지고 있지만 수집 제품으로 파일 탐색·rotation·durable queue를 제공하지 않는다. 현재 내부 상한은 Phase 34 코드 계약이며 외부 collector의 상한을 보증하지 않는다.

## Candidate Comparison

안정 릴리스와 공식 문서를 2026-10-26에 조회했다. 태그·commit은 비교 기준점이지 설치 승인이나 재현된 artifact digest가 아니다.

| 후보 | 안정 릴리스·commit·license | 플랫폼·입력 | buffering·rotation·전달 | 분석기 연결 및 판단 |
|---|---|---|---|---|
| Fluent Bit | v5.1.5, tag commit 0039c4f0d1b530bedd8448df2fa4c301d58a5b91; Apache-2.0 | 공식 자료는 Linux x86_64/Arm64와 macOS를 다룬다. Tail과 TCP Syslog 입력이 있다. Syslog 입력은 octet-counting 모드를 문서화한다. | tail은 rename/create와 copytruncate를 다루지만 copytruncate에는 race/loss 위험이 있다. memory/filesystem buffering과 retry가 있고 output logical limit 도달 시 오래된 chunk 폐기가 가능하다. | TCP output 문서만으로 기존 analyzer가 요구하는 RFC 6587 decimal length framing과 payload 보존을 확정하지 못했다. 풍부한 pipeline이지만 현재 pilot과의 wire compatibility 증거가 Vector 후보보다 불충분하다. |
| **Vector** | **0.60.0, tag commit 0d0b35865036f8b5c2f0104d9744fa84985ffff1; MPL-2.0** | release asset 목록에서 Linux amd64/arm64와 macOS arm64를 확인했다. 공식 File source와 TCP/Unix socket sink가 있다. | 파일 source는 rotation과 multiline 설정을 제공하고 copytruncate에는 드문 데이터 손실 가능성을 문서화한다. memory/disk buffer 크기와 full 시 block 정책을 설정할 수 있다. disk buffer는 원문이 디스크에 남으며 매 write의 durable fsync 보장은 아니다. | Socket sink의 bytes framing, VRL의 문자열 byte 길이 기능을 조합해 기존 octet-counting receiver를 위한 변환을 설계할 수 있다. 정확한 변환·codec 동작은 합성 검증 전이다. 별도 프로세스로 격리 가능하여 첫 adapter 후보로 선택한다. |
| OpenTelemetry Collector | distribution v0.163.2 release commit 6c65793ec707f673304e52dfcb642684fda1a048; core/contrib 모듈 v0.163.0; Apache-2.0 | 공식 release는 Linux amd64/arm64 및 macOS amd64/arm64 artifacts를 제공한다. filelog/syslog receiver는 contrib 구성요소다. Syslog receiver는 TCP, octet counting, TLS/mTLS 옵션을 문서화한다. | receiver·processor·exporter를 조립할 수 있지만 안정성은 선택한 distribution/configuration에 의존한다. 해당 syslog receiver의 연결 상한 기본값은 무제한일 수 있어 명시 설정이 필요하다. | analyzer에 OTLP Logs endpoint/adapter가 없어 D는 새 protocol adapter와 mapping을 요구한다. 첫 pilot의 wire/parser 표면을 불필요하게 넓힌다. |
| 자체 TCP listener | 프로젝트 Phase 34 loopback pilot | 현 코드에서 합성 application/SSH, loopback, Linux/macOS 검증 | bounded in-memory queue이나 durable spool·file rotation·retry 없음; downtime loss 및 재전송 duplicate 가능 | 기존 parser 연결이 가장 직접적이지만 파일 수집·rotation·buffer/retry를 계속 자체 구현해야 하므로 기업 연동 목표의 수집 책임을 해결하지 않는다. |
| 기존 file tail 경로 | 프로젝트 v1/v2/v3 file monitor | macOS/Linux local file; 기존 parser/checkpoint contract | rotation/checkpoint는 기존 구현 범위에 한함. 외부 forwarding buffer/remote transport는 제공하지 않는다. | 분석 의미와 공개 contract를 가장 잘 보존하지만 사람이 로그 파일을 준비·지정해야 하는 제약이 남는다. 별도의 private spool을 만들면 source lifecycle/보존 계약을 새로 설계해야 한다. |

외부 제품별 세부 근거와 약점은 아래 공식 문서를 따른다. 지원 플랫폼이 문서에 있다는 점은 이 프로젝트가 그 조합을 검증했다는 뜻이 아니다.

| 주제 | Fluent Bit | Vector | OpenTelemetry Collector |
|---|---|---|---|
| release/license/platform | [v5.1.5 release](https://github.com/fluent/fluent-bit/releases/tag/v5.1.5), [downloads/platforms](https://docs.fluentbit.io/manual/installation/downloads), [license](https://github.com/fluent/fluent-bit/blob/v5.1.5/LICENSE) | [v0.60.0 release](https://github.com/vectordotdev/vector/releases/tag/v0.60.0), [release list](https://vector.dev/releases/), [license](https://github.com/vectordotdev/vector/blob/v0.60.0/LICENSE) | [v0.163.2 release artifacts](https://github.com/open-telemetry/opentelemetry-collector-releases/releases/tag/v0.163.2), [core v0.163.0](https://github.com/open-telemetry/opentelemetry-collector/releases/tag/v0.163.0), [contrib v0.163.0](https://github.com/open-telemetry/opentelemetry-collector-contrib/releases/tag/v0.163.0) |
| file/Syslog, framing, rotation | [Tail](https://docs.fluentbit.io/manual/data-pipeline/inputs/tail), [Syslog input](https://docs.fluentbit.io/manual/data-pipeline/inputs/syslog) | [File source](https://vector.dev/docs/reference/configuration/sources/file/), [socket sink](https://vector.dev/docs/reference/configuration/sinks/socket/), [VRL examples](https://vector.dev/docs/reference/vrl/examples/) | [Syslog receiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/v0.163.0/receiver/syslogreceiver), [filelog receiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/v0.163.0/receiver/filelogreceiver) |
| buffers, retry, TLS/security | [backpressure](https://docs.fluentbit.io/manual/administration/backpressure), [TLS](https://docs.fluentbit.io/manual/administration/transport-security), [TCP/TLS output](https://docs.fluentbit.io/manual/data-pipeline/outputs/tcp-and-tls) | [buffer model](https://vector.dev/docs/architecture/buffering-model/), [end-to-end acknowledgements](https://vector.dev/docs/architecture/end-to-end-acknowledgements/), [hardening](https://vector.dev/docs/setup/going-to-prod/hardening/) | [security config](https://opentelemetry.io/docs/security/config-best-practices/), [hosting guidance](https://opentelemetry.io/docs/security/hosting-best-practices/) |

Across all three, transformations and redaction features do not automatically establish a privacy boundary. Configuring fields, source permissions, metrics labels, diagnostic logs, TLS identity and disk-buffer retention remains the deployer's responsibility. Product docs do not establish our end-to-end acknowledgement point, max end-to-end event size, no-loss semantics or safe configuration for this analyzer.

## Proposed Architecture

**Candidate A: Vector file source → reviewed transform → loopback TCP Syslog → existing parser.** Keep Vector outside the Python process and project dependency graph. A narrowly configured instance would read only operator-selected application or SSH files. It must remove source path and host metadata before the sink. A reviewed transform might form decimal-byte-length + one ASCII space + payload, then send bytes to the already bounded loopback receiver. Phase 35.1 found no native ASCII octet-counting encoder, and the transform/codec byte contract remains unverified; direct interoperability is not established.

For the pilot, one role and one source family per isolated instance; no cross-source correlation. Restrict filesystem reads to explicit files and state directory, run as a non-root dedicated user, deny external egress, expose no public API, and keep the analyzer endpoint loopback-only. The local endpoint itself is not authenticated: another local process may inject frames. If that risk is unacceptable, do not run the pilot; a later authenticated local ingest contract must be designed.

The collector's own file checkpoints/state directory are distinct from analyzer checkpoints. No collector event or state is automatically published to public schema 2/3 API/SSE or UI. Existing analysis continues through the selected role's existing parser and deterministic detection/correlation/risk/case path. Public projection remains alias-based. Do not run the same file through both collector and file monitor simultaneously unless a later gate defines deduplication and ownership.

| Flow | Raw-data locations | Trust/parser boundary | Ack, outage, retry and duplicate | Rotation/backpressure | Privacy, checkpoint/replay, complexity and schema impact |
|---|---|---|---|---|---|
| **A. Collector → loopback TCP Syslog → existing parser** | source file; collector bounded memory; optional collector disk buffer; transient socket/decoder/parser memory | collector process is not source identity proof. Loopback accepts local injection. Parser gets only bounded validated payload; public DTO uses existing projection | socket write is not analyzer parse/analysis acknowledgement. Collector retries may duplicate; analyzer outage can block/fail or retain data according to tested buffer policy. No exactly-once | collector handles rotation; bounded buffer must be configured. Full/block must be tested against source tail and process behavior | raw can persist in collector disk buffer. Separate collector state, no analyzer checkpoint reuse. No schema 2/3 change. Low integration complexity after framing proof |
| B. Collector → new authenticated local ingest endpoint → parser | source, collector, local transport, endpoint buffers | endpoint auth can distinguish configured local client, but key/cert lifecycle and authorization are new trust machinery | can acknowledge enqueue or analysis only if explicit protocol is implemented; retries before/after ack can duplicate | endpoint must implement queue/backpressure and buffer limits; duplicates remain unless idempotency design | new production listener and secret storage; new status/API/epoch contract. Larger code/security surface than A |
| C. Collector → private spool directory → existing file monitor | source and durable spool files, backups/sync may copy them | file owner/mode and directory handoff define trust; existing parser can read only if a new role/config adapter is added | rename/atomic handoff can reduce partial reads but crash windows and replay/duplicate semantics need explicit manifest/ack | rotation and spool quotas, cleanup, disk full, no-clobber/atomic publish all become project contracts | raw logs persist on disk; existing checkpoint must not be silently reused. Medium/high complexity; adds sensitive durable copy |
| D. Collector → OTLP Logs → dedicated adapter → pipeline | source, collector buffers, OTLP exporter queues, adapter memory and possibly disk | OTLP receiver identity/TLS plus strict closed attribute/resource mapping required; arbitrary attributes must be rejected | protocol acknowledgements have layer-specific meaning; they do not imply analyzer case/risk completion. Retries can duplicate | collector buffering is available; adapter queue and per-event limits still needed | schema and adapter conversion are new; no current OTLP analyzer input. Highest migration surface, while preserving analysis only if mapping is exact |

Candidate A was the Phase 35.0 initial hypothesis. Phase 35.1A supersedes its framing assumption: native Vector framing is incompatible, and the VRL path remains unproven. Do not modify the existing RFC 6587 listener to accommodate it. The selected next step is the independent JSON Lines adapter pure core; the previous Candidate A is not implementation approval.

## Data Contract

The collector-to-analyzer internal envelope is a closed, versioned design candidate, not a new public DTO:

| Field | Contract |
|---|---|
| schema_version | fixed supported integer/version only; unknown version fails closed |
| source_role | exactly application or ssh, explicitly configured; never inferred from payload or sender metadata |
| event_time | parsed timezone-aware timestamp or explicit unavailable; retain source timestamp semantics, do not treat as trusted wall clock |
| collector_instance_alias | per-run opaque alias, scoped to one collector instance; no host, path or stable global ID |
| sequence_hint | optional bounded advisory sequence; sequence_hint는 exactly-once ID가 아니다 and may reset/repeat |
| payload_length | bounded byte length, must equal received payload bytes |
| payload | strict UTF-8, bounded bytes/text, only trusted internal parser handoff; never status/error/log/public projection |
| truncation | closed enum/boolean indicating known truncation; truncated payload is rejected for normal analysis, never silently accepted as complete |
| possibly_retried | closed boolean/enum hint only; does not prove duplicate identity or deduplicate |

No arbitrary metadata map, collector hostname, source path, credential, TLS key, internal exception, unbounded labels, tool/action field or LLM prompt field. Do not persist a payload hash by default: hashes of low-entropy/known messages can be fingerprints. Do not create a public content hash as identity. Enforce frame byte, event count, resident byte, connection, queue and disk budgets independently; over-limit input fails as a whole and is never truncated into an apparently valid event.

## Trust Boundaries

1. **Source file → collector:** file selection and OS permissions grant read access; collector configuration is privileged operational input. Reject symlink/path substitution where the host integration can enforce it; never broaden file globs silently.
2. **Collector → local analyzer:** local process boundary, not authenticated by loopback alone. Bind only explicit loopback. No external interface or remote host. The first pilot must use synthetic data and an egress-denied test environment.
3. **Collector buffer/state:** disk buffer contains raw or near-raw sensitive data; it is not assumed encrypted. Use a private directory, bounded quota, explicit retention/cleanup, no cloud sync/backup, and disclose crash remnants. If organization policy requires encryption or retention guarantees not available in the selected deployment, stop.
4. **Analyzer parser → analysis:** reuse existing role parser and deterministic analysis. AI never changes source trust, parsing authority, detection, correlation, risk, case, or response.
5. **Internal result → public projection:** existing subject aliases and safe summaries remain. No raw payload, source path, hostname or original identifier is added to public API, SSE, UI, HTML report or ordinary errors.

## Failure Semantics

| Failure | Required design behavior |
|---|---|
| source read/rotation error | collector reports fixed degraded category; no raw line/path in public diagnostics; count cannot imply full coverage |
| malformed/truncated/oversized frame | reject the whole event, close/fail that delivery boundary as specified, increment rejected rather than accepted; no payload echo |
| queue full or disk full | explicit backpressure or terminal degraded/failed state; never silently claim normal. If configured bounded buffer evicts data, count/report loss and treat as degraded; prefer block/fail policy for pilot, then test deadlock and source behavior |
| collector unavailable | analyzer receives nothing; no invented empty-success state; restart does not prove replay |
| analyzer down before socket write | collector may retain/retry only according to tested policy; duplicate/loss depends on buffer and rotation windows |
| analyzer accepts socket bytes then crashes before parse/analysis | sender's write success is not analyzer acknowledgement; retry can duplicate, no retry can lose |
| analysis completes but collector does not observe an application-level ack | do not claim rollback; retry may duplicate prior result and must not be described as exactly once |
| config, certificate, or plugin error | fixed category, no secret/path/exception detail; fail closed before forwarding; no runtime plugin download |

Status categories may be closed to COLLECTOR_NOT_CONFIGURED, COLLECTOR_UNAVAILABLE, COLLECTOR_AUTH_FAILED, COLLECTOR_TLS_FAILED, COLLECTOR_BACKPRESSURE, COLLECTOR_QUEUE_FULL, COLLECTOR_SPOOL_FULL, COLLECTOR_MESSAGE_REJECTED, COLLECTOR_SOURCE_DEGRADED, COLLECTOR_RETRYING, COLLECTOR_STOPPED. Public state must separate partial success from healthy coverage and omit raw data, path, actual hostname, account/IP, certificate material and internal exception. No metric label may take arbitrary source values.

sequence_hint and transport ordering are advisory only. TCP preserves byte order within one connection, not source event time or global order across connections/files. Rotation, collector restart and retry can replay or miss messages depending on checkpoints and crash point. Do not promise exactly-once, lossless processing, or automatic replay. Silent drop is prohibited; any known loss becomes degraded/failed with an aggregate count.

## Privacy

The source file and optional collector disk buffer are the main persistent raw-data locations; backups, snapshots, swap, crash dumps and OS diagnostics are additional residual locations. No raw logs, traces, packet captures, collector state, rendered reports or secrets go to CI artifacts. Transform away source path/host fields and suppress payload in ordinary logs/metrics. Apply redaction only when the parser's required evidence is preserved; redaction is not a substitute for the public projection boundary. Do not use actual operational logs in the initial pilot.

Public schema 2/3, SSE cursors, UI, HTML reports, lexical guidance, restricted report contract and file monitoring v1/v2/v3 remain unchanged. The collector is not added to project dependencies. No cross-source correlation or auto-publication. Disk buffering, if later accepted, expands retention and deletion responsibilities and must be explicitly approved before implementation.

## AI Assistance Boundary

No AI runs in collection, parsing, trust decisions or failure handling. A later isolated proposal tool may use only approved synthetic samples/statistics to draft field mappings or parser candidates with citations to official vendor documentation and a static diff for operator review. It may not receive raw operational logs, set source identity, discard events, execute code/tools/shell/network, modify parser configuration, or change detections/risk/cases. Any proposal requires fixed model/runtime/artifact, network denial, closed sample DTO, structured output, schema validation, regex/AST/ReDoS checks, fuzz/property tests, parity against existing parser fixtures and human approval. Automatic parser activation is NO_GO.

## Supply Chain

The official release/tag evidence below is a candidate pin, not a verified package/image digest, signature, provenance or SBOM audit. No binary, container, plugin or runtime dependency was downloaded or executed on 2026-10-26.

| Candidate pin | Source revision / license | Supply-chain notes and open checks |
|---|---|---|
| Fluent Bit v5.1.5 | 0039c4f0d1b530bedd8448df2fa4c301d58a5b91; Apache-2.0 | release and official download/install path exist. Before adoption verify exact OS package/image digest, signed repository metadata/key lifecycle, SBOM/provenance, plugin inventory and runtime permissions. |
| **Vector 0.60.0** | **0d0b35865036f8b5c2f0104d9744fa84985ffff1; MPL-2.0** | official release lists platform artifacts and SHA256SUMS; release commit is verified. Phase 35.1 must independently verify downloaded asset digest/signature provenance, SBOM availability, license/NOTICE obligations, config version, default telemetry/egress, and whether plugins/runtime fetch occur. Do not use mutable latest tags. |
| OpenTelemetry Collector release v0.163.2 | release commit 6c65793ec707f673304e52dfcb642684fda1a048; Apache-2.0 distribution; core/contrib v0.163.0 | release assets include SBOM and signature metadata; verify each selected artifact and its component inventory. Prefer a minimal pinned distribution, not an unrestricted contrib binary. Review receiver/exporter defaults and configuration secret handling. |

All candidates run as a separate least-privilege process; no root, host networking, privileged container, broad filesystem mounts, or arbitrary plugin/runtime download. Prefer a host package or pinned standalone artifact over an unpinned container tag. The project Python dependency list stays unchanged. Secret material should not be embedded in a general config; a later remote/TLS design would need a separate secret store and rotation contract. The local-only candidate does not claim transport encryption.

Official references checked on **2026-10-26**:

- RFC 5424 Syslog: [RFC Editor](https://www.rfc-editor.org/rfc/rfc5424); TCP framing context RFC 6587: [RFC Editor](https://www.rfc-editor.org/rfc/rfc6587).
- Python stream API reference (not used to implement a listener in this phase): [Python asyncio streams](https://docs.python.org/3/library/asyncio-stream.html).
- Fluent Bit: [release v5.1.5](https://github.com/fluent/fluent-bit/releases/tag/v5.1.5), [downloads](https://docs.fluentbit.io/manual/installation/downloads), [tail](https://docs.fluentbit.io/manual/data-pipeline/inputs/tail), [Syslog input](https://docs.fluentbit.io/manual/data-pipeline/inputs/syslog), [backpressure](https://docs.fluentbit.io/manual/administration/backpressure), [TLS](https://docs.fluentbit.io/manual/administration/transport-security), [TCP/TLS output](https://docs.fluentbit.io/manual/data-pipeline/outputs/tcp-and-tls).
- Vector: [release v0.60.0](https://github.com/vectordotdev/vector/releases/tag/v0.60.0), [official releases](https://vector.dev/releases/), [file source](https://vector.dev/docs/reference/configuration/sources/file/), [socket sink](https://vector.dev/docs/reference/configuration/sinks/socket/), [buffering](https://vector.dev/docs/architecture/buffering-model/), [end-to-end acknowledgements](https://vector.dev/docs/architecture/end-to-end-acknowledgements/), [VRL length examples](https://vector.dev/docs/reference/vrl/examples/), [hardening](https://vector.dev/docs/setup/going-to-prod/hardening/).
- OpenTelemetry: [collector release v0.163.2](https://github.com/open-telemetry/opentelemetry-collector-releases/releases/tag/v0.163.2), [contrib syslog receiver v0.163.0](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/v0.163.0/receiver/syslogreceiver), [security config](https://opentelemetry.io/docs/security/config-best-practices/), [hosting](https://opentelemetry.io/docs/security/hosting-best-practices/).
- General logging safeguards: [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html); NIST log management: [SP 800-92](https://csrc.nist.gov/pubs/sp/800/92/final). These are guidance, not proof that a candidate meets our requirements.

## Verification Plan

Phase 35.1 begins with a static supply-chain audit only: fixed release/source revision, platform artifact matrix, license/NOTICE, checksum/signature/provenance/SBOM, runtime privileges, config secrets, plugin/runtime downloads, telemetry/egress defaults, and estimated disk/memory usage. Do not install or run a collector in 35.0.

Only after that gate, propose an isolated synthetic test plan: pinned Vector artifact in a disposable no-egress environment; synthetic application and SSH files; rename/create and copytruncate fixtures; multiline and oversized records; byte-exact framing parity with existing decoder; memory/disk quotas and full-buffer behavior; retry/restart duplicate/loss points; path/host metadata removal; strict source-role mapping; loopback-only binding; raw canary checks across process output/status/public API/SSE/UI/HTML; shutdown and state cleanup. No artifact containing raw input or collector state. Every result must distinguish documented feature, static audit and test actually run.

No real logs, production listener, network exposure, external collector installation, or analyzer public integration is part of this phase.

## Limitations

- Product documentation is not independent security assurance and does not guarantee the exact deployment's loss, duplication, ordering, disk durability or resource behavior.
- We did not verify rotation, copytruncate, multiline, buffer saturation, TLS, certificate identity, egress, digest/signature, memory/disk limits or byte-exact interoperability by execution.
- Vector disk buffer is persistent sensitive data and is not claimed encrypted or fsync-durable per event. when_full=block behavior and shutdown interactions need tests.
- A loopback TCP listener does not authenticate local senders. This proposal is synthetic-only; real user data and organizational deployment remain NO_GO.
- TLS/mTLS, remote collectors, durable spool support in the analyzer, long-term retention, backup/cloud-sync policy, authentication/RBAC, exactly-once and lossless delivery are not approved.
- Existing public schema and analysis semantics must not be expanded to accommodate collector metadata.
- Previous macOS SSH/SIGTERM one-off remains UNEXPLAINED_NON_REPRODUCED. Prior Ubuntu failures without stage detail are not retroactively attributed to the later local marker race.

## Phase 35.1 Entry Criteria

Proceed only if all are documented and independently reviewable:

1. Exact stable Vector release, immutable source revision and platform artifact are selected; license/NOTICE is acceptable; checksum, signature/provenance and SBOM/component inventory are verified.
2. Linux amd64/arm64 and macOS artifact support is verified for the exact chosen release; no runtime package/plugin download occurs.
3. Least-privilege filesystem scope, private state directory, bounded memory/disk, full-buffer action, retention/deletion and egress-deny controls are explicit.
4. The 0.60.0 configuration can byte-exactly emit the current octet-counted frame and preserve parser-required payload, confirmed with synthetic fixtures only.
5. Rotation, multiline, retry, restart, duplicate/loss, slow consumer, disk-full fault, shutdown and privacy behavior have testable closed contracts.
6. No raw path/host/credential/message enters diagnostics or public projection; public aliases, schema 2/3, guidance, restricted report and file monitor contracts remain unchanged.
7. No production connection or real-data use is proposed until a separate approval gate. Failure to satisfy any precondition means PRECONDITION_PENDING or NO_GO, not an alternate unreviewed integration.

## Phase 35.1 공급망 감사 후 상태

2026-10-26 정적 감사에서 Vector v0.60.0의 Linux GNU x86_64/aarch64 및 macOS arm64 archive 세 개는 게시 checksum과 수신 바이트 SHA-256이 일치했다. 그러나 release binary 서명·SBOM·artifact attestation/source-to-binary provenance는 확인되지 않았다. Socket sink의 native framing은 ASCII decimal RFC 6587 octet-counting과 일치하지 않으며 transform/custom framing의 정확한 byte 출력도 미검증이다. 따라서 Vector는 계속 첫 합성 후보일 뿐이며 **Phase 35.2 격리 실행은 `PRECONDITION_PENDING`**이다. 상세 evidence, manifest, stop 조건은 [Phase 35.1 공급망 감사](vector_supply_chain_audit_35_1.md)와 [artifact manifest](artifacts/vector_0_60_0_manifest.json)를 참조한다. Binary를 설치·실행하거나 container를 pull하지 않았다. 실제 사용자 로그·조직 운영은 계속 `NO_GO`; 자동 수집은 `NOT_IMPLEMENTED`다.
