# Phase 35.1 — Vector 0.60.0 정적 공급망·권한·데이터 경계 감사

조사 기준일: **2026-10-26**. 이 문서는 공식 upstream/release metadata, 공식 문서 및 고정 `v0.60.0` 소스의 정적 확인을 기록한다. **Vector 설치·실행하지 않았다. Container image도 pull하지 않았다.** 실제 로그·설정·checkpoint·운영 자료를 열지 않았다. 제한된 공식 release archive와 GitHub source archive는 task 전용 임시 디렉터리에서 바이트 hash 및 archive metadata만 검사한 뒤 제거했다. secure erase는 주장하지 않는다.

## Start Gate and Current Project State

Branch `main`, clean tree, exact local/origin starting SHA `2b145e23eba22dbd750f7dac79126b87452a2769`, and ahead/behind `0/0` were confirmed before the audit. Exact push run [40318080956](https://github.com/misosos/ai-security-log-analyzer/actions/runs/40318080956) completed successfully. Required Ubuntu locked install, full test, SSH checkpoint/unified monitoring, TCP smoke, 80-run Linux reliability, management smoke, restricted report/benchmark, Node·Chromium·axe, and tracked-file immutability steps succeeded. Safe completion markers reported roles=2, runs=80, leaks=0, management roles=2; axe reported 14 states and `external_requests=0`. CI artifacts: 0. The `v0.4.0` tag and Release target remain `eecd6ee1cda0545e34b01c42e1a2163a899bcc27`.

Phase 34 synthetic loopback management is `GO` within its tested scope; user guidance was 10/10 final PASS. Actual-user-data and organization use, unauthenticated remote collection, and AI parser auto-application remain `NO_GO`. Vector integration remains `NOT_IMPLEMENTED`.

## Upstream Identity

- 제품/repository: Vector, [`vectordotdev/vector`](https://github.com/vectordotdev/vector)
- release tag: [`v0.60.0`](https://github.com/vectordotdev/vector/releases/tag/v0.60.0), published 2026-10-19 17:55:58 UTC; created 17:52:04 UTC; published, not draft/prerelease.
- Tag는 lightweight이고 정확한 target source commit은 `0d0b35865036f8b5c2f0104d9744fa84985ffff1`이다. GitHub API의 commit signature verification은 valid로 확인했다. 이는 source commit의 서명 증거이지 release binary 서명이나 source-to-binary provenance 증거가 아니다.
- repository license metadata와 source `LICENSE`는 MPL-2.0이다. `NOTICE`, `LICENSE-3rdparty.csv`, `SECURITY.md`가 tag에 있다. Repository는 archived가 아니며 확인한 시점에 명시된 지원 종료/maintenance 종료 정책은 찾지 못했다. 이는 향후 지원을 보증하지 않는다.
- 정적 기준점과 artifact 결과는 [닫힌 manifest](artifacts/vector_0_60_0_manifest.json)에 기록했다. tag, source commit, release asset SHA-256은 서로 다른 identity다.

## Artifact Inventory

공식 Release API의 19개 asset을 조사했다. Release checksum 목록에는 18개 artifact가 있고, `vector-0.60.0-SHA256SUMS` 파일 자체는 자기 목록에 포함되지 않는다. 확인한 공식 checksum 18개는 GitHub Release API의 asset digest와 일치했다. manifest의 `OFFICIAL_CHECKSUM_METADATA_ONLY`는 해당 바이트를 다운로드해 직접 재검증하지 않았다는 뜻이다.

직접 수신해 실행·압축 해제 없이 스트리밍 검사한 세 archive:

| 파일 | 플랫폼/아키텍처 | 공식 표시 크기 | 수신 바이트 SHA-256 | 결과 |
|---|---|---:|---|---|
| `vector-0.60.0-x86_64-unknown-linux-gnu.tar.gz` | Linux GNU x86_64 | 58,655,370 | `89a9f134dcc35a6fbba9cb8ad0fec2d4802657bba6cb1c374a30660ef9456bdc` | 공식 SHA256SUMS와 일치 |
| `vector-0.60.0-aarch64-unknown-linux-gnu.tar.gz` | Linux GNU aarch64 | 56,805,541 | `1540662d8bc33af5afd287f821ba930417e0f3124073bc9db6a29c59dda88dbb` | 공식 SHA256SUMS와 일치 |
| `vector-0.60.0-arm64-apple-darwin.tar.gz` | macOS arm64 | 52,841,745 | `aa5c9d89416b39f1a90a7f1a088a9ecbb8c8c3a5669fb86609c9d4a958fe1a28` | 공식 SHA256SUMS와 일치 |

이 digest들은 manifest에 기재한 수신 바이트의 SHA-256이며, checksum 일치는 게시자의 서명 또는 빌드 출처를 증명하지 않는다. Linux musl x86_64/aarch64, Debian amd64/arm64, RPM x86_64/aarch64도 공식 metadata/checksum 목록에서 확인했으나 바이트를 받지 않았다. macOS x86_64 archive는 release asset에 없었다. GitHub 자동 생성 source archive는 공식 release checksum asset에 포함되지 않는다. 그 수신 hash는 자체 관찰값으로만 manifest에 표시했다.


### Container registry metadata (no pull)

공식 설치 문서는 `timberio/vector:0.60.0-debian` 및 `ghcr.io/vectordotdev/vector:0.60.0-debian` 태그를 안내한다. Docker Hub registry의 `timberio/vector`에서 OCI index, amd64/arm64 manifest와 config JSON metadata만 요청했다. GHCR metadata는 별도로 확인하지 않았다. Tag는 mutable reference이므로 향후 pinning은 registry digest로 해야 한다.

| Platform | OCI platform manifest digest | Config digest | Created | Compressed layer total | Config metadata |
|---|---|---|---|---:|---|
| Linux amd64 | `sha256:73f0cd0e2c52f5d1f7bad12b1f3f2e9dbb375b469eec8c77fb5ae35c58a8a6d2` | `sha256:f1099c8bbca2d0fb9b1172c29e7bd85d1153b26b70cbc39532080c3947268f59` | 2026-10-19 17:36:17 UTC | 99,310,690 bytes | Entrypoint `/usr/bin/vector`; User unset (root default); no Cmd, exposed port, volume or healthcheck; 8 layers |
| Linux arm64 | `sha256:454b277b44b40afde7441422dfd0c035c86ce122330c4cd60e8895f83af7bc25` | `sha256:dad0f53c7dbd8585a6cb815ac1700119bb362e3dc47087064b82ca5f1c51eaee` | 2026-10-19 17:38:32 UTC | 99,201,413 bytes | Entrypoint `/usr/bin/vector`; User unset (root default); no Cmd, exposed port, volume or healthcheck; 8 layers |

Observed index response body SHA-256 was `3ccb4bbd36e38734394e158db1411e91a69d076ed25013f8de385046a382d36a`; no registry digest header was available in this observation, so it is not labelled an authoritative index digest. Config labels identify documentation/source URLs but no verified build provenance. No image layers, signature, SBOM or attestation were fetched. The source Dockerfile pins a Debian trixie-slim base by digest. This image is not selected: metadata defaults to root, lacks declared data volume/healthcheck, has a roughly 99 MB compressed layer set, and adds container mount/privilege risk. Official examples and image metadata do not establish that Docker socket mounts or privileged execution are required; neither is accepted in the pilot.

추가 inventory: checksum asset, source archive, Docker Hub image manifest/config metadata를 포함했다. macOS x86_64는 `NOT_PUBLISHED`; installer script는 official 설치 문서에서 안내되지만 다운로드/검사/실행하지 않았다. 독립 debug symbols, detached signature, SBOM, artifact attestation/provenance asset을 release metadata에서 확인하지 못했다. 19개 release asset 밖의 package repository 상태나 모든 OCI registry metadata까지 포괄적으로 감사했다고 주장하지 않는다.

## Signature, Provenance and SBOM

다음 증거는 구별된다.

1. **Checksum:** `SHA256SUMS` 내용과 세 archive 바이트를 대조해 일치했다. 나머지 확인 목록은 API/checksum metadata뿐이다.
2. **Cryptographic signature:** release binary/archive에 대한 detached signature는 확인하지 못했다. Source commit 자체는 검증된 서명이 있다.
3. **GitHub attestation / Sigstore:** reviewed release assets/workflow metadata에서 artifact attestation 또는 cosign signature를 확인하지 못했다.
4. **Container digest:** Docker Hub의 OCI index/manifest/config metadata만 조회했다. AMD64와 ARM64 manifest descriptor digest를 얻었으며 layer는 pull하지 않았다. Index response bytes에서 계산한 hash는 registry가 제공한 digest header가 아니므로 관찰 hash로만 취급한다.
5. **SBOM:** 공식 release asset에서 SBOM을 확인하지 못했다. Cargo.lock은 Rust dependency resolution 정보이지 배포 binary의 완전한 SBOM이나 provenance가 아니다.
6. **Reproducible build/source-to-binary:** release workflow 파일을 정적으로 확인했으나 검토한 내용만으로 reproducible build나 source commit과 배포 binary의 암호학적 연결을 증명하지 못했다.

따라서 **checksum 일치만으로 artifact 서명·provenance를 승인하지 않는다.** Phase 35.2 전에 publisher가 서명/attestation을 제공하지 않는다면 조직의 독립 검증·승인 기준을 따로 정해야 한다.

## License

고정 tag의 `LICENSE`는 MPL-2.0이며 `NOTICE`와 `LICENSE-3rdparty.csv`도 제공된다. MPL은 적용 파일의 수정·재배포에 조건을 부과하는 file-level copyleft 구조다. 별도 설정 파일이나 단순 내부 사용에 대한 법률 결론은 여기서 내리지 않는다. 재배포 시 적용되는 라이선스와 attribution/notice 의무, 변경 파일 공개 의무의 범위는 법무 검토가 필요하다. CSV는 dependency/license inventory이지 각 전이 dependency의 라이선스 적합성을 전부 검증한 결과가 아니다. Release binary에 포함된 각 third-party notice의 완전성은 archive 설치 없이 확인하지 못했다.

Container base image의 license와 각 platform image 내 package license는 별도 확인이 필요하다. 공식 문서·상표 사용 조건은 code license와 동일하다고 가정하지 않는다. 현재까지 상업/내부 사용 제한을 발견하지 못했으나 이는 법률 자문이나 배포 허가가 아니다.

## Archive Static Inspection

세 binary archive는 추출하지 않고 tar metadata와 member stream을 검사했다. Linux archive는 각 53 entries, macOS archive는 47 entries였다. 검사한 범위에서 절대경로·`..` traversal·escaping symlink·hard link·setuid/setgid·world-writable regular executable은 없었다. binary archive에서 관찰된 symlink/hardlink member도 없었다. 이는 세 archive만의 정적 결과이며 package, container layer 또는 모든 release asset 결과가 아니다.

GitHub source archive는 5,382 members였다. 절대경로/parent traversal 0, hard link 0, setid 0, archive 바깥을 향하는 symlink 0이었다. 세 상대 symlink는 source test/documentation 경로를 가리켰고 escaping하지 않았다. source archive는 실행하거나 풀지 않았다.

정적 문자열 pattern 검사에서 binary bytes 안에 credential 형태와 PEM private-key marker 형태의 문자열 패턴이 발견되었다. Targeted x86_64 GNU archive scan은 AWS-key-shaped pattern 1건과 private-key PEM marker 1건을 찾았고 GitHub token pattern 및 certificate PEM marker는 찾지 못했다; 세 값 모두 출력하지 않았다. 다른 archive의 broad scan도 credential 관련 marker를 찾았지만 이는 credential 존재 확인이 아니다. 값은 어떤 문서나 출력에도 복사하지 않았다. 고정 source archive의 관련 위치는 documentation/example 및 GCP sink test fixture와 연관된 것으로 보였으나, binary가 정확히 이 source tree에서 재현됐다는 증거가 없으므로 유효하지 않은 dummy 값이라고 확정하지 않는다. 문자열 pattern은 실제 credential 여부나 실행 경로를 증명하지 않는다. 이는 Phase 35.2 전에 비밀값 아닌 synthetic fixture로 경로·빌드 포함 이유를 추가 검토할 stop condition이다.

문자열/metadata 검사만으로 동적 링크, embedded certificate의 유효성, shell 실행 경로, 자동 업데이트/telemetry의 실제 행위를 결론내리지 않았다. 문서화된 별도 updater 또는 crash-report endpoint를 확인하지 못했지만, 이것은 실행 경로 부재를 증명하지 않는다. Proxy/environment inheritance, DNS, remote config provider, cloud sink 및 plugin/runtime download 가능성은 제한된 static review만으로 완전히 닫지 못했다. archive 안의 executable은 절대 실행하지 않았다. 예상치 못한 payload·설치 script 여부는 세 archive의 member list 범위에서 기록했으며 RPM/DEB package script 검사는 수행하지 않았다.

## Dependency and Build Metadata

고정 source `Cargo.toml`은 Rust `1.95`를 요구하고, `Cargo.lock`이 존재한다. 이 tag의 lock에서 VRL은 crates.io `0.37.0`으로 확인했다. default feature set은 매우 넓고(268 feature entries), file, socket sink, remap 및 다양한 source/sink 기능을 포함한다. 따라서 단일 binary라도 기능 표면이 작다고 가정할 수 없다.

공식 build 설정에는 OpenSSL 계열 의존 경로와 Rust TLS 선택지가 있으나, 이번 감사는 모든 target별 실제 linkage를 입증하지 않았다. GNU archive의 정확한 libc 최소 버전, allocator, compression linkage, binary strip/LTO, source commit embedding, runtime plugin/dynamic loading 여부, build-time network dependency의 전체 closure는 미확인이다. 공식 설치 문서는 일반 binary에 libc가 필요하고 musl build가 별도 있음을 설명하지만 이것은 선택한 artifact의 재현된 ABI 검사 결과가 아니다.

`.github/workflows/release.yml`을 고정 tag에서 확인했으나 검토 범위가 전체 upstream workflow graph와 build worker 실행까지 포함하지 않는다. release build의 provenance·reproducibility 결론을 그 파일 하나로 추론하지 않는다. 전이 dependency의 전수 수동 감사를 완료했다고 주장하지 않는다.

## Default Network and Telemetry

공식 config 문서에서 API server 기본값은 disabled다. 활성화 시 기본 listener는 loopback이며 authentication이 없다는 문서 경고가 있으므로 첫 pilot에서 enable하지 않는다. Socket sink healthcheck는 기본 enabled이며 loopback 연결을 사전 생성할 수 있으므로 동작을 명시적으로 검토해야 한다. TCP socket sink는 TLS 설정 항목을 제공하지만 client identity, CA 검증과 실제 TLS 설정은 선택한 고정 config에서 별도로 확인해야 한다; 이번 local-only synthetic 계획에서는 TLS가 외부 인증을 대체한다고 보지 않는다. Global proxy option은 proxy 기능 설정이며 그 자체가 telemetry 전송 증거는 아니다. 일반 telemetry/automatic update/crash-report 전송은 검토한 고정 문서에서 기본 동작으로 확인하지 못했지만 **실행 검증하지 않았으므로 egress 0을 주장하지 않는다.** 다양한 외부 sink/component가 binary에 포함될 수 있다.

Phase 35.2는 host/VM firewall의 명시적 egress deny, 실행 전후 process/socket inventory, DNS 관찰, config API 비활성, healthcheck 의도 명시, proxy 환경 변수 검토를 요구한다. health/metrics endpoint는 노출하지 않고, 일반 로그의 level과 destination을 제한한다. 문자열 검색은 네트워크 동작의 완전한 증거가 아니다.

## Filesystem and Permissions

Vector root 실행은 필수라고 공식 문서가 요구하지 않는다. non-root dedicated user로 실행하되, source file 및 모든 parent directory read/traverse 권한을 최소한 부여한다. Manual archive의 기본 data directory 경로는 일반 사용자에게 writable하지 않을 수 있으므로 pilot은 task 전용 private state directory `0700`, config `0600`, 제한된 tmp 및 별도 quota를 명시하고 `data_dir`를 그 위치로 설정한다. 실제 source는 read-only synthetic fixture만 허용한다.

Analyzer checkpoint/report, 사용자 HOME, repository, Docker socket, host shared folder, `/proc`, `/sys`, device는 mount/access 목록에서 제외한다. Root filesystem read-only, `no-new-privileges`, capabilities drop, process/FD/memory/CPU/disk quota 후보를 사용한다. Vector의 임시 state/buffer와 analyzer input/output dir를 분리한다. Container image는 Docker Hub metadata에서 `User`가 비어 있어 default root 동작으로 해석되며, entrypoint `/usr/bin/vector`, declared port/volume/healthcheck 없음이었다. metadata만 확인했고 실행하지 않았다. container 후보는 privileged mode나 Docker socket을 요구한다고 확인한 것은 아니지만, root default와 host volume 경계 때문에 이번 pilot 선택에서 제외한다.

## File Source Contract

고정 release 문서의 File source 계약:

- glob `include`로 source를 선택하고 exclude를 제한할 수 있다. `read_from` 기본 동작은 신규 파일의 beginning이다. 기존 파일을 광범위하게 검색하는 설정은 사용하지 않는다.
- 기본 fingerprint는 첫 N줄 checksum 계열이며 대체 identity로 device+inode 방식이 문서화되어 있다. checkpoint는 Vector `data_dir`에 저장된다. 이를 analyzer file checkpoint와 공유하지 않는다.
- rename/create rotation을 지원하고 이전 열린 파일을 EOF까지 읽은 뒤 새 파일을 확인하는 방식이다. copytruncate는 보통 처리하지만 작은 유실 가능성을 문서가 경고한다. compressed rotation에는 추가 조건이 있다.
- multiline, encoding, `max_line_bytes`(기본 102,400), `max_read_bytes`, discovery cooldown, `ignore_older`, oldest-first/read fairness 옵션이 있다. 기본 `oldest_first`는 false다. File removal/cooldown 및 source metrics 동작은 최종 설정에서 확인할 항목으로 남긴다. 이 수치는 Vector 설정 기본값이지 우리 분석기의 안전 상한이 아니다.
- file source는 host/file metadata를 기본 추가할 수 있다. 변환에서 path/host를 제거하고 analyzer DTO에 전달하지 않도록 해야 한다. source errors/internal logs가 path를 포함할 수 있는 가능성은 Phase 35.2 canary 검증 대상이다.
- source-level acknowledgements 옵션은 deprecated 경로가 있어 global/sink ack와 구분해야 한다. Rotation, permission denial, symlink traversal의 모든 edge behavior를 이 정적 검토로 보장하지 않는다. Symlink 파일 선택 의미는 `NOT_VERIFIED`다.

정적 근거: [File source official reference](https://vector.dev/docs/reference/configuration/sources/file/) 및 fixed tag의 [`src/sources/file.rs`](https://github.com/vectordotdev/vector/blob/v0.60.0/src/sources/file.rs), [`lib/file-source`](https://github.com/vectordotdev/vector/tree/v0.60.0/lib/file-source). 문서 외 detail은 실행 결과로 표현하지 않는다.

## Socket Sink and Framing

현재 analyzer pilot은 다음 exact wire bytes를 요구한다: `<ASCII decimal UTF-8 payload byte length><one SP><payload bytes>`. 고정 Vector socket sink 문서는 TCP address, encoding codec, framing을 제공한다. `bytes` framing은 delimiter를 추가하지 않는 방식이고, `length_delimited`는 기본 little-endian 32-bit 길이 framing이다. 문서화된 native encoder 중 RFC 6587의 ASCII decimal octet-counting encoder를 찾지 못했다. 고정 source tree에는 octet-counting decoder가 있으나 대응 encoding module은 확인되지 않았다.

**Phase 35.1 시점의 잠정 판정은 `TRANSFORM_REQUIRED` / `CUSTOM_FRAMING_REQUIRED`였다. Phase 35.1A fixed-source 후속 추적으로 native framing은 `INCOMPATIBLE`, VRL source-level 경로는 가능성이 있으나 `CUSTOM_FRAMING_UNPROVEN`으로 확정했다.** VRL byte length·text serializer·bytes framer를 소스상 연결했지만 실제 Vector config validation과 wire capture는 하지 않았다. 그러므로 기존 RFC 6587 listener를 변경하지 않고, Phase 35.2는 Vector synthetic fixture보다 앞서 별도 closed JSON Lines adapter pure core를 요구한다. 구체 근거는 [35.1A framing 기록](vector_framing_preconditions_35_1a.md) 참조.

Socket sink는 reconnect/retry/buffer, timeout/batch/connection 옵션 및 acknowledgements를 제공하지만 socket write/connection acknowledgement는 analyzer가 parse·분석을 완료했다는 ack가 아니다. Source time/metadata 자동 삽입 여부와 serialization 변형은 최종 config로 별도 확인한다. Source docs: [Socket sink](https://vector.dev/docs/reference/configuration/sinks/socket/), fixed [`src/sinks/socket.rs`](https://github.com/vectordotdev/vector/blob/v0.60.0/src/sinks/socket.rs), [`bytes` framing implementation](https://github.com/vectordotdev/vector/blob/v0.60.0/lib/codecs/src/encoding/framing/bytes.rs).

## Buffer and Delivery Semantics

Vector 문서는 memory와 disk buffer, `max_size`, `when_full` 정책을 제공한다. `block`은 buffer가 찼을 때 입력을 막을 수 있고 `drop_newest` 등 drop 정책도 가능하므로 pilot 설정은 explicit bounded memory buffer와 block/fail semantics로 좁혀야 한다. Disk buffer의 최소 크기 및 sync interval 특성은 문서화되어 있지만 각 append가 매번 durable fsync 된다는 뜻이 아니다. Disk buffer에는 raw 또는 복원 가능한 event data가 남을 수 있고 자동 암호화·retention·secure deletion을 가정하지 않는다. 첫 합성 pilot은 disk buffer를 비활성화한다.

End-to-end acknowledgements는 source가 ack할 수 있어야 한다. File source가 checkpoint progress를 다루더라도 socket sink의 successful write는 analyzer analysis ack가 아니다. 장애 경계에 따라 loss/replay/duplicate가 가능하고 ordering은 source/sink/batch/retry concurrency 범위에 한정된다. Exactly-once·무유실을 claim하지 않는다. Queue full, retry storm, shutdown drain, process crash, disk full/corruption은 Phase 35.2 합성 fault 시험 전 미검증이다. 근거: [buffering model](https://vector.dev/docs/architecture/buffering-model/) 및 [end-to-end acknowledgements](https://vector.dev/docs/architecture/end-to-end-acknowledgements/).

## Privacy Data Flow

| 위치 | 원문/식별자 존재 가능성 | Phase 35.2 경계 |
|---|---|---|
| Source file | 원문·계정/IP/host/path 존재 | 합성 전용, read-only, 명시 파일만 |
| Vector memory/internal event/VRL | payload와 source metadata 존재 | bounded process; path/host drop; raw는 parser handoff 외 노출 금지 |
| Memory buffer | 원문 event가 일시 체류 | bounded, disk buffer off, process exit cleanup 확인 |
| Disk buffer | raw/near-raw durable 잔존 가능 | pilot 비활성; 나중에 필요 시 retention/encryption review 별도 |
| Vector internal log | 오류/path/metadata가 포함될 가능성 | 제한된 level, safe wrapper projection 및 canary 검사 |
| Metrics | labels/cardinality가 식별자 노출 가능 | fixed aggregate labels만; local endpoint 미노출 |
| Loopback TCP payload | framing된 원문 전달 | local process injection 가능; TLS/auth 없음; 합성만 |
| Analyzer trusted parser | bounded raw payload 임시 존재 | 기존 parser만, error/status/log로 원문 echo 금지 |
| Analyzer status/error | fixed categories/counts만 | 주소/path/payload/canary 금지 |
| Public API/SSE/UI/HTML | 원문/원 식별자 금지 | 기존 subject_alias/projection 유지 |
| Restricted report | 실제 값 허용 설계이나 이번 실행 금지 | collector input/report 연결 없음; 기존 별도 approval 경계 유지 |
| Lexical guidance | 승인된 case projection만 | collector raw payload를 guidance에 넘기지 않음 |

원문은 collector memory와 parser handoff에서 순간적으로 존재할 수 있다. Swap, core dump, crash handler, same-UID process, host compromise, backup/cloud sync는 정적 설계로 제거할 수 없다. reject/error/metric에 raw line을 남기지 않는다.

## AI Boundary

Phase 35.1 감사와 향후 35.2 합성 실행에서 AI/LLM을 사용하지 않는다. AI가 collector config, role, trust, firewall, certificate, parser를 자동 선택·수정·활성화하거나 raw event를 외부로 보내지 않는다. 허용 가능한 향후 parser proposal은 익명화된 합성 safe DTO와 공식 vendor 문서에 근거한 사람이 검토할 정적 diff로 제한한다. 구조화 출력 검증, AST/regex 안전성, ReDoS/property/fuzz/parity, network 차단 및 수동 승인이 별도 gate다. 자동 parser 적용과 AI의 detection/risk/case 변경은 `NO_GO`다.

## Phase 35.2 Entry Decision

**판정: `PRECONDITION_PENDING`.** Vector 0.60.0은 별도 프로세스 합성 후보로 유지하지만, Phase 35.2 격리 실행 진입은 승인하지 않는다.

차단 전제:

1. Checksum 검증은 있으나 release binary detached signature, SBOM, artifact attestation 및 source-to-binary provenance가 확인되지 않았다.
2. Socket sink의 native framing은 analyzer의 ASCII decimal octet-counting과 다르다. 정확한 bytes를 구성하는 transform 경로는 아직 검증되지 않았다.
3. binary에 credential 형태/PEM marker 문자열이 관찰됐다. 관련 source 위치는 example/test fixture인 것으로 보이나 유효성 및 binary-source 매핑이 확정되지 않았다.
4. file source checkpoint/rotation 및 ack는 고정 문서와 소스에 나타나지만, 합성 환경에서 analyzer ack까지의 delivery·duplicate·cleanup 의미는 미검증이다.
5. 모든 candidate platform/package의 archive 또는 installer script, target linkage/libc, image GHCR digest/signature는 전수 확인되지 않았다.

35.2 gate를 다시 열려면 정확한 artifact/platform/hash와 조직의 signature/provenance 기준을 고정하고, legal/NOTICE 검토, non-root/effectively read-only sandbox, egress deny, API off, disk buffer off, synthetic-only read-only source, bounded memory, safe logging, canary scan, output byte fixture, queue/full/timeout/restart cleanup criteria를 승인해야 한다. 성공하더라도 합성 단기 검증만 가능하며 actual logs/production integration/organization rollout은 별도 NO_GO 상태다.

## Cleanup

받은 source/binary archive 및 checksum 파일은 task 전용 임시 디렉터리에서 검사 후 제거했다. Archive를 실행하거나 추출하지 않았으며 package manager/system directory를 건드리지 않았다. Container/image/layer/volume/network를 생성하지 않았고 Vector process/listener/설치 파일은 없다. 임시 파일 제거는 secure erase를 의미하지 않는다. Repo의 production 코드, workflow, dependency 및 `uv.lock`은 변경 대상이 아니다.

## Limitations

정적 문서/source/metadata는 실제 파일 rotation, sink serialization, retry/ack, resource use, egress, permission, privacy leakage를 실행 검증하지 않는다. Release checksum은 authenticity가 아니며 source commit signature는 binary signature가 아니다. API/docs와 GitHub artifact metadata가 향후 바뀔 수 있다. 공식 문서가 명시하지 않은 부분을 보장으로 채우지 않았다. MPL 적용 범위 및 재배포 의무는 법무 검토가 필요하다.

Phase 35.1A에서 native socket framing이 analyzer의 ASCII decimal framing과 `INCOMPATIBLE`임을 고정 source로 확인했다. VRL transform 후보는 `CUSTOM_FRAMING_UNPROVEN`이다. 기존 RFC 6587 listener는 변경하지 않으며, 후속 단계에서 별도 JSON Lines adapter pure core를 구현했다. Core는 parser pipeline이나 Vector에 연결되지 않았으며 Linux 및 실제 Vector 연동은 `NOT_TESTED`다. Provenance 잔여 위험 판정과 category-only credential-shaped string 분류는 [Phase 35.1A 기록](vector_framing_preconditions_35_1a.md)에 있다. 상세 core 계약과 macOS benchmark는 [Phase 35.2 기록](collector_jsonl_adapter_core_35_2.md)에 있다.

**Vector production 통합은 `NOT_IMPLEMENTED`; 실제 사용자 자료·조직 운영은 `NO_GO`.** Phase 35.0의 후보 선택은 설계상 조건부 결정이며 Phase 35.2 Vector 실행 승인으로 승격되지 않는다.

## 조사 근거

조사일 2026-10-26. 핵심 1차 자료:

- [v0.60.0 release/tag](https://github.com/vectordotdev/vector/releases/tag/v0.60.0), [fixed tag Cargo.toml](https://github.com/vectordotdev/vector/blob/v0.60.0/Cargo.toml), [Cargo.lock](https://github.com/vectordotdev/vector/blob/v0.60.0/Cargo.lock)
- [LICENSE](https://github.com/vectordotdev/vector/blob/v0.60.0/LICENSE), [NOTICE](https://github.com/vectordotdev/vector/blob/v0.60.0/NOTICE), [third-party license inventory](https://github.com/vectordotdev/vector/blob/v0.60.0/LICENSE-3rdparty.csv), [SECURITY.md](https://github.com/vectordotdev/vector/blob/v0.60.0/SECURITY.md)
- [File source docs](https://vector.dev/docs/reference/configuration/sources/file/), [socket sink docs](https://vector.dev/docs/reference/configuration/sinks/socket/), [buffering](https://vector.dev/docs/architecture/buffering-model/), [end-to-end acknowledgements](https://vector.dev/docs/architecture/end-to-end-acknowledgements/)
- [API configuration](https://vector.dev/docs/reference/configuration/api/), [global options](https://vector.dev/docs/reference/configuration/global-options/), [Docker installation](https://vector.dev/docs/setup/installation/platforms/docker/), [installation methods](https://vector.dev/docs/setup/installation/)
- [fixed file source](https://github.com/vectordotdev/vector/blob/v0.60.0/src/sources/file.rs), [file-source implementation](https://github.com/vectordotdev/vector/tree/v0.60.0/lib/file-source), [socket sink source](https://github.com/vectordotdev/vector/blob/v0.60.0/src/sinks/socket.rs), [bytes encoder](https://github.com/vectordotdev/vector/blob/v0.60.0/lib/codecs/src/encoding/framing/bytes.rs), [release workflow](https://github.com/vectordotdev/vector/blob/v0.60.0/.github/workflows/release.yml)
- [Docker Hub official image metadata](https://hub.docker.com/r/timberio/vector/tags?name=0.60.0-debian); metadata only, no image layer pull.
