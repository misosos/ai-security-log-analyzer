# Phase 35.4A — Vector isolated-pilot artifact preflight

검토일: 2026-10-27. 이 기록은 정적·합성 preflight이며 Vector 실행 승인이나 production 통합 승인이 아니다.

## Start Gate

- 시작 SHA `c71be0e54107db8bfd37a464f9c97250bb329db2`, branch `main`, clean tree, local `main` = `origin/main`; `origin/main...HEAD`는 `0 0`이었다.
- 정확한 push run [40455658366](https://github.com/misosos/ai-security-log-analyzer/actions/runs/40455658366)은 `completed/success`였다. 전체 회귀는 `2937 passed, 2 warnings`; TCP Syslog 기본·reliability·management, JSONL Linux acceptance, restricted report Linux smoke, benchmark, Chromium/axe와 tracked-file 불변 단계가 모두 성공했다.
- JSONL marker는 로그에서 한 번 확인했다: `COLLECTOR_JSONL_LINUX_ACCEPTANCE_PASS roles=2 runs=80 synthetic=1 leaks=0`. Chromium/axe는 `states=14 external_requests=0`였다. CI artifact 수는 0이다.
- `v0.4.0` tag 및 Release target은 기존 커밋 `eecd6ee1cda0545e34b01c42e1a2163a899bcc27`을 가리켰다.

## Artifact Identity and Download

고정 제품은 Vector `v0.60.0`, lightweight tag, source commit `0d0b35865036f8b5c2f0104d9744fa84985ffff1`이다. 공식 release API에서 published `2026-10-19T17:55:58Z`, non-draft/non-prerelease와 archive asset digest를 확인했다. Ubuntu 24.04 x86_64 GNU release archive와 `SHA256SUMS`만 공식 GitHub release URL에서 내려받았다. redirect 이후 두 파일의 최종 host는 `release-assets.githubusercontent.com`이었다. 다운로드 전에 `Content-Length`가 각각 58,655,370 bytes와 1,864 bytes임을 확인했다.

| Item | Bytes | SHA-256 | Result |
|---|---:|---|---|
| x86_64 GNU archive | 58,655,370 | `89a9f134dcc35a6fbba9cb8ad0fec2d4802657bba6cb1c374a30660ef9456bdc` | expected digest 및 공식 `SHA256SUMS` 일치 |
| official `SHA256SUMS` asset | 1,864 | `c9107d804285c4980b251639afd48de14ac9ff14734371a69aca6097a2341413` | 파일을 받아 계산한 바이트 digest; 서명 아님 |
| extracted `bin/vector` | 160,680,968 | `1e6a3f7b6b03aac5f95803007d66ed71897162c5160aa401af81e55d1477ba2e` | 정적으로 추출·해시, 실행 안 함 |

공식 checksum 일치는 다운로드 바이트가 그 checksum 목록과 일치한다는 사실만 확인한다. 이는 checksum-only 검증이다. detached binary signature, SBOM, attestation, reproducible build 또는 source-to-binary provenance를 입증하지 않는다. 기존 credential 형태 문자열 `UNRESOLVED` 3건은 그대로 남는다. 따라서 기존 `CHECKSUM_ONLY_ACCEPTED_FOR_ISOLATED_PILOT` 처분은 폐기 가능한 합성 격리 실험에만 한정된다.

## Archive and Binary Inspection

압축 해제 전 tar metadata 전체 53개 member를 검사했다: regular file 42개, directory 11개, 총 regular-file expanded size 160,893,403 bytes. absolute/traversal 경로, 중복 또는 case-fold 충돌, 링크, device/FIFO/socket, setuid/setgid, world-writable executable, nested archive는 발견되지 않았다. 가장 긴 member path는 91 bytes였다. archive는 예상 Vector directory 아래 systemd unit/default, 설정 예제·문서, `LICENSE`, `NOTICE`, `LICENSE-3rdparty.csv`, license 자료와 `bin/vector`로 구성됐다. 실행에 필요한 staging 후보는 binary와 고지 파일만 별도 복사 가능하다. 전체 archive 예제 파일을 실행 staging에 포함할 필요는 없다.

안전 검사 후 task 전용 mode 0700 임시 directory에 regular member만 직접 복사했다. binary는 mode 0700 staging 파일로 만든 뒤 정적 조사만 했다. 개발 host는 macOS 15.7.7 arm64였으며 Linux x86_64 target binary를 실행하지 않았다. `/usr/bin/file` 5.41은 ELF64 LSB PIE, x86-64, dynamically linked, interpreter `/lib64/ld-linux-x86-64.so.2`, GNU/Linux 3.2.0 ABI baseline, Build ID `e736f08fa5629b76e47c5f8288085d1472d211f4`, not stripped로 식별했다. Apple LLVM `objdump` 17.0.0은 `libz.so.1`, `libresolv.so.2`, `libgcc_s.so.1`, `libpthread.so.0`, `libm.so.6`, `libdl.so.2`, `libc.so.6`, `ld-linux-x86-64.so.2`를 기록했다. `readelf`는 host에서 없었고 `ldd`는 사용하지 않았다. 이 정적 library 목록은 Ubuntu runtime에서 해석·실행 확인한 결과가 아니다.

임시 archive와 staging은 제거했고 package manager, container, process, listener를 만들지 않았다. secure erase를 주장하지 않는다.

## Disk and Resource Budget

아래는 향후 pilot을 위해 동시에 존재할 수 있다고 보수적으로 잡은 disk cap이다. 관측된 artifact 크기와 계획 상한을 구분한다.

| Item | Bytes | Basis |
|---|---:|---|
| compressed archive | 58,655,370 | 실제 측정 |
| full extracted package | 160,893,403 | archive member size 합계 |
| read-only binary + license/notice staging copy | 160,806,207 | binary 및 고지 파일 실제 크기 합계 |
| private config + state | 4,194,304 | 계획 상한 |
| Vector memory-buffer allowance | 8,388,608 | 128 events × 최대 65,536-byte JSONL line; 계획 상한 |
| synthetic source | 1,048,576 | 계획 상한 |
| wire capture | 16,777,216 | 계획 상한 |
| inventory + validation output | 4,194,304 | 계획 상한 |
| test results | 4,194,304 | 계획 상한 |
| **subtotal** | **419,152,292** | 위 항목 합계 |
| 15% safety margin | 62,872,844 | subtotal의 올림 계산 |
| **planned peak** | **482,025,136** | subtotal + margin |
| retained free-space reserve | 536,870,912 | 최소 512 MiB 계획 reserve |
| **minimum free space at start** | **1,018,896,048** | peak + reserve; 실행 기준은 반올림해 최소 1.25 GiB |

현재 macOS 개발 host에서 확인한 available space는 68 GB 초과였지만, 이는 Ubuntu pilot 환경의 증거가 아니다. 각 writable directory와 실제 isolated volume quota가 이 cap을 지키는지 Phase 35.4B에서 재확인해야 한다. 하드웨어 resource limits나 independent disposable disk가 아직 제공되지 않았으므로 실행 승인은 아니다.

## Closed Vector Configuration Candidate

`tests/fixtures/vector_jsonl_35_4a/vector_candidate.yaml`은 JSON 문법으로 제한한 YAML-compatible 후보이며 실행 가능한 운영 설정이 아니다. 한 합성 파일 경로, application 한 역할, API 비활성화, file/host source metadata 억제, 전체 event object를 여섯 필드로 새로 구성하는 transform, newline-delimited JSON, 고정 loopback socket sink, memory buffer 128 events, healthcheck 비활성화를 표현한다. SSH 실행 후보는 role만 고정 변경한 별도 config로 생성해야 하며 두 역할을 함께 넣지 않는다. 실제 파일 위치와 port는 격리 harness 전용 placeholder이며 이 문서의 예시는 사용할 endpoint 안내가 아니다.

여섯 envelope key는 Phase 35.2 `JsonLinesDecoder` 계약에서 읽어 고정했다: `schema_version`, `source_role`, `payload`, `collector_instance_alias`, `sequence_hint`, `retry_hint`. core의 상한은 payload 8,192 UTF-8 bytes, record 65,536 bytes( LF 포함), connection buffer 65,536 bytes, feed당 최대 32 records, queue 256 events/1,048,576 payload bytes다. alias와 sequence hint는 제한 문자열이며 trust·dedup ID가 아니다. fixture는 ASCII/한국어 두 role, 최대 payload와 refusal boundary를 검증한다. Vector transform의 실제 event semantics, max event serialization size, config field acceptance는 **실행 전 정적 추정**이며 Vector validator로 확인되지 않았다.

config·state·input 경로는 서로 중첩하지 않는 private mount에 둔다. config/state directory 0700, config 0600, input regular file read-only, binary/config read-only, state/temp만 writable로 제한한다. recursive glob, HOME/system logs, file/host metadata, disk buffer, secret, arbitrary metadata, shell/command component, remote config는 금지다. component allowlist와 unknown-field 거부는 추후 validator 및 config scanner에서 입증해야 한다. JSON-compatible YAML 후보의 중복 object key는 테스트에서 거부하지만 Vector YAML parser의 duplicate-key 처리 자체는 미검증이다.

## `vector validate` Static Review

공식 고정 source commit의 `src/validate.rs`에서 `--no-environment`가 environment/component/healthcheck 검사를 건너뛰고, 해당 모드에서 secret resolution을 별도로 요청하지 않으면 builder가 secret backend를 호출하지 않는 경로를 확인했다. `--skip-healthchecks`는 healthcheck만 건너뛰므로 동일한 offline 경계가 아니다. 안전 후보 명령은 다음과 같으며, 이 단계에서는 실행하지 않았다.

```text
vector validate --config-yaml <private-config> --no-environment --deny-warnings
```

이는 고정 source 코드의 config load/build, transform 및 sink config 검증만 대상으로 삼도록 계획한다. 실제 binary의 CLI 동작은 확인하지 않았고, 현재 YAML fixture가 유효한지 검증하지도 않았다. `--no-environment`는 파일 접근 및 sink 연결 환경 검사를 생략하므로 검증 성공을 실제 준비성으로 해석할 수 없다. 후속 검증도 OS egress deny 아래에서 수행하고, 설정에서 shell/exec component와 모든 비-loopback sink를 차단한다.

## Isolation Procedure and Decision

Phase 35.4B는 disposable Ubuntu 24.04 x86_64 VM/snapshot에서만 검토한다: non-root 전용 UID/GID, 외부 egress를 OS/network namespace 또는 firewall에서 deny하고 독립 probe로 확인, loopback 이외 bind/listen 금지, host shared folders/clipboard/drag-and-drop 차단, binary/config/input read-only, 0700 state/temp만 writable로 둔다. PID, CPU/time, memory, open files, disk quota를 고정하고 실행 전후 process/socket/file inventory를 비교한다. 실제 HOME·credential·logs 접근, Vector API, telemetry, healthcheck egress, remote config, dynamic download, disk buffer는 금지한다. 종료 후 Vector/child/listener/socket/state/temp가 0인지 확인한다.

현재 작업은 macOS arm64 개발 환경이며 disposable Ubuntu VM과 OS 수준 egress deny를 독립 확인할 수 없다. application socket guard만으로 이를 대체하지 않았다. 따라서 **최종 판정 `ISOLATION_BLOCKED`**다. artifact/checksum/archive preflight는 통과했지만 Vector config validation, Ubuntu ELF/runtime dependency 검사, wire capture, rotation/retry/state/cleanup 실측은 실행하지 않았다. Vector binary를 실행하지 않았다. 실행 파일은 정적 검사만 했다.

## Wire Fixtures and Boundaries

합성 wire fixture는 JSON object 하나당 LF 하나, 정확히 여섯 key, UTF-8 byte 기준 payload 길이를 사용한다. core decoder로 ASCII와 한국어 fixture를 읽고 최대 8,192-byte payload를 허용하며 상한+1, invalid UTF-8, 금지 control을 고정 오류로 거부한다. quote/backslash 및 JSON escape는 serializer가 보존해야 한다. 내부 newline은 JSON escape 뒤 decode된 payload에서 control validation으로 거부된다. 실제 source invalid UTF-8, rotation/copytruncate, retry duplicate, restart, listener unavailable, memory full, metadata stripping failure와 capture-vs-expected byte equality는 Vector 실행이 필요하므로 NOT_TESTED다. 공개 API/SSE/UI/HTML/guidance/report로의 전달 경로는 구현하지 않았고 이 단계에서 변경하지 않았다.

## Local Verification

Artifact preflight 자체는 checksum 및 archive 정적 검사 범위에서 통과했다. 저장소 회귀 gate는 Phase 35.4A1에서 결정적 scheduler-clock test reproduction과 bounded-cycle test 보정 후 전체 pytest 3회 연속 성공(`2,953 passed, 2 warnings` each)으로 복구됐다. repository 회귀 판정은 `READY_TO_PUSH`다. 과거 전체 suite 실패의 상세 traceback은 보존되지 않아 정확한 최초 assertion line은 미확인이다. 상세 근거는 [Phase 35.4A1 기록](pair_truncation_stability_35_4a1.md)에 남긴다. 이 저장소 회귀 결과는 Vector 격리 조건을 바꾸지 않으며 Vector 실행은 계속 `ISOLATION_BLOCKED`다.

35.4A 당시 저장된 전체 pytest 결과는 `2,948 passed, 1 failed, 2 existing warnings`였으며 실패 node는 `test_each_role_file_identity_fault_stops_pair_without_quiet_success[truncate-application]`였다.
당시 별도 단독 실행에서는 `isolated diagnostic run of that test passed`였으나, 이후 전체 suite와의 차이는 재현·분류가 필요해 35.4A1에서 조사했다.

35.4A1의 test-only bounded-cycle 보정 후 pair regression은 100회 단독, 테스트 파일 30회, 인접 cases 30회, Phase 32 runtime/checkpoint/cleanup 조합 20회 동안 모두 통과했다. UTC와 Asia/Seoul focused run도 각 9개 통과했다. 전체 pytest는 연속 3회 모두 2,953 passed 및 기존 warning 2개로 성공했다. 기존 Phase 35.4A evaluation/accessibility/locked dependency 결과는 그 원 기록의 증거이며 이번 안정화 작업에서 재실행한 결과와 구분한다.

## Limitations

- Ubuntu에서의 archive extraction/runtime library availability, cgroup/resource limit, egress deny와 wire bytes는 NOT_TESTED.
- config candidate는 Vector `validate`로 검증되지 않았다. unknown component/field와 YAML parser duplicate behavior도 실행 시 확인해야 한다.
- checksum만 확인됐고 detached signature, SBOM, attestation, reproducible build, binary provenance는 없다. credential 형태 문자열 UNRESOLVED 3건 유지.
- 저장소 전체 회귀 baseline은 Phase 35.4A1에서 3회 연속 전체 suite 성공으로 복구됐다. 이는 Vector 실행 승인이 아니다.
- actual user logs, organization operation, remote collection, Vector production integration, TLS/mTLS, disk buffer, durable replay, exactly-once/lossless delivery remain NO_GO/unsupported.
- 실제 사용자 로그와 실제 사용자 자료 사용, 조직 운영은 계속 `NO_GO`다.
- synthesis and static metadata are not an operational safety, privacy compliance, or availability guarantee.

## Official Sources Checked

고정 source 관찰은 모두 source commit `0d0b35865036f8b5c2f0104d9744fa84985ffff1`의 파일 링크를 사용했다: [`src/sinks/socket.rs`](https://github.com/vectordotdev/vector/blob/0d0b35865036f8b5c2f0104d9744fa84985ffff1/src/sinks/socket.rs), [`lib/codecs/src/encoding/framing/newline_delimited.rs`](https://github.com/vectordotdev/vector/blob/0d0b35865036f8b5c2f0104d9744fa84985ffff1/lib/codecs/src/encoding/framing/newline_delimited.rs), [`src/sources/file.rs`](https://github.com/vectordotdev/vector/blob/0d0b35865036f8b5c2f0104d9744fa84985ffff1/src/sources/file.rs), [`src/validate.rs`](https://github.com/vectordotdev/vector/blob/0d0b35865036f8b5c2f0104d9744fa84985ffff1/src/validate.rs), [`src/cli.rs`](https://github.com/vectordotdev/vector/blob/0d0b35865036f8b5c2f0104d9744fa84985ffff1/src/cli.rs). 공식 reference 문서도 2026-10-27에 확인했다: [file source](https://vector.dev/docs/reference/configuration/sources/file/), [socket sink](https://vector.dev/docs/reference/configuration/sinks/socket/), [global options](https://vector.dev/docs/reference/configuration/global-options/), [CLI](https://vector.dev/docs/reference/cli/), [validation guide](https://vector.dev/docs/administration/validating/). Reference URL은 mutable 최신 문서일 수 있으므로 v0.60.0 구현 근거는 고정 source 링크와 대조하고, validator 실행 결과로 오해하지 않는다.
