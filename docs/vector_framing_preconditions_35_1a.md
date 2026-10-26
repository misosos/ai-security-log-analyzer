# Phase 35.1A — Vector framing 선행조건 판정

조사 기준일: **2026-10-26**. 범위는 Phase 35.1의 남은 framing·문자열 분류·provenance 질문을 Vector `v0.60.0` 고정 source commit에서 정적으로 닫는 것이다. **Vector를 설치·실행하지 않았다.** Container를 pull하지 않았고 production 코드, workflow, dependency, 실제 로그도 사용하지 않았다. 이번 기록은 실행 호환성 시험을 대신하지 않는다.

## Decision

- Vector `v0.60.0` socket sink의 native framing은 기존 analyzer가 요구하는 `ASCII decimal payload byte length + single ASCII space + payload bytes`와 **`INCOMPATIBLE`**이다.
- 고정 VRL source와 Vector serializer를 이어 보면 custom transform은 UTF-8 byte 길이 prefix를 구성할 수 있는 것으로 **정적으로 추론**된다. 그러나 Vector 설정 전체의 검증·실행 결과나 실제 wire capture가 없으므로 그 조합의 wire compatibility는 **`CUSTOM_FRAMING_UNPROVEN`**이다.
- 기존 RFC 6587 listener는 변경하지 않는다. 당시 다음 단계였던 **`PHASE_35_2_ADAPTER_CORE_REQUIRED`**는 [Phase 35.2 pure core](collector_jsonl_adapter_core_35_2.md)에서 수행됐다. JSON Lines decoder/schema/queue core만 존재하며 Vector, socket, 외부 process, parser pipeline 연결은 없다.
- Artifact의 checksum은 확인됐지만 binary signature, SBOM, attestation 및 source-to-binary provenance는 확인되지 않았다. 기술적 잔여 위험은 제한된 disposable synthetic pilot에서만 **`CHECKSUM_ONLY_ACCEPTED_FOR_ISOLATED_PILOT`**로 수용 가능하다고 판단한다. 이는 Vector 실행 승인이 아니다. Phase 35.2 core는 Vector binary 없이 진행할 수 있다. 이후 binary 실행은 격리 통제의 별도 gate를 통과해야 한다.
- Vector production 통합은 `NOT_IMPLEMENTED`; 실제 사용자 자료·조직 운영은 `NO_GO`다.

## Start Gate

- branch `main`, clean tree, local `main`/`origin/main`/`HEAD` = `b9dcdd4d2aedbde9ed16897a09c2ee4dcb5387b6`; divergence 0/0.
- exact push run [40322008886](https://github.com/misosos/ai-security-log-analyzer/actions/runs/40322008886)은 해당 SHA에서 completed/success였다. Ubuntu locked setup, 전체 pytest, SSH ownership/unified monitoring, TCP 기본 smoke, Linux 80-run reliability, management smoke, restricted report/benchmark, Node·Chromium·axe 및 tracked-file 불변 단계가 성공했다. 안전 표식은 smoke roles=2, reliability runs=80/leaks=0, management roles=2, axe states=14/external_requests=0이었다.
- CI artifact 0개. `v0.4.0` tag와 Release target은 `eecd6ee1cda0545e34b01c42e1a2163a899bcc27` 유지.
- 먼저 읽어 대조한 Phase 35.1 manifest 및 audit는 `v0.60.0`, lightweight tag, source commit `0d0b35865036f8b5c2f0104d9744fa84985ffff1`, MPL-2.0, 아래 세 archive digest 및 공식 checksum 일치, signature/SBOM/attestation 미확인으로 일치했다. 신규 artifact는 받지 않았다.
- Phase 35.1A 계약 테스트는 본 문서 작성 전 실행해 예상대로 **3 failed**였다. 누락 문서, index link, contract 내용이 각각 없음을 검출했다.

## Native Framing Trace

근거는 Vector tag `v0.60.0`의 고정 commit `0d0b35865036f8b5c2f0104d9744fa84985ffff1` source다. 아래 링크는 mutable main이 아니라 해당 commit의 파일이다.

1. [`src/sinks/socket.rs`](https://github.com/vectordotdev/vector/blob/0d0b35865036f8b5c2f0104d9744fa84985ffff1/src/sinks/socket.rs)는 TCP mode에서 `encoding.build(SinkType::StreamBased)`로 framer·serializer를 만들고 `TcpSinkConfig`로 전달한다. 입력 event는 sink transform 이후 encoder로 간다.
2. [`lib/codecs/src/encoding/encoder.rs`](https://github.com/vectordotdev/vector/blob/0d0b35865036f8b5c2f0104d9744fa84985ffff1/lib/codecs/src/encoding/encoder.rs)는 event serializer를 먼저 적용하고 그 결과 bytes를 framer에 전달한다. 따라서 길이 framing은 원본 event 자체가 아니라 **직렬화 결과**를 센다.
3. [`lib/codecs/src/encoding/config.rs`](https://github.com/vectordotdev/vector/blob/0d0b35865036f8b5c2f0104d9744fa84985ffff1/lib/codecs/src/encoding/config.rs)는 명시된 framing을 사용한다. stream serializer에서 생략하면 text/raw/JSON 계열은 newline framing으로 기본 설정된다.
4. [`lib/codecs/src/encoding/framing/framer.rs`](https://github.com/vectordotdev/vector/blob/0d0b35865036f8b5c2f0104d9744fa84985ffff1/lib/codecs/src/encoding/framing/framer.rs)의 enum은 `Bytes`, `CharacterDelimited`, `LengthDelimited`, `NewlineDelimited`, `VarintLengthDelimited`다.

| v0.60.0 방식 | 실제 출력 경계 | RFC 6587 ASCII decimal과의 판정 |
|---|---|---|
| `bytes` | serializer bytes 그대로, framing delimiter/prefix 없음 | `INCOMPATIBLE` 단독 사용 시 |
| `newline_delimited` | serializer bytes 뒤 LF 1 byte | `INCOMPATIBLE` |
| `character_delimited` | serializer bytes 뒤 설정한 단일 ASCII delimiter | `INCOMPATIBLE`; 길이 prefix가 아님 |
| `length_delimited` | 4-byte binary 길이 prefix + serialized bytes. 실제 [`LengthDelimitedCoderOptions`](https://github.com/vectordotdev/vector/blob/0d0b35865036f8b5c2f0104d9744fa84985ffff1/lib/codecs/src/common/length_delimited.rs)는 기본 `length_field_is_big_endian=true`; 테스트도 길이 3에 `00 00 00 03`을 보인다. framer enum의 “32-bit LE” 설명 주석과 구현 기본값이 어긋나므로 여기서는 실행 코드와 테스트를 기준으로 기록한다. 설정으로 endian을 바꿀 수 있다. | `INCOMPATIBLE`: decimal ASCII와 공백이 아님 |
| `varint_length_delimited` | base-128 continuation varint prefix + bytes ([source](https://github.com/vectordotdev/vector/blob/0d0b35865036f8b5c2f0104d9744fa84985ffff1/lib/codecs/src/encoding/framing/varint_length_delimited.rs)) | `INCOMPATIBLE` |

[`TextSerializer`](https://github.com/vectordotdev/vector/blob/0d0b35865036f8b5c2f0104d9744fa84985ffff1/lib/codecs/src/encoding/format/text.rs)는 event의 message를 bytes로 coercion해 출력하고 JSON quote/escape를 추가하지 않는다. 단, JSON serializer는 JSON serialization을 수행한다. 따라서 “framing이 bytes”라는 설정만으로 원래 payload가 그대로 나온다고 볼 수 없고 codec도 맞아야 한다. TCP sink는 encoded byte stream을 재사용 연결로 보낸다. 여러 event가 한 write에 합쳐질 수 있으나 event별 encode 결과의 byte 순서를 framing이 바꾸지는 않는다. TCP write 경계는 receiver의 read 경계가 아니며 partial write/connection close는 마지막 불완전 frame을 만들 수 있다.

[`src/sinks/util/tcp.rs`](https://github.com/vectordotdev/vector/blob/0d0b35865036f8b5c2f0104d9744fa84985ffff1/src/sinks/util/tcp.rs)는 연결 실패 재시도의 backoff를 두지만, send error 경로에 대한 주석은 failed event 재시도를 보장하지 않는다. [`socket_bytes_sink.rs`](https://github.com/vectordotdev/vector/blob/0d0b35865036f8b5c2f0104d9744fa84985ffff1/src/sinks/util/socket_bytes_sink.rs)의 `BytesCodec`는 자체 application framing을 추가하지 않고, pending item 상한 및 flush/ack 처리를 한다. 이 ack는 로컬 sink flush 수준이며 analyzer parser/analysis ack가 아니다. 따라서 native sink가 RFC 6587과 호환되거나 무유실이라고 결론내리지 않는다.

## VRL Feasibility

Vector의 `Cargo.lock`은 VRL 0.37.0을 고정한다. 그 dependency source의 검토된 commit은 [`length`](https://github.com/vectordotdev/vrl/blob/7e2976448acef9055f0db76eae9907c4d847e314/src/stdlib/length.rs), [`to_string`](https://github.com/vectordotdev/vrl/blob/7e2976448acef9055f0db76eae9907c4d847e314/src/stdlib/to_string.rs), string concatenation test를 포함한다. VRL `length`는 string/bytes의 UTF-8 byte 길이를 사용하고 integer `to_string`은 decimal 문자열이다. 이는 Vector 최신 main이 아닌 lockfile로 도달한 특정 dependency source의 정적 확인이다.

개념상 transform 후보는 payload 문자열을 먼저 고정하고, `to_string(length(payload)) + " " + payload`로 message를 교체한 뒤 `text` codec + `bytes` framing으로 보내는 것이다. 고정 TextSerializer는 message bytes를 직접 출력하고 Bytes framer는 추가 delimiter를 붙이지 않는다. 이 조합은 source-level 경로상 byte contract를 구성할 수 있어 보이지만 **실제 Vector config validation이나 runtime wire capture를 수행하지 않았다**. 그러므로 전체 경로는 `CUSTOM_FRAMING_UNPROVEN`이다. 빈 문자열, 잘못된 입력 형식, transform error/drop, config 오류의 sink 동작도 실제 실행 없이 닫히지 않았다.

| 합성 payload | UTF-8 byte 수 | octet-counting 후보 | 비고 |
|---|---:|---|---|
| `hello` | 5 | `5 hello` | 총 7 wire bytes |
| `안녕` | 6 | `6 안녕` | 문자 수 2가 아니라 byte 수 6 |
| `2001:db8::1` | 11 | `11 2001:db8::1` | 문서용 IPv6 주소 |
| `🙂` | 4 | `4 🙂` | Unicode scalar count와 다름 |
| `a\nb` | 3 | `3 a\nb` | wire 길이에는 LF 포함되나 기존 payload validator는 control character를 거부 |
| empty string | 0 | `0 ` | 기존 decoder는 zero length를 거부; 생성 전에 reject 필요 |
| 8192 ASCII bytes | 8192 | `8192 ` + 8192 bytes | 제안 상한 예시, Vector 보증값 아님; 총 8197 bytes |
| NUL | 1 | `1 ` + NUL | 길이 계산 가능해도 기존 payload 계약상 거부 |
| invalid UTF-8 byte sequence | 해당 없음 | 해당 없음 | JSON/strict UTF-8 경계에서 reject해야 함; VRL의 문자열 표현으로 원 byte 보존을 가정하지 않음 |

위 표는 고정된 fixture의 수학적 byte 계산이며 Vector 출력 실측이 아니다. Custom transform의 잔여 위험: serializer 재설정 누락에 따른 이중 quote/escape, newline delimiter 추가, 문자수와 byte수 혼동, metadata가 payload에 섞임, transform 실패 시 drop/오류 로그, 복잡한 config 오입력, 임의 transform 표면 확대, 향후 버전 변경이다. 따라서 기존 listener에 이를 적용하는 것은 선택하지 않는다.

## Adapter Comparison

기존 RFC 6587 listener는 변경하지 않는다. 각 adapter 후보는 별도 config namespace, 고정 role, 독립 bounded state를 가져야 하고 공개 API/SSE/UI로 원문이나 collector metadata를 내보내지 않는다.

| 후보 | 장점 | 주요 경계/비용 | 판정 |
|---|---|---|---|
| RFC 6587 listener + custom VRL | 현재 parser 경로 재사용, 네트워크 framing은 이미 구현 | custom wire 생성 미실행 검증, sink codec·metadata·transform failure 상호작용; listener의 기존 계약에 collector 전용 예외 추가 압력 | 보류 (`CUSTOM_FRAMING_UNPROVEN`) |
| 별도 loopback JSON Lines adapter | 닫힌 envelope에서 payload와 고정 role 분리, duplicate key/type/size를 거부 가능, pure decoder 테스트 가능 | JSON serializer 계약과 stream boundary를 새 core에서 검증해야 함; local process는 여전히 payload 주입 가능 | **다음 단계 선택: core만** |
| loopback newline-delimited raw | 구현 단순 | metadata·role·alias 분리 불가, payload newline/multiline 혼동, source identity를 payload에 과신할 위험 | 미선택 |
| Unix domain socket + JSON Lines | filesystem permission으로 접근 축소 가능, envelope 이점 유지 | Unix 전용 path lifecycle, symlink/owner/stale socket 관리, same UID 프로세스 위협 지속, macOS/Linux 차이 | 후속 대안 |
| private spool file + file monitor | file source/retry 경로 재사용 가능 | disk에 원문 지속, rotation/checkpoint/replay/cleanup/backup/cloud sync 의미 확대, 기존 file monitor 계약과 상호작용 | 이번 pilot 부적합 |

JSONL은 가장 낮은 해석 모호성을 제공하는 설계 후보이며 아직 구현이 아니다. 예상 line은 compact JSON object 한 개 뒤 LF 한 개다. JSON string 안 newline은 JSON escape로 표현되어 stream delimiter와 구별된다. decode 후 payload 내부 제어문자는 기존 parser boundary에서 허용 여부를 별도로 검사한다.

### Closed JSON Lines Adapter Candidate

필수 key는 정확히 `schema_version`, `source_role`, `payload`, `collector_instance_alias`, `sequence_hint`, `retry_hint` 여섯 개다. Extra/missing key, duplicate key, JSON `NaN`/`Infinity`, bool-as-integer version, strict UTF-8 실패를 거부한다. `source_role`은 adapter config와 정확히 일치해야 하며 `application` 또는 `ssh`만 허용한다. Alias는 실제 hostname이 아닌 제한된 opaque alias다. Sequence는 bounded opaque hint/null이고 exactly-once ID가 아니다. Retry flag는 sender가 주장하는 hint이지 신뢰 보증이 아니다. 임의 metadata map은 금지한다.

Phase 35.2 core에서 시험할 제안 상한: line byte limit 65,536 bytes, payload 8,192 UTF-8 bytes, connection buffer 65,536 bytes, 최대 2 connections, queue 256 events와 1 MiB queue byte limit. 이는 프로젝트 검증용 초기 설계값이며 upstream이 보장하거나 운영 적합성을 뜻하지 않는다. 정확한 상한은 통합 전 계약 테스트로 고정한다. Record에는 LF가 정확히 하나 있어야 하며 EOF에서 미완성 record는 거부한다. Payload·alias·sequence는 trusted parser boundary와 내부 queue에서만 존재하고 public API, DTO/status/log/report/guidance로 보내지 않는다. JSONL record framing은 TCP write boundary와 무관하다.

## Credential String Classification

Phase 35.1의 공식 Linux x86_64 GNU archive를 이번 조사에서 다시 임시 수신하고, manifest SHA-256 일치를 확인한 후 executable을 실행하지 않고 tar member 안전 검증 및 bytes scan만 했다. 53 archive members, 대상 executable 160,680,968 bytes였다. 임시 archive는 TemporaryDirectory 종료 시 제거했다; secure erase는 주장하지 않는다. 안전한 식별은 출력하지 않은 값 대신 archive offset과 pattern class로 했다.

| Category | Count | Evidence and interpretation |
|---|---:|---|
| `DOCUMENTATION_EXAMPLE` | 1 | Binary offset 10,953,513의 AWS access-key-shaped pattern은 고정 source `src/aws/auth.rs`의 configurable docs example metadata와 대응한다. 해당 실제 값이 유효하지 않거나 런타임에서 사용 불가하다고 증명된 것은 아니다. |
| `PRIVATE_KEY_FIXTURE` | 1 | Binary offset 12,232,312의 PEM private-key marker는 고정 source `src/sinks/gcp_chronicle/chronicle_unstructured.rs` 내 `#[cfg(test)]` 구역의 `invalid_credentials_rejected_by_oauth_server` 테스트 fixture와 위치상 대응한다. release binary가 이 정확한 source tree에서 만들어졌다는 관계는 증명되지 않았다. |
| `UNRESOLVED` | 3 | Phase 35.1 broad scan에서 다른 두 archive에 관찰된 credential/private-key 형태 hit 3건은 이번 offset-level source matching 범위에 포함되지 않았다. category·실제 값·실행 의미를 더 좁히지 않는다. |
| 기타 category | 0 confirmed | `FEATURE_NAME`, `CERTIFICATE_FIXTURE`, `BUILD_METADATA`, `THIRD_PARTY_COMPONENT`, `EMBEDDED_RUNTIME_DATA`로 분류 확정한 추가 occurrence 없음. |

Binary scan의 AWS/GitHub token/private-key/certificate 패턴 hit count는 실제 credential 존재 여부나 사용 경로를 증명하지 않는다. 값 원문·fingerprint는 문서, assertion, 출력에 넣지 않는다. Source 대응은 문자열의 binary 편입 경로를 증명하지 못하는 provenance 한계 아래에서만 분류했다. 해결되지 않은 hit 때문에 artifact를 악성이라고 단정하지 않으며, 제한 pilot 전 synthetic source/build metadata 조사 항목으로 남긴다.

## Provenance Residual Risk

| 통제 | 상태 | 범위 |
|---|---|---|
| exact version/tag | 확인 | v0.60.0, lightweight tag |
| exact source commit | 확인 | `0d0b35865036f8b5c2f0104d9744fa84985ffff1`; source commit signature valid |
| official release URL/checksum | 확인 | 공식 release checksum metadata |
| locally verified SHA-256 | 세 archive 확인 | x86_64 GNU, aarch64 GNU, macOS arm64; manifest와 일치 |
| detached binary signature | 미확인 | binary 서명 검증 불가 |
| GitHub attestation / SBOM | 미확인 | release asset 검토에서 확인하지 못함 |
| reproducible build/source-to-binary | 미확인 | source commit과 binary의 암호학적 연결 없음 |
| isolated execution/egr​ess deny/non-root/snapshot | 계획만 | 실행하지 않음; 후속 격리 환경에서 입증 필요 |
| read-only artifact, synthetic-only, pre/post inventory, cleanup | 계획만 | 실행하지 않음 |

판정은 **`CHECKSUM_ONLY_ACCEPTED_FOR_ISOLATED_PILOT`**로 제한한다. 근거는 정확한 tag/source identity, 독립적으로 일치 확인한 공식 checksum, disposable 격리 환경에서의 non-root·외부 egress deny·synthetic-only·read-only binary·사전/사후 inventory·snapshot rollback·cleanup을 묶는 보완 통제다. 이는 provenance가 검증됐다는 뜻이 아니며, 이번 실행 승인이 아니다. 격리 통제가 준비되지 않거나 unresolved credential hit를 정책상 수용할 근거가 없으면 Vector 실행은 `PRECONDITION_PENDING`으로 남긴다. 개발자 host, 실제 로그, production/조직 사용에는 이 위험 수용을 적용하지 않는다.

## Selected Next Step

선택은 **`VECTOR_JSONL_ADAPTER_DESIGN`**이었다. 후속 Phase 35.2는 별도 namespace의 pure in-process JSON Lines core를 구현했다: closed six-key envelope, strict UTF-8, duplicate/non-finite reject, exact role match, bounded line/payload/queue, fixed errors, safe status. TDD에서 33-line batch의 기존 partial acceptance를 실패로 재현하고 atomic batch refusal로 고쳤다. 상세 검증은 [Phase 35.2 기록](collector_jsonl_adapter_core_35_2.md)에 있다. 이는 Vector 실행 승인이 아니다.

## Privacy Boundary

실제 로그는 금지한다. Phase 35.2 core는 합성 fixture만 사용한다. Disk buffer 기본 비활성. Envelope의 alias·sequence는 internal bounded context에서만 쓴다. Collector file path와 host metadata는 trusted parser 경계 전에 제거하는 설계가 필요하며, 실제 hostname/경로를 공개 projection에 보내지 않는다. Payload는 제한된 memory에 잠시 존재할 수 있다. 오류/status/log에는 payload·경로·식별자·credential을 넣지 않으며 restricted report나 guidance로 자동 전달하지 않는다. 공개 projection의 `subject_alias` 계약은 유지한다.

## AI Boundary

AI는 수집, framing, source role, trust, parser 선택에 관여하지 않는다. LLM으로 Vector config/VRL/parser를 만들거나 실행하지 않고 외부 AI에 원문을 보내지 않는다. 향후 parser proposal은 별도의 합성 전용 격리·AST/regex safety·property/fuzz·parity·사람 승인 gate를 요구한다. 자동 적용은 `NO_GO`다.

## Verification

- Source-level fixed revision trace 및 JSONL 설계 계약: 정적 검토만 수행.
- Phase 35.1A 문서 계약 테스트: 문서 작성 전 예상 실패 3건 확인. 후속 Phase 35.2 pure-core 계약 테스트와 macOS 합성 benchmark는 별도 기록에 있다.
- Vector archive: 공식 x86_64 GNU archive 한 개를 임시 수신해 manifest SHA-256 일치 및 member 안전성 확인; 실행/압축 해제하지 않음.
- Vector binary process 0; container/image/volume/network 0; package install 0; listener 0.
- manifest 변경 없음. production code, CI workflow, dependency, `uv.lock` 변경 없음.
- 정적 source trace는 runtime framing, failure behavior, throughput 또는 operational suitability의 실측이 아니다.

## Limitations

Vector native framing은 기존 listener와 호환되지 않는다. VRL custom path는 source-level 구성 가능성일 뿐 `CUSTOM_FRAMING_UNPROVEN`이다. Binary provenance·SBOM·attestation 없음과 broad-scan의 `UNRESOLVED` 3건은 유지한다. JSONL pure core는 구현됐지만 Linux와 실제 Vector 연동은 `NOT_TESTED`다. File rotation, source checkpoint replay, Vector buffer, sink delivery/retry, egress deny, process permissions는 실행하지 않았다. 실제 사용자 자료·조직 운영·원격 수집은 `NO_GO`; Vector production integration은 `NOT_IMPLEMENTED`; exactly-once·무유실 주장은 금지한다.

Phase 35.2 core: [collector JSON Lines adapter](collector_jsonl_adapter_core_35_2.md).
