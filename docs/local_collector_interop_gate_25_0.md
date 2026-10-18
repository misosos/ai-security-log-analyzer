# Phase 25.0 — 로컬 collector 상호운용 설계 gate

**판정: CONDITIONAL GO — Vector 단일 SSH source의 격리된 Phase 25.1 실험 설계에만 적용.** 외부 collector의 설치·실행, receiver 구현, 자동 전환, 공식 지원·릴리스 gate 채택은 아직 승인하지 않는다. 기존 tailer의 학습·결정적 분석 가치를 유지한다. Phase 24.2의 Ubuntu CI는 전체 회귀 2,297 passed/기존 경고 2개로 성공했고 bundle의 runtime 37·dev-inclusive 57 package 계약이 통과했다. 플랫폼별 artifact **선택** 수치와 macOS/Ubuntu manifest의 직접 byte 비교는 CI 출력으로 입증되지 않았다. Phase 24.1 OSV 경로는 release gate NO-GO이고 evidence bundle은 Release asset이 아니다.

## 현재 계약과 평가 경계

프로젝트는 로그 파일을 trusted local process에서 tail하고, 기존 parser → detector → correlation → risk → case → privacy-safe publication 의미를 소유한다. application v2 기본 config의 동일 파일 bounded checkpoint만 지원한다. SSH v1 명시적 config는 `FROM_END` live analysis이지만 durable checkpoint 대상이 아니다. rotation·truncation은 자동 handoff가 아니라 fail closed이며 명시적 새 epoch 승인을 요구한다. [Phase 21.6](live_rotation_21_6.md)의 두 세대 private checkpoint metadata 확대와 copytruncate 병합은 여전히 NO-GO다. 외부 collector를 붙여도 탐지 임계값, source role, 원본 line, timestamp·IP·account·path/query, 입력 순서를 수정할 수 없다. 수집기의 file checkpoint가 analyzer의 queue ack·분석/publication commit을 증명하지 않는다. **두 checkpoint를 독립적인 진실 원본으로 병합하지 않는다.**

아래 제품 사실은 2026-10-18에 확인한 공식 release·문서 범위다. 링크가 설명하는 *제품 기능*과 이번 프로젝트의 *채택 정책*은 별개다. 수치 상한·권한·recovery 판정은 프로젝트 정책이며 공급업체 보장이 아니다.

## 후보와 공급망

| 항목 | Fluent Bit | Vector |
| --- | --- | --- |
| 고정 후보 | [v5.1.4](https://github.com/fluent/fluent-bit/releases/tag/v5.1.4), source tag `eef172226af2879b24ce61d8d73a874567e465c3`; Apache-2.0 | [v0.59.0](https://github.com/vectordotdev/vector/releases/tag/v0.59.0), source tag `a3231c76bdea5078bc54c205cf89f5a1ceddbb73`; MPL-2.0 |
| 배포물·플랫폼 | 공식 [macOS 문서](https://docs.fluentbit.io/manual/installation/downloads/macos)는 Apple Silicon/Intel 호환과 pkg/source build를 안내하지만 Homebrew는 공식 지원 아님. [Ubuntu 문서](https://docs.fluentbit.io/manual/installation/downloads/linux/ubuntu)는 GPG 서명 패키지를 안내한다. 해당 GitHub release 자산은 schema JSON 2개이며 macOS/Linux 실행 binary digest는 이번 gate에서 고정하지 못했다. | GitHub release에 macOS arm64 archive 52,687,645 bytes, SHA-256 `6f0cd290c90ea2cfc7cb3c10eca32fc897f0b958b60d48ad2867a91d5585363c`; Linux x86_64 GNU archive 57,855,328 bytes, SHA-256 `fb15878d1cd68445e0658792a8fa7ccf02ae8a353c6cc5d6fe867b171993e19f`; SHA256SUMS asset이 있다. 다운로드·내용 검사·실행은 안 했다. |
| 공급망 한계 | 공식 Linux package signing key가 문서화되어도 정확한 v5.1.4 package→source 재현성·macOS pkg 서명·container digest는 미검증. 설치 script는 사용하지 않는다. | release checksum은 같은 게시자 제공 증거이지 독립 서명·SLSA provenance·reproducible build 증명이 아니다. archive 내부 파일/native dependency·update behavior는 실행 전 검사 필요. |
| 보안·cadence | [maintenance/security](https://github.com/fluent/fluent-bit/security): v5.1 current stable, v5.0 maintenance. cadence는 release 이력으로 관찰하되 고정 주기/SLA 주장 없음. | [security policy](https://github.com/vectordotdev/vector/security)와 release notes 공개. `vdev-*` tag는 제품 stable release가 아니므로 `v0.59.0`만 비교. 고정 cadence/SLA 주장 없음. |
| 네트워크·telemetry | package repository·image pull은 acquisition 네트워크 필요. 런타임 자동 update·telemetry의 완전한 부재는 검증하지 못했다. 무네트워크 실험이 필수. | 공식 [privacy policy](https://github.com/vectordotdev/vector/blob/master/PRIVACY.md)는 다운로드 통계를 설명한다. [API](https://vector.dev/docs/reference/configuration/api/)는 기본 disabled이지만 모든 runtime egress 부재 증명은 아니다. acquisition과 network-denied 실행 분리 필수. |

두 제품 모두 native 실행물이다. 단순 SHA-256 일치만으로 source와 binary의 독립적 provenance를 확정하지 않는다. 공급망 gate에서 exact archive/digest, checksum·서명·attestation 가능성, 포함 executable/공유 라이브러리·설치 script·updater, macOS/Linux architecture, 실행 전후 network/process/file 차이를 검증하지 못하면 Phase 25.1은 **SUPPLY_CHAIN_BLOCKED**다. 도구의 최신판 자동 설치는 없다.

## 제품 기능과 프로젝트 적합성

| 의미 | Fluent Bit 공식 근거 | Vector 공식 근거 | 채택 전 확인 |
| --- | --- | --- | --- |
| regular file·FROM_END·offset | [Tail input](https://docs.fluentbit.io/manual/4.2/data-pipeline/inputs/tail): `read_from_head=false`, SQLite `db`, inode/filename 비교 선택 | [File source](https://vector.dev/docs/reference/configuration/sources/file/): `read_from=end`, private `data_dir` checkpoint, `ignore_checkpoints`는 읽기만 무시하고 쓰기는 계속 | 기존 줄 미처리와 재시작 중 append 결과를 실제로 비교 |
| rename/late writer·copytruncate | `rotate_wait`는 이전 파일을 제한 시간 더 관찰; `skip_long_lines=true`는 줄을 버림 | 열린 FD를 EOF까지 유지, `rotate_wait_secs`; copytruncate는 rotated copy 포함/`delaycompress`로 누락 가능성을 **줄이는** 안내 | old writer late append·rapid rotation·copytruncate에서 중복/gap을 계측; 무유실 주장 금지 |
| partial/multiline·UTF-8·긴 줄 | Tail buffer/long-line 정책과 multiline parser 제공. 기본 한도 도달 시 파일 감시 중단 가능 | delimiter·multiline·`max_line_bytes`; encoding 변환을 켜면 invalid sequence가 U+FFFD로 대체됨 | pilot은 multiline/변환/skip 금지. 완성 LF·strict UTF-8·원문 byte parity 확인; oversized는 explicit FAILED |
| identity·fairness | inode/filename DB와 inotify watcher(Linux)·stat polling 경계; macOS 동일 동작은 실험 필요 | checksum fingerprint 기본 1줄(그보다 적으면 읽지 않음) 또는 device+inode; `max_read_bytes`, `oldest_first=false`의 파일 간 공정 읽기 | 단일 SSH 파일만 시작. inode reuse·짧은 파일·순서 변형 위험 기록 |
| backpressure·disk·shutdown | [Backpressure](https://docs.fluentbit.io/manual/administration/backpressure): `mem_buf_limit` pause, filesystem queue; `storage.total_limit_size` 초과 시 oldest chunk **폐기** | [Buffering model](https://vector.dev/docs/architecture/buffering-model/): memory 비영속, disk 최소 약 256 MiB/기본 500ms fsync, `block` 기본·`drop_newest` 선택; disk 손상 복구가 일부 event를 잃을 수 있음 | bounded byte/item·disk·shutdown flush를 측정. drop/unknown flush는 gap/DEGRADED, 정상 0건 금지 |
| local egress·metrics | [Forward UDS](https://docs.fluentbit.io/manual/data-pipeline/outputs/forward)는 MessagePack protocol 수신기가 필요하고 [file output](https://docs.fluentbit.io/manual/4.2/data-pipeline/outputs/file)은 privacy/format 검증 필요 | [Socket sink](https://vector.dev/docs/reference/configuration/sinks/socket/)는 `unix_stream`, `raw_message`, length/newline framing. **delivery: best effort**. `unix_datagram`은 macOS 불가. 내부 metrics는 file tag를 끌 수 있음 | sink write를 analyzer ack라 볼 수 없음. path/hostname/line이 log·metrics에 노출되지 않는지 canary 검증 |

공식 문서에 적힌 기능을 *프로젝트에서 검증한 보장*으로 옮기지 않는다. 특히 Vector file source는 성공적으로 **읽은 뒤** offset을 checkpoint할 수 있으나 socket sink의 `best effort`와 분석기 commit 사이 crash window가 남는다. Fluent Bit 역시 DB offset·output queue 간 transaction이 프로젝트의 analysis transaction과 같지 않다. CPU/memory footprint·실제 macOS/Linux 동작·정확한 shutdown flush 시간은 **NOT_TESTED**다.

## 연결 구조와 권장안

| 구조 | 개인정보·권한 | framing/backpressure·복구 | 판단 |
| --- | --- | --- | --- |
| A. private spool → 기존 tailer | 0700/0600 spool에 raw line의 **새 장기 사본** 생성, backup·삭제 책임 확대 | 기존 tailer 재사용은 쉽지만 spool rotation/동시 writer/두 offset 경쟁과 crash window 발생 | 현재 정책에서는 **NO-GO**; raw retention 확대는 별도 승인 필요 |
| B. private Unix stream socket → 새 bounded receiver | process-private 0700 directory, socket 가능한 최소 mode, peer UID 확인. 같은 UID 악성 프로세스는 완전 격리 불가 | length framing·bounded queue·명시적 disconnect/gap 가능. 새로운 trusted receiver 구현·검증 필요 | **Phase 25.1 조건부 후보**; Vector raw_message의 원문 byte parity와 end-to-end ack 부재가 핵심 gate |
| C. loopback HTTP/TCP | Host/Origin만으로 로컬 프로세스 인증 불가; raw line이 TCP stack/API에 진입 | framing/ack 설계 가능하지만 token·CSRF·포트·재연결 면적 증가 | 이번 pilot **NO-GO** |

Unix 후보 계약은 고정된 `source_role=ssh`를 trusted CLI config에서 읽고 브라우저가 source/path를 변경하지 못하게 한다. receiver는 private socket의 owner/mode·parent identity를 검증하고 가능한 Linux `SO_PEERCRED`, macOS `LOCAL_PEERCRED`/`getpeereid` 지원을 개별 검증한다. 한 collector connection만 허용한다. 4-byte length prefix + exact frame length를 NDJSON보다 우선 검토한다. NDJSON은 LF escape/partial frame 정책이 단순하지만 metadata를 안전하게 실을 closed schema가 필요하다. Vector socket sink의 length-delimited **endianness 문서 표기가 서로 달라** 실제 고정 config·capture 검증 전에는 결정하지 않는다. `raw_message`는 source/sequence/instance ID를 싣지 않는다. receiver가 부여하는 receive-local sequence는 **upstream 누락 탐지 증거가 아니다**. 전역 monotonic sequence·collector instance ID를 transform 없이 제공할 수 있는지 입증하지 못하면 restart/rotation 후 자동 연속성은 NO-GO다. 임의 Vector transform을 추가해 해결한 것으로 간주하지 않는다.

정책 후보 상한은 **frame ≤64 KiB, receiver queue ≤32개/16 KiB를 우선 재사용**하되 서로 모순될 수 있으므로 첫 구현 전에 실제 현재 줄·queue 한도와 측정으로 조정한다. 이는 설계 임시값이지 공급업체 추천치나 허용 완료 계약이 아니다. strict UTF-8, LF 완성 line, unknown field 거부, frame/idle timeout, partial frame 폐기, malformed/oversize에서 terminal FAILED, slow sender에서 bounded backpressure, disconnect에서 DEGRADED를 요구한다. payload·socket path·peer identity는 stdout/stderr/API/SSE/UI에 내보내지 않는다. 단일 source role 외 payload는 받지 않는다. 수신 시점과 analyzer ack는 별개다.

## Checkpoint 소유권과 의미 동등성

| 정책 | 장점 | 충돌/결정 |
| --- | --- | --- |
| collector offset 원본, 프로젝트는 전달 prefix만 관리 | collector rotation 기능 시험 가능 | **pilot 후보**: SSH v1 명시적 config에는 durable project checkpoint가 없다. 수신 뒤 analyzer crash와 collector checkpoint 사이 gap/duplicate 가능성을 공개하고 불명확하면 fail closed |
| project checkpoint 원본, collector는 FROM_END 전달기 | 현재 application 복구 의미 유지 | collector restart 시 과거 전송을 복원 못하고 rotation 이점 약화; 적용 안 함 |
| epoch별 결합 checkpoint | 이론상 일관성 모델 가능 | 두 시스템 transaction/ack 및 새 private metadata 필요. **NO-GO**, 별도 승인 필요 |

Phase 25.1은 **SSH 하나**를 택한다. application v2는 기존 private checkpoint와 충돌하지만 SSH v1 `--monitor-config`는 `FROM_END`이고 SSH live parser/detection/correlation/risk/case가 이미 구현되어 있다. 외부 collector가 과거를 중복·생략하면 batch parity 자체가 깨지므로 해결·정상 0건으로 표시하지 않는다. collector 자신의 checkpoint만 원본 *파일 전달 위치*로 삼을 후보이며, analyzer의 확정 prefix/분석 결과의 durability를 보장하지 않는다. 운영 exactly-once·무유실·crash recovery는 주장하지 않는다.

합성 동일 sequence의 매 완성 prefix에서 `NormalizedEvent`·detection·correlation·risk·case의 **trusted** projection을 batch, internal tailer, collector 전달 경로로 비교한다. timestamp·microsecond·순서·중복을 정규화해 숨기지 않는다. public 비교는 allowlist safe DTO만 사용한다. 시나리오: append, partial LF, rename, old-writer late append, copytruncate, restart, duplicate delivery, skipped sequence, out-of-order, queue overflow, disconnect. 각각 원문 순서가 입증되면 parity PASS, 중복/gap 증거가 있으면 explicit gap/DEGRADED, 증거 부족이면 FAIL/NOT_TESTED다. 새 분석 epoch는 사용자 승인 없이 시작하지 않는다. file-access/global/cross-source 관계를 추가하지 않는다.

## 개인정보·위협 모델

collector config/checkpoint에는 source path가 있을 수 있고, trusted socket payload와 메모리에는 raw line·account·IP·query가 있을 수 있다. config/data_dir/socket는 private owner scope, 최소 log level, raw payload logging 금지, file/host tag metrics 금지, cloud/telemetry/API 비활성 및 network-denied runtime으로 검증한다. public status는 role·count·bytes·pressure·gap/degraded만 allowlist로 표시한다. 원본 path/filename, hostname, socket path, account/IP/query/raw line, offset/fingerprint/peer ID는 API·SSE·UI·HTML·오류·일반 log에 금지한다. crash dump·backup·filesystem snapshot의 잔존과 같은 UID의 비협력 프로세스 위험은 남는다. 외부 collector는 parser/detector/correlation/risk/case를 실행하지 않고 filter·transform·AI도 쓰지 않는다.

| 위협/진입점 | 예방 | 탐지·실패 동작 | 잔여 위험 |
| --- | --- | --- | --- |
| 악의적 writer·oversized/invalid line | 단일 regular file 승인, line/frame byte cap, strict UTF-8 | parser reject와 overflow를 분리; silent skip이면 FAILED | 짧은 악성 내용은 parser가 처리해야 함 |
| symlink/path 교체·permission drift | trusted setup, owner/mode·file identity 재검증 | 변경 시 fail closed; collector 자체 경계는 pilot 계측 | 검사 사이 TOCTOU |
| socket peer 위장·같은 UID 프로세스 | private dir/socket, peer credential, one connection | peer mismatch 즉시 거부·audit count | 같은 UID의 악성 코드 완전 차단 불가 |
| slow sender·partial/oversized frame | length cap·read timeout·bounded queue | partial 폐기, DEGRADED/FAILED 및 명시적 복구 | kernel socket buffer 안의 미확정 bytes |
| queue 고갈·disk full | blocking backpressure, private bounded budget | pressure/gap count; drop이나 fsync 실패는 FAIL | writer가 계속 쓰면 원본 rotation으로 gap 가능 |
| collector/analyzer restart·stale checkpoint | 한 offset owner, fixed epoch, no guessed merge | reconnect·checkpoint mismatch는 확인 필요/FAILED | sink write와 analysis ack 사이 중복·유실 |
| sequence forgery·replay·out-of-order | 단일 peer, closed frame, sequence/instance 증거 gate | 이전/누락 sequence 거부; 증거가 없으면 parity NO-GO | Vector raw_message 자체는 upstream sequence 없음 |
| rename/copytruncate race·late writer | 한 generation씩 확인, original order parity | 입증 못 한 교차 generation은 explicit gap | 극단적 빠른 rotation의 관찰 공백 |
| config tampering·raw logging·telemetry | private config, fixed allowlist, network denied | canary와 process/network 관찰 실패 시 pilot 중단 | same-UID·backup·crash dump |

## Phase 25.1 최소 pilot과 gate

**Vector v0.59.0 + SSH source 하나**의 합성·local-only 실험을 권장한다. 별도 전경 명령을 사용하고 local_web의 자동 child 실행·systemd/LaunchAgent/root 설치는 하지 않는다. source/target은 전용 임시 자료만; 설정의 file source→socket sink 외 plugin, filter, transform, remote egress는 금지한다. 실제 로그·기본 monitor config·홈·credential은 접근 금지. 수집기는 단일 합성 입력을 읽기 전용으로 열고, 별도 실험 writer만 해당 파일을 append/rotate한다. macOS와 Linux를 각각 검증한다.

실행 전 독립 gate: (1) exact release artifact, SHA-256·가능한 signature/provenance·source 연결, archive file 목록/실행 파일 점검; (2) installer 없이 전용 private temp config·data_dir; (3) acquisition 네트워크와 실행 `--network none`에 해당하는 OS/컨테이너 통제 분리; (4) host path/mount/credential 제외; (5) bounded timeout·stdout/stderr·output; (6) 소켓 권한/peer credential·framing/strict UTF-8/raw-message byte parity; (7) stop/restart·rename rotation 1회·duplicate/gap observation·batch/internal-tail parity·shutdown cleanup; (8) 실행 전후 process/file/network 비교와 알려진 artifact만 정리. Container만으로 host 로그 file rotation을 시험했다고 주장하지 않는다. 중단 조건은 공급망 미확인, runtime egress, source 변형, 원인 불명 drop, sequence/gap 관찰 불능, 개인정보 노출, two-checkpoint merge 필요, 또는 OS별 권한 검증 실패다. **새 IPC/개인정보 저장 확대는 별도 구현 승인 필요**다.

Phase 25.0 자체는 설계 문서와 계약 테스트만 추가한다. 설치·실행·dependency/`uv.lock`·production/CI 변경 없음. 이 판정은 pilot 실험 가능성의 조건부 평가이지 collector 기능의 PASS나 릴리스 적합성 평가가 아니다.
