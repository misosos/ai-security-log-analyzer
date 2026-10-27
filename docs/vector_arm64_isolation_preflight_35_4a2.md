# Phase 35.4A2 — Vector ARM64 isolation preflight

후속 상태 (2026-10-27): Phase 35.4B는 취소되지 않았으며 Ubuntu VM malfunction으로 `USER_ACTION_REQUIRED` 상태에서 일시 보류 중이다. Vector를 실행하지 않았다. VM·snapshot·artifact 상태는 변경하지 않았다. Phase 36.0 triage 설계는 이 blocker와 독립이며 이를 해소하거나 Vector 안전성을 검증하지 않는다.

검토일: 2026-10-27. 이 문서는 읽기 전용 VMware host 확인과 합성·정적 artifact preflight 기록이다. Vector 실행을 승인하지 않는다.

## Start Gate

- 시작 branch `main`, clean tree, local `main` = `origin/main` = `572a9e38e9fe4a22f17f4e645f3db214b12d9028`; `origin/main...HEAD`는 `0 0`이었다. 대상 커밋의 부모는 `cfdc105afcb248ce414f25bde685e57b6c7630f1`이다.
- 정확한 대상 SHA의 push run [40462392016](https://github.com/misosos/ai-security-log-analyzer/actions/runs/40462392016)은 `push`, `completed/success`, 정확한 HEAD였다. locked Python 설치와 전체 회귀(`2,953 passed, 2 warnings`), TCP Syslog smoke·reliability·management, JSONL Linux acceptance, restricted report, benchmark, Node/Chromium/axe, tracked-file 불변 검사가 성공했다. artifact는 0개다.
- `COLLECTOR_JSONL_LINUX_ACCEPTANCE_PASS roles=2 runs=80 synthetic=1 leaks=0`는 정확히 한 번 관측했다. 기본 TCP smoke, reliability, management 표식도 각 한 번이었다. axe는 `states=14 external_requests=0`였다.
- 전체 회귀에 Phase 32 truncate 회귀가 포함되어 성공했다. `v0.4.0` tag와 Release target은 `eecd6ee1cda0545e34b01c42e1a2163a899bcc27`을 유지했다.
- 부모 `cfdc105...`에 대한 별도 push run은 발견하지 못했다. 부모 변경을 포함한 HEAD tree의 위 전체 run은 성공했다. 부모 SHA 자체의 독립 CI 성공으로 확대해 기록하지 않는다.

## Platform Decision

Phase 35.4A의 Ubuntu 24.04 x86_64 검사는 그 플랫폼에 대한 정적 preflight로 보존한다. 실제 사용 가능한 후보는 사용자가 제공한 기존 **Ubuntu 24.04.5 LTS aarch64** VM이므로, 첫 격리 실행 후보를 Ubuntu ARM64 GNU로 재정렬한다. x86_64 CI나 macOS ARM64 archive는 Linux ARM64 실행 증거가 아니다.

Vector는 다운로드해 임시 디렉터리에서 archive 검사 및 안전한 정적 추출만 했다. **Vector는 실행하지 않았다.** 설정 검증, listener 연결, 실제 자료 사용은 없었다.

## ARM64 Artifact Preflight

- Fixed release: Vector `v0.60.0`; source commit `0d0b35865036f8b5c2f0104d9744fa84985ffff1`.
- Official asset: [`vector-0.60.0-aarch64-unknown-linux-gnu.tar.gz`](https://github.com/vectordotdev/vector/releases/download/v0.60.0/vector-0.60.0-aarch64-unknown-linux-gnu.tar.gz), redirect 최종 host `release-assets.githubusercontent.com`.
- 실제 수신 크기 56,805,541 bytes, `Content-Length`도 같은 값. actual SHA-256 `1540662d8bc33af5afd287f821ba930417e0f3124073bc9db6a29c59dda88dbb`가 expected hash, 기존 artifact manifest 및 고정 release의 공식 `SHA256SUMS`와 일치했다.
- checksum asset은 1,864 bytes, SHA-256 `c9107d804285c4980b251639afd48de14ac9ff14734371a69aca6097a2341413`였다. 이 검사는 checksum 일치만 증명한다. signature, SBOM, attestation, reproducible build 및 source-to-binary provenance는 미확인이다. credential 형태 문자열 `UNRESOLVED` 3건을 유지한다.
- 상세값은 [ARM64 preflight manifest](artifacts/vector_0_60_0_aarch64_preflight.json)에 있다. 공용 [Vector artifact manifest](artifacts/vector_0_60_0_manifest.json)의 ARM64 record와 값이 일치한다.

## Static Binary Inspection

전체 53 archive member(42 regular file, expanded regular size 151,119,387 bytes)를 실행 전 검사했다. 절대 경로, traversal, escaping symlink, hard link, device/FIFO/socket, setuid/setgid, world-writable executable, 중복 경로, case-fold collision, 240-byte 초과 경로, nested archive는 0개였다. 최대 member 경로는 92 bytes다. 안전 검사 뒤 task 전용 mode-0700 임시 staging에 추출하고 종료 시 archive와 staging을 제거했다.

추출한 `bin/vector`: 150,906,952 bytes, SHA-256 `c0231b1714541a10cfb03a9e965a81a98d6e97401f4c738dc7f741d60cefab7a`. `/usr/bin/file` 5.41은 ELF64 LSB PIE, AArch64, dynamically linked, interpreter `/lib/ld-linux-aarch64.so.1`, GNU/Linux 3.7.0 ABI 표기, Build ID `c61411f0eb71ec46d019a2208fc2707b501ba94e`, not stripped로 분류했다. Apple LLVM `objdump` 17.0.0은 `libz.so.1`, `libgcc_s.so.1`, `libpthread.so.0`, `libm.so.6`, `libdl.so.2`, `libc.so.6`를 기록했다. `readelf`는 사용할 수 없었다. `ldd`, Vector binary와 그 어떤 Vector 명령도 실행하지 않았다. 이 정적 목록은 guest에서 dynamic loader/library resolution이 성공한다는 증거가 아니다.

## Disk and Resource Budget

| 동시 점유 항목 | bytes | 근거 |
|---|---:|---|
| ARM64 compressed archive | 56,805,541 | 이번 실제 수신 |
| 추출 distribution | 151,119,387 | 실제 archive member 합 |
| read-only staging copy | 151,119,387 | 보수적 최대 copy cap |
| config/state/temp | 4,194,304 | 계획 상한 |
| synthetic input | 1,048,576 | 계획 상한 |
| wire capture | 16,777,216 | 계획 상한 |
| inventory/validation output | 4,194,304 | 계획 상한 |
| test results | 4,194,304 | 계획 상한 |
| bounded failure allowance | 67,108,864 | 계획 상한 |
| memory buffer의 disk allowance | 0 | disk buffer 금지; memory buffer는 RAM 별도 제한 |
| **subtotal** | **456,561,883** | 합계 |
| 15% margin | 68,484,283 | subtotal 기준 올림 |
| **planned peak** | **525,046,166** | 합계 + margin |
| root에 남겨둘 reserve | 3,221,225,472 | 3 GiB |
| **실행 전 필요한 free bytes** | **3,746,271,638** | peak + reserve |

별도 최소 free 조건은 1.25 GiB(1,342,177,280 bytes)이며, 더 강한 기준인 peak + 3 GiB reserve가 적용된다. Guest의 현재 free bytes는 확인하지 않았다. 과거 약 8 GiB 관측치는 현재 근거가 아니다. 따라서 disk 조건은 `RESOURCE_BLOCKED`다. 큰 dummy file을 만들지 않았고 디스크·partition·mount를 변경하지 않았다.

5.8 GiB VM 메모리 정보는 과거 사용자 제공값이며 현재 재확인하지 않았다. 실행 전 후보 cap은 Vector 768 MiB, JSONL runtime 768 MiB, 합계 1.5 GiB 이하, CPU 1개, PID 32, FD 64, wall time 180초, state+temp 256 MiB, file size 16 MiB다. Vector memory buffer는 최대 128 event 및 line당 65,536 bytes 이론 상한을 쓰면 8 MiB를 넘지 않도록 계획한다. JSONL core 한도는 queue 256 event/1,048,576 payload bytes 및 feed당 32 record다. 이 값들은 제안 상한이며 cgroup v2 적용, swap/OOM 상태, 실제 guest memory와 disk를 확인하기 전에는 실행 설정이 아니다. 상한 적용을 독립 확인할 수 없으면 실행하지 않는다.

## VMware Host Inventory

사용자 지정 VMX 경로를 읽기만 했다. `vmrun` 및 대상 VMX가 존재한다. `vmrun list`는 VM 1개가 실행 중이고 대상 VM도 실행 중임을 확인했다. 강제 종료하지 않았다. VMX에는 2 vCPU와 6,144 MiB RAM이 설정되어 있다. 이는 guest에서 현재 사용 가능한 메모리 관측값이 아니다. snapshot 목록 조회는 성공했고 `clean-before-phase-31-2a`, `pre-phase-33-3d` 이름이 존재했다. 이름만으로 clean 상태를 추정하지 않는다.

VMX에서 network adapter `present=TRUE`, `connectionType=NAT`, `usb.present=TRUE`였다. shared folder 수 설정은 unset이다. clipboard copy/paste, drag-and-drop, HGFS/guest isolation, USB auto-connect disable 설정은 명시적으로 확인되지 않았다. unset은 disabled의 증거가 아니다. guest mount와 실제 host data visibility는 조사하지 않았다. 따라서 **host 공유 경계가 확인되지 않았고 `ISOLATION_BLOCKED`**다. VMX, snapshot, disk, network 및 VM 상태를 변경하지 않았다.

## Guest Inventory Procedure

VM console에서 다음 read-only 점검을 후속 단계에서 별도로 수행할 수 있다. 이 단계에서는 실행하지 않았다. 출력은 검토 전 식별 가능한 mount/socket/container label을 제거하고 집계값만 보관한다. 실제 HOME 내용, 환경 변수, shell history, credential 파일과 로그 파일은 열지 않는다.

```sh
cat /etc/os-release
uname -m
getconf _NPROCESSORS_ONLN
awk '/^(MemTotal|MemAvailable|SwapTotal|SwapFree):/ {print}' /proc/meminfo
df -B1 --output=size,used,avail,pcent /
findmnt -n -o FSTYPE,OPTIONS /
lsblk -b -o NAME,SIZE,TYPE,RO,FSTYPE,MOUNTPOINTS
id -u; id -g
docker version --format '{{.Client.Version}}|{{.Server.Version}}' 2>/dev/null || true
printf 'containers=%s images=%s volumes=%s networks=%s\n' \
  "$(docker ps -q 2>/dev/null | wc -l)" \
  "$(docker image ls -q 2>/dev/null | sort -u | wc -l)" \
  "$(docker volume ls -q 2>/dev/null | wc -l)" \
  "$(docker network ls -q 2>/dev/null | wc -l)"
printf 'listeners=%s processes=%s vmhgfs_mounts=%s vector_processes=%s\n' \
  "$(ss -H -lntup 2>/dev/null | wc -l)" \
  "$(ps -eo comm= | wc -l)" \
  "$(findmnt -rn -t fuse.vmhgfs-fuse,vmhgfs 2>/dev/null | wc -l)" \
  "$(pgrep -x vector 2>/dev/null | wc -l)"
printf 'cgroup_v2=%s memory_max=%s pids_max=%s\n' \
  "$(test -f /sys/fs/cgroup/cgroup.controllers && echo yes || echo no)" \
  "$(cat /sys/fs/cgroup/memory.max 2>/dev/null || echo unavailable)" \
  "$(cat /sys/fs/cgroup/pids.max 2>/dev/null || echo unavailable)"
```

추가로 허용된 전용 pilot 디렉터리만 대상으로 기존 Vector executable/config/state 존재 여부와 사용 UID/GID를 집계한다. 전체 `/`, 실제 HOME, shell command line, process arguments 또는 credential 내용을 탐색하지 않는다. system-wide open sockets는 주소를 출력하지 않는 집계만 한다.

## Network Isolation Procedure

현재 VM의 NAT는 egress deny가 아니다. 후속 실행에서는 명시적 사용자 승인 후 VMware network adapter를 disconnect하는 방안을 우선 검토한다. 그 조작은 이번 단계에서 하지 않는다. Guest에서 변경 전 기존 established connection count를 확인하고, adapter 분리 후 non-loopback interface가 모두 down인지, default route가 없거나 외부 연결이 OS 경계에서 실패하는지, loopback TCP가 동작하는지 확인한다. 아래는 다음 단계에서만 실행할 요약 출력 probe이며 이번에는 실행하지 않았다.

```sh
printf 'up_non_loopback_links=%s default_routes=%s established_sockets=%s\n' \
  "$(ip -o link show up | awk -F': ' '$2 != "lo" {n++} END {print n+0}')" \
  "$( { ip -4 route show default; ip -6 route show default; } | wc -l)" \
  "$(ss -Htn state established 2>/dev/null | wc -l)"
if getent ahosts example.com >/dev/null 2>&1; then echo dns_probe=RESOLVED; else echo dns_probe=BLOCKED; fi
python3 - <<'PY'
import socket
try:
    with socket.create_connection(("1.1.1.1", 443), timeout=2):
        print("external_tcp_probe=CONNECTED")
except OSError:
    print("external_tcp_probe=BLOCKED")
PY
```

연결 성공 또는 loopback 이외의 활성 interface가 있으면 중단한다. DNS와 TCP probe 모두 OS/network 경계에서 실패해야 하며, 격리 확인 뒤에만 고정 loopback listener를 허용한다. OS/network layer의 독립 검증이 있어야 하며 Python monkeypatch나 Vector config만으로 egress 차단을 주장하지 않는다. 인터넷에 연결된 다른 adapter가 있거나 OS-level deny를 독립 확인할 수 없으면 `ISOLATION_BLOCKED`다.

## Non-root and Resource Limits

후속 pilot은 전용 non-root UID/GID, capability 없음, privileged port 없음, `no_new_privs` 후보, read-only binary/config/synthetic input, 전용 0700 state/temp, config 0600을 사용한다. 실제 `/var/log`, journal, HOME, report/checkpoint, repository, Docker socket, host shared folder, device, 광범위한 `/proc`·`/sys` 접근은 금지한다. Vector API, disk buffer, shell/exec component, dynamic download, remote configuration, environment interpolation은 비활성·금지한다. cgroup v2 및 memory/pid/io 제한이 확인되지 않으면 실행 금지다. swap 증가/OOM을 정상 성공으로 보지 않는다.

## Configuration and Wire Fixtures

기존 `tests/fixtures/vector_jsonl_35_4a/vector_candidate.yaml`과 ASCII·한국어 fixture 4개는 수정하지 않았다. fixture SHA-256은 application ASCII `2beead5c89e0720730d5d3cfd29013cac97f5ac16836b0e975551d8276f801fe`, application 한국어 `ce99e0c554a4044f5fac5113494ac4a786748b6deaedddde3d3c98f38b40d058`, SSH ASCII `89d6a74a6ba4b347a4f0f18f8b1aa125474b13e9dfd89ee13ae8049cc713adf2`, SSH 한국어 `e97333d9320c5e3b3374561d7c269b6b5c25fac80800f2e46b97dd7e3ccdaa7e`; config fixture `e169f0b680362526bfb2b5c79b3106fed1b5b921acb0b42a51cc1232138a5e2e`였다.

JSONL 역할, 정확한 6개 key, strict UTF-8, LF delimiter, 8,192-byte payload, 65,536-byte line, 32/33 record feed 경계는 기존 core와 fixture 계약을 그대로 따른다. architecture-specific config는 만들지 않는다. 실제 Vector transform이 이를 지키는지는 아직 검증하지 않았다. Vector `validate`는 egress deny 전에는 실행하지 않으며, 이 단계에서 실행하지 않았다. 기존 fixture의 Vector API 비활성·disk buffer 비사용 후보 및 source metadata 정리는 설정 의도이지 Vector 동작 검증 결과가 아니다.

## Decision and Remaining Actions

- Artifact byte/checksum 및 archive static member checks: `PASS`; ELF/AArch64 정적 분류 완료. checksum은 서명이나 source-to-binary provenance가 아니다.
- Disk: `RESOURCE_BLOCKED`; 현재 guest free space 및 cgroup/실제 resource limits 미확인.
- VMware isolation: `ISOLATION_BLOCKED`; VM이 현재 실행 중이며 NAT와 USB가 켜져 있고 shared-folder/clipboard/drag-and-drop 경계가 확인되지 않음.
- 최종: `USER_ACTION_REQUIRED`; **Phase 35.4B 실행을 승인하지 않는다.** VM 소유자가 별도 승인된 시점에 snapshot restore/clean-state 확인, 공유·USB 차단, 네트워크 격리 및 guest inventory를 완료해야 한다. 이번 단계에서는 그 변경을 하지 않는다.
- 다운로드·정적 추출 임시 자료는 제거했다. package 설치, container/image/volume/network 생성, Vector process, listener는 0이다. secure erase를 주장하지 않는다.
- 실제 사용자 자료, 조직 운영, 원격 collection은 `NO_GO`. TLS/mTLS, durable spool, exactly-once/lossless는 지원하지 않는다. Vector production integration은 `NOT_IMPLEMENTED`다.
