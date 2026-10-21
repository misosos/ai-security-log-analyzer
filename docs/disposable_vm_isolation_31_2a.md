# Phase 31.2A — 폐기형 Linux VM 격리 기반 설계와 실행 보류

## Gate와 판정

기준 commit `1e7288ceb7312a89ed253fab4ea595bfeecbd471`의 [CI push run 39625656698](https://github.com/misosos/ai-security-log-analyzer/actions/runs/39625656698)은 `main`의 정확한 SHA에서 `completed/success`였다. 처음에는 조회되지 않았으나 나중에 생성된 기존 run을 확인했으며 **수동 dispatch는 하지 않았다**. Ubuntu 통합 설정 관리, 전체 pytest, locked Python 설치, Node 설치와 Chromium·axe 단계가 각각 성공했고 저장 artifact는 0개다. 시작 시 main·working tree clean·local/remote SHA 일치·behind 0/ahead 0을 확인했다. v0.4.0 tag·Release는 기존 `eecd6ee1cda0545e34b01c42e1a2163a899bcc27`을 유지한다.

**실제 VM 검증: `BLOCKED_NO_DISPOSABLE_VM`. Phase 31.2B: NO-GO.** macOS 15.7.7에서 QEMU 실행 파일은 있지만 실행 중인 QEMU VM이나 저장소 안의 VM image는 확인되지 않았다. 사용 가능한 Docker context는 Docker Desktop의 Linux/aarch64 daemon이다. 별도 폐기형 Linux VM의 guest OS·독립 disk·host share·clipboard·route·snapshot 정책을 확인할 근거가 없으므로 Docker Desktop container 결과를 VM PASS로 대체하지 않았다. 새 VM 설치, OS image 또는 probe image layer 다운로드, container/network 생성은 하지 않았다. 사용자 HOME·실제 로그·설정·credential에는 접근하지 않았다. 이 문서와 [고정 오프라인 계획 harness](../scripts/disposable_vm_probe_31_2a.py)는 실행 안전성을 입증하지 않는다.

[Phase 31.1 정적 감사](pentagi_supply_chain_audit_31_1.md)의 `SOURCE_IMAGE_BINDING_UNPROVEN`, versioned installer 부재, PentAGI control plane의 Docker socket 요구, runtime download 통제 미검증, LLM 없는 실행 가능성 미검증은 그대로다. PentAGI image·installer·Compose·source build·도구 실행이나 대상 스캔은 수행하지 않았다.

## VM 준비 조건

후속 실행 전에 운영자가 폐기 가능한 Linux VM의 종류, guest OS/version, 별도 가상 disk, 종료 후 전체 폐기 절차를 기록해야 한다. Host shared folder, clipboard, drag-and-drop, 사용자 HOME mount, credential 전달은 꺼져 있어야 한다. VM에 연결된 물리·가상 NIC, default route, DNS와 IPv4/IPv6 firewall 정책을 검토하되 raw route·host/LAN/VPN 주소·hostname을 저장소에 넣지 않는다. Snapshot·backup 잔존과 hypervisor/guest 간 공유의 잔여 위험을 별도로 기록한다. 이를 만족하는 기존 VM이 없으므로 현재는 OS image의 출처·크기·host 변경 범위와 사용자 승인을 확인하기 전 설치하지 않는다.

[Docker bridge 문서](https://docs.docker.com/engine/network/drivers/bridge/)에 따르면 보통의 bridge는 외부 egress가 가능하고 host가 container에 접근할 수 있다. [`--internal` 문서](https://docs.docker.com/reference/cli/docker/network/create/)도 gateway와 적절히 설정된 host 서비스 통신 가능성을 명시한다. 따라서 Docker internal network **하나만으로** 인터넷·LAN·VPN·host 차단을 증명하지 않는다. VM 바깥 경계의 route/firewall 거부와 guest 내부 정책을 함께 관찰해야 한다. Published port와 직접 라우팅도 [Docker 문서](https://docs.docker.com/engine/network/port-publishing/)에 따라 별도 확인한다.

## 고정 harmless probe 후보와 범위

공식 [Docker BusyBox image](https://hub.docker.com/_/busybox)의 `1.37.0` manifest metadata만 조회했다. Image layer는 pull하지 않았다. `linux/amd64` 후보는 `docker.io/library/busybox@sha256:66a6306db78bf2dbf3487f293aa8d6990d8e506fdffab9cc43fe422becf886e4`, `linux/arm64` 후보는 `docker.io/library/busybox@sha256:d82c2ab94640ded77cf76514ce6a84870761105058a4a9e51b05a8a79be97a6c`다. 이는 **조회 시점의 platform manifest digest**이며 사용 VM의 architecture가 확인되면 해당 digest를 다시 조회·고정하고 image 취득 범위를 검토해야 한다. Mutable tag나 PentAGI image는 실행 후보가 아니다.

`scripts/disposable_vm_probe_31_2a.py`는 `--platform` 두 값 중 하나에 대해 digest·고정 제약·검사 ID를 JSON으로 출력할 뿐 Docker 명령을 **실행하지 않는다**. 주소·hostname·명령·mount·Docker context를 입력으로 받지 않는다. 출력에 포함된 `docker run` 인자는 검토용 예시이며 `--pull=never`, non-root UID 65532, `--cap-drop=ALL`, `no-new-privileges`, read-only root, 1 MiB tmpfs, PID 32, CPU 0.5, memory/swap 64 MiB, core dump 0, restart off, 전용 network, digest를 고정한다. Host path/device/socket mount와 port publish 인자는 없다. Wall-clock 상한은 VM 내 별도 supervisor에서 강제해야 하므로 현재 인자만으로 충족됐다고 보지 않는다. `--tmpfs` 크기는 실제 disk quota 증명이 아니며 cgroup·tmpfs 결과를 guest에서 확인해야 한다. Probe container 안에는 Docker socket을 제공하지 않는다.

실행 가능한 VM이 준비되면 공격 기능이 없는 고정 응답 HTTP target **하나**만 전용 internal network에 두고, 고정 identity를 확인한다. SSH server·인증 시도·포트 스캔·exploit·provider 연결은 없다. Target에 host publish port를 주지 않는다. Probe와 target이 같은 network에서만 통신하고 다른 network/container 및 VM 외부에서는 접근할 수 없어야 한다. Target log에는 합성 canary만 넣고 raw log를 저장소에 커밋하지 않는다. 현재 harness는 target을 생성하거나 호출하지 않는다.

## 실측해야 할 검사와 실패 동작

각 연결 시도에는 짧은 bounded timeout과 고정 exit code를 부여한다. 열린 서비스가 없어서 TCP가 거부된 것과 route/firewall로 차단된 것을 혼동하지 않도록 guest firewall counter·route 정책·container exit code를 **함께** 확인한다. Host/LAN/VPN 대상은 VM이 이미 알고 있는 route·gateway만 이용하고 임의 주소를 탐색하지 않는다. 문서용 비사용 주소만으로 실제 LAN 차단을 입증하지 않는다. Raw route, 주소, packet capture는 보존하지 않는다.

| 영역 | 이후 VM에서 필요한 증거 | 현재 결과 |
|---|---|---|
| Network deny | Public HTTP·DNS, 알려진 host gateway·macOS host service, 알려진 LAN·VPN route, metadata, allowlist 밖 IP/name의 거부; dedicated target만 허용; callback 외부 비노출 | **NOT_TESTED** |
| Container privilege | Non-root, effective capability 0, no-new-privileges, privileged=false, host network=false, host path/device/socket mount 0 | **NOT_TESTED**; 오프라인 명령 계약만 검사 |
| Filesystem·resource | Root write 거부, 명시 tmpfs write 허용, CPU/RAM/PID/disk/write byte·wall-clock 상한, core dump off, child 종료 | **NOT_TESTED**; 계획 수치만 지정 |
| Target | 고정 identity, 내부 통신 1개 허용, 외부 publish 0, 다른 network에서 거부, 합성 canary만 기록 | **NOT_TESTED** |
| 반복 | 동일 조건 최소 3회에서 허용·거부 exit code와 정리 count 일치 | **NOT_TESTED** |
| Fault | Target 부재, DNS/egress 거부, resource 초과, timeout, 강제 종료, VM 재시작 후 잔존 | **NOT_TESTED** |
| Cleanup | Container/network/volume 0, child/listener 0, 임시 VM 전체 폐기와 snapshot·backup 잔여 기록 | **NOT_TESTED** |

무유실, 완전 격리, host 탈출 불가능을 주장하지 않는다. 컨테이너가 실패하면 제약을 조용히 완화하지 않고 blocker로 남긴다. 결과 기록에는 VM 종류·OS, Docker version, image digest, 제한 설정, 허용·거부 건수, exit code, cleanup count와 한계만 허용한다. Raw route, host/LAN 주소, hostname, 사용자명, 실제 경로, Docker daemon 전체 정보, packet capture, raw container log, VM image/snapshot, credential은 제외한다.

## 향후 Docker daemon 권한 선택지

[Docker daemon 보호](https://docs.docker.com/engine/security/protect-access/)와 [rootless mode](https://docs.docker.com/engine/security/rootless/)의 권한 경계를 참고한다. 아래는 정적 비교이며 PentAGI 호환성을 실행 검증하지 않았다.

| 후보 | VM/host 탈출 영향 | 구현 복잡도·호환성 | 잔여 위험 |
|---|---|---|---|
| VM 내부 Docker socket 전체 제공 | VM 내부 root 수준의 daemon 제어. macOS host root와 동일하다고 단정하지 않음 | 구현 단순, PentAGI 호환 가능성 높음 | VM escape, host share·route·snapshot을 통한 확산. 첫 probe 금지. |
| Rootless Docker | Guest 비특권 UID의 daemon으로 범위 축소 | Guest cgroup v2/systemd 등 전제와 Docker API 기능 호환성 확인 필요 | Rootless daemon 전체 제어·network/file mapping 위험. |
| Socket proxy allowlist | 허용 API만 전달할 수 있다면 제어면 축소 | PentAGI가 요구하는 create/start/network/image API와 거부 규칙을 전부 검증해야 함 | 누락된 API·요청 body 우회, 권한 상승. |
| Nested disposable daemon | 실행 daemon과 control plane 분리 가능 | 독립 disk·network·lifecycle·resource 관리 복잡 | Nested daemon 자체의 광범위 권한과 VM 경계. |
| Control plane/daemon 분리 | 별도 daemon을 VM 안에 국한 | Endpoint 설정·인증·분리 정책 호환성 미검증 | Daemon API 유출 시 해당 VM 전체 노출. |
| Source 수정으로 orchestration 제거 | Socket 자체 제거 가능성 | 큰 변경과 upstream 추적 부담, PentAGI 기능 호환성 불명 | 변경된 source-image 대응과 새 공급망 검증 필요. |

## Phase 31.2B 진입 gate

폐기형 VM 존재와 host share 부재, 인터넷·LAN·VPN·metadata 차단, 내부 target만 허용, privilege/filesystem/resource 제한 강제, socket 미제공 probe, 외부 callback 비노출, 3회 결정성, fault와 cleanup, 개인정보 비노출이 **모두 실제 PASS**여야 다음 단계를 검토할 수 있다. 현재는 `BLOCKED_NO_DISPOSABLE_VM`이고 실제 network deny·resource·privilege·cleanup은 PASS가 아니다. VM proof가 통과해도 PentAGI 실행 승인은 별도 gate다. `SOURCE_IMAGE_BINDING_UNPROVEN`, versioned installer 부재, Docker socket 요구, runtime download 통제와 LLM 없는 실행 가능성은 계속 NO-GO blocker다.
