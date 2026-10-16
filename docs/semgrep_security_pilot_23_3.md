# Phase 23.3 — isolated Semgrep pilot: supply-chain stop

판정: **SUPPLY_CHAIN_BLOCKED** (제품/CI 도입 **BLOCKED**). 2026-10-16의 공식 `semgrep/semgrep:1.181.0-nonroot` 이미지는 Docker Hub의 Verified Publisher에서 digest 고정으로 취득했으나, 실제 image metadata와 build history가 공개 OSS source tag가 아닌 **`semgrep/semgrep-proprietary` revision**을 가리켰다. 공개 Dockerfile에도 Pro 엔진 조건부 설치 stage가 있다. 따라서 공개 source와 실제 실행 이미지의 코드·native executable·dependency 범위를 충분히 연결할 수 없었다. 사용자 gate의 “공식 image의 검증 경계가 wheel보다 불명확하면 실행하지 않음”을 적용해 **Semgrep CLI/help, rule test, repository scan은 한 번도 실행하지 않았다**. Finding 0건, offline 무전송, false-positive 0건 또는 +10초 비용 통과로 해석하지 않는다.

## 시작 조건과 변경 전 기준선

- `main`, 시작 HEAD/`origin/main`: `add452dcdd66a89d821d04db7b0e6e6fa6af265a`, clean, behind 0/ahead 0. [동일 SHA의 Ubuntu CI](https://github.com/misosos/ai-security-log-analyzer/actions/runs/38912237296)는 completed/success이며 `uv sync --dev --locked --no-build-package hypothesis --no-build-package sortedcontainers`와 전체 pytest 단계가 성공했다. Ubuntu 전체 **2,261 passed, 기존 경고 2개, 새 경고 0개**; Hypothesis property 파일은 이 전체 단계에 포함되지만 독립 CI job은 없다.
- 변경 전 로컬 전체 pytest **2,261 passed, 기존 경고 2개, 84.47초**, privacy/API/UI focused **78 passed, 동일 경고 2개**. 공개 `v0.2.0` tag와 Release는 여전히 `2520e317475f96d48b4bfeef8f7ee04d63720308`, draft/prerelease 아님.
- Host `Darwin arm64`; Docker Desktop `4.95.0 (242831)`, Client/Server `29.8.2`, Engine `linux/arm64`. Client와 Server가 모두 응답했다. Docker가 있다는 사실은 격리 실행의 성공 증거가 아니다.

## 공식 배포물과 정적 공급망 검사

[Docker Hub Verified Publisher의 공식 Semgrep image](https://hub.docker.com/r/semgrep/semgrep/tags)는 `1.181.0`와 `1.181.0-nonroot` 태그를 게시한다. 여기서는 root variant를 사용하지 않고 **nonroot** index `sha256:4c37ae86cb02b5536f8c9ff6aabbc991944117e4678609e14e0f19a2bd7ea879`를 선택했다. `docker buildx imagetools inspect`로 확인한 manifest는 다음과 같다.

| Platform | 고정 manifest digest | 관찰 |
| --- | --- | --- |
| `linux/arm64` (macOS Docker Desktop에서 선택) | `sha256:67dd4c7c224746d827c722513b2268eb692af21c274a6b7f3552deaa4865277b` | 실제로 이 digest만 pull하고 metadata/history만 검사, 실행 안 함 |
| `linux/amd64` (Ubuntu x86_64 후보) | `sha256:4c45f49cb3014f0f2428709f2f759bd5fb27c83845acb4b8ae0e5cee130e29e6` | 원격 manifest만 확인; Ubuntu에서 pull/실행 안 함 |

arm64 manifest는 OCI layer **13개**와 config digest `sha256:f7bb2966913e41780b8ac0252bb0245ea7e40d0487509c3451dd5f0289336c7a`를 가졌다. Docker image inspect의 `linux/arm64` image size는 **1,590,793,665 byte(비압축)**였고 `User=semgrep`, `WorkingDir=/src`, `Cmd=[semgrep,--help]`, 별도 Entrypoint 없음이었다. 이는 nonroot 실행 가능성의 *설정상 근거*이지 실제 격리 검증은 아니다. Manifest index에는 두 플랫폼 각각 attestation manifest가 있었지만 **서명, SLSA provenance와 builder 신뢰는 독립 검증하지 않았다**.

공개 [`semgrep/semgrep` v1.181.0 source tag](https://github.com/semgrep/semgrep/tree/v1.181.0)는 OSS commit `72d3525fe7e02f486428386078f192f8c4756804`에 연결된다. 반면 pull한 이미지의 OCI label과 `DOCKER_OTEL_RESOURCE_ATTRIBUTES`는 source `github.com/semgrep/semgrep-proprietary`, revision `0f6e09374a8743d5ef1d5a2b778ad24568552335`를 명시했다. 해당 revision의 GitHub commit API는 공개 익명/현재 인증 범위에서 HTTP 404였으므로 소스 대조가 불가능했다. [`v1.181.0` 공개 Dockerfile](https://github.com/semgrep/semgrep/blob/v1.181.0/Dockerfile)은 `semgrep-core` native executable을 복사한 뒤 `semgrep-cli` stage에서 secret이 있으면 `semgrep install-semgrep-pro`를 실행하는 구조다. 실제 image history에도 `semgrep --pro --version`과 큰 wheel 설치 layer가 보였다. 따라서 Pro 포함 가능성은 예상 가능한 build path지만 **해당 proprietary revision과 OSS tag의 정확한 일치, 포함 실행 파일 목록, install 시 추가 다운로드·lifecycle 효과를 검증할 수 없다**. Root/daemon/credential helper가 필요하다는 증거는 없으나 그 부재도 실행 시험으로 입증하지 않았다. 이 검증 공백과 큰 native image 때문에 PyPI wheel 후보보다 더 좁고 투명한 공급망이라고 볼 수 없다.

## 실행 계획이었으나 시행하지 않은 격리·규칙

계획한 container 옵션은 `--network none`, `--read-only`, `--cap-drop ALL`, `--security-opt no-new-privileges`, memory/CPU/PID 상한, 최소 tmpfs, 저장소 read-only bind, nonroot UID, host home/SSH/credential/Docker socket 비마운트였다. Semgrep 옵션은 추적 local rule 경로, `--metrics=off`, `--disable-version-check`, `--oss-only`였으며 Registry·Cloud·login은 금지였다. **실제 `docker run`을 하지 않았으므로 격리, 네트워크 0건, output byte/timeout, exit-code 분류는 NOT_TESTED**다.

[Phase 23.2 후보](semgrep_security_gate_23_2.md) 네 규칙 — A DOM HTML sink, B browser storage write, C Python `subprocess`의 `shell=True`, D HTTP exception 원문 노출 — 의 should-match/should-not-match 설계는 유지한다. 그러나 Semgrep에서 rule syntax·양성/음성 fixture·repository finding을 검증하지 못했으므로 **실행 가능한 local rule/config나 fixture를 추적하지 않았다**. 현재 `app/`/`frontend/` 직접 문자열 audit의 0건은 Semgrep baseline이 아니다. 실제 보안 finding이나 production bug가 확인되지 않았으므로 production/API/schema/분석 의미는 수정하지 않았다. 기존 pytest canary, Node UI 동작, Hypothesis property가 현재 예방 경계다.

## 개인정보·성능·정리

저장소, 사용자 홈, 실제 로그, 기본 monitor config, checkpoint, `.env`, credential을 image에 mount하거나 전달하지 않았다. CLI가 source를 읽지 않았으므로 Semgrep JSON/SARIF, finding snippet, stdout/stderr scan 결과도 생성되지 않았다. 민감정보 유출 **검사 대상 출력 자체가 없었음**을 privacy PASS와 혼동하지 않는다. Docker registry로 image 취득 네트워크는 있었지만 scan 네트워크는 발생하지 않았다. Container/volume/전용 임시 output은 생성하지 않았다. Pull 전 `semgrep/` image가 없음을 확인했고, inspection 뒤 정확히 pull한 arm64 digest만 `docker image rm`으로 제거했다. 이는 Docker layer cache, registry, filesystem snapshot의 secure erase를 보증하지 않는다. 원격 amd64 manifest는 pull하지 않았다. Codex MCP/skill/config 및 project dependency/lockfile/CI workflow는 변경하지 않았다.

Rule test, repository scan, cold/warm median/p95/max, target file count, finding 결정성은 모두 **NOT_TESTED**이며 목표 +10초는 여전히 후보 gate일 뿐이다. macOS Docker metadata 검사와 Ubuntu CI의 일반 pytest를 혼동하지 않는다. CI에 Semgrep 단계를 넣지 않는다.

## 재개 조건

이 결과는 Semgrep 사용 자체의 영구 NO-GO가 아니라 **이번 공식 Docker image 경로의 공급망 차단**이다. 다음 선택지는 별도 승인 아래 공개 OSS source와 정확히 연결되는 minimal/OSS-only image 또는 wheel artifact의 서명·SBOM·native executable·전이 dependency·build provenance를 독립 확인하는 것이다. 그 전에는 image를 재실행하거나 다른 mutable tag로 우회하지 않는다. 공급망 gate가 통과하면 별도 단계에서 한 파일씩 local rule/fixture를 구현하고 bounded offline container에서 scan, 출력 canary, 정확도·성능·Ubuntu 재현을 측정해야 한다. 기존 pytest를 대체하거나 Semgrep을 production dependency/필수 CI로 추가하지 않는다.
