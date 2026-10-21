# Phase 31.1 — PentAGI v2.2.0 정적 공급망·라이선스 감사

## 범위와 판정

조사일 2026-10-21. 기준 저장소 commit `1fc5e424caf95633b643c2f029766b3c5837c580`의 [CI run 39611980896](https://github.com/misosos/ai-security-log-analyzer/actions/runs/39611980896)은 정확한 SHA에서 completed/success였다. Ubuntu 통합 관리, 전체 pytest, locked 설치, Node·axe가 성공했고 artifact는 0개다. 변경 전 전체 pytest는 **2424 passed, 기존 경고 2개**였다. [31.0 설계](pentagi_evaluation_pilot_31_0.md)의 단일 합성 SSH 범위와 금지 사항을 유지한다.

**Phase 31.2 실행형 isolation proof: NO-GO.** Source와 일부 image metadata는 정적으로 확인했지만, v2.2.0에 고정된 공식 installer asset·checksum이 없고, 기본 Compose는 host Docker socket을 control plane에 직접 mount한다. Callback·egress 차단과 runtime image/tool download 통제, 저장 경계·모든 구성요소 라이선스는 실행 환경에서 아직 검증되지 않았다. 정적 감사 결과를 실행 안전성 PASS로 표현하지 않는다. PentAGI installer·container·Compose·penetration-testing tool을 실행하지 않았고 Docker socket을 mount하지 않았다. LLM/search 연결이나 대상 스캔도 하지 않았다. Production·dependency·lockfile·CI는 변경하지 않았다.

## v2.2.0 release identity와 source archive

공식 [`vxcontrol/pentagi` v2.2.0 Release](https://github.com/vxcontrol/pentagi/releases/tag/v2.2.0)는 2026-10-05 게시, draft=false, prerelease=false다. `refs/tags/v2.2.0`은 **lightweight tag**여서 별도 annotated tag object는 없으며 peeled source commit과 ref object가 모두 `b611fbebcf55b6deb88ad1fb7bf1f1ce7a357242`다. Commit tree는 `f3fb014f5d3e48d54f3a1dadff50eb40e5c3879e`이고 GitHub는 commit signature를 verified로 표시한다. 이는 source archive·container image의 독립 서명을 뜻하지 않는다. Release의 별도 업로드 asset은 **0개**다.

Release note는 [CVE-2026-14784](https://github.com/vxcontrol/pentagi/releases/tag/v2.2.0) 관련 sandbox 격리 수정, nested Docker 기본값 변경, unified `web_search`, multi-instance, provider 확장, 세션·의존성 보안 수정, 재로그인·DB migration 등의 upgrade 영향을 명시한다. 특히 `DOCKER_INSIDE=false` 기본값과 별도 daemon 요구는 **worker sandbox**의 host socket 자동 mount 문제에 관한 설명이다. [v2.2.0 Compose](https://github.com/vxcontrol/pentagi/blob/v2.2.0/docker-compose.yml)의 **control plane `pentagi` 서비스**는 여전히 host Docker socket을 기본 mount한다. Tag 이후 `main` 문서나 mutable installer 설명을 v2.2.0의 고정 사실로 간주하지 않는다.

공식 GitHub tarball `https://api.github.com/repos/vxcontrol/pentagi/tarball/v2.2.0`을 전용 private 임시 디렉터리로 내려받아 **실행 없이** 검사했다. 다운로드 byte 수 **52,672,094**, 관찰 SHA-256 `43050f8507659707b54bb62387ca8163752df8eecfeba4c5f861590f119f787b`다. GitHub 자동 생성 archive의 공식 별도 checksum은 확인되지 않았다. 따라서 이 hash는 이번 응답의 식별자이지 재생성 시 byte-for-byte 재현을 보장하는 공식 서명이 아니다. 공식 v2.2.0 tag tree에서 mode `160000` submodule entry는 0개다. Archive 최상위 이름은 `vxcontrol-pentagi-b611fbe`; 1,977 entry 중 일반 파일 1,715개, 비압축 일반 파일 합계 103,571,087 byte였다. Path traversal 0, hardlink 0, setuid/setgid 0, symlink 13개이며 symlink target은 모두 archive root 안에 있다. 일반 파일만 private 위치에 복사하고 symlink는 추출하지 않았다. `Dockerfile`, 기본 Compose, LICENSE, NOTICE, EULA, CI workflow의 Git blob SHA는 공식 tag tree와 **6/6 일치**했다.

Executable mode file은 19개다. 대부분 shell/build helper이지만 `observability/jaeger/bin/`에 **정적 링크된 Linux ELF 2개**(amd64 28,795,924 byte, arm64 27,780,344 byte)가 source archive에 포함된다. 이 둘은 첫 pilot에서 제외할 optional observability 자산이다. Extension 기준 `.so/.dll/.dylib/.exe/.a/.o/.wasm` 파일은 0개였고, credential·private-key 형태의 파일명은 0개였다. 이는 파일 내용의 비밀 부재나 binary의 무해성을 증명하지 않는다. Source에는 `Dockerfile`, Compose 5개, Go/Node manifest, install/build script, GitHub workflow, installer Go source가 있다. `Dockerfile`은 Node·Go build stage와 Alpine final stage, package manager 설치를 포함한다. Runtime source에는 Docker `ImagePull` 및 installer image pull 경로가 있다. Source 코드·스크립트 범위의 단순 `curl|sh`/`wget|bash` 패턴은 0건이었으나 간접 실행·외부 도구 내부 동작까지 배제하지 못한다. URL literal은 docs/test/example을 포함하면 341종 host가 추출되므로 이를 실제 runtime 연결 목록으로 취급하지 않는다. Runtime 주요 endpoint는 아래 데이터 흐름 표에서 따로 분류한다.

## Installer artifact — UNVERIFIED_ARTIFACT

v2.2.0 GitHub Release에 macOS arm64, Linux amd64/arm64 **업로드 installer asset이 없다**. [공식 Quick Start](https://pentagi.com/docs/getting-started/quickstart/)는 플랫폼별 `installer-latest.zip`을 안내하지만 이는 버전 고정 URL이 아니며 v2.2.0 byte 내용·checksum을 증명하지 않는다. 이 mutable installer를 내려받거나 실행하지 않았다. 따라서 asset 이름·크기·SHA-256, 공식 checksum, signature/notarization/provenance, archive 내용, 실행 파일 형식·연결 library, embedded URL/command, 실제 생성 파일·권한은 **미검증**이다. macOS signed/notarized라는 현재 문서 설명을 Linux artifact의 증거로 전용하지 않는다. [tag 고정 installer source](https://github.com/vxcontrol/pentagi/tree/v2.2.0/backend/cmd/installer)는 `.env` 생성·수정, Compose·config 파일 배치, Docker API/image pull, update service 연동 경로를 보이지만 배포 executable과의 byte 대응은 미증명이다. Installer는 root/docker-group 권한과 Docker API 경계를 별도 검토해야 한다. 첫 pilot에서 installer 사용은 **NO-GO**다.

## Compose 권한·서비스 감사

아래 표는 tag 고정 [기본 Compose](https://github.com/vxcontrol/pentagi/blob/v2.2.0/docker-compose.yml), [Graphiti](https://github.com/vxcontrol/pentagi/blob/v2.2.0/docker-compose-graphiti.yml), [Langfuse](https://github.com/vxcontrol/pentagi/blob/v2.2.0/docker-compose-langfuse.yml), [observability](https://github.com/vxcontrol/pentagi/blob/v2.2.0/docker-compose-observability.yml), [e2e](https://github.com/vxcontrol/pentagi/blob/v2.2.0/docker-compose.e2e.yml)를 직접 YAML로 읽은 결과다. Compose 변수는 실제 `.env`와 override에 따라 달라진다. 모든 service의 `build`, `privileged`, `cap_add/drop`, `security_opt`, `network_mode`가 **미설정**이며 `restart: unless-stopped`는 e2e override를 제외한 기본값이다. 미설정을 제한 정책의 적용으로 해석하지 않는다. Docker image 자체의 config user/entrypoint는 다음 표와 별도로 확인했다.

| Stack / service | 기본 image·실행 권한 | Port·mount / state | 의존·비밀·첫 pilot |
|---|---|---|---|
| 기본 `pentagi` | `vxcontrol/pentagi:latest`; `root:root` | `127.0.0.1:8443`; data·SSL·Ollama writable volume, provider config/cert host mount, **`/var/run/docker.sock` host mount** | `pgvector` healthy 의존. Provider key·cookie salt·DB URL·search key·Docker 변수 env. Control plane 후보이나 현재 구성 NO-GO. |
| 기본 `pgvector` | `vxcontrol/pgvector:latest`; user 미설정 | `127.0.0.1:5432`; PostgreSQL named volume writable | DB user/password env, healthcheck. 필수 후보, digest·private secret·보존 검증 필요. |
| 기본 `pgexporter` | `quay.io/prometheuscommunity/postgres-exporter:v0.16.0`; user 미설정 | `127.0.0.1:9187`; mount 없음 | DB source DSN env, pgvector healthy 의존. 첫 pilot 제외 가능성 검증. |
| 기본 `scraper` | `vxcontrol/scraper:latest`; user 미설정 | `127.0.0.1:9443`; SSL named volume | username/password env. Web/browser 제외 pilot에서는 제거 후보, core dependency 검증 필요. |
| Graphiti `neo4j` | `neo4j:5.26.2`; user 미설정 | loopback 7474/7687; data volume, local conf/plugin/log/import/metrics/SSL/backup host mount | NEO4J_AUTH, healthcheck. **제외**. |
| Graphiti `graphiti` | `vxcontrol/graphiti:latest`; user 미설정 | loopback 8000; config host mount `:ro` | Neo4j·LLM/embedding credentials. **제외**. |
| Langfuse `langfuse-worker` | `langfuse/langfuse-worker:3`; user 미설정 | host port 없음, direct volume 없음 | DB·S3·Redis·ClickHouse credentials, 네 서비스 의존. **제외**. |
| Langfuse `langfuse-web` | `langfuse/langfuse:3`; user 미설정 | loopback 4000, direct volume 없음 | 동일 secret + auth/session/init credentials. **제외**. |
| Langfuse `clickhouse` | `clickhouse/clickhouse-server:24`; user `101:101` | data·log named volumes | password env, healthcheck. **제외**. |
| Langfuse `minio` | `cgr.dev/chainguard/minio:latest`; user `0:0` | data named volume | root credential env, healthcheck; metadata 조회 오류. **제외**. |
| Langfuse `redis` | `redis:7`; user 미설정 | host port·volume 없음 | healthcheck. **제외**. |
| Langfuse `postgres` | `postgres:16`; user 미설정 | data named volume | DB password env, healthcheck. **제외**. |
| Observability `grafana` | `grafana/grafana:11.4.0`; user 미설정 | loopback 3000; config/dashboard host `:rw`, data volume | **제외**. |
| Observability `node-exporter` | `prom/node-exporter:v1.8.2`; user 미설정 | host `/proc`, `/sys`, `/` read-only mounts | `otel` 의존. Host visibility 때문에 **제외**. |
| Observability `cadvisor` | `gcr.io/cadvisor/cadvisor:v0.51.0`; user 미설정 | host `/`·`/sys`·Docker data, **`/var/run:rw`** | `otel` 의존. Host exposure 때문에 **제외**. |
| Observability `otel` | `otel/opentelemetry-collector-contrib:0.116.1`; user 미설정 | loopback 8148/4318; config host `:rw` | **제외**. |
| Observability `victoriametrics` | `victoriametrics/victoria-metrics:v1.108.1`; user 미설정 | data volume | **제외**. |
| Observability `clickstore` | `clickhouse/clickhouse-server:24`; user 미설정 | config host `:ro`, data volume | DB credential, healthcheck. **제외**. |
| Observability `loki` | `grafana/loki:3.3.2`; user 미설정 | config host `:ro` | **제외**. |
| Observability `jaeger` | `jaegertracing/all-in-one:1.56.0`; user 미설정 | Jaeger host directory `:rw` | clickstore healthy 의존. **제외**. |
| E2E `mock-llm` | `node:24-alpine`; user 미설정 | test source host `:ro` | e2e 전용, **제외**. |
| E2E `pentagi`·`pgvector` override | 기본 image 상속 | local config mount·mock endpoint | 제품 첫 pilot 구성이 아니므로 **제외**. |

기본 Compose의 root·socket·writable volumes에 `read_only`, `no-new-privileges`, capability drop, PID/CPU/memory/disk cap이 없다. [보안 문서](https://pentagi.com/docs/configuration/security/)의 sandbox callback `28000–29999`는 Compose의 UI port 목록과 별도로 runtime Docker API가 publish할 수 있고 기본 `DOCKER_PUBLIC_IP=0.0.0.0`이다. Docker publish가 host firewall을 우회할 수 있어 loopback UI만으로 비공개 상태를 증명하지 않는다. `host-gateway`/host network를 첫 pilot에서는 금지하되, 실제 sandbox 생성 설정·VM route를 실행 전 별도 검증해야 한다.

## Registry manifest·config 관찰

2026-10-21에 anonymous registry API로 manifest·config blob을 조회하고 아래에서 명시한 정확한 v2.2.0 amd64 image layer만 별도로 정적 검사했다. Local Docker daemon에 접근하거나 image를 pull하지 않았다. 아래 digest는 조회 시점 관찰값이며, 특히 `latest`, `:3`, `:24`, `:7`, `:16` 등 mutable tag의 향후 값을 보장하지 않는다. `linux/amd64`는 Intel macOS Docker Desktop의 일반 선택, `linux/arm64`는 Apple Silicon의 일반 선택 후보이나 실제 Desktop 설정·platform override에 따라 달라진다. 압축 layer byte 합은 unpacked disk 사용량이 아니다. `cgr.dev/chainguard/minio:latest`는 registry API HTTP 400으로 metadata 미확인이다. 이 optional service는 첫 pilot에서 제외한다. Attestation descriptor 개수는 index metadata의 구조만 뜻하며 서명·내용·SBOM 유효성 증명이 아니다. Manifest digest가 조회돼도 실행·license 승인으로 이어지지 않는다.

| Default image reference | Index digest | linux/amd64 digest | linux/arm64 digest | amd64 created / layers / compressed MB | Config user; entrypoint / cmd; ports; env·label key count | Attestation descriptor 수 |
|---|---|---|---|---|---|---|
| `vxcontrol/pentagi:latest` | `sha256:0d58d71a6ac4128ec5c4e594952a516f08a3cb44c28f51feb68b09569e4d54f8` | `sha256:9e3c5be99444f347ae9dabcc92ab188aaaf0599509b56f543eec08393410bf07` | `sha256:d6cbaae84459c69ac7ce55cdc7c222a00e81622076576a77fc6aeb6fc228ca76` | 2026-10-09; 48 / 277.8 | pentagi; /opt/pentagi/bin/entrypoint.sh,/opt/pentagi/bin/pentagi / —; —; 1·10 | 2 |
| `vxcontrol/pgvector:latest` | `sha256:09afd689127bdb42319a133b2ef7cd4318b7ebda58412644975d6eacd2367fb0` | `sha256:b94c536d5e326512ee4973a7844745aa57abc8cf77588eb3045e3d757a6390c7` | `sha256:841d51ebcf46f4e98e15affc466f37be5492592863f04b6b4f479619938eb07a` | 2024-06-25; 17 / 154.1 | 미지정; docker-entrypoint.sh / postgres; 5432/tcp; 6·0 | 2 |
| `quay.io/prometheuscommunity/postgres-exporter:v0.16.0` | `sha256:6999a7657e2f2fb0ca6ebf417213eebf6dc7d21b30708c622f6fcb11183a2bb0` | `sha256:fe38515ba4d00fe9b4e83bc53e7ea38e1eb451d415c5447454ae1a3e043ff13d` | `sha256:3177aadc52924ee36abaa4339c715c34f53729ee7b782485caee179a46483cc4` | 2024-11-10; 3 / 11.1 | nobody; /bin/postgres_exporter / —; 9187/tcp; 1·1 | 0 |
| `vxcontrol/scraper:latest` | `sha256:4a3b0f179ab29003313167877ee2f6ab74c89f3fcb1ce108e648ca1ffadc51b7` | `sha256:b5c09a0047909335bc46004fc63e4a4a535f5cee517e3933e20a2d190ae4a74f` | `sha256:5ae7576252304053ad20e2f1359a90af543b855aa799253f43419cedf8e959e3` | 2024-10-15; 23 / 1306.1 | blessuser; — / sh,-c,/usr/local/bin/entrypoint.sh /usr/local/bin/scraper & ./start.sh &…; 3000/tcp,443/tcp; 21·2 | 2 |
| `neo4j:5.26.2` | `sha256:099b9f74968c123209972835417985ed2a1cc19c0422c0753a313e26a736c365` | `sha256:4c303612beef27013ad6cbb9d18b7911d2288f0aea9eb8e9fde8acc78a19e1ec` | `sha256:a731d66b956a4155333eb09badfb3b17ad51d1aedaaf2c1530e24fd24e5559a9` | 2025-02-05; 6 / 338.1 | 미지정; tini,-g,--,/startup/docker-entrypoint.sh / neo4j; 7473/tcp,7474/tcp,7687/tcp; 7·0 | 2 |
| `vxcontrol/graphiti:latest` | `sha256:43de1d966e0d1f9ea038b17915bc8a9e8d667411847591f6b949804f2f8a33fe` | `sha256:b5bb38ad62888f8247826257736ff9b264fb4c8cf28642ddf1c13b83bf05f299` | `sha256:de9817245de0c74e945650f37f5c92444a5414f700b0a1abfabfa30d80db6d95` | 2026-10-18; 19 / 208.5 | app; — / sh,-c,exec uvicorn graph_service.main:app --host 0.0.0.0 --port ${PORT}; 8000/tcp; 12·0 | 0 |
| `langfuse/langfuse-worker:3` | `sha256:8a28c946bb5401eef488153fa294db5a79bd99dd5c90db8e4d39559374c9ebd3` | `sha256:1cc3adfecde5d2170707da5719d74e38eb335cc527408cb5b2459e88ba9d97df` | `sha256:6b8349e2d6d3fb380be5cb74ba3dee40e55346e2574dfcbf9694c8c809e3084a` | 2026-09-24; 12 / 337.0 | expressjs; dumb-init,--,./worker/entrypoint.sh / node,worker/dist/index.js; 3030/tcp; 7·8 | 0 |
| `langfuse/langfuse:3` | `sha256:a343f64e035eb01aeea358703a0428945d909d01e19452509a5a830862dda878` | `sha256:919ce3d2c4c2a84d0217b779d0f50063055367be48bfcc9d9e1400329e38c9c1` | `sha256:fba6a7ebbda3f5448c81647cdd1aca207c48eed625b92373df677b9d05b7bb24` | 2026-09-24; 24 / 353.0 | nextjs; dumb-init,--,./web/entrypoint.sh / /bin/sh,-c,if [ -n "$NEXT_PUBLIC_LANGFUSE_CLOUD_REGION" ]; then     node…; —; 10·8 | 0 |
| `clickhouse/clickhouse-server:24` | `sha256:2113951827761e37c386b37f716dbdf8522b9172488a44b97a96fe6059e172a8` | `sha256:daf89d208ec3c67eefb11f3c674af52035ab8d25343ff8bf211f671a3f63773c` | `sha256:27782bdeac78627e7ff949b71abc997a411498b9334ad0d10d76718598cda46d` | 2024-11-19; 11 / 180.6 | 미지정; /entrypoint.sh / —; 8123/tcp,9000/tcp,9009/tcp; 4·5 | 2 |
| `cgr.dev/chainguard/minio:latest` | **미확인: HTTP 400** | 미확인 | 미확인 | — | Optional, 첫 pilot 제외 | 미확인 |
| `redis:7` | `sha256:44960b3100c48159a66d28c18b0588c193492e25f7551d60e51dd464fc3eca5b` | `sha256:026c880268ce52fb3a63b66150af583108a38c13af7633e325ae82a145f53a87` | `sha256:617bd2a7a36d215e3e0c61353a17cb5c856b192664e774455ef8023a60bee6ac` | 2026-10-21; 7 / 43.6 | 미지정; docker-entrypoint.sh / redis-server; 6379/tcp; 2·0 | 5 |
| `postgres:16` | `sha256:a902560563d3a5661228585f53474c5065e7f273b21ffd77e555a8b5682c5690` | `sha256:f9d1e581cde3e4c8bc696b07e6f7b7aea1d41014b33a52b27990762daae61beb` | `sha256:d735d89e0f050dd5efa611ad633e44e06b526da77b04a7501cece311cd032375` | 2026-10-21; 14 / 160.3 | 미지정; docker-entrypoint.sh / postgres; 5432/tcp; 6·0 | 8 |
| `grafana/grafana:11.4.0` | `sha256:d8ea37798ccc41061a62ab080f2676dda6bf7815558499f901bdb0f533a456fb` | `sha256:8d938a1c52b018c60cb3583657e038054387aa18a74f09a865c99a522481f7ac` | `sha256:4e07c49573f2a13f25cf92a11f970a2bb2a700eb63cc48f38d62fef62728d530` | 2024-12-04; 10 / 132.8 | 472; /run.sh / —; 3000/tcp; 7·1 | 0 |
| `prom/node-exporter:v1.8.2` | `sha256:4032c6d5bfd752342c3e631c2f1de93ba6b86c41db6b167b9a35372c139e7706` | `sha256:065914c03336590ebed517e7df38520f0efb44465fde4123c3f6b7328f5a9396` | `sha256:1eabab826c9d9f0c534e4e8fa745445f743fef9aee276d561d12811edea74004` | 2024-07-14; 3 / 12.0 | nobody; /bin/node_exporter / —; 9100/tcp; 1·1 | 0 |
| `gcr.io/cadvisor/cadvisor:v0.51.0` | `sha256:771a65c7877817cd9bb4c2d9eecb9fd1ac56f370287617658c51a35061efa71a` | `sha256:ffbcdce30b2d737e589c7d58cd37c0794ac0fc1448f61435a5ce81852240b9d7` | `sha256:905086cff84ead5ae05378b5476bde089ccd01fddee6d109d744a5383fdec908` | 2024-10-30; 5 / 32.6 | 미지정; /usr/bin/cadvisor,-logtostderr / —; 8080/tcp; 2·0 | 0 |
| `otel/opentelemetry-collector-contrib:0.116.1` | `sha256:d0ebf65280da2e1b1491d1b93648281afd353d4b9ea19160090303cec9a233bd` | `sha256:13e54470e044523d723d512be7f83d7187770e1784a3a8745232fd022843fad2` | `sha256:52ea63650b516bd83843bfac485c104ef598f6ad0765656f7fe5b77f066d34ce` | 2024-12-17; 3 / 74.3 | 10001; /otelcol-contrib / --config,/etc/otelcol-contrib/config.yaml; 4317/tcp,4318/tcp,55678/tcp,55679/tcp; 1·6 | 0 |
| `victoriametrics/victoria-metrics:v1.108.1` | `sha256:f6e5322b315795ae2fec494c1d1c94b2e0325b789fead60ef3a13fccdefcd81e` | `sha256:70e3cba3f7d481f0b9dcb4a89e7b7c91d930daff112564d347f8beb5cfe4f473` | `sha256:67f29e7c58f9566f67ebcfcf1c0b6705e6f5aaea5bd2a2da86cd295ab9ee56e3` | 2024-12-18; 3 / 16.5 | 미지정; /victoria-metrics-prod / —; 8428/tcp; 1·0 | 0 |
| `grafana/loki:3.3.2` | `sha256:8af2de1abbdd7aa92b27c9bcc96f0f4140c9096b507c77921ffddf1c6ad6c48f` | `sha256:e9d0a18363c9c3022aef6793a7e135000d11127fb0e18b89de08b1e21e629d60` | `sha256:133d7dd2d203340ad81f117ea8d515ea090c66fa334b2a99a88b14dd034c656b` | 2024-12-18; 16 / 33.2 | 10001; /usr/bin/loki / -config.file=/etc/loki/local-config.yaml; 3100/tcp; 2·0 | 0 |
| `jaegertracing/all-in-one:1.56.0` | `sha256:d2cd4c226624bdc116decd3106091b4df9882da8db42f8550293596cab79b8ea` | `sha256:f421219dbd77248301fc42ac6e8ba5026f4bada9448ab33ac89061e21cfe3fea` | `sha256:e8ace4e075d847aa71b955ffdcb6dfdfd28fa1ad0a286ce257bf278c6da960ca` | 2024-04-03; 5 / 34.3 | 10001; /go/bin/all-in-one-linux / —; 14250/tcp,14268/tcp,16686/tcp,4317/tcp,4318/tcp,5775/udp,5778/tcp,6831/udp,6832/udp,9411/tcp; 2·0 | 4 |
| `node:24-alpine` | `sha256:44fce696f38ba8c987c4db89954051000bbd05ffd8d8659ba15ed4a8602e937f` | `sha256:429bdfbc204b4eabc6438e6d34e4e9d8dd2ca1df8289bcd78cdd3c5db387b7a5` | `sha256:5b12456322560dcf9342f7339662bccf8c5665cf0732a8ec8363687aa93c5277` | 2026-10-14; 4 / 62.4 | 미지정; docker-entrypoint.sh / node; —; 3·0 | 3 |
| `vxcontrol/pentagi:2.2.0` | `sha256:64bd1802799142a12bc5eb23c15a1ccc50d3476736d3d2a98a9b773910283a1e` | `sha256:00e7510f54762377dcb2bfb05b9df8404d5e012104a6e7ad4c00d735610be2b9` | `sha256:3c8d8a67a5539d16a487264a24712c57790a692d7e2c8f937e3dfc89b1b92bf1` | 2026-10-05; 48 / 277.7 | pentagi; /opt/pentagi/bin/entrypoint.sh,/opt/pentagi/bin/pentagi / —; —; 1·10 | 2 |
| `vxcontrol/kali-linux:latest` | `sha256:7f803e5be80ec33dcf4228d9702ea1264658b43301e9d6bf3bce6cf8b1077399` | `sha256:d8eec83f505fe633eea996955d2458ac2b38a1506b9a7a554603651005455bee` | `sha256:7dc3cde74bb0d7dbc37ae274f315b64a6fa2d1fbfbb3c3537d06f90807aaf078` | 2026-09-29; 11 / 6026.7 | 미지정; — / /bin/bash; —; 5·14 | 2 |
| `vxcontrol/kali-linux:test` | `sha256:2ec4b178bc232dd264a166db1593bfa44dd792077119b72430ce28079b1fa0bc` | `sha256:ea8b0d0138649ab366d8d5c2d3cd7a21b9fca25ab07d1d6fb2085d2ac193ccbf` | `sha256:18fb854ab4a3c8ac5da27ee532b384edcb10162c20e079d3d7ca8061f52d9bd9` | 2026-09-29; 4 / 74.6 | 미지정; — / /bin/bash; —; 2·14 | 2 |
| `debian:latest` | `sha256:4c25275446ca371766b8b093c696782eabce06263fccacb8d5d813b3dc44b308` | `sha256:15a71cc87173e191d5046f9c4288db4e8954b67f92e48d9587087826b0afe562` | `sha256:0daf3052d9359adaa0de63035b87949cc6c7966bfd6d60746d318ee1999f5edb` | 2026-10-20; 1 / 49.4 | 미지정; — / bash; —; 1·0 | 8 |

`vxcontrol/pentagi:latest`의 관찰 image revision은 `843dfeb4bfc809c09d1bc5022e567c602d8fc9dd`로 v2.2.0 source commit과 **다르다**. v2.2.0 후보는 별도 `vxcontrol/pentagi:2.2.0` index `sha256:64bd1802799142a12bc5eb23c15a1ccc50d3476736d3d2a98a9b773910283a1e`, amd64 `sha256:00e7510f54762377dcb2bfb05b9df8404d5e012104a6e7ad4c00d735610be2b9`, arm64 `sha256:3c8d8a67a5539d16a487264a24712c57790a692d7e2c8f937e3dfc89b1b92bf1`로 식별했다. Config created는 2026-10-05T07:13:12Z, user `pentagi`, entrypoint는 `/opt/pentagi/bin/entrypoint.sh`→`/opt/pentagi/bin/pentagi`, config revision label은 예상 source commit과 일치한다. 그러나 Compose `user: root:root` override가 있어 실제 기본 service의 user는 root다. Image config 환경변수 **값**과 raw manifest/SBOM은 저장소에 기록하지 않는다. Registry API의 SBOM·provenance 조회는 아래 별도 판정한다.

## Image layer와 source-image 대응

`vxcontrol/pentagi:2.2.0`의 **linux/amd64** platform digest에서 48개 gzip layer, 압축 합계 **277,695,361 byte**를 registry blob으로 읽어 각 SHA-256을 검증하고 tar header·실행 파일 magic만 정적 검사했다. Blob을 Docker daemon이나 cache로 보내지 않고 메모리에서 처리했다. 관찰 entry 1,553개, 일반 파일 683개, symlink 589개, hardlink 0개, tar 오류 0개다. Layer에는 setuid/setgid 표시 8개 entry가 있으며 이 중 1개는 디렉터리(`home/pentagi`), 7개는 `chage`·`chfn`·`chsh`·`expiry`·`gpasswd`·`passwd`·`unix_chkpwd` 실행 파일이다. 실행 가능한 ELF magic 파일은 106개로 관찰됐다. Alpine `apk`·shell 2개·`wget` 1개는 있고 Docker CLI 및 이름으로 식별되는 `nmap`·Metasploit·`sqlmap`·`hydra`는 core image layer에서 발견되지 않았다. 이 부재는 runtime sandbox Kali image나 다른 이름의 도구가 없다는 뜻이 아니다. `LICENSE`·`NOTICE`·`EULA`와 entrypoint script는 관찰됐다. Private-key/credential 형태의 **파일명**은 0개였지만 CA certificate로 보이는 path가 다수 있으며 내용 비밀 검사는 완료되지 않았다. Layer별 항목은 whiteout·최종 합성 filesystem을 고려하지 않은 raw 관찰이고, arm64 layer는 내려받지 않았다. Setuid 항목의 최종 보존 여부와 writable 디렉터리·debug listener는 실행 전 검토 과제다. 악성 여부를 단정하지 않는다.

Tag 고정 [Dockerfile](https://github.com/vxcontrol/pentagi/blob/v2.2.0/Dockerfile)은 Node·Go builder 뒤 Alpine runtime에 app binary, frontend, license/NOTICE/EULA를 복사한다. Registry config는 version `2.2.0-ce`, source revision `b611...`을 선언한다. [tag 고정 build workflow](https://github.com/vxcontrol/pentagi/blob/v2.2.0/.github/workflows/ci.yml)는 `provenance: true`, `sbom: true`를 지정한다. `2.2.0` image index에는 amd64·arm64 platform manifest와 각각 연결된 attestation manifest가 있다. amd64 attestation의 SPDX-2.3 문서에는 package 563개·file 305개·relationship 2,003개가 있으나 package licenseDeclared 중 **534개가 NOASSERTION**이다. SLSA provenance v1의 subject는 amd64 digest와 일치하며 builder URL은 [tag push workflow run 37275280604](https://github.com/vxcontrol/pentagi/actions/runs/37275280604)를 가리킨다. 해당 run의 head SHA는 v2.2.0 commit이고 success다. Provenance는 Dockerfile과 Alpine 3.23.5·Go 1.26-bookworm·Node 24.17.0-slim base image digest를 열거하지만 source context commit/digest를 직접 포함하지 않는다. Attestation의 서명·발행자 신뢰 체인과 재현 build도 검증하지 않았다. **SOURCE_IMAGE_BINDING_UNPROVEN**을 유지한다. Workflow 성공이나 OCI label만으로 image byte가 source commit에서 재현됐다고 주장하지 않는다.

## 라이선스·사용 조건

Tag 고정 [LICENSE](https://github.com/vxcontrol/pentagi/blob/v2.2.0/LICENSE)는 PentAGI source MIT이고, copyright/license notice 보존이 필요하다. [EULA](https://github.com/vxcontrol/pentagi/blob/v2.2.0/EULA.md)는 승인된 합법적 penetration testing/research 목적, prebuilt image와 web UI 조건, 제3자 서비스 책임을 다룬다. Source MIT와 EULA의 재배포 문구 관계는 별도 검토가 필요하다. [NOTICE](https://github.com/vxcontrol/pentagi/blob/v2.2.0/NOTICE)의 VXControl Cloud SDK AGPL-3.0 특별 예외는 **공식 PentAGI 프로젝트**에 한정된다. 예외를 우리 프로젝트·fork·복사 코드로 이전할 수 있다고 가정하지 않는다. 이는 법률 자문이 아니다.

| 구성요소 | 관찰한 조건 | 잔여 검토 |
|---|---|---|
| PentAGI source / EULA / NOTICE | MIT notice와 별도 EULA; Cloud SDK official-project-only 예외 | Fork·재배포·출력물 조건을 version별로 검토. |
| Frontend asset | Tag의 `frontend/public/fonts/LICENSE-Apache-2.0.txt` 등 별도 notice 존재 | 전체 asset attribution과 bundled package별 license 확인. |
| Bundled binary·base image | Archive Jaeger ELF 2개; Dockerfile Alpine/Node/Go stage | ELF 출처·base image license, build 산출물 license 확인. |
| PostgreSQL/pgvector·exporter | [PostgreSQL License](https://www.postgresql.org/about/licence/), [pgvector PostgreSQL License](https://github.com/pgvector/pgvector/blob/master/LICENSE); exporter는 별도 구성요소 | PentAGI MIT로 포괄하지 않음. 실제 image package별 license는 미검증. |
| Neo4j·Graphiti / Langfuse / observability | Optional stack마다 독립 license와 telemetry. [Neo4j Community GPLv3](https://neo4j.com/legal-terms/), [Grafana licensing](https://github.com/grafana/grafana/blob/main/LICENSING.md), [Loki licensing](https://github.com/grafana/loki/blob/main/LICENSING.md) 참고 | 첫 pilot 제외. Edition·tag별 실제 image license와 재배포 조건은 별도 감사. |
| Pentesting tool / runtime download | Kali·기타 도구가 별도 image 또는 동적 pull | 각 도구 license·배포 조건, runtime 고정 필요. |

| 활용 방식 | 판정 |
|---|---|
| 별도 개발 도구 실행·합성 로그 생성·내부 평가 | **조건부 후보**. 승인된 합성 대상, EULA, 격리·공급망 gate 후에만. |
| 정제 합성 fixture 커밋 | **조건부 후보**. 개인정보·명령·payload·출력 권리 별도 심사. |
| Raw PentAGI report 커밋 | **NO-GO**. Prompt·명령·대상·secret·제3자 자료 가능성. |
| Source 일부 복사·image 재배포 | **이번 범위 NO-GO**. MIT notice와 EULA/SDK/전이 license 분리 검토. |
| Production dependency·사용자 기능 | **NO-GO**. 현재 제품·안전 계약에 포함하지 않음. |

## 네트워크·credential·저장 경계

| 경로·endpoint | 기본 활성·비활성·첫 pilot | 전송·credential·차단 시 동작 |
|---|---|---|
| Docker Hub·Quay·Chainguard·GCR 등 image registry | Image pull 때 필요; 사전 digest 고정·반입 후 runtime deny. | Image/ref 및 호스트 정보; 차단 시 미반입 image 시작 실패. |
| `update.pentagi.com`·support endpoint | Server check 주기 0 설정 후보; installer 통신은 별도. 첫 pilot 불필요. | Version·installation/stack 정보 가능; 차단 시 update/support 기능 실패 여부 검증. |
| LLM·embedding provider | 실제 flow에 최소 1 provider 필요. Cloud 보류, local endpoint만 미래 후보. | Prompt·tool output·target·API key 가능; 차단 시 flow 실패를 기대. |
| Search·browser·scraper | Source에 여러 search provider와 internal `web_search`; 첫 pilot 제외. | Query·URL·page, provider key·scraper auth 가능; 차단 시 search 실패·fallback 여부 검증. |
| Telemetry·Langfuse·OTEL·Grafana/Loki/Jaeger | Optional stack off, `OTEL_HOST` 미설정 후보. | Trace·prompt·terminal·flow metadata 가능; 비활성 후에도 base DB/log 확인 필요. |
| Sandbox callback | Runtime Docker publish, 기본 범위 28000–29999·all-interface 위험. 첫 pilot host publish 금지. | 대상이 접속 가능하면 외부 노출; 미공개 구성 불가 시 NO-GO. |
| Package manager·tool download | Dockerfile build와 installer·sandbox runtime pull 경로 존재. 첫 pilot runtime deny. | Registry/패키지 URL·tool list; 차단 시 tool 기능 실패가 명시돼야 함. |
| PostgreSQL/pgvector | 기본 필수, 내부 network만. | Flow·tool·memory·vector와 DB credential; 차단 시 app 기능 실패. |
| Local UI/API | 기본 127.0.0.1:8443, control plane 후보. | Cookie·session·설정; host 공개 금지. |

31.2 allowlist 초안은 disposable VM 내부 `pentagi→pgvector`, 필요한 경우 `pentagi→고정 local LLM`, control plane→고정 synthetic SSH target만이다. `pgexporter`·scraper가 필수인지 source 경로로 재확인해야 한다. Denylist는 인터넷·임의 DNS, host gateway, LAN/VPN, metadata address, public callback, cloud LLM·search·telemetry, runtime registry/package manager다. Network deny만으로 Docker API 권한을 제한하지 못한다.

| 자료 | 생성·저장 후보와 보존·삭제 계약 | 미해결 위험 |
|---|---|---|
| `.env`·provider API key·DB password·cookie salt·default credential | Installer/수동 설정 파일과 Compose env; 첫 pilot 실제 key 금지, private 권한·수명 관리 필수. 기본 DB credential 예시가 source에 있어 그대로 사용 금지. | Process env, Compose inspect, shell history, backup. |
| Generated TLS certificate·Ollama key | `pentagi-ssl`·`pentagi-ollama` volume 및 entrypoint 생성; 첫 pilot의 필요성 검토. | Private key·CA 임시 파일, volume snapshot. |
| Uploaded file·screenshot·terminal output·prompt/response·report | App data volume, PostgreSQL/pgvector, Docker log 또는 optional Langfuse/observability 후보. Raw 자료 반입·커밋 금지. | 구체 schema·파일 경로·로그 redaction은 미확인, 그래서 실행 blocker. |
| Vector memory·named volume | `pentagi-postgres-data`, `pentagi-data`, `scraper-ssl` 등; optional stack에는 추가 DB/object/log volume. | Container 종료 뒤 지속, backup/snapshot 잔존. |

첫 pilot에서는 합성 canary만 쓰며 volume·network·임시 디렉터리·listener 삭제 대상을 사전 명세해야 한다. Docker log·crash dump·backup/snapshot 잔존을 별도 감사하고 **secure erase를 주장하지 않는다**. 실제 credential은 생성하지 않았다.

## Phase 31.2 최소 후보와 hard stop

후보는 **disposable Linux VM 내부**의 수동 고정 Compose다. `vxcontrol/pentagi:2.2.0`을 포함해 필수 image를 platform별 digest로 고정하고, private SSH target network 및 VM 밖 egress deny를 둔다. Host network·실제 LAN/VPN route·callback host publish·실제 Docker socket 직접 mount는 금지한다. PentAGI가 Docker API를 필요로 한다면 별도 제한 daemon/worker proxy와 실제 정책 거부 test가 필요하며, 이를 구현·검증할 수 없으면 우회하지 않고 중단한다. Optional Neo4j/Graphiti, Langfuse, observability, search/browser를 제외한다. 실제 provider key는 없고 local LLM은 network proof에서는 연결하지 않는다. `read_only` 가능성, capability drop, `no-new-privileges`, CPU/RAM/PID/disk/time 상한, private volume·정리 순서를 설계하되 이 감사에서 작동 PASS로 표시하지 않는다.

다음 중 하나라도 남으면 **Phase 31.2 NO-GO**: installer/image digest 미확정, source-image binding 미증명, Docker socket 권한 제한 불가, callback 비공개 구성 불가, egress/host·LAN 차단 불가, runtime 추가 download 통제 불가, raw prompt·terminal·report 저장 위치 불명, provider 전송 비활성화 불가, cleanup 대상 불명, license/EULA 충돌, platform 지원 불명, resource budget 강제 불가. 현재 installer provenance·socket 권한·runtime download·저장 위치·격리 실측이 미해결이므로 **31.2로 진행하지 않는다**.

## 항목별 판정

| 항목 | 판정 |
|---|---|
| Source release identity | **PASS — 정적 식별**: lightweight v2.2.0 ref→예상 commit, key blob 6/6. |
| Installer artifact | **UNVERIFIED_ARTIFACT / NO-GO**: v2.2.0 release asset 0, mutable installer만 안내. |
| Image digest 고정 가능성 | **PARTIAL**: 조회된 core·runtime image는 platform digest 확인; optional Chainguard MinIO 미확인, mutable tag는 재현 기준 아님. |
| Source-image binding | **SOURCE_IMAGE_BINDING_UNPROVEN**: label·SLSA·workflow 연결 관찰, 서명·재현성 미검증. |
| Docker 권한 | **NO-GO**: 기본 control plane root+host socket mount. |
| Network 격리 가능성 | **NOT_TESTED**: VM/egress/callback proof 전. |
| 데이터·credential 경계 | **PARTIAL / NO-GO 실행**: Compose volume/env 확인, raw 저장 세부·삭제 경계 미확인. |
| License/EULA | **PARTIAL**: source MIT와 EULA·NOTICE 확인; SDK/전이 도구·image 재배포 조건 별도 검토. |
| Cleanup | **PASS — 감사 임시 자료에 한정**; Docker cache·container/volume/network는 생성하지 않음. 실행 후 cleanup은 미검증. |
| Phase 31.2 | **NO-GO 현재 구성**. 별도 blocker 해소·독립 승인 없이는 isolation proof를 실행하지 않는다. |
