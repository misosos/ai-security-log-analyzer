# Phase 24.0 — dependency·SBOM·vulnerability 검증 도구 선정 gate

판정: **CONDITIONAL GO — Phase 24.1의 검증 대상은 OSV-Scanner v2.7.0 한 개와 이미 사용 중인 uv 0.11.26의 CycloneDX export**다. 이 문서는 설계·공식 자료 조사 결과이며 OSV-Scanner, pip-audit, Syft, Grype, Trivy, CycloneDX Python, Dependabot action, CodeQL을 설치·실행하지 않았다. 도구를 production/dev dependency나 CI에 추가하지 않았고 현재 취약점 finding 0건을 주장하지 않는다. 특히 uv export의 CycloneDX 형식은 **preview**이며 runtime/dev 귀속·SBOM 결정성은 아직 미검증이다.

## 시작점과 현재 자산

시작 `main`/`origin/main`은 `56148be8ecd9abd77a7c01d6b447eba7535a6f4a`, clean·behind 0/ahead 0이었다. [해당 SHA의 Ubuntu CI](https://github.com/misosos/ai-security-log-analyzer/actions/runs/39101912404)는 completed/success다. `uv sync --dev --locked --no-build`, Phase 23.5 Schemathesis focused 및 전체 **2,276 passed, 기존 경고 2개**가 성공했다. Hypothesis property는 별도 CI step이 아니라 이 전체 회귀에 포함된다. 공개 v0.2.0 [Release](https://github.com/misosos/ai-security-log-analyzer/releases/tag/v0.2.0)는 정식·asset 0개이며 tag target은 `2520e317475f96d48b4bfeef8f7ee04d63720308`로 불변이다. 변경 전 로컬 전체 pytest도 2,276 passed, 동일 경고 2개였다. Phase 23.5는 이 Ubuntu 검증 범위에서 최종 **GO**다.

| 현재 자산 | 관찰된 계약 | 검증 범위 |
| --- | --- | --- |
| `pyproject.toml` | Python >=3.12, MIT, `0.2.0`; runtime 직접 6개: FastAPI, google-genai, pandas, python-dotenv, python-multipart, uvicorn; dev 직접 Hypothesis 6.170.0, pytest >=9.1.1, Schemathesis 4.31.1 | `google-genai`는 **runtime dependency**이나 외부 LLM 전송은 기능별 명시적 경계다. optional dependency group은 없다. dev와 runtime을 혼동하지 않는다. |
| `uv.lock` | project virtual source, runtime·`dev` edge, 전이 버전·artifact URL/hash·platform marker | lock은 설치 후보 전체이지 현재 macOS/Ubuntu 환경에 실제 설치된 wheel 목록 그 자체가 아니다. |
| `.github/workflows/ci.yml` | Ubuntu 24.04, Python 3.12.7, uv 0.11.26, `--locked --no-build`, checkout/setup-uv를 commit SHA로 pin, `permissions: contents: read` | artifact upload·write token·`pull_request_target` 없음. Actions 자체의 취약점·pinning 분석은 별도 계층. |
| frontend | `frontend/*.js`를 정적 제공하며 `package.json`·npm lock·Node runtime dependency 없음 | Node는 테스트 실행 도구다. REA npm tarball은 중단된 개발용 실험 자료이며 제품 npm 공급망이 아니다. |
| Docker | 제품 Dockerfile/image 없음 | REA·Semgrep 감사에서 기록한 digest는 **외부 개발용 도구 이미지**만의 근거다. 현재 제품 container/OS package scan을 주장하지 않는다. |
| 배포 | source checkout + locked uv 설치; 기존 flat-layout `uv build` 문제로 wheel/PyPI 배포 미지원 | SBOM은 checkout의 locked dependency inventory이지 배포 wheel의 구성목록이 아니다. |

현재 테스트는 Python·Node 구문/행동, lock 일치, 합성 평가를 다루지만 공개 취약점 DB의 신규 advisory를 조회하거나 검토 가능한 SBOM을 만들지는 않는다. 이것이 추가 가치다.

## 후보 공급망과 기능 비교

2026-10-18 기준 공식 repository/release/문서에서 확인했다. 아래 version은 조사 시점 최신 release 관찰값이며, **tag↔binary provenance 검증 완료**를 뜻하지 않는다. PyPI wheel/sdist 또는 native archive를 받는 pilot 전에 정확한 선택 artifact의 hash·서명·source 연계를 다시 검증한다. 모두 MIT 프로젝트와 라이선스 자체는 충돌하지 않는 Apache-2.0 또는 MIT이지만 라이선스 판정은 전이 구성요소와 실제 사용 형태를 따로 검토한다.

| 후보 | 공식 release·license·배포 | `uv.lock`/설치·dev 경계 | 주요 결과와 제한 |
| --- | --- | --- | --- |
| [PyPA pip-audit](https://github.com/pypa/pip-audit/releases/tag/v2.10.1) | 2.10.1, Apache-2.0, [PyPI](https://pypi.org/project/pip-audit/2.10.1/) wheel/sdist; Python >=3.10 | 설치 환경 또는 pinned requirements/PEP 751 `pylock.*.toml`; **`uv.lock` 직접 지원 근거 없음**. uv에서 그룹별 export 필요 | PyPI/OSV advisory, JSON·CycloneDX, exit code·ID ignore. 취약점 질의 시 package/version 외부 전송; 완전한 offline DB 계약은 확인되지 않음. `--fix`는 본 프로젝트에서 금지. |
| [OSV-Scanner](https://github.com/google/osv-scanner/releases/tag/v2.7.0) | 2.7.0, Apache-2.0, macOS arm64·Linux amd64 Go binary와 checksums·in-toto attestation | [공식 지원 목록](https://github.com/google/osv-scanner/blob/v2.7.0/docs/supported_languages_and_lockfiles.md)에 `uv.lock` 명시. `dev` group 출력·누락/중복은 실제 lock으로 확인 필요 | 전이 locked package의 OSV finding, JSON, ID/기간/이유 config, CI exit; [offline DB](https://github.com/google/osv-scanner/blob/v2.7.0/docs/offline-mode.md)는 별도 취득 후 무전송. source/image scan도 가능하나 pilot에서는 **명시적 lock/SBOM 한 개만** 입력. |
| [Anchore Syft](https://github.com/anchore/syft/releases/tag/v1.54.1) + [Grype](https://github.com/anchore/grype/releases/tag/v0.120.1) | 1.54.1 + 0.120.1, 둘 다 Apache-2.0, macOS/Linux native Go archives·checksums·Sigstore 자료 | `uv.lock` cataloger가 있으나 source-tree/설치 환경과 범위가 다르고 dev 분리 검증 필요 | SPDX/CycloneDX + 다중 공급원 취약점·image/OS package에 강함. 두 binary·DB update·경로 metadata·추가 비용이 현재 제품에 과도함. |
| [Aqua Trivy](https://github.com/aquasecurity/trivy/releases/tag/v0.76.0) | 0.76.0, Apache-2.0, macOS/Linux Go archives·checksum·Sigstore·SBOM | uv lock/설치 cataloging과 dev 귀속은 pilot 없이는 미확정 | vulnerability·secret·misconfiguration·SBOM·container를 한 도구로 제공. 전체 repo secret scan은 이번 privacy 정책과 출력 위험이 맞지 않으며 제품 image가 없음. DB/update 분리 필요. |
| [CycloneDX Python](https://github.com/CycloneDX/cyclonedx-python/releases/tag/v7.5.0) | 7.5.0, Apache-2.0, [PyPI](https://pypi.org/project/cyclonedx-bom/7.5.0/) wheel/sdist | 공식 문서상 [uv.lock 직접 파서는 아직 없음](https://github.com/CycloneDX/cyclonedx-python/blob/main/docs/usage.rst); 설치 venv inventory 사용 가능 | CycloneDX 전용이며 advisory·exit gate 아님. native 없는 자체 wheel이라도 전이 dependency와 설치 환경 격리 필요. 현재 uv 내장 export와 중복. |
| [Dependabot Core](https://github.com/dependabot/dependabot-core)·GitHub alerts·[dependency review action](https://github.com/actions/dependency-review-action) | Core release v0.400.0·MIT; action 최신 tag v5.0.0·MIT, GitHub-hosted 서비스·action | GitHub는 [uv ecosystem](https://docs.github.com/en/code-security/reference/supply-chain-security/supported-ecosystems-and-repositories)을 지원. dependency review는 PR diff·runtime/development scope를 제공하나 현재 저장소의 실제 그래프·설정은 별도 확인 필요 | GitHub에 공개된 manifest/lock과 PR metadata를 이용. 로컬 offline DB/SBOM 생성 대체 아님. action 도입 시 full commit SHA pin·`contents: read`·`pull_request`만. |
| [GitHub CodeQL](https://github.com/github/codeql) | query source MIT, CLI binary v2.27.2는 별도 배포·약관; public repo 사용 조건은 [GitHub 문서](https://docs.github.com/en/code-security/concepts/code-scanning/codeql/codeql-cli) 기준 | 소스 코드 dataflow/취약 패턴 분석; dependency lock 취약점·SBOM 도구 아님 | SARIF/code scanning 업로드는 별도 권한·데이터 전송. Semgrep 중단과 별개로 향후 코드 계층에서만 비교. |

OSV-Scanner v2.7.0의 고정 후보: tag는 annotated object를 거쳐 source commit `bfe2f84abd2f09fe0b83ba7f6dad40d296762f40`을 가리킨다. 공식 release asset metadata의 `osv-scanner_darwin_arm64`는 55,336,530 byte/SHA-256 `d4926ef8da134332543be276dff157e4c170f99ad91fc48e89448a8816bdf70b`, `osv-scanner_linux_amd64`는 57,725,088 byte/SHA-256 `160c6253e2922e9e0a6a9771c5c4c40a4b3c6090b34a3cdd5e80c96cc2e4218b`다. release에 `osv-scanner_SHA256SUMS`와 `multiple.intoto.jsonl`이 있지만 서명/attestation subject·builder·source 연계는 **아직 독립 검증하지 않았다**. Go binary가 native 실행 파일이고 별도 install script는 쓰지 않는 다운로드 후보일 뿐, 실행 안전 증거는 아니다. 다른 후보의 선택 archive/wheel도 같은 검증을 거치지 않아 이번 gate에서 실행 승인 대상으로 삼지 않는다.

### 검출 능력의 정확한 경계

| 결과 종류 | 현재 최소 조합의 책임 | 별도 계층/NOT_COVERED |
| --- | --- | --- |
| lock의 transitive 취약점 | OSV-Scanner의 `uv.lock` 또는 동일 lock에서 생성한 SBOM | 실제 설치 wheel/native ABI와 advisory reachability는 별도 확인 |
| runtime/dev | uv의 그룹별 export로 inventory 분리 후 OSV 결과와 대조 | OSV 직접 `uv.lock`의 group attribution과 shared transitive는 pilot 전 미확정 |
| installed environment | 기존 `uv sync --locked --no-build` 및 `--no-dev` 결과와 비교 | lock scan을 installed scan으로 주장하지 않음 |
| OS/container package | 해당 제품 image가 없으므로 이번 범위 불필요 | Docker Desktop/macOS host의 OS 취약점 검사 아님 |
| secret/misconfiguration/Actions pin | 현재 workflow 정적 리뷰와 기존 privacy 테스트 | OSV vulnerability scan이 secret·misconfiguration·pinning을 검출한다고 주장하지 않음 |
| SBOM/license | 기존 uv의 CycloneDX 1.5 export 후보; dependency name/version/source를 점검 | license completeness, local path, UUID/timestamp 결정성, SPDX 비교는 pilot gate. OSV offline license 조회는 deps.dev 기능과 동일시하지 않음 |

`pip-audit --locked .`는 [공식 문서](https://github.com/pypa/pip-audit/blob/v2.10.1/README.md)에 따르면 `pyproject.toml`과 `pylock.*.toml`을 찾는다. `uv.lock` 직접 해석을 추측하지 않는다. 반대로 현재 uv 0.11.26의 `uv export --help`에는 `requirements.txt`·`pylock.toml`·`cyclonedx1.5`, `--locked`·`--no-dev`·`--only-dev`가 있다. `uv audit --help`도 runtime/dev 그룹 필터를 보이지만 [공식 preview 계약](https://docs.astral.sh/uv/concepts/preview/)이며 네트워크 없이 audit할 수 없으므로 현 시점의 단독 release gate로 승격하지 않는다. uv의 CycloneDX export 역시 [preview](https://docs.astral.sh/uv/concepts/projects/export/)라 형식 안정성을 입증한 뒤에만 사용한다.

## 개인정보·네트워크·출력 정책

- 대상은 공개 dependency **이름·버전·lock metadata**만이다. OSV 온라인 API는 이 정보를 전송한다. 프로젝트 기본 정책은 **scan 단계 `--offline` + 별도 DB acquisition**이다. 공식 offline 문서는 DB가 없으면 오류이며 project/dependency 정보를 전송하지 않는다고 명시한다. DB 취득·서명 검증 경계는 Phase 24.1에서 독립 검증한다. `--offline-vulnerabilities`만 사용해 다른 기능의 네트워크를 열지 않는다.
- source, secret candidate, 실제 로그, 기본 monitor config, checkpoint, `.env`, 사용자 홈, credential, private path는 입력과 mount에서 제외한다. repository 전체를 재귀 scan하지 않고 승인된 `uv.lock`/필요한 `pyproject.toml` 또는 private 임시 SBOM만 다룬다. 스캐너의 home config와 update/telemetry 가능성은 별도 빈 HOME·network deny harness에서 확인한다.
- 결과 JSON/SBOM은 **0700 임시 디렉터리의 0600 파일**에만 저장하고 stdout/stderr 크기·시간을 제한한다. OSV JSON의 `source.path`, SBOM의 workspace path, package URL, absolute path, username, repository URL, scan timestamp/UUID, advisory 설명과 오류를 공개 DTO로 보지 않는다. 정규화 후 안전 요약만 문서화한다. raw report/SBOM을 Git, GitHub artifact, Release asset, 외부 SaaS에 자동 업로드하지 않는다. 삭제는 secure erase가 아니다.
- GitHub dependency graph/alerts는 **이미 공개된 저장소 파일**에 대해 GitHub가 제공하는 서비스다. 별도 action을 추가하면 dependency diff·경로·advisory metadata가 GitHub에 처리된다. public source 외 비공개 환경 자료를 넘기는 설계는 아니다. CodeQL SARIF에는 소스 위치/snippet이 들어갈 수 있으므로 업로드는 별도 승인 대상이다.

## 최소 선택과 Phase 24.1 pilot gate

**선택 G: OSV-Scanner v2.7.0 단독 신규 binary + 현재 고정된 uv 0.11.26 export.** A는 uv.lock 직접 입력과 offline DB가 약하고, B는 직접 lock·offline에 강하지만 SBOM 생성기가 아니다. C는 SBOM 도구가 하나 더 필요하지만 uv.lock 직접 파서가 없다. D/E는 제품 image가 없는 현재 범위에 과하며 source·secret 후보 노출과 DB/설치 비용이 커진다. F는 PR 변경 감시는 유용하지만 local/offline release inventory가 아니다. 동일 OSV DB에 pip-audit/Grype/Trivy를 중복 조회하는 조합은 채택하지 않는다.

1. 고정된 두 OSV release binary의 hash, tag→source commit, `multiple.intoto.jsonl` subject/서명·builder를 **실행 전에** 검증한다. 검증 불가면 `SUPPLY_CHAIN_BLOCKED`로 중단한다. macOS arm64와 실제 Ubuntu x86_64를 각각 확인한다. installer script·mutable container tag를 쓰지 않는다.
2. 별도 network-enabled acquisition에서 공식 PyPI OSV DB snapshot을 private 공간에 취득하고 출처·snapshot 시각·checksum을 기록한다. 스캔은 empty HOME, read-only copied public lock, network deny, bounded 30초/JSON 1MiB 후보 상한에서 수행한다. 상한은 개발용 가설이며 측정으로 조정한다. DB 누락·오래됨·검사 오류는 finding 0건이 아니라 **SCAN_INDETERMINATE**다.
3. `uv lock --check` 후 같은 lock을 **직접 OSV scan**하고, `uv export --locked --offline --no-dev --no-emit-project --format cyclonedx1.5`와 `--only-dev` 후보 결과를 별도 private 파일로 생성한다. uv preview option/출력 형식은 실제 0.11.26에서 확인한다. 두 SBOM의 집합·shared transitive·marker와 직접 lock inventory를 대조한다. runtime/dev 귀속이 모호하거나 누락되면 release gate 자동화는 NO-GO이며 결과를 합쳐서 과장하지 않는다.
4. wheel-only로 분리한 실제 macOS/Ubuntu `--no-dev`·`--dev` 환경과 선택 패키지 수/버전을 대조한다. lock은 cross-platform 후보를 담으므로 차이가 정당한 marker인지, 누락인지 구분한다. flat-layout `uv build`를 고치거나 wheel/PyPI 배포를 주장하지 않는다.
5. synthetic advisory fixture와 현재 **공개 dependency metadata**만 쓴다. finding 0건을 가정하지 않고 정상 finding, scanner/DB 오류, malformed JSON, output 상한 초과를 각각 검증한다. 자동 `fix`, report upload, source scan, secret scan, image scan, Actions 설정 변경은 하지 않는다. 실제 실행 비용과 DB 크기를 macOS/Ubuntu에서 재고 CI 추가 여부를 별도 결정한다.

### Finding·예외·CI 정책

기록 최소 단위는 OSV/GHSA/CVE ID 및 alias, affected range, selected/installed version, fixed version, runtime/dev/shared scope, platform, evidence, reachability 판단과 reviewer다. Advisory 존재는 exploit reachability 증명이 아니고, finding 없음은 안전 증명이 아니다. severity만으로 일률 실패하지 않는다. **새 runtime critical/high**는 자동 통과하지 않고 소유자 triage·수정 가능성·실제 사용 경로를 확인한다. 기존 accepted finding은 ID·정확한 package/version 범위·이유·reviewer·만료일을 갖는 좁은 예외만 허용한다. broad/permanent ignore나 DB 오류를 0건으로 처리하는 정책은 NO-GO다. PR gate는 새 dependency/advisory 차이, release gate는 고정 DB 시점의 전체 runtime+dev inventory와 미해결 예외를 본다. 이 정책은 프로젝트 결정이지 OSV/NIST가 정한 severity 임계값이 아니다.

### SBOM·GitHub 정책

현재 Python-only lock에는 CycloneDX 1.5 JSON이 자연스럽고 uv에 export가 이미 있다. SPDX도 상호운용 표준이나 이를 위해 Syft를 하나 더 들이지 않는다. 최소 공개 전 검토 필드는 package name/version, source/PURL, license의 근거와 runtime/dev scope다. `uv export`가 license를 모두 채우는지 **미검증**이다. 불완전하면 비어 있는 값을 거짓 MIT로 보완하지 말고 별도 수동 확인 또는 다음 Phase의 도구 비교로 남긴다. timestamp/serial/UUID, 절대 path·user·machine ID를 제거한 정규화가 동일 lock 반복과 UTC/KST에서 같은지 실험한다. raw SBOM은 CI 내부 private 증거이며 Git에 추적하거나 v0.2.0 Release에 소급 첨부하지 않는다.

[GitHub dependency review](https://docs.github.com/en/code-security/how-tos/secure-your-supply-chain/manage-your-dependency-security/configure-dependency-review-action)는 공개 저장소의 PR 변화 감시에 유용한 **후속 별도 후보**다. 도입한다면 `actions/dependency-review-action`의 immutable commit SHA pin, `contents: read`, `pull_request`만 사용하고 `pull_request_target`, token write, report upload를 기본 금지한다. GitHub dependency graph/Dependabot alerts의 현재 enablement·누락 범위는 별도 점검해야 하며, public repo 지원만으로 이미 활성이라고 주장하지 않는다. CodeQL은 코드 dataflow 계층으로 보류한다.

## GO/NO-GO

- **GO**: 선택 binary의 검증 가능한 source/artifact 연계, DB 출처·시점, 네트워크 차단, `uv.lock` 완전성, runtime/dev 귀속, safe JSON/SBOM, macOS·Ubuntu 결과와 bounded 비용을 모두 실증.
- **CONDITIONAL GO (현재)**: 공식 `uv.lock`·offline 근거와 검증 후보 artifact는 있으나 attestation, 직접 lock의 group 귀속, uv preview SBOM의 재현성·license, Ubuntu 실행, DB/CI 비용은 미검증.
- **NO-GO**: source/secret 후보를 외부로 전송하거나 숨길 수 없음, dependency 누락·scope 혼동, DB/scan 실패를 finding 0으로 위장, provenance를 확인할 수 없는 binary, 무제한 output 또는 무기한 broad suppression.

외부 문서가 프로젝트의 30초·1MiB·예외 만료 정책을 정한 것은 아니다. 이 수치는 Phase 24.1에서 검증할 **프로젝트 가설**이다.
