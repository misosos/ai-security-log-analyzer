# Phase 24.1 — 임시 OSV-Scanner·uv CycloneDX pilot

**판정: NO-GO (완전한 SBOM/release gate).** 취약점 검사의 *제한된* 로컬 pilot은 동작했지만, 현재 uv 0.11.26 CycloneDX 1.5 출력은 artifact hash와 license 정보를 전혀 담지 않는다. Phase 24.1의 “name·version·source·hash 관계 유지”를 충족하지 않으므로 SBOM을 완전한 locked artifact 증거로 채택하거나 CI/release gate로 연결하지 않는다. 취약점 0건이라는 관찰도 이 snapshot과 추출된 package 집합에만 해당한다. 스캐너 설치·project dependency·CI·Release 변경은 없었다.

## 시작·환경·범위

시작 `main`과 `origin/main`은 `a6a0c6309ca8f552d73e5c430bcadbf96b17c0cc`, clean·behind 0/ahead 0이었다. [해당 CI](https://github.com/misosos/ai-security-log-analyzer/actions/runs/39102909728)는 completed/success다. 변경 전 macOS 전체 pytest **2,279 passed, 기존 deprecation 경고 2개**. 공개 v0.2.0 tag peeled SHA `2520e317475f96d48b4bfeef8f7ee04d63720308`, [정식 Release](https://github.com/misosos/ai-security-log-analyzer/releases/tag/v0.2.0)는 draft/prerelease false·별도 asset 0개로 불변이다. Phase 23.5 Ubuntu [CI](https://github.com/misosos/ai-security-log-analyzer/actions/runs/39101912404)는 locked wheel-only 설치, Schemathesis focused 및 전체 2,276 passed에 포함된 Hypothesis suite를 통과해 최종 GO다.

검증 호스트는 **macOS arm64**, uv `0.11.26`, OSV-Scanner `2.7.0`/osv-scalibr `0.5.3`이다. Ubuntu x86_64 artifact는 취득·검증했으나 **Ubuntu에서 실행하지 않았다**. 제품은 source-checkout 설치이고 flat-layout `uv build` 경계, runtime 직접 6개와 dev 직접 Hypothesis·pytest·Schemathesis, optional group 없음은 유지된다. 임시 합성 SBOM과 공개 `uv.lock`의 사본만 스캔했다. 원본 로그·설정·checkpoint·홈 자료는 대상이 아니었다.

## 공급망 검증과 실행 경계

[공식 v2.7.0 release](https://github.com/google/osv-scanner/releases/tag/v2.7.0)의 annotated tag는 source commit `bfe2f84abd2f09fe0b83ba7f6dad40d296762f40`을 가리킨다. 공식 checksum·release metadata·다운로드 SHA-256이 아래와 일치했다.

| artifact | 크기 | SHA-256 | 정적 파일 형식 |
| --- | ---: | --- | --- |
| `osv-scanner_darwin_arm64` | 55,336,530 byte | `d4926ef8da134332543be276dff157e4c170f99ad91fc48e89448a8816bdf70b` | Mach-O arm64 |
| `osv-scanner_linux_amd64` | 57,725,088 byte | `160c6253e2922e9e0a6a9771c5c4c40a4b3c6090b34a3cdd5e80c96cc2e4218b` | ELF x86-64, statically linked |

Release의 `multiple.intoto.jsonl`은 Sigstore bundle/SLSA provenance v0.2다. 기존 `gh attestation verify`로 macOS·Linux artifact의 서명과 transparency timestamp를 검증했고, signer identity를 `slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v2.1.0`, source ref를 `refs/tags/v2.7.0`, source digest를 위 commit으로 제한했다. 처음 기본 predicate v1/기본 repository identity로 시도한 검증은 실패했고, bundle의 **실제 v0.2 predicate와 reusable builder identity**를 확인한 뒤에만 성공했다. 이 검증은 provenance 주장과 받은 byte의 연결이지 재현 빌드나 binary 내부 무해성의 증명이 아니다. 별도 installer·archive·lifecycle script 없이 단일 native binary만 임시 private 위치에 두었다. binary는 `--help`/`--version`에서 2.7.0과 동일 commit을 보고했다. `fix`, daemon, MCP, updater는 실행하지 않았다. [공식 설치 안내](https://google.github.io/osv-scanner/installation/)도 release provenance와 SLSA verifier를 설명한다.

스캔은 macOS `sandbox-exec`의 network deny 및 홈 경로 read deny, 빈 임시 HOME, **`--offline --no-resolve`**, 30초 process alarm, 1 MiB 파일 상한, 지정한 SBOM 또는 `uv.lock` **한 파일** 입력으로 실행했다. 실제 credential·repository 전체는 scanner에 주지 않았다. DB 준비는 별도의 HTTPS GET `https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip` 한 건으로 분리해 dependency 이름/버전이나 source를 요청 본문에 보내지 않았다. 이 endpoint는 [공식 오프라인 문서](https://github.com/google/osv-scanner/blob/v2.7.0/docs/offline-mode.md)에 명시된다. 내려받은 PyPI DB는 36,436,224 byte, SHA-256 `fa7a991d4ef3875c7f18f272d77f776f298a1ca71a169d84a91f572de8e3c401`, HTTP Last-Modified `2026-10-18 02:02:48 GMT`였고 zip 검사에 통과했다. DB 자체의 서명·advisory 완전성은 검증하지 않았다.

중요한 실측 차이: 위 공식 문서의 `{cache}/osv-scanner/PyPI/all.zip` 위치는 이 binary에서 **DB 없음(exit 127)**을 냈다. `{cache}/osv-scalibr/PyPI/all.zip`에 같은 검증된 zip을 배치하자 합성 finding이 나왔다. 이는 2.7.0의 실제 관찰이며, 문서 경로를 근거로 성공을 추측하지 않았다. 홈·기본 cache를 탐색해 우회하지 않았고, scanner 출력의 `source.path`에는 임시 절대 경로가 포함되므로 raw JSON/오류는 공개하거나 추적하지 않는다.

## CycloneDX와 lock 검증

기존 uv의 `--preview-features sbom-export --locked --offline --format cyclonedx1.5`만 사용했다. runtime에는 `--no-dev`를 더했고, 개발 포함에는 기본 dev group을 사용했다. `--output-file`을 주어도 uv가 SBOM을 stdout에 출력하므로 이후 반복은 stdout을 `/dev/null`로 보냈다. 전용 임시 **상위 디렉터리 0700**은 유지했다. 첫 취약 합성 scanner probe의 raw report는 예상과 달리 **0644**로 생성됐고, 최초 DB 중간 디렉터리도 0755였다. 상위 0700 때문에 다른 로컬 사용자에게 경로 접근을 허용한 것은 아니지만, 요구한 개별 파일·디렉터리 권한을 충족하지 못한 첫 실행은 별도 결함으로 기록한다. 이후 `umask 077`을 실행 전에 적용하고 DB 디렉터리·파일 권한을 0700/0600으로 재검증했다. 이 권한 문제도 자동 CI/release gate 채택을 보류하는 이유다.

| inventory | Python dependency component | dependency graph entry | Hypothesis·Schemathesis | 크기 |
| --- | ---: | ---: | --- | ---: |
| runtime-only | 37 | 38 (project root 포함) | 없음 | 11,590 byte |
| development-inclusive | 57 | 58 (project root 포함) | 둘 다 있음 | 17,241 byte |

Project root component는 `0.2.0`으로 정확하다. `uv.lock`은 root 포함 58 package이며 개발 포함 SBOM과 OSV의 직접 `uv.lock` 추출에서 Python package 57개의 **이름 집합**이 같다. 현재 macOS 개발 환경에는 55개가 설치되어 있다. lock-only에만 있는 `colorama`, `tzdata`는 이 플랫폼의 marker 후보라 설치 inventory와 동일시하지 않는다. runtime-only 별도 clean install은 수행하지 않았다. SBOM은 PURL·이름·버전·dependency refs를 제공하지만 **component hash 0/57, license 0/57, source artifact URL 0/57**이다. root license도 SBOM에 없다. 즉 `uv.lock`에 hash가 있더라도 SBOM 단독으로 artifact identity/license를 보존하지 않는다. 이를 허위 MIT/license 또는 임의 변환기로 채우지 않는다. [uv 공식 문서](https://docs.astral.sh/uv/concepts/projects/export/)도 CycloneDX export를 preview로 표시한다.

원본 SBOM은 매번 `serialNumber` UUID와 UTC timestamp가 달라 byte-identical하지 않다. 테스트용 `scripts/supply_chain_pilot_24_1.py`는 private metadata 패턴을 거부하고 **안전한** root 이름/버전·Python PURL/name/version·graph refs만 canonical digest로 만든다. 이 제한된 inventory digest는 UTC와 Asia/Seoul의 반복 export에서 runtime끼리, dev끼리 같았다. raw SBOM의 artifact 재현성을 주장하지 않는다. 실패하면 raw 내용/경로 대신 고정 상태를 반환한다.

## Scanner 결과와 실패 의미

| 입력 | 옵션 | exit | 확인한 의미 |
| --- | --- | ---: | --- |
| 합성 Django 2.2 CycloneDX | `-S`, `--offline --all-packages` | 1 | 1 package, DB의 고유 advisory ID 75개; 의도적으로 취약한 fixture에서 finding |
| 합성 미게시 package | `-S` | 0 | 1 package 추출, vulnerability 0건 |
| malformed CycloneDX | `-L` | 127 | JSON extraction 오류; 정상 0건 아님 |
| empty CycloneDX | `-S` | 128 | package source 없음; 정상 0건 아님 |
| DB 없는 private cache | `-S`, `--offline` | 127 | DB 조회 실패; 정상 0건 아님 |
| 실제 runtime SBOM | `-S --all-packages` | 0 | 37 package 추출, 현재 DB finding 0건 |
| 실제 dev 포함 SBOM | `-S --all-packages` | 0 | 57 package 추출, 현재 DB finding 0건 |
| 공개 `uv.lock` 사본 | `-L --all-packages` | 0 | 57 package 추출, 현재 DB finding 0건 |

**거짓 녹색 경계:** `-L runtime.cdx.json`과 `-L development.cdx.json`은 exit 0/빈 `results`를 반환했지만 SBOM package를 추출하지 않았다. `-S`는 정상 추출하지만 CLI가 deprecated 경고를 낸다. `--all-packages`의 **추출 수가 기대와 같아야** `ZERO_FINDINGS`로 인정하는 작은 개발용 classifier를 추가했다. `-L` 결과나 DB 실패를 0건으로 바꾸지 않는다. 이 경계와 향후 `-S` 제거 위험 때문에 CLI 자동 gate 도입은 보류한다. Finding 75개는 의도적으로 취약한 합성 Django fixture의 수치이며 현재 프로젝트 finding이 아니다. 실제 프로젝트의 현재 DB finding 0건은 reachability나 미래 안전성을 증명하지 않는다. CVE/GHSA/OSV suppression은 만들지 않았고 dependency upgrade도 하지 않았다.

Raw report에는 source의 임시 절대 경로와 취약 advisory 세부가 있으며, malformed 오류도 임시 경로를 포함할 수 있다. wrapper는 추출 패키지 수·finding 수·`FINDINGS`/`ZERO_FINDINGS`/`SCAN_INDETERMINATE`만 안전하게 반환한다. `repr()`·JSON·stdout을 public API/Release에 연결하지 않는다. 별도 단위 테스트는 **합성** path·account·IP·query·raw line·credential canary를 주입해 private metadata 거부를 확인한다. 실제 로그·account·IP·query·credential은 scanner 입력에 사용하지 않았다. 생성 SBOM/report/DB를 Git이나 GitHub artifact에 업로드하지 않았다. 파일 목록과 symlink 부재를 확인한 뒤 전용 임시 디렉터리 전체를 **macOS 휴지통으로 이동**했다. 원래 위치의 잔존은 없지만 복구 가능하며 secure erase가 아니다.

## 성능과 CI 판단

macOS arm64 개발 표본이다. uv export 4회(UTC/KST × 2 inventory)는 각각 약 0.07초, DB HTTPS 취득은 15.7초·36.4 MB였다. DB를 준비한 뒤 첫 합성 취약 scan은 4.87초. runtime/dev warm scan 각 3회, 총 6회는 median 약 **4.68초**, nearest-rank p95/max **4.79초**였다. 입력은 37/57 component, SBOM 약 11.6/17.2 KiB, DB 36.4 MB이며 OS·디스크 cache·network 상태에 종속된다. canonicalization은 작아서 독립 반복 측정하지 않았다. 이 값은 CI SLA나 최악 시간 보장이 아니다. Ubuntu scanner 실행·DB snapshot 재현성·full artifact provenance replay는 미검증이다.

권장 CI 구조는 **PR: lock과 deterministic safe inventory 계약 테스트만**, scheduled/release: 별도 승인·고정 snapshot의 취약점 scan 검토다. 매 PR live network scan은 DB·시간 비결정성과 외부 전송 경계 때문에 기본 채택하지 않는다. GitHub dependency review는 PR diff 계층의 별도 후속 후보이며 action을 도입한다면 commit SHA pin과 최소 `contents: read`, `pull_request`만 사용한다. 이번 Phase는 workflow를 변경하지 않았다.

## 종료 gate와 다음 조건

Phase 24.1의 artifact·서명 검증과 **offline synthetic/실제 lock 검사**는 PASS다. 그러나 uv CycloneDX의 hash·source artifact·license 결손, `-L` SBOM false-zero, `-S` deprecation, 첫 probe의 파일 권한 불일치, 공식 DB cache 경로와 실제 차이, Ubuntu 실제 실행 미검증 때문에 **완전한 공급망 release gate는 NO-GO**다. 다음 단계에서 임의 변환을 만들기보다 uv preview 형식의 상향 또는 source/hash를 보존하는 공식 SBOM 도구·OSV v2.7 이후 문서화된 SBOM 옵션을 별도 공급망 gate로 평가해야 한다. 새 도구 설치나 CI 연결은 별도 승인 대상이다. raw report/SBOM/DB/verified binary는 이 pilot의 임시 자료로만 사용하고 secure erase를 주장하지 않는다.
