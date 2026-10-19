# AI Security Log Analyzer

현재 개발 branch의 [Phase 26.1 Ubuntu SSH checkpoint 수용 gate](docs/ssh_checkpoint_linux_acceptance_26_1.md)는 별도 프로세스 advisory lock·권한·재시작·reset smoke를 CI에 추가했지만, 해당 새 단계의 Ubuntu 결과는 다음 push 이후에만 확인할 수 있습니다. 기존 원격 전체 회귀 성공을 이 독립 검증의 PASS로 해석하지 않습니다.

> 보안 계약 변경: deprecated `/api/analyze`의 상위 구조는 유지하지만 중첩 탐지·상관관계·위험도·전체 상관관계는 개인정보 안전 projection으로 변경되었습니다. 기존 raw nested 값 소비자는 [migration 안내](docs/public_analysis_privacy.md)를 확인하세요. 새 로컬 개발에는 `POST /api/v1/investigations`를 사용하세요. 인증 없는 공개 업로드는 지원하지 않습니다.

AI Security Log Analyzer는 애플리케이션 인증 로그, OpenSSH 인증 로그, 웹 접근 로그와 선택적인 Linux Audit 레코드를 정규화한 뒤, 결정적인 규칙으로 탐지·상관관계·IP별 위험도를 계산하는 방어 목적의 배치 분석 프로젝트입니다. 보안 로그 조사 흐름을 학습하거나 소규모 환경에서 초기 검토하는 데 사용할 수 있습니다.

v0.2.0에는 명시적으로 승인한 단일 파일의 실행 이후 추가분을 읽는 [bounded 내부 tail core·parser adapter·단일 record lease·worker·detection accumulator](docs/live_log_monitoring_design.md)가 있습니다. 기존 application·SSH·access parser와 detector를 그대로 재사용합니다. Worker는 queue ack 성공 후에만 탐지 후보를 commit하며, 이는 원자적 transaction이나 exactly-once가 아닙니다. Session-local observation ID에는 개인정보나 hash가 없지만 trusted 내부 history에는 원문 계정·path/query가 남을 수 있습니다. 전체 PARSED session prefix는 명시된 item·byte 상한 안에 보존하며 오래된 event를 조용히 제거하지 않습니다. 기존 v0.1.0 업로드·배치 분석은 그대로 동작합니다. 즉시 처리·무유실·운영 성능·hosted 수집을 약속하지 않습니다.

Phase 14~15에서는 확정된 detection change만 받는 process-local·memory-only bounded publication/replay buffer, 읽기 전용 loopback status/SSE, `--monitor-config` 자동 polling과 접근 가능한 화면 표시가 연결됐습니다. 기본 `uv run python -m app.local_web`에서는 live endpoint와 화면 영역이 비활성입니다. Detection commit 이후 publication 실패는 되돌리지 않고 terminal 무결성 오류로 기록합니다. SSE replay는 여전히 process-local이며 재시작 후 이벤트 ID 연속성·무유실·여러 process 간 일관성을 보장하지 않습니다. 기본 v2 설정의 동일 파일 분석 prefix 복구는 별도의 bounded checkpoint 경계입니다.

Phase 16의 [live correlation·risk·조사 사례 설계](docs/live_analysis_correlation_case_design.md)는 현재 단일-source history에서 기존 batch 의미를 보존할 수 있는 최소 범위와 개인정보 경계를 정리했습니다. 당시에는 설계만 완료됐고, 이후 Phase 16.1~16.3의 현재 연결 범위는 아래에 구분했습니다.

Phase 16.1~16.3에서는 단일 `application` source의 내부 proposal/commit/abort 분석과 안전한 `analysis_changes` SSE/UI를 연결했습니다. Phase 22.3은 기존 SSH parser·detector·batch correlation/risk/case 의미를 같은 내부 transaction과 안전 projection으로 확장했습니다. SSH live 관계·위험도·조사 사례는 **명시적 v1 `--monitor-config`로 지정한 SSH 파일 하나**에서 새 줄부터 표시할 수 있습니다. `access`는 detection-only입니다. 기존 `observation_changes` schema는 유지하고 브라우저에서는 두 event를 같은 제한된 대기열에 보관하다가 **새 결과 보기**를 선택할 때 표시합니다. 256 PARSED event/256 KiB를 넘으면 일부 기록을 버리고 계속하지 않습니다. Ack는 되돌릴 수 없고 queue·두 accumulator·publication은 원자적 transaction이 아닙니다. SSH 인증 성공은 계정 탈취·인과관계·동일 행위자를 확정하지 않습니다. Session-local ID는 재시작 후 유지되지 않으며 exactly-once·무유실도 보장하지 않습니다. [SSH Phase 22.3 계약](docs/ssh_live_analysis_integration_22_3.md)을 참조하세요.

Phase 16.4의 [로컬 통합 감사](docs/live_analysis_16_4_audit.md), [Phase 17·17.1 수용성 기록](docs/live_monitoring_acceptance_17.md), [Phase 18 복구 검증](docs/live_monitoring_release_gate_18.md)은 당시 합성 application 흐름의 batch parity·두-event publication·replay·개인정보 경계와 실제 loopback 종료 정리를 구분합니다. 사용자는 Safari의 live keyboard-only·실제 200% 확대·최소 창 너비·Web Inspector 주요 흐름·pause 중 append·terminal 및 replay gap 복구 화면을 직접 확인했습니다. 이는 후속 SSH 화면의 수동 Safari 검수까지 뜻하지 않습니다. 정확한 320 CSS px와 VoiceOver 상세는 미검증입니다. 운영 SLA나 WCAG 2.2 AA 준수를 뜻하지 않습니다. [Phase 26.0](docs/ssh_checkpoint_recovery_26_0.md)은 단일 SSH 기본 v2 설정의 동일 파일 checkpoint 복구를 추가했지만, rotation handoff·cross-source 결합과 access 분석은 보류됩니다.

로컬 모니터링 사용 순서: (1) 읽을 수 있는 로그 파일 하나를 준비합니다. (2) 아래 설정 마법사를 사용하는 것이 권장됩니다. 기존 수동 방식은 개인 경로가 없는 [예시 설정](docs/examples/live-monitor.json)을 복사하고 source 절대 경로를 로컬 값으로 바꿔 `uv run python -m app.local_web --monitor-config /absolute/path/to/live-monitor.json`으로 실행합니다. (3) 브라우저의 **실시간 로그 모니터링** 영역에서 상태와 로그 역할을 확인합니다. (4) 새 탐지 관찰이 생기면 **새 결과 N건 보기**를 눌러 반영합니다. (5) `Ctrl+C`로 종료합니다. 시작 전 파일 내용은 읽지 않습니다. **화면 업데이트 일시 정지**는 서버 수집을 멈추지 않습니다. 기존 3파일 분석과 Linux Audit 단일 업로드는 별도 흐름입니다. `/api/health`의 200은 웹 서버 준비만 뜻하고 live 상태는 `/api/v1/live/status`에서 확인합니다. 탐지 관찰은 침해 확정이 아니고 hosted 용도가 아닙니다.

JSON을 직접 작성하지 않으려면 [안전한 설정 마법사](docs/monitor_setup_20.md)를 실행하세요. 현재는 **application 로그 하나**만 등록합니다. 미리보기와 bounded dry-run을 확인한 후 명시적으로 저장을 승인해야 하며, 설정 생성만으로 모니터링이 시작되지는 않습니다.

```bash
uv run python -m app.monitor_setup
uv run python -m app.local_web --monitor
```

기본 설정을 안전한 요약으로 확인하거나 기본 설정 파일 하나만 승인 후 삭제할 수 있습니다.

```bash
uv run python -m app.monitor_setup --show
uv run python -m app.monitor_setup --delete
uv run python -m app.monitor_setup --reset-checkpoint
```

`--show`는 원본 경로나 JSON을 표시하지 않고 마지막 처리 위치의 안전한 상태만 요약합니다. `--delete`는 기본 config와 연결된 private checkpoint만 승인 후 삭제하며 원본 로그·설정 parent·사용자 지정 `--output` 파일은 삭제하지 않습니다. checkpoint-enabled 모니터링 실행 중에는 삭제를 거부합니다. 설정 삭제는 secure erase가 아닙니다. 마법사는 source 경로를 private config에 저장하므로 공유하지 마십시오. 명시적 `--output`은 기존 `--monitor-config <절대-경로>`로 실행하며, 그 경로가 터미널 기록에 남을 수 있습니다. `--monitor`가 없으면 live는 자동 활성화되지 않습니다. 새 마법사 설정은 application `BOUNDED_REPLAY_V1`을 사용합니다. 별도로 준비한 private 기본 v2 SSH 설정도 같은 정책을 명시하면 `--monitor`에서 동일 파일 복구가 가능하지만, **마법사는 아직 SSH 설정을 생성하지 않습니다**. 처음에는 `FROM_END`로 시작하고, 이후 같은 application 또는 SSH 파일의 bounded 원본 구간을 재생해 탐지·관계·위험도·사례 prefix를 재구성합니다. 기존 `DISABLED` 설정과 명시적 `--monitor-config`는 계속 재시작 때 `FROM_END`입니다. 특히 **SSH의 명시적 v1 설정은 checkpoint 없이 재시작마다 `FROM_END`**입니다. Checkpoint에 원본 로그는 복사하지 않지만 private 파일 identity·byte 위치가 저장됩니다. 중복·gap 가능성이 있고 exactly-once·무유실·완전한 crash recovery가 아닙니다. 파일 교체·rotation·truncation은 자동 복구하지 않고 중단합니다. 외부 LLM 자동 전송은 없습니다. 종료는 `Ctrl+C`; access의 수동 v1 설정은 detection-only입니다. [Phase 21 상세 계약](docs/live_checkpoint_21.md)과 [Phase 26.0 SSH 범위](docs/ssh_checkpoint_recovery_26_0.md)를 참조하세요.

Phase 21.1은 [관찰 가능한 로그 파일 축소](docs/live_rotation_21_1.md)를 읽기 위치보다 아직 큰 경우에도 감지해 중단합니다. 자동 rotation 연결은 여전히 없으며, 두 검사 사이의 truncate·재성장까지 무유실로 판별하지는 못합니다.

Phase 21.2는 [checkpoint 잠금 이름 교체와 원자 교체 후 장애 경계](docs/live_checkpoint_21_2.md)를 검증합니다. 잠금 파일이 다른 inode로 바뀐 것이 관찰되면 다음 처리 전에 중단하지만, 악의적인 동일 사용자에 대한 절대적 단일 실행이나 전원 차단 시 exactly-once를 보장하지 않습니다.

Phase 21.3은 [실제 두 서버 프로세스의 동일 파일 재시작](docs/live_checkpoint_21_3.md)을 검증했습니다. Bounded 원본 재생으로 분석 prefix를 복구하되 과거 publication을 다시 보내지 않습니다. 이전 프로세스의 SSE cursor는 새로운 transport session에서 replay gap으로 처리하도록 ID 충돌 가능성을 낮췄습니다. ID 형식은 같지만 전역 유일성이나 Safari 재시작 흐름의 수동 검증까지 보장하지는 않습니다.

Phase 21.4는 [poll 이후 ack 이전의 파일 상태 재검증](docs/live_rotation_21_4.md)을 추가했습니다. 관찰 가능한 교체·축소가 이 구간에 발생하면 proposal을 취소하고 queue lease를 되돌린 뒤 모니터링을 중단합니다. 마지막 검사와 ack 사이의 race, 빠른 truncate·재성장, 자동 rotation 복구는 여전히 해결되지 않았습니다.

Phase 21.5의 [rotation handoff 안전성 gate](docs/live_rotation_21_5.md)는 이전 파일 writer가 rename 후에도 계속 기록할 수 있고 일시적인 EOF만으로 종료를 알 수 없음을 검증했습니다. 현재의 단일 파일 checkpoint로 두 세대의 분석 prefix를 재시작 후 재구성할 수 없으므로, 자동 handoff는 구현하지 않고 fail closed를 유지합니다.

Phase 21.6의 [두 파일 세대 복구 검토](docs/live_rotation_21_6.md)는 EOF 이후 old writer append, old/new partial line, retained old 파일의 재시작 거부, copytruncate 재성장의 관찰 한계를 재현했습니다. 자동 rotation 복구는 여전히 지원하지 않으며, 두 세대 private checkpoint metadata 확대는 승인되지 않았습니다.

Phase 21.7은 [사용자 승인 기반 새 분석 epoch 준비](docs/live_checkpoint_epoch_reset_21_7.md)를 추가했습니다. 파일 교체·축소 또는 checkpoint 불일치로 중단되면 원인을 확인하고 모니터링을 종료한 뒤 `uv run python -m app.monitor_setup --reset-checkpoint`에서 결과 연속성 포기를 `y/yes`로 승인할 수 있습니다. 연결된 derived checkpoint **하나만** 삭제하며 설정·원본 로그는 그대로 둡니다. 다음 `--monitor`는 현재 파일의 `FROM_END`부터 새 세션으로 시작하고 중단 기간 로그나 과거 탐지·관계·위험도·사례를 복원하지 않습니다. [Phase 21.8 Linux 검증 기록](docs/live_checkpoint_epoch_reset_21_8_linux_audit.md)은 Ubuntu CI 증거와 별도 프로세스 reset 검증의 범위를 구분합니다. 자동 rotation handoff와 두 세대 checkpoint metadata 확대는 승인되지 않았으며 계속 NO-GO입니다. 이 삭제는 secure erase가 아닙니다.

테스트 경계: [Phase 23.0 도입 gate](docs/hypothesis_property_testing_gate_23_0.md) 이후 [Phase 23.1 개발용 pilot](docs/hypothesis_property_testing_pilot_23_1.md)에 Hypothesis 6.170.0을 **dev dependency로만** 추가했습니다. 합성 parser·lease queue·개인정보 안전 projection의 bounded property를 기본 전체 회귀에서 검사하며, production 기능이나 운영 탐지율·무유실 증명이 아닙니다. 로컬 Hypothesis cache와 실패 example은 추적하지 않습니다. [Phase 23.2 Semgrep 정적 보안 규칙 gate](docs/semgrep_security_gate_23_2.md)는 설계만 완료됐고 [Phase 23.3 공급망 감사](docs/semgrep_security_pilot_23_3.md)는 공식 Docker image와 공개 OSS source의 연결을 충분히 검증할 수 없어 실행 전에 중단했습니다. Semgrep은 project dependency나 CI 검사에 추가되지 않았습니다. [Phase 23.4 Schemathesis OpenAPI fuzzing gate](docs/schemathesis_api_fuzzing_gate_23_4.md) 이후 [Phase 23.5 개발용 pilot](docs/schemathesis_api_pilot_23_5.md)은 Schemathesis 4.31.1을 **dev dependency로만** 추가하고 합성 sample·live status·legacy HTTP 계약을 bounded하게 검사합니다. multipart 전체 및 SSE fuzzing은 포함하지 않으며 실제 로그를 생성 입력으로 사용하지 않습니다. Ubuntu CI에서 pilot과 전체 회귀가 통과했습니다. [Phase 24.0 공급망 검증 도구 선정 gate](docs/software_supply_chain_gate_24_0.md)는 OSV-Scanner의 검증된 오프라인 lock 검사와 기존 uv의 CycloneDX export를 조건부 pilot 후보로 선정했으며, 아직 도구 설치·실행이나 CI 연결은 하지 않았습니다.

연결이 종료되면 화면의 서버 상태 안내를 확인하고 필요한 경우 **최신 상태로 다시 연결**을 선택하십시오. 이 동작은 잃은 변경 기록을 복원하지 않습니다. Phase 15.1의 [실시간 UI 수용성 검증 기록](docs/live_monitoring_acceptance_15_1.md)은 자동 테스트, 실제 Safari WebDriver 확인, 아직 필요한 수동 keyboard·확대·콘솔 확인을 구분합니다.

현재 지원하는 주요 관찰은 Brute Force, Password Spraying-like, Path Traversal, SQL Injection-like, XSS-like, Sensitive Resource Probing-like, Web Scanning-like, 인증 실패 후 로그인 성공, Brute Force 후 로그인 성공입니다. 탐지와 상관관계는 조사할 관찰이지 침해의 증명이 아니며, 이 프로젝트는 SIEM·EDR·WAF·자동 대응 또는 사고 판정 시스템이 아닙니다. 새 웹 관찰의 고정 pattern과 한계는 [설계 문서](docs/web_attack_observation_design.md)에 기록했습니다.

처리 흐름은 다음과 같습니다.

```text
로그 → 로딩·정규화 → 탐지 → 상관관계 → IP별 위험도 → CLI·HTML·API
```

[Phase 24.1 로컬 공급망 pilot](docs/software_supply_chain_pilot_24_1.md)은 OSV-Scanner 2.7.0의 검증된 임시 binary와 오프라인 DB로 합성 입력 및 현재 공개 의존성을 검사했습니다. uv CycloneDX export에는 artifact hash·license가 빠져 완전한 SBOM gate로 채택하지 않았습니다. 스캐너·DB·생성 SBOM은 project dependency, CI 또는 릴리스 asset에 포함하지 않습니다.

[Phase 24.2 locked dependency evidence bundle](docs/dependency_evidence_bundle_24_2.md)은 `uv.lock` digest, runtime/dev requirements의 artifact hash, 원본 CycloneDX graph를 **분리된 private 임시 증거**로 대조합니다. `uv run python -m scripts.dependency_evidence_bundle_24_2`로 안전한 count·digest prefix만 확인할 수 있습니다. CycloneDX 원본의 UUID·timestamp는 비결정적이고 license·vulnerability 결과는 별도 검토 대상입니다. Ubuntu 전체 회귀에서 bundle 계약은 통과했지만, 공식 vulnerability/release gate로는 아직 사용하지 않습니다.

## 요구 사항과 설치

- Python 3.12 이상(`pyproject.toml`의 `requires-python = ">=3.12"`)
- [uv](https://docs.astral.sh/uv/)

저장소를 받은 뒤 프로젝트 루트에서 검증된 잠금 파일로 개발 의존성까지 동기화합니다. 프로젝트 버전의 단일 출처는 `pyproject.toml`의 `0.2.0`이며 API/평가 schema version과 별개입니다. 이 버전의 공식 설치 방식은 source checkout입니다. 현재 `uv build`는 flat-layout package discovery 오류로 실패하므로 wheel/PyPI 설치를 지원한다고 주장하지 않습니다.

```bash
uv sync --locked --dev
```

기본 로컬 CLI, HTML 보고서, 개발 API에는 환경 변수가 필요하지 않습니다. 실제 키나 운영 로그를 저장소, `.env`, 명령행 또는 문서에 넣지 마십시오.

Gemini 설명 기능은 `app/analyzer/llm.py`에 있는 선택적 개발 경계입니다. 이를 직접 호출할 때만 `GEMINI_API_KEY`가 필요합니다. 기본 CLI, HTML 보고서, 기본 API와 보안 Linux Audit API는 LLM을 호출하지 않으며, 핵심 시연에도 LLM이나 외부 네트워크가 필요하지 않습니다.

## 빠른 시작

처음 사용하는 경우 웹 UI부터 시작하십시오. macOS 또는 Linux에서 Python 3.12와 `uv`를 설치한 뒤 터미널에서 다음 명령을 실행합니다. Windows의 실제 로그 업로드는 지원 완료로 검증되지 않았습니다.

```bash
git clone https://github.com/misosos/ai-security-log-analyzer.git
cd ai-security-log-analyzer
uv sync --locked --dev
uv run python -m app.local_web
```

서버가 준비되면 `http://127.0.0.1:8000/`을 안내하고 기본 브라우저를 한 번 엽니다. 브라우저가 열리지 않으면 안내된 주소를 직접 여십시오. 브라우저 자동 열기를 원하지 않으면 `--no-browser`를 붙입니다. 기본 포트는 8000이며, 충돌할 때만 `--port 8001`처럼 1024~65535 사이의 포트를 하나 지정할 수 있습니다. host는 언제나 `127.0.0.1`이고 외부 인터페이스 지정과 `--reload`는 지원하지 않습니다. 종료는 실행한 터미널에서 `Ctrl+C`입니다. 이것은 현재 컴퓨터에서 직접 사용하는 전경 개발 실행기이며 hosted 배포가 아닙니다.

로컬 실제 로그 업로드의 임시 파일 보호는 플랫폼의 `O_NOFOLLOW` 지원을 요구합니다. 지원하지 않는 플랫폼에서는 업로드가 고정 오류로 거부됩니다. Windows에서 전체 업로드·브라우저 흐름은 아직 검증되지 않았으므로 이 문서를 Windows 지원 완료의 근거로 사용하지 마십시오.

첫 화면에서 **샘플로 체험하기**를 누르면 사용자 파일 없이 합성 로그의 조사 사례·Timeline을 볼 수 있습니다. 실제 로그는 **내 로그 분석하기**에서 세 칸에 각각 애플리케이션 인증 로그(`sample_logs/brute_force.log`), SSH 인증 로그(`sample_logs/ssh_auth.log`), 웹 접근 로그(`sample_logs/web_shell.log`) 형식의 UTF-8 파일을 넣습니다. 세 sample 파일로도 로컬 입력 절차를 연습할 수 있습니다. 결과의 **HTML 보고서 다운로드**는 현재 탭의 응답에서 대상별 보고서를 저장하며, 사례 Timeline 전체를 포함하지 않습니다. 샘플 결과는 실제 조직 환경의 보안 상태를 증명하지 않습니다.

입력 한계는 파일당 32 KiB, 합계 80 KiB, multipart 요청 전체 96 KiB, 한 줄 2048바이트, 파일당 512줄입니다. 압축 파일은 지원하지 않습니다. 분석은 외부 LLM을 호출하지 않습니다. 로그·결과·보고서를 서버에 영구 저장하지 않으며 정상·오류·취소·timeout 종료 때 요청별 임시 파일을 정리합니다. 프로세스나 호스트의 비정상 종료 뒤에는 임시 파일 잔존 가능성이 있습니다. 다운로드한 보고서는 민감한 조사 자료이므로 안전하게 저장·공유·삭제하십시오. 이 경로는 공개 인터넷 업로드나 실시간 수집 기능이 아닙니다. 포트 포워딩 및 `0.0.0.0` 바인딩을 하지 마십시오.

첫 실행이 막히면 `uv sync --locked --dev` 완료 여부를 확인하고, 포트 충돌 메시지가 나오면 해당 로컬 서버를 종료하거나 다른 허용 포트를 지정하십시오. 브라우저가 열리지 않으면 출력된 주소를 직접 여십시오. 분석 오류가 나오면 세 입력칸의 파일 종류, UTF-8, 크기·줄 한계를 확인하고 화면의 필드별 오류와 복구 행동을 따르십시오. 결과가 비어 보인다고 안전하다는 뜻은 아닙니다. Safari·키보드·확대 동작은 사용자 환경에서도 확인하십시오. 릴리스 후보에서 확인한 범위와 미검증 범위는 아래 표를 참고하십시오.

### 지원 환경과 검증 범위

| 환경 | 현재 상태 | 근거·남은 확인 |
| --- | --- | --- |
| macOS Apple Silicon | 로컬 자동·일부 Safari 수동 검증됨 | Python 3.12 locked 설치, launcher·loopback API·전체 테스트. Safari keyboard-only 주요 흐름·visible focus·실제 200% 확대·가능한 최소 창 너비·콘솔 오류 부재는 사용자 수동 확인. 정확한 320 CSS px 측정과 일부 VoiceOver 읽기는 미검증 |
| Linux | CI 자동 테스트 범위 | Ubuntu 24.04/Python 3.12 workflow. 실제 호스트·브라우저 수동 검증은 별도 |
| Windows | 제한적 | `O_NOFOLLOW` 미지원 시 실제 업로드 거부; 전체 업로드 흐름 미검증 |
| Hosted server | 지원 안 함 | 인증·인가·tenant isolation 없음 |
| Public internet | 노출 금지 | 실제 로그 업로드 보안 gate 미충족 |

`v0.2.0`의 범위와 제한은 [변경 이력](CHANGELOG.md), [릴리스 노트](docs/releases/v0.2.0.md), [릴리스 체크리스트](docs/release_checklist.md)에 기록했다. v0.1.0은 [이전 릴리스 노트](docs/releases/v0.1.0.md)에 보존한다. 라이선스는 [MIT](LICENSE)이며 저작권 표기는 `Copyright (c) 2026 misosos`다. 비공개 취약점 신고는 사용자가 활성화를 확인한 GitHub `Report a vulnerability` 경로를 따른다([SECURITY](SECURITY.md)). 릴리스 후보의 원격 CI와 Safari WebDriver 주요 흐름을 확인했다. 실제 운영환경 탐지율·WCAG 2.2 AA 준수·hosted 배포를 주장하지 않는다.

### 업데이트와 삭제

먼저 Ctrl+C로 서버를 종료하고 `git status`로 local change와 미추적 보고서를 확인한다. Clean working tree에서만 다음을 실행한다.

```bash
git status
git pull --ff-only
uv sync --locked --dev
```

삭제할 때는 사용자가 저장한 HTML 보고서의 위치를 먼저 확인한다. 저장소를 제거해도 브라우저 다운로드 파일은 자동 삭제되지 않는다. 보고서는 민감한 조사 자료이므로 별도로 확인해 안전하게 삭제한다. 저장소 디렉터리 자체의 삭제는 내용을 확인한 사용자가 명시적으로 선택해야 하며, 여기에는 재귀 삭제 명령을 제공하지 않는다.

### 기존 CLI와 개발 API

CLI 도움말:

```bash
uv run python -m app.main --help
```

`--linux-audit PATH`와 `--html-report PATH`가 표시됩니다.

### 기본 sample logs 분석

```bash
uv run python -m app.main
```

이 명령은 저장소의 `sample_logs/brute_force.log`, `sample_logs/ssh_auth.log`, `sample_logs/web_shell.log`를 한 번씩 읽어 기존 텍스트 보고서를 출력합니다. 출력에는 탐지 근거, 위험도, 신뢰도와 지원되는 상관관계가 포함됩니다.

### 독립형 HTML 조사 보고서 생성

```bash
uv run python -m app.main --html-report investigation.html
```

macOS에서는 생성된 파일을 다음과 같이 직접 열 수 있습니다.

```bash
open investigation.html
```

CLI가 브라우저를 자동으로 열지는 않습니다. 같은 대상에 다시 쓰지 않으므로 재시연 전에는 아래의 [안전한 정리](#안전한-정리)를 따르십시오.

### 개발 API를 직접 실행하고 상태 확인

첫 번째 터미널:

```bash
uv run uvicorn app.api:app --host 127.0.0.1 --port 8000 --no-access-log --no-proxy-headers
```

두 번째 터미널:

```bash
curl --fail --silent http://127.0.0.1:8000/api/health
```

예상 응답은 `{"status":"ok"}`입니다. 기본 개발 API는 인증이 없으므로 인터넷에 공개하지 마십시오.

합성 샘플 조사 API는 파일·본문·query 없이 호출합니다.

```bash
curl -X POST http://127.0.0.1:8000/api/v1/investigations/sample
```

응답은 `합성 샘플 결과`로 표시되는 개인정보 제한 JSON이며 실제 조직의 보안 상태를 뜻하지 않습니다. 같은 분석 결과로 만든 대상별 standalone HTML이 `report_export`에 포함됩니다. 샘플 요청 제한은 단일 프로세스 범위이므로 공개 배포용 edge 제한을 대신하지 않습니다.

### 로컬 웹 체험과 실제 로그 분석

위 명령으로 개발 서버를 `127.0.0.1`에 바인딩한 뒤 `http://127.0.0.1:8000/`을 여세요. **샘플로 체험하기**가 첫 번째 경로입니다. 직접 실행한 로컬 서버에서만 **내 로그 분석하기**의 애플리케이션 인증·SSH 인증·웹 접근 로그를 각각 선택할 수 있습니다. `POST /api/v1/investigations`는 세 multipart field `application_file`, `ssh_file`, `access_file`을 정확히 한 번씩 받고, loopback client와 고정 loopback Host를 확인합니다. 교차 출처 Origin과 forwarding header를 거부합니다. 확장자·MIME·사용자 filename은 신뢰하지 않습니다. Linux Audit, archive와 외부 LLM은 이 경계에서 처리하지 않습니다.

각 파일의 decoded 상한은 32 KiB, 합계는 80 KiB, multipart envelope는 96 KiB, 한 줄은 2048바이트, 파일당 512줄입니다. 업로드 처리와 분석은 각각 10초, 동시 분석은 1개, 요청은 프로세스당 60초에 6회로 제한합니다. 이는 작은 로컬 학습·초기 조사 용도입니다. 기준 측정에서 기존 합성 세 파일은 총 2001바이트·27줄·분석 약 0.05초였고, 20회 반복한 입력은 약 40020바이트·540줄·약 0.22초였습니다. 측정값은 해당 개발 환경의 참고치이지 모든 로그의 처리시간 보장은 아닙니다. 특히 ASGI 서버/프록시가 앱에 넘기기 전 보유한 단일 네트워크 청크에는 앱 제한을 적용할 수 없으므로 공개 업로드 보호로 해석하지 마십시오.

요청별 임시 디렉터리는 `0700`, 고정 내부 파일은 `0600`으로 만들고 정상 응답, 검증·분석·보고서 실패, 취소와 timeout 때 알려진 디렉터리를 정리합니다. timeout의 별도 worker process는 종료하고 정리 후 응답합니다. 프로세스 또는 호스트가 비정상 종료되면 orphan 임시 파일 삭제를 보장하지 않습니다. 로그·분석 결과·보고서는 서버의 영구 저장소에 보관하지 않으며, 결과는 현재 브라우저 탭 메모리에만 둡니다. HTML 다운로드는 사용자 클릭 때 Blob으로 만들고 서버에 재요청하지 않습니다. 현재 형식은 대상별 결정적 조사 보고서이며 사례 Timeline 전체는 포함하지 않습니다. 모든 HTML 보고서는 원래 HTTP 요청 경로와 full query를 표시하지 않지만 Path Traversal 일치 패턴과 승인된 상태 근거는 유지합니다. 다운로드 파일은 민감한 조사 자료로 안전하게 저장·공유·삭제하십시오.

이 local endpoint의 loopback 확인은 인증이나 방화벽을 대신하지 않습니다. 위 실행 명령은 Uvicorn의 URL query가 포함될 수 있는 access log와 proxy-header 신뢰를 끕니다. 다른 실행·프록시 구성을 쓸 경우 동일한 로그 비노출과 client 주소 검증을 다시 입증해야 합니다. 기존 `/api/analyze`는 deprecated이며 상위 구조만 유지하고 nested 값은 개인정보 안전 projection으로 변경되었습니다. 또한 whole-file read, filename suffix, 인증·rate 제한 부재 등 기존 한계가 있으므로 공개용으로 사용하지 마십시오. `0.0.0.0` 바인딩, 포트 포워딩과 무인증 hosted upload는 금지입니다. 실제 Safari·키보드·확대·WCAG 검증은 별도로 수행해야 합니다. 분석 결과는 침해 확정이 아닙니다.

## 입력 개요

지원 범위는 저장소가 구현하고 테스트하는 다음 형식으로 제한됩니다.

- 애플리케이션 인증 로그: timestamp와 `LEVEL EVENT key=value` 형식
- OpenSSH 인증 로그: password/public-key 성공·실패 레코드
- 웹 접근 로그: common/combined 스타일 레코드
- 선택적 Linux Audit 레코드: 동일 source·node·Audit event ID로 묶을 수 있는 compound event

모든 제품이나 임의의 로그 형식을 지원한다고 가정하지 마십시오. 기본 세 sample 경로는 `app/main.py`에 고정되어 있고, CLI에서 추가할 수 있는 입력은 반복 가능한 `--linux-audit PATH`입니다.

```bash
uv run python -m app.main \
  --linux-audit sample_logs/linux_audit_shared_memory_execution_contract_synthetic.log \
  --linux-audit sample_logs/linux_audit_session_process_co_observation_contract_synthetic.log
```

각 Linux Audit 경로는 서로 다른 비어 있지 않은 일반 파일이어야 합니다. 오류는 입력 번호만 표시하고 경로와 내부 예외는 출력하지 않습니다.

## 출력 개요

- **CLI 텍스트**: IP별 탐지, 위험도, 평가 근거와 상관관계를 출력합니다. Linux Audit 프로세스 관련 출력은 승인된 집계 위주이지만, 일반 인증 상관관계에는 계정 등 조사 필드가 나타날 수 있으므로 CLI도 민감하게 취급하십시오.
- **HTML 조사 보고서**: 한국어 UI, 결정적인 검토 순서, 타입이 지정된 증거, 보고서 로컬 `Account N` 별칭, 해석 한계와 고정 조사 단계를 포함하는 독립형 파일입니다. 원본 로그와 전체 HTTP query는 projection에 포함하지 않습니다.
- **Linux Audit 집계·조사 후보**: 별도 입력이 있을 때 기존 count-only 요약 다음에 셸·전송 도구·권한 변경 도구·임시 위치 실행의 고정 category와 건수·한계·다음 단계를 CLI에 표시합니다. 이는 악성 탐지나 공격 성공 판정이 아닙니다. 실행 파일명·상세 argv·PATH record·command line·`PROCTITLE`·raw record·세션 컨텍스트는 새 섹션에 표시하지 않습니다. 기존 선택적 보안 Linux Audit API, 인증·웹 조사 API, HTML, LLM의 계약은 변경하지 않았습니다.
- **Linux Audit 로컬 웹 조사 후보**: `uv run python -m app.local_web`로 직접 실행한 loopback 웹 화면의 별도 `Linux Audit 프로세스 실행 확인` 영역에서 UTF-8 Audit 파일 한 개를 선택할 수 있습니다. `POST /api/v1/investigations/linux-audit`는 기존 인증·웹 3파일 분석과 분리된 범주별 건수·우선순위·한계·다음 단계만 반환합니다. 실행 파일명·경로·인자·계정·Audit ID는 반환하지 않고 LLM·HTML 보고서·인증/웹 사례와 연결하지 않습니다. 이 기능은 공개 서버 업로드가 아닙니다.

Linux Audit 로컬 웹 입력 한계는 파일 64 KiB, multipart 요청 72 KiB, 한 줄 1024바이트, 최대 512줄입니다. 가장 큰 문서화된 합성 Audit fixture는 15,742바이트·68줄·최장 363바이트이고, 서로 다른 세 fixture 합계는 27,602바이트·125줄입니다. 이를 수용하는 소규모 로컬 학습 한계입니다. 요청별 private 임시 디렉터리(0700)와 파일(0600)은 정상·오류·취소·timeout 후 정리하지만 프로세스 강제 종료 뒤 잔존은 보장하지 않습니다. 이 제한은 ASGI 서버·프록시의 사전 할당이나 여러 worker 전체를 통합하는 rate limit이 아닙니다.
- **기본 API 응답**: `/api/analyze`는 기존 per-IP 결과, global correlation과 `ai_summary: null`을 반환합니다. 별도 보고서 route는 없으며 sample 및 loopback-only 조사 API의 같은 응답에 bounded `report_export`가 포함됩니다.
- **선택적 LLM 설명**: 개발자가 명시적으로 직접 호출할 때만 결정적 분석 결과를 설명합니다. 탐지·상관관계·위험도를 만들거나 변경하는 분석 권한은 없습니다.

## HTML 보고서 보안

HTML 보고서는 로컬에서 여는 하나의 민감한 파일입니다. JavaScript, 외부 CSS·글꼴·이미지·스크립트 또는 원격 네트워크 요청이 없고, 지원되는 플랫폼에서 `0600` 권한으로 생성됩니다. 대상 부모 디렉터리는 이미 존재하는 실제 디렉터리여야 하며, 파일명은 소문자 `.html`로 끝나야 합니다. 환경 변수와 `~`를 확장하지 않고, 부모를 만들지 않으며, 기존 파일이나 symlink를 덮어쓰지 않습니다.

원본 로그가 projection 밖에 있어도 보고서에는 IP, 위험도와 보안 관찰이 포함되므로 민감합니다. 조직의 접근 통제·공유·증거 보존·삭제 정책에 따라 보관하고 전달하며 제거하십시오. 이 프로젝트는 모든 환경에 적용되는 보존 기간을 정하지 않습니다. 파일시스템 race를 완전히 제거한다고 주장하지 않으므로 신뢰할 수 없는 사용자가 조상 디렉터리를 바꿀 수 없는 위치를 사용하십시오.

## 해석 한계

- 탐지는 침해 확인이 아닙니다.
- 상관관계는 인과관계가 아닙니다.
- 로그인 성공은 공격 성공이나 계정 침해의 증명이 아닙니다.
- HTTP 200은 파일 접근, 파일 내용 반환 또는 데이터 노출의 증명이 아닙니다.
- Password Spraying-like 관찰은 동일한 인증정보 재사용을 증명하지 않습니다.
- Linux Audit 집계는 관찰 수이며 고유 프로세스, 공격자 또는 사고 수가 아닙니다.
- 탐지가 없다는 사실은 악의적 활동이 없다는 뜻이 아닙니다.

## API 계약

기본 개발 애플리케이션은 다음 route만 등록합니다.

- `GET /api/health`
- `POST /api/analyze`

`POST /api/analyze`에는 `application_file`, `ssh_file`, `access_file` multipart 파일 세 개가 모두 필요합니다. 각 파일은 비어 있지 않은 `.log` 또는 `.txt`이고 10 MiB 이하여야 합니다. 응답의 `ai_summary`는 `null`이며 Gemini를 호출하지 않습니다. `/api/upload-test`, `/api/analyze-linux-audit`, `/internal/readiness`는 기본 앱에 없습니다.

보안 Linux Audit API의 `POST /api/analyze-linux-audit`는 명시적인 secured app construction에서만 등록됩니다. 반복 가능한 multipart 필드 이름은 `linux_audit_files`입니다. bearer 인증, `linux-audit:analyze` 권한, audit sink와 용량 제한이 필요하며 응답은 UUID, 완료 상태와 count-only 요약으로 제한됩니다. 기본 시연에서는 이 production 전용 route를 사용하지 마십시오. 자세한 배포 전제는 [Linux Audit API 배포 보안](docs/linux_audit_api_deployment_security.md)을 따릅니다.

운영용 factory target은 `uvicorn app.deployment.asgi:create_linux_audit_api_app --factory`입니다. 이 경계는 `CREDENTIALS_DIRECTORY`, `LINUX_AUDIT_API_PRINCIPAL_ID`, `LINUX_AUDIT_API_MAX_CONCURRENT_ANALYSES`와 systemd credential 파일 `linux-audit-api-operator-token`을 사용합니다. 운영 전에는 systemd, journald, Nginx, TLS, host 권한과 보존 정책을 별도로 검증해야 하며 저장소 테스트만으로 Linux production host가 승인되지는 않습니다. Production 전용 `GET /internal/readiness`는 OpenAPI에서 제외되고 내부에서만 사용해야 합니다.

## 테스트

전체 회귀 테스트:

```bash
uv run pytest
```

테스트는 합성 fixture를 사용합니다. 실제 운영 호스트의 TLS, 방화벽, systemd credential 전달, journald 지속성, Nginx 동작, 보존 정책 또는 부하 용량을 승인하지 않습니다.

## 프로젝트 구조

```text
app/main.py                         CLI orchestration
app/analyzer/pipeline.py            로딩·탐지·상관관계·위험도 흐름
app/analyzer/report.py              기존 CLI 텍스트 보고서
app/analyzer/report_projection.py   개인정보가 제한된 불변 HTML projection
app/analyzer/html_report.py         순수 독립형 HTML renderer
app/analyzer/html_report_file.py    검증·0600·no-overwrite 보안 writer
app/api.py                          기본 API와 선택적 secured API 구성
sample_logs/                        비밀이 아닌 합성 sample/fixture
tests/                              단위·경계·통합·수용 테스트
docs/                               설계, 배포 경계와 시연 문서
```

`frontend/`는 합성 샘플 Landing, loopback-only 실제 로그 업로드, 결과 개요와 사례·Timeline 상세 및 HTML 다운로드, 명시적으로 설정한 단일 파일의 bounded 로컬 실시간 모니터링 화면을 지원합니다. `docs/architecture.md`, `docs/evaluation.md`, `app/detector/suspicious_file.py`는 비어 있는 placeholder이며 지원 기능이 아닙니다. 인증된 hosted upload, 원격·다중 source 수집, database, 자동 차단, 자동 incident verdict와 보호된 상세 증거 API는 구현되어 있지 않습니다.

향후 v0.3 방향은 [안전한 로컬 설정·Collector 설계](docs/local_collector_v030_design.md)에 구분해 기록했습니다. 단일 application 로그의 trusted CLI 설정 마법사와 기본 설정 조회·삭제, 경로 없는 실행, 동일 파일 bounded checkpoint core는 구현됐습니다. [Phase 25.0 외부 로컬 collector 상호운용 gate](docs/local_collector_interop_gate_25_0.md)에 이어 [Phase 25.1 격리형 Vector 합성 SSH 실험](docs/vector_collector_pilot_25_1.md)을 수행했으나, 긴 줄 누락·rotation 순서 변경·copytruncate/연결 종료 gap과 analyzer ack 부재로 production 연계는 NO-GO입니다. Vector는 설치·자동 실행·CI 필수 단계에 포함되지 않습니다. 기존 tailer는 유지하며 rotation 자동 복구·다중 source·별도 최소 권한 collector는 후속 gate입니다. 운영 무유실은 약속하지 않습니다.

## 오프라인 탐지 평가 기준선

작은 합성 경계 corpus에서 현재 parser·탐지·관계·risk·조사 사례 계약을 분리해 평가합니다.

```bash
uv run python -m app.evaluation
uv run python -m app.evaluation --format json
uv run python -m app.evaluation --scenario brute_success
```

결과는 stdout에만 출력되며 운영 환경 탐지율이나 침해 확률이 아닙니다. 현재 SSH·parser-only·정상 활동 및 모호한 자동화 시나리오를 포함합니다. 모호한 운영 활동은 일반 TP/FP/TN 계산에서 제외합니다. Web Scanning-like의 support는 양성 라벨 시나리오 수로, 현재 정확 임계값·초과·60초 경계 3개다. 요청 순열과 반복 요청 검증은 별도 불변식이며 support에 포함하지 않습니다. 고정 라벨·metric·한계·외부 데이터셋 검토는 [평가 문서](docs/detection_evaluation.md)에 있습니다. 기존 탐지 임계값과 시간 범위는 유지하며, 여러 로그인 성공 후보의 관계는 가장 가까운 유일한 후속 endpoint를 입력 순서와 무관하게 선택합니다.

Linux Audit 프로세스 실행 조사는 같은 명령의 **별도 21개 합성 시나리오 section**에서 평가하며 위 79개 IP 탐지 metric에 합치지 않습니다. CLI에서만 조사 후보를 표시하고, 합성 일치도를 실제 운영환경 악성 탐지율로 일반화하지 않습니다.

## 안전한 정리

아래 명령은 위 빠른 시작에서 현재 디렉터리에 직접 만든 `investigation.html`만 제거합니다. 다른 보고서나 디렉터리에 사용하지 마십시오.

```bash
rm -- investigation.html
```

## 추가 문서

- [5–7분 최종 시연 가이드](docs/final_demo_guide.md)
- [HTML 조사 보고서 설계](docs/html_investigation_report_design.md)
- [Release readiness](docs/release_readiness.md)
- [Linux Audit 프로세스 실행](docs/linux_audit_process_execution.md)
- [Shared-memory 실행 검토](docs/shared_memory_execution_review.md)
- [Session/process 동시 관찰](docs/linux_audit_session_process_review.md)
- [Linux Audit API 경계](docs/linux_audit_api_design.md)
- [Linux Audit API 보안 설계](docs/linux_audit_api_security_design.md)
- [Linux Audit API 배포 보안](docs/linux_audit_api_deployment_security.md)

보안 이슈에는 합성 데이터로 재현할 수 있는 관찰 증거, 영향받는 입력 또는 route, 재현 단계와 개인정보 영향을 포함하십시오. 실제 credential, 운영 로그, private key 또는 복사한 운영 증거는 포함하지 마십시오.
