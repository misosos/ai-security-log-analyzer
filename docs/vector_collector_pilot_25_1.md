# Phase 25.1 — 격리형 Vector SSH 수집 실험

**판정: NO-GO — 현 구성의 production 연계 및 연속성 주장 금지.** 합성 SSH의 정상 append에서는 원문 바이트·순서와 기존 분석 의미가 같았지만, 실험에서 긴 줄의 무통지 누락, rename 시 세대 간 순서 역전, copytruncate 및 receiver disconnect 후 누락을 관찰했다. 테스트용 `PILOT_SEQ`는 실제 SSH 로그에 없는 장치이므로 이 누락을 제품에서 검출할 근거가 없다. Vector의 file checkpoint는 분석기의 queue ack·analysis commit과 하나의 transaction이 아니다. 기존 tailer, checkpoint, API, SSE, UI 및 production dependency는 변경하지 않았다.

## 시작 기준과 공급망

- Phase 25.0 기준 `b398fde43b0727b57b9633a857c33a9d05c636a4`, local/remote `main` 일치·clean, 해당 [CI](https://github.com/misosos/ai-security-log-analyzer/actions/runs/39127307442) 성공: Ubuntu 2,300 passed, 기존 경고 2개. 로컬 변경 전 2,300 passed, 경고 2개. v0.2.0 공개 tag/Release target은 `2520e317475f96d48b4bfeef8f7ee04d63720308`로 유지.
- [공식 v0.59.0 release](https://github.com/vectordotdev/vector/releases/tag/v0.59.0)의 source tag commit `a3231c76bdea5078bc54c205cf89f5a1ceddbb73`. 같은 commit의 [Release Suite](https://github.com/vectordotdev/vector/actions/runs/37474254292)는 macOS arm64·Linux x86_64 GNU build, checksum 생성, 게시 job 성공. 실제 실행된 Linux archive의 `vector --version`은 `0.59.0`, `x86_64-unknown-linux-gnu`, `a3231c7`을 보고했다.
- 공식 release metadata 및 `SHA256SUMS`와 대조한 Linux x86_64 GNU archive: 57,855,328 bytes, SHA-256 `fb15878d1cd68445e0658792a8fa7ccf02ae8a353c6cc5d6fe867b171993e19f`. macOS arm64 archive metadata: 52,687,645 bytes, SHA-256 `6f0cd290c90ea2cfc7cb3c10eca32fc897f0b958b60d48ad2867a91d5585363c` (다운로드·실행하지 않음). `SHA256SUMS` asset 자체 SHA-256: `53d0372f2a26e377a2bf88ac8d485f7c890d284b28ad8e0897085571c2eb98fa`.
- Archive는 절대/상위 경로·symlink 없이 `bin/vector` 한 executable, LICENSE·NOTICE·third-party license·예시 config·사용하지 않은 service template 포함. Installer/package manager는 사용하지 않았다. 이 검사는 공개 release와 binary의 **독립적인** 서명·SLSA provenance·재현 빌드 증명이 아니다. GitHub attestation API에서 해당 archive의 attestation을 확인하지 못했다. 실험에서만 이 잔여 위험을 수용했고 production 채택 근거로 확대하지 않는다.
- 격리 base: 공식 `python:3.12-slim` Linux/amd64 digest `sha256:2b4f19dae3a777dfc3b76730bda1e82e1f66ab2a2686fa93ca78edbfb4f04ffe`. Docker Desktop/Engine 29.8.2, macOS arm64 host에서 **에뮬레이션한 Linux/amd64** container. 네이티브 Ubuntu x86_64와 macOS Vector 실행은 NOT_TESTED.

## 실행 경계와 재현

다운로드는 전용 0700 임시 디렉터리에서 checksum 대조 후 수행했고 실행 컨테이너는 별도였다. 실행은 UID 502 비root, `--network none --read-only --cap-drop ALL --security-opt no-new-privileges --memory 512m --cpus 1 --pids-limit 64`, 16 MiB `/tmp` tmpfs, synthetic source/config/state/socket을 담은 `/tmp/pilot` 0700, binary와 test harness read-only mount, 안전 요약 출력 디렉터리만 writable bind mount였다. Docker socket, host home, repository, 실제 로그·기본 monitor config·credential, host port는 mount/전달하지 않았다. 격리 probe에서 network deny·root filesystem read-only·socket 부재와 UID를 확인했다. Vector 자체 stdout/stderr는 private 0600 파일에 bounded capture했고 원문을 공개 출력하지 않았다. child umask 077과 1 MiB file-size limit를 적용했다.

`tests/vector_collector_pilot_25_1.py`는 독립적인 **test-only** harness이며 Vector를 CI/pytest에서 자동 다운로드·실행하지 않는다. 입력은 합성 SSH 한 파일이고 socket receiver는 단일 연결, LF frame ≤4096 bytes, strict UTF-8, 256 records/256 KiB, 0.2초 I/O timeout, 0600 socket·0700 parent를 사용한다. Linux `SO_PEERCRED`로 같은 UID를 확인한다. macOS receiver에서는 같은 peer credential 계약을 확인하지 않았으므로 인증됐다고 주장하지 않는다. 사용자가 개발용으로 재현할 때는 정확한 binary digest를 먼저 검증한 뒤 Docker에서 `python /opt/pilot.py --binary /opt/vector/bin/vector --work /tmp/pilot --summary-output /work/safe-summary.json`을 위 격리 옵션으로 실행한다. 로컬 기본 경로나 사용자 파일을 넣지 않는다.

Config는 `file` source 한 개, `read_from=end`, `fingerprint.strategy=device_and_inode`, `max_line_bytes=2048`, 100 ms discovery, transform 없음, `unix_stream` socket sink, `raw_message`+`newline_delimited`, memory buffer 32 events/`when_full=block`, API off, private `data_dir`다. 실제 `vector validate --skip-healthchecks --config-json`이 network-none 안에서 통과했다. [file source 문서](https://vector.dev/docs/reference/configuration/sources/file/)는 `read_from`, checkpoint·rotation과 초과 줄의 **discard**를 설명하고, [socket sink 문서](https://vector.dev/docs/reference/configuration/sinks/socket/)는 raw `message`와 LF framing·UDS를 설명한다. 이 문서는 프로젝트 보장이 아니라 제품 계약이다.

## 합성 시나리오 결과

Sequence marker는 실험 관찰용 suffix다. 표의 expected→received는 **한 실행의 최대 7초 관찰 창에서 본 값**이며, 재시작·경쟁 조건을 일반 보장으로 확대하지 않는다. 정상 append의 16줄+동일 내용 2줄, 64줄, 분석 6줄 및 256줄 제한 수신에서 바이트·순서가 같았다. 다른 timing의 앞선 실행에서는 split UTF-8 partial이 receiver의 `FRAME_NOT_UTF8`로 실패했지만 후속 실행에서는 완성 LF 전 0건·완성 뒤 1건이 관찰됐다. 실패를 재시도로 지우지 않고 timing-sensitive 결과로 기록한다.

| 상황 | 관찰 | 판정·한계 |
|---|---|---|
| 시작/FROM_END | 기존 seq0 제외, 새 seq1만 도착 | PASS, 이 파일·실행 한정 |
| 정상 append/동일 내용 반복 | 1–17,17 → 1–17,17; byte-equal | PASS |
| 분석용 실패→성공 | 1–6 → 1–6; byte-equal | PASS, 아래 parity 조건 한정 |
| 64줄/256줄 | 순서·바이트 동일 | PASS; 실제 buffer 포화 입증은 아님 |
| partial LF와 UTF-8 분할 | 일부 실행 PASS, 한 실행 `FRAME_NOT_UTF8` | PARTIAL; production 적합성 NO-GO |
| 2047/2050-byte LF 포함 줄 | 짧은 줄 전달, 긴 줄 누락. LF 포함 2049-byte 줄은 전달되는 실행을 관찰 | NO-GO: receiver에 명시적 gap 없음. `max_line_bytes`가 LF 제외 기준인지 공식·경계 확인 필요 |
| invalid UTF-8 | receiver에 정상 record 없음 | collector drop인지 framing/인코딩인지 추가 확인 필요, NOT_COVERED |
| 같은 data_dir 정상 재시작 | 1, 중지 중 append 2 → 1,2 | PASS 관찰, durable analyzer ack 보장 아님 |
| 새 data_dir epoch | 과거 줄 제외, 새 seq2만 | PASS/FROM_END; 잃은 prefix 복구 아님 |
| rename + 이전 writer late append | 1,2,3 → 1,3,2 | NO-GO: 원래 append 순서 불변 아님 |
| copytruncate + 재성장 | 1,2 → 1 | NO-GO: 누락 관찰 |
| receiver 연결 종료 | 1,2 → 1 | NO-GO: 재연결 기간 누락 관찰 |
| receiver 읽기 지연 | 256/256 전달 | PARTIAL: 지연 실험일 뿐 실제 buffer-full/drop/block/metric 미입증 |

Vector 내부 checkpoint는 private `data_dir`에 한 파일(관찰 크기 약 127–131 bytes)로 생성됐고 child umask 077 적용 후 mode 0600, parent 0700이었다. 파일에는 검사한 literal source path/filename/IP/원문 marker와 합성 개인정보 canary가 보이지 않았지만 `fingerprint`·`inode` 필드 이름은 관찰됐다. 따라서 파일 identity는 private metadata로 취급한다. binary encoding이나 offset metadata의 정확한 의미·보존 기간은 추정하지 않는다. 파일 source는 [공식 문서](https://vector.dev/docs/reference/configuration/sources/file/)상 읽은 위치를 checkpoint한다. socket 전달 성공은 analyzer의 lease ack·분석 commit·publication과 연결되지 않는다. 따라서 두 checkpoint를 추측으로 병합하지 않는다.

## 분석 의미와 개인정보

`--verify-summary`는 실제 Vector가 수신한 합성 6줄의 byte digest·순서를 fixture와 확인한 뒤, 같은 줄의 기존 SSH batch parser 결과와 기존 internal live tailer normalized events를 비교한다. detection, 실패→성공·Brute Force→성공 relation, risk, case trusted state도 비교해 일치했다. **깨진 순서/누락 시나리오에는 parity를 주장하지 않는다.** 정렬·중복 제거·후처리로 결과를 맞추지 않았다. 실제 SSH 로그에는 marker가 없으므로 upstream duplicate/gap을 탐지할 수 없다.

원문은 합성 source, Vector memory, socket, receiver의 trusted memory에 존재한다. safe summary에는 count·bytes·fixture sequence·synthetic digest·고정 status만 둔다. 별도 `privacy` 시나리오에 account/IP/filename/query/raw-line/exception **합성 canary**를 넣어 한 줄 전달을 확인했고 private stdout/stderr·state·safe summary에는 canary가 나타나지 않았다. 그러나 Vector의 private stderr에는 socket disconnect 시 합성 source path가 나타난 다른 실행이 있었으므로 운영 로그를 공개하면 안 된다. 검사한 checkpoint에 literal canary가 없었다는 것은 저장 형식 전체의 개인정보 부재를 증명하지 않는다. config validation output도 합성 config path를 포함할 수 있다. API/SSE/UI/LLM을 시작하지 않았으며 노출이 없었다는 말은 **연결하지 않았기 때문**이지 향후 IPC privacy 검증의 대체가 아니다. 실제 개인정보는 사용하지 않았다. 보고서·raw capture·state는 추적하지 않고 정리하며 secure erase는 주장하지 않는다.

## 남은 gate

Production 연계에는 독립적인 artifact provenance, native macOS 및 native Linux 검증, peer credential/동일 UID 위협, 원문 보존·line-length 오류의 명시적 fail-closed, rename/copytruncate·partial/invalid UTF-8의 안전한 상태, 재연결/queue 포화의 loss signal, upstream durable sequence·epoch와 application-level ack의 별도 설계·승인이 필요하다. Vector checkpoint만으로 analyzer commit을 복원할 수 없다. production IPC receiver·framing protocol·checkpoint schema·wizard·child process·service는 구현하지 않았다. 외부 전송, system service, root 권한도 사용하지 않았다. 실험 후 전용 temp의 archive·binary·config·source·socket·state·raw output을 확인해 삭제했고 Vector process/container/volume/socket/listener 잔존은 없었다. **공유 Docker image cache는 남아 있으며 secure erase를 주장하지 않는다.**

개발용 측정은 4회(분석 시나리오 3회; 첫 회 warm-up 포함)에서 config validation median/p95/max가 시작 615.5/644/644 ms, 정상 18줄 603.5/612/612 ms, 64줄 605/649/649 ms, 256줄 읽기 지연 608.5/644/644 ms였다. Vector process 시작→첫 수신의 같은 수치는 시작 924.5/929/929 ms, 정상 900.5/931/931 ms, 64줄 920.5/924/924 ms, 256줄 1588/1589/1589 ms다. 이 수치에는 fixture 준비를 위한 **고정 0.8초 대기**(partial은 추가 0.5초)가 들어가므로 순수 append→delivery latency가 아니다. 정상 종료는 최종 실행에서 약 0.1초, 일시적 Docker 관찰은 약 104 MiB/512 MiB·6 PID였고 지속 idle CPU·최대 memory·실제 buffer 포화는 측정하지 못했다. 분석용 6줄의 batch/internal-tail/Vector equality는 통과했지만 collector의 실제 payload를 analyzer에 직접 주입하지 않고 digest를 확인한 동일 fixture로 비교했다는 점도 한계다. Docker emulation, startup·poll interval, scheduling과 네트워크 차단이 수치에 영향을 준다. 운영 SLA가 아니며 한 번의 정상 전달로 무유실·exactly-once·장애 복구를 주장하지 않는다.
