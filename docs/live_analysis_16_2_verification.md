# Phase 16.2 보강 검증 기록 (2026-10-13)

범위는 기존 production 의미와 API/SSE/UI schema를 변경하지 않는 테스트·측정이다. `PASS`는 해당 fault를 독립 test ID로 주입하고 queue, revision, terminal/resume 경계를 확인했다는 뜻이다. 아래 `D/A/P`는 각각 detection/analysis/publication 내부 확정 revision이다. Publication의 공개 snapshot은 detection revision을 반영할 수 있으므로 테스트는 실제 내부 buffer cursor를 비교한다. 실패 후 `FAILED`에서는 step/resume을 금지하고 close만 허용한다. `DEGRADED`에서는 명시적 resume만 허용한다. Raw 예외·IP·계정·경로가 안전 오류/snapshot에 섞이지 않는지도 확인했다. 이 검증은 원자적 transaction이나 exactly-once 보장이 아니다.

| 번호 | fault point | 결과 | worker / queue / D/A/P / ack·release | 근거 |
| ---: | --- | --- | --- | --- |
| 01 | poll | PASS | FAILED / empty / 0/0/0 / 0·0 | `test_individual_fault_boundary[01_poll]` |
| 02 | lease | PASS | FAILED / available 5 / 0/0/0 / 0·0 | `[02_lease]` |
| 03 | parse | PASS | DEGRADED / available 5 / 0/0/0 / 0·1 | `[03_parse]` |
| 04 | parse batch validation | PASS | DEGRADED / available 5 / 0/0/0 / 0·1 | `[04_parse_batch_validation]` |
| 05 | detection prepare | PASS | DEGRADED / available 5 / 0/0/0 / 0·1 | `[05_detection_prepare]` |
| 06 | analysis correlation prepare | PASS | DEGRADED / available 5 / 0/0/0 / 0·1 | `[06_analysis_correlation_prepare]` |
| 07 | analysis risk prepare | PASS | DEGRADED / available 5 / 0/0/0 / 0·1 | `[07_analysis_risk_prepare]` |
| 08 | analysis case prepare | PASS | DEGRADED / available 5 / 0/0/0 / 0·1 | `[08_analysis_case_prepare]` |
| 09 | analysis safe projection | PASS | DEGRADED / available 5 / 0/0/0 / 0·1 | `[09_analysis_safe_projection]` |
| 10 | publication prepare | PASS | DEGRADED / available 5 / 0/0/0 / 0·1 | `[10_publication_prepare]` |
| 11 | cross-proposal validation | PASS | DEGRADED / available 5 / 0/0/0 / 0·1 | `[11_cross_proposal_validation]` |
| 12 | detection abort | PASS | FAILED / leased 5 / 0/0/0 / 0·0 | `[12_detection_abort]` |
| 13 | analysis abort | PASS | FAILED / leased 5 / 0/0/0 / 0·0 | `[13_analysis_abort]` |
| 14 | lease release | PASS | FAILED / leased 5 / 0/0/0 / 0·1 attempted | `[14_lease_release]` |
| 15 | queue ack | PASS | FAILED / leased 5 / 0/0/0 / 1 attempted·0 | `[15_queue_ack]` |
| 16 | queue ack 직후 | PASS | FAILED / empty / 0/0/0 / 1·0 | `[16_after_queue_ack]` |
| 17 | detection state swap | PASS | FAILED / empty / 0/0/0 / 1·0 | `[17_detection_state_swap]` |
| 18 | detection commit 직후 | PASS | FAILED / empty / 0/0/0 / 1·0; detection은 확인 가능한 마지막 state로 terminalize | `[18_after_detection_commit]` |
| 19 | analysis state swap | PASS | FAILED / empty / 1/0/0 / 1·0 | `[19_analysis_state_swap]` |
| 20 | analysis commit 직후 | PASS | FAILED / empty / 1/1/0 / 1·0 | `[20_after_analysis_commit]` |
| 21 | publication state swap | PASS | FAILED / empty / 1/1/0 / 1·0 | `[21_publication_state_swap]` |
| 22 | publication commit 직후 | PASS | FAILED / empty / 1/1/1 / 1·0; 자동 재게시 없음 | `[22_after_publication_commit]` |
| 23 | worker summary 갱신 | PASS | FAILED / empty / 1/1/1 / 1·0; 같은 revision 재처리 없음 | `[23_worker_summary]` |
| 24 | runner notify_change | PASS | runner FAILED, worker READY / empty / 1/1/1 / 1·0; runner 추가 step 없음 | `test_fault_point_24_runner_notify_change_is_terminal_without_reprocessing` |
| 25 | close | PASS | 첫 close FAILED, 재시도 STOPPED / empty / 0/0/0 / 0·0; FD 정리 | `test_fault_point_25_close_fails_bounded_then_can_retry_cleanup` |

Ack 전 계산 실패는 proposal abort→lease release→FIFO 복구→DEGRADED이다. Abort/release 자체 실패는 ownership을 추측하지 않고 FAILED다. Ack 실패는 release를 추측하지 않는다. Ack 후 detection·analysis·publication·summary 실패는 rollback·자동 retry·재게시 없이 terminal FAILED다. 18번의 commit 직후 fault는 detection의 일부 state swap을 공개 성공으로 표시하지 않도록 마지막 확인 state로 terminalize한다. 20번의 analysis commit 직후 fault는 실제 analysis revision이 1일 수 있으나 publication은 0이며 성공 step은 아니다. 22번의 publication commit 직후 fault는 실제 buffer revision이 1일 수 있으나 worker는 terminal이고 자동 재게시하지 않는다. Process crash/`MemoryError`가 원자적으로 처리된다고 주장하지 않는다.

## 같은 process·같은 prefix 측정

재현 명령: `uv run python -m tests.benchmark_live_analysis_16_2`. 개발 머신 Python 3.12, warm-up 2, 측정 12회. 같은 IP/계정의 합성 application 실패 255건(동일 event time) 뒤 성공 1건으로 **256 PARSED event / encoded raw 17,150 byte**의 확정 candidate prefix를 만든다. 마지막 성공 줄이 실제 poll→lease→parse→detection prepare→analysis prepare→cross check→ack→두 commit→기존 publication→안전 결과의 단일 worker step을 통과한다. 최종 결과는 활성 detection 1, relation 2, risk 1, case 1이다. 한 번의 step에서 256개의 *새* record를 처리하는 것은 기존 poll 16줄·lease 상한 32건 계약상 불가능하며, 255건은 앞선 bounded step들에서 이미 확정했다.

| 구간 (ms) | 표본 | median | p95 | max |
| --- | ---: | ---: | ---: | ---: |
| 256-prefix worker 전체 step, tracing 없음 | 12 | 7.237 | 7.992 | 7.992 |
| 동일 step의 analysis prepare, tracing 없음 | 12 | 5.115 | 5.543 | 5.543 |
| ack 반환 직후→세 commit→worker 요약, tracing 없음 | 12 | 0.046 | 0.135 | 0.135 |
| 동일 input의 analysis prepare, `tracemalloc` 사용 | 12 | 22.250 | 25.362 | 25.362 |

기존 Phase 16.1의 약 55.367ms는 `tracemalloc`을 켠 **단일** prepare 측정이며, Phase 16.2의 1.310ms는 instrumentation 없는 별도 단일 측정이었다. 이번 동일 input·동일 process 반복에서는 tracing 유무만으로 median 22.250ms 대 5.115ms의 차이가 재현됐다. 따라서 55ms와 1.31ms는 직접 비교할 수 없다. 남은 차이는 원래의 정확한 fixture 구성·tracing 시작 시점·warm-up·단일 표본 변동을 동일하게 복원하지 못했으므로 하나의 원인으로 단정하지 않는다.

실제 0.5초 runner 실행 중 application status HTTP 40회(warm-up 1회)는 median 2.459ms, p95 3.656ms, max 6.993ms였다. 4회 worker step 중 status 요청 3회가 step 실행 구간과 겹쳤고 16줄이 실제 ack됐다. HTTP 200과 schema version/source role을 매번 검증했다. 이 표본에서 256-prefix 전체 step p95는 0.5초 미만이고 status 지연도 현저한 stall을 보이지 않았다. 운영 SLA·최악 입력·지속 부하·p99 보장은 아니다.

## 동일 runtime lifecycle

`test_same_running_runtime_commits_cases_but_transmits_only_observations`는 실제 config→tail→detection→analysis→worker→publication→service→runner→FastAPI lifespan을 한 번 구성한다. 이 TestClient lifespan 검증은 초기 줄 미처리, 인증 실패 5건과 성공 1건 자동 step, 두 revision 일치, generic `failed_to_successful_login`과 `brute_force_to_successful_login`, risk 및 `CASE-BRUTE-SUCCESS-01`의 exact-endpoint supporting 1건, resident queue 0·active proposal 없음, 기존 `observation_changes` frame, status/OpenAPI/SSE의 analysis 상세·개인정보 비노출, lifespan 종료 후 FD 반환을 확인한다. 테스트 내부의 trusted analysis accessor만 관계·case를 조회한다.

별도 `uv run python -m tests.live_analysis_16_2_socket_smoke`는 실제 loopback socket 서버를 임시 synthetic config/source로 실행했다. `/api/health`·live status HTTP 200, 시작 전 줄 미처리, append 후 자동 publication, SSE `snapshot`→`observation_changes`, API/SSE analysis 비노출, SIGINT 종료 후 listener 해제·process FD 종료·임시 디렉터리 제거를 확인했다. 외부 process이므로 내부 relation/risk/case 확인은 위 동일 runtime TestClient 테스트에서 수행했다. Socket smoke에서는 OS process의 FD를 직접 개별 열거하지 않았으며 process 종료와 port 해제만 검증했다.

판정: **Phase 16.3 설계·구현 검토 GO (개발용 조건부)**. 현 합성 범위의 0.5초 budget에서는 초과를 관찰하지 않았다. 더 복잡한 다중 subject·case와 실제 사용 입력의 latency, OS socket shutdown, 브라우저 수용성은 별도 검증이 필요하다. Analysis API/SSE/UI 노출은 아직 하지 않는다.
