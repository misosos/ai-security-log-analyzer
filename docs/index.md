# 문서 지도

[README](../README.md)는 첫 사용과 핵심 한계를 안내한다. 아래 문서는 상세 계약, 설계 근거와 당시의 검증 범위를 보존한다. 과거 검증 수치는 현재 릴리스의 새 기능을 자동으로 승인하지 않는다.

## 시작·사용·릴리스

- [로컬 웹 시연](final_demo_guide.md) · [HTML 조사 보고서](html_investigation_report_design.md)
- [v0.4.0 릴리스 노트](releases/v0.4.0.md) · [v0.3.0](releases/v0.3.0.md) · [v0.2.0](releases/v0.2.0.md) · [v0.1.0](releases/v0.1.0.md)
- [릴리스 체크리스트](release_checklist.md) · [release readiness](release_readiness.md)

## Live monitoring·checkpoint

- [단일 파일 live 설계](live_log_monitoring_design.md) · [로컬 설정 마법사](monitor_setup_20.md) · [application·SSH 설정 통합 설계](monitor_setup_ssh_design_30_0.md) · [SSH 설정 구현](monitor_setup_ssh_30_1.md) · [관리·복구 통합 감사](monitor_setup_unified_audit_30_2.md) · [Ubuntu·사용자 수용 기록](monitor_setup_acceptance_30_3.md) · [checkpoint 계약](live_checkpoint_21.md)
- [분석 관계·위험도·사례 설계](live_analysis_correlation_case_design.md) · [SSH live 연결](ssh_live_analysis_integration_22_3.md) · [SSH 분석 감사](ssh_live_analysis_audit_22_4.md)
- [SSH checkpoint 복구](ssh_checkpoint_recovery_26_0.md) · [Ubuntu SSH 수용 기록](ssh_checkpoint_linux_acceptance_26_1.md)
- [checkpoint 잠금·장애 경계](live_checkpoint_21_2.md) · [별도 프로세스 재시작](live_checkpoint_21_3.md) · [명시적 epoch reset](live_checkpoint_epoch_reset_21_7.md) · [Linux reset 검증](live_checkpoint_epoch_reset_21_8_linux_audit.md)
- [축소 감지](live_rotation_21_1.md) · [poll/ack 경계](live_rotation_21_4.md) · [rotation handoff 검토](live_rotation_21_5.md) · [두 파일 세대 검토](live_rotation_21_6.md)
- [local collector 설계](local_collector_v030_design.md) · [상호운용 gate](local_collector_interop_gate_25_0.md) · [Vector 합성 pilot](vector_collector_pilot_25_1.md)
- [자동 보안 로그 수집 설계 gate](automatic_log_collection_design_34_0.md) — loopback TCP Syslog 후보와 framing·backpressure·trust/privacy 계약
- [Phase 35.1A Vector framing 선행조건 판정](vector_framing_preconditions_35_1a.md) — native socket framing `INCOMPATIBLE`, VRL 경로 `CUSTOM_FRAMING_UNPROVEN`; 기존 listener 불변
- [Phase 35.2 외부 collector JSON Lines 순수 core](collector_jsonl_adapter_core_35_2.md) — closed schema·bounded decoder/queue만 구현; Vector·socket·외부 process와 parser pipeline 연결은 NOT_TESTED, 실제 자료·조직 운영 NO_GO
- [Phase 35.3 외부 collector JSON Lines runtime](collector_jsonl_runtime_35_3.md) — 별도 loopback listener에서 합성 application·SSH 입력을 기존 결정적 pipeline에 내부 연결; 제한된 Ubuntu acceptance GO, Vector 미실행, 실제 자료·조직 운영 NO_GO
- [Phase 35.3A JSON Lines runtime Ubuntu reliability acceptance](collector_jsonl_runtime_linux_acceptance_35_3a.md) — 정확한 push run `40452774780`의 80회·queue·soak·cleanup 표식 통과; Ubuntu 합성 범위만 GO, Vector·실제 자료·조직 운영 NO_GO
- [Phase 35.4A Vector artifact·configuration·resource preflight](vector_artifact_preflight_35_4a.md) · [x86_64 preflight manifest](artifacts/vector_0_60_0_x86_64_preflight.json) — checksum과 archive 정적 검사 일치; binary 미실행; Ubuntu disposable isolation/egress deny 미제공으로 ISOLATION_BLOCKED, 실제 자료·조직 운영 NO_GO
- [Phase 35.4A2 Ubuntu ARM64 Vector isolation preflight](vector_arm64_isolation_preflight_35_4a2.md) · [ARM64 artifact manifest](artifacts/vector_0_60_0_aarch64_preflight.json) — 공식 checksum·archive 및 AArch64 ELF 정적 검사 통과; VM이 실행 중이고 NAT·USB 활성, 공유 경계와 guest free space 미확인으로 USER_ACTION_REQUIRED / ISOLATION_BLOCKED / RESOURCE_BLOCKED; Vector 미실행
- [Phase 35.4A1 pair truncate 회귀 안정성](pair_truncation_stability_35_4a1.md) — cycle budget 경계에서 테스트가 단일 cycle의 양 역할 검사 완료를 가정한 동기화 문제를 결정적으로 재현; 3회 연속 전체 회귀 기준선 확정 전이며 Vector는 계속 ISOLATION_BLOCKED
- [Phase 35.4 Vector 격리 JSON Lines pilot 계획](vector_isolated_integration_plan_35_4.md) — Vector 실행은 `ISOLATION_BLOCKED`; config/wire 검증 미실행, checksum-only·미해결 3건 유지
- [Phase 35.1 Vector 0.60.0 공급망·권한·데이터 경계 정적 감사](vector_supply_chain_audit_35_1.md) · [artifact manifest](artifacts/vector_0_60_0_manifest.json) — 세 archive checksum은 일치했지만 binary provenance는 미확인; native framing은 기존 계약과 비호환, custom VRL은 미검증; pure JSON Lines core 구현 후 Vector는 미설치·미실행
- [Phase 35.0 기업형 로그 수집 연동 설계](enterprise_log_collection_architecture_35_0.md) — 공식 릴리스 비교, Vector 0.60.0 합성 pilot 후보만 CONDITIONAL_GO; collector 미설치·미실행, 실제 자료와 조직 운영 NO_GO
- [Phase 34.1 bounded TCP Syslog pure core](bounded_tcp_syslog_core_34_1.md) — in-process framing·buffer·queue 계약 · [Phase 34.2 loopback pilot](loopback_tcp_syslog_pilot_34_2.md) — Ubuntu CI subprocess smoke 통과 · [Phase 34.3 수용 검증](loopback_tcp_syslog_acceptance_34_3.md) — macOS 반복 lifecycle·자원 정리 · [Phase 34.3A Ubuntu bounded reliability](loopback_tcp_syslog_linux_reliability_34_3a.md) — Ubuntu bounded 반복 smoke 통과 · [Phase 34.4 CLI 설정·실행·삭제](loopback_tcp_syslog_management_34_4.md) 및 [Phase 34.5 사용자 수용](loopback_tcp_syslog_management_acceptance_34_5.md) — Ubuntu management CI와 10개 합성 안내 항목 사용자 PASS; Phase 34 합성 관리 pilot `GO`, 실제 자료·조직 운영·원격 수집 `NO_GO`

## 탐지·평가·개인정보

- [합성 탐지 평가](detection_evaluation.md) · [웹 공격 관찰](web_attack_observation_design.md) · [incident case/Timeline](incident_case_timeline_design.md)
- [공개 분석 projection과 기존 API migration](public_analysis_privacy.md)
- [Hypothesis 설계](hypothesis_property_testing_gate_23_0.md) · [property pilot](hypothesis_property_testing_pilot_23_1.md) · [Schemathesis 설계](schemathesis_api_fuzzing_gate_23_4.md) · [API pilot](schemathesis_api_pilot_23_5.md)
- [검증 가능한 로컬 AI 조사 도우미 설계 gate](local_ai_investigation_assistant_33_0.md) — Phase 33.0 설계 전용; Gemini 현행 경계, safe evidence, corpus, 위협 모델과 33.1 평가 기준
- [Phase 36.0 AI investigation triage 설계](ai_investigation_triage_design_36_0.md) — deterministic 분석 권위 유지, LLM 없는 사례 검토 우선순위 기준선부터; 사용자 자료·조직 운영 NO_GO
- [Phase 36.1 결정적 investigation triage 기준선](deterministic_investigation_triage_36_1.md) — 내부·합성 전용 DTO, 검토 우선순위, citation 확인 checklist; 모델·public integration 없음
- [Phase 36.2 lexical investigation checklist](lexical_investigation_checklist_36_2.md) — Phase 33.1 직접 관련 citation으로 고정 한국어 수동 확인 항목; path traversal/process는 corpus 근거 부족으로 거부, 사용자 이해도 NOT_TESTED
- [결정적 로컬 지식 검색·citation baseline](local_ai_lexical_retrieval_33_1.md) — Phase 33.1 시점의 internal/test-only 기준선; production 사례 도움말 연결은 [Phase 33.4](local_investigation_guidance_33_4.md) 참조
- [Phase 33.4 근거 도움말](local_investigation_guidance_33_4.md) · [33.4A 수용 검수](local_investigation_guidance_acceptance_33_4a.md) — synthetic IP canary가 기존 public case/report 응답에 노출되어 `NO_GO`; Safari 검수 중단
- [33.4B 공개 사례·보고서 개인정보 projection](public_investigation_privacy_33_4b.md) — schema 2 별칭 migration과 API·HTML·UI 경계; Safari 수동 재검수는 NOT_TESTED
- [33.4C 공개 식별자 보호 수용 검수](public_investigation_privacy_acceptance_33_4c.md) — 공개 projection·별칭·lexical guidance 범위 GO; 확대·전체 VoiceOver·Web Inspector는 NOT_TESTED
- [33.5A 제한된 내부 조사 보고서 설계](trusted_analyst_report_design_33_5a.md) · [33.5B 합성 전용 CLI pilot](trusted_analyst_report_pilot_33_5b.md) · [33.5C Linux 수용 기록](trusted_analyst_report_linux_acceptance_33_5c.md) — Ubuntu `roles=3` smoke·benchmark 통과, 합성 pilot 범위 CONDITIONAL_GO; 실제 사용자 자료 export·조직 운영은 NO_GO · [33.5D 사용자 안전장치 수용](trusted_analyst_report_user_acceptance_33_5d.md) — 10개 안내 항목 사용자 PASS, 자동 회귀 기록과 함께 합성 pilot 범위 CONDITIONAL_GO; 실제 자료 export·조직 사용 NO_GO
- [로컬 embedding 공급망·평가 설계 gate](local_embedding_supply_chain_gate_33_2a.md) — Phase 33.2A 당시 정적 후보 비교; 후속 실행은 33.2B 기록 참조
- [격리형 multilingual E5 retrieval pilot](local_embedding_retrieval_pilot_33_2b.md) — 합성 전용 native macOS 비교; production 통합 NO_GO, lexical 기준선 유지
- [구조화 local LLM 설명 pilot 공급망·평가 설계 gate](local_llm_supply_chain_gate_33_3a.md) — Phase 33.3A 정적 설계; [33.3B](local_llm_pilot_33_3b.md)·[33.3C](local_llm_pilot_33_3c.md)는 격리 근거 부족으로 중단, [33.3D](local_llm_pilot_33_3d.md)는 acquisition 전 `SUPPLY_CHAIN_BLOCKED`, [33.3E artifact·wheel·disk gate](local_llm_artifact_closure_33_3e.md)는 `RESOURCE_NO_GO`, [33.3F 전용 저장공간·잔여 closure](local_llm_acquisition_environment_33_3f.md)는 `STORAGE_SETUP_BLOCKED`

## Linux Audit

- [프로세스 실행 조사](linux_audit_process_execution.md) · [shared-memory 검토](shared_memory_execution_review.md) · [session/process 동시 관찰](linux_audit_session_process_review.md)
- [API 경계](linux_audit_api_design.md) · [API 보안 설계](linux_audit_api_security_design.md) · [배포 전제](linux_audit_api_deployment_security.md)

## UI·접근성·수용 검증

- [웹 UI 설계](web_application_design.md) · [실시간 UI 수용](live_monitoring_acceptance_15_1.md) · [live 수용 기록](live_monitoring_acceptance_17.md)
- [v0.3.0 Safari 수용 기록](v030_safari_acceptance_27_1.md) · [오픈소스 UI 품질 gate](ui_open_source_quality_gate_28_0.md) · [axe/Playwright pilot](ui_accessibility_axe_pilot_28_1.md)
- [독립 보안 대시보드 비교안](ui_dashboard_prototype_28_2.md) · [첫 조사 화면 정보 구조](ui_investigation_experience_28_3.md) · [작업 화면 탐색](ui_workspace_navigation_28_4.md) · [아이콘과 시각 계층](ui_visual_language_28_4.md) · [Safari 수용 검수](ui_safari_acceptance_28_5.md)

## 개발·보안 검증 기록

- [PentAGI 격리 평가 pilot 설계 gate](pentagi_evaluation_pilot_31_0.md) · [v2.2.0 정적 공급망 감사](pentagi_supply_chain_audit_31_1.md) · [폐기형 VM 격리 기록·최종 NO-GO](disposable_vm_isolation_31_2a.md) — 무해 probe 실측과 PentAGI 실행 차단 조건
- [두 로그 동시 모니터링 설계 gate](bounded_multi_source_monitoring_32_0.md) · [Phase 32.1A private v3 설정 계약](multi_source_private_config_32_1.md) · [Phase 32.1B 내부 runtime 검증](multi_source_runtime_32_1b.md) · [Phase 32.2 publication·API·SSE](multi_source_publication_32_2.md) · [Phase 32.3 사용자 실행·관리·production UI](multi_source_user_monitoring_32_3.md) · [Phase 32.4 독립 수용·장애 검증](multi_source_acceptance_32_4.md) · [Safari 수용 체크리스트](safari_multi_source_acceptance_32_3.md)
- [Semgrep 설계](semgrep_security_gate_23_2.md) · [Semgrep 공급망 검토](semgrep_security_pilot_23_3.md)
- [공급망 gate](software_supply_chain_gate_24_0.md) · [OSV pilot](software_supply_chain_pilot_24_1.md) · [dependency evidence bundle](dependency_evidence_bundle_24_2.md)
- [REA 개발 pilot](rea_development_pilot_22_0.md) · [CLI pilot](rea_cli_pilot_22_1.md) · [정적 경로 감사](rea_static_path_audit_22_1a.md)
- [live 분석 검증](live_analysis_16_2_verification.md) · [통합 감사](live_analysis_16_4_audit.md) · [복구 검증](live_monitoring_release_gate_18.md)
