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

## 탐지·평가·개인정보

- [합성 탐지 평가](detection_evaluation.md) · [웹 공격 관찰](web_attack_observation_design.md) · [incident case/Timeline](incident_case_timeline_design.md)
- [공개 분석 projection과 기존 API migration](public_analysis_privacy.md)
- [Hypothesis 설계](hypothesis_property_testing_gate_23_0.md) · [property pilot](hypothesis_property_testing_pilot_23_1.md) · [Schemathesis 설계](schemathesis_api_fuzzing_gate_23_4.md) · [API pilot](schemathesis_api_pilot_23_5.md)
- [검증 가능한 로컬 AI 조사 도우미 설계 gate](local_ai_investigation_assistant_33_0.md) — Phase 33.0 설계 전용; Gemini 현행 경계, safe evidence, corpus, 위협 모델과 33.1 평가 기준
- [결정적 로컬 지식 검색·citation baseline](local_ai_lexical_retrieval_33_1.md) — Phase 33.1 시점의 internal/test-only 기준선; production 사례 도움말 연결은 [Phase 33.4](local_investigation_guidance_33_4.md) 참조
- [Phase 33.4 근거 도움말](local_investigation_guidance_33_4.md) · [33.4A 수용 검수](local_investigation_guidance_acceptance_33_4a.md) — synthetic IP canary가 기존 public case/report 응답에 노출되어 `NO_GO`; Safari 검수 중단
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
