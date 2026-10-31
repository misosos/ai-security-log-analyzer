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

- [Phase 36.9B 지원 로그 형식 호환성 프로파일](supported_log_format_compatibility_36_9b.md) — 합성 fixture의 Parser 의미 검증; false acceptance 3건으로 UNSAFE_ACCEPTANCE_HOLD
- [Phase 36.9B-R1 Parser false acceptance 복구](parser_false_acceptance_remediation_36_9b_r1.md) — 최초 RED 보존, source IP·SSH process·HTTP status 경계 수정 및 회귀 검증
- [Phase 36.9B-R2 합성 로그 형식 호환성 종결 및 회귀 수용](log_format_compatibility_closure_36_9b_r2.md) — 21개 compatibility fixture와 R1의 세 오해석 수정 독립 재검증; 로컬 합성 범위에 한정
- [Phase 36.9C 탐지 정확도·오탐·미탐 합성 평가](detector_accuracy_evaluation_36_9c.md) — 독립 pattern/context 라벨의 46개 시나리오 결과; Brute Force missed subwindow 1건, 실환경 정확도는 미검증
- [Phase 36.9D Brute Force 시간창 의미 평가](brute_force_window_semantics_evaluation_36_9d.md) — whole-span과 세 sliding 계정 범위 후보를 24개 합성 시나리오에서 비교; production detector 불변
- [Phase 36.9E Brute Force Evidence·Correlation 계약](brute_force_evidence_correlation_contract_36_9e.md) — Candidate C와 실제 Case adapter·Correlation 충돌을 shadow 검증하고 비공개 Window Context 계약 제안
- [Phase 36.9F Brute Force Sliding Window Production 복구](brute_force_sliding_window_production_remediation_36_9f.md) — Candidate C의 내부 Window Context를 Production Detection·Correlation·Case 경로에 연결하고 전체 IP feature 및 Password Spray 의미를 보존
- [Phase 36.10B Password Spray scope·운영상 오경보 합성 평가](password_spray_scope_false_alert_evaluation_36_10b.md) — whole-span과 Window 후보 정책을 독립 합성 corpus에서 비교; Production 정책 변경은 `MORE_EVIDENCE_REQUIRED`
- [Phase 36.10B-R1 Password Spray Evidence·Consumer 계약 설계](password_spray_evidence_consumer_contract_design_36_10b_r1.md) — 전체 IP와 선택 Window 의미, Correlation/Risk/Case/Report 경계 및 추가 근거를 설계; Production은 whole-span 유지
- [Phase 36.9A 프로젝트 성숙도·실무 준비도 평가](project_maturity_readiness_assessment_36_9a.md) — 현재 합성 검증 범위, 운영 미검증 경계, 다음 개발 우선순위 (docs/index.md)
- [합성 탐지 평가](detection_evaluation.md) · [웹 공격 관찰](web_attack_observation_design.md) · [incident case/Timeline](incident_case_timeline_design.md)
- [공개 분석 projection과 기존 API migration](public_analysis_privacy.md)
- [Hypothesis 설계](hypothesis_property_testing_gate_23_0.md) · [property pilot](hypothesis_property_testing_pilot_23_1.md) · [Schemathesis 설계](schemathesis_api_fuzzing_gate_23_4.md) · [API pilot](schemathesis_api_pilot_23_5.md)
- [검증 가능한 로컬 AI 조사 도우미 설계 gate](local_ai_investigation_assistant_33_0.md) — Phase 33.0 설계 전용; Gemini 현행 경계, safe evidence, corpus, 위협 모델과 33.1 평가 기준
- [Phase 36.0 AI investigation triage 설계](ai_investigation_triage_design_36_0.md) — deterministic 분석 권위 유지; 36.3A 합성 UI 이해도 10/10 최종 PASS를 별도 기록
- [Phase 36.1 결정적 investigation triage 기준선](deterministic_investigation_triage_36_1.md) — closed DTO와 별도 검토 우선순위; source role 미상 시 priority `undetermined`
- [Phase 36.2 lexical investigation checklist](lexical_investigation_checklist_36_2.md) — Phase 33.1 citation 기반 고정 checklist, 24개 합성 fixture; 36.3A 사용자 수용은 별도 기록
- [Phase 36.2A 한국어 checklist 수용 검수](investigation_checklist_acceptance_36_2a.md) — 합성 내부 안내 8/8 PASS; 최초 refusal 안내 FAIL과 재검수 기록, Phase 36.3 UI는 별도 미검수
- [Phase 36.3 조사 checklist read-only API·명시적 UI](investigation_checklist_api_ui_36_3.md) — POST 1개와 버튼 클릭만으로 요청; `CONDITIONAL_GO`, 36.3A 사용자 이해도 10/10 PASS, 새 Ubuntu CI 및 전체 Safari 접근성은 남음
- [Phase 36.3A 조사 checklist API/UI 수용 검수](investigation_checklist_acceptance_36_3a.md) — 실제 합성 Safari UI 사용자 이해도 10/10 최종 PASS, item 7 최초 FAIL 유지; 접근성 검수는 별도
- [Phase 36.3B Safari 접근성 수용 검수](investigation_checklist_safari_acceptance_36_3b.md) — CI gate 통과; task-private Safari 프로필 격리를 확보하지 못해 keyboard, VoiceOver, 확대, 320 CSS px, Web Inspector는 NOT_TESTED
- [Phase 36.4 검증된 source role checklist 전달](investigation_checklist_verified_role_36_4.md) — same-analysis normalized source metadata만 사용, 혼합·누락·stale 시 `unknown`; API schema v2, 로컬 conditional 범위만
- [Phase 36.5A 검토 작업공간 재설계](investigation_review_workspace_redesign_36_5a.md) — 결과 목록과 독립 상세 화면, 접근 가능한 활동 흐름, 작업 카드와 접힌 근거; 새 Ubuntu CI와 36.5B 사용자 검수 전 `CONDITIONAL_GO`
- [Phase 36.5B/C/D PatternFly 참고 정적 prototype](investigation_workspace_patternfly_prototype_36_5b.md) · [desktop 사용자 검수](investigation_workspace_patternfly_acceptance_36_5c.md) · [모바일 검수](investigation_workspace_mobile_acceptance_36_5d.md) — desktop 및 모바일 사용자 수용 완료; production 미이식, 200% equivalent overflow 미해결, 실제 기기·Safari `NOT_TESTED`
- [Phase 36.6A production 이식 설계](investigation_workspace_production_migration_design_36_6a.md) — 기존 API/projection을 유지하는 단계별 이식과 rollback 계약; dashboard·개요 구현 진행, 기존 UI rollback 유지, 실제 자료·조직 운영 `NO_GO`
- [Phase 36.6B closed UI projection·navigation shell](investigation_workspace_projection_navigation_36_6b.md) · [Phase 36.6C dashboard·상세 개요](investigation_workspace_dashboard_overview_36_6c.md) — closed projection과 기존 hash route 사용; 기존 UI를 대체하지 않음, limitation은 분석 한계로만 표시하고 추가 확인 count는 생략; 새 화면 Chromium 200% equivalent 통과, 전체 앱 확대·Safari 미검증
- [Phase 36.6D 활동 흐름 Timeline·비인과적 Relation](investigation_workspace_timeline_relation_36_6d.md) — 기존 19필드 projection을 유지하고 검증된 동일 snapshot의 순서·시간을 별도 불변 adapter로 표시; Safari·실제 기기 및 실제 자료·조직 운영은 미검증/NO_GO
- [Phase 36.6E 확인할 작업·근거·명시적 점검표](investigation_workspace_tasks_evidence_36_6e.md) — 기존 checklist v2와 guidance를 명시적 사용자 요청으로 표시; projection·분석 결과 불변, Safari·실제 기기 NOT_TESTED, 실제 자료·조직 운영 NO_GO
- [Phase 36.6E-CI-FIX Chromium 간격 검사 복구](investigation_workspace_ci_recovery_36_6e.md) — wrapping 허용 탭의 실제 사각형 간격으로 검사; Ubuntu 재검증 전, Phase 36.6F 아님
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

- [Phase 36.10A-UI1 Cyberpunk 조사 워크스페이스 리디자인](cyberpunk_investigation_workspace_redesign_36_10a_ui1.md) — 기존 조사 Projection·Hash Route·Checklist/Guidance 계약을 유지한 Cyberpunk 스타일 및 Chromium 반응형·접근성 회귀
- [Phase 36.10A-UI2 사이버펑크 워크스페이스 가독성·레이아웃 보완](cyberpunk_ui_readability_layout_refinement_36_10a_ui2.md) — CSS px 기준 Chromium 측정, 반응형/200% equivalent reflow와 사용자 Safari 수용 범위 구분
- [Phase 36.10A-UI3 Safari 화면 수용 준비 및 Navigation 회귀 종결](cyberpunk_safari_acceptance_navigation_closure_36_10a_ui3.md) — 구형 DOM 기대와 현행 Guidance opt-in 검증을 분리하고, Safari 18.6 자동화 smoke와 사용자 검수 항목 기록
- [웹 UI 설계](web_application_design.md) · [실시간 UI 수용](live_monitoring_acceptance_15_1.md) · [live 수용 기록](live_monitoring_acceptance_17.md)
- [v0.3.0 Safari 수용 기록](v030_safari_acceptance_27_1.md) · [오픈소스 UI 품질 gate](ui_open_source_quality_gate_28_0.md) · [axe/Playwright pilot](ui_accessibility_axe_pilot_28_1.md)
- [Phase 36.8A 로그 텍스트 직접 입력 설계](log_text_paste_input_design_36_8a.md) · [36.8B bounded local backend](log_text_paste_backend_36_8b.md) — 단일 source 텍스트 API 구현; 브라우저 입력 UI는 Phase 36.8C 예정
- [독립 보안 대시보드 비교안](ui_dashboard_prototype_28_2.md) · [첫 조사 화면 정보 구조](ui_investigation_experience_28_3.md) · [작업 화면 탐색](ui_workspace_navigation_28_4.md) · [아이콘과 시각 계층](ui_visual_language_28_4.md) · [Safari 수용 검수](ui_safari_acceptance_28_5.md)

## 개발·보안 검증 기록

- [PentAGI 격리 평가 pilot 설계 gate](pentagi_evaluation_pilot_31_0.md) · [v2.2.0 정적 공급망 감사](pentagi_supply_chain_audit_31_1.md) · [폐기형 VM 격리 기록·최종 NO-GO](disposable_vm_isolation_31_2a.md) — 무해 probe 실측과 PentAGI 실행 차단 조건
- [두 로그 동시 모니터링 설계 gate](bounded_multi_source_monitoring_32_0.md) · [Phase 32.1A private v3 설정 계약](multi_source_private_config_32_1.md) · [Phase 32.1B 내부 runtime 검증](multi_source_runtime_32_1b.md) · [Phase 32.2 publication·API·SSE](multi_source_publication_32_2.md) · [Phase 32.3 사용자 실행·관리·production UI](multi_source_user_monitoring_32_3.md) · [Phase 32.4 독립 수용·장애 검증](multi_source_acceptance_32_4.md) · [Safari 수용 체크리스트](safari_multi_source_acceptance_32_3.md)
- [Semgrep 설계](semgrep_security_gate_23_2.md) · [Semgrep 공급망 검토](semgrep_security_pilot_23_3.md)
- [공급망 gate](software_supply_chain_gate_24_0.md) · [OSV pilot](software_supply_chain_pilot_24_1.md) · [dependency evidence bundle](dependency_evidence_bundle_24_2.md)
- [REA 개발 pilot](rea_development_pilot_22_0.md) · [CLI pilot](rea_cli_pilot_22_1.md) · [정적 경로 감사](rea_static_path_audit_22_1a.md)
- [live 분석 검증](live_analysis_16_2_verification.md) · [통합 감사](live_analysis_16_4_audit.md) · [복구 검증](live_monitoring_release_gate_18.md)
- [Phase 36.9G Brute Window 사후 회귀 및 계약 종결](brute_window_post_remediation_closure_36_9g.md)
- [Phase 36.9G-R1 Brute Window Context 실행 소유권 보완](brute_window_run_ownership_remediation_36_9g_r1.md)
- [Phase 36.9G-R2 Brute Window Context 소유권 독립 종결 검증](brute_window_context_ownership_closure_36_9g_r2.md)
- [Phase 36.9G-R2-R1 Analysis Owner 단일 결속 보완](analysis_owner_unique_binding_remediation_36_9g_r2_r1.md)
- [Phase 36.9G-R2-R2 Analysis Owner 독립 Closure — 재포장 우회 HOLD](analysis_owner_independent_closure_36_9g_r2_r2.md)
- [Phase 36.9G-R2-R2-R1 신뢰된 분석 Provenance 경계 보완](trusted_analysis_provenance_boundary_remediation_36_9g_r2_r2_r1.md)
- [Phase 36.9G-R2-R2-R2 신뢰된 분석 Provenance 독립 종결 검증](trusted_analysis_provenance_independent_closure_36_9g_r2_r2_r2.md)
- [Phase 36.10A 탐지 준비도 및 잔여 위험 우선순위 평가](detection_readiness_risk_prioritization_36_10a.md) — Detector·Parser·Consumer 근거 감사, 운영 blocker 및 36.10B/C/D roadmap
- [Phase 36.10B Password Spray 범위·운영상 오경보 평가](password_spray_scope_false_alert_evaluation_36_10b.md) — 현재 whole-span과 평가 전용 window 후보를 36개 독립 합성 시나리오에서 비교; Production 정책 변경은 추가 근거 전까지 보류
