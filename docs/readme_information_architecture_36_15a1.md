# Phase 36.15A1 — README Information Architecture

확인일: 2026-11-04

## 목적과 결정

README의 보안 경계와 실행 계약은 유지하면서, 방문자가 프로젝트 가치, 지원 입력, 결과, 로컬 실행, 지원하지 않는 범위를 30초 안에 훑을 수 있도록 정보 위계를 바꿨다. 첫 화면은 **가치 제안 → 합성 화면 → 처리 흐름 → 핵심 기능 → 빠른 시작** 순서이며, 세부 검증 이력은 접힌 영역과 문서 지도로 옮겼다.

외부 badge 서비스는 필수 정보가 아니고 렌더링 시 외부 asset에 의존하므로 추가하지 않았다. 저장소에 이미 추적된 합성 화면을 사용하며 실제 자료가 아님을 이미지 바로 아래에 표시했다.

## 공식 README 참고

현재 공식 GitHub 저장소 README만 확인했다. 구조와 정보 위계만 참고했고 외부 문장·이미지·asset을 복사하지 않았다.

| 공식 저장소 | 확인한 구조 | 이 README에 적용한 부분 |
| --- | --- | --- |
| [grafana/loki](https://github.com/grafana/loki/blob/main/README.md) | 짧은 가치 제안, 차이점, Getting started, 상세 문서 분리 | 한 문장 가치 제안 뒤 기능 범위와 문서 링크 배치 |
| [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma/blob/master/README.md) | 대상 사용자와 규칙 유형을 먼저 설명하고 세부 생태계를 분리 | 지원 입력과 결과 의미를 닫힌 표·bullet로 요약 |
| [WithSecureOpenSource/chainsaw](https://github.com/WithSecureOpenSource/chainsaw/blob/master/README.md) | 기능, 목차, Quick Start, 예시 순서 | 핵심 기능을 사용자 작업 흐름으로 제한하고 빠른 시작을 앞부분에 배치 |
| [openobserve/openobserve](https://github.com/openobserve/openobserve/blob/main/README.md) | 제품 문구, Quick Start, Product Tour, Architecture, Security, FAQ | 합성 화면으로 실제 동작을 먼저 보여주되 지원 범위와 제한을 별도 구획 |
| [ollama/ollama](https://github.com/ollama/ollama/blob/main/README.md) | 짧은 시작 문구, 설치, 사용 예시, 문서·통합 링크 | 실행 경로를 앞에 두고 상세 개발 기록은 뒤로 이동 |

공통적으로 채택한 원칙은 짧은 첫 문단의 **가치 제안**, 앞부분의 **빠른 시작**, 실제 동작을 보여주는 **합성 화면**, 기능을 내부 Phase가 아니라 사용자 흐름으로 설명하는 방식, **지원 범위와 제한**의 분리, 상세 자료를 docs로 연결하는 방식이다. badge는 많을수록 신뢰 근거가 되는 것이 아니므로 추가하지 않았고 Security·변경 이력·License 링크는 마지막에 모았다.

## 변경 전후 구조

| 이전 | 현재 |
| --- | --- |
| 주요 기능 안에 collector·Vector·검증 이력이 함께 노출 | 6개 핵심 사용자 기능만 노출 |
| 개인정보 문단 안에 Phase 33·36 이력 장문 혼재 | 개인정보 경계는 짧게 유지하고 이력은 접힌 영역으로 분리 |
| 화면 예시 없음 | 추적된 1440px 합성 검토 큐와 합성 안내 사용 |
| 실행·입력·결과 설명이 기술 계약 중심 | 흐름, 지원 입력 표, 결과를 읽는 법으로 재배치 |
| 배포 준비 상태가 README에 반영되지 않음 | `STANDALONE_BUNDLE_FIRST` 설계와 artifact 미구현을 함께 명시 |

## 보존한 계약

- Quick Start의 clone, `uv sync --locked --dev`, local web 명령, loopback URL, 종료 방법을 그대로 유지했다.
- source checkout, wheel·PyPI 미지원, 인터넷 공개 금지와 Python 3.12 이상을 유지했다.
- `FROM_END`, checkpoint, rotation·copytruncate, cross-source, exactly-once·무유실 제한과 사용자 적용 동작을 유지했다.
- 탐지·상관관계·로그인 성공·HTTP 200의 해석 한계를 유지했다.
- 외부 LLM 비호출, 공개 Issue 경고, 별칭 수명, 임시 자료와 secure erase, SECURITY.md 경계를 유지했다.
- AI, Vector, collector, report의 역사적 경계와 현재 `NO_GO`를 접힌 기록에 보존했다.
- Phase 36.14F `12/12 PASS`는 합성 사용자 수용으로만, Phase 36.15A `STANDALONE_BUNDLE_FIRST`는 설계 결정으로만 표현했다.

## 범위와 검증

Production Python, API, frontend, dependency, lockfile, workflow는 변경하지 않는다. README, 이 결정 기록, 문서 색인, 문서 계약 테스트만 변경한다. 외부 README의 기능·디자인을 제품 기능으로 가져오지 않았으며 새 외부 이미지나 script도 추가하지 않았다.

문서 계약은 H1·가치 제안, 합성 화면, 60번째 줄 이전 빠른 시작, 처리 흐름, 지원 입력, 결과·개인정보 경계, 접힌 역사 기록, 최신 수용·배포 상태, 상대 링크 유효성, 120줄·17,000 UTF-8 byte 상한과 임시 CI·개인 경로 부재를 검사한다.

최종 판정은 새 커밋의 Ubuntu CI 전에 `README_INFORMATION_ARCHITECTURE_LOCAL_CONDITIONAL_GO`로 제한한다. 실제 사용자 자료·조직 운영·자동 대응은 계속 `NO_GO`다.
