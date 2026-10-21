"""Keep the PentAGI proposal a bounded, non-executing design gate."""

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
PLAN = ROOT / "docs/pentagi_evaluation_pilot_31_0.md"


def _plan() -> str:
    return PLAN.read_text(encoding="utf-8")


def test_proposal_is_not_an_installation_or_product_feature() -> None:
    text = _plan()
    for required in (
        "CONDITIONAL GO — 설계 gate", "PentAGI 실행은 NO-GO",
        "PentAGI를 다운로드·설치·실행하지 않았고",
        "installer·Compose·image pull·LLM/검색 연결·공격 명령·스캔을 수행하지 않았다",
        "production 코드, dependency, lockfile, CI에는 PentAGI가 없다",
        "실제 인증 행동은 **Phase 31.4 이전에 실행하지 않는다**",
        "`curl | sh`, `latest`, 검증하지 않은 installer의 root 실행은 **NO-GO**",
    ):
        assert required in text
    assert "PentAGI" not in (ROOT / "README.md").read_text(encoding="utf-8")


def test_official_identity_license_and_unverified_supply_chain() -> None:
    text = _plan()
    for required in (
        "vxcontrol/pentagi", "v2.2.0", "b611fbebcf55b6deb88ad1fb7bf1f1ce7a357242",
        "MIT", "EULA", "AGPL-3.0", "특별 예외", "제3자 보안 도구",
        "platform별 image digest", "installer archive hash", "서명·notarization·provenance",
        "SBOM", "runtime tool/image download", "image layer", "latest",
    ):
        assert required in text
    assert "https://github.com/vxcontrol/pentagi" in text
    assert "https://pentagi.com/docs/" in text
    assert "https://docs.docker.com/" in text


def test_scope_is_synthetic_and_network_fail_closed() -> None:
    text = _plan()
    for required in (
        "합성 SSH target 컨테이너 **1개**", "disposable Linux VM",
        "host gateway", "인터넷 egress", "metadata address", "callback",
        "no-new-privileges", "CPU/RAM/PID/disk/time", "Docker socket",
        "Cloud LLM", "web search", "Secure erase는 보장하지 않는다",
        "target identity 불확실", "resource budget 강제 실패",
        "실제 credential", "실제 LAN/VPN route",
    ):
        assert required in text
    assert "Docker network 자체는 완전한 sandbox가 아니다" in text


def test_independent_truth_roadmap_and_phase_30_limits() -> None:
    text = _plan()
    for required in (
        "Ubuntu application **PASS**", "Ubuntu SSH **PASS**",
        "사용자 이해도 9개 항목 수정 후 **PASS**",
        "rotation/copytruncate", "SIGKILL·전원 차단 복구",
        "exactly-once·무유실", "비협력적 동일 UID",
        "A. PentAGI 실행 사실", "B. 합성 SSH target 로그", "C. 우리 분석기",
        "PentAGI 보고서는 정답이 아니다", "Phase 31.1", "31.2", "31.3",
        "31.4", "31.5", "31.6", "기존 detector threshold를 PentAGI 결과에 맞춰 바꾸지 않는다",
    ):
        assert required in text
    assert "PentAGI 격리 평가 pilot 설계 gate" in (ROOT / "docs/index.md").read_text(encoding="utf-8")
    for target in re.findall(r"\]\(([^)]+)\)", text):
        if "://" not in target:
            assert (PLAN.parent / target.split("#", 1)[0]).exists()
