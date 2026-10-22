"""Keep reported VM probe evidence narrower than a PentAGI isolation proof."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs/disposable_vm_isolation_31_2a.md"


def test_reported_arm64_probe_and_limits_are_recorded() -> None:
    text = DOC.read_text(encoding="utf-8")
    for required in (
        "Ubuntu 24.04.5 LTS", "aarch64", "Docker Server 29.1.3",
        "sha256:d82c2ab94640ded77cf76514ce6a84870761105058a4a9e51b05a8a79be97a6c",
        "UID 65534", "--network none", "3/3", "clean-before-phase-31-2a",
        "사용자 제공", "Phase 31.2B: NO-GO", "SOURCE_IMAGE_BINDING_UNPROVEN",
        "internal target 통신은 NOT_TESTED", "resource limit 극한 동작은 NOT_TESTED",
        "PentAGI 안전성", "VM 전체 host 접근 차단",
    ):
        assert required in text
    assert "BLOCKED_NO_DISPOSABLE_VM" not in text.split("## 실제 VMware Fusion 검증", 1)[1].split("## 최초 gate", 1)[0]


def test_no_unverified_proof_or_private_identifiers() -> None:
    text = DOC.read_text(encoding="utf-8")
    assert "Phase 31.2B: GO" not in text
    assert "PentAGI 실행: PASS" not in text
    for forbidden in ("Ubuntu0", "vmwarevm", "192.168.", "10.0.", "172.16."):
        assert forbidden not in text
