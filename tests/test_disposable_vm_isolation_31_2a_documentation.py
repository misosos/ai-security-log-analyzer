"""Keep the VM isolation record separate from an actual execution claim."""

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs/disposable_vm_isolation_31_2a.md"


def test_gate_and_blocked_result_are_explicit() -> None:
    text = DOC.read_text(encoding="utf-8")
    for required in (
        "1e7288ceb7312a89ed253fab4ea595bfeecbd471",
        "39625656698", "completed/success", "수동 dispatch는 하지 않았다",
        "BLOCKED_NO_DISPOSABLE_VM", "Phase 31.2B: NO-GO",
        "SOURCE_IMAGE_BINDING_UNPROVEN", "eecd6ee1cda0545e34b01c42e1a2163a899bcc27",
        "VM image", "Docker Desktop container 결과를 VM PASS로 대체하지 않았다",
    ):
        assert required in text
    assert "BLOCKED_NO_DISPOSABLE_VM" in (ROOT / "docs/pentagi_evaluation_pilot_31_0.md").read_text(encoding="utf-8")
    assert "BLOCKED_NO_DISPOSABLE_VM" in (ROOT / "docs/pentagi_supply_chain_audit_31_1.md").read_text(encoding="utf-8")


def test_probe_scope_and_unverified_results_are_clear() -> None:
    text = DOC.read_text(encoding="utf-8")
    for required in (
        "docker.io/library/busybox@sha256:", "Image layer는 pull하지 않았다",
        "--pull=never", "--cap-drop=ALL", "no-new-privileges",
        "read-only root", "1 MiB tmpfs", "실행하지 않는다",
        "인터넷", "LAN", "VPN", "metadata", "callback",
        "최소 3회", "Target 부재", "강제 종료", "VM 재시작",
        "**NOT_TESTED**", "socket 미제공", "Host shared folder",
    ):
        assert required in text
    assert "실제 VM 검증: `BLOCKED_NO_DISPOSABLE_VM`" in text
    assert "disposable_vm_isolation_31_2a.md" in (ROOT / "docs/index.md").read_text(encoding="utf-8")
    for target in re.findall(r"\]\(([^)]+)\)", text):
        if "://" not in target:
            assert (DOC.parent / target.split("#", 1)[0]).exists()


def test_no_product_or_dependency_change_is_claimed() -> None:
    text = DOC.read_text(encoding="utf-8")
    assert "PentAGI image·installer·Compose·source build·도구 실행이나 대상 스캔은 수행하지 않았다" in text
    assert "PentAGI 실행 승인은 별도 gate" in text
    assert "secure erase" not in text.lower()
