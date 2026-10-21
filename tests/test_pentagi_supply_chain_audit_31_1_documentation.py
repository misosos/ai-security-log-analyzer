"""Keep the PentAGI audit static, versioned, and fail closed."""

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
AUDIT = ROOT / "docs/pentagi_supply_chain_audit_31_1.md"


def _audit() -> str:
    return AUDIT.read_text(encoding="utf-8")


def test_release_identity_and_archive_observation_are_specific() -> None:
    text = _audit()
    for required in (
        "1fc5e424caf95633b643c2f029766b3c5837c580",
        "39611980896", "lightweight tag",
        "b611fbebcf55b6deb88ad1fb7bf1f1ce7a357242",
        "CVE-2026-14784", "52,672,094",
        "43050f8507659707b54bb62387ca8163752df8eecfeba4c5f861590f119f787b",
        "Path traversal 0", "hardlink 0", "symlink 13", "6/6 일치",
        "GitHub 자동 생성 archive의 공식 별도 checksum은 확인되지 않았다",
    ):
        assert required in text
    assert "https://github.com/vxcontrol/pentagi/releases/tag/v2.2.0" in text


def test_installer_image_and_compose_blockers_are_not_waived() -> None:
    text = _audit()
    for required in (
        "UNVERIFIED_ARTIFACT", "v2.2.0 GitHub Release에", "업로드 installer asset이 없다",
        "installer-latest.zip", "root:root", "/var/run/docker.sock",
        "28000–29999", "0.0.0.0", "latest",
        "sha256:64bd1802799142a12bc5eb23c15a1ccc50d3476736d3d2a98a9b773910283a1e",
        "sha256:00e7510f54762377dcb2bfb05b9df8404d5e012104a6e7ad4c00d735610be2b9",
        "sha256:3c8d8a67a5539d16a487264a24712c57790a692d7e2c8f937e3dfc89b1b92bf1",
        "SOURCE_IMAGE_BINDING_UNPROVEN", "NO-GO 현재 구성",
        "48개 gzip layer", "277,695,361 byte", "setuid/setgid",
        "Docker CLI", "SPDX-2.3", "NOASSERTION",
    ):
        assert required in text
    assert "<!-- REGISTRY_TABLE -->" not in text
    assert "<!-- LAYER_SUMMARY -->" not in text
    assert text.count("| `vxcontrol/pentagi:latest` |") == 1
    assert text.count("| `vxcontrol/pentagi:2.2.0` |") == 1


def test_license_data_and_no_execution_contract() -> None:
    text = _audit()
    for required in (
        "PentAGI installer·container·Compose·penetration-testing tool을 실행하지 않았고",
        "Docker socket을 mount하지 않았다", "LLM/search 연결이나 대상 스캔도 하지 않았다",
        "MIT", "EULA", "NOTICE", "AGPL-3.0", "공식 PentAGI 프로젝트",
        "Raw PentAGI report 커밋", "secure erase를 주장하지 않는다",
        "disposable Linux VM", "실제 Docker socket 직접 mount", "resource budget 강제 불가",
        "Phase 31.2 실행형 isolation proof: NO-GO",
    ):
        assert required in text
    assert "PentAGI" not in (ROOT / "README.md").read_text(encoding="utf-8")
    assert "Phase 31.1 정적 공급망 감사" in (ROOT / "docs/pentagi_evaluation_pilot_31_0.md").read_text(encoding="utf-8")
    assert "pentagi_supply_chain_audit_31_1.md" in (ROOT / "docs/index.md").read_text(encoding="utf-8")
    for target in re.findall(r"\]\(([^)]+)\)", text):
        if "://" not in target:
            assert (AUDIT.parent / target.split("#", 1)[0]).exists()
