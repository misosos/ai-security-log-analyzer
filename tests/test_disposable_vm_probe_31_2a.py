"""The offline probe plan must remain fixed, bounded, and non-executing."""

from pathlib import Path
import inspect

import pytest

from scripts import disposable_vm_probe_31_2a as probe


def test_plan_is_blocked_and_repeatable_without_a_vm() -> None:
    first = probe.plan("linux/arm64")
    assert first == probe.plan("linux/arm64")
    assert first["verdict"] == "BLOCKED_NO_DISPOSABLE_VM"
    assert first["execution_performed"] is False
    assert first["network_created"] is False
    assert first["target_created"] is False
    assert "VM egress deny" in first["network_policy"]
    assert first["planned_repetitions"] == 3
    assert len(first["required_checks"]) == 16
    assert len(first["fault_checks"]) == 7


@pytest.mark.parametrize("platform", ["linux/amd64", "linux/arm64"])
def test_container_plan_has_pinned_image_and_closed_restrictions(platform: str) -> None:
    argv = probe.container_argv(platform)
    assert argv[0:2] == ("docker", "run")
    assert "--pull=never" in argv
    assert "--cap-drop=ALL" in argv
    assert "--security-opt=no-new-privileges" in argv
    assert "--read-only" in argv
    assert "--pids-limit=32" in argv
    assert "--cpus=0.5" in argv
    assert "--memory=64m" in argv
    assert "--memory-swap=64m" in argv
    assert "--ulimit=core=0:0" in argv
    assert "--restart=no" in argv
    assert argv[argv.index("--user") + 1] == "65532:65532"
    assert argv[argv.index("--network") + 1] == probe.NETWORK_NAME
    assert argv[-3] == probe.IMAGE_BY_PLATFORM[platform]
    assert argv[-2:] == ("id", "-u")
    assert "@sha256:" in argv[-3]
    assert len(argv[-3].split("@sha256:")[-1]) == 64
    assert not any(value in argv for value in ("--privileged", "--network=host", "-v", "--volume", "--mount", "--device", "-p", "--publish"))


def test_no_arbitrary_target_command_or_execution_path() -> None:
    with pytest.raises(ValueError, match="unsupported fixed probe platform"):
        probe.plan("linux/other")
    assert tuple(inspect.signature(probe.plan).parameters) == ("platform",)
    source = Path(probe.__file__).read_text(encoding="utf-8")
    for forbidden in ("subprocess", "os.system", "shell=True", "eval(", "exec(", "socket.", "requests.", "urllib."):
        assert forbidden not in source
    assert "PentAGI" not in " ".join(probe.IMAGE_BY_PLATFORM.values())
