"""Emit a fixed, non-executing isolation probe plan for a future disposable VM.

This module deliberately has no container, network, or VM execution path. It
does not accept an address, hostname, mount, Docker context, or command input.
"""

from __future__ import annotations

import argparse
import json


IMAGE_BY_PLATFORM = {
    "linux/amd64": "docker.io/library/busybox@sha256:66a6306db78bf2dbf3487f293aa8d6990d8e506fdffab9cc43fe422becf886e4",
    "linux/arm64": "docker.io/library/busybox@sha256:d82c2ab94640ded77cf76514ce6a84870761105058a4a9e51b05a8a79be97a6c",
}
NETWORK_NAME = "phase31_2a_internal"
RUN_COUNT = 3

REQUIRED_CHECKS = (
    "vm_identity_and_no_host_share",
    "non_root_and_zero_effective_capabilities",
    "read_only_root_and_bounded_tmpfs",
    "cgroup_cpu_memory_pid_and_wall_clock_limits",
    "internet_http_denied",
    "public_dns_denied",
    "known_host_gateway_denied",
    "known_mac_host_service_denied",
    "known_lan_route_denied",
    "known_vpn_route_denied",
    "cloud_metadata_denied",
    "out_of_allowlist_ip_and_name_denied",
    "fixed_internal_target_allowed",
    "other_network_and_external_callback_denied",
    "no_docker_socket_or_host_mount",
    "no_child_or_residual_container_network_volume",
)
FAULT_CHECKS = (
    "target_absent",
    "dns_denied",
    "egress_denied",
    "resource_limit_exceeded",
    "wall_clock_timeout",
    "forced_container_termination",
    "vm_restart_residue",
)


def container_argv(platform: str) -> tuple[str, ...]:
    """Return fixed Docker arguments for review; never run them here."""
    if platform not in IMAGE_BY_PLATFORM:
        raise ValueError("unsupported fixed probe platform")
    return (
        "docker", "run", "--rm", "--name", "phase31_2a_probe",
        "--pull=never", "--platform", platform,
        "--network", NETWORK_NAME,
        "--user", "65532:65532", "--cap-drop=ALL",
        "--security-opt=no-new-privileges", "--read-only",
        "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=1m,mode=1777",
        "--pids-limit=32", "--cpus=0.5", "--memory=64m",
        "--memory-swap=64m", "--ulimit=core=0:0",
        "--restart=no", "--stop-timeout=5",
        IMAGE_BY_PLATFORM[platform], "id", "-u",
    )


def plan(platform: str) -> dict[str, object]:
    """Describe required evidence without querying the host or a network."""
    argv = container_argv(platform)
    return {
        "phase": "31.2A",
        "verdict": "BLOCKED_NO_DISPOSABLE_VM",
        "execution_performed": False,
        "probe_image": IMAGE_BY_PLATFORM[platform],
        "platform": platform,
        "network": NETWORK_NAME,
        "network_policy": "new internal bridge plus separately verified VM egress deny",
        "network_created": False,
        "target_created": False,
        "planned_repetitions": RUN_COUNT,
        "required_checks": REQUIRED_CHECKS,
        "fault_checks": FAULT_CHECKS,
        "fixed_container_argv": argv,
        "note": "A command plan is not VM, network, privilege, or cleanup evidence.",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--platform", choices=tuple(IMAGE_BY_PLATFORM), required=True,
        help="select a pre-reviewed Linux image digest; no container is started",
    )
    args = parser.parse_args()
    print(json.dumps(plan(args.platform), ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
