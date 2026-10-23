"""Fail-closed, test-only gate for a future disposable-VM LLM pilot.

This module records only boolean attestations. It does not inspect or control a
VM, download artifacts, start a model, or prove that an attestation is true.
"""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class IsolationAttestations:
    ubuntu_2404_arm64: bool
    clean_snapshot: bool
    shared_host_integration_disabled: bool
    network_deny_verified: bool
    docker_client_and_daemon_verified: bool
    no_sensitive_guest_data: bool
    resource_and_inventory_checks_complete: bool


def isolation_gate(evidence: IsolationAttestations) -> str:
    """Return readiness only when every required assertion is literally true.

    This is a contract check, not an isolation measurement. The caller must
    retain the evidence source separately and must not treat this helper as
    verification of the VM or its hypervisor boundary.
    """
    if type(evidence) is not IsolationAttestations:
        return "ISOLATION_BLOCKED"
    values = (
        evidence.ubuntu_2404_arm64,
        evidence.clean_snapshot,
        evidence.shared_host_integration_disabled,
        evidence.network_deny_verified,
        evidence.docker_client_and_daemon_verified,
        evidence.no_sensitive_guest_data,
        evidence.resource_and_inventory_checks_complete,
    )
    if any(type(value) is not bool or value is not True for value in values):
        return "ISOLATION_BLOCKED"
    return "PREFLIGHT_ATTESTATIONS_COMPLETE_REQUIRES_REVIEW"
