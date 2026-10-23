from dataclasses import fields

from tests.local_llm_pilot_33_3c import IsolationAttestations, isolation_gate


def _complete(**overrides):
    values = {field.name: True for field in fields(IsolationAttestations)}
    values.update(overrides)
    return IsolationAttestations(**values)


def test_vm_isolation_gate_fails_closed_for_each_missing_attestation():
    for field in fields(IsolationAttestations):
        assert isolation_gate(_complete(**{field.name: False})) == "ISOLATION_BLOCKED"


def test_vm_isolation_gate_rejects_truthy_non_boolean_and_wrong_object():
    assert isolation_gate(_complete(clean_snapshot=1)) == "ISOLATION_BLOCKED"
    assert isolation_gate({"ubuntu_2404_arm64": True}) == "ISOLATION_BLOCKED"


def test_complete_attestations_are_not_mistaken_for_verified_isolation():
    assert isolation_gate(_complete()) == "PREFLIGHT_ATTESTATIONS_COMPLETE_REQUIRES_REVIEW"
