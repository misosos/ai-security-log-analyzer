# Linux Audit process-execution fixture provenance

Access date for all sources: 2026-09-19.

These files are fixture inputs, not captured telemetry. Concrete timestamps,
serials, process IDs, identities, paths, inode values, session IDs, pointer
values, node labels, and keys are synthetic and contain no real credentials.

## Primary sources

- Red Hat, *Security hardening — Auditing the system*, RHEL 8, execution
  example at lines 4451–4457:
  <https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html-single/security_hardening/index>
  The example supplies the compound `PROCTITLE`, reverse-`item` `PATH`, `CWD`,
  `EXECVE`, and successful `SYSCALL` record shape used by the canonical fixture.
- Linux kernel, `kernel/auditsc.c`, `audit_log_execve_info()` and constants
  `MAX_EXECVE_AUDIT_LEN` / `MAX_PROCTITLE_AUDIT_LEN`:
  <https://github.com/torvalds/linux/blob/master/kernel/auditsc.c>
  The implementation supplies `argc`, `aN_len`, `aN[k]`, hex encoding for
  control-containing arguments, record continuation, empty-string quoting, and
  bounded `PROCTITLE` emission behavior.
- Linux Audit Project, audit field dictionary:
  <https://github.com/linux-audit/audit-documentation/blob/main/specs/fields/field-dictionary.csv>
  The entries for `a[0-3]`, `aN[k]`, and `argc` distinguish raw `SYSCALL`
  arguments from encoded `EXECVE` argument fields and define the argument count.

## Fixture classifications and adaptations

| Fixture | Classification | Source basis and intentional structure | Synthetic replacements / assumptions |
|---|---|---|---|
| `linux_audit_exec_success_rhel_source_derived.log` | adapted source-derived | RHEL compound execution example; one event with successful `SYSCALL`, `EXECVE`, `CWD`, three `PATH` records emitted out of numeric `item` order, and `PROCTITLE` | All concrete values replaced; record-family membership and shared event identity retained |
| `linux_audit_exec_failure_structurally_derived.log` | synthetic structurally-derived | Kernel syscall success/failure fields plus kernel `EXECVE` emission structure | Constructed failed syscall (`success=no`, negative `exit`) with an `EXECVE`; no claim that it is a captured failure |
| `linux_audit_exec_split_argument_structurally_derived.log` | synthetic structurally-derived | `audit_log_execve_info()` continuation records and `aN_len`/`aN[k]` fragments | Short synthetic hex fragments stand in for a kernel-length argument; physical fragment-record order is intentionally reversed |
| `linux_audit_exec_encoded_arguments_structurally_derived.log` | synthetic structurally-derived | Kernel quoted safe strings, hex encoding for control bytes, and zero-length quoted string | Neutral strings and a synthetic newline-containing argument |
| `linux_audit_exec_optional_records_missing.log` | synthetic structurally-derived | Required record-family shape selected for later V1 research | Intentionally omits `CWD`, `PATH`, and `PROCTITLE`; this fixture makes no future eligibility claim |
| `linux_audit_exec_interleaved_scope_isolation.log` | synthetic ambiguity case | Audit event identity is timestamp plus serial; repository loader additionally scopes by configured source and record `node` | Interleaved, non-canonical physical order; same event ID reused across two synthetic nodes |
| `linux_audit_exec_incomplete_arguments_synthetic.log` | synthetic ambiguity case | Kernel argument index and fragment field forms | Missing `a1` index in one event and missing `a1[1]` in another are intentional malformed cases |
| `linux_audit_exec_duplicate_fields_synthetic.log` | synthetic ambiguity case | Kernel `EXECVE`/fragment and `PATH item` field forms | Conflicting `argc`, duplicate/conflicting argument or fragment fields, and duplicate/conflicting `PATH item` are intentional |
| `linux_audit_exec_required_records_ambiguous_synthetic.log` | synthetic ambiguity case | `SYSCALL` and `EXECVE` record-family forms | Contains a two-`SYSCALL` group, an `EXECVE`-only group, and a `SYSCALL`-only group |
| `linux_audit_shared_memory_execution_contract_synthetic.log` | synthetic | RHEL/Linux Audit compound execution record structure; shared-memory path candidate motivated by the official SigmaHQ, Elastic Security, and Splunk Security Content rules listed below | Neutral synthetic paths, identities, outcomes, missing fields, optional conflicts, and a conspicuous privacy canary cover detector-contract boundaries; no captured attack or filesystem state is represented |
| `linux_audit_shared_memory_execution_scope_synthetic.log` | synthetic | Repository loader scope contract plus RHEL/Linux Audit compound execution record structure | Interleaved records, reused event ID across nodes, same/different sessions, and non-canonical record order are synthetic and establish grouping/determinism only |

The fixtures preserve raw ambiguity only. They do not define future argument
reconstruction, PATH ordering, execution candidate acceptance, or normalization
behavior.

## Shared-memory execution fixture sources

Access date for the sources in this section: 2026-09-26.

The shared-memory fixtures use Linux Audit raw record structure from the
primary sources above. Their review-candidate motivation comes from these
official rule repositories:

- SigmaHQ, `Process Execution From Shared Memory Directory`:
  <https://github.com/SigmaHQ/sigma/blob/master/rules/linux/process_creation/proc_creation_lnx_susp_exec_from_dev_shm.yml>
- Elastic Security, `Binary Executed from Shared Memory Directory`:
  <https://github.com/elastic/detection-rules/blob/main/rules/linux/execution_process_started_in_shared_memory_directory.toml>
- Splunk Security Content, `Linux Binary Executed from Shared Memory Directory`:
  <https://github.com/splunk/security_content/blob/develop/detections/endpoint/linux_binary_executed_from_shared_memory_directory.yml>

Those rules motivate investigation of observed execution from shared-memory
paths. They do not make these synthetic fixtures evidence of malware,
fileless execution, privilege escalation, persistence, compromise, attacker
intent, attack success, binary trust, filesystem mount type or permissions,
or parent-child causation. Product-specific EDR fields are not added to the
Linux Audit records.
