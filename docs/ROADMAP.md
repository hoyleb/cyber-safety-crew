# Staged delivery and acceptance criteria

## M0 — Offline foundation: implemented

- One Python package and CLI, one runbook, synthetic examples and normalized reports.
- Import Zeek JSON connection logs, Nuclei JSONL results and manual findings.
- Preserve source hashes/lines, evidence status and scope-filtered inventory.
- Update checker, observed source snapshots and CI definition.
- Automated tests for offline execution, scope rejection, malformed input, report escaping, duplicate conflicts and update behavior.

Limit: no real-device integration validation, capture, live probes, native CSET import, arbitrary Malcolm export import, firmware advisory matching, model integration, encrypted case store or automated retest comparison.

## M1 — Validate useful field evidence: in progress

Implemented in v0.2: collector-supplied manufacturer/model/firmware inventory with timezone-aware collection timestamps and source references; transactional imports; strict evidence validation; independent report snapshots; report tool version and approved asset ranges.

Remaining: choose supported upstream releases, obtain sanitized real-format fixtures and add versioned adapter tests. Support Zeek TSV conversion or explicitly document the approved JSON export procedure. Implement a selected Malcolm export format and determine whether a CSET export parser is useful. Add collection metadata for the other evidence types, a reviewed vendor-advisory matching mechanism and assessment comparison.

Acceptance: a representative offline pilot produces a report whose factual claims can all be traced to source evidence; unsupported or missing data is explicit. No active traffic is required for this milestone.

## M2 — Isolated lab and bounded active runner

Implement the complete execution boundary in docs/ARCHITECTURE.md. Begin with a simulated controller service and disposable network namespaces/VMs; test destination isolation, redirects, DNS changes, IPv6, scanner callbacks, timeouts, cancellation and malicious imported text. Add only reviewed checks with lab evidence. Read-only intent alone is insufficient for production suitability.

Acceptance: disallowed actions/destinations fail at the enforcement boundary even when a model or malicious template requests them. The operator can stop execution. Every action has an audit record. Lab passes do not establish safety on all real controllers.

## M3 — Refrigeration pilot

Select one authorized shop and its maintainer. Review the exact controller family and configuration. Use passive collection first and only separately approved active checks suitable for those devices. Produce prioritized fixes and retest evidence. Validate emergency contacts, monitoring and recovery before any live check.

Acceptance: the owner receives actionable, verified findings with limitations and agreed retest outcomes; no unexpected process changes occur. Results from a single pilot are not universal certification.

## M4 — Volunteer release

Add operator onboarding, a versioned check review process, release signatures, tool/container digests, privacy/retention mechanisms, vulnerability disclosure process and maintainer ownership. Document supported devices and excluded techniques. Have an OT specialist review the field profile. Publish sanitized success/failure lessons and contribute improvements upstream.

Acceptance: a second operator can reproduce the workflow from the documentation and correctly distinguish evidence statuses and unsupported equipment.

## Optional AI report assistant

Only after deterministic evidence contracts stabilize: integrate an engagement-approved model, evidence-grounded report drafting, prompt-injection tests and human review. Keep all execution enforcement outside the model. This can proceed without giving the model credentials or direct access to production devices.
