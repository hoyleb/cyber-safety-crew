# Architecture and integration contracts

## Ownership

This repository owns engagement metadata, an evidence model, import adapters, the operator runbook, report generation, device profiles, adapter compatibility tests and upstream update review. Upstream projects own their scanners, analyzers and assessment engines.

We use a monorepo for our packages and instructions, with external versioned tools. Branches are for changes under review. A permanent branch for every dependency would create parallel products rather than combine them.

## Packages

| Logical package | Present implementation | Boundary |
| --- | --- | --- |
| Core/scope | `src/cyber_safety_crew/core.py: Scope` | IP/CIDR report filtering; no assertion of legal authorization |
| Evidence adapters | `Assessment.ingest` | Zeek JSON connection logs, Nuclei JSONL, our manual JSONL |
| Reporting | `report` and CLI | Deterministic Markdown and normalized JSON; escaped untrusted text |
| Profiles | `profiles/refrigeration.json` | Assessment checklist metadata, not executable tests |
| Upstream review | `scripts/check_upstreams.py` | Explicit maintainer network operation; separate from assessment |
| AI assistant | Contract only | Optional future summarization; no integrated model calls |
| Live runner | Planned | Must be implemented independently of a model's suggested actions |

The initial code keeps modules small in one installable Python package. Split into separately versioned packages only when integration ownership or consumers justify it.

## Evidence contract v1

An assessment contains an ID, site, authorization reference, offline mode, IP inventory, connection record count, imported sources, normalized findings and limitations. Each source has a kind, basename and SHA-256. Each finding has a stable ID, literal-IP target, check ID used for deduplication, title, severity, evidence status, remediation text, optional reviewer and source/line references. The check ID is also included in the stable ID derivation.

Severity describes consequence; status describes evidence. They must remain separate. Imported Nuclei results are `potential` regardless of severity. Manual `confirmed` is a human declaration requiring a reviewer name, not a cryptographic or automated validation of that person. Contradictory duplicate findings fail import for reconciliation.

No real vulnerability detection rule is included in v0.1. Zeek imports inventory only. The synthetic Nuclei record demonstrates normalization, not a known vulnerability. There is no firmware-advisory matching engine yet.

## Future execution boundary

Before live probes can be field-enabled, implement all of the following:

- Engagement-specific target and action allowlists, validity window, network vantage, operator identity and an external emergency stop.
- Reviewed immutable check packages with exact template bytes/digests, tool version, device family, request budget and stop conditions. Pin the Nuclei engine and template set independently.
- DNS/IP validation at planning and connection time, redirect handling, IPv4/IPv6 parity, and enforced egress to approved destinations. Subprocess arguments alone do not reliably constrain an extensible scanner.
- Network-level isolation of the runner, with no arbitrary script, code-template, browser or shell execution exposed to a model. Disable outbound callback services and automatic downloads in the field profile.
- Explicit separation of offline review, passive acquisition, active assessment and remediation. A passive acquisition interface must not accidentally bridge production networks.
- Device-reviewed checks exercised against a lab representative of the intended equipment. An HTTP GET can trigger device behavior; read-only intent is not a universal safety guarantee.
- A complete action log with exact versions and checks, bounded output, timeout, rate/concurrency limits, cancellations and tested recovery behavior. Lower speed complements device suitability rather than replacing it.

These controls are requirements for a future implementation. The current importer enforces no network execution boundary because it performs no network execution.

## AI boundary

The first AI integration should receive a minimized normalized assessment and approved reference material. Treat imported content as quoted evidence, not instructions. Every generated recommendation needs an evidence reference and an uncertainty statement when appropriate. Keep deterministic findings as the source of truth, preserve the original report, and require human review of model prose. No execution channel or credentials should be accessible to the report-writing model. Run locally or use an engagement-approved service; do not upload raw captures by default.

## Data lifecycle

Keep original evidence in encrypted engagement storage with separately controlled access. Record acquisition time, collector, scope, vantage, tool version and collection settings outside the source file hash. Store only necessary metadata in reports. The current application does not enforce retention, authenticate operators, encrypt files, provide a central case store or redact every possible secret in free text. Those remain operational responsibilities until implemented.
