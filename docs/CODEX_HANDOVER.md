# Codex handover

Objective: turn this working offline starter into a coordinated community assessment kit. Preserve the authorization assumptions, production process constraints and evidence distinctions already captured in AGENTS.md.

## Start here

Read README.md, AGENTS.md, docs/ARCHITECTURE.md, docs/ROADMAP.md and docs/UPSTREAMS.md. Run `make test` and `make demo`. Review `demo-output/report.md` to understand what the current implementation actually does.

## First useful implementation task

Advance M1: select a supported Zeek release and add sanitized real JSON connection-log fixtures with acquisition/version metadata. Device inventory schema/import support is already available in v0.2 (docs/INVENTORY.md); extend collection metadata consistently to the other evidence types. Do not launch third-party tools or query real targets just to populate examples.

Then implement advisory matching against a small reviewed manufacturer data set. Match exact product/firmware and preserve uncertainty for ambiguous versions. Do not invent vulnerabilities or treat lexical string version ordering as a universal firmware comparison algorithm. Support vendor-specific version schemes and regression fixtures.

## Module boundaries

Keep source-specific fields in adapters; stable evidence in core; device guidance in profiles; report formatting separate; network execution isolated. Refactor the current single core module when new adapters justify it, without changing the evidence contract accidentally.

## Upstream coordination

Use `scripts/check_upstreams.py` from a maintainer environment. It creates a review candidate only. Review releases and advisories and add fixtures before claiming compatibility. Submit general fixes upstream and keep source forks small if needed. Use short-lived PR branches for each integration change.

## Delivery requirements

Deliver working code, relevant regression tests, updated limitations/runbook and a concise validation record. Call out unsupported formats explicitly. No claim that a tool is integrated merely because its repo is tracked; no claim that a synthetic test validates real equipment; no implicit live network activity from an offline command.

## Repository

Canonical repository: https://github.com/hoyleb/cyber-safety-crew. Continue through focused branches and pull requests against `main`. Check the Actions page for CI and upstream-review run results. Do not include real engagement files. Repository publication does not make the starter a validated production assessment tool; follow the roadmap milestones before field use.
