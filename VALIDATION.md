# Validation record — 7 November 2026

## v0.2.0 evidence-integrity improvements

- 35 automated tests pass: the original 16 plus 19 regression/feature tests for device inventory/provenance, transactional imports, snapshot isolation, strict JSON and field validation, Unicode line handling, Nuclei target consistency and upstream-output path protection.
- Source compilation succeeds. The synthetic demo produces two asset addresses, one enriched device inventory record and two imported findings, with collection metadata and evidence references.
- The v0.2.0 wheel builds, installs using `--no-index --no-deps`, and generates an inventory report through its installed CLI.
- Existing v0.1.0 validation below remains the historical publication record. No real controllers, production targets or third-party scanner executions were used to validate v0.2.0. GitHub CI status is available on the change's pull request and Actions page.

## v0.1.0 initial validation

- Python unittest suite: 16 passing tests, covering the offline end-to-end demo, evidence provenance, scope rejection, IP-only handling, IPv6, active-mode rejection, malformed/oversized input, duplicate reconciliation, output preservation, report escaping and upstream candidate behavior.
- Source compilation: passed for the package and maintainer script.
- Python wheel packaging: built successfully without installing third-party runtime dependencies.
- Built wheel: installed with `--no-index --no-deps` into an isolated target directory; its module CLI help ran successfully.
- Synthetic CLI demonstration: produced a Markdown report and normalized JSON with two observed in-scope assets and two imported findings, with limitations and source references.
- Upstream bookmarks: source commit metadata retrieved from GitHub for Zeek, Malcolm, Nuclei, Nuclei Templates and CSET on 7 November 2026. The checkout action commit was resolved from its v4 tag.

## Hosted publication

Published to https://github.com/hoyleb/cyber-safety-crew on 7 November 2026. The initial full-source commit is `5d4f9e5905eb5c572bf60b7b2ee1bda9f62cca74`. GitHub Actions completed `make test` and `make demo` successfully: https://github.com/hoyleb/cyber-safety-crew/actions/runs/42367382685.

The upstream-review job was correctly skipped for this push event; it is configured for the weekly schedule and manual workflow dispatch. Its live HTTP path has not yet been exercised by this publication. The update proposal logic was tested with fixture responses.

No production targets, network probes, packet captures or refrigeration controllers were exercised. The third-party products were not installed or launched. Adapter fixtures are synthetic; this is not equipment compatibility validation.
