# Validation record — 7 November 2026

- Python unittest suite: 16 passing tests, covering the offline end-to-end demo, evidence provenance, scope rejection, IP-only handling, IPv6, active-mode rejection, malformed/oversized input, duplicate reconciliation, output preservation, report escaping and upstream candidate behavior.
- Source compilation: passed for the package and maintainer script.
- Python wheel packaging: built successfully without installing third-party runtime dependencies.
- Built wheel: installed with `--no-index --no-deps` into an isolated target directory; its module CLI help ran successfully.
- Synthetic CLI demonstration: produced a Markdown report and normalized JSON with two observed in-scope assets and two imported findings, with limitations and source references.
- Upstream bookmarks: source commit metadata retrieved from GitHub for Zeek, Malcolm, Nuclei, Nuclei Templates and CSET on 7 November 2026. The checkout action commit was resolved from its v4 tag.

No production targets, network probes, packet captures or refrigeration controllers were exercised. The third-party products were not installed or launched. Adapter fixtures are synthetic; this is not equipment compatibility validation. The GitHub workflow is supplied but has not run in a hosted repository. The update proposal logic was tested with fixture responses; the Python checker's live HTTP path was not exercised in this environment.
