# Changelog

## 0.2.0 — 7 November 2026

- Add offline device-inventory import and reporting with manufacturer, model, firmware, collector, collection time and source provenance.
- Preserve prior assessment state when any record in an imported file fails.
- Return independent result snapshots and include generating tool version and asset ranges.
- Reject ambiguous duplicate JSON keys, non-JSON numeric constants, malformed field types, numeric IP/range coercions and conflicting Nuclei literal-IP fields.
- Preserve valid JSON strings containing Unicode line separators and correctly handle a trailing newline at the record limit.
- Prevent upstream-review output paths from overwriting the reviewed lock or each other.
- Extend regression coverage, documentation and the packaged release. All equipment examples remain synthetic.

## 0.1.0 — 7 November 2026

Initial offline evidence-import/report starter, operator runbook, shared development instructions and upstream coordination workflow.
