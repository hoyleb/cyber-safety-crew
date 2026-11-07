# Cyber Safety Crew

One coordinating repository for authorized community cybersecurity assessments of shops and other small facilities. Start with refrigeration; keep the evidence model reusable for other equipment.

**Status: working offline starter, v0.2.0.** This package imports evidence and device inventory and generates reports. It does not run Zeek, Malcolm, Nuclei or CSET; capture traffic; send probes; use an LLM; or modify equipment. Adapters are tested with synthetic fixtures, not real installations. The live assessment workflow is specified for subsequent implementation.

## Try it

Python 3.11 or newer; no third-party runtime packages required. From this repository:

```bash
make test
make demo
```

Open `demo-output/report.md` and `demo-output/assessment.json`. Everything in `examples/` is synthetic and uses documentation IP addresses. `make demo` deliberately refuses to overwrite an existing output directory; choose a fresh output path for another run.

Without Make:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
PYTHONPATH=src python3 -m cyber_safety_crew assess \
  --scope examples/scope.json \
  --zeek examples/conn.jsonl \
  --nuclei examples/nuclei.jsonl \
  --manual examples/manual.jsonl \
  --inventory examples/inventory.jsonl \
  --output demo-output
```

For an installed CLI, create a virtual environment and run `python -m pip install -e .`; this may need build dependencies from your approved package source. The command then becomes `csc assess ...`. The source-based commands above avoid that installation requirement.

The release archive also contains a prebuilt wheel in `release/`. Inside an activated Python 3.11+ virtual environment, install it without contacting a package index:

```bash
python -m pip install --no-index --no-deps release/cyber_safety_crew-0.2.0-py3-none-any.whl
```

The wheel installs the CLI/runtime only. Runbook, profiles, examples and maintainer tools remain in the source folder.

## One workflow, separate upstream tools

| Component | Integration in this release | Next stage |
| --- | --- | --- |
| Zeek | Import JSON Lines `conn.log` records; inventory only in-scope IPs | Validate against captured exports from chosen supported Zeek releases |
| Malcolm | Import its underlying Zeek-format connection evidence through the same adapter | Add a versioned Malcolm export adapter; no claim of arbitrary OpenSearch JSON support |
| Nuclei | Import existing JSONL results as **potential** findings | Curated, device-reviewed active checks behind an isolated execution service |
| CSET | Reference CSET work in manually authored normalized findings | Select and test a documented export format before implementing direct import |
| AI/Codex | Project implementation instructions and evidence-handling contract | Optional constrained report assistant; no model API is integrated yet |

The original projects remain independent. We coordinate their outputs, supported versions, field procedure and reporting; we do not claim affiliation or merge their source histories.

## What's included

- Offline Python CLI and reusable import/report functions.
- One evidence format with source hashes and record references.
- Device model/firmware inventory with collector, timezone-aware collection time and source references.
- Scope filtering, input limits, no DNS resolution, and explicit evidence status.
- Synthetic examples and regression tests, including rejection cases.
- A refrigeration assessment profile and one operator runbook.
- `AGENTS.md` and `docs/CODEX_HANDOVER.md` for continuing development.
- Observed upstream source snapshots, update checker and a GitHub Actions workflow.
- Architecture, upstream contribution strategy, privacy guidance and staged delivery criteria.

Read `docs/RUNBOOK.md` for the field process; `docs/ARCHITECTURE.md` for boundaries and module contracts; `docs/UPSTREAMS.md` for updates and forks; and `docs/ROADMAP.md` for what remains.

## Input and report boundaries

`--zeek`, `--nuclei`, `--manual`, and `--inventory` can each be repeated. Nuclei records require one consistent in-scope literal IP across `ip`, `host` and `matched-at`; conflicting IPs and hostname-only records are rejected without DNS resolution. Hostnames accompanied by a recorded IP are accepted as evidence text. Zeek connections to outside addresses contribute to the connection count, but outside addresses are omitted from reported inventory. A finding or inventory device outside scope fails the entire CLI operation before output creation.

Sources are bounded at 10 MiB and 100,000 data records each. Duplicate JSON keys, non-JSON numeric constants, numeric IP/range values and malformed evidence fields are rejected. All inputs are validated before output is created. Each file import is transactional: a failure leaves the reusable `Assessment` unchanged. Results are independent snapshots. Reports are written to a new directory with restrictive POSIX permissions; on Windows use filesystem ACLs/encrypted storage appropriate to the engagement. A disk failure during output writing can still leave an incomplete directory: rerun to a new path.

Device inventory follows the contract in `docs/INVENTORY.md`. It records collector-supplied identity and firmware; it does not independently verify a device or infer vulnerability from a version string.

Raw HTTP requests/responses and full packet payloads are not copied into normalized findings. IP addresses, source filenames and manually authored text can still be sensitive. Review reports before sharing. Hashes identify bytes; they do not prove authorship, trusted collection or authenticity.

## Repository and development

Canonical repository: https://github.com/hoyleb/cyber-safety-crew. Clone it to continue development and follow `AGENTS.md` and `docs/CODEX_HANDOVER.md`. Keep real assessment data outside the repository, including in private branches.

The included GitHub Actions workflow runs tests on pushes and pull requests. Its weekly upstream review is configured for Mondays at 07:23 UTC while Actions is enabled. It produces a candidate diff in the Actions summary, does not update `main`, and does not auto-merge new tooling. GitHub scheduling can be delayed or disabled by repository settings/inactivity; inspect Actions for actual run results. No separate reminder or external scheduled task has been created.

License: MIT for this repository's original code and documentation. Third-party products and assessment content retain their own licenses; see `THIRD_PARTY.md`.
