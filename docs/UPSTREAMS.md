# Keeping coordinated with upstream teams

## Strategy

Use adapters and external tools first. Keep `main` as the working product and create short-lived branches such as `deps/zeek-compat`, `feature/malcolm-export-adapter` or `profile/refrigeration-v1`. A branch does not automatically follow another repository.

`upstreams.lock.json` records source commits observed through GitHub on 7 November 2026. These are review bookmarks, **not installed versions, approved deployment pins or tested compatibility claims**. No third-party source or binary is bundled. Before deploying a tool, select a supported release, verify its provenance, and record its release/commit plus binary or container digest in a separate deployment lock. Do not build a field environment from arbitrary upstream HEAD snapshots.

The Nuclei engine and Nuclei templates are tracked separately. A new template collection can change scan behavior even without an engine update. The future curated field profile must name exact approved template digests.

## Check for changes

Run this only from a maintainer environment with internet access:

```bash
python3 scripts/check_upstreams.py
```

The checker fetches public GitHub commit metadata and creates `upstreams.candidate.json` and `upstream-review.md`. `GH_TOKEN` is optional for API limits; do not put it in a command argument or commit it. The checker does not install packages, execute upstream code, change the reviewed lock, open a PR, or merge anything. An HTTP/API error fails the check rather than claiming everything is current.

The GitHub Actions workflow also runs this on its weekly schedule once published/enabled. View the candidate diff in the Actions run summary. A failed scheduled run is an unresolved update check, not a security pass. The workflow is not running while this is only a downloaded starter.

## Adopt an update

1. Check the actual releases, support status and security advisories. Default-branch movement is only a signal; the checker does not ingest advisory feeds or compare release semantics.
2. Create a short-lived dependency review branch.
3. Choose the release/commit and runtime digests you intend to support. Inspect changed formats and licenses.
4. Add sanitized real-format fixtures from that version; run adapter tests and representative lab checks. The current tests are synthetic contract tests only.
5. Update compatibility notes, the relevant source snapshot and release notes. Keep unrelated dependency upgrades separate when failures would be difficult to diagnose.
6. Review and merge the change; issue a versioned kit release. No automatic adoption of a moving `latest` tag.

## If a fork becomes necessary

Fork only the upstream needing a patch. Keep its `upstream` remote and synchronize the default branch through normal fetch/merge or rebase. Keep local changes on a small integration branch and contribute general fixes back upstream. Our coordinating repo then pins the fork's exact reviewed commit. Prefer optional submodules only when maintaining source patches is a real requirement; document recursive clone and update procedures before introducing them. No submodules are needed in v0.1.

## Primary references

- Zeek: https://github.com/zeek/zeek and https://docs.zeek.org/
- Malcolm: https://github.com/cisagov/Malcolm and https://cisagov.github.io/Malcolm/docs/
- Nuclei: https://github.com/projectdiscovery/nuclei and https://docs.projectdiscovery.io/
- Nuclei templates: https://github.com/projectdiscovery/nuclei-templates
- CSET: https://github.com/cisagov/cset
- Refrigeration alert: https://www.cert.cyber.gouv.fr/alerte/CERTFR-2026-ALE-012/
- OT security guidance: https://csrc.nist.gov/pubs/sp/800/82/r3/final

These references describe the upstream products and guidance, not endorsement of this project. Recheck current official recommendations during each assessment.
