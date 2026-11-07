# One operator runbook

## 1. Prepare the engagement

Confirm the authorized asset list and technical contacts. Record the network owner and refrigeration maintainer, emergency contact, review window, data handling, permitted vantage points and permitted actions. A store-floor visit and an outside-in assessment answer different questions. Do not infer public internet exposure from an internal observation.

Create an engagement copy of `examples/scope.json` outside Git. Use a genuine authorization reference and only the approved IP ranges. The `mode` remains `offline` in this release. Scope metadata is a record, not proof of permission.

## 2. Gather existing evidence

Request equipment model/firmware inventories, network diagrams, remote maintenance arrangements, account policies and update/support information. Prefer relevant exports and metadata over broad captures. Apply the checklist in `profiles/refrigeration.json`.

For existing Zeek captures, obtain JSON Lines connection logs. Tab-separated Zeek logs are not supported by this importer. Malcolm users can supply the corresponding Zeek-format evidence; arbitrary Malcolm/OpenSearch exports require a future adapter. Collecting live traffic requires an appropriate mirror/TAP setup or a capture supplied by the operator; joining guest Wi-Fi does not make other network traffic visible.

Existing Nuclei JSONL findings may be imported if their collection was separately authorized. The importer does not run Nuclei or retroactively validate the collection. IP-only target checks do not establish that the original scan stayed in scope.

CSET findings can be manually summarized into our `examples/manual.jsonl` format with source references maintained in the engagement record. This is not a native CSET export parser.

## 3. Review offline

Run `csc assess` or its source-based equivalent in README.md with fresh output paths. Out-of-scope finding targets or malformed records fail the operation. For legitimate hostname results, obtain a documented IP mapping from the collection time; do not casually resolve historical hostnames and pretend they identify the same equipment.

Read the report's coverage limitations. Check model, firmware and exact manufacturer guidance before turning a suspected vulnerability into an action. Confirmations must be documented by a reviewer; scanner output alone is not proof of exploitability.

## 4. Report to the owner and maintainer

For every material finding, include the affected asset, vantage, observed condition, evidence, likely consequence, recommended action, responsible maintainer and retest method. Separate verified facts from hypotheses. Avoid public details that reveal an individual shop's exposed controls. Coordinate a suspected new product vulnerability privately with the vendor before publication.

Refrigeration priorities include management interface exposure, protected remote maintenance, account access, supported firmware, segmentation, independent temperature alarming and recovery. A current firmware version alone does not establish secure configuration. Changing remote access requires coordination so that essential maintenance and alarm delivery still work.

## 5. Fix and retest

The owner and qualified maintainer plan and implement changes, including backups and restoration arrangements. Collect new evidence after changes, run a separate assessment, and reconcile finding IDs and statuses. v0.1 does not yet automate comparison between assessments.

Live checks, controller writes and automatic remediation are not implemented. Follow docs/ROADMAP.md for the staged runner implementation instead of improvising commands on production equipment.

## Data handling

Keep real files in an encrypted engagement directory outside the source repository. Never commit a capture, customer network map, credentials or report. Scope filtering prevents reporting unrelated asset addresses, but does not sanitize raw inputs or arbitrary text. Review all report content before external sharing and apply the agreed retention/deletion process.
