# Device inventory contract v1

Use `--inventory PATH` (repeatable) to import collector-supplied device identity and firmware. The input is UTF-8 JSON Lines: one object per physical line. The complete synthetic example is in `examples/inventory.jsonl`. This is our normalized format, not a claim of direct vendor, CSET or Malcolm export compatibility.

| Field | Required value |
| --- | --- |
| `schema_version` | Integer `1` (a boolean is invalid) |
| `target` | An in-scope literal IP address, or a URL whose host is that IP |
| `manufacturer` | Nonempty string |
| `model` | Nonempty string |
| `firmware` | Nonempty string; use an explicit declaration such as `unknown` if not established |
| `collector` | Nonempty string identifying who recorded the observation |
| `collected_at` | ISO 8601 datetime containing `T` and an explicit timezone, e.g. `2026-11-07T12:00:00+01:00` |
| `source_ref` | Nonempty reference to the original observation/export in the engagement record |

Strings are limited to 4000 characters. Collector text and timestamps are assertions from the supplier of the file, not authenticated identities or clock measurements. Timestamps are normalized to UTC in the report. Capture the actual firmware display/export rather than guessing it from a network banner. No automatic advisory lookup or firmware version comparison is performed.

The output adds `device_inventory` to the assessment alongside the existing string-address `assets` array. Each device includes target, manufacturer, model, firmware and an evidence array with file hash, physical line, collector, normalized collection time and source reference. Existing schema-v1 readers should ignore new optional fields they do not use. The assessment also records its generating tool version and approved asset ranges.

Identical device identity/firmware records merge their provenance. Different manufacturer/model/firmware values for the same target are rejected rather than silently overwriting each other. For a firmware update, create a new assessment; a historical record and a retest are different observations, not a conflicting single inventory.

An invalid record rolls back its entire file import. Results returned to API consumers are independent snapshots. Inventory alone creates no vulnerability finding, and an asset absent from an input is not proven absent from the network.

Treat this file and the generated report as engagement data. Collector names, asset addresses and source references may be sensitive; keep real inputs outside Git and review reports before sharing.
