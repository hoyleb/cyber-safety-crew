"""Offline-only command line interface."""

import argparse
import json
import os
from pathlib import Path

from .core import Assessment, Scope, read_bytes, report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    assess = sub.add_parser("assess", help="Import existing evidence and generate a report")
    assess.add_argument("--scope", type=Path, required=True)
    assess.add_argument("--zeek", type=Path, action="append", default=[])
    assess.add_argument("--nuclei", type=Path, action="append", default=[])
    assess.add_argument("--manual", type=Path, action="append", default=[])
    assess.add_argument("--output", type=Path, required=True, help="New output directory")
    args = parser.parse_args(argv)
    try:
        assessment = Assessment(Scope(json.loads(read_bytes(args.scope))))
        for kind in ("zeek", "nuclei", "manual"):
            for path in getattr(args, kind):
                assessment.ingest(kind, path)
        if not assessment.sources:
            raise ValueError("At least one evidence input is required")
        doc = assessment.result()
        # Validate everything before creating an output directory; never overwrite a report.
        result_json, result_md = json.dumps(doc, indent=2) + "\n", report(doc)
        args.output.mkdir(mode=0o700, parents=False, exist_ok=False)
        for filename, content in (("assessment.json", result_json), ("report.md", result_md)):
            with (args.output / filename).open("x", encoding="utf-8") as handle:
                os.chmod(handle.name, 0o600)
                handle.write(content)
    except (ValueError, OSError, KeyError, TypeError) as exc:
        parser.exit(2, f"Assessment failed: {exc}\n")
    print(f"Created {args.output / 'report.md'} and assessment.json (offline review only)")


if __name__ == "__main__":
    main()
