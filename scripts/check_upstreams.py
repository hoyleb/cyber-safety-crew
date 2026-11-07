#!/usr/bin/env python3
"""Maintainer-only network operation: propose source snapshots, never install or merge."""

import argparse
from copy import deepcopy
import datetime
import difflib
import json
import os
from pathlib import Path
import re
from urllib.request import Request, urlopen


def fetch_commit(repository):
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError("Invalid GitHub repository")
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "cyber-safety-crew-upstream-review"}
    if os.environ.get("GH_TOKEN"):
        headers["Authorization"] = "Bearer " + os.environ["GH_TOKEN"]
    request = Request(f"https://api.github.com/repos/{repository}/commits?per_page=1", headers=headers)
    with urlopen(request, timeout=20) as response:
        data = response.read(2_000_001)
    if len(data) > 2_000_000:
        raise ValueError("Upstream response too large")
    commit = json.loads(data)[0]
    sha = commit["sha"]
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise ValueError("Invalid commit SHA")
    return sha, commit["commit"]["committer"]["date"]


def propose(lock, fetcher=fetch_commit):
    candidate = deepcopy(lock)
    changed = []
    for name, project in candidate["projects"].items():
        sha, date = fetcher(project["repository"])
        if sha != project["observed_commit"]:
            changed.append(name)
            project["observed_commit"] = sha
            project["observed_commit_date"] = date
            project["compatibility"] = "not integration-tested against this snapshot"
    if changed:
        candidate["checked_at"] = datetime.date.today().isoformat()
    return candidate, changed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", type=Path, default=Path("upstreams.lock.json"))
    parser.add_argument("--output", type=Path, default=Path("upstreams.candidate.json"))
    parser.add_argument("--summary", type=Path, default=Path("upstream-review.md"))
    args = parser.parse_args()
    if args.lock.resolve() == args.output.resolve():
        parser.error("Candidate output must not overwrite the reviewed lock")
    lock = json.loads(args.lock.read_text())
    candidate, changed = propose(lock)
    before, after = json.dumps(lock, indent=2) + "\n", json.dumps(candidate, indent=2) + "\n"
    args.output.write_text(after)
    diff = "".join(difflib.unified_diff(before.splitlines(True), after.splitlines(True),
                    fromfile="upstreams.lock.json", tofile="upstreams.candidate.json"))
    summary = ("# Upstream review\n\nChanged source snapshots: " + (", ".join(changed) or "none") +
        "\n\nSource snapshots are not validated deployment pins. Review releases, advisories, licenses and adapter fixtures before adoption. No packages were installed and no branch was updated.\n\n```diff\n" + diff + "```\n")
    args.summary.write_text(summary)
    print(summary)


if __name__ == "__main__":
    main()
