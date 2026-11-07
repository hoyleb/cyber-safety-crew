import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("check_upstreams", ROOT / "scripts/check_upstreams.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class UpstreamTests(unittest.TestCase):
    def test_unchanged_snapshot_does_not_churn_lock(self):
        lock = json.loads((ROOT / "upstreams.lock.json").read_text())
        by_repo = {p["repository"]: p for p in lock["projects"].values()}
        proposed, changed = module.propose(lock, lambda repo: (by_repo[repo]["observed_commit"], by_repo[repo]["observed_commit_date"]))
        self.assertEqual(proposed, lock)
        self.assertEqual(changed, [])

    def test_candidate_never_mutates_reviewed_input(self):
        lock = json.loads((ROOT / "upstreams.lock.json").read_text())
        original = json.dumps(lock, sort_keys=True)
        proposed, changed = module.propose(lock, lambda repo: ("a" * 40, "2026-11-07T00:00:00Z"))
        self.assertEqual(json.dumps(lock, sort_keys=True), original)
        self.assertEqual(len(changed), 5)
        self.assertTrue(all(p["observed_commit"] == "a" * 40 for p in proposed["projects"].values()))
