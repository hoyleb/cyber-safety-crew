import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cyber_safety_crew.__main__ import main
from cyber_safety_crew.core import Assessment, Scope, md

ROOT = Path(__file__).resolve().parents[1]


class AssessmentTests(unittest.TestCase):
    def scope(self):
        return Scope(json.loads((ROOT / "examples/scope.json").read_text()))

    def test_complete_demo_runs_without_network_and_has_provenance(self):
        with tempfile.TemporaryDirectory() as temp, patch("socket.socket", side_effect=AssertionError("network forbidden")):
            out = Path(temp) / "output"
            main(["assess", "--scope", str(ROOT / "examples/scope.json"),
                  "--zeek", str(ROOT / "examples/conn.jsonl"),
                  "--nuclei", str(ROOT / "examples/nuclei.jsonl"),
                  "--manual", str(ROOT / "examples/manual.jsonl"), "--output", str(out)])
            doc = json.loads((out / "assessment.json").read_text())
            self.assertEqual(doc["assets"], ["192.0.2.10", "192.0.2.20"])
            self.assertEqual(doc["connection_records"], 2)
            self.assertEqual(len(doc["findings"]), 2)
            self.assertTrue(all(x["check_id"].startswith("synthetic-") for x in doc["findings"]))
            self.assertEqual(len(doc["sources"]), 3)
            self.assertEqual({x["status"] for x in doc["findings"]}, {"potential", "untested"})
            self.assertTrue(all(len(x["sha256"]) == 64 for x in doc["sources"]))
            self.assertIn("No findings does not establish security", (out / "report.md").read_text())
            self.assertEqual(out.stat().st_mode & 0o777, 0o700)
            self.assertEqual((out / "assessment.json").stat().st_mode & 0o777, 0o600)

    def test_no_dns_resolution_for_hostname_targets(self):
        with patch("socket.getaddrinfo", side_effect=AssertionError("DNS forbidden")):
            with self.assertRaises(ValueError):
                self.scope().target("https://controller.example")

    def test_scope_excludes_outside_ipv4_and_ipv6(self):
        for target in ["198.51.100.1", "https://198.51.100.1/path", "::1"]:
            with self.subTest(target=target), self.assertRaises(ValueError):
                self.scope().target(target)

    def test_ipv6_scope_support(self):
        scope = Scope({"schema_version": 1, "assessment_id": "demo", "site": "demo",
                       "authorization_ref": "demo", "mode": "offline", "asset_ranges": ["2001:db8::/32"]})
        self.assertEqual(scope.target("https://[2001:db8::1]/"), "2001:db8::1")

    def test_active_mode_is_rejected(self):
        doc = json.loads((ROOT / "examples/scope.json").read_text())
        doc["mode"] = "active"
        with self.assertRaises(ValueError):
            Scope(doc)

    def test_imported_nuclei_is_never_automatically_confirmed(self):
        assessment = Assessment(self.scope())
        assessment.ingest("nuclei", ROOT / "examples/nuclei.jsonl")
        self.assertEqual(assessment.result()["findings"][0]["status"], "potential")

    def test_bad_import_creates_no_report(self):
        with tempfile.TemporaryDirectory() as temp:
            path, out = Path(temp) / "bad.jsonl", Path(temp) / "output"
            path.write_text('{"template-id":"x","host":"198.51.100.8","info":{"name":"Outside scope"}}\n')
            with self.assertRaises(SystemExit) as raised:
                main(["assess", "--scope", str(ROOT / "examples/scope.json"),
                      "--nuclei", str(path), "--output", str(out)])
            self.assertEqual(raised.exception.code, 2)
            self.assertFalse(out.exists())

    def test_invalid_json_creates_no_report(self):
        with tempfile.TemporaryDirectory() as temp:
            path, out = Path(temp) / "bad.jsonl", Path(temp) / "output"
            path.write_text("not JSON\n")
            with self.assertRaises(SystemExit):
                main(["assess", "--scope", str(ROOT / "examples/scope.json"),
                      "--zeek", str(path), "--output", str(out)])
            self.assertFalse(out.exists())

    def test_missing_evidence_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp) / "output"
            with self.assertRaises(SystemExit):
                main(["assess", "--scope", str(ROOT / "examples/scope.json"), "--output", str(out)])
            self.assertFalse(out.exists())

    def test_existing_reports_are_not_overwritten(self):
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp) / "output"
            out.mkdir()
            report = out / "report.md"
            report.write_text("original")
            with self.assertRaises(SystemExit):
                main(["assess", "--scope", str(ROOT / "examples/scope.json"),
                      "--zeek", str(ROOT / "examples/conn.jsonl"), "--output", str(out)])
            self.assertEqual(report.read_text(), "original")

    def test_confirmed_manual_finding_requires_named_reviewer(self):
        assessment = Assessment(self.scope())
        kwargs = dict(source={"kind": "manual", "sha256": "a" * 64}, row=1,
            target="192.0.2.1", title="Reviewed result", severity="low", status="confirmed",
            remediation="Apply approved fix", check_id="manual-1")
        with self.assertRaises(ValueError):
            assessment.add(**kwargs)
        assessment.add(**kwargs, reviewer="Synthetic reviewer")
        self.assertEqual(assessment.result()["findings"][0]["status"], "confirmed")

    def test_duplicate_provenance_and_conflicts(self):
        assessment = Assessment(self.scope())
        kwargs = dict(source={"kind": "manual", "sha256": "a" * 64},
            target="192.0.2.1", title="Review", severity="low", status="potential",
            remediation="Check configuration", check_id="manual-1")
        assessment.add(**kwargs, row=1)
        assessment.add(**kwargs, row=2)
        self.assertEqual(len(assessment.result()["findings"][0]["evidence"]), 2)
        kwargs["severity"] = "critical"
        with self.assertRaises(ValueError):
            assessment.add(**kwargs, row=3)

    def test_markdown_escapes_untrusted_links_html_and_headings(self):
        escaped = md('[click](https://bad.example)\n# injected <script>alert(1)</script>')
        self.assertNotIn("<script>", escaped)
        self.assertNotIn("\n#", escaped)
        self.assertIn(r"\[click\]\(", escaped)

    def test_oversized_input_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "large.jsonl"
            path.write_bytes(b" " * 101)
            with patch("cyber_safety_crew.core.MAX_BYTES", 100), self.assertRaises(ValueError):
                Assessment(self.scope()).ingest("zeek", path)


if __name__ == "__main__":
    unittest.main()
