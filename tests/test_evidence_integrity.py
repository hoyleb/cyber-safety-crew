"""Regression cases found during the v0.2 evidence review."""

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cyber_safety_crew.__main__ import main
from cyber_safety_crew.core import Assessment, Scope, json_lines, load_json, nuclei_target, report

ROOT = Path(__file__).resolve().parents[1]


class EvidenceIntegrityTests(unittest.TestCase):
    def assessment(self):
        return Assessment(Scope(load_json((ROOT / "examples/scope.json").read_bytes())))

    def inventory(self):
        return json.loads((ROOT / "examples/inventory.jsonl").read_text())

    def ingest_rows(self, assessment, kind, rows):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "evidence.jsonl"
            path.write_text("\n".join(json.dumps(row) for row in rows) + "\n")
            assessment.ingest(kind, path)

    def test_inventory_cli_is_offline_and_reports_collection_metadata(self):
        with tempfile.TemporaryDirectory() as temp, patch("socket.socket", side_effect=AssertionError("network forbidden")):
            out = Path(temp) / "result"
            main(["assess", "--scope", str(ROOT / "examples/scope.json"),
                  "--inventory", str(ROOT / "examples/inventory.jsonl"), "--output", str(out)])
            result = json.loads((out / "assessment.json").read_text())
            self.assertEqual(result["tool_version"], "0.2.0")
            self.assertEqual(result["asset_ranges"], ["192.0.2.0/24"])
            self.assertEqual(result["assets"], ["192.0.2.20"])
            self.assertEqual(result["findings"], [])  # Inventory is not a vulnerability finding.
            device = result["device_inventory"][0]
            self.assertEqual(device["firmware"], "example-1.0")
            self.assertEqual(device["evidence"][0]["collected_at"], "2026-11-07T11:00:00+00:00")
            self.assertEqual(device["evidence"][0]["line"], 1)
            rendered = (out / "report.md").read_text()
            self.assertIn("Synthetic Controller", rendered)
            self.assertIn("Synthetic maintainer", rendered)
            self.assertIn("not independently authenticated", rendered)

    def test_failed_zeek_import_preserves_existing_state(self):
        assessment = self.assessment()
        assessment.ingest("manual", ROOT / "examples/manual.jsonl")
        before = assessment.result()
        with self.assertRaises(ValueError):
            self.ingest_rows(assessment, "zeek", [
                {"id.orig_h": "192.0.2.99", "id.resp_h": "192.0.2.98"},
                {"id.orig_h": "not-an-ip", "id.resp_h": "192.0.2.98"}])
        self.assertEqual(assessment.result(), before)

    def test_failed_nuclei_import_keeps_no_partial_findings(self):
        assessment = self.assessment()
        before = assessment.result()
        with self.assertRaises(ValueError):
            self.ingest_rows(assessment, "nuclei", [
                {"template-id": "test", "ip": "192.0.2.50", "info": {"name": "First"}},
                {"template-id": "test", "ip": "198.51.100.50", "info": {"name": "Outside"}}])
        self.assertEqual(assessment.result(), before)

    def test_conflicting_inventory_rolls_back_whole_file(self):
        assessment = self.assessment()
        original = self.inventory()
        with self.assertRaisesRegex(ValueError, "Conflicting inventory"):
            self.ingest_rows(assessment, "inventory", [original, {**original, "firmware": "different"}])
        self.assertEqual(assessment.result()["device_inventory"], [])
        self.assertEqual(assessment.result()["assets"], [])

    def test_repeated_inventory_merges_provenance(self):
        assessment = self.assessment()
        original = self.inventory()
        self.ingest_rows(assessment, "inventory", [original, {**original, "collector": "Second collector"}])
        devices = assessment.result()["device_inventory"]
        self.assertEqual(len(devices), 1)
        self.assertEqual(len(devices[0]["evidence"]), 2)

    def test_inventory_requires_timezone_and_explicit_details(self):
        for overrides in [
            {"collected_at": "2026-11-07T11:00:00"}, {"collected_at": "2026-11-07"},
            {"collected_at": "not-a-date"}, {"firmware": None}, {"collector": ""},
            {"source_ref": ""}, {"schema_version": True}, {"target": "198.51.100.8"}]:
            with self.subTest(overrides=overrides), self.assertRaises(ValueError):
                self.ingest_rows(self.assessment(), "inventory", [{**self.inventory(), **overrides}])

    def test_inventory_text_is_escaped_in_report(self):
        assessment = self.assessment()
        self.ingest_rows(assessment, "inventory", [{**self.inventory(),
            "model": '[bad](https://bad.example) <script>alert(1)</script>'}])
        rendered = report(assessment.result())
        self.assertNotIn("<script>", rendered)
        self.assertIn(r"\[bad\]\(", rendered)

    def test_result_is_a_snapshot_not_a_mutable_view(self):
        assessment = self.assessment()
        assessment.ingest("inventory", ROOT / "examples/inventory.jsonl")
        snapshot = assessment.result()
        snapshot["sources"].clear()
        snapshot["device_inventory"][0]["evidence"].clear()
        self.assertEqual(len(assessment.result()["sources"]), 1)
        self.assertEqual(len(assessment.result()["device_inventory"][0]["evidence"]), 1)

    def test_duplicate_json_keys_are_rejected_in_scope_and_records(self):
        with self.assertRaisesRegex(ValueError, "Duplicate JSON key"):
            load_json('{"mode":"active","mode":"offline"}')
        with self.assertRaisesRegex(ValueError, "line 1"):
            list(json_lines(b'{"target":"192.0.2.1","target":"198.51.100.1"}\n'))

    def test_non_json_number_constants_are_rejected(self):
        for constant in ("NaN", "Infinity", "-Infinity"):
            with self.subTest(constant=constant), self.assertRaises(ValueError):
                load_json('{"value":' + constant + '}')

    def test_scope_disallows_boolean_version_and_numeric_ranges(self):
        original = load_json((ROOT / "examples/scope.json").read_bytes())
        for overrides in ({"schema_version": True}, {"asset_ranges": [1]}, {"asset_ranges": [False]}):
            with self.subTest(overrides=overrides), self.assertRaises(ValueError):
                Scope({**original, **overrides})

    def test_unicode_line_separator_preserves_valid_json_record(self):
        data = '{"value":"first\u2028second"}\n{"value":"third"}\n'.encode()
        rows = list(json_lines(data))
        self.assertEqual([line for line, _ in rows], [1, 2])
        self.assertEqual(rows[0][1]["value"], "first\u2028second")

    def test_record_limit_allows_trailing_newline_and_rejects_extra_record(self):
        with patch("cyber_safety_crew.core.MAX_RECORDS", 2):
            self.assertEqual(len(list(json_lines(b'{}\n{}\n'))), 2)
            with self.assertRaises(ValueError):
                list(json_lines(b'{}\n{}\n{}\n'))

    def test_conflicting_nuclei_literal_targets_are_rejected(self):
        for row in [
            {"ip": "192.0.2.1", "host": "https://198.51.100.1"},
            {"ip": "192.0.2.1", "matched-at": "http://192.0.2.2/path"},
            {"host": "192.0.2.1:443", "matched-at": "https://192.0.2.2"}]:
            with self.subTest(row=row), self.assertRaises(ValueError):
                nuclei_target(row)

    def test_nuclei_hostname_with_recorded_ip_needs_no_dns(self):
        with patch("socket.getaddrinfo", side_effect=AssertionError("DNS forbidden")):
            self.assertEqual(nuclei_target({"ip": "192.0.2.1", "host": "https://controller.example"}), "192.0.2.1")
            self.assertEqual(nuclei_target({"host": "192.0.2.1:443"}), "192.0.2.1")
            with self.assertRaises(ValueError):
                nuclei_target({"host": "https://controller.example"})

    def test_numeric_ip_and_malformed_finding_fields_are_rejected(self):
        for overrides in ({"severity": []}, {"status": {}}, {"reviewer": {}},
                          {"reviewer": "bad\x00value"}, {"schema_version": True}):
            original = json.loads((ROOT / "examples/manual.jsonl").read_text())
            with self.subTest(overrides=overrides), self.assertRaises(ValueError):
                self.ingest_rows(self.assessment(), "manual", [{**original, **overrides}])
        with self.assertRaises(ValueError):
            self.ingest_rows(self.assessment(), "zeek", [{"id.orig_h": 3221225985, "id.resp_h": "192.0.2.2"}])

    def test_deep_malformed_json_produces_cli_error_without_partial_report(self):
        with tempfile.TemporaryDirectory() as temp:
            path, out = Path(temp) / "malformed.jsonl", Path(temp) / "output"
            path.write_text("[" * 2000 + "]" * 2000)
            with self.assertRaises(SystemExit) as caught:
                main(["assess", "--scope", str(ROOT / "examples/scope.json"),
                      "--manual", str(path), "--output", str(out)])
            self.assertEqual(caught.exception.code, 2)
            self.assertFalse(out.exists())
