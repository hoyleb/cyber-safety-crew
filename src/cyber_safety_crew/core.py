"""Small, deterministic import pipeline. Treat every input as untrusted data."""

from __future__ import annotations

import hashlib
import html
import ipaddress
import json
import re
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from . import __version__

MAX_BYTES = 10 * 1024 * 1024
MAX_RECORDS = 100_000
SEVERITIES = {"info", "low", "medium", "high", "critical", "unknown"}
STATUSES = {"observed", "potential", "confirmed", "untested"}
INPUT_KINDS = ("zeek", "nuclei", "manual", "inventory")


def read_bytes(path: Path) -> bytes:
    with path.open("rb") as handle:
        data = handle.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError(f"Input exceeds {MAX_BYTES} bytes: {path.name}")
    return data


def text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 4000:
        raise ValueError(f"{label} must be a nonempty string, at most 4000 characters")
    if any(ord(c) < 32 and c not in "\n\t\r" for c in value):
        raise ValueError(f"{label} contains control characters")
    return value


def literal_ip(value: object) -> str:
    value = text(value, "IP address")
    if "%" in value:
        raise ValueError("Scoped IPv6 addresses are not supported")
    return str(ipaddress.ip_address(value))


def load_json(data: str | bytes):
    """Reject ambiguous duplicate keys and non-JSON numbers such as NaN."""
    def unique_object(pairs):
        obj = {}
        for key, value in pairs:
            if key in obj:
                raise ValueError(f"Duplicate JSON key: {key}")
            obj[key] = value
        return obj

    def invalid_constant(value):
        raise ValueError(f"Invalid JSON number: {value}")

    return json.loads(data, object_pairs_hook=unique_object, parse_constant=invalid_constant)


def collection_time(value: object) -> str:
    value = text(value, "collected_at")
    if "T" not in value:
        raise ValueError("collected_at requires an ISO 8601 timestamp with a timezone")
    timestamp = datetime.fromisoformat(value)
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError("collected_at requires a timezone")
    return timestamp.astimezone(timezone.utc).isoformat()


class Scope:
    def __init__(self, doc: dict):
        if not isinstance(doc, dict) or type(doc.get("schema_version")) is not int or doc["schema_version"] != 1:
            raise ValueError("Scope requires schema_version 1")
        self.assessment_id = text(doc.get("assessment_id"), "assessment_id")
        self.site = text(doc.get("site"), "site")
        self.authorization_ref = text(doc.get("authorization_ref"), "authorization_ref")
        if doc.get("mode") != "offline":
            raise ValueError("This release supports offline mode only")
        ranges = doc.get("asset_ranges")
        if not isinstance(ranges, list) or not ranges or len(ranges) > 1000:
            raise ValueError("asset_ranges requires 1 to 1000 IP/CIDR strings")
        self.networks = [ipaddress.ip_network(text(x, "asset range"), strict=True) for x in ranges]

    def allows(self, value: str) -> bool:
        address = ipaddress.ip_address(literal_ip(value))
        return any(address.version == net.version and address in net for net in self.networks)

    def target(self, value: str) -> str:
        value = text(value, "target")
        # No DNS lookups. URL hostnames must be literal IP addresses in v0.1.
        candidate = urlsplit(value).hostname if "://" in value else value
        address = literal_ip(candidate)
        if not self.allows(address):
            raise ValueError("Finding target is outside the approved asset ranges")
        return address


def json_lines(data: bytes):
    records = 0
    for number, line in enumerate(data.decode("utf-8-sig").split("\n"), 1):
        if not line.strip() or line.startswith("#"):
            continue
        records += 1
        if records > MAX_RECORDS:
            raise ValueError("Too many records")
        try:
            row = load_json(line)
        except (ValueError, RecursionError) as exc:
            raise ValueError(f"Invalid JSON at line {number}: {exc}") from exc
        if not isinstance(row, dict):
            raise ValueError(f"Expected an object at line {number}")
        yield number, row


def nuclei_target(row: dict) -> str:
    """Require consistent literal-IP evidence without resolving hostnames."""
    addresses = set()
    if row.get("ip") not in (None, ""):
        addresses.add(literal_ip(row["ip"]))
    for field in ("host", "matched-at"):
        value = row.get(field)
        if value in (None, ""):
            continue
        value = text(value, field)
        try:
            addresses.add(literal_ip(value))
            continue
        except ValueError:
            pass
        hostname = urlsplit(value if "://" in value else "//" + value).hostname
        if hostname is None:
            raise ValueError(f"Invalid {field} target")
        try:
            addresses.add(literal_ip(hostname))
        except ValueError:
            # A DNS name is evidence text only; never resolve it during import.
            if "%" in hostname:
                raise ValueError("Scoped IPv6 addresses are not supported")
    if len(addresses) != 1:
        raise ValueError("Nuclei requires one consistent literal IP across ip/host/matched-at")
    return addresses.pop()


def fingerprint(*values: str) -> str:
    return hashlib.sha256(json.dumps(values).encode()).hexdigest()[:20]


class Assessment:
    def __init__(self, scope: Scope):
        self.scope = scope
        self.assets: set[str] = set()
        self.findings: dict[str, dict] = {}
        self.sources: list[dict] = []
        self.inventory: dict[str, dict] = {}
        self.connections = 0

    def add(self, *, source: dict, row: int, target: str, title: str, severity: str,
            status: str, remediation: str, check_id: str, reviewer: str = ""):
        target = self.scope.target(target)
        title, remediation = text(title, "title"), text(remediation, "remediation")
        check_id = text(check_id, "check_id")
        if not isinstance(severity, str) or not isinstance(status, str) or severity not in SEVERITIES or status not in STATUSES:
            raise ValueError("Unsupported severity or evidence status")
        if not isinstance(reviewer, str):
            raise ValueError("reviewer must be a string")
        if reviewer:
            text(reviewer, "reviewer")
        if status == "confirmed":
            text(reviewer, "reviewer for confirmed findings")
        key = fingerprint(source["kind"], target, check_id, title)
        evidence = {"sha256": source["sha256"], "line": row, "kind": source["kind"]}
        if key in self.findings:
            # Contradictory duplicates require human reconciliation, never silent overwrite.
            old = self.findings[key]
            if any(old[k] != v for k, v in {"severity": severity, "status": status,
                    "remediation": remediation, "reviewer": reviewer}.items()):
                raise ValueError("Conflicting duplicate finding; reconcile before import")
            if evidence not in old["evidence"]:
                old["evidence"].append(evidence)
            return
        self.assets.add(target)
        self.findings[key] = {"id": key, "check_id": check_id, "target": target, "title": title,
            "severity": severity, "status": status, "remediation": remediation,
            "reviewer": reviewer, "evidence": [evidence]}

    def ingest(self, kind: str, path: Path):
        """Commit an entire file or leave the reusable assessment unchanged."""
        staged = deepcopy(self)
        staged._ingest(kind, path)
        self.__dict__.update(staged.__dict__)

    def _ingest(self, kind: str, path: Path):
        data = read_bytes(path)
        source = {"kind": kind, "filename": path.name,
                  "sha256": hashlib.sha256(data).hexdigest()}
        if kind not in INPUT_KINDS:
            raise ValueError("Unsupported evidence kind")
        for line, row in json_lines(data):
            if kind == "zeek":
                for field in ("id.orig_h", "id.resp_h"):
                    address = literal_ip(row[field])
                    if self.scope.allows(address):
                        self.assets.add(address)
                self.connections += 1
            elif kind == "nuclei":
                info = row.get("info", {})
                if not isinstance(info, dict):
                    raise ValueError("Nuclei info must be an object")
                self.add(source=source, row=line,
                    target=nuclei_target(row),
                    title=info.get("name"), severity=info.get("severity", "unknown"),
                    status="potential", check_id=row.get("template-id"),
                    remediation="Have the system maintainer validate the result against the exact product and manufacturer advisory; apply the approved fix and retest.")
            elif kind == "manual":
                if type(row.get("schema_version")) is not int or row["schema_version"] != 1:
                    raise ValueError("Manual findings require schema_version 1")
                self.add(source=source, row=line, target=row.get("target"),
                    title=row.get("title"), severity=row.get("severity"),
                    status=row.get("status"), remediation=row.get("remediation"),
                    check_id=row.get("check_id"), reviewer=row.get("reviewer", ""))
            else:
                self.add_inventory(source, line, row)
        self.sources.append(source)

    def add_inventory(self, source: dict, line: int, row: dict):
        if type(row.get("schema_version")) is not int or row["schema_version"] != 1:
            raise ValueError("Inventory records require schema_version 1")
        target = self.scope.target(row.get("target"))
        details = {field: text(row.get(field), field) for field in ("manufacturer", "model", "firmware")}
        evidence = {"kind": "inventory", "sha256": source["sha256"], "line": line,
            "collector": text(row.get("collector"), "collector"),
            "collected_at": collection_time(row.get("collected_at")),
            "source_ref": text(row.get("source_ref"), "source_ref")}
        existing = self.inventory.get(target)
        if existing is not None:
            if any(existing[field] != value for field, value in details.items()):
                raise ValueError("Conflicting inventory details for one target; reconcile before import")
            if evidence not in existing["evidence"]:
                existing["evidence"].append(evidence)
        else:
            self.inventory[target] = {"target": target, **details, "evidence": [evidence]}
        self.assets.add(target)

    def result(self) -> dict:
        return deepcopy({"schema_version": 1, "tool_version": __version__, "assessment_id": self.scope.assessment_id,
            "site": self.scope.site, "authorization_ref": self.scope.authorization_ref,
            "mode": "offline", "assets": sorted(self.assets),
            "asset_ranges": sorted(str(net) for net in self.scope.networks),
            "device_inventory": [self.inventory[key] for key in sorted(self.inventory)],
            "connection_records": self.connections, "sources": self.sources,
            "findings": sorted(self.findings.values(), key=lambda x: x["id"]),
            "limitations": [
                "No live probing, packet capture, exploit validation or remediation was performed by this application.",
                "Imported tool results are untrusted evidence, not independent confirmation of exploitability.",
                "A file hash identifies imported bytes; it does not authenticate their origin or establish chain of custody.",
                "Device identity, firmware and collection metadata are supplied by the collector; they are not independently authenticated or matched against advisories.",
                "Scope filters reported assets/findings; it does not authorize or constrain the original collection.",
                "Passive assets include only addresses visible in supplied records; quiet devices and encrypted traffic limit coverage.",
                "Network isolation, public exposure, patch completeness and alarm independence were not established unless explicitly documented in reviewed findings.",
                "No findings does not establish security."
            ]})


def md(value: object) -> str:
    # Untrusted evidence must not become links, HTML, headings or instructions.
    clean = html.escape(str(value), quote=True).replace("\n", " ").replace("\r", " ")
    return re.sub(r"([\\`*_{}\[\]()#+.!|>~-])", r"\\\1", clean)


def report(doc: dict) -> str:
    lines = ["# Cyber Safety Crew assessment", "",
        f"Assessment: {md(doc['assessment_id'])}", "", f"Site: {md(doc['site'])}", "",
        f"Authorization reference: {md(doc['authorization_ref'])}", "",
        "Mode: offline evidence review", "",
        f"Observed in-scope assets: {len(doc['assets'])}; imported findings: {len(doc['findings'])}", "",
        "## Coverage and limitations", ""]
    lines += [f"- {x}" for x in doc["limitations"]]
    lines += ["", "## Observed assets", ""]
    lines += [f"- {md(x)}" for x in doc["assets"]] or ["No in-scope assets observed."]
    if doc.get("device_inventory"):
        lines += ["", "## Device inventory", ""]
        for device in doc["device_inventory"]:
            lines += [f"### {md(device['target'])}", "",
                f"Manufacturer: {md(device['manufacturer'])}; model: {md(device['model'])}; firmware: {md(device['firmware'])}.", ""]
            for evidence in device["evidence"]:
                lines += [f"- Collected by {md(evidence['collector'])} at {md(evidence['collected_at'])}; reference: {md(evidence['source_ref'])}; SHA-256 {evidence['sha256']}, line {evidence['line']}."]
            lines += [""]
    lines += ["", "## Findings", ""]
    if not doc["findings"]:
        lines += ["No findings imported. See coverage limitations above.", ""]
    for item in doc["findings"]:
        lines += [f"### {md(item['title'])}", "",
            f"Target: {md(item['target'])}; severity: {md(item['severity'])}; evidence status: {md(item['status'])}.", "",
            f"Recommended action: {md(item['remediation'])}", ""]
        if item["reviewer"]:
            lines += [f"Reviewer: {md(item['reviewer'])}", ""]
        lines += ["Evidence references:", ""]
        lines += [f"- {md(e['kind'])}, SHA-256 {e['sha256']}, line {e['line']}" for e in item["evidence"]]
        lines += [""]
    lines += ["## Source provenance", ""]
    lines += [f"- {md(s['kind'])}: {md(s['filename'])}; SHA-256 {s['sha256']}" for s in doc["sources"]]
    return "\n".join(lines) + "\n"
