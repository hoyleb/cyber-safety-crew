"""Small, deterministic import pipeline. Treat every input as untrusted data."""

from __future__ import annotations

import hashlib
import html
import ipaddress
import json
import re
from pathlib import Path
from urllib.parse import urlsplit

MAX_BYTES = 10 * 1024 * 1024
MAX_RECORDS = 100_000
SEVERITIES = {"info", "low", "medium", "high", "critical", "unknown"}
STATUSES = {"observed", "potential", "confirmed", "untested"}


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


class Scope:
    def __init__(self, doc: dict):
        if not isinstance(doc, dict) or doc.get("schema_version") != 1:
            raise ValueError("Scope requires schema_version 1")
        self.assessment_id = text(doc.get("assessment_id"), "assessment_id")
        self.site = text(doc.get("site"), "site")
        self.authorization_ref = text(doc.get("authorization_ref"), "authorization_ref")
        if doc.get("mode") != "offline":
            raise ValueError("This release supports offline mode only")
        ranges = doc.get("asset_ranges")
        if not isinstance(ranges, list) or not ranges or len(ranges) > 1000:
            raise ValueError("asset_ranges requires 1 to 1000 IP/CIDR strings")
        self.networks = [ipaddress.ip_network(x, strict=True) for x in ranges]

    def allows(self, value: str) -> bool:
        address = ipaddress.ip_address(value)
        return any(address.version == net.version and address in net for net in self.networks)

    def target(self, value: str) -> str:
        value = text(value, "target")
        # No DNS lookups. URL hostnames must be literal IP addresses in v0.1.
        candidate = urlsplit(value).hostname if "://" in value else value
        address = str(ipaddress.ip_address(candidate))
        if not self.allows(address):
            raise ValueError("Finding target is outside the approved asset ranges")
        return address


def json_lines(data: bytes):
    for number, line in enumerate(data.decode("utf-8").splitlines(), 1):
        if number > MAX_RECORDS:
            raise ValueError("Too many records")
        if not line.strip() or line.startswith("#"):
            continue
        row = json.loads(line)
        if not isinstance(row, dict):
            raise ValueError(f"Expected an object at line {number}")
        yield number, row


def fingerprint(*values: str) -> str:
    return hashlib.sha256(json.dumps(values).encode()).hexdigest()[:20]


class Assessment:
    def __init__(self, scope: Scope):
        self.scope = scope
        self.assets: set[str] = set()
        self.findings: dict[str, dict] = {}
        self.sources: list[dict] = []
        self.connections = 0

    def add(self, *, source: dict, row: int, target: str, title: str, severity: str,
            status: str, remediation: str, check_id: str, reviewer: str = ""):
        target = self.scope.target(target)
        title, remediation = text(title, "title"), text(remediation, "remediation")
        check_id = text(check_id, "check_id")
        if severity not in SEVERITIES or status not in STATUSES:
            raise ValueError("Unsupported severity or evidence status")
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
        data = read_bytes(path)
        source = {"kind": kind, "filename": path.name,
                  "sha256": hashlib.sha256(data).hexdigest()}
        if kind not in {"zeek", "nuclei", "manual"}:
            raise ValueError("Unsupported evidence kind")
        # Caller must discard this Assessment if any import raises an exception.
        for line, row in json_lines(data):
            if kind == "zeek":
                for field in ("id.orig_h", "id.resp_h"):
                    address = str(ipaddress.ip_address(row[field]))
                    if self.scope.allows(address):
                        self.assets.add(address)
                self.connections += 1
            elif kind == "nuclei":
                info = row.get("info", {})
                if not isinstance(info, dict):
                    raise ValueError("Nuclei info must be an object")
                self.add(source=source, row=line,
                    target=row.get("ip") or row.get("host") or row.get("matched-at"),
                    title=info.get("name"), severity=info.get("severity", "unknown"),
                    status="potential", check_id=row.get("template-id"),
                    remediation="Have the system maintainer validate the result against the exact product and manufacturer advisory; apply the approved fix and retest.")
            else:
                if row.get("schema_version") != 1:
                    raise ValueError("Manual findings require schema_version 1")
                self.add(source=source, row=line, target=row.get("target"),
                    title=row.get("title"), severity=row.get("severity"),
                    status=row.get("status"), remediation=row.get("remediation"),
                    check_id=row.get("check_id"), reviewer=row.get("reviewer", ""))
        self.sources.append(source)

    def result(self) -> dict:
        return {"schema_version": 1, "assessment_id": self.scope.assessment_id,
            "site": self.scope.site, "authorization_ref": self.scope.authorization_ref,
            "mode": "offline", "assets": sorted(self.assets),
            "connection_records": self.connections, "sources": self.sources,
            "findings": sorted(self.findings.values(), key=lambda x: x["id"]),
            "limitations": [
                "No live probing, packet capture, exploit validation or remediation was performed by this application.",
                "Imported tool results are untrusted evidence, not independent confirmation of exploitability.",
                "A file hash identifies imported bytes; it does not authenticate their origin or establish chain of custody.",
                "Scope filters reported assets/findings; it does not authorize or constrain the original collection.",
                "Passive assets include only addresses visible in supplied records; quiet devices and encrypted traffic limit coverage.",
                "Network isolation, public exposure, patch completeness and alarm independence were not established unless explicitly documented in reviewed findings.",
                "No findings does not establish security."
            ]}


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
