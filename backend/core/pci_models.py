"""
PCI DSS scanner — shared data models.
All other pci_* modules import from here.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any


# ── Severity / Category constants ─────────────────────────────────────────────

SEVERITY_WEIGHT: dict[str, int] = {
    "critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1,
}

# PCI DSS v4.0 requirement labels
PCI_REQ_LABELS: dict[str, str] = {
    "Req 1": "Network Access Controls",
    "Req 2": "Secure Configurations",
    "Req 3": "Protect Stored Account Data",
    "Req 4": "Encrypt Cardholder Data in Transit",
    "Req 5": "Anti-Malware",
    "Req 6": "Secure Systems & Software",
    "Req 7": "Restrict Access to CHD",
    "Req 8": "Identify & Authenticate Users",
    "Req 9": "Restrict Physical Access",
    "Req 10": "Log & Monitor All Access",
    "Req 11": "Test Security of Systems",
    "Req 12": "Org Security Policies",
}

SCAN_PHASES = [
    "scope_resolution",
    "host_discovery",
    "port_scan",
    "vulnerability",
    "brute_exposure",
    "web_crawl",
    "web_checks",
    "malware",
    "report",
]


# ── Evidence & Remediation structures ────────────────────────────────────────

@dataclass
class PciEvidence:
    """Raw evidence captured during scanning — used for dispute/audit purposes."""
    raw_request: str = ""
    raw_response: str = ""
    banner: str = ""
    payload: str = ""
    timestamp: str = ""
    source_ip: str = ""
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "raw_request": self.raw_request[:2000],
            "raw_response": self.raw_response[:2000],
            "banner": self.banner[:500],
            "payload": self.payload[:500],
            "timestamp": self.timestamp,
            "source_ip": self.source_ip,
            "notes": self.notes,
        }


@dataclass
class PciRemediation:
    description: str
    pci_req: str = ""
    cvss_score: float = 0.0
    cve_ids: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    priority: int = 1  # 1=immediate, 2=short-term, 3=long-term

    def to_dict(self) -> dict[str, Any]:
        return {
            "description": self.description,
            "pci_req": self.pci_req,
            "cvss_score": self.cvss_score,
            "cve_ids": self.cve_ids,
            "references": self.references,
            "priority": self.priority,
        }


# ── Core finding ──────────────────────────────────────────────────────────────

@dataclass
class PciFinding:
    """Universal finding produced by every pci_* scanner module."""
    check_name: str
    severity: str                   # critical | high | medium | low | info
    category: str                   # see PCI_CATEGORY_LABELS below
    title: str
    detail: str
    target: str                     # IP, hostname, or URL

    port: int = 0
    service: str = ""
    protocol: str = "tcp"

    cvss_score: float = 0.0
    cve_ids: list[str] = field(default_factory=list)
    plugin_id: str = ""             # e.g. "PCI-TLS-001"

    pci_req: str = ""               # e.g. "Req 4.2.1"

    evidence: PciEvidence = field(default_factory=PciEvidence)
    remediation: PciRemediation = field(default_factory=lambda: PciRemediation(""))

    phase: str = "web"              # which scan phase produced this
    false_positive_likelihood: str = "low"

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_name": self.check_name,
            "severity": self.severity,
            "category": self.category,
            "title": self.title,
            "detail": self.detail,
            "target": self.target,
            "port": self.port,
            "service": self.service,
            "cvss_score": self.cvss_score,
            "cve_ids": self.cve_ids,
            "plugin_id": self.plugin_id,
            "pci_req": self.pci_req,
            "evidence": self.evidence.to_dict(),
            "remediation": self.remediation.to_dict(),
            "phase": self.phase,
            "false_positive_likelihood": self.false_positive_likelihood,
        }


# ── Scan summary ──────────────────────────────────────────────────────────────

@dataclass
class PciScanSummary:
    scope_name: str = ""
    scan_profile: str = "web_only"
    target_count: int = 0
    hosts_live: int = 0
    ports_open: int = 0
    pages_crawled: int = 0
    processors_detected: list[str] = field(default_factory=list)
    phases_completed: list[str] = field(default_factory=list)
    findings_by_severity: dict[str, int] = field(default_factory=lambda: {
        "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
    })
    findings_by_category: dict[str, int] = field(default_factory=dict)
    findings_by_pci_req: dict[str, int] = field(default_factory=dict)

    def tally(self, findings: list[PciFinding]) -> None:
        self.findings_by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        self.findings_by_category = {}
        self.findings_by_pci_req = {}
        for f in findings:
            self.findings_by_severity[f.severity] = self.findings_by_severity.get(f.severity, 0) + 1
            self.findings_by_category[f.category] = self.findings_by_category.get(f.category, 0) + 1
            req_key = f.pci_req.split(".")[0] if f.pci_req else "Other"
            self.findings_by_pci_req[req_key] = self.findings_by_pci_req.get(req_key, 0) + 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "scope_name": self.scope_name,
            "scan_profile": self.scan_profile,
            "target_count": self.target_count,
            "hosts_live": self.hosts_live,
            "ports_open": self.ports_open,
            "pages_crawled": self.pages_crawled,
            "processors_detected": self.processors_detected,
            "phases_completed": self.phases_completed,
            "findings_by_severity": self.findings_by_severity,
            "findings_by_category": self.findings_by_category,
            "findings_by_pci_req": self.findings_by_pci_req,
        }
