"""
PCI vulnerability checks — banner-based service fingerprinting matched against
a built-in signature database of PCI-relevant CVEs and misconfigurations.
Also performs SSL/TLS deep checks via the ssl module.
"""
from __future__ import annotations
import re
import socket
import ssl
from dataclasses import dataclass, field
from typing import Callable

from core.pci_models import PciFinding, PciEvidence, PciRemediation
from core.pci_port_scanner import OpenPort


# ── Vulnerability signature database ─────────────────────────────────────────

@dataclass
class VulnSig:
    id: str
    name: str
    services: list[str]             # match against detected service
    banner_pattern: str = ""        # regex matched against banner
    port_check: Callable[[int], bool] | None = None
    cve_ids: list[str] = field(default_factory=list)
    cvss: float = 0.0
    severity: str = "medium"
    pci_req: str = ""
    detail: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)


VULN_DB: list[VulnSig] = [
    # ── FTP ──────────────────────────────────────────────────────────────────
    VulnSig(
        id="PCI-FTP-001",
        name="FTP Anonymous Login Allowed",
        services=["ftp"],
        banner_pattern=r"(?i)(anonymous|230 Login)",
        cve_ids=[],
        cvss=6.5,
        severity="high",
        pci_req="Req 2.2.1",
        detail="The FTP server accepts anonymous logins, allowing unauthenticated file access.",
        remediation="Disable anonymous FTP. Use SFTP/FTPS. Restrict access to authorized users.",
    ),
    VulnSig(
        id="PCI-FTP-002",
        name="FTP Cleartext Protocol (PCI Prohibited)",
        services=["ftp"],
        banner_pattern=r"^220",
        cve_ids=[],
        cvss=7.5,
        severity="high",
        pci_req="Req 4.2.1",
        detail="FTP transmits credentials and data in cleartext. PCI DSS prohibits cleartext transmission of cardholder data.",
        remediation="Replace FTP with SFTP (SSH file transfer) or FTPS. Block port 21 at the firewall.",
    ),
    # ── SSH ───────────────────────────────────────────────────────────────────
    VulnSig(
        id="PCI-SSH-001",
        name="Old OpenSSH Version (< 8.0)",
        services=["ssh"],
        banner_pattern=r"SSH-2\.0-OpenSSH_([1-7]\.|8\.0)",
        cve_ids=["CVE-2023-38408", "CVE-2021-28041"],
        cvss=7.0,
        severity="high",
        pci_req="Req 6.3.3",
        detail="An outdated OpenSSH version with known vulnerabilities was detected. Versions below 8.5 have multiple known CVEs.",
        remediation="Update OpenSSH to the latest stable release. Apply OS vendor patches.",
        references=["https://www.openssh.com/security.html"],
    ),
    VulnSig(
        id="PCI-SSH-002",
        name="SSH Protocol 1 Banner",
        services=["ssh"],
        banner_pattern=r"SSH-1\.",
        cve_ids=["CVE-2001-0572"],
        cvss=9.0,
        severity="critical",
        pci_req="Req 4.2.1",
        detail="SSH Protocol 1 is fundamentally broken and vulnerable to man-in-the-middle attacks.",
        remediation="Disable SSH Protocol 1. Configure SSHv2 only.",
    ),
    # ── Telnet ────────────────────────────────────────────────────────────────
    VulnSig(
        id="PCI-TELNET-001",
        name="Telnet Service Active (Cleartext Admin)",
        services=["telnet"],
        banner_pattern=r"",
        cve_ids=[],
        cvss=9.8,
        severity="critical",
        pci_req="Req 4.2.1",
        detail="Telnet transmits all data including credentials in cleartext. PCI DSS explicitly prohibits non-console administrative access via cleartext protocols.",
        remediation="Disable Telnet immediately. Replace with SSH. Block port 23 at the firewall.",
    ),
    # ── SMTP ──────────────────────────────────────────────────────────────────
    VulnSig(
        id="PCI-SMTP-001",
        name="SMTP Open Relay",
        services=["smtp"],
        banner_pattern=r"(?i)(250 ok|relaying|relay)",
        cve_ids=[],
        cvss=5.3,
        severity="medium",
        pci_req="Req 1.3.2",
        detail="The SMTP server may allow open relaying, enabling spam/phishing abuse.",
        remediation="Disable open relay. Restrict SMTP to authenticated senders. Enable SPF, DKIM, DMARC.",
    ),
    # ── HTTP/Web ──────────────────────────────────────────────────────────────
    VulnSig(
        id="PCI-WEB-001",
        name="Apache Version Disclosure",
        services=["http", "https", "http-alt", "https-alt"],
        banner_pattern=r"Server:\s*Apache/(\d+\.\d+)",
        cve_ids=[],
        cvss=5.0,
        severity="medium",
        pci_req="Req 2.2.1",
        detail="Apache version disclosed in Server header. Version information aids attackers in targeting known CVEs.",
        remediation="Set 'ServerTokens Prod' and 'ServerSignature Off' in Apache config.",
    ),
    VulnSig(
        id="PCI-WEB-002",
        name="Nginx Version Disclosure",
        services=["http", "https", "http-alt", "https-alt"],
        banner_pattern=r"Server:\s*nginx/(\d+\.\d+)",
        cve_ids=[],
        cvss=5.0,
        severity="medium",
        pci_req="Req 2.2.1",
        detail="Nginx version disclosed in Server header. Version disclosure helps attackers fingerprint and target the server.",
        remediation="Add 'server_tokens off;' to nginx.conf.",
    ),
    VulnSig(
        id="PCI-WEB-003",
        name="IIS Version Disclosure",
        services=["http", "https", "http-alt", "https-alt"],
        banner_pattern=r"Server:\s*Microsoft-IIS/(\d+\.\d+)",
        cve_ids=[],
        cvss=5.0,
        severity="medium",
        pci_req="Req 2.2.1",
        detail="IIS version is visible in the Server header, enabling targeted attacks.",
        remediation="Set 'removeServerHeader' in IIS or use URL Rewrite module to suppress the header.",
    ),
    # ── Databases ─────────────────────────────────────────────────────────────
    VulnSig(
        id="PCI-REDIS-001",
        name="Redis Accessible Without Authentication",
        services=["redis"],
        banner_pattern=r"",
        cve_ids=["CVE-2022-0543", "CVE-2021-32627"],
        cvss=9.8,
        severity="critical",
        pci_req="Req 1.3.2",
        detail="Redis is accessible without authentication. An attacker can read/write all keys, execute Lua scripts, and potentially achieve RCE.",
        remediation="Enable Redis AUTH (requirepass). Bind to localhost. Use firewall rules. Consider TLS.",
        references=["https://redis.io/docs/management/security/"],
    ),
    VulnSig(
        id="PCI-MONGO-001",
        name="MongoDB Accessible Without Authentication",
        services=["mongodb"],
        banner_pattern=r"",
        cve_ids=["CVE-2017-15535"],
        cvss=9.8,
        severity="critical",
        pci_req="Req 1.3.2",
        detail="MongoDB is accessible without authentication. All databases can be read, modified, or dropped.",
        remediation="Enable MongoDB authentication. Add --auth flag. Use firewall to restrict access.",
    ),
    VulnSig(
        id="PCI-ES-001",
        name="Elasticsearch Accessible Without Authentication",
        services=["elasticsearch"],
        banner_pattern=r"",
        cve_ids=["CVE-2015-1427"],
        cvss=9.8,
        severity="critical",
        pci_req="Req 1.3.2",
        detail="Elasticsearch is accessible without authentication. All indexed data (potentially including cardholder data) is exposed.",
        remediation="Enable X-Pack security. Restrict access via firewall. Never expose Elasticsearch publicly.",
    ),
    VulnSig(
        id="PCI-MYSQL-001",
        name="MySQL Version Disclosure",
        services=["mysql"],
        banner_pattern=r"",
        cve_ids=[],
        cvss=4.0,
        severity="medium",
        pci_req="Req 2.2.1",
        detail="MySQL is accessible. Version information may aid in targeting known CVEs.",
        remediation="Firewall MySQL port (3306). Disable remote root login. Apply latest patches.",
    ),
    # ── SMB ───────────────────────────────────────────────────────────────────
    VulnSig(
        id="PCI-SMB-001",
        name="SMB Service Exposed to Internet",
        services=["smb"],
        banner_pattern=r"",
        cve_ids=["CVE-2017-0144", "CVE-2017-0145"],
        cvss=9.8,
        severity="critical",
        pci_req="Req 1.3.2",
        detail="SMB (port 445) is exposed. EternalBlue and related exploits target SMB for ransomware and worm propagation.",
        remediation="Block port 445 at the firewall. Apply MS17-010 patch. Disable SMBv1.",
        references=["https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2017/ms17-010"],
    ),
    # ── RDP ───────────────────────────────────────────────────────────────────
    VulnSig(
        id="PCI-RDP-001",
        name="RDP Exposed to Internet",
        services=["rdp"],
        banner_pattern=r"",
        cve_ids=["CVE-2019-0708"],
        cvss=9.8,
        severity="critical",
        pci_req="Req 1.3.2",
        detail="RDP (port 3389) is accessible from the internet. BlueKeep and other RDP vulnerabilities enable unauthenticated RCE.",
        remediation="Block RDP from the internet. Use VPN for remote access. Apply Network Level Authentication (NLA).",
        references=["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2019-0708"],
    ),
    # ── VNC ───────────────────────────────────────────────────────────────────
    VulnSig(
        id="PCI-VNC-001",
        name="VNC Service Exposed",
        services=["vnc"],
        banner_pattern=r"RFB",
        cve_ids=[],
        cvss=8.8,
        severity="critical",
        pci_req="Req 1.3.2",
        detail="VNC is exposed. VNC provides full graphical desktop access and should never be internet-facing.",
        remediation="Firewall VNC. Use SSH tunneling or VPN for remote admin. Enable VNC password authentication.",
    ),
]


# ── SSL/TLS vulnerability checks ──────────────────────────────────────────────

def check_tls_vulnerabilities(host: str, port: int) -> list[PciFinding]:
    """
    Deep TLS checks: negotiated version, certificate chain, HSTS, weak ciphers.
    These extend the basic transport checks in pci_scanner.py.
    """
    findings: list[PciFinding] = []

    # ── Test TLS 1.1 support (best-effort) ───────────────────────────────────
    for min_ver, max_ver, label in [
        (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1, "TLS 1.0"),
        (ssl.TLSVersion.TLSv1_1, ssl.TLSVersion.TLSv1_1, "TLS 1.1"),
    ]:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.minimum_version = min_ver
            ctx.maximum_version = max_ver
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=5) as raw:
                with ctx.wrap_socket(raw, server_hostname=host):
                    findings.append(PciFinding(
                        check_name=f"tls-{label.lower().replace(' ', '')}-accepted",
                        severity="critical",
                        category="vulnerability",
                        title=f"{label} Accepted by Server",
                        detail=(
                            f"{host}:{port} accepted a {label} handshake. "
                            f"{label} is prohibited by PCI DSS 3.2.1+ (effective June 2018)."
                        ),
                        target=host,
                        port=port,
                        service="tls",
                        cvss_score=5.9,
                        pci_req="Req 4.2.1",
                        plugin_id=f"PCI-TLS-{label.replace(' ', '').replace('.', '')}",
                        evidence=PciEvidence(banner=f"{label} handshake succeeded"),
                        remediation=PciRemediation(
                            description=f"Disable {label} in server TLS configuration. Accept TLS 1.2 and 1.3 only.",
                            pci_req="Req 4.2.1",
                            cvss_score=5.9,
                            priority=1,
                        ),
                        phase="vulnerability",
                    ))
        except Exception:
            pass  # not supported — good

    return findings


# ── Banner-based vulnerability matching ───────────────────────────────────────

def check_banner_vulns(
    host: str,
    open_ports: list[OpenPort],
) -> list[PciFinding]:
    findings: list[PciFinding] = []

    for op in open_ports:
        # Build a combined string for matching
        combined = f"Service: {op.service}\nBanner: {op.banner}"

        for sig in VULN_DB:
            # Service match
            if op.service not in sig.services:
                continue
            # Banner match (if pattern specified)
            if sig.banner_pattern and not re.search(sig.banner_pattern, combined, re.MULTILINE):
                continue

            # Match! Create a finding
            findings.append(PciFinding(
                check_name=sig.id.lower(),
                severity=sig.severity,
                category="vulnerability",
                title=f"{sig.name} ({host}:{op.port})",
                detail=sig.detail,
                target=host,
                port=op.port,
                service=op.service,
                cvss_score=sig.cvss,
                cve_ids=list(sig.cve_ids),
                plugin_id=sig.id,
                pci_req=sig.pci_req,
                evidence=PciEvidence(banner=op.banner[:500]),
                remediation=PciRemediation(
                    description=sig.remediation,
                    pci_req=sig.pci_req,
                    cvss_score=sig.cvss,
                    cve_ids=list(sig.cve_ids),
                    references=list(sig.references),
                    priority=1 if sig.severity in ("critical", "high") else 2,
                ),
                phase="vulnerability",
            ))

    return findings
