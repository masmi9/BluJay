"""
PCI port scanner — async TCP connect with banner grab and service detection.
No raw sockets required; works unprivileged on Windows and Linux.
"""
from __future__ import annotations
import asyncio
import re
from dataclasses import dataclass, field

from core.pci_models import PciFinding, PciEvidence, PciRemediation


# ── Service signature table ───────────────────────────────────────────────────
# Maps (port, banner_pattern) → service name

_SERVICE_SIGS: list[tuple[int | None, str, str]] = [
    # (port_hint, banner_regex, service_name)
    (21,   r"^220.*[Ff][Tt][Pp]",           "ftp"),
    (22,   r"^SSH-",                          "ssh"),
    (23,   r"",                               "telnet"),
    (25,   r"^220.*[Ss][Mm][Tt][Pp]",        "smtp"),
    (80,   r"HTTP/",                           "http"),
    (110,  r"^\+OK",                           "pop3"),
    (143,  r"^\* OK",                          "imap"),
    (443,  r"",                               "https"),
    (445,  r"",                               "smb"),
    (993,  r"",                               "imaps"),
    (995,  r"",                               "pop3s"),
    (1433, r"",                               "mssql"),
    (1521, r"",                               "oracle"),
    (3306, r"",                               "mysql"),
    (3389, r"",                               "rdp"),
    (5432, r"",                               "postgresql"),
    (5900, r"^RFB",                            "vnc"),
    (6379, r"",                               "redis"),
    (8080, r"HTTP/",                           "http-alt"),
    (8443, r"",                               "https-alt"),
    (9200, r"",                               "elasticsearch"),
    (27017,r"",                               "mongodb"),
]

# Cleartext / risky protocols (PCI DSS prohibits unencrypted admin access)
CLEARTEXT_SERVICES = {"ftp", "telnet", "smtp", "pop3", "imap", "http", "http-alt"}
RISKY_SERVICES = {"rdp", "vnc", "smb", "redis", "elasticsearch", "mongodb"}


@dataclass
class OpenPort:
    port: int
    service: str = ""
    banner: str = ""
    tls: bool = False


async def _grab_banner(ip: str, port: int, timeout: float = 3.0) -> str:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        try:
            banner = await asyncio.wait_for(reader.read(1024), timeout=timeout)
            writer.close()
            return banner.decode(errors="replace").strip()
        except Exception:
            writer.close()
    except Exception:
        pass
    return ""


def _identify_service(port: int, banner: str) -> str:
    for port_hint, pattern, name in _SERVICE_SIGS:
        if port_hint is not None and port_hint != port:
            continue
        if not pattern or re.search(pattern, banner):
            if port_hint == port:
                return name
    # Fall back to well-known port table
    _PORT_DEFAULTS = {
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
        80: "http", 110: "pop3", 143: "imap", 443: "https",
        445: "smb", 993: "imaps", 995: "pop3s", 1433: "mssql",
        1521: "oracle", 3306: "mysql", 3389: "rdp", 5432: "postgresql",
        5900: "vnc", 6379: "redis", 8080: "http-alt", 8443: "https-alt",
        9200: "elasticsearch", 27017: "mongodb",
    }
    return _PORT_DEFAULTS.get(port, f"unknown-{port}")


async def _scan_port(ip: str, port: int, timeout: float) -> OpenPort | None:
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        # Port is open — grab banner
        banner = await _grab_banner(ip, port, timeout)
        service = _identify_service(port, banner)
        tls = port in (443, 8443, 993, 995, 465, 587)
        return OpenPort(port=port, service=service, banner=banner, tls=tls)
    except Exception:
        return None


async def scan_host_ports(
    ip: str,
    ports: list[int],
    timeout: float = 3.0,
    max_concurrency: int = 100,
) -> list[OpenPort]:
    sem = asyncio.Semaphore(max_concurrency)

    async def _limited(port: int) -> OpenPort | None:
        async with sem:
            return await _scan_port(ip, port, timeout)

    results = await asyncio.gather(*[_limited(p) for p in ports])
    return [r for r in results if r is not None]


# ── PCI findings from port scan ───────────────────────────────────────────────

def findings_from_ports(ip: str, open_ports: list[OpenPort]) -> list[PciFinding]:
    findings: list[PciFinding] = []

    for op in open_ports:
        # Cleartext protocol findings
        if op.service in CLEARTEXT_SERVICES and op.service != "http":
            findings.append(PciFinding(
                check_name="cleartext-service",
                severity="high",
                category="ports",
                title=f"Cleartext Protocol Exposed: {op.service.upper()} on port {op.port}",
                detail=(
                    f"{op.service.upper()} on {ip}:{op.port} transmits data in cleartext. "
                    "PCI DSS Req 4.2.1 prohibits unencrypted transmission of cardholder data."
                ),
                target=ip,
                port=op.port,
                service=op.service,
                pci_req="Req 4.2.1",
                plugin_id=f"PCI-PORT-{op.service.upper()}",
                evidence=PciEvidence(banner=op.banner[:300]),
                remediation=PciRemediation(
                    description=f"Disable {op.service.upper()}. Use encrypted alternatives (SFTP/SSH, HTTPS, IMAPS).",
                    pci_req="Req 4.2.1",
                    priority=1,
                ),
                phase="port_scan",
            ))

        # HTTP on non-80 ports (may be a misconfigured internal service)
        if op.service in ("http", "http-alt") and op.port not in (80, 8080):
            findings.append(PciFinding(
                check_name="http-non-standard-port",
                severity="medium",
                category="ports",
                title=f"HTTP Service on Non-Standard Port: {op.port}",
                detail=f"Unencrypted HTTP detected on {ip}:{op.port}. Verify this is not handling cardholder data.",
                target=ip,
                port=op.port,
                service=op.service,
                pci_req="Req 4.2.1",
                plugin_id="PCI-PORT-HTTP-NONSTANDARD",
                evidence=PciEvidence(banner=op.banner[:300]),
                remediation=PciRemediation(
                    description="Redirect to HTTPS. If this port is internal, ensure it's not in the CDE.",
                    pci_req="Req 4.2.1",
                    priority=2,
                ),
                phase="port_scan",
            ))

        # Risky directly-accessible services
        if op.service in RISKY_SERVICES:
            sev = "critical" if op.service in ("redis", "elasticsearch", "mongodb") else "high"
            findings.append(PciFinding(
                check_name=f"risky-service-exposed-{op.service}",
                severity=sev,
                category="ports",
                title=f"Risky Service Exposed: {op.service.upper()} on port {op.port}",
                detail=(
                    f"{op.service.upper()} is accessible on {ip}:{op.port}. "
                    "This service should not be reachable from the internet."
                ),
                target=ip,
                port=op.port,
                service=op.service,
                pci_req="Req 1.3.2",
                plugin_id=f"PCI-PORT-RISKY-{op.service.upper()}",
                evidence=PciEvidence(banner=op.banner[:300]),
                remediation=PciRemediation(
                    description=f"Firewall {op.service.upper()} port {op.port}. Enable authentication. Use VPN for admin access.",
                    pci_req="Req 1.3.2",
                    priority=1,
                    cvss_score=9.8 if sev == "critical" else 7.5,
                ),
                phase="port_scan",
            ))

    return findings
