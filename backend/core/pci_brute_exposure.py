"""
PCI brute-force exposure checks.
Tests whether administrative services and login portals are exposed
without adequate lockout/rate-limiting protections.
No credentials are tested — exposure and policy checks only.
"""
from __future__ import annotations
import asyncio
import re
from urllib.parse import urljoin, urlparse

import httpx

from core.pci_models import PciFinding, PciEvidence, PciRemediation
from core.pci_port_scanner import OpenPort


# ── Well-known admin paths ────────────────────────────────────────────────────

_ADMIN_PATHS: list[tuple[str, str]] = [
    ("/admin",           "Generic Admin Panel"),
    ("/admin/login",     "Admin Login"),
    ("/administrator",   "Administrator Panel"),
    ("/wp-admin",        "WordPress Admin"),
    ("/wp-login.php",    "WordPress Login"),
    ("/phpmyadmin",      "phpMyAdmin"),
    ("/pma",             "phpMyAdmin Alias"),
    ("/manager/html",    "Tomcat Manager"),
    ("/console",         "JBoss/Wildfly Console"),
    ("/actuator",        "Spring Boot Actuator"),
    ("/actuator/health", "Spring Boot Actuator Health"),
    ("/api/v1/admin",    "API Admin Endpoint"),
    ("/cpanel",          "cPanel"),
    ("/webmail",         "Webmail"),
    ("/remote",          "Remote Admin"),
    ("/_admin",          "Hidden Admin"),
    ("/login",           "Login Page"),
    ("/signin",          "Sign-in Page"),
    ("/auth/login",      "Auth Login"),
]

_RATE_LIMIT_HEADERS = (
    "x-ratelimit-limit",
    "x-rate-limit-limit",
    "retry-after",
    "ratelimit-limit",
)

_LOCKOUT_PATTERNS = re.compile(
    r"(?:account.?locked|too.?many.?attempts|captcha|rate.?limit|try.?again.?later)",
    re.IGNORECASE,
)

_CAPTCHA_PATTERNS = re.compile(
    r"(?:recaptcha|hcaptcha|turnstile|captcha|g-recaptcha)",
    re.IGNORECASE,
)

# Body signatures that confirm a 200 response is actually an admin panel,
# not a CDN/SPA catch-all. Grouped by panel type.
_ADMIN_BODY_SIGS: dict[str, list[str]] = {
    "wp-admin":     [r"wp-login", r"wordpress", r"wplogin", r"log in to wordpress"],
    "phpmyadmin":   [r"phpmyadmin", r"pma_", r"mysqladmin", r"phpMyAdmin"],
    "cpanel":       [r"cpanel", r"whm", r"cPanel"],
    "actuator":     [r'"status"', r'"health"', r'"components"', r"actuator"],
    "console":      [r"jboss", r"wildfly", r"management console"],
    "tomcat":       [r"tomcat", r"apache tomcat", r"manager app"],
    "generic_admin":[
        r'<form[^>]*(?:action|method)[^>]*(?:login|signin|admin)',
        r'(?:id|name|class)\s*=\s*["\'](?:admin|login|signin)',
        r'<title>[^<]*(?:admin|login|dashboard|control panel)',
        r'href=["\'][^"\']*(?:/admin|/login)',
    ],
}

_ALL_ADMIN_SIGS = re.compile(
    r"(?:phpmyadmin|pma_|mysqladmin|cpanel|whm|jboss|wildfly|tomcat manager"
    r"|wp-login|wordpress login|actuator/health|<title>[^<]*(?:admin|dashboard|control panel)"
    r"|(?:id|name|class)=[\"'](?:admin-|login-|dashboard))",
    re.IGNORECASE,
)


# ── Port-based exposure ───────────────────────────────────────────────────────

def check_admin_port_exposure(ip: str, open_ports: list[OpenPort]) -> list[PciFinding]:
    findings: list[PciFinding] = []

    _risky = {
        22:    ("SSH", "Req 1.3.2", "critical"),
        23:    ("Telnet", "Req 4.2.1", "critical"),
        3389:  ("RDP", "Req 1.3.2", "critical"),
        5900:  ("VNC", "Req 1.3.2", "critical"),
        5901:  ("VNC-1", "Req 1.3.2", "critical"),
        2222:  ("SSH Alt", "Req 1.3.2", "high"),
        8888:  ("Admin Port", "Req 1.3.2", "high"),
        10000: ("Webmin", "Req 1.3.2", "high"),
        8161:  ("ActiveMQ Admin", "Req 1.3.2", "high"),
        4848:  ("GlassFish Admin", "Req 1.3.2", "high"),
    }

    open_port_nums = {op.port for op in open_ports}
    for port, (name, req, sev) in _risky.items():
        if port in open_port_nums:
            findings.append(PciFinding(
                check_name=f"admin-port-exposed-{port}",
                severity=sev,
                category="brute-exposure",
                title=f"Administrative Service Exposed: {name} on port {port}",
                detail=(
                    f"{name} (port {port}) is accessible on {ip}. "
                    "PCI DSS requires that administrative interfaces are restricted to authorized users "
                    "and not accessible from untrusted networks."
                ),
                target=ip,
                port=port,
                service=name.lower(),
                pci_req=req,
                plugin_id=f"PCI-BRUTE-PORT-{port}",
                remediation=PciRemediation(
                    description=f"Restrict {name} to management networks only. Use VPN for remote admin. Consider MFA.",
                    pci_req=req,
                    cvss_score=9.8 if sev == "critical" else 7.5,
                    priority=1,
                ),
                phase="brute_exposure",
            ))
    return findings


# ── Web admin exposure ────────────────────────────────────────────────────────

async def check_web_admin_exposure(
    base_urls: list[str],
    max_concurrency: int = 10,
) -> list[PciFinding]:
    findings: list[PciFinding] = []
    sem = asyncio.Semaphore(max_concurrency)

    async def probe(base: str, path: str, label: str) -> PciFinding | None:
        url = urljoin(base.rstrip("/") + "/", path.lstrip("/"))
        async with sem:
            try:
                async with httpx.AsyncClient(
                    verify=False, timeout=8, follow_redirects=True,
                    headers={"User-Agent": "BluJay-PCI-Scanner/1.0"},
                ) as client:
                    resp = await client.get(url)
            except Exception:
                return None

            status = resp.status_code

            if status == 200:
                # Only flag 200 if the body contains actual admin panel signatures.
                # CDN-fronted SPAs and catch-all routers return 200 for every path,
                # so a bare 200 is not sufficient evidence of exposure.
                body = resp.text[:4000]
                if not _ALL_ADMIN_SIGS.search(body):
                    return None
                severity = "high"

            elif status in (401, 403, 405):
                # Server acknowledged path exists but rejected — medium (path enumerable)
                severity = "medium"
            else:
                return None

            return PciFinding(
                check_name=f"admin-panel-exposed-{path.strip('/').replace('/', '-')}",
                severity=severity,
                category="brute-exposure",
                title=f"{label} Exposed: {url}",
                detail=(
                    f"{label} is reachable at {url} (HTTP {status}). "
                    "PCI DSS Req 6.3.3 and Req 8 require admin panels to be protected "
                    "and not exposed to untrusted networks."
                ),
                target=urlparse(url).netloc,
                port=443 if url.startswith("https") else 80,
                service="http",
                pci_req="Req 8.2.1",
                plugin_id=f"PCI-ADMIN-{path.strip('/').upper()[:20]}",
                evidence=PciEvidence(
                    raw_request=f"GET {url}",
                    raw_response=f"HTTP {status}",
                ),
                remediation=PciRemediation(
                    description=(
                        "Restrict admin interfaces to management IP ranges. "
                        "Enable MFA. Move admin to a non-standard URL. "
                        "Add IP allowlisting."
                    ),
                    pci_req="Req 8.2.1",
                    priority=1 if severity == "high" else 2,
                ),
                phase="brute_exposure",
            )

    tasks = [
        probe(base, path, label)
        for base in base_urls
        for path, label in _ADMIN_PATHS
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, PciFinding):
            findings.append(r)

    return findings


# ── Login page policy checks ──────────────────────────────────────────────────

async def check_login_policy(
    pages_with_forms: list[tuple[str, str, dict]],
) -> list[PciFinding]:
    """
    pages_with_forms: list of (url, body, headers) tuples for pages that have forms.
    Checks for: CAPTCHA presence, rate-limit headers, account-lockout messaging.
    """
    findings: list[PciFinding] = []

    for url, body, headers in pages_with_forms:
        parsed = urlparse(url)
        host = parsed.netloc

        has_captcha = bool(_CAPTCHA_PATTERNS.search(body))
        has_rate_limit_header = any(
            h.lower() in headers for h in _RATE_LIMIT_HEADERS
        )
        has_lockout_text = bool(_LOCKOUT_PATTERNS.search(body))
        has_protection = has_captcha or has_rate_limit_header or has_lockout_text

        # Only flag login pages
        is_login = bool(re.search(r'(?:login|signin|sign.?in|password|passwd)', url + body[:500], re.IGNORECASE))
        if not is_login:
            continue

        if not has_protection:
            findings.append(PciFinding(
                check_name="login-no-brute-protection",
                severity="medium",
                category="brute-exposure",
                title=f"Login Page Without Visible Brute-Force Protection: {url}",
                detail=(
                    "No CAPTCHA, rate-limit headers, or lockout messaging detected on the login page. "
                    "PCI DSS Req 8.3.4 requires account lockout after no more than 10 consecutive failed attempts."
                ),
                target=host,
                port=443 if url.startswith("https") else 80,
                pci_req="Req 8.3.4",
                plugin_id="PCI-BRUTE-LOGIN-POLICY",
                evidence=PciEvidence(
                    raw_request=f"GET {url}",
                    notes=f"CAPTCHA: {has_captcha}, Rate-limit header: {has_rate_limit_header}, Lockout text: {has_lockout_text}",
                ),
                remediation=PciRemediation(
                    description=(
                        "Implement account lockout after 10 failed attempts. "
                        "Add CAPTCHA or similar anti-automation control. "
                        "Apply rate limiting at the application or WAF level."
                    ),
                    pci_req="Req 8.3.4",
                    priority=2,
                ),
                phase="brute_exposure",
            ))

    return findings
