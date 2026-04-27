"""
PCI DSS scanner — main orchestrator.

Two modes:
  1. Quick web scan:  scan_url_pci(url)        — URL-list → web checks only
  2. Full PCI scan:   run_full_pci_scan(scope)  — scope config → all phases
"""
from __future__ import annotations
import asyncio
import json
import re
import socket
import ssl
from datetime import datetime, timezone
from typing import AsyncGenerator, Callable, Awaitable
from urllib.parse import urlparse

from core.pci_models import PciFinding, PciEvidence, PciRemediation, PciScanSummary
from core.pci_scope import PciScope, get_ports_for_profile

# ── Quick-scan: web-only checks (preserved from v1) ──────────────────────────

_PROCESSOR_SIGS: list[tuple[str, list[str]]] = [
    ("Stripe",        [r"js\.stripe\.com", r"pk_(?:live|test)_[A-Za-z0-9]{20,}"]),
    ("Braintree",     [r"js\.braintreegateway\.com", r"braintree[-/]"]),
    ("PayPal",        [r"paypalobjects\.com", r"js\.paypal\.com", r"paypal\.com/sdk"]),
    ("Adyen",         [r"checkoutshopper-(?:live|test)\.adyen\.com", r"adyenpayments"]),
    ("Square",        [r"js\.squareup\.com", r"squareupsandbox\.com"]),
    ("Klarna",        [r"js\.klarna\.com", r"x\.klarnacdn\.net"]),
    ("Checkout.com",  [r"cdn\.checkout\.com"]),
    ("Recurly",       [r"js\.recurly\.com"]),
    ("Authorize.Net", [r"authorize\.net", r"AcceptUI\.js"]),
    ("Worldpay",      [r"worldpay\.com/js"]),
    ("CyberSource",   [r"cybersource\.com"]),
    ("Zuora",         [r"static\.zuora\.com"]),
    ("Alipay",        [r"gw\.alipayobjects\.com"]),
    ("WeChat Pay",    [r"pay\.weixin\.qq\.com"]),
]

_PAN_RE = re.compile(
    r'\b(?:4[0-9]{12}(?:[0-9]{3,6})?|5[1-5][0-9]{14}|2[2-7][0-9]{14}'
    r'|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12}'
    r'|(?:[0-9]{4}[- ]){3}[0-9]{4})\b'
)
_CVV_RE = re.compile(
    r'(?:cvv2?|cvc2?|cvn|security[_\s-]{0,6}code)["\s:=\']+\d{3,4}', re.IGNORECASE
)
_TRACK1_RE = re.compile(r'%B\d{13,19}\^[\w /]+\^\d{4}')
_TRACK2_RE = re.compile(r';\d{13,19}=\d{4}')
_3DS_RE = re.compile(r'(?:threeDSMethodURL|3[Dd][Ss]|acs[_\s]?url|CardholderInfo)', re.IGNORECASE)


def _luhn(number: str) -> bool:
    digits = [int(c) for c in number if c.isdigit()]
    if not (13 <= len(digits) <= 19):
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def detect_processors(body: str, headers: dict) -> list[str]:
    full = body + json.dumps(headers)
    return [n for n, pats in _PROCESSOR_SIGS if any(re.search(p, full, re.IGNORECASE) for p in pats)]


def _web_checks(url: str, body: str, headers: dict, tls: bool) -> list[PciFinding]:
    """Run all web-layer PCI checks (headers, cookies, forms, data, processors, CORS)."""
    from core.pci_scanner_web import run_web_checks
    return run_web_checks(url, body, headers, tls)


async def scan_url_pci(url: str) -> tuple[list[PciFinding], list[str]]:
    """Quick scan: fetch URL and run web-layer checks. Returns (findings, processors)."""
    import httpx
    findings: list[PciFinding] = []

    # TLS transport check
    from core.pci_scanner_web import check_transport
    findings += check_transport(url)

    tls = url.startswith("https://")
    try:
        async with httpx.AsyncClient(verify=False, timeout=20, follow_redirects=True) as client:
            resp = await client.get(url, headers={"User-Agent": "BluJay-PCI-Scanner/1.0"})
    except Exception as exc:
        findings.append(PciFinding(
            check_name="fetch-failed",
            severity="high",
            category="transport",
            title="Failed to Fetch Target URL",
            detail=f"Could not reach {url}: {exc}",
            target=url,
            evidence=PciEvidence(notes=str(exc)[:200]),
            remediation=PciRemediation("Ensure the target URL is accessible from the scanner host."),
        ))
        return findings, []

    body = resp.text
    headers = dict(resp.headers)
    ct = headers.get("content-type", "").lower()
    if "html" in ct or not ct or "javascript" in ct:
        findings += _web_checks(url, body, headers, tls)

    processors = detect_processors(body, headers)
    return findings, processors


# ── Full PCI scan orchestrator ────────────────────────────────────────────────

ProgressCallback = Callable[[str, str], Awaitable[None]]  # (phase, message)


async def run_full_pci_scan(
    scope: PciScope,
    on_progress: ProgressCallback | None = None,
    job_id: int | None = None,
) -> tuple[list[PciFinding], PciScanSummary, list]:
    """
    Full Tenable-style PCI scan:
      scope_resolution → host_discovery → port_scan → vulnerability →
      brute_exposure → web_crawl → web_checks → malware → report
    """
    findings: list[PciFinding] = []
    summary = PciScanSummary(
        scope_name=scope.name,
        scan_profile=scope.assessment_type,
    )

    async def progress(phase: str, msg: str) -> None:
        summary.phases_completed.append(phase)
        if on_progress:
            await on_progress(phase, msg)

    # ── Phase 1: Scope resolution ─────────────────────────────────────────────
    await progress("scope_resolution", f"Resolving {len(scope.raw_targets)} targets…")
    loop = asyncio.get_event_loop()
    if not scope.resolved:
        from core.pci_scope import resolve_targets
        await loop.run_in_executor(None, resolve_targets, scope)
    all_ips = list({ip for rt in scope.resolved for ip in rt.ips})
    summary.target_count = len(scope.resolved)

    # Collect all seed URLs for web scanning
    seed_urls: list[str] = []
    for rt in scope.resolved:
        seed_urls += rt.seed_urls
    seed_urls += scope.web.payment_pages + scope.web.entry_pages

    # ── Phase 2: Host discovery ───────────────────────────────────────────────
    live_hosts_map: dict[str, str] = {}   # ip → hostname
    if scope.checks.host_discovery and all_ips:
        await progress("host_discovery", f"Probing {len(all_ips)} IP(s)…")
        from core.pci_host_discovery import discover_hosts
        live = await discover_hosts(all_ips)
        live_hosts_map = {h.ip: h.hostname for h in live}
        summary.hosts_live = len(live)
        await progress("host_discovery", f"Found {len(live)} live host(s)")
    else:
        # If no IPs resolved (URL-only scope), treat hostnames as live
        for rt in scope.resolved:
            if rt.hostname:
                live_hosts_map[rt.hostname] = rt.hostname
        summary.hosts_live = len(live_hosts_map)

    # ── Phase 3: Port scan ────────────────────────────────────────────────────
    host_ports: dict[str, list] = {}   # ip → list[OpenPort]
    if scope.checks.port_scan and live_hosts_map:
        ports_to_scan = get_ports_for_profile(scope.ports)
        await progress("port_scan", f"Scanning ports on {len(live_hosts_map)} host(s)…")
        from core.pci_port_scanner import scan_host_ports, findings_from_ports
        for ip in list(live_hosts_map.keys()):
            open_ports = await scan_host_ports(ip, ports_to_scan)
            host_ports[ip] = open_ports
            summary.ports_open += len(open_ports)
            pf = findings_from_ports(ip, open_ports)
            findings += pf

    # ── Phase 4: Vulnerability checks ────────────────────────────────────────
    if scope.checks.vulnerability and host_ports:
        await progress("vulnerability", "Running vulnerability checks…")
        from core.pci_vuln_checks import check_banner_vulns, check_tls_vulnerabilities
        for ip, open_ports in host_ports.items():
            findings += check_banner_vulns(ip, open_ports)
            # TLS deep check on HTTPS ports
            for op in open_ports:
                if op.service in ("https", "https-alt"):
                    tls_f = await loop.run_in_executor(
                        None, check_tls_vulnerabilities, ip, op.port
                    )
                    findings += tls_f

    # ── Phase 5: Brute-force exposure ─────────────────────────────────────────
    if scope.checks.brute_exposure:
        await progress("brute_exposure", "Checking brute-force exposure…")
        from core.pci_brute_exposure import check_admin_port_exposure, check_web_admin_exposure
        for ip, open_ports in host_ports.items():
            findings += check_admin_port_exposure(ip, open_ports)
        if seed_urls:
            bf_findings = await check_web_admin_exposure(seed_urls)
            findings += bf_findings

    # ── Phase 6: Web crawl ────────────────────────────────────────────────────
    crawled_pages = []
    if scope.checks.web_scan and seed_urls:
        await progress("web_crawl", f"Crawling {len(seed_urls)} seed URL(s)…")
        from core.pci_web_crawler import crawl
        crawled_pages = await crawl(seed_urls, scope.web)
        summary.pages_crawled = len(crawled_pages)
        await progress("web_crawl", f"Crawled {len(crawled_pages)} pages")

    # ── Phase 7: Web checks (headers, TLS, forms, cookies, CORS, data) ───────
    if scope.checks.web_scan:
        await progress("web_checks", "Running PCI web checks…")
        from core.pci_scanner_web import check_transport, run_web_checks

        # Check URLs from crawl
        for page in crawled_pages:
            tls = page.url.startswith("https://")
            findings += run_web_checks(page.url, page.body, page.headers, tls)

        # Also check seed URLs that may not have been crawled
        crawled_urls = {p.url for p in crawled_pages}
        for url in seed_urls:
            if url not in crawled_urls:
                wf, procs = await scan_url_pci(url)
                findings += wf
                summary.processors_detected = list(set(summary.processors_detected + procs))

        # Extract processors from crawled pages
        for page in crawled_pages:
            procs = detect_processors(page.body, page.headers)
            for p in procs:
                if p not in summary.processors_detected:
                    summary.processors_detected.append(p)

        # Login policy checks (brute exposure on web forms)
        if scope.checks.brute_exposure:
            from core.pci_brute_exposure import check_login_policy
            pages_with_forms = [
                (p.url, p.body, p.headers)
                for p in crawled_pages
                if p.forms_found > 0
            ]
            findings += await check_login_policy(pages_with_forms)

    # ── Phase 8: Malware checks ───────────────────────────────────────────────
    if scope.checks.malware and crawled_pages:
        await progress("malware", "Running malware and skimmer checks…")
        from core.pci_malware_checks import check_malware_indicators
        for page in crawled_pages:
            findings += check_malware_indicators(page)

    # ── Phase 9: Payment flow testing ─────────────────────────────────────────
    flow_results = []
    if scope.checks.payment_flow:
        payment_urls = [p.url for p in crawled_pages if p.is_payment_page]
        if not payment_urls:
            payment_urls = seed_urls[:5]
        if payment_urls:
            await progress("payment_flow", f"Testing payment flows on {len(payment_urls)} URL(s)…")
            from core.pci_payment_flow import run_payment_flow_tests
            flow_results = await run_payment_flow_tests(payment_urls[:10])
            for fr in flow_results:
                findings += fr.findings
            reached = sum(1 for fr in flow_results if fr.reached_payment_form)
            await progress("payment_flow", f"Flow tests complete — {reached}/{len(flow_results)} forms reached")

    await progress("report", f"Scan complete — {len(findings)} findings")
    summary.tally(findings)
    return findings, summary, flow_results


# ── Web checks module (split for maintainability) ─────────────────────────────
# pci_scanner_web.py is imported above — ensure it exists

def _ensure_web_module() -> None:
    """Create pci_scanner_web.py if it doesn't exist (shouldn't happen)."""
    pass
