"""
PCI web-layer checks — extracted from orchestrator for reuse.
Covers: TLS/transport, security headers, cookies, forms, mixed content,
        card data, payment processor fingerprinting, SRI, CORS.
"""
from __future__ import annotations
import json
import re
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

from core.pci_models import PciFinding, PciEvidence, PciRemediation

_PROCESSOR_SIGS: list[tuple[str, list[str]]] = [
    ("Stripe",        [r"js\.stripe\.com", r"pk_(?:live|test)_[A-Za-z0-9]{20,}"]),
    ("Braintree",     [r"js\.braintreegateway\.com"]),
    ("PayPal",        [r"paypalobjects\.com", r"js\.paypal\.com", r"paypal\.com/sdk"]),
    ("Adyen",         [r"checkoutshopper-(?:live|test)\.adyen\.com"]),
    ("Square",        [r"js\.squareup\.com"]),
    ("Klarna",        [r"js\.klarna\.com", r"x\.klarnacdn\.net"]),
    ("Checkout.com",  [r"cdn\.checkout\.com"]),
    ("Recurly",       [r"js\.recurly\.com"]),
    ("Authorize.Net", [r"authorize\.net", r"AcceptUI\.js"]),
    ("Worldpay",      [r"worldpay\.com/js"]),
    ("CyberSource",   [r"cybersource\.com"]),
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


# ── Transport / TLS ───────────────────────────────────────────────────────────

def check_transport(url: str) -> list[PciFinding]:
    findings: list[PciFinding] = []
    parsed = urlparse(url)
    host = parsed.hostname or ""
    port = parsed.port or 443

    if parsed.scheme != "https":
        findings.append(PciFinding(
            check_name="https-required", severity="critical", category="transport",
            title="Payment URL Not Using HTTPS",
            detail=f"{url} uses unencrypted HTTP. PCI DSS Req 4.2.1 mandates TLS for all cardholder data in transit.",
            target=url,
            evidence=PciEvidence(notes=f"scheme={parsed.scheme}"),
            remediation=PciRemediation("Redirect HTTP to HTTPS. Enforce TLS 1.2+ on all payment endpoints.",
                                        pci_req="Req 4.2.1", priority=1),
            pci_req="Req 4.2.1", phase="web_checks",
        ))
        return findings

    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=10) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                proto = ssock.version() or ""
                if proto in ("TLSv1", "TLSv1.1"):
                    findings.append(PciFinding(
                        check_name="tls-obsolete-version", severity="critical", category="transport",
                        title=f"Obsolete TLS Negotiated: {proto}",
                        detail=f"Server negotiated {proto}, prohibited by PCI DSS 3.2.1+ (June 2018).",
                        target=host, port=port, service="tls",
                        pci_req="Req 4.2.1", plugin_id="PCI-TLS-OBSOLETE",
                        evidence=PciEvidence(banner=f"Negotiated: {proto}"),
                        remediation=PciRemediation("Disable TLS 1.0/1.1. Accept TLS 1.2+ only.", pci_req="Req 4.2.1", priority=1),
                        phase="web_checks",
                    ))
                not_after = cert.get("notAfter", "")
                if not_after:
                    try:
                        exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                        days = (exp - datetime.now(timezone.utc)).days
                        if days < 0:
                            findings.append(PciFinding(
                                check_name="tls-cert-expired", severity="critical", category="transport",
                                title="TLS Certificate Expired",
                                detail=f"Certificate for {host} expired {abs(days)} days ago.",
                                target=host, port=port, pci_req="Req 4.2.1",
                                evidence=PciEvidence(notes=f"notAfter={not_after}"),
                                remediation=PciRemediation("Renew TLS certificate immediately.", pci_req="Req 4.2.1", priority=1),
                                phase="web_checks",
                            ))
                        elif days <= 30:
                            findings.append(PciFinding(
                                check_name="tls-cert-expiring", severity="high", category="transport",
                                title=f"TLS Certificate Expires in {days} Days",
                                detail=f"Certificate for {host} expires {not_after}.",
                                target=host, port=port, pci_req="Req 4.2.1",
                                evidence=PciEvidence(notes=f"notAfter={not_after}"),
                                remediation=PciRemediation("Renew the TLS certificate.", pci_req="Req 4.2.1", priority=1),
                                phase="web_checks",
                            ))
                    except ValueError:
                        pass
    except ssl.SSLCertVerificationError as exc:
        msg = str(exc)
        cn = "hostname-mismatch" if "HOSTNAME" in msg else "self-signed" if "SELF_SIGNED" in msg else "invalid"
        findings.append(PciFinding(
            check_name=f"tls-cert-{cn}", severity="critical", category="transport",
            title=f"TLS Certificate Issue: {cn.replace('-', ' ').title()}",
            detail=msg[:300], target=host, port=port, pci_req="Req 4.2.1",
            evidence=PciEvidence(notes=msg[:300]),
            remediation=PciRemediation("Obtain a valid CA-signed certificate matching the hostname.", pci_req="Req 4.2.1", priority=1),
            phase="web_checks",
        ))
    except Exception as exc:
        findings.append(PciFinding(
            check_name="tls-connection-failed", severity="high", category="transport",
            title="TLS Connection Failed",
            detail=f"Could not connect to {host}:{port}: {exc}",
            target=host, port=port, pci_req="Req 4.2.1",
            remediation=PciRemediation("Ensure TLS is properly configured.", pci_req="Req 4.2.1", priority=1),
            phase="web_checks",
        ))
    return findings


# ── Security headers ──────────────────────────────────────────────────────────

def check_headers(url: str, headers: dict, tls: bool) -> list[PciFinding]:
    findings: list[PciFinding] = []
    h = {k.lower(): v for k, v in headers.items()}
    host = urlparse(url).netloc

    if tls:
        hsts = h.get("strict-transport-security", "")
        if not hsts:
            findings.append(PciFinding(check_name="hsts-missing", severity="high", category="headers",
                title="Missing HSTS on Payment Page", target=host, pci_req="Req 4.2.1",
                detail="No Strict-Transport-Security header. SSL stripping attacks can downgrade payment flows.",
                remediation=PciRemediation("Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload", pci_req="Req 4.2.1", priority=1),
                phase="web_checks"))
        else:
            m = re.search(r"max-age\s*=\s*(\d+)", hsts, re.IGNORECASE)
            if m and int(m.group(1)) < 31536000:
                findings.append(PciFinding(check_name="hsts-max-age-short", severity="medium", category="headers",
                    title=f"HSTS max-age Too Short ({m.group(1)}s)", target=host, pci_req="Req 4.2.1",
                    detail="HSTS max-age should be ≥ 1 year on payment pages.",
                    evidence=PciEvidence(banner=hsts[:200]),
                    remediation=PciRemediation("Set max-age=31536000.", pci_req="Req 4.2.1", priority=2),
                    phase="web_checks"))

    csp = h.get("content-security-policy", "")
    if not csp:
        findings.append(PciFinding(check_name="csp-missing", severity="high", category="headers",
            title="Missing CSP on Payment Page", target=host, pci_req="Req 6.4.3",
            detail="No Content-Security-Policy. XSS can steal card data or inject skimmers. PCI DSS v4.0 Req 6.4.3 mandates CSP.",
            remediation=PciRemediation("Define a strict CSP allowlisting only required payment processor domains.", pci_req="Req 6.4.3", priority=1),
            phase="web_checks"))
    else:
        if "'unsafe-inline'" in csp:
            findings.append(PciFinding(check_name="csp-unsafe-inline", severity="high", category="headers",
                title="CSP Allows 'unsafe-inline'", target=host, pci_req="Req 6.4.3",
                detail="'unsafe-inline' in CSP permits arbitrary inline scripts on payment pages.",
                evidence=PciEvidence(banner=csp[:300]),
                remediation=PciRemediation("Remove 'unsafe-inline'. Use nonces or hashes.", pci_req="Req 6.4.3", priority=1),
                phase="web_checks"))
        if "'unsafe-eval'" in csp:
            findings.append(PciFinding(check_name="csp-unsafe-eval", severity="medium", category="headers",
                title="CSP Allows 'unsafe-eval'", target=host, pci_req="Req 6.4.3",
                detail="'unsafe-eval' in CSP permits eval() and related constructs.",
                evidence=PciEvidence(banner=csp[:300]),
                remediation=PciRemediation("Remove 'unsafe-eval'.", pci_req="Req 6.4.3", priority=2),
                phase="web_checks"))

    xfo = h.get("x-frame-options", "")
    if not xfo and "frame-ancestors" not in csp:
        findings.append(PciFinding(check_name="xframe-missing", severity="high", category="headers",
            title="Missing Clickjacking Protection on Payment Page", target=host, pci_req="Req 6.4.3",
            detail="No X-Frame-Options or CSP frame-ancestors. Payment forms can be embedded in attacker iframes.",
            remediation=PciRemediation("Add: X-Frame-Options: DENY or CSP frame-ancestors 'none'", pci_req="Req 6.4.3", priority=1),
            phase="web_checks"))

    if "x-content-type-options" not in h:
        findings.append(PciFinding(check_name="xcontent-type-missing", severity="low", category="headers",
            title="Missing X-Content-Type-Options", target=host, pci_req="Req 6.4.3",
            detail="MIME sniffing enabled on payment page.",
            remediation=PciRemediation("Add: X-Content-Type-Options: nosniff", pci_req="Req 6.4.3", priority=3),
            phase="web_checks"))

    ref = h.get("referrer-policy", "")
    if not ref:
        findings.append(PciFinding(check_name="referrer-policy-missing", severity="medium", category="headers",
            title="Missing Referrer-Policy on Payment Page", target=host, pci_req="Req 4.2.1",
            detail="Payment page URLs may leak via Referer header to third-party payment SDKs.",
            remediation=PciRemediation("Add: Referrer-Policy: strict-origin-when-cross-origin", pci_req="Req 4.2.1", priority=2),
            phase="web_checks"))

    return findings


# ── Cookies ───────────────────────────────────────────────────────────────────

def check_cookies(url: str, headers: dict, tls: bool) -> list[PciFinding]:
    findings: list[PciFinding] = []
    h = {k.lower(): v for k, v in headers.items()}
    host = urlparse(url).netloc
    for cookie_str in [v for k, v in h.items() if k == "set-cookie"]:
        parts = [p.strip().lower() for p in cookie_str.split(";")]
        name = cookie_str.split("=")[0].strip()
        is_session = any(k in name.lower() for k in ("sess", "token", "auth", "jwt", "sid", "user"))
        if tls and "secure" not in parts:
            findings.append(PciFinding(check_name="cookie-missing-secure", severity="high", category="cookies",
                title=f"Cookie Missing Secure Flag: {name}", target=host, pci_req="Req 6.4.3",
                detail=f"'{name}' on HTTPS payment page lacks Secure flag.",
                evidence=PciEvidence(banner=cookie_str[:250]),
                remediation=PciRemediation("Set Secure flag on all cookies.", pci_req="Req 6.4.3", priority=1),
                phase="web_checks"))
        if is_session and "httponly" not in parts:
            findings.append(PciFinding(check_name="cookie-missing-httponly", severity="medium", category="cookies",
                title=f"Session Cookie Missing HttpOnly: {name}", target=host, pci_req="Req 6.4.3",
                detail=f"'{name}' accessible via JavaScript. XSS can steal session tokens.",
                evidence=PciEvidence(banner=cookie_str[:250]),
                remediation=PciRemediation("Set HttpOnly on all session cookies.", pci_req="Req 6.4.3", priority=2),
                phase="web_checks"))
        if not any(p.startswith("samesite") for p in parts):
            findings.append(PciFinding(check_name="cookie-missing-samesite", severity="low", category="cookies",
                title=f"Cookie Missing SameSite: {name}", target=host, pci_req="Req 6.4.3",
                detail="No SameSite attribute — CSRF attacks possible.",
                evidence=PciEvidence(banner=cookie_str[:250]),
                remediation=PciRemediation("Add SameSite=Lax or Strict.", pci_req="Req 6.4.3", priority=3),
                phase="web_checks"))
    return findings


# ── Forms, mixed content, SRI ─────────────────────────────────────────────────

def check_forms_and_content(url: str, body: str, tls: bool) -> list[PciFinding]:
    findings: list[PciFinding] = []
    host = urlparse(url).netloc

    for tag in re.findall(r'<script[^>]*>', body, re.IGNORECASE):
        src_m = re.search(r'src\s*=\s*["\']([^"\']+)["\']', tag, re.IGNORECASE)
        if not src_m:
            continue
        src = src_m.group(1)
        if tls and src.startswith("http://"):
            findings.append(PciFinding(check_name="mixed-content-script", severity="critical", category="mixed-content",
                title="HTTP Script on HTTPS Payment Page", target=host, pci_req="Req 4.2.1",
                detail=f"Script {src[:200]} loaded over HTTP — replaceable by MITM.",
                evidence=PciEvidence(banner=src[:200]),
                remediation=PciRemediation("Load all scripts over HTTPS.", pci_req="Req 4.2.1", priority=1),
                phase="web_checks"))
        is_payment = any(re.search(sig, src, re.IGNORECASE) for _, sigs in _PROCESSOR_SIGS for sig in sigs)
        if src.startswith(("http", "//")) and is_payment and "integrity=" not in tag.lower():
            findings.append(PciFinding(check_name="payment-script-no-sri", severity="high", category="integrity",
                title="Payment SDK Script Without SRI", target=host, pci_req="Req 6.4.3",
                detail=f"External payment script {src[:200]} has no integrity= attribute. A compromised CDN can inject a skimmer.",
                evidence=PciEvidence(banner=src[:200]),
                remediation=PciRemediation("Add integrity= (SRI hash) and crossorigin= to all external payment scripts.", pci_req="Req 6.4.3", priority=1),
                phase="web_checks"))

    for form in re.findall(r'<form[^>]*>.*?</form>', body, re.IGNORECASE | re.DOTALL):
        has_pay = bool(re.search(r'(?:cc-number|card.?number|cardnumber|credit.?card|pan|payment)', form, re.IGNORECASE))
        has_cvv = bool(re.search(r'(?:cvv|cvc|cvn|security.?code)', form, re.IGNORECASE))
        if not (has_pay or has_cvv):
            continue
        action_m = re.search(r'action\s*=\s*["\']([^"\']+)["\']', form, re.IGNORECASE)
        if action_m and action_m.group(1).startswith("http://"):
            findings.append(PciFinding(check_name="payment-form-http-action", severity="critical", category="forms",
                title="Payment Form Posts to HTTP URL", target=host, pci_req="Req 4.2.1",
                detail=f"Payment form submits to {action_m.group(1)[:200]} over plain HTTP.",
                evidence=PciEvidence(banner=f"action={action_m.group(1)[:200]}"),
                remediation=PciRemediation("Change form action to HTTPS URL.", pci_req="Req 4.2.1", priority=1),
                phase="web_checks"))
        for inp in re.findall(r'<input[^>]+>', form, re.IGNORECASE):
            il = inp.lower()
            if any(k in il for k in ("cc-number", "card", "cvv", "cvc", "exp")):
                ac_m = re.search(r'autocomplete\s*=\s*["\']([^"\']*)["\']', inp, re.IGNORECASE)
                if ac_m and ac_m.group(1).lower() not in ("off", "new-password"):
                    findings.append(PciFinding(check_name="payment-form-autocomplete", severity="medium", category="forms",
                        title="Card Input Has Autocomplete Enabled", target=host, pci_req="Req 3.4",
                        detail=f"autocomplete='{ac_m.group(1)}' — browsers may cache card data.",
                        evidence=PciEvidence(banner=inp[:200]),
                        remediation=PciRemediation('Set autocomplete="off" on card fields.', pci_req="Req 3.4", priority=2),
                        phase="web_checks"))
    return findings


# ── Card data detection ───────────────────────────────────────────────────────

def check_card_data(url: str, body: str) -> list[PciFinding]:
    findings: list[PciFinding] = []
    host = urlparse(url).netloc
    seen: set[str] = set()
    for m in _PAN_RE.finditer(body):
        digits = re.sub(r'[^0-9]', '', m.group(0))
        if digits not in seen and _luhn(digits):
            seen.add(digits)
            masked = digits[:4] + "×" * (len(digits) - 8) + digits[-4:]
            findings.append(PciFinding(check_name="pan-in-response", severity="critical", category="data",
                title="Possible PAN in Response Body", target=host, pci_req="Req 3.3.1",
                cvss_score=9.5,
                detail="Luhn-valid card number pattern found. Storing/returning PANs violates PCI DSS Req 3.3.1.",
                evidence=PciEvidence(notes=f"Masked: {masked}"),
                remediation=PciRemediation("Remove PANs from responses. Tokenize. Never log PANs.", pci_req="Req 3.3.1", priority=1),
                phase="web_checks"))
    if _CVV_RE.search(body):
        cvv_m = _CVV_RE.search(body)
        findings.append(PciFinding(check_name="cvv-in-response", severity="critical", category="data",
            title="CVV/CVC Value Found in Response", target=host, pci_req="Req 3.3.2",
            cvss_score=9.5,
            detail="CVV/CVC security code pattern detected. PCI DSS strictly prohibits storing CVV after authorization.",
            evidence=PciEvidence(notes=cvv_m.group(0)[:120] if cvv_m else ""),
            remediation=PciRemediation("Never store or return CVV/CVC. Remove from logs.", pci_req="Req 3.3.2", priority=1),
            phase="web_checks"))
    if _TRACK1_RE.search(body) or _TRACK2_RE.search(body):
        findings.append(PciFinding(check_name="track-data-in-response", severity="critical", category="data",
            title="Magnetic Stripe Track Data in Response", target=host, pci_req="Req 3.3.1",
            cvss_score=10.0,
            detail="Track 1 or Track 2 magnetic stripe data pattern detected. Storing track data is prohibited.",
            evidence=PciEvidence(notes="Track data pattern matched"),
            remediation=PciRemediation("Remove all track data from responses and storage.", pci_req="Req 3.3.1", priority=1),
            phase="web_checks"))
    return findings


# ── Processors + 3DS ─────────────────────────────────────────────────────────

def check_processors(url: str, body: str, headers: dict) -> list[PciFinding]:
    findings: list[PciFinding] = []
    host = urlparse(url).netloc
    full = body + json.dumps(headers)
    processors = [n for n, pats in _PROCESSOR_SIGS if any(re.search(p, full, re.IGNORECASE) for p in pats)]
    if processors:
        findings.append(PciFinding(check_name="payment-processor-detected", severity="info", category="processor",
            title=f"Payment Processor(s) Detected: {', '.join(processors)}", target=host, pci_req="Req 12.8",
            detail=f"Page uses: {', '.join(processors)}. Verify each is PCI DSS Level 1 certified.",
            evidence=PciEvidence(notes=f"Detected: {', '.join(processors)}"),
            remediation=PciRemediation("Confirm processors are on Visa Global Registry of Service Providers.", pci_req="Req 12.8", priority=3),
            phase="web_checks"))
        if len(processors) > 2:
            findings.append(PciFinding(check_name="multiple-processors", severity="low", category="processor",
                title=f"Multiple Payment Processors ({len(processors)}) on One Page", target=host, pci_req="Req 12.8",
                detail="Multiple SDKs increase attack surface and PCI scope.",
                evidence=PciEvidence(notes=", ".join(processors)),
                remediation=PciRemediation("Minimize payment SDKs in scope.", pci_req="Req 12.8", priority=3),
                phase="web_checks"))
    if _3DS_RE.search(body):
        findings.append(PciFinding(check_name="3ds-detected", severity="info", category="processor",
            title="3D Secure / SCA Flow Detected", target=host, pci_req="Req 6.4",
            detail="3DS/Strong Customer Authentication indicators found. Reduces liability and meets SCA requirements.",
            phase="web_checks"))
    return findings


# ── CORS ──────────────────────────────────────────────────────────────────────

def check_cors(url: str, headers: dict) -> list[PciFinding]:
    findings: list[PciFinding] = []
    h = {k.lower(): v for k, v in headers.items()}
    host = urlparse(url).netloc
    acao = h.get("access-control-allow-origin", "")
    acac = h.get("access-control-allow-credentials", "")
    if acao == "*":
        findings.append(PciFinding(check_name="cors-wildcard-payment", severity="high", category="cors",
            title="CORS Wildcard on Payment Endpoint", target=host, pci_req="Req 6.4.3",
            detail="ACAO: * allows any origin to read payment responses. Session tokens or order data may be exposed.",
            evidence=PciEvidence(banner=f"ACAO: {acao}"),
            remediation=PciRemediation("Restrict CORS to trusted origins. Never use wildcard on payment APIs.", pci_req="Req 6.4.3", priority=1),
            phase="web_checks"))
    if acao and acao != "*" and acac.lower() == "true":
        findings.append(PciFinding(check_name="cors-reflected-credentials", severity="medium", category="cors",
            title="CORS Allows Credentialed Requests from External Origin", target=host, pci_req="Req 6.4.3",
            detail=f"ACAO: {acao} with ACAC: true grants credentialed cross-origin access.",
            evidence=PciEvidence(banner=f"ACAO: {acao}, ACAC: {acac}"),
            remediation=PciRemediation("Validate allowed origins against a strict allowlist.", pci_req="Req 6.4.3", priority=2),
            phase="web_checks"))
    return findings


# ── Combined entry point ──────────────────────────────────────────────────────

def run_web_checks(url: str, body: str, headers: dict, tls: bool) -> list[PciFinding]:
    findings: list[PciFinding] = []
    findings += check_headers(url, headers, tls)
    findings += check_cookies(url, headers, tls)
    findings += check_forms_and_content(url, body, tls)
    findings += check_card_data(url, body)
    findings += check_processors(url, body, headers)
    findings += check_cors(url, headers)
    return findings
