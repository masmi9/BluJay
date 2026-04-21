"""
Passive scanner — runs checks on each proxied flow without sending
additional requests. Called from the internal_flow endpoint.
"""
import json
import re
from dataclasses import dataclass, field
from urllib.parse import parse_qs, urlparse


@dataclass
class PassiveFinding:
    check_name: str
    severity: str
    title: str
    detail: str
    evidence: str = ""
    remediation: str = ""


# ── Helpers ──────────────────────────────────────────────────────────────────

def _headers_lower(headers: dict) -> dict[str, str]:
    return {k.lower(): v for k, v in headers.items()}


def _get_cookies(headers: dict[str, str]) -> list[str]:
    return [v for k, v in headers.items() if k == "set-cookie"]


# ── Checks ───────────────────────────────────────────────────────────────────

def check_missing_security_headers(resp_headers: dict, tls: bool) -> list[PassiveFinding]:
    h = _headers_lower(resp_headers)
    findings = []

    checks = [
        ("x-content-type-options", "low",
         "Missing X-Content-Type-Options",
         "The response does not set X-Content-Type-Options: nosniff, allowing MIME-type sniffing attacks.",
         "Add header: X-Content-Type-Options: nosniff"),
        ("x-frame-options", "medium",
         "Missing X-Frame-Options",
         "No X-Frame-Options or CSP frame-ancestors directive. The page may be embeddable in iframes, enabling clickjacking.",
         "Add: X-Frame-Options: DENY or CSP frame-ancestors 'none'"),
        ("referrer-policy", "info",
         "Missing Referrer-Policy",
         "No Referrer-Policy header. Sensitive URL fragments may leak to third parties via the Referer header.",
         "Add: Referrer-Policy: strict-origin-when-cross-origin"),
    ]

    # Check CSP separately
    if "content-security-policy" not in h:
        findings.append(PassiveFinding(
            check_name="missing-security-headers",
            severity="medium",
            title="Missing Content-Security-Policy",
            detail="No CSP header found. XSS attacks may execute without restriction.",
            remediation="Define a Content-Security-Policy header appropriate for this application.",
        ))

    for header_name, severity, title, detail, remediation in checks:
        if header_name not in h:
            findings.append(PassiveFinding(
                check_name="missing-security-headers",
                severity=severity, title=title, detail=detail, remediation=remediation,
            ))

    if tls and "strict-transport-security" not in h:
        findings.append(PassiveFinding(
            check_name="missing-security-headers",
            severity="medium",
            title="Missing HSTS Header",
            detail="HTTPS response does not include Strict-Transport-Security, leaving users vulnerable to SSL stripping.",
            remediation="Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
        ))

    return findings


def check_insecure_cookies(resp_headers: dict, tls: bool) -> list[PassiveFinding]:
    findings = []
    for cookie_val in _get_cookies(_headers_lower(resp_headers)):
        parts = [p.strip().lower() for p in cookie_val.split(";")]
        name = cookie_val.split("=")[0].strip()

        if "httponly" not in parts:
            findings.append(PassiveFinding(
                check_name="insecure-cookie",
                severity="medium",
                title=f"Cookie Missing HttpOnly: {name}",
                detail=f"Cookie '{name}' is accessible via JavaScript. XSS attacks can steal it.",
                evidence=cookie_val[:200],
                remediation="Set the HttpOnly flag on all session and auth cookies.",
            ))
        if tls and "secure" not in parts:
            findings.append(PassiveFinding(
                check_name="insecure-cookie",
                severity="medium",
                title=f"Cookie Missing Secure Flag: {name}",
                detail=f"Cookie '{name}' may be transmitted over HTTP.",
                evidence=cookie_val[:200],
                remediation="Set the Secure flag on all cookies for HTTPS applications.",
            ))
        samesite_vals = [p for p in parts if p.startswith("samesite")]
        if not samesite_vals:
            findings.append(PassiveFinding(
                check_name="insecure-cookie",
                severity="low",
                title=f"Cookie Missing SameSite: {name}",
                detail=f"Cookie '{name}' has no SameSite attribute, exposing it to CSRF attacks.",
                evidence=cookie_val[:200],
                remediation="Add SameSite=Lax or SameSite=Strict.",
            ))
    return findings


def check_reflected_input(url: str, req_headers: dict, req_body: str, resp_body: str) -> list[PassiveFinding]:
    if not resp_body:
        return []
    findings = []
    parsed = urlparse(url)
    params: dict[str, list[str]] = parse_qs(parsed.query)

    # Also parse form-encoded body
    content_type = _headers_lower(req_headers).get("content-type", "")
    if "application/x-www-form-urlencoded" in content_type and req_body:
        params.update(parse_qs(req_body))

    for param, values in params.items():
        for val in values:
            # Only flag non-trivial values (3+ chars, not purely numeric)
            if len(val) >= 3 and not val.isdigit() and val in resp_body:
                findings.append(PassiveFinding(
                    check_name="reflected-input",
                    severity="medium",
                    title=f"Reflected Input: {param}",
                    detail=f"Parameter '{param}' value is reflected verbatim in the response. This may indicate a reflected XSS vulnerability.",
                    evidence=f"{param}={val}",
                    remediation="Ensure all user-controlled input is properly HTML-encoded before being reflected in responses.",
                ))
                break  # one finding per param is enough
    return findings


_SENSITIVE_PATTERNS = [
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID", "critical"),
    (r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"]?([A-Za-z0-9\-_]{16,})", "API Key", "high"),
    (r"(?i)(secret[_-]?key|client[_-]?secret)\s*[:=]\s*['\"]?([A-Za-z0-9\-_]{16,})", "Secret Key", "high"),
    (r"-----BEGIN (RSA |EC )?PRIVATE KEY-----", "Private Key", "critical"),
    (r"(?i)password\s*[:=]\s*['\"]?([^\s'\"]{6,})", "Password in Response", "high"),
    (r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+", "JWT Token", "medium"),
    (r"(?i)(bearer|token)\s*[:=]\s*['\"]?([A-Za-z0-9\-_\.]{20,})", "Bearer Token", "medium"),
]


def check_sensitive_data(resp_body: str, url: str) -> list[PassiveFinding]:
    if not resp_body:
        return []
    findings = []
    seen: set[str] = set()
    for pattern, label, severity in _SENSITIVE_PATTERNS:
        m = re.search(pattern, resp_body)
        if m and label not in seen:
            seen.add(label)
            findings.append(PassiveFinding(
                check_name="sensitive-data-exposure",
                severity=severity,
                title=f"Sensitive Data Exposed: {label}",
                detail=f"The response appears to contain a {label}.",
                evidence=m.group(0)[:120],
                remediation="Remove sensitive data from API responses. Apply response filtering and secrets scanning in CI.",
            ))
    return findings


def check_info_disclosure(resp_headers: dict, resp_body: str) -> list[PassiveFinding]:
    findings = []
    h = _headers_lower(resp_headers)

    server = h.get("server", "")
    if re.search(r"[0-9]+\.[0-9]+", server):
        findings.append(PassiveFinding(
            check_name="info-disclosure",
            severity="low",
            title="Server Version Disclosed",
            detail=f"Server header reveals version: {server}",
            evidence=server,
            remediation="Configure the server to omit or genericize the Server header.",
        ))

    powered_by = h.get("x-powered-by", "")
    if powered_by:
        findings.append(PassiveFinding(
            check_name="info-disclosure",
            severity="low",
            title="X-Powered-By Header Present",
            detail=f"Technology stack disclosed: {powered_by}",
            evidence=powered_by,
            remediation="Remove the X-Powered-By header.",
        ))

    if resp_body:
        stack_patterns = [
            r"Traceback \(most recent call last\)",
            r"at [A-Za-z0-9_$]+\.[A-Za-z0-9_$]+\(.*\.java:\d+\)",
            r"Microsoft\.AspNetCore",
            r"System\.NullReferenceException",
            r"ORA-\d{5}:",
            r"You have an error in your SQL syntax",
            r"Warning: mysql_",
        ]
        for pat in stack_patterns:
            if re.search(pat, resp_body):
                findings.append(PassiveFinding(
                    check_name="info-disclosure",
                    severity="medium",
                    title="Stack Trace / Error Message Leaked",
                    detail="The response contains a server-side stack trace or detailed error, which discloses implementation details.",
                    evidence=re.search(pat, resp_body).group(0)[:120],  # type: ignore
                    remediation="Disable detailed error messages in production. Use generic error pages.",
                ))
                break

    return findings


def check_cors(resp_headers: dict, req_headers: dict) -> list[PassiveFinding]:
    findings = []
    h = _headers_lower(resp_headers)
    acao = h.get("access-control-allow-origin", "")
    acac = h.get("access-control-allow-credentials", "")

    if acao == "*" and acac.lower() == "true":
        findings.append(PassiveFinding(
            check_name="cors-misconfiguration",
            severity="high",
            title="CORS: Wildcard Origin with Credentials",
            detail="Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: true allows any origin to make credentialed cross-origin requests.",
            evidence=f"ACAO: {acao} | ACAC: {acac}",
            remediation="Never use wildcard ACAO with ACAC: true. Explicitly allowlist trusted origins.",
        ))

    origin = _headers_lower(req_headers).get("origin", "")
    if origin and acao == origin and acac.lower() == "true":
        findings.append(PassiveFinding(
            check_name="cors-misconfiguration",
            severity="medium",
            title="CORS: Origin Reflected with Credentials",
            detail="The server reflects the request Origin back in Access-Control-Allow-Origin with credentials enabled. If the allowlist is permissive this enables cross-origin data theft.",
            evidence=f"Origin: {origin} → ACAO: {acao}",
            remediation="Validate the Origin against a strict allowlist before reflecting it.",
        ))

    return findings


# ── Main entry point ──────────────────────────────────────────────────────────

def run_passive_checks(flow: dict) -> list[PassiveFinding]:
    """Run all passive checks against a single captured flow dict."""
    findings: list[PassiveFinding] = []

    resp_headers: dict = flow.get("response_headers") or {}
    req_headers: dict = flow.get("request_headers") or {}
    if isinstance(resp_headers, str):
        try:
            resp_headers = json.loads(resp_headers)
        except Exception:
            resp_headers = {}
    if isinstance(req_headers, str):
        try:
            req_headers = json.loads(req_headers)
        except Exception:
            req_headers = {}

    resp_body: str = flow.get("response_body") or ""
    if isinstance(resp_body, bytes):
        resp_body = resp_body.decode(errors="replace")

    req_body: str = flow.get("request_body") or ""
    if isinstance(req_body, bytes):
        req_body = req_body.decode(errors="replace")

    url: str = flow.get("url") or ""
    tls: bool = flow.get("tls", False)
    status: int = flow.get("response_status") or 0

    # Only run header/cookie checks on HTML/JSON responses, not images/fonts/etc.
    content_type = (flow.get("content_type") or "").lower()
    is_document = any(t in content_type for t in ("html", "json", "javascript", "text"))

    if status and is_document:
        findings += check_missing_security_headers(resp_headers, tls)
        findings += check_insecure_cookies(resp_headers, tls)
        findings += check_cors(resp_headers, req_headers)

    findings += check_sensitive_data(resp_body[:50_000], url)
    findings += check_info_disclosure(resp_headers, resp_body[:20_000])

    if is_document and status and status < 500:
        findings += check_reflected_input(url, req_headers, req_body, resp_body[:20_000])

    return findings
