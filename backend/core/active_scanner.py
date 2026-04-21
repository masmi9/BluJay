"""
Active scanner — sends crafted payloads against target flows to detect
XSS, SQLi, open redirect, path traversal, and basic SSRF.
"""
import asyncio
import json
import re
from dataclasses import dataclass, field
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx
import structlog

logger = structlog.get_logger()


@dataclass
class ActiveFinding:
    check_name: str
    severity: str
    title: str
    detail: str
    evidence: str = ""
    remediation: str = ""
    url: str = ""


# ── Payloads ──────────────────────────────────────────────────────────────────

XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'><img src=x onerror=alert(1)>",
    '<svg onload=alert(1)>',
]

SQLI_PAYLOADS = [
    "'",
    '"',
    "' OR '1'='1",
    "' OR 1=1--",
    "1' AND SLEEP(0)--",
    "; DROP TABLE users--",
]

SQLI_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"warning: mysql",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"ora-\d{4,5}",
    r"pg::syntaxerror",
    r"sqlite3::exception",
    r"microsoft ole db provider for sql server",
    r"syntax error.*near",
    r"invalid query",
]

REDIRECT_PAYLOADS = [
    "//evil.com",
    "https://evil.com",
    "//evil.com/%2F..",
    "///evil.com",
]

REDIRECT_PARAM_HINTS = {"redirect", "url", "next", "return", "returnurl", "goto", "dest", "destination", "continue", "redir", "location", "target"}

TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
]

TRAVERSAL_PARAM_HINTS = {"file", "path", "page", "filename", "filepath", "dir", "folder", "include", "load", "read", "template"}

TRAVERSAL_SUCCESS_PATTERNS = [r"root:.*:0:0:", r"\[boot loader\]"]

SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://127.0.0.1/",
    "http://localhost/",
    "http://[::1]/",
]

SSRF_PARAM_HINTS = {"url", "uri", "endpoint", "host", "server", "target", "proxy", "fetch", "load", "src", "source", "webhook", "callback"}


# ── Request helpers ───────────────────────────────────────────────────────────

def _inject_param(url: str, param: str, payload: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [payload]
    new_query = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def _inject_body_param(body: str, param: str, payload: str, content_type: str) -> str:
    if "json" in content_type:
        try:
            data = json.loads(body)
            if isinstance(data, dict):
                data[param] = payload
                return json.dumps(data)
        except Exception:
            pass
    # form-encoded
    qs = parse_qs(body, keep_blank_values=True)
    qs[param] = [payload]
    return urlencode(qs, doseq=True)


def _clean_headers(headers: dict) -> dict:
    skip = {"host", "content-length", "transfer-encoding", "connection"}
    return {k: v for k, v in headers.items() if k.lower() not in skip}


def _parse_headers(raw: str | dict) -> dict:
    if isinstance(raw, dict):
        return raw
    try:
        return json.loads(raw or "{}")
    except Exception:
        return {}


# ── Individual check runners ──────────────────────────────────────────────────

async def check_xss(client: httpx.AsyncClient, flow: dict, progress_cb) -> list[ActiveFinding]:
    findings: list[ActiveFinding] = []
    url = flow.get("url", "")
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    req_headers = _clean_headers(_parse_headers(flow.get("request_headers", {})))

    for param in list(qs.keys()):
        for payload in XSS_PAYLOADS:
            test_url = _inject_param(url, param, payload)
            try:
                await progress_cb()
                r = await client.get(test_url, headers=req_headers, timeout=10, follow_redirects=True)
                if payload in r.text:
                    findings.append(ActiveFinding(
                        check_name="xss-reflected",
                        severity="high",
                        title=f"Reflected XSS: {param}",
                        detail=f"Parameter '{param}' reflects payload unsanitized in the response.",
                        evidence=f"Payload: {payload}\nURL: {test_url}",
                        remediation="HTML-encode all user-controlled output. Implement a Content-Security-Policy.",
                        url=test_url,
                    ))
                    break  # one finding per param
            except Exception:
                pass

    return findings


async def check_sqli(client: httpx.AsyncClient, flow: dict, progress_cb) -> list[ActiveFinding]:
    findings: list[ActiveFinding] = []
    url = flow.get("url", "")
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    req_headers = _clean_headers(_parse_headers(flow.get("request_headers", {})))

    for param in list(qs.keys()):
        for payload in SQLI_PAYLOADS:
            test_url = _inject_param(url, param, payload)
            try:
                await progress_cb()
                r = await client.get(test_url, headers=req_headers, timeout=10, follow_redirects=True)
                body_lower = r.text.lower()
                for pat in SQLI_ERROR_PATTERNS:
                    if re.search(pat, body_lower):
                        findings.append(ActiveFinding(
                            check_name="sqli-error",
                            severity="critical",
                            title=f"SQL Injection (Error-Based): {param}",
                            detail=f"Parameter '{param}' triggers a database error response, indicating SQL injection.",
                            evidence=f"Payload: {payload}\nPattern matched: {pat}",
                            remediation="Use parameterized queries / prepared statements. Never concatenate user input into SQL.",
                            url=test_url,
                        ))
                        return findings  # one confirmed finding is enough
            except Exception:
                pass

    return findings


async def check_open_redirect(client: httpx.AsyncClient, flow: dict, progress_cb) -> list[ActiveFinding]:
    findings: list[ActiveFinding] = []
    url = flow.get("url", "")
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    req_headers = _clean_headers(_parse_headers(flow.get("request_headers", {})))

    # Only test params whose names look redirect-related
    redirect_params = [p for p in qs if p.lower() in REDIRECT_PARAM_HINTS]
    if not redirect_params:
        redirect_params = list(qs.keys())

    for param in redirect_params:
        for payload in REDIRECT_PAYLOADS:
            test_url = _inject_param(url, param, payload)
            try:
                await progress_cb()
                r = await client.get(test_url, headers=req_headers, timeout=10, follow_redirects=False)
                loc = r.headers.get("location", "")
                if r.status_code in (301, 302, 303, 307, 308) and "evil.com" in loc:
                    findings.append(ActiveFinding(
                        check_name="open-redirect",
                        severity="medium",
                        title=f"Open Redirect: {param}",
                        detail=f"Parameter '{param}' controls a redirect destination without validation.",
                        evidence=f"Payload: {payload}\nLocation: {loc}",
                        remediation="Validate redirect destinations against an allowlist of trusted URLs.",
                        url=test_url,
                    ))
                    break
            except Exception:
                pass

    return findings


async def check_path_traversal(client: httpx.AsyncClient, flow: dict, progress_cb) -> list[ActiveFinding]:
    findings: list[ActiveFinding] = []
    url = flow.get("url", "")
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    req_headers = _clean_headers(_parse_headers(flow.get("request_headers", {})))

    traversal_params = [p for p in qs if p.lower() in TRAVERSAL_PARAM_HINTS] or list(qs.keys())

    for param in traversal_params:
        for payload in TRAVERSAL_PAYLOADS:
            test_url = _inject_param(url, param, payload)
            try:
                await progress_cb()
                r = await client.get(test_url, headers=req_headers, timeout=10, follow_redirects=True)
                for pat in TRAVERSAL_SUCCESS_PATTERNS:
                    if re.search(pat, r.text):
                        findings.append(ActiveFinding(
                            check_name="path-traversal",
                            severity="critical",
                            title=f"Path Traversal: {param}",
                            detail=f"Parameter '{param}' is vulnerable to directory traversal. Server file content was returned.",
                            evidence=f"Payload: {payload}\nMatch: {re.search(pat, r.text).group(0)[:80]}",  # type: ignore
                            remediation="Canonicalize file paths and validate them against an allowed base directory. Never pass user input directly to file system APIs.",
                            url=test_url,
                        ))
                        return findings
            except Exception:
                pass

    return findings


async def check_ssrf(client: httpx.AsyncClient, flow: dict, progress_cb) -> list[ActiveFinding]:
    findings: list[ActiveFinding] = []
    url = flow.get("url", "")
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    req_headers = _clean_headers(_parse_headers(flow.get("request_headers", {})))

    ssrf_params = [p for p in qs if p.lower() in SSRF_PARAM_HINTS]
    if not ssrf_params:
        return findings

    # Get baseline response
    try:
        baseline = await client.get(url, headers=req_headers, timeout=10, follow_redirects=True)
        baseline_len = len(baseline.text)
    except Exception:
        return findings

    for param in ssrf_params:
        for payload in SSRF_PAYLOADS:
            test_url = _inject_param(url, param, payload)
            try:
                await progress_cb()
                r = await client.get(test_url, headers=req_headers, timeout=10, follow_redirects=True)
                # Heuristic: significant response length change or AWS metadata keywords
                len_diff = abs(len(r.text) - baseline_len)
                has_meta = any(k in r.text for k in ("ami-id", "instance-id", "meta-data", "computeMetadata"))
                if has_meta or (r.status_code == 200 and len_diff > 100 and len(r.text) > 50):
                    findings.append(ActiveFinding(
                        check_name="ssrf-basic",
                        severity="high",
                        title=f"Potential SSRF: {param}",
                        detail=f"Parameter '{param}' may be used in a server-side request. The response changed when targeting internal addresses.",
                        evidence=f"Payload: {payload}\nStatus: {r.status_code}, Length: {len(r.text)} (baseline: {baseline_len})",
                        remediation="Validate and allowlist target URLs. Block requests to internal IP ranges and cloud metadata endpoints.",
                        url=test_url,
                    ))
                    break
            except Exception:
                pass

    return findings


# ── Job runner ────────────────────────────────────────────────────────────────

CHECK_RUNNERS = {
    "xss-reflected": check_xss,
    "sqli-error": check_sqli,
    "open-redirect": check_open_redirect,
    "path-traversal": check_path_traversal,
    "ssrf-basic": check_ssrf,
}


async def run_active_scan(
    job_id: int,
    flows: list[dict],
    checks: list[str],
    on_finding,
    on_progress,
    on_done,
) -> None:
    """
    Run active checks against a list of flows.
    Callbacks:
      on_finding(job_id, finding: ActiveFinding, flow_id: str)
      on_progress(job_id, requests_sent: int)
      on_done(job_id, finding_count: int, requests_sent: int, error: str | None)
    """
    requests_sent = 0
    finding_count = 0
    error = None

    async def _progress():
        nonlocal requests_sent
        requests_sent += 1
        await on_progress(job_id, requests_sent)

    try:
        limits = httpx.Limits(max_connections=10, max_keepalive_connections=5)
        async with httpx.AsyncClient(verify=False, timeout=12, limits=limits, follow_redirects=False) as client:
            for flow in flows:
                flow_id = flow.get("id", "")
                parsed = urlparse(flow.get("url", ""))
                if not parsed.scheme or not parsed.netloc:
                    continue

                # If no query params, inject seed params so bare URLs are still tested
                if not parse_qs(parsed.query):
                    seed_params = ["id", "q", "search", "url", "redirect", "file", "path", "input", "page", "next"]
                    seed_qs = urlencode({p: "test" for p in seed_params})
                    flow = {**flow, "url": f"{flow.get('url', '')}?{seed_qs}"}

                for check_name in checks:
                    runner = CHECK_RUNNERS.get(check_name)
                    if not runner:
                        continue
                    try:
                        new_findings = await runner(client, flow, _progress)
                        for f in new_findings:
                            finding_count += 1
                            await on_finding(job_id, f, flow_id)
                    except Exception as e:
                        logger.warning("active_scan check error", check=check_name, error=str(e))

    except Exception as e:
        error = str(e)
        logger.error("active_scan job failed", job_id=job_id, error=error)

    await on_done(job_id, finding_count, requests_sent, error)
