"""
Passive recon engine:
  - Subdomain enumeration via crt.sh (certificate transparency)
  - DNS resolution of discovered hosts
  - Cloud storage bucket enumeration (S3, GCS, Azure Blob)
"""
import asyncio
import re
import socket
from dataclasses import dataclass, field

import httpx
import structlog

logger = structlog.get_logger()

# Cloud bucket URL templates: {name} = derived app name
_S3_TEMPLATES = [
    "https://{name}.s3.amazonaws.com",
    "https://{name}-prod.s3.amazonaws.com",
    "https://{name}-staging.s3.amazonaws.com",
    "https://{name}-dev.s3.amazonaws.com",
    "https://{name}-backup.s3.amazonaws.com",
    "https://{name}-assets.s3.amazonaws.com",
    "https://{name}-static.s3.amazonaws.com",
    "https://{name}-public.s3.amazonaws.com",
    "https://{name}-media.s3.amazonaws.com",
    "https://{name}-data.s3.amazonaws.com",
    "https://s3.amazonaws.com/{name}",
    "https://s3.amazonaws.com/{name}-prod",
    "https://s3.amazonaws.com/{name}-backup",
]

_GCS_TEMPLATES = [
    "https://storage.googleapis.com/{name}",
    "https://storage.googleapis.com/{name}-prod",
    "https://storage.googleapis.com/{name}-backup",
    "https://{name}.storage.googleapis.com",
]

_AZURE_TEMPLATES = [
    "https://{name}.blob.core.windows.net",
    "https://{name}prod.blob.core.windows.net",
    "https://{name}backup.blob.core.windows.net",
    "https://{name}static.blob.core.windows.net",
]


@dataclass
class ReconFinding:
    type: str          # "subdomain" | "bucket" | "dns"
    host: str
    detail: str
    severity: str = "info"
    resolved_ip: str | None = None
    status_code: int | None = None


@dataclass
class ReconResult:
    target: str
    subdomains: list[str] = field(default_factory=list)
    resolved_hosts: list[dict] = field(default_factory=list)
    open_buckets: list[dict] = field(default_factory=list)
    findings: list[ReconFinding] = field(default_factory=list)
    error: str | None = None


def _derive_bucket_names(target: str) -> list[str]:
    # From a domain or package name, derive bucket name candidates
    cleaned = re.sub(r"[^a-z0-9\-]", "-", target.lower().replace(".", "-"))
    cleaned = re.sub(r"-+", "-", cleaned).strip("-")
    # Also try just the company portion (first segment)
    parts = cleaned.split("-")
    candidates = list({cleaned, parts[0], "-".join(parts[:2])})
    return [c for c in candidates if len(c) >= 3]


async def _crtsh_subdomains(domain: str, client: httpx.AsyncClient) -> list[str]:
    try:
        r = await client.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=20.0,
            headers={"User-Agent": "BluJay-Recon/1.0"},
        )
        if r.status_code != 200:
            return []
        data = r.json()
        names: set[str] = set()
        for entry in data:
            for name in entry.get("name_value", "").split("\n"):
                name = name.strip().lower().lstrip("*.")
                if name and name.endswith(domain) and name != domain:
                    names.add(name)
        return sorted(names)
    except Exception as e:
        logger.warning("crt.sh lookup failed", domain=domain, error=str(e))
        return []


def _resolve(host: str) -> str | None:
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None


async def _check_bucket(url: str, client: httpx.AsyncClient) -> dict | None:
    try:
        r = await client.get(url, timeout=8.0, follow_redirects=False)
        if r.status_code in (200, 403):
            accessible = r.status_code == 200
            listing = "<ListBucketResult" in r.text or "<Contents>" in r.text
            return {
                "url": url,
                "status": r.status_code,
                "accessible": accessible,
                "listing_enabled": listing,
                "snippet": r.text[:200],
            }
    except Exception:
        pass
    return None


async def run_recon(
    target: str,
    package_name: str | None = None,
    check_subdomains: bool = True,
    check_buckets: bool = True,
    resolve_hosts: bool = True,
) -> ReconResult:
    result = ReconResult(target=target)

    # Derive the apex domain from target (strip scheme / path)
    domain = re.sub(r"https?://", "", target).split("/")[0].split(":")[0]
    bucket_seed = package_name or domain

    async with httpx.AsyncClient(verify=False, timeout=15.0) as client:

        # ── Subdomain enumeration ─────────────────────────────────────────────
        if check_subdomains:
            logger.info("recon: crt.sh lookup", domain=domain)
            subdomains = await _crtsh_subdomains(domain, client)
            result.subdomains = subdomains

            if resolve_hosts:
                resolve_tasks = [
                    asyncio.get_event_loop().run_in_executor(None, _resolve, sub)
                    for sub in subdomains[:50]
                ]
                ips = await asyncio.gather(*resolve_tasks)
                for sub, ip in zip(subdomains[:50], ips):
                    if ip:
                        result.resolved_hosts.append({"host": sub, "ip": ip})
                        result.findings.append(ReconFinding(
                            type="subdomain",
                            host=sub,
                            detail=f"Resolves to {ip}",
                            severity="info",
                            resolved_ip=ip,
                        ))

        # ── Cloud bucket enumeration ──────────────────────────────────────────
        if check_buckets:
            bucket_names = _derive_bucket_names(bucket_seed)
            bucket_urls = []
            for name in bucket_names:
                bucket_urls += [t.format(name=name) for t in _S3_TEMPLATES]
                bucket_urls += [t.format(name=name) for t in _GCS_TEMPLATES]
                bucket_urls += [t.format(name=name) for t in _AZURE_TEMPLATES]

            logger.info("recon: checking buckets", count=len(bucket_urls))
            sem = asyncio.Semaphore(10)

            async def _checked(url: str):
                async with sem:
                    return await _check_bucket(url, client)

            bucket_results = await asyncio.gather(*[_checked(u) for u in bucket_urls])
            for b in bucket_results:
                if b:
                    result.open_buckets.append(b)
                    sev = "critical" if b["listing_enabled"] else ("high" if b["accessible"] else "medium")
                    result.findings.append(ReconFinding(
                        type="bucket",
                        host=b["url"],
                        detail=(
                            "Bucket listing enabled — contents publicly enumerable"
                            if b["listing_enabled"]
                            else ("Bucket publicly accessible (no listing)" if b["accessible"]
                                  else "Bucket exists but returns 403 (private but discoverable)")
                        ),
                        severity=sev,
                        status_code=b["status"],
                    ))

    return result
