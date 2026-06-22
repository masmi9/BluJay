"""
Full passive + active domain OSINT engine.

Sources:
  - DNS baseline: SOA, NS, A, MX, TXT via dnspython (falls back to socket)
  - Zone transfer attempt (AXFR)
  - crt.sh certificate transparency with sub-zone recursion
  - Passive DNS: HackerTarget, AlienVault OTX, Wayback CDX, URLScan
  - Shodan InternetDB (no API key required)
  - RDAP IP intel (ASN, org, country)
  - ExternalDNS TXT extraction (K8s namespace/ingress/owner intel)
"""
import asyncio
import re
import socket
from dataclasses import asdict, dataclass, field
from datetime import datetime
from urllib.parse import urlparse

import httpx
import structlog

logger = structlog.get_logger()

_UA = "BluJay-OSINT/1.0"


# ── Data models ───────────────────────────────────────────────────────────────

@dataclass
class OsintFinding:
    type: str        # dns | subdomain | cert | passive_dns | shodan | k8s | ip_intel
    host: str
    source: str
    detail: str
    severity: str = "info"
    ip: str | None = None
    metadata: dict = field(default_factory=dict)


@dataclass
class OsintResult:
    target: str
    started_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    finished_at: str | None = None

    dns_records: dict[str, list[str]] = field(default_factory=dict)
    zone_transfer: str = "not_attempted"   # not_attempted | refused | success | error

    subdomains: list[str] = field(default_factory=list)
    resolved_hosts: dict[str, str] = field(default_factory=dict)   # host → ip

    cert_history: list[dict] = field(default_factory=list)
    ip_intel: dict[str, dict] = field(default_factory=dict)        # ip → rdap data
    shodan: dict[str, dict] = field(default_factory=dict)          # ip → internetdb data
    external_dns: list[dict] = field(default_factory=list)         # k8s ingress records

    findings: list[OsintFinding] = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict:
        d = asdict(self)
        d["findings"] = [asdict(f) for f in self.findings]
        return d


# ── DNS baseline ──────────────────────────────────────────────────────────────

def _dns_query(domain: str, record_type: str, nameserver: str | None = None) -> list[str]:
    try:
        import dns.resolver
        import dns.exception
        r = dns.resolver.Resolver()
        if nameserver:
            r.nameservers = [nameserver]
        answers = r.resolve(domain, record_type)
        return [str(a) for a in answers]
    except ImportError:
        pass
    except Exception:
        return []

    # fallback: stdlib socket for A records only
    if record_type == "A":
        try:
            infos = socket.getaddrinfo(domain, None, socket.AF_INET)
            return list({info[4][0] for info in infos})
        except Exception:
            return []
    return []


def _attempt_zone_transfer(domain: str, nameserver: str) -> str:
    try:
        import dns.query
        import dns.zone
        import dns.exception
        ns_ip = socket.gethostbyname(nameserver)
        zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=5))
        names = [str(n) for n in zone.nodes.keys()]
        return f"SUCCESS: {len(names)} records — " + ", ".join(names[:10])
    except ImportError:
        return "skipped (dnspython not installed)"
    except Exception as e:
        return f"refused: {e}"


async def _dns_baseline(domain: str) -> tuple[dict[str, list[str]], str]:
    loop = asyncio.get_event_loop()
    records: dict[str, list[str]] = {}

    for rtype in ("SOA", "NS", "A", "MX", "TXT"):
        vals = await loop.run_in_executor(None, _dns_query, domain, rtype, None)
        if vals:
            records[rtype] = vals

    zone_result = "not_attempted"
    ns_list = records.get("NS", [])
    if ns_list:
        ns = ns_list[0].rstrip(".")
        zone_result = await loop.run_in_executor(None, _attempt_zone_transfer, domain, ns)

    return records, zone_result


# ── crt.sh certificate transparency ──────────────────────────────────────────

async def _crtsh_query(query: str, client: httpx.AsyncClient) -> list[dict]:
    try:
        r = await client.get(
            f"https://crt.sh/?q={query}&output=json",
            timeout=20.0,
            headers={"User-Agent": _UA},
        )
        if r.status_code == 200:
            return r.json()
    except Exception as e:
        logger.warning("crt.sh query failed", query=query, error=str(e))
    return []


async def _run_crtsh(domain: str, client: httpx.AsyncClient) -> tuple[list[str], list[dict]]:
    """Query crt.sh for root zone AND any discovered sub-zone apexes."""
    entries = await _crtsh_query(f"%.{domain}", client)

    names: set[str] = set()
    sub_zones: set[str] = set()

    for entry in entries:
        for name in entry.get("name_value", "").split("\n"):
            name = name.strip().lower().lstrip("*.")
            if not name or not name.endswith(domain):
                continue
            names.add(name)
            # Detect sub-zone apexes (3+ label parts)
            parts = name.split(".")
            domain_parts = domain.split(".")
            extra = parts[: len(parts) - len(domain_parts)]
            if len(extra) >= 2:
                apex = ".".join(extra[-1:]) + "." + domain
                sub_zones.add(apex)

    # Re-query for each sub-zone apex (crt.sh %.domain only matches one level deep)
    for apex in list(sub_zones)[:5]:
        sub_entries = await _crtsh_query(apex, client)
        for entry in sub_entries:
            for name in entry.get("name_value", "").split("\n"):
                name = name.strip().lower().lstrip("*.")
                if name:
                    names.add(name)

    # Collect cert history
    history: list[dict] = []
    seen: set[str] = set()
    for e in entries[:50]:
        key = e.get("id", "")
        if key in seen:
            continue
        seen.add(key)
        history.append({
            "id": e.get("id"),
            "logged_at": e.get("entry_timestamp", ""),
            "not_before": e.get("not_before", ""),
            "not_after": e.get("not_after", ""),
            "name_value": e.get("name_value", ""),
            "issuer": e.get("issuer_name", ""),
        })

    subdomains = sorted(n for n in names if n != domain and n.endswith(domain))
    return subdomains, history


# ── Passive DNS sources ───────────────────────────────────────────────────────

async def _hackertarget(domain: str, client: httpx.AsyncClient) -> list[str]:
    try:
        r = await client.get(
            f"https://api.hackertarget.com/hostsearch/?q={domain}",
            timeout=15.0,
            headers={"User-Agent": _UA},
        )
        if r.status_code == 200:
            hosts = []
            for line in r.text.splitlines():
                parts = line.split(",")
                if parts and parts[0].endswith(domain):
                    hosts.append(parts[0].strip())
            return hosts
    except Exception as e:
        logger.warning("HackerTarget failed", domain=domain, error=str(e))
    return []


async def _otx(domain: str, client: httpx.AsyncClient) -> list[str]:
    try:
        r = await client.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
            timeout=15.0,
            headers={"User-Agent": _UA},
        )
        if r.status_code == 200:
            data = r.json()
            return [e.get("hostname", "") for e in data.get("passive_dns", []) if e.get("hostname", "").endswith(domain)]
    except Exception as e:
        logger.warning("OTX failed", domain=domain, error=str(e))
    return []


async def _wayback(domain: str, client: httpx.AsyncClient) -> list[str]:
    try:
        r = await client.get(
            f"http://web.archive.org/cdx/search/cdx?url=*.{domain}&output=json&fl=original&collapse=urlkey&limit=200",
            timeout=20.0,
            headers={"User-Agent": _UA},
        )
        if r.status_code == 200:
            data = r.json()
            hosts: set[str] = set()
            for item in data[1:]:
                h = urlparse(item[0]).netloc if item else ""
                if h and h.endswith(domain):
                    hosts.add(h.lower())
            return list(hosts)
    except Exception as e:
        logger.warning("Wayback CDX failed", domain=domain, error=str(e))
    return []


async def _urlscan(domain: str, client: httpx.AsyncClient) -> list[str]:
    try:
        r = await client.get(
            f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=100",
            timeout=15.0,
            headers={"User-Agent": _UA},
        )
        if r.status_code == 200:
            data = r.json()
            return [
                res["page"].get("domain", "")
                for res in data.get("results", [])
                if res.get("page", {}).get("domain", "").endswith(domain)
            ]
    except Exception as e:
        logger.warning("URLScan failed", domain=domain, error=str(e))
    return []


async def _passive_dns(domain: str, client: httpx.AsyncClient) -> list[str]:
    results = await asyncio.gather(
        _hackertarget(domain, client),
        _otx(domain, client),
        _wayback(domain, client),
        _urlscan(domain, client),
        return_exceptions=True,
    )
    merged: set[str] = set()
    for r in results:
        if isinstance(r, list):
            for h in r:
                if h and h.endswith(domain) and h != domain:
                    merged.add(h.lower().strip("."))
    return sorted(merged)


# ── Host resolution ───────────────────────────────────────────────────────────

def _resolve_host(host: str) -> str | None:
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None


async def _resolve_all(hosts: list[str]) -> dict[str, str]:
    loop = asyncio.get_event_loop()
    tasks = [loop.run_in_executor(None, _resolve_host, h) for h in hosts[:100]]
    ips = await asyncio.gather(*tasks)
    return {h: ip for h, ip in zip(hosts[:100], ips) if ip}


# ── Shodan InternetDB ─────────────────────────────────────────────────────────

async def _shodan_internetdb(ips: list[str], client: httpx.AsyncClient) -> dict[str, dict]:
    sem = asyncio.Semaphore(5)
    results: dict[str, dict] = {}

    async def _fetch(ip: str):
        async with sem:
            try:
                r = await client.get(f"https://internetdb.shodan.io/{ip}", timeout=8.0, headers={"User-Agent": _UA})
                if r.status_code == 200:
                    results[ip] = r.json()
            except Exception:
                pass

    await asyncio.gather(*[_fetch(ip) for ip in ips])
    return results


# ── RDAP IP intel ─────────────────────────────────────────────────────────────

async def _rdap_ip(ips: list[str], client: httpx.AsyncClient) -> dict[str, dict]:
    sem = asyncio.Semaphore(5)
    results: dict[str, dict] = {}

    async def _fetch(ip: str):
        async with sem:
            try:
                r = await client.get(
                    f"https://rdap.arin.net/registry/ip/{ip}",
                    timeout=8.0,
                    headers={"User-Agent": _UA},
                    follow_redirects=True,
                )
                if r.status_code == 200:
                    data = r.json()
                    results[ip] = {
                        "name": data.get("name", ""),
                        "country": data.get("country", ""),
                        "type": data.get("type", ""),
                        "handle": data.get("handle", ""),
                        "start_address": data.get("startAddress", ""),
                        "end_address": data.get("endAddress", ""),
                    }
            except Exception:
                pass

    await asyncio.gather(*[_fetch(ip) for ip in ips])
    return results


# ── ExternalDNS TXT extraction ────────────────────────────────────────────────

_EXT_DNS_RE = re.compile(
    r"heritage=external-dns"
    r"(?:,external-dns/owner=(?P<owner>[^,\s]+))?"
    r"(?:,external-dns/resource=ingress/(?P<namespace>[^/]+)/(?P<ingress>[^\s\"]+))?",
    re.IGNORECASE,
)


async def _external_dns_txt(hosts: list[str]) -> list[dict]:
    loop = asyncio.get_event_loop()
    records: list[dict] = []

    def _query_txt(host: str) -> list[str]:
        return _dns_query(host, "TXT")

    tasks = [loop.run_in_executor(None, _query_txt, h) for h in hosts[:50]]
    results = await asyncio.gather(*tasks)

    for host, txts in zip(hosts[:50], results):
        for txt in txts:
            m = _EXT_DNS_RE.search(txt)
            if m:
                records.append({
                    "host": host,
                    "txt": txt,
                    "owner": m.group("owner") or "",
                    "namespace": m.group("namespace") or "",
                    "ingress": m.group("ingress") or "",
                })
    return records


# ── Main orchestrator ─────────────────────────────────────────────────────────

async def run_domain_osint(
    target: str,
    dns_baseline: bool = True,
    crtsh: bool = True,
    passive_dns: bool = True,
    shodan: bool = True,
    external_dns_txt: bool = True,
) -> OsintResult:
    result = OsintResult(target=target)

    domain = re.sub(r"https?://", "", target).split("/")[0].split(":")[0].lower()

    try:
        async with httpx.AsyncClient(verify=False, timeout=20.0) as client:

            # DNS baseline
            if dns_baseline:
                logger.info("osint: dns baseline", domain=domain)
                result.dns_records, result.zone_transfer = await _dns_baseline(domain)
                for rtype, vals in result.dns_records.items():
                    for val in vals:
                        result.findings.append(OsintFinding(
                            type="dns", host=domain, source="dns_baseline",
                            detail=f"{rtype} {val}", severity="info",
                        ))
                if "success" in result.zone_transfer.lower():
                    result.findings.append(OsintFinding(
                        type="dns", host=domain, source="zone_transfer",
                        detail=result.zone_transfer, severity="high",
                        metadata={"title": "Zone Transfer Enabled"},
                    ))

            # crt.sh
            subdomains_crt: list[str] = []
            if crtsh:
                logger.info("osint: crt.sh lookup", domain=domain)
                subdomains_crt, result.cert_history = await _run_crtsh(domain, client)
                for sub in subdomains_crt:
                    result.findings.append(OsintFinding(
                        type="subdomain", host=sub, source="crtsh",
                        detail="Certificate transparency record", severity="info",
                    ))

            # Passive DNS
            subdomains_passive: list[str] = []
            if passive_dns:
                logger.info("osint: passive DNS sources", domain=domain)
                subdomains_passive = await _passive_dns(domain, client)
                for sub in subdomains_passive:
                    result.findings.append(OsintFinding(
                        type="subdomain", host=sub, source="passive_dns",
                        detail="Passive DNS record", severity="info",
                    ))

            # Merge and deduplicate subdomains
            all_subs = sorted(set(subdomains_crt + subdomains_passive))
            result.subdomains = all_subs

            # Resolve hosts
            logger.info("osint: resolving hosts", count=len(all_subs))
            result.resolved_hosts = await _resolve_all(all_subs)
            for host, ip in result.resolved_hosts.items():
                result.findings.append(OsintFinding(
                    type="dns", host=host, source="resolution",
                    detail=f"Resolves to {ip}", severity="info", ip=ip,
                ))

            unique_ips = list(set(result.resolved_hosts.values()))

            # Shodan InternetDB
            if shodan and unique_ips:
                logger.info("osint: shodan internetdb", ips=len(unique_ips))
                result.shodan = await _shodan_internetdb(unique_ips, client)
                for ip, data in result.shodan.items():
                    ports = data.get("ports", [])
                    vulns = data.get("vulns", [])
                    sev = "critical" if vulns else ("medium" if ports else "info")
                    detail = f"Ports: {ports}"
                    if vulns:
                        detail += f" | CVEs: {vulns[:3]}"
                    result.findings.append(OsintFinding(
                        type="shodan", host=ip, source="shodan_internetdb",
                        detail=detail, severity=sev, ip=ip,
                        metadata={"ports": ports, "vulns": vulns, "hostnames": data.get("hostnames", [])},
                    ))

            # RDAP IP intel
            if unique_ips:
                logger.info("osint: rdap ip intel", ips=len(unique_ips))
                result.ip_intel = await _rdap_ip(unique_ips, client)

            # ExternalDNS TXT
            if external_dns_txt and all_subs:
                logger.info("osint: external-dns txt extraction", count=len(all_subs))
                result.external_dns = await _external_dns_txt(all_subs)
                for rec in result.external_dns:
                    sev = "low" if rec.get("owner") == "my-identifier" else "info"
                    result.findings.append(OsintFinding(
                        type="k8s", host=rec["host"], source="external_dns_txt",
                        detail=f"K8s ingress: {rec.get('namespace','?')}/{rec.get('ingress','?')} owner={rec.get('owner','?')}",
                        severity=sev, metadata=rec,
                    ))

    except Exception as e:
        logger.error("osint: engine error", error=str(e))
        result.error = str(e)

    result.finished_at = datetime.utcnow().isoformat()
    return result
