"""
PCI scope parser.
Reads YAML or JSON scope configs and resolves them to concrete scan targets.
"""
from __future__ import annotations
import ipaddress
import json
import socket
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse


# ── Config dataclasses ────────────────────────────────────────────────────────

@dataclass
class WebScopeConfig:
    payment_pages: list[str] = field(default_factory=list)
    entry_pages: list[str] = field(default_factory=list)
    include_patterns: list[str] = field(default_factory=list)
    exclude_patterns: list[str] = field(default_factory=list)
    max_depth: int = 3
    max_pages: int = 50
    file_types: list[str] = field(default_factory=lambda: [
        ".html", ".htm", ".php", ".asp", ".aspx",
    ])


@dataclass
class PortScopeConfig:
    profile: str = "pci_standard"   # pci_standard | pci_full | custom
    custom_ports: list[int] = field(default_factory=list)


@dataclass
class CheckConfig:
    host_discovery: bool = True
    port_scan: bool = True
    vulnerability: bool = True
    web_scan: bool = True
    brute_exposure: bool = True
    malware: bool = True
    tls: bool = True
    payment_flow: bool = True


@dataclass
class ResolvedTarget:
    original: str
    ips: list[str] = field(default_factory=list)
    hostname: str = ""
    seed_urls: list[str] = field(default_factory=list)

    @property
    def label(self) -> str:
        return self.hostname or self.original


@dataclass
class PciScope:
    name: str = "PCI DSS Assessment"
    description: str = ""
    assessment_type: str = "external_pci"
    raw_targets: list[dict] = field(default_factory=list)
    resolved: list[ResolvedTarget] = field(default_factory=list)
    web: WebScopeConfig = field(default_factory=WebScopeConfig)
    ports: PortScopeConfig = field(default_factory=PortScopeConfig)
    checks: CheckConfig = field(default_factory=CheckConfig)


# ── Port profiles ─────────────────────────────────────────────────────────────

PCI_STANDARD_PORTS: list[int] = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    465, 587, 993, 995, 1433, 1521, 1723, 2049, 3306, 3389,
    5432, 5900, 6379, 8080, 8443, 8888, 9200, 27017,
]

PCI_FULL_PORTS: list[int] = (
    list(range(1, 1025))
    + [1433, 1521, 1723, 2049, 3306, 3389, 5432, 5900,
       6379, 8080, 8443, 8888, 9200, 27017, 50000]
)


def get_ports_for_profile(config: PortScopeConfig) -> list[int]:
    if config.profile == "custom":
        return sorted(set(config.custom_ports))
    if config.profile == "pci_full":
        return PCI_FULL_PORTS
    return PCI_STANDARD_PORTS


# ── Parsers ───────────────────────────────────────────────────────────────────

def _load_raw(text: str) -> dict:
    """Try YAML first, fall back to JSON."""
    text = text.strip()
    try:
        import yaml
        return yaml.safe_load(text) or {}
    except Exception:
        pass
    return json.loads(text)


def _parse_web(raw: dict) -> WebScopeConfig:
    w = raw.get("web", {})
    return WebScopeConfig(
        payment_pages=w.get("payment_pages", []),
        entry_pages=w.get("entry_pages", []),
        include_patterns=w.get("include_patterns", []),
        exclude_patterns=w.get("exclude_patterns", []),
        max_depth=int(w.get("max_depth", 3)),
        max_pages=int(w.get("max_pages", 50)),
        file_types=w.get("file_types", [".html", ".htm", ".php", ".asp", ".aspx"]),
    )


def _parse_ports(raw: dict) -> PortScopeConfig:
    p = raw.get("ports", {})
    return PortScopeConfig(
        profile=p.get("profile", "pci_standard"),
        custom_ports=p.get("custom", []),
    )


def _parse_checks(raw: dict) -> CheckConfig:
    c = raw.get("checks", {})
    return CheckConfig(
        host_discovery=c.get("host_discovery", True),
        port_scan=c.get("port_scan", True),
        vulnerability=c.get("vulnerability", True),
        web_scan=c.get("web_scan", True),
        brute_exposure=c.get("brute_exposure", True),
        malware=c.get("malware", True),
        tls=c.get("tls", True),
        payment_flow=c.get("payment_flow", True),
    )


def parse_scope(text: str) -> PciScope:
    """Parse a YAML or JSON scope string into a PciScope."""
    raw = _load_raw(text)
    s = raw.get("scope", raw)   # support both { scope: {...} } and bare objects
    scope = PciScope(
        name=s.get("name", "PCI Assessment"),
        description=s.get("description", ""),
        assessment_type=s.get("scan_profile", s.get("assessment_type", "external_pci")),
        raw_targets=s.get("targets", []),
        web=_parse_web(s),
        ports=_parse_ports(s),
        checks=_parse_checks(s),
    )
    return scope


def parse_scope_file(path: str | Path) -> PciScope:
    return parse_scope(Path(path).read_text())


# ── Target resolution (sync — call from executor) ─────────────────────────────

def _resolve_domain(hostname: str) -> list[str]:
    try:
        info = socket.getaddrinfo(hostname, None)
        return list({i[4][0] for i in info})
    except OSError:
        return []


def _expand_cidr(cidr: str) -> list[str]:
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        if net.num_addresses > 1024:
            # Cap large ranges to avoid runaway scans
            hosts = list(net.hosts())[:256]
        else:
            hosts = list(net.hosts())
        return [str(h) for h in hosts]
    except ValueError:
        return []


def resolve_targets(scope: PciScope) -> None:
    """Resolve raw_targets into scope.resolved (sync — run in executor)."""
    scope.resolved = []
    for t in scope.raw_targets:
        kind = t.get("type", "").lower()
        value = t.get("value", "").strip()
        if not value:
            continue

        rt = ResolvedTarget(original=value)

        if kind == "url" or value.startswith(("http://", "https://")):
            parsed = urlparse(value if "://" in value else f"https://{value}")
            rt.hostname = parsed.hostname or value
            rt.seed_urls = [value]
            rt.ips = _resolve_domain(rt.hostname)

        elif kind == "cidr" or "/" in value:
            rt.ips = _expand_cidr(value)

        elif kind == "ip" or _is_ip(value):
            rt.ips = [value]

        else:
            # treat as domain
            rt.hostname = value
            rt.ips = _resolve_domain(value)
            rt.seed_urls = [f"https://{value}"]

        scope.resolved.append(rt)


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


# ── Scope-from-urls convenience ───────────────────────────────────────────────

def scope_from_urls(urls: list[str], scan_profile: str = "web_only") -> PciScope:
    """Build a minimal scope from a flat list of URLs (quick-scan mode)."""
    targets = [{"type": "url", "value": u} for u in urls]
    seed_urls = list(urls)
    scope = PciScope(
        name="Quick Web Scan",
        assessment_type=scan_profile,
        raw_targets=targets,
        web=WebScopeConfig(payment_pages=seed_urls),
        checks=CheckConfig(
            host_discovery=False,
            port_scan=False,
            vulnerability=False,
            brute_exposure=False,
            web_scan=True,
            malware=True,
            tls=True,
        ),
    )
    for url in urls:
        parsed = urlparse(url)
        rt = ResolvedTarget(
            original=url,
            hostname=parsed.hostname or url,
            seed_urls=[url],
        )
        scope.resolved.append(rt)
    return scope
