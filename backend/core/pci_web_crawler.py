"""
PCI payment-page crawler.
BFS over a seed URL set, scoped to the target domain/path.
Returns crawled pages for web checks and malware analysis.
"""
from __future__ import annotations
import asyncio
import fnmatch
import re
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse, urlunparse

import httpx

from core.pci_scope import WebScopeConfig


@dataclass
class CrawledPage:
    url: str
    status: int
    headers: dict[str, str]
    body: str
    is_payment_page: bool = False
    forms_found: int = 0
    links_found: int = 0


# Payment-page heuristics
_PAYMENT_URL_PATTERNS = re.compile(
    r'(?:payment|checkout|billing|pay|cart|purchase|order|coinrecharge|addfunds|topup)',
    re.IGNORECASE,
)
_PAYMENT_BODY_PATTERNS = re.compile(
    r'(?:card.?number|credit.?card|cardnumber|cc-number|cvv|cvc|expiry|expiration)',
    re.IGNORECASE,
)

_USER_AGENT = "BluJay-PCI-Crawler/1.0"


def _normalize_url(url: str) -> str:
    p = urlparse(url)
    return urlunparse((p.scheme, p.netloc, p.path, "", "", ""))


def _in_scope(url: str, base_hosts: set[str], scope: WebScopeConfig) -> bool:
    parsed = urlparse(url)
    if parsed.hostname not in base_hosts:
        return False

    path = parsed.path.lower()
    full = url.lower()

    # Exclude patterns take priority
    for pat in scope.exclude_patterns:
        if fnmatch.fnmatch(full, f"*{pat.lower()}*"):
            return False
        if fnmatch.fnmatch(path, f"*{pat.lower()}*"):
            return False

    # Extension filter
    for ext in [".js", ".css", ".png", ".jpg", ".gif", ".ico", ".woff",
                ".woff2", ".svg", ".map", ".txt", ".xml"]:
        if path.endswith(ext):
            return False

    # Include patterns (if specified, only match those)
    if scope.include_patterns:
        for pat in scope.include_patterns:
            if fnmatch.fnmatch(full, f"*{pat.lower()}*"):
                return True
        return False

    return True


def _extract_links(base_url: str, html: str) -> list[str]:
    links: list[str] = []
    for m in re.finditer(r'href\s*=\s*["\']([^"\'#][^"\']*)["\']', html, re.IGNORECASE):
        href = m.group(1).strip()
        if href.startswith("javascript:") or href.startswith("mailto:"):
            continue
        links.append(urljoin(base_url, href))
    for m in re.finditer(r'action\s*=\s*["\']([^"\']+)["\']', html, re.IGNORECASE):
        links.append(urljoin(base_url, m.group(1).strip()))
    return links


def _is_payment(url: str, body: str) -> bool:
    return bool(_PAYMENT_URL_PATTERNS.search(url)) or bool(_PAYMENT_BODY_PATTERNS.search(body))


async def crawl(
    seed_urls: list[str],
    scope: WebScopeConfig,
    max_depth: int | None = None,
    max_pages: int | None = None,
) -> list[CrawledPage]:
    depth_limit = max_depth or scope.max_depth
    page_limit = max_pages or scope.max_pages

    # Derive allowed hosts from seeds
    base_hosts = {urlparse(u).hostname for u in seed_urls if urlparse(u).hostname}

    visited: set[str] = set()
    queue: list[tuple[str, int]] = [(u, 0) for u in seed_urls]
    pages: list[CrawledPage] = []

    async with httpx.AsyncClient(
        verify=False,
        timeout=15,
        follow_redirects=True,
        headers={"User-Agent": _USER_AGENT},
    ) as client:
        while queue and len(pages) < page_limit:
            url, depth = queue.pop(0)
            norm = _normalize_url(url)
            if norm in visited:
                continue
            visited.add(norm)

            try:
                resp = await client.get(url)
            except Exception:
                continue

            ct = resp.headers.get("content-type", "").lower()
            if "html" not in ct and "javascript" not in ct:
                continue

            body = resp.text
            forms_found = len(re.findall(r'<form', body, re.IGNORECASE))
            links = _extract_links(url, body) if depth < depth_limit else []
            is_pay = _is_payment(url, body)

            page = CrawledPage(
                url=url,
                status=resp.status_code,
                headers=dict(resp.headers),
                body=body,
                is_payment_page=is_pay,
                forms_found=forms_found,
                links_found=len(links),
            )
            pages.append(page)

            if depth < depth_limit:
                for link in links:
                    if _in_scope(link, base_hosts, scope):
                        norm_link = _normalize_url(link)
                        if norm_link not in visited:
                            queue.append((link, depth + 1))

    return pages
