"""
PCI host discovery — TCP-based.
Uses asyncio TCP connect so it works without root/admin on Windows.
"""
from __future__ import annotations
import asyncio
import socket
from dataclasses import dataclass, field


# Discovery probe ports — if any of these are open the host is considered live
_PROBE_PORTS = [80, 443, 22, 8080, 8443, 21, 25, 3389]
_TIMEOUT = 2.0


@dataclass
class LiveHost:
    ip: str
    hostname: str = ""
    responding_ports: list[int] = field(default_factory=list)


async def _tcp_probe(ip: str, port: int, timeout: float) -> bool:
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False


async def _reverse_dns(ip: str) -> str:
    try:
        loop = asyncio.get_event_loop()
        info = await loop.run_in_executor(
            None, lambda: socket.gethostbyaddr(ip)
        )
        return info[0]
    except Exception:
        return ""


async def discover_hosts(
    ips: list[str],
    timeout: float = _TIMEOUT,
    max_concurrency: int = 50,
) -> list[LiveHost]:
    """
    Probe each IP on common ports.  Returns only the hosts that responded.
    """
    sem = asyncio.Semaphore(max_concurrency)
    live: list[LiveHost] = []

    async def probe_ip(ip: str) -> LiveHost | None:
        async with sem:
            tasks = [_tcp_probe(ip, port, timeout) for port in _PROBE_PORTS]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            responding = [
                _PROBE_PORTS[i]
                for i, r in enumerate(results)
                if r is True
            ]
            if responding:
                hostname = await _reverse_dns(ip)
                return LiveHost(ip=ip, hostname=hostname, responding_ports=responding)
        return None

    results = await asyncio.gather(*[probe_ip(ip) for ip in ips])
    for r in results:
        if r is not None:
            live.append(r)

    return live
