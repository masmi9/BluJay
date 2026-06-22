"""
DNS subdomain brute-force with wildcard detection, NXDOMAIN short-circuit,
configurable resolvers and worker count.

Can be used as a library (brute_force_async) or as a CLI:
    python3 dnsbrute2.py wordlist.txt -z target.com sub.target.com \\
        -r 8.8.8.8 1.1.1.1 9.9.9.9 -w 400 -o results.txt
"""
import argparse
import asyncio
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path


@dataclass
class BruteResult:
    fqdn: str
    ips: list[str]


_WILDCARD_IPS: set[str] = set()


def _check_wildcard(zone: str, resolvers: list[str], timeout: float = 1.5) -> set[str]:
    try:
        import dns.resolver
        import dns.exception
    except ImportError:
        return set()

    test = f"zznonexistent99xyz123.{zone}"
    for ns in resolvers:
        try:
            r = dns.resolver.Resolver()
            r.nameservers = [ns]
            r.timeout = timeout
            r.lifetime = timeout
            answers = r.resolve(test, "A")
            return {str(a) for a in answers}
        except (Exception,):
            continue
    return set()


def _resolve(fqdn: str, resolvers: list[str], timeout: float = 1.5) -> BruteResult | None:
    try:
        import dns.resolver
        import dns.exception
    except ImportError:
        import socket
        try:
            ip = socket.gethostbyname(fqdn)
            return BruteResult(fqdn=fqdn, ips=[ip])
        except Exception:
            return None

    for ns in resolvers:
        try:
            r = dns.resolver.Resolver()
            r.nameservers = [ns]
            r.timeout = timeout
            r.lifetime = timeout
            answers = r.resolve(fqdn, "A")
            ips = sorted({str(a) for a in answers})
            return BruteResult(fqdn=fqdn, ips=ips)
        except dns.resolver.NXDOMAIN:
            return None
        except (Exception,):
            continue
    return None


async def brute_force_async(
    wordlist: list[str],
    zones: list[str],
    resolvers: list[str] | None = None,
    workers: int = 300,
    progress_cb=None,
) -> list[BruteResult]:
    """
    Async entry-point for use from the domain OSINT engine.
    progress_cb(done, total) called periodically.
    Returns list of BruteResult for all resolved FQDNs not matching a wildcard.
    """
    if resolvers is None:
        resolvers = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]

    global _WILDCARD_IPS
    _WILDCARD_IPS = set()

    for zone in zones:
        wc = _check_wildcard(zone, resolvers)
        if wc:
            _WILDCARD_IPS |= wc

    targets = [f"{w}.{z}" for z in zones for w in wordlist]
    total = len(targets)
    hits: list[BruteResult] = []
    done = 0
    lock = threading.Lock()

    loop = asyncio.get_event_loop()

    def _resolve_target(fqdn: str) -> BruteResult | None:
        return _resolve(fqdn, resolvers)

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futs = {executor.submit(_resolve_target, t): t for t in targets}
        for fut in as_completed(futs):
            result = fut.result()
            with lock:
                done += 1
                if progress_cb and done % 500 == 0:
                    asyncio.run_coroutine_threadsafe(
                        _safe_progress_cb(progress_cb, done, total),
                        loop,
                    )
            if result and not set(result.ips) <= _WILDCARD_IPS:
                hits.append(result)

    return hits


async def _safe_progress_cb(cb, done: int, total: int):
    try:
        await cb(done, total)
    except Exception:
        pass


def main():
    ap = argparse.ArgumentParser(description="DNS subdomain brute-force")
    ap.add_argument("wordlist", help="Path to wordlist file")
    ap.add_argument("-z", "--zones", nargs="+", required=True, help="Target zone(s)")
    ap.add_argument("-r", "--resolvers", nargs="+", default=["8.8.8.8", "1.1.1.1", "9.9.9.9"])
    ap.add_argument("-w", "--workers", type=int, default=300)
    ap.add_argument("-o", "--output", default=None)
    args = ap.parse_args()

    words_path = Path(args.wordlist)
    if not words_path.exists():
        print(f"[!] Wordlist not found: {args.wordlist}", file=sys.stderr)
        sys.exit(1)

    words = [
        line.strip().lower()
        for line in words_path.read_text(encoding="utf-8", errors="replace").splitlines()
        if line.strip() and not line.startswith("#")
    ]

    global _WILDCARD_IPS
    _WILDCARD_IPS = set()
    for zone in args.zones:
        wc = _check_wildcard(zone, args.resolvers)
        if wc:
            print(f"[!] Wildcard detected for {zone}: {wc}", file=sys.stderr)
            _WILDCARD_IPS |= wc
        else:
            print(f"[+] No wildcard for {zone}", file=sys.stderr)

    targets = [f"{w}.{z}" for z in args.zones for w in words]
    total = len(targets)
    print(f"[*] {total} targets, {args.workers} workers", file=sys.stderr)

    hits: list[str] = []
    done = 0
    lock = threading.Lock()

    import time
    start = time.time()
    out = open(args.output, "w") if args.output else None

    def cb(fqdn: str, ips: list[str]):
        nonlocal done
        with lock:
            done += 1
            if done % 5000 == 0:
                elapsed = time.time() - start
                print(
                    f"  [{done}/{total}] {done / max(1, elapsed):.0f}/s  hits={len(hits)}",
                    file=sys.stderr,
                )
        if ips and not set(ips) <= _WILDCARD_IPS:
            line = f"{fqdn}\t{','.join(ips)}"
            hits.append(line)
            print(line)
            if out:
                out.write(line + "\n")
                out.flush()

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futs = {executor.submit(_resolve, t, args.resolvers): t for t in targets}
        for fut in as_completed(futs):
            r = fut.result()
            if r:
                cb(r.fqdn, r.ips)
            else:
                with lock:
                    done += 1

    elapsed = time.time() - start
    print(
        f"\n[+] Done: {total} queries, {elapsed:.1f}s ({total / elapsed:.0f}/s), {len(hits)} hits",
        file=sys.stderr,
    )
    if out:
        out.close()


if __name__ == "__main__":
    main()
