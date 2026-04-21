"""
TLS auditor — probes hosts for protocol support, weak ciphers, cert validity,
and HSTS. Uses Python ssl stdlib so no extra deps are required.
"""
import asyncio
import socket
import ssl
from datetime import datetime, timezone
from typing import Any

import structlog

logger = structlog.get_logger()

WEAK_CIPHERS = {
    "RC4", "DES", "3DES", "NULL", "EXPORT", "anon",
    "RC4-MD5", "RC4-SHA", "DES-CBC-SHA", "DES-CBC3-SHA",
    "EXP-", "ADH-", "AECDH-",
}

# (ssl.TLSVersion, label)
_TLS_VERSIONS = [
    (ssl.TLSVersion.TLSv1,   "tls10"),
    (ssl.TLSVersion.TLSv1_1, "tls11"),
    (ssl.TLSVersion.TLSv1_2, "tls12"),
    (ssl.TLSVersion.TLSv1_3, "tls13"),
]


def _probe_version(host: str, port: int, version: ssl.TLSVersion) -> bool:
    """Return True if the host accepts connections at exactly this TLS version."""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = version
        ctx.maximum_version = version
        with socket.create_connection((host, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return True
    except Exception:
        return False


def _get_cert_info(host: str, port: int) -> dict:
    """Connect with TLS 1.2/1.3 and extract cert details."""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                der = ssock.getpeercert(binary_form=True)
                cipher = ssock.cipher()

        if not der:
            return {}

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes

        cert = x509.load_der_x509_certificate(der)
        subject = cert.subject.rfc4514_string()
        issuer = cert.issuer.rfc4514_string()
        expiry = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after.replace(tzinfo=timezone.utc)
        self_signed = subject == issuer

        return {
            "cert_subject": subject[:500],
            "cert_issuer": issuer[:500],
            "cert_expiry": expiry.isoformat(),
            "cert_self_signed": self_signed,
            "negotiated_cipher": cipher[0] if cipher else None,
        }
    except Exception as exc:
        logger.debug("cert_info failed", host=host, error=str(exc))
        return {}


def _check_hsts(host: str, port: int) -> bool:
    """Return True if the server sends Strict-Transport-Security header."""
    try:
        import http.client
        conn = http.client.HTTPSConnection(host, port, timeout=8,
                                           context=ssl._create_unverified_context())
        conn.request("HEAD", "/")
        resp = conn.getresponse()
        return "strict-transport-security" in {h.lower() for h, _ in resp.getheaders()}
    except Exception:
        return False


def _detect_weak_ciphers(host: str, port: int) -> list[str]:
    """Try to negotiate known-weak cipher suites; return those that succeed."""
    found = []
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_ciphers("ALL:@SECLEVEL=0")
        with socket.create_connection((host, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                c = ssock.cipher()
                if c:
                    name = c[0]
                    if any(w in name.upper() for w in WEAK_CIPHERS):
                        found.append(name)
    except Exception:
        pass
    return found


def audit_host(host: str, port: int = 443) -> dict[str, Any]:
    """Synchronous full audit of one host. Run in executor for async use."""
    result: dict[str, Any] = {
        "host": host,
        "port": port,
        "status": "ok",
        "error": None,
        "tls10_enabled": False,
        "tls11_enabled": False,
        "tls12_enabled": False,
        "tls13_enabled": False,
        "hsts_present": False,
        "weak_ciphers": [],
        "findings_json": [],
        "cert_subject": None,
        "cert_issuer": None,
        "cert_expiry": None,
        "cert_self_signed": None,
    }

    try:
        # Protocol versions
        result["tls10_enabled"] = _probe_version(host, port, ssl.TLSVersion.TLSv1)
        result["tls11_enabled"] = _probe_version(host, port, ssl.TLSVersion.TLSv1_1)
        result["tls12_enabled"] = _probe_version(host, port, ssl.TLSVersion.TLSv1_2)
        result["tls13_enabled"] = _probe_version(host, port, ssl.TLSVersion.TLSv1_3)

        # Cert info
        result.update(_get_cert_info(host, port))

        # HSTS
        result["hsts_present"] = _check_hsts(host, port)

        # Weak ciphers
        result["weak_ciphers"] = _detect_weak_ciphers(host, port)

        # Build findings
        findings = []
        if result["tls10_enabled"]:
            findings.append({"severity": "high", "title": "TLS 1.0 enabled (deprecated)"})
        if result["tls11_enabled"]:
            findings.append({"severity": "medium", "title": "TLS 1.1 enabled (deprecated)"})
        if not result["tls12_enabled"] and not result["tls13_enabled"]:
            findings.append({"severity": "critical", "title": "No modern TLS (1.2/1.3) support"})
        if result["cert_self_signed"]:
            findings.append({"severity": "high", "title": "Self-signed certificate"})
        if result["cert_expiry"]:
            expiry = datetime.fromisoformat(result["cert_expiry"])
            now = datetime.now(timezone.utc)
            if expiry < now:
                findings.append({"severity": "critical", "title": "Certificate has expired"})
            elif (expiry - now).days < 30:
                days = (expiry - now).days
                findings.append({"severity": "medium", "title": f"Certificate expires in {days} days"})
        if not result["hsts_present"]:
            findings.append({"severity": "medium", "title": "HSTS header not present"})
        for c in result["weak_ciphers"]:
            findings.append({"severity": "high", "title": f"Weak cipher negotiated: {c}"})

        result["findings_json"] = findings

    except Exception as exc:
        result["status"] = "error"
        result["error"] = str(exc)

    return result


async def extract_hosts_from_session(session_id: int, db) -> list[tuple[str, int]]:
    """Return unique (host, port) pairs from proxy flows for the session."""
    from sqlalchemy import select, distinct
    from models.session import ProxyFlow

    result = await db.execute(
        select(distinct(ProxyFlow.host))
        .where(ProxyFlow.session_id == session_id)
        .where(ProxyFlow.tls == True)  # noqa: E712
    )
    hosts = result.scalars().all()
    # Default port 443 for HTTPS
    return [(h, 443) for h in hosts if h]
