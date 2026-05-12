"""
Protocol Tester — TLS/SSL analysis, subdomain enumeration, LDAP enumeration, gRPC fuzzing.

Endpoints:
  POST /protocol/tls/scan          — analyze TLS configuration and certificate
  POST /protocol/subdomain/enum    — enumerate subdomains (crt.sh + DNS brute force)
  POST /protocol/ldap/enum         — enumerate LDAP directory
  POST /protocol/grpc/reflect      — discover gRPC services via server reflection
  POST /protocol/grpc/send         — invoke a gRPC method
  POST /protocol/grpc/fuzz         — fuzz a gRPC method with payload suite
"""

import asyncio
import ipaddress
import json
import socket
import ssl
import subprocess
from datetime import datetime, timezone

import httpx
import structlog
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

logger = structlog.get_logger()
router = APIRouter()

# ── Schemas ────────────────────────────────────────────────────────────────

class TLSScanRequest(BaseModel):
    host: str
    port: int = 443
    timeout: float = 10.0

class SubdomainEnumRequest(BaseModel):
    domain: str
    wordlist: list[str] = []        # if empty, use built-in top-500
    include_crtsh: bool = True

class LDAPEnumRequest(BaseModel):
    host: str
    port: int = 389
    bind_dn: str = ""
    bind_password: str = ""
    base_dn: str = ""
    timeout: float = 10.0

class GRPCReflectRequest(BaseModel):
    host: str
    port: int = 50051
    use_tls: bool = False
    verify_tls: bool = True

class GRPCSendRequest(BaseModel):
    host: str
    port: int = 50051
    service: str
    method: str
    payload: dict = {}
    use_tls: bool = False

class GRPCFuzzRequest(BaseModel):
    host: str
    port: int = 50051
    service: str
    method: str
    field_map: dict = {}            # {"field": "type"} — tells fuzzer which fields to inject
    use_tls: bool = False


# ── TLS analysis ───────────────────────────────────────────────────────────

WEAK_CIPHERS = {
    "RC4", "DES", "3DES", "EXPORT", "NULL", "ANON", "ADH", "AECDH",
    "MD5", "PSK", "SRP",
}

DEPRECATED_PROTOS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}


def _cert_info(cert: dict) -> dict:
    subject  = dict(x[0] for x in cert.get("subject", []))
    issuer   = dict(x[0] for x in cert.get("issuer", []))
    san_list = []
    for ext_type, ext_val in cert.get("subjectAltName", []):
        if ext_type.lower() == "dns":
            san_list.append(ext_val)
    not_after  = cert.get("notAfter", "")
    not_before = cert.get("notBefore", "")
    expired, days_left = False, None
    if not_after:
        try:
            exp_dt    = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            now       = datetime.now(timezone.utc)
            expired   = exp_dt < now
            days_left = (exp_dt - now).days
        except Exception:
            pass
    cn = subject.get("commonName", "")
    return {
        "cn":         cn,
        "san":        san_list,
        "issuer":     issuer.get("organizationName") or issuer.get("commonName", ""),
        "not_before": not_before,
        "not_after":  not_after,
        "expired":    expired,
        "days_left":  days_left,
        "self_signed": subject == issuer,
    }


def _probe_tls_version(host: str, port: int, proto_ver: int, timeout: float) -> bool:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion(proto_ver)
    ctx.maximum_version = ssl.TLSVersion(proto_ver)
    ctx.check_hostname  = False
    ctx.verify_mode     = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return True
    except Exception:
        return False


@router.post("/tls/scan", summary="Analyze TLS configuration for a host")
async def tls_scan(req: TLSScanRequest):
    host, port = req.host.strip(), req.port
    loop = asyncio.get_event_loop()

    # ── Get cert ──────────────────────────────────────────────────────────
    cert_data = None
    negotiated_proto    = None
    negotiated_cipher   = None
    cert_error          = None
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        def _get_cert():
            with socket.create_connection((host, port), timeout=req.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    return ssock.getpeercert(), ssock.version(), ssock.cipher()
        cert_data, negotiated_proto, negotiated_cipher = await loop.run_in_executor(None, _get_cert)
    except Exception as e:
        cert_error = str(e)

    cert_info = _cert_info(cert_data) if cert_data else None

    # ── Version probes ────────────────────────────────────────────────────
    version_checks = []
    try:
        for label, ver_attr, secure in [
            ("TLS 1.3", "TLSv1_3", True),
            ("TLS 1.2", "TLSv1_2", True),
            ("TLS 1.1", "TLSv1_1", False),
            ("TLS 1.0", "TLSv1",   False),
        ]:
            ver_const = getattr(ssl.TLSVersion, ver_attr, None)
            if ver_const is None:
                continue
            supported = await loop.run_in_executor(None, _probe_tls_version, host, port, int(ver_const), req.timeout)
            status = "PASS" if (secure and supported) or (not secure and not supported) else ("FAIL" if not secure else "INFO")
            version_checks.append({"version": label, "supported": supported, "status": status})
    except Exception:
        pass

    # ── Cipher quality ────────────────────────────────────────────────────
    cipher_name = negotiated_cipher[0] if negotiated_cipher else None
    cipher_weak = any(w in (cipher_name or "").upper() for w in WEAK_CIPHERS) if cipher_name else False

    # ── Known vulnerability checks ────────────────────────────────────────
    vuln_checks = []

    # BEAST: TLS 1.0 + CBC cipher
    tls10_supported = any(c["version"] == "TLS 1.0" and c["supported"] for c in version_checks)
    if tls10_supported:
        vuln_checks.append({"vuln": "BEAST", "status": "WARN", "detail": "TLS 1.0 supported — BEAST attack possible with CBC ciphers"})
    else:
        vuln_checks.append({"vuln": "BEAST", "status": "PASS", "detail": "TLS 1.0 not supported"})

    # POODLE: SSLv3
    vuln_checks.append({"vuln": "POODLE", "status": "INFO", "detail": "SSLv3 probe requires legacy ssl module (Python ssl module removed SSLv3 support)"})

    # LOGJAM: weak DH
    if cipher_name and ("DHE" in cipher_name or "DH" in cipher_name):
        vuln_checks.append({"vuln": "LOGJAM", "status": "WARN", "detail": f"DH cipher in use: {cipher_name} — verify DH key length ≥ 2048"})
    else:
        vuln_checks.append({"vuln": "LOGJAM", "status": "PASS", "detail": "No DHE cipher negotiated"})

    # DROWN: SSLv2 (we can't probe easily from Python, note it)
    vuln_checks.append({"vuln": "DROWN", "status": "INFO", "detail": "Requires SSLv2 — use testssl.sh or nmap --script ssl-drown for definitive check"})

    # Cert issues
    cert_checks = []
    if cert_info:
        if cert_info["expired"]:
            cert_checks.append({"check": "Certificate Expiry", "status": "FAIL", "detail": f"Certificate EXPIRED on {cert_info['not_after']}"})
        elif cert_info["days_left"] is not None and cert_info["days_left"] < 30:
            cert_checks.append({"check": "Certificate Expiry", "status": "WARN", "detail": f"Expires in {cert_info['days_left']} days"})
        else:
            cert_checks.append({"check": "Certificate Expiry", "status": "PASS", "detail": f"{cert_info['days_left']} days remaining"})
        if cert_info["self_signed"]:
            cert_checks.append({"check": "Certificate Trust", "status": "FAIL", "detail": "Self-signed certificate — no trusted CA"})
        else:
            cert_checks.append({"check": "Certificate Trust", "status": "PASS", "detail": f"Issued by: {cert_info['issuer']}"})
    elif cert_error:
        cert_checks.append({"check": "Certificate", "status": "ERROR", "detail": cert_error})

    return {
        "host":             host,
        "port":             port,
        "negotiated_proto": negotiated_proto,
        "negotiated_cipher": cipher_name,
        "cipher_weak":      cipher_weak,
        "certificate":      cert_info,
        "version_checks":   version_checks,
        "vuln_checks":      vuln_checks,
        "cert_checks":      cert_checks,
    }


# ── Subdomain enumeration ──────────────────────────────────────────────────

TOP_500_SUBS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk", "ns2",
    "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test", "ns", "blog", "pop3",
    "dev", "www2", "admin", "forum", "news", "vpn", "ns3", "mail2", "new", "mysql", "old",
    "lists", "support", "mobile", "mx", "static", "docs", "beta", "wiki", "media", "email",
    "images", "img", "www3", "mail1", "intranet", "portal", "video", "sip", "dns2", "api",
    "cdn", "stats", "dns1", "ns4", "www1", "dns", "web", "host", "ftp2", "smtp2", "stage",
    "demo", "download", "secure", "login", "shop", "app", "store", "help", "chat", "internal",
    "owa", "exchange", "assets", "staging", "services", "cloud", "monitor", "dashboard",
    "remote", "git", "gitlab", "github", "jira", "confluence", "jenkins", "ci", "registry",
    "docker", "kubernetes", "k8s", "grafana", "prometheus", "kibana", "elastic", "redis",
    "db", "database", "mysql", "postgres", "mongo", "kafka", "rabbit", "mq",
    "backup", "archive", "files", "upload", "uploads", "cdn2", "cdn1", "preview",
    "testing", "qa", "uat", "prod", "production", "live", "dev2", "develop", "development",
]


async def _crtsh_lookup(domain: str) -> list[dict]:
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(
                "https://crt.sh/",
                params={"q": f"%.{domain}", "output": "json"},
                headers={"Accept": "application/json"},
            )
            if resp.status_code != 200:
                return []
            entries = resp.json()
            seen = set()
            results = []
            for entry in entries:
                names = entry.get("name_value", "").split("\n")
                for name in names:
                    name = name.strip().lstrip("*.")
                    if name and name.endswith(f".{domain}") and name not in seen:
                        seen.add(name)
                        results.append({"subdomain": name, "source": "crt.sh"})
            return results
    except Exception as e:
        logger.warning("crtsh_failed", error=str(e))
        return []


async def _dns_resolve(fqdn: str, timeout: float = 2.0) -> str | None:
    loop = asyncio.get_event_loop()
    try:
        result = await asyncio.wait_for(
            loop.run_in_executor(None, socket.gethostbyname, fqdn),
            timeout=timeout,
        )
        return result
    except Exception:
        return None


@router.post("/subdomain/enum", summary="Enumerate subdomains via crt.sh and DNS brute force")
async def subdomain_enum(req: SubdomainEnumRequest):
    domain = req.domain.strip().lstrip("*.")
    results: list[dict] = []

    # crt.sh
    crtsh_results = []
    if req.include_crtsh:
        crtsh_results = await _crtsh_lookup(domain)
        results.extend(crtsh_results)

    # DNS brute force
    wordlist = req.wordlist or TOP_500_SUBS
    known = {r["subdomain"] for r in results}

    sem = asyncio.Semaphore(50)
    async def _check(sub: str):
        fqdn = f"{sub}.{domain}"
        if fqdn in known:
            return
        async with sem:
            ip = await _dns_resolve(fqdn)
            if ip:
                results.append({"subdomain": fqdn, "ip": ip, "source": "dns-brute"})
                known.add(fqdn)

    await asyncio.gather(*[_check(sub) for sub in wordlist])

    # Resolve IPs for crt.sh results that don't have one
    for r in crtsh_results:
        if "ip" not in r:
            ip = await _dns_resolve(r["subdomain"])
            r["ip"] = ip

    results.sort(key=lambda r: r["subdomain"])
    return {"domain": domain, "total": len(results), "results": results}


# ── LDAP enumeration ───────────────────────────────────────────────────────

@router.post("/ldap/enum", summary="Enumerate LDAP directory")
async def ldap_enum(req: LDAPEnumRequest):
    try:
        import ldap3  # type: ignore
    except ImportError:
        raise HTTPException(503, "ldap3 not installed — pip install ldap3")

    server = ldap3.Server(req.host, port=req.port, get_info=ldap3.ALL, connect_timeout=req.timeout)

    results: dict = {
        "host":            req.host,
        "port":            req.port,
        "anonymous_bind":  False,
        "naming_contexts": [],
        "server_info":     {},
        "users":           [],
        "password_policy": {},
        "error":           None,
    }

    try:
        if req.bind_dn and req.bind_password:
            conn = ldap3.Connection(server, user=req.bind_dn, password=req.bind_password, auto_bind=True)
        else:
            conn = ldap3.Connection(server, auto_bind=True)
            results["anonymous_bind"] = True
    except Exception as e:
        results["error"] = f"Bind failed: {e}"
        return results

    # Server info
    if server.info:
        results["naming_contexts"] = list(server.info.naming_contexts or [])
        results["server_info"] = {
            "dns_host_name":   str(server.info.other.get("dnsHostName", [""])[0]),
            "domain_func_lvl": str(server.info.other.get("domainFunctionality", [""])[0]),
            "forest_func_lvl": str(server.info.other.get("forestFunctionality", [""])[0]),
        }

    base_dn = req.base_dn or (results["naming_contexts"][0] if results["naming_contexts"] else "")

    # User enumeration
    if base_dn:
        try:
            conn.search(
                base_dn,
                "(objectClass=person)",
                attributes=["sAMAccountName", "cn", "mail", "memberOf", "userAccountControl"],
                size_limit=200,
            )
            for entry in conn.entries:
                results["users"].append({
                    "dn":  entry.entry_dn,
                    "sam": str(entry.sAMAccountName) if hasattr(entry, "sAMAccountName") else "",
                    "cn":  str(entry.cn) if hasattr(entry, "cn") else "",
                    "mail": str(entry.mail) if hasattr(entry, "mail") else "",
                })
        except Exception as e:
            results["error"] = f"User enum failed: {e}"

        # Password policy
        try:
            conn.search(
                base_dn,
                "(objectClass=domain)",
                attributes=["minPwdLength", "lockoutThreshold", "pwdHistoryLength", "maxPwdAge"],
            )
            if conn.entries:
                entry = conn.entries[0]
                results["password_policy"] = {
                    "min_length":       str(entry.minPwdLength) if hasattr(entry, "minPwdLength") else "?",
                    "lockout_threshold": str(entry.lockoutThreshold) if hasattr(entry, "lockoutThreshold") else "?",
                    "history_length":   str(entry.pwdHistoryLength) if hasattr(entry, "pwdHistoryLength") else "?",
                }
        except Exception:
            pass

    conn.unbind()
    return results


# ── gRPC ───────────────────────────────────────────────────────────────────

def _grpc_channel(host: str, port: int, use_tls: bool, verify_tls: bool):
    try:
        import grpc  # type: ignore
    except ImportError:
        raise HTTPException(503, "grpcio not installed — pip install grpcio grpcio-reflection")

    addr = f"{host}:{port}"
    if use_tls:
        if verify_tls:
            credentials = grpc.ssl_channel_credentials()
        else:
            credentials = grpc.ssl_channel_credentials(root_certificates=None)
        return grpc.secure_channel(addr, credentials)
    return grpc.insecure_channel(addr)


@router.post("/grpc/reflect", summary="Discover gRPC services via server reflection")
async def grpc_reflect(req: GRPCReflectRequest):
    try:
        import grpc  # type: ignore
        from grpc_reflection.v1alpha import reflection_pb2, reflection_pb2_grpc  # type: ignore
    except ImportError:
        raise HTTPException(503, "grpcio and grpcio-reflection not installed — pip install grpcio grpcio-reflection")

    channel = _grpc_channel(req.host, req.port, req.use_tls, req.verify_tls)
    stub = reflection_pb2_grpc.ServerReflectionStub(channel)

    def _list_services():
        request = reflection_pb2.ServerReflectionRequest(list_services="")
        responses = stub.ServerReflectionInfo(iter([request]))
        services = []
        for resp in responses:
            for svc in resp.list_services_response.service:
                services.append(svc.name)
        return services

    try:
        loop = asyncio.get_event_loop()
        services = await asyncio.wait_for(loop.run_in_executor(None, _list_services), timeout=15.0)
        channel.close()
        return {"host": req.host, "port": req.port, "services": services}
    except asyncio.TimeoutError:
        raise HTTPException(504, "gRPC reflection timed out")
    except Exception as e:
        raise HTTPException(502, f"gRPC reflection failed: {e}")


@router.post("/grpc/send", summary="Invoke a gRPC method with a JSON payload")
async def grpc_send(req: GRPCSendRequest):
    try:
        import grpc  # type: ignore
        from google.protobuf import json_format, descriptor_pool, symbol_database  # type: ignore
    except ImportError:
        raise HTTPException(503, "grpcio and protobuf not installed — pip install grpcio protobuf")

    channel = _grpc_channel(req.host, req.port, req.use_tls, False)

    def _call():
        from grpc_reflection.v1alpha import reflection_pb2, reflection_pb2_grpc  # type: ignore
        from google.protobuf import descriptor_pb2  # type: ignore
        stub_ref = reflection_pb2_grpc.ServerReflectionStub(channel)
        # Get file descriptor for the service
        req_reflect = reflection_pb2.ServerReflectionRequest(file_containing_symbol=f"{req.service}.{req.method}")
        responses = list(stub_ref.ServerReflectionInfo(iter([req_reflect])))
        if not responses:
            return {"error": "Service not found via reflection"}
        # Build a raw unary call using channel.unary_unary
        import json as _json
        method_path = f"/{req.service}/{req.method}"
        raw_bytes = _json.dumps(req.payload).encode()
        # Use grpc.experimental.channel_ready_future for raw call
        method_call = channel.unary_unary(
            method_path,
            request_serializer=lambda x: x,
            response_deserializer=lambda x: x,
        )
        result = method_call(raw_bytes)
        return {"response_bytes": result.hex() if isinstance(result, bytes) else str(result)}

    try:
        loop = asyncio.get_event_loop()
        result = await asyncio.wait_for(loop.run_in_executor(None, _call), timeout=30.0)
        channel.close()
        return result
    except asyncio.TimeoutError:
        raise HTTPException(504, "gRPC call timed out")
    except Exception as e:
        raise HTTPException(502, f"gRPC call failed: {e}")


FUZZ_PAYLOADS = [
    {"name": "empty string",    "value": ""},
    {"name": "null byte",       "value": "\x00"},
    {"name": "long string",     "value": "A" * 8192},
    {"name": "sql injection",   "value": "' OR '1'='1"},
    {"name": "nosql injection", "value": '{"$gt": ""}'},
    {"name": "path traversal",  "value": "../../../../etc/passwd"},
    {"name": "ssti",            "value": "{{7*7}}"},
    {"name": "format string",   "value": "%s%s%s%s%s"},
    {"name": "unicode bidi",    "value": "‮"},
    {"name": "oversized int",   "value": 2**63 - 1},
    {"name": "negative int",    "value": -1},
    {"name": "float overflow",  "value": 1e308},
    {"name": "null json",       "value": None},
    {"name": "array",           "value": []},
    {"name": "nested object",   "value": {"a": {"b": {"c": "d"}}}},
]


@router.post("/grpc/fuzz", summary="Fuzz a gRPC method with a payload suite")
async def grpc_fuzz(req: GRPCFuzzRequest):
    channel = _grpc_channel(req.host, req.port, req.use_tls, False)
    results = []

    for fuzz in FUZZ_PAYLOADS:
        payload = dict(req.field_map)
        for field in list(payload.keys()):
            payload[field] = fuzz["value"]

        def _call(p=payload):
            import json as _json
            try:
                import grpc  # type: ignore
            except ImportError:
                raise HTTPException(503, "grpcio not installed")
            method_path = f"/{req.service}/{req.method}"
            method_call = channel.unary_unary(
                method_path,
                request_serializer=lambda x: x,
                response_deserializer=lambda x: x,
            )
            try:
                raw = _json.dumps(p).encode()
                result = method_call(raw, timeout=5)
                return {"status": "ok", "response": str(result)[:200]}
            except Exception as e:
                return {"status": "error", "error": str(e)[:200]}

        try:
            loop = asyncio.get_event_loop()
            outcome = await asyncio.wait_for(loop.run_in_executor(None, _call), timeout=10.0)
        except asyncio.TimeoutError:
            outcome = {"status": "timeout"}
        except Exception as e:
            outcome = {"status": "error", "error": str(e)}

        results.append({
            "payload_name": fuzz["name"],
            "payload":      str(fuzz["value"])[:80],
            **outcome,
        })

    channel.close()
    errors   = [r for r in results if r["status"] not in ("ok", "timeout")]
    timeouts = [r for r in results if r["status"] == "timeout"]
    return {
        "service":       req.service,
        "method":        req.method,
        "total":         len(results),
        "errors":        len(errors),
        "timeouts":      len(timeouts),
        "results":       results,
    }
