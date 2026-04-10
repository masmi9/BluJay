"""
AODS Vector DB Secret Fingerprinting
====================================

This module provides HMAC-based fingerprinting for secrets, enabling
"seen before" detection without exposing the actual secret values in
the vector database.

Security Properties:
- Fingerprints are one-way (cannot reverse to original secret)
- Per-tenant keys prevent cross-tenant correlation attacks
- Truncated output (16 chars) balances uniqueness with storage efficiency

Use Cases:
- Detect duplicate hardcoded credentials across scans
- Track secret exposure patterns without storing secrets
- Enable semantic search by secret type without revealing values
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
from typing import Any, Dict, List, Optional, Tuple

# Logging with graceful fallback
try:
    from core.logging_config import get_logger

    logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging

    logger = stdlib_logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Secret Detection Patterns
# ---------------------------------------------------------------------------

# Patterns to identify different types of secrets in code/text
SECRET_TYPE_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}", re.IGNORECASE)),
    ("aws_secret_key", re.compile(r"aws_secret_access_key\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})", re.IGNORECASE)),
    ("github_token", re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,}", re.IGNORECASE)),
    ("github_classic", re.compile(r"ghp_[A-Za-z0-9]{36,}", re.IGNORECASE)),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")),
    ("google_api_key", re.compile(r"AIza[0-9A-Za-z_-]{35}", re.IGNORECASE)),
    ("slack_token", re.compile(r"xox[baprs]-[0-9A-Za-z-]+")),
    ("stripe_key", re.compile(r"sk_live_[0-9A-Za-z]{24,}")),
    ("generic_api_key", re.compile(r"api[_-]?key\s*[:=]\s*['\"]?([A-Za-z0-9_-]{20,})['\"]?", re.IGNORECASE)),
    ("generic_password", re.compile(r"password\s*[:=]\s*['\"]?([^\s'\"]{8,})['\"]?", re.IGNORECASE)),
    ("generic_secret", re.compile(r"secret\s*[:=]\s*['\"]?([A-Za-z0-9_-]{16,})['\"]?", re.IGNORECASE)),
    ("generic_token", re.compile(r"token\s*[:=]\s*['\"]?([A-Za-z0-9_-]{20,})['\"]?", re.IGNORECASE)),
    ("bearer_token", re.compile(r"bearer\s+([A-Za-z0-9_.-]+)", re.IGNORECASE)),
    ("private_key_header", re.compile(r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----")),
    ("base64_long", re.compile(r"[A-Za-z0-9+/]{50,}={0,2}")),
]


# ---------------------------------------------------------------------------
# Per-Tenant Key Management
# ---------------------------------------------------------------------------

# In-memory cache for tenant keys (in production, use secure key store)
_TENANT_KEYS: Dict[str, bytes] = {}
_MASTER_KEY: Optional[bytes] = None


def _get_master_key() -> bytes:
    """
    Get the master key for HMAC derivation.

    In production, this should come from a secure key management system.
    For development, falls back to environment variable or generates one.
    """
    global _MASTER_KEY

    if _MASTER_KEY is not None:
        return _MASTER_KEY

    # Try environment variable first
    key_hex = os.environ.get("AODS_SECRET_HMAC_KEY")
    if key_hex:
        _MASTER_KEY = bytes.fromhex(key_hex)
        return _MASTER_KEY

    # Generate a persistent key (WARNING: in production, use proper key management)
    key_file = os.path.join(
        os.environ.get("AODS_VECTOR_DB_PATH", "data/vector_index/"),
        ".hmac_master_key",
    )

    try:
        if os.path.exists(key_file):
            with open(key_file, "rb") as f:
                _MASTER_KEY = f.read()
            logger.warning(
                "hmac_master_key_file_based",
                path=key_file,
                message=(
                    "Using file-based HMAC key. For production, set "
                    "AODS_SECRET_HMAC_KEY env var for portability and "
                    "key rotation support."
                ),
            )
        else:
            # Generate new key
            _MASTER_KEY = os.urandom(32)
            os.makedirs(os.path.dirname(key_file), exist_ok=True)
            with open(key_file, "wb") as f:
                f.write(_MASTER_KEY)
            # Set restrictive permissions
            os.chmod(key_file, 0o600)
            logger.info("hmac_master_key_generated", path=key_file)
    except (OSError, IOError) as e:
        # Fall back to in-memory generated key
        logger.warning("hmac_master_key_fallback", error=str(e))
        _MASTER_KEY = os.urandom(32)

    return _MASTER_KEY


def _get_tenant_hmac_key(tenant_id: str) -> bytes:
    """
    Get the HMAC key for a specific tenant.

    Keys are derived from the master key using HKDF-like derivation.

    Args:
        tenant_id: The tenant identifier

    Returns:
        32-byte key for the tenant
    """
    if tenant_id in _TENANT_KEYS:
        return _TENANT_KEYS[tenant_id]

    master = _get_master_key()

    # Derive tenant key using HMAC-based derivation
    derived = hmac.new(
        master,
        f"tenant:{tenant_id}".encode("utf-8"),
        hashlib.sha256,
    ).digest()

    _TENANT_KEYS[tenant_id] = derived
    return derived


# ---------------------------------------------------------------------------
# Secret Fingerprinting Functions
# ---------------------------------------------------------------------------


def compute_secret_fingerprint(secret_value: str, tenant_id: str = "default") -> str:
    """
    Compute HMAC fingerprint for 'seen before' detection without revealing secret.

    The fingerprint is:
    - Deterministic: Same secret + tenant = same fingerprint
    - One-way: Cannot reverse to original secret
    - Tenant-isolated: Different tenants get different fingerprints

    Args:
        secret_value: The secret value to fingerprint
        tenant_id: Tenant ID for per-tenant key isolation

    Returns:
        HMAC fingerprint (truncated to 16 hex characters)

    Examples:
        >>> fp1 = compute_secret_fingerprint("my_api_key_123", "tenant_a")
        >>> fp2 = compute_secret_fingerprint("my_api_key_123", "tenant_a")
        >>> fp1 == fp2  # Same secret, same tenant
        True
        >>> fp3 = compute_secret_fingerprint("my_api_key_123", "tenant_b")
        >>> fp1 == fp3  # Same secret, different tenant
        False
    """
    tenant_key = _get_tenant_hmac_key(tenant_id)

    fingerprint = hmac.new(
        tenant_key,
        secret_value.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    # Truncate to 16 chars for storage efficiency while maintaining uniqueness
    return fingerprint[:16]


def detect_secret_type(text: str) -> Optional[str]:
    """
    Detect the type of secret in a text string.

    Args:
        text: Text potentially containing a secret

    Returns:
        Secret type identifier (e.g., "aws_access_key") or None
    """
    for secret_type, pattern in SECRET_TYPE_PATTERNS:
        if pattern.search(text):
            return secret_type
    return None


def extract_secrets(text: str) -> List[Tuple[str, str, str]]:
    """
    Extract secrets from text with their types and values.

    Args:
        text: Text to scan for secrets

    Returns:
        List of tuples: (secret_type, matched_text, extracted_value)
    """
    results = []

    for secret_type, pattern in SECRET_TYPE_PATTERNS:
        for match in pattern.finditer(text):
            matched_text = match.group(0)

            # Try to extract the actual secret value (group 1 if available)
            if match.lastindex and match.lastindex >= 1:
                value = match.group(1)
            else:
                value = matched_text

            results.append((secret_type, matched_text, value))

    return results


def fingerprint_finding_secrets(
    finding: Dict[str, Any],
    tenant_id: str = "default",
) -> Dict[str, Any]:
    """
    Extract and fingerprint secrets from a finding.

    This adds secret metadata to the finding without including raw values.

    Args:
        finding: The finding dict
        tenant_id: Tenant ID for isolation

    Returns:
        Dict with secret metadata:
        - secret_types: List of detected secret types
        - secret_fingerprints: List of fingerprints
        - secret_count: Number of secrets found
    """
    # Scan relevant fields for secrets
    fields_to_scan = [
        finding.get("description", ""),
        finding.get("evidence", {}).get("code_snippet", "") if isinstance(finding.get("evidence"), dict) else "",
        finding.get("recommendation", ""),
    ]

    all_text = "\n".join(str(f) for f in fields_to_scan if f)

    secrets = extract_secrets(all_text)

    if not secrets:
        return {
            "secret_types": [],
            "secret_fingerprints": [],
            "secret_count": 0,
        }

    secret_types = []
    fingerprints = []

    for secret_type, _, value in secrets:
        secret_types.append(secret_type)
        fingerprints.append(compute_secret_fingerprint(value, tenant_id))

    # Deduplicate while preserving order
    seen_fps = set()
    unique_types = []
    unique_fps = []

    for st, fp in zip(secret_types, fingerprints):
        if fp not in seen_fps:
            seen_fps.add(fp)
            unique_types.append(st)
            unique_fps.append(fp)

    return {
        "secret_types": unique_types,
        "secret_fingerprints": unique_fps,
        "secret_count": len(unique_fps),
    }


def find_duplicate_secrets(
    fingerprints: List[str],
    known_fingerprints: Dict[str, List[str]],
) -> Dict[str, List[str]]:
    """
    Find which fingerprints have been seen before.

    Args:
        fingerprints: List of fingerprints from new finding
        known_fingerprints: Dict mapping fingerprint -> list of scan_ids

    Returns:
        Dict mapping fingerprint -> list of scan_ids where it was seen
    """
    duplicates = {}

    for fp in fingerprints:
        if fp in known_fingerprints:
            duplicates[fp] = known_fingerprints[fp]

    return duplicates
