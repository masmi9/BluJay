#!/usr/bin/env python3
"""
EncryptionAtRestManager

Provides optional encryption-at-rest facilities for artifacts. When the
`cryptography` package is available, uses Fernet (AES128 + HMAC) for simple,
authenticated encryption. Otherwise, securely degrades to a no-op provider so
workflows remain functional without hard dependency.

This manager is intentionally small and explicit to keep blast radius low.
"""

from __future__ import annotations

import base64
import os
from pathlib import Path
from typing import Optional


class _NoopProvider:
    name = "noop"

    def encrypt(self, data: bytes) -> bytes:
        return data

    def decrypt(self, data: bytes) -> bytes:
        return data


class _FernetProvider:
    name = "fernet"

    def __init__(self, key_b64: Optional[str] = None) -> None:
        from cryptography.fernet import Fernet  # type: ignore

        if key_b64:
            key = key_b64.encode("utf-8")
        else:
            key = Fernet.generate_key()
        self._fernet = Fernet(key)
        self.key_b64 = key.decode("utf-8")

    def encrypt(self, data: bytes) -> bytes:
        return self._fernet.encrypt(data)

    def decrypt(self, data: bytes) -> bytes:
        return self._fernet.decrypt(data)


class EncryptionAtRestManager:
    """Facade for optional encryption-at-rest.

    Provider selection:
      - provider == 'fernet' → use cryptography.fernet (if available)
      - provider == 'noop'   → passthrough
      - provider == 'auto'   → try fernet then noop

    Key sources for fernet:
      - `key_b64` argument if provided
      - env `AODS_ENCRYPTION_KEY_B64`
      - generated ephemeral key (not persisted)
    """

    def __init__(self, provider: str = "auto", key_b64: Optional[str] = None) -> None:
        self.provider_name = "noop"
        self._provider = _NoopProvider()

        desired = (provider or "auto").strip().lower()
        key_env = key_b64 or os.getenv("AODS_ENCRYPTION_KEY_B64")

        if desired in ("fernet", "auto"):
            try:
                # Validate base64 if provided
                if key_env:
                    try:
                        base64.urlsafe_b64decode(key_env.encode("utf-8"))
                    except Exception:
                        # fall back to generated key if invalid
                        key_env = None
                self._provider = _FernetProvider(key_env)
                self.provider_name = "fernet"
                return
            except Exception:
                # cryptography not installed or other error → fall through to noop
                pass

        # Default noop
        self._provider = _NoopProvider()
        self.provider_name = "noop"

    def encrypt_bytes(self, plaintext: bytes) -> bytes:
        if not isinstance(plaintext, (bytes, bytearray)):
            raise TypeError("plaintext must be bytes-like")
        return self._provider.encrypt(bytes(plaintext))

    def decrypt_bytes(self, ciphertext: bytes) -> bytes:
        if not isinstance(ciphertext, (bytes, bytearray)):
            raise TypeError("ciphertext must be bytes-like")
        return self._provider.decrypt(bytes(ciphertext))

    def encrypt_file(self, src_path: str, dst_path: Optional[str] = None) -> str:
        src = Path(src_path)
        if not src.exists() or not src.is_file():
            raise FileNotFoundError(str(src))
        dst = Path(dst_path) if dst_path else src.with_suffix(src.suffix + ".enc")
        data = src.read_bytes()
        enc = self.encrypt_bytes(data)
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(enc)
        return str(dst)

    def decrypt_file(self, src_path: str, dst_path: Optional[str] = None) -> str:
        src = Path(src_path)
        if not src.exists() or not src.is_file():
            raise FileNotFoundError(str(src))
        if dst_path:
            dst = Path(dst_path)
        else:
            suffix = src.suffix
            dst = src.with_suffix("") if suffix == ".enc" else src.with_suffix(suffix + ".dec")
        data = src.read_bytes()
        dec = self.decrypt_bytes(data)
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(dec)
        return str(dst)
