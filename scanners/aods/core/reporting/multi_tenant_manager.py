#!/usr/bin/env python3
"""
MultiTenantManager

Simple tenant-aware path and label utilities to support artifact separation.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

SAFE_TENANT_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


class MultiTenantManager:
    def __init__(self, base_dir: str):
        self.base_dir = Path(base_dir)

    def _sanitize(self, tenant_id: str) -> str:
        t = (tenant_id or "default").strip()
        if not SAFE_TENANT_RE.match(t):
            # Replace unsafe chars with underscores
            t = re.sub(r"[^A-Za-z0-9_.-]", "_", t)[:64]
        return t or "default"

    def artifacts_dir(self, tenant_id: Optional[str]) -> str:
        t = self._sanitize(tenant_id or "default")
        p = self.base_dir / t
        p.mkdir(parents=True, exist_ok=True)
        return str(p)

    def label(self, tenant_id: Optional[str]) -> str:
        return self._sanitize(tenant_id or "default")
