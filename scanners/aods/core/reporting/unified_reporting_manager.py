#!/usr/bin/env python3
"""
Unified Reporting Manager (Schema v1)

Provides simple schema validation and export helpers for AODS reports.
Includes a basic artifact retention manager for housekeeping.
"""

from __future__ import annotations

import json
import os
import shutil
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Tuple

from .encryption_at_rest_manager import EncryptionAtRestManager
from .multi_tenant_manager import MultiTenantManager

SCHEMA_VERSION = "1.0"


class ReportValidationError(ValueError):
    pass


@dataclass
class ValidationResult:
    valid: bool
    errors: List[str]


class UnifiedReportingManager:
    """Validate and export reports conforming to schema v1."""

    REQUIRED_TOP_LEVEL_KEYS = {"metadata", "findings"}
    REQUIRED_METADATA_KEYS = {"schema_version"}
    REQUIRED_FINDING_KEYS = {"title", "severity"}

    def __init__(self, schema_version: str = SCHEMA_VERSION, base_dir: str = "reports"):
        self.schema_version = schema_version
        # Tenant-aware base directory (default 'default' tenant)
        tenant_id = os.getenv("AODS_TENANT_ID", "default")
        self._tenant_mgr = MultiTenantManager(base_dir)
        self.report_base_dir = Path(self._tenant_mgr.artifacts_dir(tenant_id))

        # Optional encryption-at-rest (default disabled via 'noop')
        provider = os.getenv("AODS_ENCRYPTION_PROVIDER", "noop")
        key_b64 = os.getenv("AODS_ENCRYPTION_KEY_B64")
        self._enc_mgr = EncryptionAtRestManager(provider=provider, key_b64=key_b64)

    def validate(self, report: Dict[str, Any]) -> ValidationResult:
        errors: List[str] = []

        if not isinstance(report, dict):
            return ValidationResult(False, ["report is not a dict"])

        missing = self.REQUIRED_TOP_LEVEL_KEYS - set(report.keys())
        if missing:
            errors.append(f"missing top-level keys: {sorted(list(missing))}")

        metadata = report.get("metadata", {})
        if not isinstance(metadata, dict):
            errors.append("metadata is not a dict")
        else:
            md_missing = self.REQUIRED_METADATA_KEYS - set(metadata.keys())
            if md_missing:
                errors.append(f"metadata missing keys: {sorted(list(md_missing))}")
            else:
                if str(metadata.get("schema_version")) != self.schema_version:
                    errors.append(
                        f"schema_version mismatch: expected {self.schema_version}, got {metadata.get('schema_version')}"
                    )

        findings = report.get("findings", [])
        if not isinstance(findings, list):
            errors.append("findings is not a list")
        else:
            for idx, f in enumerate(findings):
                if not isinstance(f, dict):
                    errors.append(f"finding[{idx}] is not a dict")
                    continue
                f_missing = self.REQUIRED_FINDING_KEYS - set(f.keys())
                if f_missing:
                    errors.append(f"finding[{idx}] missing keys: {sorted(list(f_missing))}")

        return ValidationResult(len(errors) == 0, errors)

    def ensure_version(self, report: Dict[str, Any]) -> Dict[str, Any]:
        r = dict(report)
        md = dict(r.get("metadata", {}))
        md.setdefault("schema_version", self.schema_version)
        r["metadata"] = md
        return r

    def export_json(self, report: Dict[str, Any], output_path: str) -> Tuple[bool, List[str]]:
        report = self.ensure_version(report)
        vr = self.validate(report)
        if not vr.valid:
            return False, vr.errors
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)

        # Encrypt if provider is not noop; otherwise write plaintext JSON
        if self._enc_mgr.provider_name != "noop":
            plaintext = json.dumps(report, indent=2, ensure_ascii=False).encode("utf-8")
            enc_bytes = self._enc_mgr.encrypt_bytes(plaintext)
            enc_path = out if str(out).endswith(".enc") else out.with_suffix(out.suffix + ".enc")
            enc_path.write_bytes(enc_bytes)
            return True, []
        else:
            with out.open("w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            return True, []

    def export_report(self, report: Dict[str, Any], filename: str | None = None) -> str:
        """Export report into tenant-aware directory with optional encryption.

        Returns absolute path to the written file ('.enc' suffix if encrypted).
        """
        if filename is None:
            ts = time.strftime("%Y%m%d_%H%M%S")
            filename = f"aods_report_{ts}.json"
        out = self.report_base_dir / filename
        ok, errors = self.export_json(report, str(out))
        if not ok:
            raise ReportValidationError("; ".join(errors))
        if self._enc_mgr.provider_name != "noop":
            out = out.with_suffix(out.suffix + ".enc")
        return str(out)

    def summarize(self, report: Dict[str, Any]) -> Dict[str, Any]:
        findings = report.get("findings", []) if isinstance(report, dict) else []
        sev_counts: Dict[str, int] = {}
        for f in findings:
            sev = str(f.get("severity", "info")).upper()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
        return {
            "total_findings": len(findings),
            "by_severity": sev_counts,
            "schema_version": report.get("metadata", {}).get("schema_version", SCHEMA_VERSION),
        }


class ArtifactRetentionManager:
    """Retention manager for artifacts directories."""

    def __init__(self, base_dir: str, retention_hours: int = 168):
        self.base_dir = Path(base_dir)
        self.retention_hours = max(1, int(retention_hours))

    def purge_expired(self) -> List[str]:
        """Delete artifact subdirectories older than retention threshold.

        Returns list of deleted directory paths.
        """
        deleted: List[str] = []
        if not self.base_dir.exists():
            return deleted
        now = time.time()
        threshold = now - (self.retention_hours * 3600)
        for child in self.base_dir.iterdir():
            try:
                if not child.is_dir():
                    continue
                mtime = child.stat().st_mtime
                if mtime < threshold:
                    shutil.rmtree(child, ignore_errors=True)
                    deleted.append(str(child))
            except Exception:
                # Best-effort; continue on errors
                continue
        return deleted
