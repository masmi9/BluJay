"""
core.autoresearch.metrics - AQS computation, report parsing, baselines.

The AODS Quality Score (AQS) is a composite metric the loop maximizes:
  AQS = 0.6 * detection_score - 0.3 * fp_penalty + 0.1 * stability_bonus
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from core.logging_config import get_logger
    logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging
    logger = stdlib_logging.getLogger(__name__)


@dataclass
class ScanResult:
    """Result from scanning a single APK."""

    apk_name: str
    apk_type: str  # "vulnerable" or "production"
    total_findings: int = 0
    severity_counts: Dict[str, int] = field(default_factory=dict)
    cwe_counts: Dict[str, int] = field(default_factory=dict)
    plugin_counts: Dict[str, int] = field(default_factory=dict)
    scan_time_seconds: float = 0.0
    success: bool = True
    report_path: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "apk_name": self.apk_name,
            "apk_type": self.apk_type,
            "total_findings": self.total_findings,
            "severity_counts": self.severity_counts,
            "cwe_counts": self.cwe_counts,
            "plugin_counts": self.plugin_counts,
            "scan_time_seconds": round(self.scan_time_seconds, 2),
            "success": self.success,
            "report_path": self.report_path,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ScanResult":
        return cls(
            apk_name=d["apk_name"],
            apk_type=d["apk_type"],
            total_findings=d.get("total_findings", 0),
            severity_counts=d.get("severity_counts", {}),
            cwe_counts=d.get("cwe_counts", {}),
            plugin_counts=d.get("plugin_counts", {}),
            scan_time_seconds=d.get("scan_time_seconds", 0.0),
            success=d.get("success", True),
            report_path=d.get("report_path"),
        )


@dataclass
class SessionBaseline:
    """Calibration baseline established at the start of a session."""

    scan_results: List[ScanResult]
    git_commit: str = ""
    timestamp: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "git_commit": self.git_commit,
            "timestamp": self.timestamp,
            "scan_results": [r.to_dict() for r in self.scan_results],
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "SessionBaseline":
        return cls(
            git_commit=d.get("git_commit", ""),
            timestamp=d.get("timestamp", ""),
            scan_results=[ScanResult.from_dict(r) for r in d.get("scan_results", [])],
        )

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.to_dict(), indent=2))
        tmp.rename(path)

    @classmethod
    def load(cls, path: Path) -> "SessionBaseline":
        data = json.loads(path.read_text())
        return cls.from_dict(data)

    def get_result(self, apk_name: str) -> Optional[ScanResult]:
        for r in self.scan_results:
            if r.apk_name == apk_name:
                return r
        return None


@dataclass
class CorpusResult:
    """Aggregated result from scanning the full corpus."""

    scan_results: List[ScanResult]
    aqs: float = 0.0
    detection_score: float = 0.0
    fp_penalty: float = 0.0
    stability_bonus: float = 0.0
    total_time: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "aqs": round(self.aqs, 4),
            "detection_score": round(self.detection_score, 4),
            "fp_penalty": round(self.fp_penalty, 4),
            "stability_bonus": round(self.stability_bonus, 4),
            "total_time": round(self.total_time, 2),
            "scan_results": [r.to_dict() for r in self.scan_results],
        }


def parse_report(report_path: Path, apk_name: str, apk_type: str) -> ScanResult:
    """Parse a JSON scan report into a ScanResult."""
    result = ScanResult(apk_name=apk_name, apk_type=apk_type, report_path=str(report_path))

    try:
        data = json.loads(report_path.read_text(encoding="utf-8", errors="replace"))
    except (json.JSONDecodeError, OSError) as e:
        logger.warning("parse_report_failed", path=str(report_path), error=str(e))
        result.success = False
        return result

    # Extract findings from either key
    findings = data.get("findings") or data.get("vulnerabilities") or []
    if not isinstance(findings, list):
        findings = []

    result.total_findings = len(findings)

    severity_counts: Dict[str, int] = {}
    cwe_counts: Dict[str, int] = {}
    plugin_counts: Dict[str, int] = {}

    for finding in findings:
        if not isinstance(finding, dict):
            continue

        severity = str(finding.get("severity", "UNKNOWN")).upper()
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

        cwe = finding.get("cwe_id") or finding.get("cwe")
        if cwe:
            cwe_str = str(cwe)
            cwe_counts[cwe_str] = cwe_counts.get(cwe_str, 0) + 1

        plugin = finding.get("plugin_name") or finding.get("source")
        if plugin:
            plugin_str = str(plugin)
            plugin_counts[plugin_str] = plugin_counts.get(plugin_str, 0) + 1

    result.severity_counts = severity_counts
    result.cwe_counts = cwe_counts
    result.plugin_counts = plugin_counts

    # Extract timing from metadata if available
    metadata = data.get("metadata") or {}
    if isinstance(metadata, dict):
        result.scan_time_seconds = float(metadata.get("scan_duration_seconds", 0))

    return result


def compute_aqs(results: List[ScanResult], baseline: SessionBaseline) -> CorpusResult:
    """Compute AODS Quality Score against the session baseline.

    AQS = 0.6 * detection_score - 0.3 * fp_penalty + 0.1 * stability_bonus
    """
    vuln_scores = []
    prod_penalties = []
    severity_stable = True

    for result in results:
        if not result.success:
            continue

        bl = baseline.get_result(result.apk_name)
        if bl is None or not bl.success:
            continue

        if result.apk_type == "vulnerable":
            # detection_score: ratio of findings vs baseline, capped at 1.05
            if bl.total_findings > 0:
                ratio = result.total_findings / bl.total_findings
            else:
                ratio = 1.0 if result.total_findings == 0 else 1.05
            vuln_scores.append(min(ratio, 1.05))

        elif result.apk_type == "production":
            # fp_penalty: excess findings above baseline
            if bl.total_findings > 0:
                excess = max(0, result.total_findings - bl.total_findings)
                prod_penalties.append(excess / bl.total_findings)
            else:
                # Baseline had 0 findings; any new finding is penalty
                prod_penalties.append(float(result.total_findings))

        # Stability: severity distribution within +/-2 per bucket
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            bl_count = bl.severity_counts.get(sev, 0)
            cur_count = result.severity_counts.get(sev, 0)
            if abs(cur_count - bl_count) > 2:
                severity_stable = False

    detection_score = sum(vuln_scores) / len(vuln_scores) if vuln_scores else 1.0
    fp_penalty = sum(prod_penalties) / len(prod_penalties) if prod_penalties else 0.0
    stability_bonus = 1.0 if severity_stable else 0.0

    aqs = 0.6 * detection_score - 0.3 * fp_penalty + 0.1 * stability_bonus

    total_time = sum(r.scan_time_seconds for r in results)

    return CorpusResult(
        scan_results=results,
        aqs=aqs,
        detection_score=detection_score,
        fp_penalty=fp_penalty,
        stability_bonus=stability_bonus,
        total_time=total_time,
    )
