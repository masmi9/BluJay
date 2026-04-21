"""
iOS Feature Extractor – converts IPA findings into ML feature vectors.
"""
from __future__ import annotations

from typing import Any, Dict, List

_SEVERITY_SCORE = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}

_CATEGORY_FEATURES = [
    "binary_security", "ats", "keychain", "entitlements", "code_signing",
    "cryptography", "data_storage", "network", "webview", "url_scheme",
    "privacy", "logging", "clipboard", "jailbreak", "anti_debug",
    "secrets", "swift_objc", "third_party", "cert_pinning", "dynamic",
]


class IOSFeatureExtractor:
    """Converts a list of findings into a numerical feature vector for ML scoring."""

    def extract(self, findings: List[Dict[str, Any]], ipa_ctx=None) -> Dict[str, float]:
        features: Dict[str, float] = {}

        # Severity counts
        for sev in ("critical", "high", "medium", "low", "info"):
            features[f"count_{sev}"] = sum(
                1 for f in findings if f.get("severity", "info") == sev
            )

        # Total findings
        features["total_findings"] = float(len(findings))

        # Average confidence
        if findings:
            features["avg_confidence"] = sum(
                f.get("confidence", 0.5) for f in findings
            ) / len(findings)
        else:
            features["avg_confidence"] = 1.0

        # Category distribution
        for cat in _CATEGORY_FEATURES:
            features[f"cat_{cat}"] = sum(
                1 for f in findings
                if cat in (f.get("finding_id", "") + f.get("vulnerability_type", "")).lower()
            )

        # Binary security flags (from ipa_ctx)
        if ipa_ctx:
            features["has_pie"] = float(ipa_ctx.has_pie or False)
            features["has_arc"] = float(ipa_ctx.has_arc or False)
            features["has_stack_canary"] = float(ipa_ctx.has_stack_canary or False)
            features["symbols_stripped"] = float(ipa_ctx.symbols_stripped or False)
        else:
            for flag in ("has_pie", "has_arc", "has_stack_canary", "symbols_stripped"):
                features[flag] = 0.0

        # Weighted severity score
        features["severity_score"] = sum(
            _SEVERITY_SCORE.get(f.get("severity", "info"), 1) * f.get("confidence", 0.5)
            for f in findings
        )

        return features

    def extract_single(self, finding: Dict[str, Any]) -> Dict[str, float]:
        """Extract features for a single finding (for per-finding ML scoring)."""
        sev = finding.get("severity", "info")
        return {
            "severity_score": float(_SEVERITY_SCORE.get(sev, 1)),
            "confidence": float(finding.get("confidence", 0.5)),
            "has_cwe": float(bool(finding.get("cwe_id"))),
            "has_masvs": float(bool(finding.get("masvs_control"))),
            "has_file_path": float(bool(finding.get("file_path"))),
            "has_code_snippet": float(bool(finding.get("code_snippet"))),
            "has_remediation": float(bool(finding.get("remediation"))),
        }
