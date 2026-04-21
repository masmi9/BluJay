"""EVRE Remediation Mixin – attach CWE-specific remediation templates."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

_BUILTIN_REMEDIATION: Dict[str, str] = {
    "CWE-312": "Avoid storing sensitive data in plaintext. Use iOS Keychain with kSecAttrAccessibleWhenUnlockedThisDeviceOnly.",
    "CWE-295": "Implement proper certificate validation. Do not disable SSL validation in NSURLSessionDelegate.",
    "CWE-327": "Replace weak cryptographic algorithms (DES, MD5, SHA-1) with AES-256 and SHA-256 or higher.",
    "CWE-321": "Never hardcode cryptographic keys. Use SecKeyGeneratePair or derive keys from secure user input.",
    "CWE-259": "Remove hardcoded credentials. Use Keychain Services or secure configuration management.",
    "CWE-922": "Set NSFileProtectionComplete on sensitive files. Avoid NSFileProtectionNone.",
    "CWE-532": "Disable NSLog in production builds. Use os_log with appropriate privacy labels.",
    "CWE-200": "Restrict data exposure. Avoid logging sensitive fields and sanitize clipboard content.",
    "CWE-693": "Implement jailbreak detection to enforce app integrity in sensitive contexts.",
    "CWE-494": "Enable binary hardening: PIE, stack canaries, ARC. Strip debug symbols for release builds.",
    "CWE-319": "Enforce App Transport Security. Remove NSAllowsArbitraryLoads and exception domains.",
    "CWE-749": "Restrict WKWebView JavaScript interfaces. Avoid UIWebView (deprecated, insecure).",
}


class EVRERemediationMixin:
    def _attach_remediation(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Attach remediation text from templates if not already present."""
        templates = self._load_remediation_templates()
        for finding in findings:
            if finding.get("remediation"):
                continue
            cwe = finding.get("cwe_id", "")
            # Try YAML templates first, then built-in fallbacks
            remediation = templates.get(cwe) or _BUILTIN_REMEDIATION.get(cwe)
            if remediation:
                finding["remediation"] = remediation
        return findings

    def _load_remediation_templates(self) -> Dict[str, str]:
        cache_key = "_remediation_templates_cache"
        cached = getattr(self, cache_key, None)
        if cached is not None:
            return cached

        import yaml
        templates_path = Path(__file__).parent.parent.parent / "config" / "ios_remediation_templates.yaml"
        result: Dict[str, str] = {}
        if templates_path.exists():
            try:
                with open(templates_path) as f:
                    data = yaml.safe_load(f) or {}
                    result = data.get("remediation_templates", {})
            except Exception:
                pass
        setattr(self, cache_key, result)
        return result
