from __future__ import annotations

from typing import List
from .script_suggester import APKAnalysisSignals, ScriptSuggestion, FridaScriptSuggester


class RuleBasedSuggester(FridaScriptSuggester):
    """Deterministic rule-based suggester for initial domains (ssl, webview)."""

    def suggest(self, signals: APKAnalysisSignals) -> List[ScriptSuggestion]:
        suggestions: List[ScriptSuggestion] = []

        # SSL domain
        has_okhttp = any(
            "okhttp3" in (signals.libraries or {}) or "okhttp3" in (cls or "") for cls in (signals.classes or [])
        )
        has_trust_manager = any(
            any(token in (cls or "") for token in ["TrustManager", "X509TrustManager", "HostnameVerifier"])
            for cls in (signals.classes or [])
        )
        methods = signals.methods or []
        has_cert_pinner_method = any("CertificatePinner" in m or "#certificatePinner" in m for m in methods)
        has_trust_manager_method = any("#checkServerTrusted" in m or "#checkClientTrusted" in m for m in methods)
        has_hostname_verifier_method = any(
            "#verify" in m and ("HostnameVerifier" in m or "OkHostnameVerifier" in m) for m in methods
        )

        if has_okhttp or has_cert_pinner_method:
            suggestions.append(
                ScriptSuggestion(
                    template_id="ssl_bypass_comprehensive.js",
                    params={"pinning_method": "okhttp", "target_classes": _pick_ssl_classes(signals)},
                    reason="Detected OkHttp/CertificatePinner signals; likely certificate pinning",
                    score=0.85 if has_cert_pinner_method else 0.8,
                )
            )
        elif has_trust_manager or has_trust_manager_method or has_hostname_verifier_method:
            suggestions.append(
                ScriptSuggestion(
                    template_id="ssl_bypass_comprehensive.js",
                    params={"pinning_method": "trust_manager", "target_classes": _pick_ssl_classes(signals)},
                    reason="Detected TrustManager/HostnameVerifier method signals",
                    score=0.75 if (has_trust_manager_method or has_hostname_verifier_method) else 0.7,
                )
            )

        # WebView domain
        has_webview_class = any("WebView" in (cls or "") for cls in (signals.classes or []))
        js_interface_added = any("addJavascriptInterface" in (m or "") for m in methods)
        js_enabled = any("#setJavaScriptEnabled" in (m or "") for m in methods)
        if js_interface_added or has_webview_class or js_enabled:
            suggestions.append(
                ScriptSuggestion(
                    template_id="webview_security_analysis.js",
                    params={
                        "webview_present": has_webview_class,
                        "javascript_interface": js_interface_added,
                        "javascript_enabled": js_enabled,
                    },
                    reason="Detected WebView with JS interface/enablement signals",
                    score=0.85 if js_interface_added else (0.7 if js_enabled else 0.6),
                )
            )

        # Crypto domain (weak/custom crypto)
        crypto_indicators = any(
            any(token in (cls or "") for token in ["javax.crypto", "Cipher", "MessageDigest"])
            for cls in (signals.classes or [])
        )
        if crypto_indicators:
            suggestions.append(
                ScriptSuggestion(
                    template_id="crypto_hooks.js",
                    params={},
                    reason="Crypto APIs detected; inspect cipher usage",
                    score=0.6,
                )
            )

        # Storage domain (SharedPreferences/SQLite)
        storage_indicators = any(
            any(token in (cls or "") for token in ["SharedPreferences", "SQLiteDatabase"])
            for cls in (signals.classes or [])
        )
        if storage_indicators:
            suggestions.append(
                ScriptSuggestion(
                    template_id="storage_hooks.js",
                    params={},
                    reason="Local storage APIs detected; inspect storage security",
                    score=0.6,
                )
            )

        # Root/emulator detection bypass
        root_indicators = any(
            any(token in (cls or "") for token in ["Build", "SystemProperties"]) for cls in (signals.classes or [])
        )
        if root_indicators:
            suggestions.append(
                ScriptSuggestion(
                    template_id="universal_emulator_bypass.js",
                    params={},
                    reason="Potential device checks detected; try emulator/root bypass",
                    score=0.55,
                )
            )

        return suggestions


def _pick_ssl_classes(signals: APKAnalysisSignals) -> List[str]:
    classes = []
    for cls in signals.classes or []:
        if any(
            token in (cls or "")
            for token in ["TrustManager", "X509TrustManager", "HostnameVerifier", "CertificatePinner"]
        ):
            classes.append(cls)
    return classes[:10]
