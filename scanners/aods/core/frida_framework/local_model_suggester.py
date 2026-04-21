from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from .script_suggester import APKAnalysisSignals, ScriptSuggestion, FridaScriptSuggester


@dataclass
class LocalModel:
    features: Dict[str, float]
    thresholds: Dict[str, float]

    @staticmethod
    def load(model_path: Path) -> "LocalModel":
        data = json.loads(Path(model_path).read_text())
        return LocalModel(features=data.get("features", {}), thresholds=data.get("thresholds", {"min_score": 0.5}))


def _featurize(signals: APKAnalysisSignals) -> Dict[str, float]:
    features: Dict[str, float] = {}
    classes = signals.classes or []
    methods = signals.methods or []
    libs = signals.libraries or {}
    features["has_webview"] = 1.0 if any("WebView" in c for c in classes) else 0.0
    features["js_interface"] = 1.0 if any("addJavascriptInterface" in m for m in methods) else 0.0
    features["js_enabled"] = 1.0 if any("setJavaScriptEnabled" in m for m in methods) else 0.0
    features["has_okhttp"] = 1.0 if ("okhttp3" in libs or any("okhttp3" in c for c in classes)) else 0.0
    features["has_trust_mgr_cls"] = (
        1.0 if any(t in c for c in classes for t in ["TrustManager", "X509TrustManager", "HostnameVerifier"]) else 0.0
    )
    features["has_trust_mgr_mtd"] = (
        1.0 if any("#checkServerTrusted" in m or "#checkClientTrusted" in m for m in methods) else 0.0
    )
    features["has_hostname_verify"] = 1.0 if any("#verify" in m for m in methods) else 0.0
    return features


class LocalModelSuggester(FridaScriptSuggester):
    def __init__(self, model_path: Optional[str] = None):
        self.model: Optional[LocalModel] = None
        self.model_path = Path(model_path) if model_path else Path("models/frida_local_model.json")
        try:
            if self.model_path.exists():
                self.model = LocalModel.load(self.model_path)
        except Exception:
            self.model = None

    def suggest(self, signals: APKAnalysisSignals) -> List[ScriptSuggestion]:
        # Fallback to rule-based behavior if model missing
        if self.model is None:
            from .rule_based_suggester import RuleBasedSuggester

            return RuleBasedSuggester().suggest(signals)

        feats = _featurize(signals)
        min_score = float(self.model.thresholds.get("min_score", 0.5))

        suggestions: List[ScriptSuggestion] = []
        # Simple linear scoring using feature weights

        def score_of(keys: List[str]) -> float:
            return sum(float(self.model.features.get(k, 0.0)) * float(feats.get(k, 0.0)) for k in keys)

        # SSL
        ssl_keys = ["has_okhttp", "has_trust_mgr_cls", "has_trust_mgr_mtd", "has_hostname_verify"]
        ssl_score = score_of(ssl_keys)
        if ssl_score >= min_score:
            suggestions.append(
                ScriptSuggestion(
                    template_id="ssl_bypass_comprehensive.js",
                    params={"pinning_method": "auto", "target_classes": []},
                    reason=f"ML score {ssl_score:.2f} for SSL/pinning",
                    score=float(ssl_score),
                )
            )

        # WebView
        web_keys = ["has_webview", "js_interface", "js_enabled"]
        web_score = score_of(web_keys)
        if web_score >= min_score:
            suggestions.append(
                ScriptSuggestion(
                    template_id="webview_security_analysis.js",
                    params={
                        "javascript_enabled": feats["js_enabled"] >= 1.0,
                        "javascript_interface": feats["js_interface"] >= 1.0,
                    },
                    reason=f"ML score {web_score:.2f} for WebView risks",
                    score=float(web_score),
                )
            )

        # If nothing crosses threshold, backstop with rule-based
        if not suggestions:
            from .rule_based_suggester import RuleBasedSuggester

            return RuleBasedSuggester().suggest(signals)

        return suggestions
