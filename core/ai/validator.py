from __future__ import annotations
import json, os, re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from .prompts import BASE_PROMPT

@dataclass
class ValidationResult:
    label: str                     # "true_positive" | "false_positive" | "needs_review"
    confidence: float              # 0..1
    explanation: str
    severity_adjustment: str       # "none" | "downgrade" | "upgrade"

DEFAULT_THRESHOLD = 0.65  # below => treat as needs_review unless label is strong

class AIValidator:
    """
    Pluggable AI validator for BluJay findings.
    Providers supported via env/config:
      - OPENAI (env: OPENAI_API_KEY, model via BLUJAY_AI_MODEL)
      - ANTHROPIC (env: ANTHROPIC_API_KEY, model via BLUJAY_AI_MODEL)
      - OLLAMA/local (http://localhost:11434 by default) or dry_run heuristics
    """
    def __init__(
        self,
        provider: str = "dry_run",          # "openai"|"anthropic"|"ollama"|"dry_run"
        model: Optional[str] = None,        # e.g. "gpt-4o-mini", "claude-3-haiku", "llama3"
        threshold: float = DEFAULT_THRESHOLD,
        max_findings: int = 1000,
    ) -> None:
        self.provider = provider.lower()
        self.model = model or os.getenv("BLUJAY_AI_MODEL", "gpt-4o-mini")
        self.threshold = threshold
        self.max_findings = max_findings

    # ---------- public API ----------
    def validate_findings(self, findings: List[Dict[str, Any]], language: str = "unknown",
                          frameworks: str = "") -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for f in findings[: self.max_findings]:
            prompt = self._build_prompt(f, language, frameworks)
            result = self._run(prompt, f)
            # gate on threshold: low-confidence => needs_review
            if result.confidence < self.threshold and result.label == "true_positive":
                result.label = "needs_review"
            f2 = dict(f)
            f2["ai_validation"] = {
                "label": result.label,
                "confidence": round(result.confidence, 3),
                "explanation": result.explanation.strip(),
                "severity_adjustment": result.severity_adjustment,
            }
            out.append(f2)
        return out

    # ---------- prompt ----------
    def _build_prompt(self, f: Dict[str, Any], language: str, frameworks: str) -> str:
        # tolerate absent keys from older pipelines
        return BASE_PROMPT.format(
            language=language,
            frameworks=frameworks or "unknown",
            rule_id=f.get("rule_id", "unknown"),
            cwe_id=f.get("cwe_id", "NA"),
            file=f.get("file", "NA"),
            line=f.get("line", "NA"),
            severity=f.get("severity", "NA"),
            message=f.get("message", ""),
            code_snippet=_trim_snippet(f.get("code", f.get("snippet", ""))),
            source=_safe_str(f.get("source", "")),
            sink=_safe_str(f.get("sink", "")),
            sanitizers=", ".join(f.get("sanitizers", [])) if isinstance(f.get("sanitizers"), list) else str(f.get("sanitizers", "")),
            taint_path=" -> ".join(f.get("taint_path", [])) if isinstance(f.get("taint_path"), list) else str(f.get("taint_path", "")),
        )

    # ---------- provider dispatch ----------
    def _run(self, prompt: str, f: Dict[str, Any]) -> ValidationResult:
        try:
            if self.provider == "openai":
                return self._run_openai(prompt)
            if self.provider == "anthropic":
                return self._run_anthropic(prompt)
            if self.provider == "ollama":
                return self._run_ollama(prompt)
            # default: deterministic heuristics (no network, no keys)
            return self._run_heuristics(f)
        except Exception as e:
            # on error, fall back to heuristics
            return self._run_heuristics(f, note=f"Provider error: {e}")

    # ---------- REAL providers (stubs; wire up SDKs in your env) ----------
    def _run_openai(self, prompt: str) -> ValidationResult:
        # Example stub. Replace with openai SDK call if desired.
        # from openai import OpenAI; client = OpenAI()
        # resp = client.chat.completions.create(model=self.model, messages=[{"role":"user","content":prompt}], response_format={"type":"json_object"})
        # data = json.loads(resp.choices[0].message.content)
        data = {"label":"needs_review", "confidence":0.5, "explanation":"Stub OpenAI path.", "severity_adjustment":"none"}
        return ValidationResult(**data)

    def _run_anthropic(self, prompt: str) -> ValidationResult:
        # Example stub for Anthropic Claude JSON output
        data = {"label":"needs_review", "confidence":0.5, "explanation":"Stub Anthropic path.", "severity_adjustment":"none"}
        return ValidationResult(**data)

    def _run_ollama(self, prompt: str) -> ValidationResult:
        # Minimal local call example (pseudo; plug your HTTP client)
        data = {"label":"needs_review", "confidence":0.5, "explanation":"Stub Ollama path.", "severity_adjustment":"none"}
        return ValidationResult(**data)

    # ---------- Heuristics fallback (fast & zero-dep) ----------
    def _run_heuristics(self, f: Dict[str, Any], note: str = "") -> ValidationResult:
        """
        Very simple rules to get value with zero API keys:
        - If sink is clearly dangerous AND source/taint exists AND no sanitizers -> true_positive (0.9)
        - If rule is test/demo path or snippet shows obvious sanitization -> false_positive (0.85)
        - Else needs_review (0.6)
        """
        msg = _safe_str(f.get("message",""))
        sink = _safe_str(f.get("sink","")) + " " + msg
        src  = _safe_str(f.get("source",""))
        code = _safe_str(f.get("code", f.get("snippet","")))
        sanitizers = " ".join(f.get("sanitizers", [])) if isinstance(f.get("sanitizers"), list) else str(f.get("sanitizers",""))

        dangerous = any(k in sink.lower() for k in ["exec", "eval", "sql", "query(", "rawquery", "system(", "processbuilder(", "webview.loadurl", "file(", "url(", "requests.", "fetch("])
        tainted   = bool(src) or "taint" in (f.get("taint_path") or []) or re.search(r"\binput\b|\brequest\.", code, re.I)
        sanitized = any(s in sanitizers.lower() for s in ["sanitize", "escape", "parametr", "preparestatement", "whitelist", "allowlist", "encode"])
        is_test   = re.search(r"/(test|web_tests|samples?)/", f.get("file",""), re.I) or "mock" in code.lower()

        if dangerous and tainted and not sanitized and not is_test:
            return ValidationResult("true_positive", 0.9, "Dangerous sink reachable from tainted source without sanitization.", "none")

        if sanitized or is_test:
            return ValidationResult("false_positive", 0.85, "Sanitized or test harness/mock context.", "downgrade")

        exp = "Heuristic triage; insufficient signals." + (f" {note}" if note else "")
        return ValidationResult("needs_review", 0.6, exp, "none")


def _safe_str(x: Any) -> str:
    return "" if x is None else str(x)

def _trim_snippet(s: str, max_chars: int = 900) -> str:
    s = s or ""
    return (s[:max_chars] + "\n...") if len(s) > max_chars else s
