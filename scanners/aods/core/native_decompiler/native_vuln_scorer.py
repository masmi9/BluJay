"""
core.native_decompiler.native_vuln_scorer - Score decompiled native code for vulnerabilities.

Takes decompiled pseudo-C functions from GhidraBridge and scores them
using the trained C/C++ vulnerability detection model (F1=0.834).

Falls back to pattern-based detection when ML models aren't available.
"""

from __future__ import annotations

import re
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
class NativeVulnerability:
    """A vulnerability found in native code."""
    title: str
    description: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    confidence: float  # 0.0-1.0
    cwe_id: str
    function_name: str
    source_binary: str
    code_snippet: str = ""
    detection_method: str = "pattern"  # "ml" or "pattern"
    architecture: str = ""  # ARM64, ARM32, x86, etc.
    binary_size_kb: int = 0

    @property
    def enriched_description(self) -> str:
        """Description enriched with context for agent consumption."""
        parts = [self.description]
        if self.source_binary:
            parts.append(f"Found in native library: {self.source_binary}")
        if self.architecture:
            parts.append(f"Architecture: {self.architecture}")
        if self.code_snippet:
            snippet = self.code_snippet.replace("\n", " ").strip()[:200]
            parts.append(f"Decompiled code: {snippet}")
        parts.append(
            "This vulnerability is in compiled native code (.so), not Java/Kotlin. "
            "Remediation requires modifying the C/C++ source and recompiling."
        )
        return " | ".join(parts)


# Common vulnerability patterns in C/C++ code
_VULN_PATTERNS = [
    {
        "name": "Buffer Overflow (strcpy)",
        "pattern": re.compile(r"\bstrcpy\s*\(", re.IGNORECASE),
        "cwe": "CWE-120",
        "severity": "HIGH",
        "confidence": 0.7,
        "description": "Use of strcpy without bounds checking - vulnerable to buffer overflow",
    },
    {
        "name": "Buffer Overflow (sprintf)",
        "pattern": re.compile(r"\bsprintf\s*\(", re.IGNORECASE),
        "cwe": "CWE-120",
        "severity": "HIGH",
        "confidence": 0.65,
        "description": "Use of sprintf without bounds checking - vulnerable to buffer overflow",
    },
    {
        "name": "Buffer Overflow (gets)",
        "pattern": re.compile(r"\bgets\s*\(", re.IGNORECASE),
        "cwe": "CWE-120",
        "severity": "CRITICAL",
        "confidence": 0.9,
        "description": "Use of gets() - always vulnerable to buffer overflow, no bounds checking possible",
    },
    {
        "name": "Format String Vulnerability",
        "pattern": re.compile(r"\b(printf|fprintf|syslog)\s*\(\s*[a-zA-Z_]", re.IGNORECASE),
        "cwe": "CWE-134",
        "severity": "HIGH",
        "confidence": 0.4,  # Calibrated: many FPs from non-user-controlled format args
        "description": "Potential format string vulnerability - user-controlled format argument",
    },
    # Note: Use-after-free requires post-free analysis, not just free() detection.
    # Handled separately in _check_use_after_free() with context-aware matching.
    {
        "name": "Integer Overflow in Allocation",
        "pattern": re.compile(r"(malloc|calloc)\s*\([^)]*\b\w+\s*\*\s*\w+[^)]*\)", re.IGNORECASE),
        "cwe": "CWE-190",
        "severity": "MEDIUM",
        "confidence": 0.5,
        "description": "Multiplication in malloc/calloc size - if operands are unchecked, integer overflow leads to undersized allocation",
    },
    {
        "name": "Command Injection",
        "pattern": re.compile(r"\b(system|popen|exec[lv]p?)\s*\(", re.IGNORECASE),
        "cwe": "CWE-78",
        "severity": "CRITICAL",
        "confidence": 0.6,
        "description": "Use of system()/exec() - vulnerable to command injection if input not sanitized",
    },
    {
        "name": "Hardcoded Credentials",
        "pattern": re.compile(r'(password|secret|api_key|token)\s*=\s*"[^"]{4,}"', re.IGNORECASE),
        "cwe": "CWE-798",
        "severity": "HIGH",
        "confidence": 0.5,  # Calibrated: regex may match non-secret constants
        "description": "Hardcoded credential or secret in native code",
    },
    {
        "name": "Weak Random Number Generator",
        "pattern": re.compile(r"\b(rand|srand)\s*\(", re.IGNORECASE),
        "cwe": "CWE-338",
        "severity": "MEDIUM",
        "confidence": 0.45,  # Calibrated: rand() in non-security context is common
        "description": "Use of weak PRNG (rand/srand) - not suitable for security-sensitive operations",
    },
    {
        "name": "NULL Pointer Dereference",
        "pattern": re.compile(r"if\s*\(\s*\w+\s*==\s*NULL\s*\).*?return", re.DOTALL),
        "cwe": "CWE-476",
        "severity": "MEDIUM",
        "confidence": 0.4,
        "description": "Potential NULL pointer dereference - check may be incomplete",
    },
    {
        "name": "Insecure Network Communication",
        "pattern": re.compile(r"\b(connect|send|recv|socket)\s*\(", re.IGNORECASE),
        "cwe": "CWE-319",
        "severity": "MEDIUM",
        "confidence": 0.4,
        "description": "Native network communication - verify TLS is enforced",
    },
    {
        "name": "Weak Cryptography (DES/RC4/MD5)",
        "pattern": re.compile(r"\b(DES_|RC4_|MD5_|EVP_des|EVP_rc4|EVP_md5)", re.IGNORECASE),
        "cwe": "CWE-327",
        "severity": "HIGH",
        "confidence": 0.8,
        "description": "Use of weak/deprecated cryptographic algorithm in native code",
    },
]


def _decompilation_quality(code: str) -> float:
    """Estimate decompilation quality (0.0-1.0).

    Higher quality means more readable decompilation - findings in
    high-quality decompiled code are more trustworthy.

    Heuristics:
    - Named variables (not just FUN_/DAT_ prefixes) → higher
    - Type annotations present → higher
    - Reasonable length (5-200 lines) → higher
    - Minimal unnamed hex references → higher
    """
    if not code or len(code) < 10:
        return 0.1

    lines = code.split("\n")
    line_count = len(lines)

    score = 0.0

    # Length: reasonable functions are 5-200 lines
    if 5 <= line_count <= 200:
        score += 0.3
    elif line_count < 5:
        score += 0.1
    else:
        score += 0.2

    # Type annotations present
    type_keywords = ["int ", "char ", "void ", "long ", "short ", "unsigned ",
                     "float ", "double ", "bool ", "size_t ", "uint"]
    has_types = any(t in code for t in type_keywords)
    if has_types:
        score += 0.25

    # Named variables (not just FUN_/DAT_/UNK_ prefixes)
    words = set(re.findall(r'\b[a-z][a-zA-Z0-9_]{2,}\b', code))
    ghidra_names = {w for w in words if w.startswith(("param_", "local_", "uVar", "iVar", "lVar", "pVar", "bVar"))}
    real_names = words - ghidra_names
    if len(real_names) > 3:
        score += 0.25
    elif len(real_names) > 0:
        score += 0.1

    # Minimal hex noise
    hex_refs = len(re.findall(r'0x[0-9a-fA-F]{6,}', code))
    if hex_refs < line_count * 0.3:
        score += 0.2
    elif hex_refs < line_count:
        score += 0.1

    return min(1.0, score)


def _check_use_after_free(code: str, func_name: str, source_binary: str) -> Optional[NativeVulnerability]:
    """Context-aware use-after-free detection.

    Looks for a free() call where the freed variable is referenced
    AFTER the free. Excludes cases where:
    - The freed pointer is set to NULL after free (correct cleanup)
    - The function returns immediately after free
    - The freed variable is a function parameter that's just being cleaned up
    """
    free_pattern = re.compile(r'free\s*\(\s*(\w+)\s*\)')
    matches = list(free_pattern.finditer(code))
    if not matches:
        return None

    for match in matches:
        freed_var = match.group(1)
        after_free = code[match.end():]

        # Skip if immediately followed by return or NULL assignment
        next_lines = after_free.strip()[:200]
        if next_lines.startswith("return") or next_lines.startswith("}"):
            continue
        # Skip if pointer is set to NULL right after (correct pattern)
        null_assign = re.compile(
            r'\*?\s*' + re.escape(freed_var) + r'\s*=\s*(NULL|0|nullptr)\s*;'
        )
        if null_assign.search(next_lines[:100]):
            continue

        # Check if the freed variable is actually used after free
        use_after = re.search(r'\b' + re.escape(freed_var) + r'\b', after_free[1:])
        if use_after:
            # Extract snippet
            start = max(0, match.start() - 30)
            end = min(len(code), match.end() + 100)
            snippet = code[start:end].strip()

            return NativeVulnerability(
                title=f"Native: Use After Free in {func_name}",
                description=(
                    f"Variable '{freed_var}' is used after being freed. "
                    f"This can lead to heap corruption, code execution, or crashes."
                ),
                severity="CRITICAL",
                confidence=0.6,
                cwe_id="CWE-416",
                function_name=func_name,
                source_binary=source_binary,
                code_snippet=snippet[:500],
                detection_method="pattern",
            )

    return None


def score_functions_with_patterns(
    functions: list,
    source_binary: str = "",
) -> List[NativeVulnerability]:
    """Score decompiled functions using pattern matching.

    This is the fallback when ML models aren't available. Scans
    decompiled pseudo-C for known vulnerable patterns.

    Args:
        functions: List of DecompiledFunction objects.
        source_binary: Name of the source .so file.

    Returns:
        List of detected vulnerabilities.
    """
    vulns: List[NativeVulnerability] = []

    for func in functions:
        code = getattr(func, "code", "") or ""
        func_name = getattr(func, "name", "unknown")

        if len(code) < 5:
            continue

        # Assess decompilation quality - adjust confidence for low-quality output
        quality = _decompilation_quality(code)

        # Context-aware use-after-free check
        uaf = _check_use_after_free(code, func_name, source_binary or getattr(func, "source_binary", ""))
        if uaf:
            uaf.confidence = round(uaf.confidence * quality, 3)
            vulns.append(uaf)

        for pattern_def in _VULN_PATTERNS:
            match = pattern_def["pattern"].search(code)
            if match:
                # Extract a code snippet around the match
                start = max(0, match.start() - 50)
                end = min(len(code), match.end() + 50)
                snippet = code[start:end].strip()

                # Adjust confidence by decompilation quality
                adjusted_confidence = round(pattern_def["confidence"] * quality, 3)

                vulns.append(NativeVulnerability(
                    title=f"Native: {pattern_def['name']} in {func_name}",
                    description=pattern_def["description"],
                    severity=pattern_def["severity"],
                    confidence=adjusted_confidence,
                    cwe_id=pattern_def["cwe"],
                    function_name=func_name,
                    source_binary=source_binary or getattr(func, "source_binary", ""),
                    code_snippet=snippet[:500],
                    detection_method="pattern",
                ))

    return vulns


def score_functions_with_ml(
    functions: list,
    source_binary: str = "",
) -> List[NativeVulnerability]:
    """Score decompiled functions using the trained C/C++ ML model.

    Loads the vulnerability_detection_advanced model (F1=0.834) and
    scores each function's pseudo-C code.

    Falls back to pattern matching if model isn't available.

    Args:
        functions: List of DecompiledFunction objects.
        source_binary: Name of the source .so file.

    Returns:
        List of detected vulnerabilities.
    """
    try:
        from core.ml.safe_pickle import safe_joblib_load

        model_path = Path(__file__).parent.parent.parent / "models" / "vulnerability_detection_advanced" / "augmented_model.pkl"
        if not model_path.exists():
            logger.debug("native_ml_model_not_found", path=str(model_path))
            return score_functions_with_patterns(functions, source_binary)

        model = safe_joblib_load(str(model_path))
        logger.info("native_ml_model_loaded", path=str(model_path))
    except Exception as exc:
        logger.debug("native_ml_model_load_failed", error=str(exc))
        return score_functions_with_patterns(functions, source_binary)

    vulns: List[NativeVulnerability] = []

    for func in functions:
        code = getattr(func, "code", "") or ""
        func_name = getattr(func, "name", "unknown")

        if len(code) < 20:
            continue

        try:
            # Extract features from pseudo-C (simplified feature extraction)
            features = _extract_code_features(code)

            # Score with ML model
            import numpy as np
            X = np.array([features])
            proba = model.predict_proba(X)[0]
            vuln_confidence = float(proba[1]) if len(proba) > 1 else float(proba[0])

            if vuln_confidence >= 0.5:
                # Determine CWE from code patterns
                cwe = _infer_cwe_from_code(code)
                severity = _confidence_to_severity(vuln_confidence)

                vulns.append(NativeVulnerability(
                    title=f"Native: ML-detected vulnerability in {func_name}",
                    description=f"ML model detected potential vulnerability with {vuln_confidence:.0%} confidence",
                    severity=severity,
                    confidence=round(vuln_confidence, 3),
                    cwe_id=cwe,
                    function_name=func_name,
                    source_binary=source_binary,
                    code_snippet=code[:500],
                    detection_method="ml",
                ))
        except Exception:
            continue

    # Also run pattern matching for findings ML might miss
    pattern_vulns = score_functions_with_patterns(functions, source_binary)
    # Deduplicate: keep ML findings, add pattern findings for functions ML didn't flag
    ml_func_names = {v.function_name for v in vulns}
    for pv in pattern_vulns:
        if pv.function_name not in ml_func_names:
            vulns.append(pv)

    return vulns


def _extract_code_features(code: str) -> List[float]:
    """Extract numerical features from pseudo-C code for ML scoring.

    Simplified feature extraction - mirrors the training features
    from scripts/enhanced_vuln_features.py.
    """
    features = []

    # Code length features
    lines = code.split("\n")
    features.append(min(len(lines), 500))  # Line count (capped)
    features.append(min(len(code), 10000))  # Char count (capped)

    # Unsafe function counts
    unsafe_funcs = ["strcpy", "strcat", "sprintf", "gets", "scanf", "strncpy"]
    for uf in unsafe_funcs:
        features.append(code.lower().count(uf))

    # Memory management
    features.append(code.count("malloc"))
    features.append(code.count("calloc"))
    features.append(code.count("realloc"))
    features.append(code.count("free"))

    # Control flow complexity
    features.append(code.count("if"))
    features.append(code.count("for"))
    features.append(code.count("while"))
    features.append(code.count("switch"))
    features.append(code.count("goto"))

    # Pointer operations
    features.append(code.count("*"))
    features.append(code.count("&"))
    features.append(code.count("->"))

    # System calls
    features.append(code.count("system("))
    features.append(code.count("exec"))
    features.append(code.count("popen"))

    # Crypto indicators
    features.append(code.lower().count("aes"))
    features.append(code.lower().count("des"))
    features.append(code.lower().count("md5"))
    features.append(code.lower().count("sha"))

    # Network indicators
    features.append(code.count("socket"))
    features.append(code.count("connect"))
    features.append(code.count("send"))
    features.append(code.count("recv"))

    # String handling
    features.append(code.count("strlen"))
    features.append(code.count("strcmp"))
    features.append(code.count("memcpy"))
    features.append(code.count("memset"))

    # Pad to expected feature count (70 features from training)
    while len(features) < 70:
        features.append(0)

    return features[:70]


def _infer_cwe_from_code(code: str) -> str:
    """Infer the most likely CWE from code patterns."""
    code_lower = code.lower()

    if any(f in code_lower for f in ["strcpy", "strcat", "gets", "sprintf"]):
        return "CWE-120"  # Buffer overflow
    if any(f in code_lower for f in ["printf", "fprintf", "syslog"]):
        return "CWE-134"  # Format string
    if "free" in code_lower and code_lower.count("free") > 1:
        return "CWE-416"  # Use after free
    if any(f in code_lower for f in ["system(", "popen(", "exec"]):
        return "CWE-78"  # Command injection
    if any(f in code_lower for f in ["des_", "rc4_", "md5_"]):
        return "CWE-327"  # Weak crypto
    if any(f in code_lower for f in ["rand(", "srand("]):
        return "CWE-338"  # Weak RNG
    if "null" in code_lower:
        return "CWE-476"  # NULL pointer

    return "CWE-119"  # Generic buffer error


def _confidence_to_severity(confidence: float) -> str:
    """Map ML confidence to severity level."""
    if confidence >= 0.9:
        return "CRITICAL"
    if confidence >= 0.75:
        return "HIGH"
    if confidence >= 0.6:
        return "MEDIUM"
    return "LOW"
