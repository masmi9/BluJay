from __future__ import annotations

import hashlib
import os
import platform
import re
import sys
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from core.utils.path_sanitizer import sanitize_source_path
from core.cli.finding_processing import _PLUGIN_SUMMARY_PATTERNS

# Evidence enrichment integration (Track 7 Phase 3)
_evidence_enrichment_available = False
try:
    from core.evidence_enrichment_pipeline import enrich_plugin_findings, calculate_evidence_metrics

    _evidence_enrichment_available = True
except ImportError:
    pass

# Vector database integration (Track 14)
_vector_db_available = False
try:
    from core.vector_db import (
        get_semantic_finding_index,
        is_vector_db_available as _check_vector_db,
    )

    _vector_db_available = True
except ImportError:
    pass

ALLOWED_STATUS = {"SUCCESS", "FAILURE", "ERROR", "PARTIAL"}
ALLOWED_SEVERITY = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}


def _round_confidence(value: Any) -> float:
    """Round confidence to 2 decimal places."""
    try:
        return round(float(value), 2)
    except (TypeError, ValueError):
        return 0.5


def _validate_line_number(line_num: Any) -> Optional[int]:
    """Validate line number - must be > 0 or None."""
    if line_num is None:
        return None
    try:
        num = int(line_num)
        # Line number 0 is invalid, return None
        if num <= 0:
            return None
        return num
    except (TypeError, ValueError):
        return None


def _sanitize_finding_paths(finding: Dict[str, Any]) -> None:
    """Sanitize all paths in a finding to remove absolute system paths."""
    # Sanitize top-level path fields
    path_fields = ["file_path", "decompilation_path", "jadx_decompilation_path", "source_path", "apk_path", "location"]
    for field in path_fields:
        if finding.get(field):
            finding[field] = sanitize_source_path(finding[field]) or finding[field]

    # Sanitize paths in evidence
    evidence = finding.get("evidence")
    if isinstance(evidence, dict):
        if evidence.get("file_path"):
            evidence["file_path"] = sanitize_source_path(evidence["file_path"]) or evidence["file_path"]

    # Sanitize paths in description (remove absolute paths)
    desc = finding.get("description", "")
    if isinstance(desc, str) and "/home/" in desc:
        # Extract just the filename or relative path from absolute paths
        import re

        desc = re.sub(r"/home/[^/]+/[^\s]+/workspace/[^/]+/", "", desc)
        desc = re.sub(r"/home/[^/]+/[^\s]+/", "", desc)
        finding["description"] = desc


def _normalize_finding(finding: Dict[str, Any]) -> None:
    """Normalize a finding to meet AODS reporting standards."""
    # Ensure title is set (use name as fallback)
    if not finding.get("title") and finding.get("name"):
        finding["title"] = finding["name"]

    # Round confidence
    if "confidence" in finding:
        finding["confidence"] = _round_confidence(finding["confidence"])

    # Validate line_number
    if "line_number" in finding:
        finding["line_number"] = _validate_line_number(finding["line_number"])

    # Validate evidence.line_number
    evidence = finding.get("evidence")
    if isinstance(evidence, dict) and "line_number" in evidence:
        evidence["line_number"] = _validate_line_number(evidence["line_number"])

    # Normalize app://unknown to empty string
    if finding.get("file_path") == "app://unknown":
        finding["file_path"] = ""
    evidence = finding.get("evidence")
    if isinstance(evidence, dict) and evidence.get("file_path") == "app://unknown":
        evidence["file_path"] = ""

    # Populate location from file_path when location is missing or "unknown"
    loc = finding.get("location")
    fp = finding.get("file_path")
    if (not loc or loc == "unknown") and fp and fp != "unknown":
        finding["location"] = fp

    # Sanitize paths
    _sanitize_finding_paths(finding)


def _normalize_status(raw: Optional[str]) -> str:
    if not raw:
        return "SUCCESS"
    m = str(raw).strip().lower()
    # Handle enum string representation like "AnalysisStatus.SUCCESS"
    if "." in m:
        m = m.split(".")[-1]
    if m in {"completed", "success"}:
        return "SUCCESS"
    if m in {"partial", "partial_success", "partial-success"}:
        return "PARTIAL"
    if m in {"error", "exception"}:
        return "ERROR"
    if m in {"failed", "failure"}:
        return "FAILURE"
    return "SUCCESS"


def _normalize_severity(raw: Optional[str]) -> str:
    if not raw:
        return "MEDIUM"
    m = str(raw).strip().upper()
    # Handle enum string representation like "SeverityLevel.HIGH"
    if "." in m:
        m = m.split(".")[-1]
    mapping = {
        "CRIT": "CRITICAL",
        "WARNING": "LOW",
        "WARN": "LOW",
        "MODERATE": "MEDIUM",
    }
    sev = mapping.get(m, m)
    return sev if sev in ALLOWED_SEVERITY else "MEDIUM"


def _canonical_key(f: Dict[str, Any]) -> Tuple[str, str, str, str]:
    """Build stage-2 (cross-plugin) dedup key: (title, category, file_path, cwe_id).

    Intentionally EXCLUDES plugin_source so that two plugins reporting the same
    vulnerability are merged. Stage-1 (plugin-scoped) dedup in
    finding_processing._create_canonical_findings() uses a different key that
    includes plugin_source - the two stages are complementary by design.

    Track 60 Fix 7: Removed line_number and rule_id from the key - they create
    false uniqueness for semantically identical findings from different plugins.
    Track 75.fix: Strip trailing (category) suffix from title and normalize
    app://unknown to empty - cross-plugin findings often differ only by suffix.
    """
    title = (f.get("title") or f.get("name") or "").strip().casefold()
    # Strip trailing parenthetical category suffix: "SSL issue (crypto_weakness)" → "SSL issue"
    if title.endswith(")") and "(" in title:
        title = title[: title.rindex("(")].strip()
    category = (f.get("category") or "").strip().upper()
    file_path = ""
    evidence = f.get("evidence") or {}
    if isinstance(evidence, dict):
        file_path = (evidence.get("file_path") or "").strip()
    # Normalize app://unknown to empty so it merges with findings that have real paths
    if file_path == "app://unknown":
        file_path = ""
    # Include CWE in canonical key for semantic deduplication
    cwe_id = str(f.get("cwe_id") or f.get("cwe") or "").upper().replace("CWE-", "")
    return (title, category, file_path, cwe_id)


def _stable_id(key: Tuple[str, ...]) -> str:
    h = hashlib.sha256("|".join(key).encode("utf-8")).hexdigest()[:16]
    return f"AODS-{h}"


def _merge_findings(a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
    # Keep highest severity by rank, highest confidence, union sources/tags
    severity_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    sa = _normalize_severity(a.get("severity"))
    sb = _normalize_severity(b.get("severity"))
    merged = dict(a)
    merged["severity"] = sa if severity_rank.get(sa, 0) >= severity_rank.get(sb, 0) else sb
    merged["confidence"] = max(a.get("confidence", 0.0) or 0.0, b.get("confidence", 0.0) or 0.0)
    # Merge sources
    sources = []
    for s in (a.get("sources"), b.get("sources")):
        if isinstance(s, list):
            sources.extend(s)
        elif s:
            sources.append(s)
    if sources:
        merged["sources"] = list({str(x) for x in sources})
    # Merge tags
    tags = []
    for t in (a.get("tags"), b.get("tags")):
        if isinstance(t, list):
            tags.extend(t)
        elif t:
            tags.append(t)
    if tags:
        merged["tags"] = sorted(list({str(x) for x in tags}))
    return merged


# Track 60.1 Fix 3: Manifest-related CWEs where file_path is irrelevant
# (only one AndroidManifest.xml per APK, so dedup by CWE alone)
# Only CWEs that truly represent a SINGLE finding type per manifest.
# CWE-926 (exported components) and CWE-1104 (SDK versions) are too broad  - 
# they cover multiple distinct finding types (activities, receivers, providers,
# permissions, target SDK, min SDK) that should NOT be merged.
# CWE-693 (Protection Mechanism Failure) is also too broad - covers root
# detection bypass (RESILIENCE-1), security hardening, and Privacy Sandbox.
_MANIFEST_CWES = frozenset({"489", "200"})


def _strip_title_suffix(title: str) -> str:
    """Normalize a finding title for similarity comparison.

    Strips trailing parenthetical suffixes like '(crypto_weakness)' and casefolds.
    Also strips trailing non-alphanumeric chars to handle cases like
    'method(' vs 'method( (suffix)' where the regex eats differently.
    """
    result = re.sub(r"\s*\([^)]*\)\s*$", "", title).strip().casefold()
    # Strip trailing non-alphanumeric characters (parens, punctuation) for fuzzy matching
    return re.sub(r"[^a-z0-9]+$", "", result)


def _cwe_file_dedup(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Secondary dedup pass: merge findings sharing (cwe_id, file_path).

    Handles cross-plugin duplicates where two plugins report the same
    vulnerability with different titles but identical CWE and file.
    For manifest-related CWEs, dedup by CWE alone (file_path ignored).
    Findings with a CWE but no meaningful file_path are absorbed into
    existing CWE groups only when their title matches a group member
    (preventing distinct findings with the same CWE from merging).
    """
    severity_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    grouped: List[Dict[str, Any]] = []  # findings that can't be CWE-deduped
    # Findings with a CWE but no file_path, pending absorption into CWE groups
    pending_cwe_no_path: List[Tuple[str, Dict[str, Any]]] = []
    cwe_groups: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}

    for f in findings:
        cwe_raw = str(f.get("cwe_id") or f.get("cwe") or "").upper().replace("CWE-", "").strip()
        if not cwe_raw:
            grouped.append(f)
            continue

        evidence = f.get("evidence") or {}
        file_path = ""
        if isinstance(evidence, dict):
            file_path = (evidence.get("file_path") or "").strip()

        # Normalize placeholder paths to empty
        if file_path in ("app://unknown", "unknown"):
            file_path = ""

        # Detect manifest paths: findings from AndroidManifest.xml with a CWE
        # NOT in _MANIFEST_CWES should use title-guarded dedup (same as
        # pending_no_path) because a single CWE (e.g., 1104, 926, 250) can
        # cover multiple distinct finding types within the same manifest.
        _is_manifest_path = "androidmanifest" in file_path.lower().replace("_", "")

        # For manifest CWEs, ignore file_path (only one manifest per APK)
        if cwe_raw in _MANIFEST_CWES:
            key = (cwe_raw, "")
        elif file_path and not _is_manifest_path:
            key = (cwe_raw, file_path)
        else:
            # No file_path or manifest path - defer to absorption pass
            pending_cwe_no_path.append((cwe_raw, f))
            continue

        cwe_groups.setdefault(key, []).append(f)

    # Absorption pass: findings with CWE but no file_path merge into a
    # matching CWE group ONLY if their title matches a group member.
    # This prevents distinct findings sharing a CWE (e.g., "Exported
    # activities" vs "Exported services", both CWE-926) from merging.
    for cwe_raw, f in pending_cwe_no_path:
        pending_title = _strip_title_suffix(f.get("title") or f.get("name") or "")
        absorbed = False
        for key, group in cwe_groups.items():
            if key[0] != cwe_raw:
                continue
            # Check if any finding in the group has a matching title
            for member in group:
                member_title = _strip_title_suffix(member.get("title") or member.get("name") or "")
                if pending_title == member_title:
                    group.append(f)
                    absorbed = True
                    break
            if absorbed:
                break
        if not absorbed:
            grouped.append(f)

    result = list(grouped)
    for key, group in cwe_groups.items():
        if len(group) == 1:
            result.append(group[0])
        else:
            # Keep the finding with highest severity, breaking ties by confidence
            group.sort(
                key=lambda g: (
                    severity_rank.get(_normalize_severity(g.get("severity")), 0),
                    g.get("confidence") or 0.0,
                ),
                reverse=True,
            )
            winner = group[0]
            for loser in group[1:]:
                winner = _merge_findings(winner, loser)
            result.append(winner)
    return result


_CWE_RECOMMENDATION_MAP = {
    "89": "Use parameterized queries or prepared statements. Never concatenate user input into SQL strings.",
    "79": "Sanitize user input and encode output. Use Content Security Policy headers.",
    "200": "Avoid exposing sensitive information in error messages or logs.",
    "250": "Follow the principle of least privilege. Request only necessary permissions.",
    "276": "Use MODE_PRIVATE for file creation. Avoid world-readable/writable permissions.",
    "295": "Implement certificate pinning. Validate SSL/TLS certificates properly.",
    "312": "Encrypt sensitive data at rest using Android Keystore or EncryptedSharedPreferences.",
    "319": "Use HTTPS for all network communication. Set android:usesCleartextTraffic to false.",
    "327": "Use strong cryptographic algorithms (AES-256, RSA-2048+). Avoid DES, RC4, MD5.",
    "330": "Use SecureRandom for cryptographic randomness. Never use java.util.Random for security.",
    "502": "Validate and sanitize all deserialized data. Use allowlists for accepted classes.",
    "532": "Avoid logging sensitive information. Use ProGuard/R8 to strip debug logs in release builds.",
    "611": "Disable external entity processing in XML parsers. Use defusedxml or equivalent.",
    "649": "Use intent-filters with explicit component names. Set android:exported=false where appropriate.",
    "693": "Implement root/jailbreak detection. Use SafetyNet/Play Integrity API.",
    "798": "Store credentials in Android Keystore. Never hardcode secrets in source code.",
    "919": "Validate all data received via Content Providers. Use parameterized queries.",
    "921": "Encrypt data stored in external storage. Use app-specific directories.",
    "922": "Use internal storage for sensitive data. Encrypt files with Android cryptographic APIs.",
    "926": "Implement proper authorization checks on all exported components.",
}

_CATEGORY_KEYWORDS = {
    "crypto": ("crypt", "cipher", "aes", "rsa", "hash", "md5", "sha", "encrypt", "decrypt", "key"),
    "storage": ("storage", "file", "shared_pref", "database", "sqlite", "cache", "data_store"),
    "network": ("network", "http", "cleartext", "ssl", "tls", "certificate", "pinning", "traffic"),
    "injection": ("inject", "sql", "xss", "command", "query", "content_provider"),
    "configuration": ("config", "manifest", "debug", "backup", "export", "permission", "component"),
    "authentication": ("auth", "login", "password", "credential", "token", "session", "biometric"),
}


def _derive_category(f: Dict[str, Any]) -> str:
    """Derive a granular category from CWE or title keywords."""
    cwe_raw = str(f.get("cwe_id") or f.get("cwe") or "")
    cwe_num = cwe_raw.upper().replace("CWE-", "").strip()
    # CWE-based mapping
    _cwe_to_cat = {
        "89": "injection",
        "79": "injection",
        "502": "injection",
        "919": "injection",
        "295": "network",
        "319": "network",
        "312": "storage",
        "922": "storage",
        "921": "storage",
        "327": "crypto",
        "330": "crypto",
        "276": "configuration",
        "649": "configuration",
        "926": "configuration",
        "798": "authentication",
        "532": "logging",
        "200": "information_disclosure",
    }
    if cwe_num in _cwe_to_cat:
        return _cwe_to_cat[cwe_num]

    # Title keyword matching
    title_lower = (f.get("title") or "").lower()
    for cat, keywords in _CATEGORY_KEYWORDS.items():
        if any(kw in title_lower for kw in keywords):
            return cat
    return "security"


def _derive_recommendation(f: Dict[str, Any]) -> str:
    """Derive a recommendation from CWE mapping or severity-based generic."""
    cwe_raw = str(f.get("cwe_id") or f.get("cwe") or "")
    cwe_num = cwe_raw.upper().replace("CWE-", "").strip()
    if cwe_num in _CWE_RECOMMENDATION_MAP:
        return _CWE_RECOMMENDATION_MAP[cwe_num]
    sev = (f.get("severity") or "MEDIUM").upper()
    if sev in ("CRITICAL", "HIGH"):
        return "Address this finding immediately. Review the affected code and apply security best practices."
    elif sev == "MEDIUM":
        return "Review and remediate this finding. Apply defense-in-depth measures."
    else:
        return "Review this finding and consider applying security hardening."


def _looks_like_stringified_dict(text: str) -> bool:
    """Detect code_snippet that is a stringified Python dict (e.g., {'title': ...})."""
    t = text.strip()
    if t.startswith("{") and t.endswith("}") and ("'title':" in t or "'severity':" in t or "'description':" in t):
        return True
    return False


def _looks_like_report_dump(text: str) -> bool:
    """Detect code_snippet that is an emoji-laden analysis summary dump."""
    _REPORT_MARKERS = (
        "\U0001f534",
        "\U0001f7e1",
        "\U0001f4ca",
        "\u2705",
        "\u274c",
        "Security Analysis",
        "Risk Level:",
        "Total Findings:",
    )
    count = sum(1 for m in _REPORT_MARKERS if m in text)
    return count >= 2


def _coerce_required_fields(f: Dict[str, Any]) -> None:
    # Title/name
    if not f.get("title"):
        f["title"] = f.get("name") or f.get("rule_id") or "Vulnerability"
    # Severity
    f["severity"] = _normalize_severity(f.get("severity"))
    # Category default - prefer owasp_category when category is missing or a generic plugin name
    owasp_cat = f.get("owasp_category")
    if isinstance(owasp_cat, list):
        owasp_cat = owasp_cat[0] if owasp_cat else ""
    owasp_cat = owasp_cat or ""
    cur_cat = f.get("category") or ""
    # Use owasp_category when: (a) no category, or (b) category is a generic plugin name
    # (doesn't look like an OWASP/MASVS identifier) and owasp_category is a proper one
    is_owasp_id = cur_cat.startswith(("M", "MASVS", "CWE"))
    if not cur_cat or (not is_owasp_id and owasp_cat.startswith(("M", "MASVS"))):
        f["category"] = owasp_cat or "UNKNOWN"
    # Track 81: Set baseline confidence when None. ConfidenceScorer in
    # serialize_final_report() is the sole authority and will replace this
    # with a domain-aware calculated value. This default only survives
    # if ConfidenceScorer import fails.
    if f.get("confidence") is None:
        f["confidence"] = 0.5
    # Evidence structure and sanitization
    ev = f.get("evidence") or {}
    if not isinstance(ev, dict):
        ev = {}
    ev["file_path"] = sanitize_source_path(ev.get("file_path")) if ev.get("file_path") else ev.get("file_path")
    if ev.get("line_number") is not None:
        try:
            ev["line_number"] = int(ev["line_number"])
        except Exception:
            ev["line_number"] = None
    # Track 60 Fix 5: Clean dict-stringified code_snippet / evidence
    for snippet_key in ("code_snippet",):
        snippet_val = ev.get(snippet_key)
        if isinstance(snippet_val, dict):
            ev[snippet_key] = None
        elif isinstance(snippet_val, str) and _looks_like_stringified_dict(snippet_val):
            ev[snippet_key] = None
        elif isinstance(snippet_val, str) and _looks_like_report_dump(snippet_val):
            ev[snippet_key] = None
    # Also check top-level code_snippet
    top_snippet = f.get("code_snippet")
    if isinstance(top_snippet, dict):
        f["code_snippet"] = None
    elif isinstance(top_snippet, str) and _looks_like_stringified_dict(top_snippet):
        f["code_snippet"] = None
    elif isinstance(top_snippet, str) and _looks_like_report_dump(top_snippet):
        f["code_snippet"] = None

    # Track 60 Fix 11: Propagate line_number to evidence
    if f.get("line_number") and not ev.get("line_number"):
        ev["line_number"] = f["line_number"]

    f["evidence"] = ev

    # Sanitize other path fields that might contain absolute paths
    path_fields = ["decompilation_path", "jadx_decompilation_path", "source_path", "apk_path"]
    for field in path_fields:
        if f.get(field):
            f[field] = sanitize_source_path(f[field]) or f[field]
    # Attribution policy
    if f.get("attribution_verified") and float(f.get("attribution_confidence") or 0.0) < 0.8:
        f["attribution_verified"] = False

    # Track 60 Fix 14: Normalize owasp_category to string
    owasp = f.get("owasp_category")
    if isinstance(owasp, list) and owasp:
        f["owasp_category"] = owasp[0]
    elif owasp is None:
        f["owasp_category"] = ""

    # Track 60 Fix 16: Derive granular category from CWE/title when flat "security"
    cat = f.get("category", "")
    if not cat or cat.upper() in ("UNKNOWN", "SECURITY", ""):
        f["category"] = _derive_category(f)

    # Track 60 Fix 8: Generate CWE-based references when empty
    refs = f.get("references")
    if not refs:
        refs = []
        cwe_raw = str(f.get("cwe_id") or f.get("cwe") or "")
        cwe_num = cwe_raw.upper().replace("CWE-", "").strip()
        if cwe_num.isdigit():
            refs.append(f"https://cwe.mitre.org/data/definitions/{cwe_num}.html")
        owasp_cat = f.get("owasp_category") or ""
        if owasp_cat and isinstance(owasp_cat, str) and owasp_cat != "":
            refs.append(f"https://mas.owasp.org/MASVS/controls/{owasp_cat}")
        f["references"] = refs

    # Track 60 Fix 9: Expand recommendation fallback
    if not f.get("remediation") and not f.get("recommendation"):
        f["recommendation"] = _derive_recommendation(f)

    # Track 60 Fix 15: Derive false_positive_probability from confidence
    if f.get("false_positive_probability") in (None, 0.0, 0):
        conf = f.get("confidence")
        if conf is not None and isinstance(conf, (int, float)):
            f["false_positive_probability"] = round(1.0 - float(conf), 4)
        else:
            f["false_positive_probability"] = 0.5


_SEVERITY_CONFIDENCE_FALLBACK = {
    "CRITICAL": 0.95,
    "HIGH": 0.85,
    "MEDIUM": 0.70,
    "LOW": 0.50,
    "INFO": 0.30,
}


def _apply_severity_confidence_fallback(findings: List[Dict[str, Any]]) -> bool:
    """Apply severity-based confidence when ML pipeline produced uniform values (Track 30 - Defect 1).

    Detects when all confidence values cluster around a single value (near-zero
    variance), indicating the ML pipeline failed to calibrate. Replaces with
    severity-derived values so the report shows meaningful differentiation.

    Returns True if fallback was applied.
    """
    if len(findings) < 5:
        return False

    confidences = [f.get("confidence") for f in findings if f.get("confidence") is not None]
    if len(confidences) < 5:
        return False

    mean_conf = sum(confidences) / len(confidences)
    variance = sum((c - mean_conf) ** 2 for c in confidences) / len(confidences)

    # Variance < 0.001 means essentially all values are the same (e.g. all 0.5561)
    if variance >= 0.001:
        return False

    for f in findings:
        sev = (f.get("severity") or "MEDIUM").upper()
        f["confidence"] = _SEVERITY_CONFIDENCE_FALLBACK.get(sev, 0.5)
    return True


def _generate_learning_analytics_summary() -> Optional[Dict[str, Any]]:
    """Generate learning analytics summary with a 2-second time cap.

    Uses lazy imports to avoid import cycles. Returns None on any failure
    so callers can gracefully degrade.
    """
    import time as _time_mod

    deadline = _time_mod.monotonic() + 2.0
    try:
        from core.shared_infrastructure.learning_analytics_dashboard import (
            generate_executive_summary_for_dashboard,
            LearningAnalyticsDashboard,
            AnalyticsTimeframe,
        )

        if _time_mod.monotonic() > deadline:
            return None

        dashboard = LearningAnalyticsDashboard()

        if _time_mod.monotonic() > deadline:
            return None

        summary = generate_executive_summary_for_dashboard(dashboard, AnalyticsTimeframe.LAST_MONTH)

        if _time_mod.monotonic() > deadline:
            return None

        return summary if isinstance(summary, dict) else None
    except Exception:
        return None


def serialize_final_report(json_results: Dict[str, Any], apk_context: Any = None) -> Dict[str, Any]:
    """
    Serialize and normalize the final AODS report.

    Ensures all required fields are present and properly formatted:
    - scan_id: Unique UUID for the scan
    - timestamp: ISO8601 timestamp at root level
    - apk_info: APK metadata section
    - Normalized findings with sanitized paths and validated fields
    """
    # === PHASE 12.1: Add required root-level fields ===

    # Add scan_id if not present
    if not json_results.get("scan_id"):
        json_results["scan_id"] = str(uuid.uuid4())

    # Add timestamp at root level
    if not json_results.get("timestamp"):
        json_results["timestamp"] = datetime.now(timezone.utc).isoformat()

    # Build apk_info section from available data
    if not json_results.get("apk_info") or not json_results.get("apk_info", {}).get("sha256"):
        apk_info = dict(json_results.get("apk_info") or {})

        # Try to find APK path from various sources
        apk_path = None
        metadata = json_results.get("metadata", {})
        scan_config = json_results.get("scan_config", {})

        # Search for APK path in multiple locations
        for source in [json_results, metadata, scan_config]:
            if isinstance(source, dict):
                for key in ["apk_path", "apk_file", "input_apk", "target_apk"]:
                    path_val = source.get(key)
                    if path_val and isinstance(path_val, str):
                        apk_path = path_val
                        break
            if apk_path:
                break

        # Extract real metadata from APK if path exists
        if apk_path:
            from pathlib import Path

            apk_file = Path(apk_path)
            if apk_file.exists() and apk_file.is_file():
                try:
                    from core.shared_infrastructure.utilities.apk_parsers import APKParser

                    parser = APKParser()
                    apk_metadata = parser.extract_apk_metadata(apk_file)
                    if apk_metadata:
                        apk_info["package_name"] = apk_info.get("package_name") or apk_metadata.package_name or ""
                        apk_info["version_name"] = apk_metadata.version_name or ""
                        apk_info["version_code"] = apk_metadata.version_code or 0
                        apk_info["sha256"] = apk_metadata.file_hash_sha256 or ""
                        apk_info["file_size_bytes"] = apk_metadata.file_size or 0
                        apk_info["min_sdk_version"] = apk_metadata.min_sdk_version or 0
                        apk_info["target_sdk_version"] = apk_metadata.target_sdk_version or 0
                        if apk_metadata.app_name:
                            apk_info["app_name"] = apk_metadata.app_name
                except Exception:
                    pass  # Fall through to manual extraction below

        # Fallback: extract from metadata/scan_config if APK parsing failed
        if isinstance(metadata, dict):
            if not apk_info.get("package_name"):
                apk_info["package_name"] = metadata.get("package_name") or metadata.get("app_package") or ""
            if apk_path:
                apk_info["apk_path"] = sanitize_source_path(apk_path) or ""

        if isinstance(scan_config, dict):
            if not apk_info.get("package_name"):
                apk_info["package_name"] = scan_config.get("package_name", "")

        # Derive file_name from apk_path if not already set
        if not apk_info.get("file_name") and apk_path:
            from pathlib import Path as _PPath
            apk_info["file_name"] = _PPath(apk_path).name

        # Add placeholders for any still-missing fields
        apk_info.setdefault("package_name", "")
        apk_info.setdefault("file_name", "")
        apk_info.setdefault("version_name", "")
        apk_info.setdefault("version_code", 0)
        apk_info.setdefault("sha256", "")
        apk_info.setdefault("file_size_bytes", 0)
        json_results["apk_info"] = apk_info

    # Pick canonical container - prefer canonical_findings (aggregated) over raw findings
    candidates = [
        json_results.get("canonical_findings"),  # Aggregated findings (preferred)
        json_results.get("vulnerability_findings"),
        json_results.get("vulnerabilities"),
        json_results.get("findings"),
    ]
    findings: List[Dict[str, Any]] = []
    for arr in candidates:
        if isinstance(arr, list) and arr:
            findings = arr
            break

    # Title-based aggregation FIRST: group by (title, severity, cwe_id, category) and collect all affected files
    # This addresses the issue where plugins generate per-file findings (e.g., 200+ "Unencrypted File Storage")
    title_aggregated: Dict[Tuple[str, str, str, str], Dict[str, Any]] = {}
    for f in findings or []:
        if not isinstance(f, dict):
            continue
        _coerce_required_fields(f)
        # Aggregation key: title + severity + cwe + category (ignore file path for grouping)
        title = (f.get("title") or "").strip().casefold()
        severity = _normalize_severity(f.get("severity"))
        cwe_id = str(f.get("cwe_id") or f.get("cwe") or "").upper().replace("CWE-", "")
        category = (f.get("category") or "").strip().upper()
        agg_key = (title, severity, cwe_id, category)

        # Extract file path from finding or evidence
        file_path = f.get("file_path") or f.get("location") or ""
        evidence = f.get("evidence") or {}
        if isinstance(evidence, dict):
            file_path = file_path or evidence.get("file_path") or ""

        if agg_key in title_aggregated:
            # Merge into existing - Track 60 Fix 12: keep higher severity, not just max confidence
            existing = title_aggregated[agg_key]
            _sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
            ex_sev = _normalize_severity(existing.get("severity"))
            new_sev = _normalize_severity(f.get("severity"))
            if _sev_rank.get(new_sev, 0) > _sev_rank.get(ex_sev, 0):
                existing["severity"] = new_sev
                existing["confidence"] = f.get("confidence", 0.0) or 0.0
            else:
                existing["confidence"] = max(existing.get("confidence", 0.0) or 0.0, f.get("confidence", 0.0) or 0.0)
            # Collect affected files
            affected = existing.setdefault("_affected_files", set())
            if file_path:
                affected.add(str(file_path))
            # Merge sources
            for src in f.get("sources") or []:
                if src and src not in existing.get("sources", []):
                    existing.setdefault("sources", []).append(src)
        else:
            # First occurrence - initialize
            f_copy = dict(f)
            f_copy["_affected_files"] = {str(file_path)} if file_path else set()
            title_aggregated[agg_key] = f_copy

    # Convert aggregated results back to list, updating evidence with affected_files count
    findings = []
    for agg_key, f in title_aggregated.items():
        affected_files = f.pop("_affected_files", set())
        if len(affected_files) > 1:
            # Multiple files affected - update evidence to show aggregation
            evidence = f.get("evidence") or {}
            if not isinstance(evidence, dict):
                evidence = {}
            evidence["affected_files_count"] = len(affected_files)
            evidence["affected_files_sample"] = sorted(affected_files)[:10]  # Show first 10
            if len(affected_files) > 10:
                evidence["affected_files_truncated"] = True
            f["evidence"] = evidence
            # Update description to indicate aggregation
            orig_desc = f.get("description") or ""
            if not orig_desc.startswith("Found in"):
                f["description"] = f"Found in {len(affected_files)} files. {orig_desc}"
        findings.append(f)

    # Dedupe and merge (local canonical key pass)
    deduped: Dict[Tuple[str, ...], Dict[str, Any]] = {}
    for f in findings or []:
        if not isinstance(f, dict):
            continue
        _coerce_required_fields(f)
        key = _canonical_key(f)
        if key in deduped:
            deduped[key] = _merge_findings(deduped[key], f)
        else:
            deduped[key] = f

    # === TRACK 60.1 Fix 3: CWE+file secondary dedup (cross-plugin) ===
    deduped_list_pre_cwe = list(deduped.values())
    deduped_list_post_cwe = _cwe_file_dedup(deduped_list_pre_cwe)
    # Rebuild deduped dict from the CWE-deduped list
    deduped = {}
    for f in deduped_list_post_cwe:
        key = _canonical_key(f)
        deduped[key] = f

    # === TRACK 30: Severity-based confidence fallback ===
    # Detect when ML pipeline produced uniform confidence (Defect 1) and apply fallback
    deduped_list_for_conf = list(deduped.values())
    if _apply_severity_confidence_fallback(deduped_list_for_conf):
        meta = json_results.setdefault("metadata", {})
        meta["confidence_fallback_applied"] = True

    # === TRACK 7 PHASE 3: Evidence Enrichment ===
    # Enrich findings with line numbers and code snippets before final normalization
    # Controlled by AODS_EVIDENCE_ENRICHMENT env var (default: enabled)
    if _evidence_enrichment_available and os.getenv("AODS_EVIDENCE_ENRICHMENT", "1") == "1":
        try:
            deduped_list = list(deduped.values())
            enrichment_result = enrich_plugin_findings(deduped_list, apk_context=apk_context)

            # Store enrichment metrics in metadata
            if enrichment_result.findings_enriched > 0:
                enrichment_meta = json_results.setdefault("metadata", {})
                enrichment_meta["evidence_enrichment"] = {
                    "findings_processed": enrichment_result.findings_processed,
                    "findings_enriched": enrichment_result.findings_enriched,
                    "line_numbers_added": enrichment_result.line_numbers_added,
                    "code_snippets_added": enrichment_result.code_snippets_added,
                    "elapsed_ms": round(enrichment_result.elapsed_ms, 2),
                }

            # Calculate final evidence metrics
            metrics = calculate_evidence_metrics(deduped_list)
            enrichment_meta = json_results.setdefault("metadata", {})
            enrichment_meta["evidence_coverage"] = {
                "line_number_pct": metrics.line_number_pct,
                "code_snippet_pct": metrics.code_snippet_pct,
                "file_path_pct": metrics.file_path_pct,
                "taxonomy_pct": metrics.taxonomy_pct,
            }
        except Exception as e:
            # Log but don't fail serialization
            import logging

            logging.getLogger(__name__).warning(f"Evidence enrichment failed: {e}")

    # === Track 75.fix: Manifest line number enrichment ===
    # Findings from enhanced_manifest_analysis often lack line_number.
    # Use manifest_parsing_utils to look up line numbers from AndroidManifest.xml.
    _manifest_line_map_ser = None
    for f in deduped.values():
        if f.get("line_number"):
            continue
        fp = str(f.get("file_path") or "").lower()
        if "androidmanifest" not in fp and "manifest" not in str(f.get("plugin_source") or "").lower():
            continue
        if _manifest_line_map_ser is None:
            try:
                from core.manifest_parsing_utils import build_manifest_line_map, lookup_manifest_line
                from pathlib import Path as _Path

                _manifest_line_map_ser = {}
                # Search workspace for decompiled manifest
                workspace = _Path("workspace")
                if not workspace.is_dir():
                    try:
                        from core.cli import REPO_ROOT
                        workspace = _Path(REPO_ROOT) / "workspace"
                    except Exception:
                        pass
                if workspace.is_dir():
                    manifests = sorted(workspace.glob("*/AndroidManifest.xml"))
                    if manifests:
                        _manifest_line_map_ser = build_manifest_line_map(str(manifests[0]))
            except Exception:
                _manifest_line_map_ser = {}
        if not _manifest_line_map_ser:
            break
        try:
            title = f.get("title", "")
            evidence_str = ""
            if isinstance(f.get("evidence"), dict):
                evidence_str = str(f["evidence"].get("code_snippet", ""))
            ln = lookup_manifest_line(
                _manifest_line_map_ser,
                f.get("location", ""),
                component_name=f.get("component_name"),
                permission_name=f.get("permission_name"),
                title=title,
                evidence=evidence_str,
            )
            if ln:
                f["line_number"] = ln
        except Exception:
            pass

    # === Confidence Scoring: Apply ConfidenceScorer as final normalization pass ===
    # Runs HERE because normalize_findings_integrated() in execution_parallel.py
    # overwrites earlier confidence values (from scanner_report.py) with plugin defaults (0.5).
    # This is the last step before _normalize_finding() - nothing downstream can overwrite it.
    try:
        from core.confidence_scorer import ConfidenceScorer
        _scorer = ConfidenceScorer(
            apk_path=str(getattr(apk_context, 'apk_path', '')) if apk_context else ''
        )
        _scorer_ctx = {
            "app_type": getattr(apk_context, 'app_type', 'unknown') if apk_context else 'unknown',
            "apk_context": apk_context,
        }
        for f in deduped.values():
            if isinstance(f, dict):
                try:
                    assessment = _scorer.calculate_confidence_score(f, _scorer_ctx)
                    f["confidence"] = assessment.confidence_score
                    f["confidence_level"] = assessment.confidence_level.value
                    f["context_factors"] = assessment.context_factors
                except Exception:
                    pass  # Keep existing confidence from plugin/fallback
    except ImportError:
        pass

    # Assign stable IDs and normalize findings
    final_findings: List[Dict[str, Any]] = []
    for key, f in deduped.items():
        f = dict(f)
        f["id"] = f.get("id") or _stable_id(key)
        # Apply normalization (path sanitization, confidence rounding, line validation)
        _normalize_finding(f)
        final_findings.append(f)

    # === TRACK 71: Remove status-report findings (safety net) ===
    # Plugin status reports that slipped through earlier filtering.
    import re as _re71

    # Track 81: Use shared blocklist from finding_processing (was duplicated here)
    _no_issue_phrases = (
        "no issues",
        "no vulnerabilities",
        "no significant findings",
        "no findings",
        "fallback mode",
        "no sql injection vulnerabilities detected",
    )

    def _is_status_finding(f: Dict[str, Any]) -> bool:
        t = (f.get("title") or "").strip().lower()
        d = (f.get("description") or "").strip().lower()
        if t in _PLUGIN_SUMMARY_PATTERNS:
            return True
        # Raw plugin name as title (lowercase_with_underscores)
        if _re71.match(r"^[a-z][a-z0-9_]+$", t) and "_" in t:
            return True
        # Status suffix like (Pass), (Fail)
        if _re71.search(r"\(\s*(pass|fail|error|success|ok|skipped)\s*\)\s*$", t):
            return True
        # Description indicates no findings
        if any(phr in d for phr in _no_issue_phrases):
            sev = (f.get("severity") or "").upper()
            if sev not in ("HIGH", "CRITICAL"):
                return True
        return False

    pre_status_count = len(final_findings)
    final_findings = [f for f in final_findings if not _is_status_finding(f)]
    status_removed = pre_status_count - len(final_findings)

    # === TRACK 30 PHASE 4b: Post-dedup noise filter ===
    # Track 71: Remove library findings without code_snippet evidence regardless of severity.
    # Third-party library code findings without concrete evidence are false positives.
    _library_prefixes = (
        "androidx/",
        "com/google/",
        "com/android/support/",
        "kotlin/",
        "kotlinx/",
        "com/squareup/",
        "io/reactivex/",
        "org/apache/",
        "com/facebook/",
        "com/bumptech/",
        "com/fasterxml/",
        "org/jetbrains/",
        "javax/",
    )
    # Track 75.fix: Known third-party SDK packages - ALWAYS filter regardless of code_snippet.
    # App developers cannot fix internal SDK code; decompiled source evidence is irrelevant.
    _always_filter_prefixes = (
        "com/google/firebase/",
        "com/google/android/gms/",
        "com/google/android/play/",
        "com/google/android/exoplayer",
        "com/google/android/material/",
        "com/google/common/",          # Guava
        "com/google/protobuf/",
        "com/google/gson/",
        "com/squareup/okhttp",
        "com/squareup/retrofit",
        "io/reactivex/",
        "org/apache/",
        "com/facebook/react/",
        "com/bumptech/glide/",
        "com/fasterxml/jackson/",
        "org/jetbrains/",
    )

    def _is_noise_finding(f: Dict[str, Any]) -> bool:
        # Track 72: Check all path fields, not just top-level file_path.
        paths = []
        fp = (f.get("file_path") or "").replace("\\", "/")
        if fp:
            paths.append(fp)
        ev = f.get("evidence")
        if isinstance(ev, dict):
            ev_fp = (ev.get("file_path") or "").replace("\\", "/")
            if ev_fp:
                paths.append(ev_fp)
        for af in f.get("affected_files") or []:
            s = str(af).replace("\\", "/")
            if s:
                paths.append(s)

        # Track 75.fix: Known third-party SDK - always noise, even with code_snippet
        if any(any(sdk in p for sdk in _always_filter_prefixes) for p in paths):
            return True

        if not any(any(prefix in p for prefix in _library_prefixes) for p in paths):
            return False
        # Track 71: Library findings without real code_snippet are noise regardless of severity.
        # code_snippet must be actual source code, not a stringified dict/object.
        if isinstance(ev, dict):
            snippet = ev.get("code_snippet")
            if isinstance(snippet, str) and len(snippet) > 10:
                s = snippet.strip()
                if not (s.startswith(("{", "[", "{'", '{"'))):
                    return False
        return True

    pre_filter_count = len(final_findings)
    final_findings = [f for f in final_findings if not _is_noise_finding(f)]
    noise_removed = pre_filter_count - len(final_findings)

    # === TRACK 30 PHASE 4a: plugins_summary ===
    # Build a summary of plugin contribution to findings
    plugin_findings_count: Dict[str, int] = {}
    for f in final_findings:
        plugin_name = f.get("plugin_source") or f.get("category") or f.get("plugin") or f.get("source") or "unknown"
        # Normalize: take first source if it's a list
        if isinstance(f.get("sources"), list) and f["sources"]:
            plugin_name = f["sources"][0]
        plugin_findings_count[plugin_name] = plugin_findings_count.get(plugin_name, 0) + 1

    plugins_summary = {
        "plugins_with_findings": len(plugin_findings_count),
        "findings_per_plugin": dict(sorted(plugin_findings_count.items(), key=lambda x: x[1], reverse=True)),
    }
    if noise_removed > 0:
        plugins_summary["noise_findings_removed"] = noise_removed
    if status_removed > 0:
        plugins_summary["status_findings_removed"] = status_removed

    meta = json_results.setdefault("metadata", {})
    meta["plugins_summary"] = plugins_summary
    meta["total_findings"] = len(final_findings)

    # Replace canonical container and align others by ID reference (optional reference-only mode)
    reference_only = os.getenv("AODS_REFERENCE_ONLY", "0") == "1"
    json_results["vulnerabilities"] = final_findings
    if reference_only:
        id_refs = [f.get("id") for f in final_findings]
        json_results["vulnerability_findings"] = id_refs
        json_results["findings"] = id_refs
    else:
        json_results["vulnerability_findings"] = final_findings
        json_results["findings"] = final_findings
    json_results["findings_count"] = len(final_findings)

    # Sync summary sections with post-dedup finding counts
    _severity_counts: Dict[str, int] = {}
    for f in final_findings:
        sev = str(f.get("severity", "medium")).lower()
        _severity_counts[sev] = _severity_counts.get(sev, 0) + 1
    _total = len(final_findings)

    vuln_summary = json_results.get("vulnerability_summary")
    if isinstance(vuln_summary, dict):
        vuln_summary["total_vulnerabilities"] = _total
        vuln_summary["critical"] = _severity_counts.get("critical", 0)
        vuln_summary["high"] = _severity_counts.get("high", 0)
        vuln_summary["medium"] = _severity_counts.get("medium", 0)
        vuln_summary["low"] = _severity_counts.get("low", 0)

    masvs_summary = json_results.get("masvs_summary")
    if isinstance(masvs_summary, dict):
        masvs_summary["total_findings"] = _total

    integration_cov = json_results.get("integration_coverage_validation")
    if isinstance(integration_cov, dict):
        integration_cov["total_findings"] = _total

    # Normalize top-level status
    json_results["status"] = _normalize_status(json_results.get("status"))

    # Metadata and environment
    metadata = json_results.get("metadata") or {}
    if not isinstance(metadata, dict):
        metadata = {}
    metadata.setdefault("schema_version", "aods_report_v1")
    metadata.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
    json_results["metadata"] = metadata

    environment = json_results.get("environment") or {}
    if not isinstance(environment, dict):
        environment = {}
    environment.setdefault("os", platform.platform())
    environment.setdefault("python_version", sys.version.split(" ")[0])
    json_results["environment"] = environment

    # Versions placeholder (extend as needed)
    versions = json_results.get("versions") or {}
    if not isinstance(versions, dict):
        versions = {}
    json_results["versions"] = versions

    # Scan config placeholder (extend as needed)
    scan_config = json_results.get("scan_config") or {}
    if not isinstance(scan_config, dict):
        scan_config = {}
    json_results["scan_config"] = scan_config

    # === Learning Analytics Summary ===
    # Inject learning_analytics_summary for the ML analytics API endpoint and executive dashboard.
    # Only runs if the field is not already present (EVRE path may have set it) and caps at 2s.
    if not json_results.get("learning_analytics_summary"):
        json_results["learning_analytics_summary"] = _generate_learning_analytics_summary()

    # Resource usage
    ru = json_results.get("resource_usage") or {}
    if not isinstance(ru, dict):
        ru = {}
    for k in ("cpu_seconds", "max_memory_mb", "io_read_mb", "io_write_mb", "wall_time_seconds"):
        ru.setdefault(k, 0)
    json_results["resource_usage"] = ru

    # === TRACK 14: Vector Database Indexing Hook ===
    # Index findings in vector database for semantic search (post-dedup only)
    # Controlled by AODS_VECTOR_DB_ENABLED env var (default: disabled)
    if _vector_db_available and os.getenv("AODS_VECTOR_DB_ENABLED", "0") == "1":
        try:
            if _check_vector_db():
                index = get_semantic_finding_index()
                if index and index.is_available():
                    # Build scan context from report metadata
                    scan_context = {
                        "scan_id": json_results.get("scan_id", ""),
                        "owner_user_id": json_results.get("owner_user_id")
                        or metadata.get("owner_user_id")
                        or metadata.get("user")
                        or "",
                        "tenant_id": json_results.get("tenant_id") or metadata.get("tenant_id") or "default",
                        "visibility": json_results.get("visibility") or metadata.get("visibility") or "private",
                    }

                    # Only index if we have owner metadata
                    if scan_context.get("owner_user_id"):
                        # Index findings in batch (pollution filter applied internally)
                        indexed_count = index.index_findings_batch(
                            findings=final_findings,
                            scan_context=scan_context,
                        )

                        # Store indexing stats in metadata
                        vector_meta = metadata.setdefault("vector_index", {})
                        vector_meta["indexed"] = indexed_count
                        vector_meta["total"] = len(final_findings)
                        vector_meta["scan_id"] = scan_context["scan_id"]
                    else:
                        # Log warning about missing owner
                        import logging

                        logging.getLogger(__name__).debug(
                            "Vector indexing skipped: no owner_user_id in report metadata"
                        )
        except Exception as e:
            # Log but don't fail serialization
            import logging

            logging.getLogger(__name__).warning(f"Vector database indexing failed: {e}")

    return json_results
