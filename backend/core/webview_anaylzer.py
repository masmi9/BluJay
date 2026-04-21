"""
JS / WebView analysis — extracts JavaScript from APK assets and
scans for secrets, dangerous APIs, postMessage handlers, and JS bridges.
"""
import re
from pathlib import Path

import structlog

logger = structlog.get_logger()

# ── Regex rules ──────────────────────────────────────────────────────────────

_RULES = [
    {
        "id": "secret_api_key",
        "pattern": re.compile(
            r"""(?i)(?:api[_-]?key|apikey|secret[_-]?key|auth[_-]?token)\s*[:=]\s*['"]([A-Za-z0-9\-_]{16,})['"]"""
        ),
        "severity": "high",
        "title": "Potential API key or secret",
    },
    {
        "id": "eval_usage",
        "pattern": re.compile(r"\beval\s*\("),
        "severity": "high",
        "title": "eval() usage",
    },
    {
        "id": "inner_html",
        "pattern": re.compile(r"\.innerHTML\s*="),
        "severity": "medium",
        "title": "innerHTML assignment (XSS risk)",
    },
    {
        "id": "post_message",
        "pattern": re.compile(r"\bpostMessage\s*\("),
        "severity": "medium",
        "title": "postMessage usage",
    },
    {
        "id": "mixed_content",
        "pattern": re.compile(r"""src\s*=\s*['"]http://"""),
        "severity": "medium",
        "title": "Mixed content (HTTP resource in HTTPS context)",
    },
    {
        "id": "document_write",
        "pattern": re.compile(r"\bdocument\.write\s*\("),
        "severity": "medium",
        "title": "document.write() usage",
    },
    {
        "id": "location_href",
        "pattern": re.compile(r"location\.href\s*="),
        "severity": "low",
        "title": "location.href assignment (open redirect risk)",
    },
    {
        "id": "hardcoded_url",
        "pattern": re.compile(r"""['"]https?://[A-Za-z0-9\-._/]+['"]"""),
        "severity": "info",
        "title": "Hardcoded URL",
    },
]

# Inline javascript: loadUrl calls in Java
_LOADURL_RE = re.compile(r'loadUrl\s*\(\s*"(javascript:[^"]+)"', re.DOTALL)
_LOADDATA_RE = re.compile(r'loadData(?:WithBaseURL)?\s*\([^,]+,\s*"([^"]{20,})"', re.DOTALL)
_JS_INTERFACE_RE = re.compile(
    r'addJavascriptInterface\s*\(\s*(\w+)\s*,\s*"([^"]+)"', re.DOTALL
)

# Match public methods in a Java class (simplified)
_PUBLIC_METHOD_RE = re.compile(
    r'@JavascriptInterface[^{]*?\bpublic\b[^{(]+?\b(\w+)\s*\(([^)]*)\)', re.DOTALL
)


def _scan_js_content(filename: str, content: str) -> list[dict]:
    findings = []
    lines = content.splitlines()
    for rule in _RULES:
        for lineno, line in enumerate(lines, 1):
            if rule["pattern"].search(line):
                findings.append({
                    "rule_id": rule["id"],
                    "severity": rule["severity"],
                    "title": rule["title"],
                    "file": filename,
                    "line": lineno,
                    "evidence": line.strip()[:200],
                })
    return findings


def _extract_js_bridge_methods(java_text: str) -> list[str]:
    return [
        f"{m.group(1)}({m.group(2)})"
        for m in _PUBLIC_METHOD_RE.finditer(java_text)
    ]


def extract_webview_js(decompile_path: str | None, jadx_path: str | None) -> list[dict]:
    """
    Returns a list of dicts:
      { source, path, size_bytes, content, findings, bridge_methods }
    """
    files: list[dict] = []

    # 1. JS / HTML files in assets + res/raw
    for base in filter(None, [decompile_path]):
        bp = Path(base)
        for pattern in ("assets/**/*.js", "res/raw/**/*.js", "assets/**/*.html", "res/raw/**/*.html"):
            for fp in bp.glob(pattern):
                try:
                    content = fp.read_text(errors="replace")
                    findings = _scan_js_content(fp.name, content)
                    files.append({
                        "source": "asset",
                        "path": str(fp.relative_to(bp)),
                        "size_bytes": fp.stat().st_size,
                        "content": content,
                        "findings": findings,
                        "bridge_methods": [],
                    })
                except OSError:
                    pass

    # 2. Inline JS from loadUrl / loadData in Java source
    for base in filter(None, [jadx_path]):
        jp = Path(base)
        for java_file in jp.rglob("*.java"):
            try:
                java_text = java_file.read_text(errors="replace")
            except OSError:
                continue

            for m in _LOADURL_RE.finditer(java_text):
                snippet = m.group(1)
                findings = _scan_js_content(f"inline:{java_file.name}", snippet)
                files.append({
                    "source": "loadUrl_inline",
                    "path": str(java_file.relative_to(jp)),
                    "size_bytes": len(snippet),
                    "content": snippet,
                    "findings": findings,
                    "bridge_methods": [],
                })

            for m in _LOADDATA_RE.finditer(java_text):
                snippet = m.group(1)
                findings = _scan_js_content(f"inline:{java_file.name}", snippet)
                files.append({
                    "source": "loadData_inline",
                    "path": str(java_file.relative_to(jp)),
                    "size_bytes": len(snippet),
                    "content": snippet,
                    "findings": findings,
                    "bridge_methods": [],
                })

            # 3. addJavascriptInterface bridges
            for bm in _JS_INTERFACE_RE.finditer(java_text):
                interface_class = bm.group(1)
                interface_name = bm.group(2)
                methods = _extract_js_bridge_methods(java_text)
                files.append({
                    "source": "js_bridge",
                    "path": str(java_file.relative_to(jp)),
                    "size_bytes": 0,
                    "content": f"// JS Bridge: {interface_name} → {interface_class}",
                    "findings": [{
                        "rule_id": "js_bridge",
                        "severity": "high",
                        "title": f"addJavascriptInterface: {interface_name} ({interface_class})",
                        "file": java_file.name,
                        "line": 0,
                        "evidence": bm.group(0)[:200],
                    }],
                    "bridge_methods": methods,
                })

    return files
