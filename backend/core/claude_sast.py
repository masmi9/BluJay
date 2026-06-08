"""
AI-powered SAST for decompiled Android source code using the Anthropic API.

Adapted from the claude-code-security-review approach:
  https://github.com/anthropics/claude-code-security-review

Pipeline:
  1. Collect Java/Kotlin files from JADX output, scored by security relevance
  2. Batch into ~50k-char chunks to stay within token limits
  3. Call Claude with an Android-focused security prompt
  4. Apply hard exclusion rules (test files, generated code, low confidence)
  5. Return normalized StaticFinding-compatible dicts

Requires ANTHROPIC_API_KEY in the environment. Skips gracefully if absent.
"""
import asyncio
import json
import os
from pathlib import Path

import structlog

logger = structlog.get_logger()

# ── File selection ─────────────────────────────────────────────────────────────

_HIGH_PRIORITY_KEYWORDS = {
    "auth", "login", "signup", "register", "token", "session",
    "crypto", "cipher", "encrypt", "decrypt", "hash", "hmac", "key",
    "ssl", "tls", "certificate", "trust", "pinning",
    "network", "http", "api", "request", "response", "retrofit", "okhttp",
    "webview", "javascript",
    "database", "sql", "query", "cursor", "contentprovider",
    "file", "storage", "sharedpref",
    "intent", "broadcast", "service", "receiver", "pending",
    "permission", "access", "policy",
    "password", "credential", "secret",
}

_SKIP_NAMES = {"r.java", "buildconfig.java"}
_SKIP_PATH_SEGMENTS = {"test", "androidtest", "unittest", "mock", "stub"}


def _priority_score(path: Path) -> int:
    name_lower = path.name.lower()
    if name_lower in _SKIP_NAMES:
        return 0
    path_lower = str(path).lower()
    if any(seg in path_lower.split("/") or seg in path_lower.split("\\")
           for seg in _SKIP_PATH_SEGMENTS):
        return 0
    # Check filename first (most reliable signal), then full path
    if any(kw in name_lower for kw in _HIGH_PRIORITY_KEYWORDS):
        return 3
    if any(kw in path_lower for kw in _HIGH_PRIORITY_KEYWORDS):
        return 2
    return 1


def _collect_source_files(source_dir: Path, max_files: int = 100) -> list[Path]:
    candidates: list[tuple[int, Path]] = []
    for ext in (".java", ".kt"):
        for f in source_dir.rglob(f"*{ext}"):
            score = _priority_score(f)
            if score > 0:
                candidates.append((score, f))
    candidates.sort(key=lambda x: (-x[0], str(x[1])))
    return [f for _, f in candidates[:max_files]]


# ── Batching ───────────────────────────────────────────────────────────────────

_MAX_CHARS_PER_BATCH = 50_000
_MAX_BATCHES = 8
_MAX_FILE_CHARS = 12_000


def _batch_files(
    files: list[Path], base_dir: Path
) -> list[list[tuple[str, str]]]:
    batches: list[list[tuple[str, str]]] = []
    current: list[tuple[str, str]] = []
    used = 0

    for fp in files:
        try:
            content = fp.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if len(content) > _MAX_FILE_CHARS:
            content = content[:_MAX_FILE_CHARS] + "\n// ... [truncated for analysis]"
        try:
            rel = str(fp.relative_to(base_dir))
        except ValueError:
            rel = fp.name
        cost = len(rel) + len(content) + 80

        if used + cost > _MAX_CHARS_PER_BATCH and current:
            batches.append(current)
            current = []
            used = 0

        current.append((rel, content))
        used += cost

    if current:
        batches.append(current)

    return batches[:_MAX_BATCHES]


# ── Prompt ─────────────────────────────────────────────────────────────────────

_SYSTEM_PROMPT = """\
You are an expert Android security researcher performing SAST (Static Application Security Testing) \
on decompiled Android APK source code. Your goal is to find real, exploitable vulnerabilities — not \
theoretical issues or code-style concerns.

## Vulnerability categories to look for

1. **SQL Injection** — rawQuery / execSQL with string concatenation from user input in \
SQLiteDatabase or ContentProvider query methods.

2. **WebView Attacks** — addJavascriptInterface exposing sensitive methods, \
setJavaScriptEnabled without origin validation, loadUrl / loadData with unsanitized input, \
shouldOverrideUrlLoading accepting file:// or javascript: schemes.

3. **Insecure IPC** — exported Activities/Services/ContentProviders/BroadcastReceivers without \
enforced permissions; Intent extras used to redirect component execution without validation; \
broadcast receivers processing implicit actions with sensitive payloads.

4. **Path Traversal** — File operations built from untrusted Intent extras, ContentProvider \
openFile using getLastPathSegment without canonicalization, directory traversal via "../" in paths.

5. **Cryptographic Weaknesses** — DES/3DES/RC4/Blowfish/Arcfour; MD5 or SHA-1 for password \
hashing; ECB cipher mode; hardcoded static IV; hardcoded encryption keys in source; \
SecureRandom seeded with constant.

6. **Insecure Network** — HTTP endpoints for auth or PII; custom X509TrustManager that accepts \
all certificates; HostnameVerifier returning true unconditionally; disabled certificate pinning \
with empty onReceivedSslError.

7. **Insecure Data Storage** — Credentials or PII in unencrypted SharedPreferences; sensitive \
data written to external storage; credentials logged with Log.d/Log.v/Log.i.

8. **PendingIntent Hijacking** — PendingIntent created without FLAG_IMMUTABLE on API 31+ targets; \
implicit PendingIntent passed to third-party components.

9. **JavaScript Interface Exposure** — @JavascriptInterface methods granting file read, arbitrary \
shell, or sensitive device data access without caller validation.

10. **Authentication / Authorization Bypass** — ContentProvider CRUD operations lacking caller \
permission checks; custom checkCallingPermission logic that can be bypassed.

## Hard exclusions — do NOT report these
- Findings inside test/, androidTest/, or mock/ directories
- Issues in auto-generated files (R.java, BuildConfig.java, *.pb.java)
- General denial-of-service or resource exhaustion (unless remotely triggerable)
- Missing rate limiting, missing HTTP security headers, CSRF (not applicable to Android)
- Code quality, maintainability, or null-pointer issues that are not security-relevant

## Output format
Return ONLY a valid JSON array — no prose, no markdown fences, no explanation before or after.
Each finding object must include all of these keys:

[
  {
    "file_path": "com/example/app/AuthManager.java",
    "line_number": 87,
    "severity": "high",
    "category": "injection",
    "title": "SQL Injection in getUser() via rawQuery",
    "description": "The getUser() method constructs a rawQuery by concatenating the userId \
parameter directly into the SQL string without parameterization.",
    "exploit": "An attacker controlling the userId value (e.g. via an exported ContentProvider) \
can inject SQL to dump the entire users table: ' UNION SELECT * FROM users--",
    "remediation": "Replace with: db.rawQuery(\\\"SELECT * FROM users WHERE id=?\\\", \
new String[]{userId})",
    "confidence": 0.92
  }
]

Only include findings with confidence >= 0.70.
If no vulnerabilities are found, return exactly: []
"""


def _build_user_message(batch: list[tuple[str, str]]) -> str:
    parts = [f"### {rel_path}\n```java\n{content}\n```" for rel_path, content in batch]
    return "\n\n".join(parts)


# ── False positive filter ──────────────────────────────────────────────────────

_EXCLUDE_PATH_SEGMENTS = {"test", "androidtest", "unittest", "mock", "stub", "fake"}
_EXCLUDE_FILENAMES = {"r.java", "buildconfig.java"}
_MIN_CONFIDENCE = 0.70


def _should_exclude(finding: dict) -> bool:
    fp = finding.get("file_path", "").lower().replace("\\", "/")
    segments = set(fp.split("/"))
    if segments & _EXCLUDE_PATH_SEGMENTS:
        return True
    if Path(fp).name in _EXCLUDE_FILENAMES:
        return True
    if finding.get("confidence", 1.0) < _MIN_CONFIDENCE:
        return True
    return False


# ── JSON extraction ────────────────────────────────────────────────────────────

def _extract_json_array(text: str) -> list[dict]:
    text = text.strip()
    # Strip markdown code fences if present
    for fence in ("```json", "```"):
        if text.startswith(fence):
            text = text[len(fence):]
            if "```" in text:
                text = text[: text.index("```")]
            break
    try:
        result = json.loads(text.strip())
        if isinstance(result, list):
            return result
    except json.JSONDecodeError:
        pass
    start = text.find("[")
    end = text.rfind("]") + 1
    if start != -1 and end > start:
        try:
            result = json.loads(text[start:end])
            if isinstance(result, list):
                return result
        except json.JSONDecodeError:
            pass
    return []


# ── Main entry point ───────────────────────────────────────────────────────────

_VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
_VALID_CATEGORIES = {
    "injection", "crypto", "network", "storage", "ipc",
    "webview", "authentication", "authorization", "pendingintent",
    "sast_finding",
}


async def run_claude_sast(
    source_dir: Path,
    analysis_id: int,
    progress_queue: asyncio.Queue | None = None,
    max_files: int = 100,
) -> list[dict]:
    """
    Runs AI-powered SAST on a decompiled JADX source directory.
    Returns a list of finding dicts compatible with the StaticFinding model.
    Requires ANTHROPIC_API_KEY env var; returns [] if absent or on error.
    """
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        logger.info("Claude SAST skipped — ANTHROPIC_API_KEY not set", analysis_id=analysis_id)
        return []

    try:
        import anthropic
    except ImportError:
        logger.warning("Claude SAST skipped — anthropic package not installed")
        return []

    files = _collect_source_files(source_dir, max_files=max_files)
    if not files:
        logger.info("Claude SAST skipped — no source files found", source_dir=str(source_dir))
        return []

    batches = _batch_files(files, source_dir)
    if not batches:
        return []

    logger.info(
        "Claude SAST starting",
        analysis_id=analysis_id,
        files=len(files),
        batches=len(batches),
    )

    client = anthropic.AsyncAnthropic(api_key=api_key)
    raw_findings: list[dict] = []

    for i, batch in enumerate(batches):
        if progress_queue:
            pct = 91 + int((i / len(batches)) * 4)  # slides from 91 → 95
            await progress_queue.put({
                "type": "progress",
                "stage": "claude_sast",
                "pct": pct,
                "message": f"AI SAST: batch {i + 1}/{len(batches)} ({len(batch)} files)...",
            })

        user_msg = _build_user_message(batch)

        for attempt in range(3):
            try:
                resp = await client.messages.create(
                    model="claude-opus-4-8",
                    max_tokens=4096,
                    system=_SYSTEM_PROMPT,
                    messages=[{"role": "user", "content": user_msg}],
                )
                text = resp.content[0].text
                raw_findings.extend(_extract_json_array(text))
                break
            except Exception as exc:
                if attempt == 2:
                    logger.warning(
                        "Claude SAST batch failed after 3 attempts",
                        batch_index=i,
                        error=str(exc),
                    )
                else:
                    await asyncio.sleep(2 ** attempt)

    # Normalize and filter
    output: list[dict] = []
    for raw in raw_findings:
        if not isinstance(raw, dict):
            continue
        if _should_exclude(raw):
            continue

        sev = raw.get("severity", "medium").lower()
        if sev not in _VALID_SEVERITIES:
            sev = "medium"

        category = raw.get("category", "sast_finding").lower()
        if category not in _VALID_CATEGORIES:
            category = "sast_finding"

        ln = raw.get("line_number")
        if not isinstance(ln, int) or ln < 1:
            ln = None

        evidence = json.dumps({
            "exploit": raw.get("exploit", ""),
            "remediation": raw.get("remediation", ""),
            "confidence": raw.get("confidence", 1.0),
            "source": "claude_sast",
        })

        output.append({
            "category": category,
            "severity": sev,
            "title": raw.get("title", "Security Finding"),
            "description": raw.get("description", ""),
            "file_path": raw.get("file_path", ""),
            "line_number": ln,
            "evidence": evidence,
            "rule_id": f"claude_sast_{category}",
        })

    logger.info("Claude SAST complete", analysis_id=analysis_id, findings=len(output))
    return output
