"""
Scans decompiled APK source for hardcoded secrets and insecure patterns.
Uses regex + Shannon entropy analysis.
"""
import asyncio
import math
import re
from dataclasses import dataclass
from pathlib import Path

SCAN_EXTENSIONS = {".java", ".kt", ".smali", ".xml", ".json", ".properties", ".gradle", ".yaml", ".yml", ".txt"}

# (rule_id, compiled_pattern, severity, title)
_PATTERNS: list[tuple[str, re.Pattern, str, str]] = []

_RAW_PATTERNS = [
    ("aws_access_key",    r"AKIA[0-9A-Z]{16}",                                           "critical", "AWS Access Key ID"),
    ("aws_secret_key",    r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]",    "critical", "AWS Secret Access Key"),
    ("google_api_key",    r"AIza[0-9A-Za-z\-_]{35}",                                     "high",     "Google API Key"),
    ("firebase_url",      r"https://[a-z0-9\-]+\.firebaseio\.com",                        "medium",   "Firebase Database URL"),
    ("firebase_key",      r"AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140}",                 "high",     "Firebase Server Key"),
    ("jwt_token",         r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+",  "high",     "JSON Web Token (JWT)"),
    ("rsa_private_key",   r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",        "critical", "Private Key Material"),
    ("generic_password",  r"(?i)(password|passwd|pwd)\s*[=:]\s*[\"'][^\"'\s]{6,}[\"']",  "medium",   "Hardcoded Password"),
    ("generic_api_key",   r"(?i)(api[_\-]?key|apikey|api[_\-]?secret)\s*[=:]\s*[\"'][^\"'\s]{8,}[\"']", "high", "Hardcoded API Key"),
    ("generic_secret",    r"(?i)(secret[_\-]?key|client[_\-]?secret|app[_\-]?secret)\s*[=:]\s*[\"'][^\"'\s]{8,}[\"']", "high", "Hardcoded Secret"),
    ("slack_token",       r"xox[baprs]\-[0-9]{12}\-[0-9]{12}\-[0-9]{12}\-[a-z0-9]{32}", "high",     "Slack Token"),
    ("stripe_key",        r"(?:r|s)k_(live|test)_[0-9a-zA-Z]{24}",                       "critical", "Stripe API Key"),
    ("github_token",      r"ghp_[0-9a-zA-Z]{36}",                                         "critical", "GitHub Personal Access Token"),
    ("http_basic_auth",   r"https?://[^:@\s]+:[^@\s]+@[^\s]+",                            "high",     "Credentials in URL"),
    ("ip_address",        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b", "info", "Hardcoded IP Address"),
]

for _rid, _pat, _sev, _title in _RAW_PATTERNS:
    _PATTERNS.append((_rid, re.compile(_pat), _sev, _title))


@dataclass
class SecretFinding:
    rule_id: str
    severity: str
    title: str
    file_path: str
    line_number: int
    match: str
    context: str


def _shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    freq: dict[str, int] = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def scan_file(file_path: Path, base_dir: Path) -> list[SecretFinding]:
    findings: list[SecretFinding] = []
    if file_path.suffix not in SCAN_EXTENSIONS:
        return findings
    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return findings

    rel_path = str(file_path.relative_to(base_dir))
    lines = content.splitlines()

    for lineno, line in enumerate(lines, start=1):
        for rule_id, pattern, severity, title in _PATTERNS:
            for m in pattern.finditer(line):
                # Avoid duplicates from the same line
                ctx_start = max(0, lineno - 3)
                ctx_end = min(len(lines), lineno + 2)
                context = "\n".join(lines[ctx_start:ctx_end])
                findings.append(SecretFinding(
                    rule_id=rule_id,
                    severity=severity,
                    title=title,
                    file_path=rel_path,
                    line_number=lineno,
                    match=m.group(0)[:200],
                    context=context[:500],
                ))
                break  # one finding per rule per line

    # Entropy scan on string literals
    string_literal_re = re.compile(r'["\']([A-Za-z0-9+/=_\-]{20,})["\']')
    for lineno, line in enumerate(lines, start=1):
        for m in string_literal_re.finditer(line):
            candidate = m.group(1)
            if _shannon_entropy(candidate) > 4.5 and len(candidate) >= 24:
                findings.append(SecretFinding(
                    rule_id="high_entropy_string",
                    severity="medium",
                    title="High-Entropy String (possible secret)",
                    file_path=rel_path,
                    line_number=lineno,
                    match=candidate[:200],
                    context=line[:300],
                ))

    return findings


async def scan_directory(
    base_dir: Path,
    progress_queue: asyncio.Queue | None = None,
) -> list[SecretFinding]:
    all_findings: list[SecretFinding] = []
    files = [f for f in base_dir.rglob("*") if f.is_file() and f.suffix in SCAN_EXTENSIONS]

    def _scan_batch(batch: list[Path]) -> list[SecretFinding]:
        results = []
        for fp in batch:
            results.extend(scan_file(fp, base_dir))
        return results

    loop = asyncio.get_event_loop()
    batch_size = 50
    for i in range(0, len(files), batch_size):
        batch = files[i:i + batch_size]
        found = await loop.run_in_executor(None, _scan_batch, batch)
        all_findings.extend(found)
        if progress_queue:
            pct = min(99, int((i + batch_size) / max(len(files), 1) * 100))
            await progress_queue.put({"type": "scan_progress", "scanned": i + len(batch), "total": len(files), "pct": pct})

    return all_findings
