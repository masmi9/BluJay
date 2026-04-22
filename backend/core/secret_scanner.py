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
    # ── Cloud providers ─────────────────────────────────────────────────────────
    ("aws_access_key",        r"AKIA[0-9A-Z]{16}",                                              "critical", "AWS Access Key ID"),
    ("aws_secret_key",        r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]",       "critical", "AWS Secret Access Key"),
    ("aws_session_token",     r"FwoGZXIvYXdz[A-Za-z0-9+/=]{100,}",                             "critical", "AWS Session Token"),
    ("aws_mws_key",           r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "high", "Amazon MWS Key"),
    ("google_api_key",        r"AIza[0-9A-Za-z\-_]{35}",                                        "high",     "Google API Key"),
    ("gcp_service_account",   r'"type"\s*:\s*"service_account"',                                "critical", "GCP Service Account JSON"),
    ("gcp_oauth_client",      r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",        "high",     "GCP OAuth Client ID"),
    ("firebase_url",          r"https://[a-z0-9\-]+\.firebaseio\.com",                          "medium",   "Firebase Database URL"),
    ("firebase_key",          r"AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140}",                   "high",     "Firebase Server Key"),
    ("azure_conn_str",        r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}", "critical", "Azure Storage Connection String"),
    ("azure_sas_token",       r"(?i)sig=[A-Za-z0-9%]{43,}",                                    "high",     "Azure SAS Token"),
    ("azure_client_secret",   r"(?i)client.?secret['\"\s:=]+[A-Za-z0-9~._\-]{34,}",           "critical", "Azure Client Secret"),
    # ── Source control ───────────────────────────────────────────────────────────
    ("github_pat",            r"ghp_[0-9a-zA-Z]{36}",                                           "critical", "GitHub Personal Access Token"),
    ("github_oauth",          r"gho_[0-9a-zA-Z]{36}",                                           "critical", "GitHub OAuth Token"),
    ("github_app_token",      r"(ghu|ghs)_[0-9a-zA-Z]{36}",                                    "critical", "GitHub App Token"),
    ("github_refresh",        r"ghr_[0-9a-zA-Z]{76}",                                           "critical", "GitHub Refresh Token"),
    ("gitlab_pat",            r"glpat-[0-9a-zA-Z\-_]{20}",                                     "critical", "GitLab Personal Access Token"),
    ("npm_token",             r"npm_[A-Za-z0-9]{36}",                                           "high",     "NPM Access Token"),
    # ── Payment processors ───────────────────────────────────────────────────────
    ("stripe_key",            r"(?:r|s)k_(live|test)_[0-9a-zA-Z]{24}",                         "critical", "Stripe API Key"),
    ("stripe_webhook",        r"whsec_[A-Za-z0-9]{32,}",                                       "critical", "Stripe Webhook Secret"),
    ("square_access",         r"sq0atp-[0-9A-Za-z\-_]{22}",                                    "critical", "Square Access Token"),
    ("square_oauth",          r"sq0csp-[0-9A-Za-z\-_]{43}",                                    "critical", "Square OAuth Secret"),
    ("paypal_client_id",      r"(?i)paypal.{0,20}client.?id['\"\s:=]+[A-Za-z0-9]{16,}",       "high",     "PayPal Client ID"),
    ("braintree_token",       r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",         "critical", "Braintree Access Token"),
    # ── Messaging / comms ────────────────────────────────────────────────────────
    ("slack_token",           r"xox[baprs]\-[0-9]{12}\-[0-9]{12}\-[0-9]{12}\-[a-z0-9]{32}",   "high",     "Slack Token"),
    ("slack_webhook",         r"https://hooks\.slack\.com/services/T[A-Z0-9]{8}/B[A-Z0-9]{8}/[A-Za-z0-9]{24}", "high", "Slack Webhook URL"),
    ("twilio_account",        r"AC[0-9a-fA-F]{32}",                                             "high",     "Twilio Account SID"),
    ("twilio_auth",           r"(?i)twilio.{0,20}auth.?token['\"\s:=]+[0-9a-fA-F]{32}",       "critical", "Twilio Auth Token"),
    ("sendgrid_key",          r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}",                  "critical", "SendGrid API Key"),
    ("mailgun_key",           r"key-[0-9a-zA-Z]{32}",                                           "high",     "Mailgun API Key"),
    ("mailchimp_key",         r"[0-9a-f]{32}-us[0-9]{1,2}",                                    "high",     "Mailchimp API Key"),
    ("pusher_key",            r"(?i)pusher.{0,20}(app.?key|app.?secret)['\"\s:=]+[A-Za-z0-9]{8,}", "high", "Pusher Key"),
    # ── Auth providers ───────────────────────────────────────────────────────────
    ("jwt_token",             r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+",    "high",     "JSON Web Token (JWT)"),
    ("auth0_domain",          r"[a-zA-Z0-9\-]+\.auth0\.com",                                   "medium",   "Auth0 Domain"),
    ("okta_domain",           r"[a-zA-Z0-9\-]+\.okta\.com",                                    "medium",   "Okta Domain"),
    ("okta_token",            r"(?i)okta.{0,20}token['\"\s:=]+[A-Za-z0-9\-_]{20,}",           "high",     "Okta Token"),
    # ── DevOps / infra ───────────────────────────────────────────────────────────
    ("heroku_api_key",        r"(?i)heroku.{0,20}['\"][0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}['\"]", "high", "Heroku API Key"),
    ("docker_hub_token",      r"(?i)docker.{0,20}token['\"\s:=]+[A-Za-z0-9_\-]{20,}",         "high",     "Docker Hub Token"),
    ("datadog_api_key",       r"(?i)datadog.{0,20}api.?key['\"\s:=]+[0-9a-fA-F]{32}",         "high",     "Datadog API Key"),
    ("circleci_token",        r"(?i)circle.{0,20}token['\"\s:=]+[0-9a-fA-F]{40}",             "high",     "CircleCI Token"),
    ("jenkins_token",         r"(?i)jenkins.{0,20}token['\"\s:=]+[A-Za-z0-9]{20,}",           "medium",   "Jenkins Token"),
    # ── E-commerce / CMS ────────────────────────────────────────────────────────
    ("shopify_token",         r"shpat_[A-Za-z0-9]{32}",                                        "critical", "Shopify Admin API Token"),
    ("shopify_shared_secret", r"shpss_[A-Za-z0-9]{32}",                                        "critical", "Shopify Shared Secret"),
    ("hubspot_key",           r"(?i)hubspot.{0,20}api.?key['\"\s:=]+[0-9a-fA-F\-]{36}",       "high",     "HubSpot API Key"),
    ("wordpress_key",         r"define\s*\(\s*'AUTH_KEY'\s*,\s*'[^']{20,}'",                   "high",     "WordPress Auth Key"),
    # ── Credentials in code ──────────────────────────────────────────────────────
    ("rsa_private_key",       r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",          "critical", "Private Key Material"),
    ("certificate",           r"-----BEGIN CERTIFICATE-----",                                   "info",     "Embedded Certificate"),
    ("generic_password",      r"(?i)(password|passwd|pwd)\s*[=:]\s*[\"'][^\"'\s]{6,}[\"']",   "medium",   "Hardcoded Password"),
    ("generic_api_key",       r"(?i)(api[_\-]?key|apikey|api[_\-]?secret)\s*[=:]\s*[\"'][^\"'\s]{8,}[\"']", "high", "Hardcoded API Key"),
    ("generic_secret",        r"(?i)(secret[_\-]?key|client[_\-]?secret|app[_\-]?secret)\s*[=:]\s*[\"'][^\"'\s]{8,}[\"']", "high", "Hardcoded Secret"),
    ("generic_token",         r"(?i)(bearer|access.?token|auth.?token)\s*[=:]\s*[\"'][A-Za-z0-9\-_\.]{20,}[\"']", "high", "Hardcoded Token"),
    ("http_basic_auth",       r"https?://[^:@\s]+:[^@\s]+@[^\s]+",                             "high",     "Credentials in URL"),
    ("ip_address",            r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b", "info", "Hardcoded IP Address"),
    ("internal_hostname",     r"(?i)(host|hostname|endpoint|server)\s*[=:]\s*[\"'][a-z0-9\-]+\.(internal|local|corp|intranet|lan)[\"']", "medium", "Internal Hostname"),
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
