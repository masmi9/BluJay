"""
Vulnerability Intelligence — NVD CVE lookup, Nuclei template runner, ExploitDB search.

Endpoints:
  POST /vuln/cve/search         — search NVD by keyword or CPE
  POST /vuln/versions/match     — auto-match nmap service versions to CVEs
  GET  /vuln/cve/{cve_id}       — get single CVE detail
  GET  /vuln/nuclei/status      — check nuclei binary availability
  POST /vuln/nuclei/scan        — run nuclei against a target URL
  GET  /vuln/nuclei/results/{id} — get nuclei scan results
  POST /vuln/exploitdb/search   — search ExploitDB by keyword
"""

import asyncio
import json
import os
import shutil
import subprocess
import time
from datetime import datetime, timezone

import httpx
import structlog
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

logger = structlog.get_logger()
router = APIRouter()

_DATA_DIR     = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data")
_CVE_CACHE    = os.path.join(_DATA_DIR, "vuln_cache.json")
_NUCLEI_DIR   = os.path.join(_DATA_DIR, "nuclei_results")
_CACHE_TTL    = 86400  # 24 hours

NVD_API       = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EXPLOITDB_API = "https://www.exploit-db.com/search"

# ── Cache helpers ──────────────────────────────────────────────────────────

def _load_cache() -> dict:
    try:
        with open(_CVE_CACHE) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _save_cache(cache: dict) -> None:
    try:
        os.makedirs(_DATA_DIR, exist_ok=True)
        tmp = _CVE_CACHE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(cache, f)
        os.replace(tmp, _CVE_CACHE)
    except Exception as e:
        logger.warning("vuln_cache_save_failed", error=str(e))


def _cache_key(params: dict) -> str:
    import hashlib
    return hashlib.md5(json.dumps(params, sort_keys=True).encode()).hexdigest()


# ── NVD query ──────────────────────────────────────────────────────────────

async def _nvd_query(params: dict) -> list[dict]:
    cache = _load_cache()
    key   = _cache_key(params)
    entry = cache.get(key)
    if entry and (time.time() - entry.get("ts", 0)) < _CACHE_TTL:
        return entry["data"]

    nvd_key = os.environ.get("NVD_API_KEY", "")
    headers = {"apiKey": nvd_key} if nvd_key else {}

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(NVD_API, params=params, headers=headers)
            if resp.status_code == 403:
                raise HTTPException(403, "NVD API rate limit hit — set NVD_API_KEY env var for 50 req/30s")
            resp.raise_for_status()
            raw = resp.json()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(502, f"NVD API error: {e}")

    vulns = raw.get("vulnerabilities", [])
    results = []
    for v in vulns:
        cve  = v.get("cve", {})
        cve_id = cve.get("id", "")
        descs = cve.get("descriptions", [])
        desc  = next((d["value"] for d in descs if d.get("lang") == "en"), "")
        metrics = cve.get("metrics", {})
        cvss_score = None
        cvss_vector = None
        severity    = "UNKNOWN"
        for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric_list = metrics.get(metric_key, [])
            if metric_list:
                cvss_data   = metric_list[0].get("cvssData", {})
                cvss_score  = cvss_data.get("baseScore")
                cvss_vector = cvss_data.get("vectorString")
                severity    = metric_list[0].get("baseSeverity") or cvss_data.get("baseSeverity", "UNKNOWN")
                break

        refs = [r.get("url") for r in cve.get("references", [])[:5]]
        results.append({
            "id":         cve_id,
            "score":      cvss_score,
            "severity":   severity.upper(),
            "vector":     cvss_vector,
            "description": desc[:500],
            "published":  cve.get("published"),
            "refs":       refs,
        })

    cache[key] = {"ts": time.time(), "data": results}
    _save_cache(cache)
    return results


# ── Nuclei helpers ─────────────────────────────────────────────────────────

def _nuclei_paths() -> list[str]:
    import sys
    if sys.platform == "win32":
        return [
            os.path.expanduser(r"~\go\bin\nuclei.exe"),
            r"C:\Program Files\nuclei\nuclei.exe",
        ]
    return [
        os.path.expanduser("~/go/bin/nuclei"),
        "/usr/local/bin/nuclei",
        "/usr/bin/nuclei",
        "/opt/homebrew/bin/nuclei",
    ]


def _resolve_nuclei() -> str | None:
    found = shutil.which("nuclei") or shutil.which("nuclei.exe")
    if found:
        return found
    for p in _nuclei_paths():
        if os.path.isfile(p):
            return p
    return None


# ── Schemas ────────────────────────────────────────────────────────────────

class CVESearchRequest(BaseModel):
    keyword: str = ""
    cpe_name: str = ""
    limit: int = 20


class VersionMatchRequest(BaseModel):
    services: list[dict]   # [{service, version, port?}]


class NucleiScanRequest(BaseModel):
    target: str
    tags: list[str] = ["cves", "exposures", "misconfigs", "default-login"]
    severity: list[str] = ["critical", "high", "medium"]
    timeout: int = 120


class ExploitDBRequest(BaseModel):
    keyword: str
    limit: int = 20


# ── CVE routes ─────────────────────────────────────────────────────────────

@router.post("/cve/search", summary="Search NVD for CVEs by keyword or CPE")
async def cve_search(req: CVESearchRequest):
    if not req.keyword and not req.cpe_name:
        raise HTTPException(400, "Provide keyword or cpe_name")
    params: dict = {"resultsPerPage": min(req.limit, 50)}
    if req.keyword:
        params["keywordSearch"] = req.keyword
    if req.cpe_name:
        params["cpeName"] = req.cpe_name
    results = await _nvd_query(params)
    return {"total": len(results), "results": results}


@router.get("/cve/{cve_id}", summary="Get a single CVE by ID")
async def get_cve(cve_id: str):
    params = {"cveId": cve_id.upper()}
    results = await _nvd_query(params)
    if not results:
        raise HTTPException(404, f"CVE {cve_id} not found")
    return results[0]


@router.post("/versions/match", summary="Match nmap service versions to CVEs")
async def versions_match(req: VersionMatchRequest):
    matched = []
    for svc in req.services:
        service = svc.get("service", "")
        version = svc.get("version", "")
        port    = svc.get("port")
        if not service and not version:
            continue
        keyword = f"{service} {version}".strip()
        try:
            cves = await _nvd_query({"keywordSearch": keyword, "resultsPerPage": 5})
        except Exception:
            cves = []
        matched.append({
            "service": service,
            "version": version,
            "port":    port,
            "cves":    cves,
            "highest_severity": max((c["severity"] for c in cves), default="NONE",
                                     key=lambda s: {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(s, 0)),
        })
        await asyncio.sleep(0.7)  # NVD rate limit: ~6 req/30s unauthenticated
    return {"services": matched}


# ── Nuclei routes ──────────────────────────────────────────────────────────

@router.get("/nuclei/status", summary="Check nuclei binary availability")
async def nuclei_status():
    path = _resolve_nuclei()
    version = None
    if path:
        try:
            result = subprocess.run([path, "-version"], capture_output=True, text=True, timeout=10)
            version = (result.stdout or result.stderr).strip().split("\n")[0]
        except Exception:
            pass
    return {
        "available": path is not None,
        "path":      path,
        "version":   version,
        "hint":      "Install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest" if not path else None,
    }


_nuclei_scans: dict[str, dict] = {}


@router.post("/nuclei/scan", summary="Run nuclei against a target")
async def nuclei_scan(req: NucleiScanRequest):
    path = _resolve_nuclei()
    if not path:
        raise HTTPException(503, "nuclei not installed. Install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")

    scan_id = f"nuclei_{int(time.time() * 1000)}"
    os.makedirs(_NUCLEI_DIR, exist_ok=True)
    out_file = os.path.join(_NUCLEI_DIR, f"{scan_id}.jsonl")

    _nuclei_scans[scan_id] = {
        "id":        scan_id,
        "target":    req.target,
        "status":    "running",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "findings":  [],
        "error":     None,
    }

    async def _run():
        cmd = [
            path,
            "-target", req.target,
            "-tags",   ",".join(req.tags),
            "-severity", ",".join(req.severity),
            "-json-export", out_file,
            "-silent",
            "-timeout", str(req.timeout),
        ]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=req.timeout + 30)
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except Exception:
                pass
            _nuclei_scans[scan_id]["status"] = "timeout"
            return
        except Exception as e:
            _nuclei_scans[scan_id]["status"] = "error"
            _nuclei_scans[scan_id]["error"]  = str(e)
            return

        findings = []
        try:
            if os.path.exists(out_file):
                with open(out_file) as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                findings.append(json.loads(line))
                            except json.JSONDecodeError:
                                pass
        except Exception:
            pass

        _nuclei_scans[scan_id].update({
            "status":       "complete",
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "findings":     findings,
        })

    asyncio.create_task(_run())
    return {"id": scan_id, "status": "running", "target": req.target}


@router.get("/nuclei/results/{scan_id}", summary="Get nuclei scan results")
async def nuclei_results(scan_id: str):
    scan = _nuclei_scans.get(scan_id)
    if not scan:
        raise HTTPException(404, f"Scan {scan_id} not found")
    return scan


@router.get("/nuclei/scans", summary="List all nuclei scans")
async def list_nuclei_scans():
    return [
        {"id": s["id"], "target": s["target"], "status": s["status"],
         "findings_count": len(s["findings"]), "started_at": s["started_at"]}
        for s in reversed(list(_nuclei_scans.values()))
    ]


# ── ExploitDB routes ───────────────────────────────────────────────────────

@router.post("/exploitdb/search", summary="Search ExploitDB by keyword")
async def exploitdb_search(req: ExploitDBRequest):
    # Try searchsploit CLI first (available when exploitdb package is installed)
    searchsploit = shutil.which("searchsploit")
    if searchsploit:
        try:
            result = subprocess.run(
                [searchsploit, "--json", req.keyword],
                capture_output=True, text=True, timeout=30,
            )
            data = json.loads(result.stdout)
            exploits = data.get("RESULTS_EXPLOIT", []) + data.get("RESULTS_SHELLCODE", [])
            return {
                "source": "searchsploit",
                "total":  len(exploits),
                "results": [
                    {
                        "id":    e.get("EDB-ID", ""),
                        "title": e.get("Title", ""),
                        "type":  e.get("Type", ""),
                        "path":  e.get("Path", ""),
                        "date":  e.get("Date", ""),
                        "url":   f"https://www.exploit-db.com/exploits/{e.get('EDB-ID', '')}",
                    }
                    for e in exploits[:req.limit]
                ],
            }
        except Exception:
            pass  # Fall through to API

    # Fallback: ExploitDB web API
    try:
        async with httpx.AsyncClient(timeout=20.0, headers={"User-Agent": "BluJay/1.0"}) as client:
            resp = await client.get(
                EXPLOITDB_API,
                params={"q": req.keyword, "draw": 1, "start": 0, "length": req.limit},
                headers={"X-Requested-With": "XMLHttpRequest"},
            )
            if resp.status_code != 200:
                raise HTTPException(502, f"ExploitDB returned {resp.status_code}")
            data = resp.json()
            results = []
            for row in data.get("data", []):
                edb_id = str(row.get("id", ""))
                results.append({
                    "id":    edb_id,
                    "title": row.get("description", ""),
                    "type":  row.get("type", {}).get("label", "") if isinstance(row.get("type"), dict) else str(row.get("type", "")),
                    "date":  row.get("date_published", ""),
                    "url":   f"https://www.exploit-db.com/exploits/{edb_id}",
                    "path":  None,
                })
            return {"source": "exploitdb-api", "total": data.get("recordsTotal", len(results)), "results": results}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(502, f"ExploitDB search failed: {e}")
