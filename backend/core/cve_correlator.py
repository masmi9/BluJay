"""
CVE correlation via OSV.dev — extracts library info from decompiled APK
and queries https://api.osv.dev/v1/query for known vulnerabilities.
"""
import asyncio
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import aiohttp
import structlog

logger = structlog.get_logger()

OSV_API = "https://api.osv.dev/v1/query"

# Known package-prefix → library name mapping for import scanning
_KNOWN_NAMESPACES: list[tuple[str, str]] = [
    ("com.squareup.okhttp3", "okhttp"),
    ("com.squareup.retrofit2", "retrofit"),
    ("com.squareup.picasso", "picasso"),
    ("com.squareup.leakcanary", "leakcanary-android"),
    ("com.google.gson", "gson"),
    ("com.google.firebase", "firebase-bom"),
    ("com.google.android.gms", "play-services-base"),
    ("io.realm", "realm-android"),
    ("org.apache.http", "httpclient"),
    ("okhttp3", "okhttp"),
    ("retrofit2", "retrofit"),
    ("io.reactivex", "rxjava"),
    ("com.facebook.react", "react-native"),
    ("com.facebook.fresco", "fresco"),
    ("com.airbnb.lottie", "lottie"),
    ("com.jakewharton.timber", "timber"),
    ("com.bumptech.glide", "glide"),
    ("io.coil-kt", "coil"),
]

# Gradle dep line: implementation 'group:artifact:version'
_GRADLE_RE = re.compile(
    r"""(?:implementation|api|compile|runtimeOnly|compileOnly)\s+['"]([^'"]+)['"]""",
    re.MULTILINE,
)

# Version string in XML/strings.xml: version="1.2.3" or >1.2.3<
_VERSION_RE = re.compile(r"\d+\.\d+(?:\.\d+)?(?:[.-][A-Za-z0-9]+)*")


def _parse_gradle_deps(gradle_text: str) -> list[dict]:
    libs = []
    for m in _GRADLE_RE.finditer(gradle_text):
        parts = m.group(1).split(":")
        if len(parts) >= 2:
            group, artifact = parts[0], parts[1]
            version = parts[2] if len(parts) >= 3 else None
            libs.append({
                "name": f"{group}:{artifact}",
                "version": version,
                "ecosystem": "Maven",
                "source": "build.gradle",
            })
    return libs


def _scan_imports(java_root: Path) -> list[dict]:
    seen: set[str] = set()
    libs = []
    for java_file in java_root.rglob("*.java"):
        try:
            text = java_file.read_text(errors="replace")
        except OSError:
            continue
        for ns, artifact in _KNOWN_NAMESPACES:
            if ns in text and artifact not in seen:
                seen.add(artifact)
                # Try to find a version near the namespace
                version = None
                vm = _VERSION_RE.search(text[text.find(ns):text.find(ns) + 200])
                if vm:
                    version = vm.group(0)
                libs.append({
                    "name": artifact,
                    "version": version,
                    "ecosystem": "Maven",
                    "source": "import_scan",
                })
    return libs


def extract_libraries(jadx_path: str | None, decompile_path: str | None) -> list[dict]:
    libs: list[dict] = []
    seen_names: set[str] = set()

    # 1. build.gradle files in decompile output
    if decompile_path:
        dp = Path(decompile_path)
        for gradle_file in dp.rglob("build.gradle"):
            try:
                text = gradle_file.read_text(errors="replace")
                for lib in _parse_gradle_deps(text):
                    if lib["name"] not in seen_names:
                        seen_names.add(lib["name"])
                        libs.append(lib)
            except OSError:
                pass

    # 2. Import scan on JADX Java output
    if jadx_path:
        jp = Path(jadx_path)
        for lib in _scan_imports(jp):
            if lib["name"] not in seen_names:
                seen_names.add(lib["name"])
                libs.append(lib)

    return libs


async def query_osv(session: aiohttp.ClientSession, name: str, version: str | None, ecosystem: str) -> list[dict]:
    payload: dict = {"package": {"name": name, "ecosystem": ecosystem}}
    if version:
        payload["version"] = version

    try:
        async with session.post(OSV_API, json=payload, timeout=aiohttp.ClientTimeout(total=15)) as resp:
            if resp.status != 200:
                return []
            data = await resp.json()
            return data.get("vulns", [])
    except Exception as exc:
        logger.warning("OSV query failed", package=name, error=str(exc))
        return []


def _extract_cve(osv_vuln: dict) -> str | None:
    for alias in osv_vuln.get("aliases", []):
        if alias.startswith("CVE-"):
            return alias
    return None


def _extract_severity(osv_vuln: dict) -> tuple[str | None, float | None]:
    """Returns (severity_label, cvss_score)."""
    # Try database_specific.severity first
    db_specific = osv_vuln.get("database_specific", {})
    sev_str = db_specific.get("severity", "")

    # Try severity array (CVSS)
    cvss_score = None
    for s in osv_vuln.get("severity", []):
        score_str = s.get("score", "")
        # CVSS v3 vector starts with CVSS:3
        if score_str.startswith("CVSS:3"):
            try:
                # Last field after / is base score
                base = float(score_str.split("/")[-1])
                cvss_score = base
                if base >= 9.0:
                    sev_str = "CRITICAL"
                elif base >= 7.0:
                    sev_str = "HIGH"
                elif base >= 4.0:
                    sev_str = "MEDIUM"
                else:
                    sev_str = "LOW"
            except ValueError:
                pass
            break

    label = sev_str.lower() if sev_str else None
    # Normalise
    if label not in {"critical", "high", "medium", "low"}:
        label = None
    return label, cvss_score


def _extract_fixed_version(osv_vuln: dict) -> str | None:
    for affected in osv_vuln.get("affected", []):
        for r in affected.get("ranges", []):
            for ev in r.get("events", []):
                fixed = ev.get("fixed")
                if fixed:
                    return fixed
    return None


async def run_cve_scan(analysis_id: int, db_factory) -> None:
    """Orchestrates library extraction + OSV querying + DB persistence."""
    from models.analysis import Analysis
    from models.cve import DetectedLibrary, CveMatch

    async with db_factory() as db:
        analysis = await db.get(Analysis, analysis_id)
        if not analysis:
            logger.warning("CVE scan: analysis not found", analysis_id=analysis_id)
            return

        # Skip if already scanned (libraries exist)
        from sqlalchemy import select
        existing = await db.execute(
            select(DetectedLibrary).where(DetectedLibrary.analysis_id == analysis_id).limit(1)
        )
        if existing.scalar_one_or_none():
            logger.info("CVE scan: already ran, skipping", analysis_id=analysis_id)
            return

        libs = extract_libraries(analysis.jadx_path, analysis.decompile_path)
        logger.info("CVE scan: found libraries", count=len(libs), analysis_id=analysis_id)

        # Persist detected libraries
        db_libs: list[DetectedLibrary] = []
        for lib in libs:
            dl = DetectedLibrary(
                analysis_id=analysis_id,
                name=lib["name"],
                version=lib.get("version"),
                ecosystem=lib["ecosystem"],
                source=lib["source"],
            )
            db.add(dl)
            db_libs.append(dl)
        await db.flush()

        # Query OSV with concurrency cap
        sem = asyncio.Semaphore(10)

        async def _fetch(dl: DetectedLibrary) -> list[dict]:
            async with sem:
                async with aiohttp.ClientSession() as http:
                    return await query_osv(http, dl.name, dl.version, dl.ecosystem)

        tasks = [_fetch(dl) for dl in db_libs]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for dl, vulns in zip(db_libs, results):
            if isinstance(vulns, Exception):
                continue
            for vuln in vulns:
                severity, cvss_score = _extract_severity(vuln)
                match = CveMatch(
                    analysis_id=analysis_id,
                    library_id=dl.id,
                    osv_id=vuln.get("id", ""),
                    cve_id=_extract_cve(vuln),
                    severity=severity,
                    cvss_score=cvss_score,
                    summary=vuln.get("summary"),
                    fixed_version=_extract_fixed_version(vuln),
                    published=vuln.get("published"),
                )
                db.add(match)

        await db.commit()
        logger.info("CVE scan complete", analysis_id=analysis_id)
