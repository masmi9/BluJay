import asyncio
import functools
import json
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path

import aiofiles
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, UploadFile, File
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from database import get_db, AsyncSessionLocal
from models.analysis import Analysis, StaticFinding
from schemas.analysis import AnalysisSummary
from schemas.ipa import IpaSummary, EntitlementInfo

router = APIRouter()

_ipa_progress_queues: dict[int, asyncio.Queue] = {}


def _find_7zip() -> str | None:
    for candidate in [
        r"C:\Program Files\7-Zip\7z.exe",
        r"C:\Program Files (x86)\7-Zip\7z.exe",
    ]:
        if Path(candidate).exists():
            return candidate
    return shutil.which("7z") or shutil.which("7za")


def _repack_with_7zip_sync(src: Path, dest: Path) -> bool:
    """Extract src IPA with 7-zip and repack into a standard zip at dest."""
    import structlog
    log = structlog.get_logger()

    sevenzip = _find_7zip()
    if not sevenzip:
        log.warning("7-zip not found", checked_paths=[
            r"C:\Program Files\7-Zip\7z.exe",
            r"C:\Program Files (x86)\7-Zip\7z.exe",
        ])
        return False

    with tempfile.TemporaryDirectory() as tmp:
        extract_cmd = [sevenzip, "x", str(src), f"-o{tmp}", "-y"]
        r1 = subprocess.run(extract_cmd, capture_output=True, timeout=120)
        log.info("7z extract", cmd=extract_cmd, rc=r1.returncode,
                 stdout=r1.stdout.decode(errors="replace"),
                 stderr=r1.stderr.decode(errors="replace"))
        # rc=0: success, rc=1: warnings, rc=2: some files failed (truncated archive)
        # Abort only on command-line errors or if nothing was extracted at all
        extracted = list(Path(tmp).iterdir())
        log.info("extracted contents", rc=r1.returncode, files=[str(p) for p in extracted])
        if r1.returncode not in (0, 1, 2) or not extracted:
            return False

        repack_cmd = [sevenzip, "a", "-tzip", str(dest), str(Path(tmp) / "*")]
        r2 = subprocess.run(repack_cmd, capture_output=True, timeout=120)
        log.info("7z repack", cmd=repack_cmd, rc=r2.returncode,
                 stdout=r2.stdout.decode(errors="replace"),
                 stderr=r2.stderr.decode(errors="replace"))
        return r2.returncode == 0


async def _repack_with_7zip(src: Path, dest: Path) -> bool:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, functools.partial(_repack_with_7zip_sync, src, dest))


@router.post("", response_model=AnalysisSummary, status_code=201)
async def upload_ipa(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
):
    if not file.filename or not file.filename.lower().endswith(".ipa"):
        raise HTTPException(400, "Only .ipa files are accepted")

    upload_path = settings.uploads_dir / file.filename
    content = await file.read()

    if not content:
        raise HTTPException(400, "Uploaded file is empty")

    # Validate it's a zip archive before saving (IPAs are zip files)
    if content[:2] != b"PK":
        raise HTTPException(400, "File does not appear to be a valid IPA (not a zip archive). App Store IPAs downloaded via iTunes may be DRM-encrypted and unsupported.")

    async with aiofiles.open(upload_path, "wb") as f:
        await f.write(content)

    # Verify the saved file is a valid zip; if not, try to repair with 7-zip.
    # IPAs dumped from jailbroken devices often have a malformed EOCD record
    # that Python's zipfile rejects but 7-zip can repair.
    try:
        with zipfile.ZipFile(upload_path, "r") as zf:
            zf.namelist()
    except zipfile.BadZipFile:
        repacked = upload_path.with_suffix(".repacked.ipa")
        ok = await _repack_with_7zip(upload_path, repacked)
        if not ok:
            upload_path.unlink(missing_ok=True)
            raise HTTPException(
                400,
                "IPA has a malformed zip structure and 7-zip is not available to repair it. "
                "Install 7-zip to C:\\Program Files\\7-Zip\\ and re-upload.",
            )
        repacked.replace(upload_path)

    # Compute SHA256 from the (possibly repaired) file on disk
    import hashlib
    h = hashlib.sha256()
    with open(upload_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    sha256 = h.hexdigest()

    # Check duplicate — but re-analyze if previous iOS run left bundle_id empty
    existing = await db.execute(select(Analysis).where(Analysis.apk_sha256 == sha256))
    if ex := existing.scalar_one_or_none():
        if ex.platform == "ios" and ex.bundle_id is None and ex.status == "complete":
            ex.status = "pending"
            await db.commit()
            await db.refresh(ex)
            queue: asyncio.Queue = asyncio.Queue()
            _ipa_progress_queues[ex.id] = queue
            async def _rerun(aid=ex.id, path=str(upload_path)):
                from core.ipa_analyzer import run_ipa_analysis
                await run_ipa_analysis(aid, path, queue, AsyncSessionLocal)
                _ipa_progress_queues.pop(aid, None)
            background_tasks.add_task(_rerun)
        return ex

    analysis = Analysis(
        apk_filename=file.filename,
        apk_sha256=sha256,
        upload_path=str(upload_path),
        platform="ios",
        status="pending",
    )
    db.add(analysis)
    await db.commit()
    await db.refresh(analysis)

    queue: asyncio.Queue = asyncio.Queue()
    _ipa_progress_queues[analysis.id] = queue

    async def _run():
        from core.ipa_analyzer import run_ipa_analysis
        await run_ipa_analysis(analysis.id, str(upload_path), queue, AsyncSessionLocal)
        _ipa_progress_queues.pop(analysis.id, None)

    background_tasks.add_task(_run)
    return analysis


@router.post("/{analysis_id}/dynamic-scan", status_code=201, summary="Start an IODS dynamic scan for an IPA analysis")
async def start_dynamic_scan(
    analysis_id: int,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    mode: str = "deep",
):
    analysis = await db.get(Analysis, analysis_id)
    if not analysis or analysis.platform != "ios":
        raise HTTPException(404, "IPA analysis not found")
    if not analysis.upload_path or not Path(analysis.upload_path).exists():
        raise HTTPException(404, "IPA file not found on disk")

    from models.owasp import OwaspScan
    from core.owasp_scanner import run_scan

    scan = OwaspScan(
        platform="ios",
        apk_path=analysis.upload_path,
        package_name=analysis.bundle_id,
        mode=mode,
        analysis_id=analysis_id,
        status="pending",
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    background_tasks.add_task(
        run_scan, scan.id, Path(analysis.upload_path), analysis.bundle_id, mode, "ios"
    )
    return {"id": scan.id, "status": "pending"}


@router.get("/{analysis_id}/plist")
async def get_plist(analysis_id: int, db: AsyncSession = Depends(get_db)):
    analysis = await db.get(Analysis, analysis_id)
    if not analysis or analysis.platform != "ios":
        raise HTTPException(404, "IPA analysis not found")

    ipa_path = analysis.upload_path
    if not ipa_path or not Path(ipa_path).exists():
        raise HTTPException(404, "IPA file not found on disk")

    import re, plistlib
    from core.ipa_analyzer import _norm, _find_app_bundle
    try:
        zf_handle = zipfile.ZipFile(ipa_path, "r")
    except zipfile.BadZipFile:
        raise HTTPException(422, "IPA file is not a valid zip archive")
    with zf_handle as zf:
        name_map = {_norm(n): n for n in zf.namelist()}
        app_path = _find_app_bundle(zf)
        if not app_path:
            raise HTTPException(404, "No .app bundle found in IPA")
        # Try exact, case-insensitive, then any top-level plist
        candidates = [k for k in name_map
                      if k.startswith(app_path) and k.endswith(".plist")
                      and k[len(app_path):].count("/") == 0]
        plist_key = next((c for c in candidates if c.lower() == (app_path + "info.plist").lower()), None)
        if not plist_key and candidates:
            plist_key = candidates[0]
        if not plist_key:
            raise HTTPException(404, "Info.plist not found in IPA")
        return plistlib.loads(zf.read(name_map[plist_key]))


@router.get("/{analysis_id}/entitlements", response_model=list[EntitlementInfo])
async def get_entitlements(analysis_id: int, db: AsyncSession = Depends(get_db)):
    analysis = await db.get(Analysis, analysis_id)
    if not analysis or analysis.platform != "ios":
        raise HTTPException(404, "IPA analysis not found")

    ipa_path = analysis.upload_path
    if not ipa_path or not Path(ipa_path).exists():
        raise HTTPException(404, "IPA file not found on disk")

    try:
        zf_handle = zipfile.ZipFile(ipa_path, "r")
    except zipfile.BadZipFile:
        raise HTTPException(422, "IPA file is not a valid zip archive")
    with zf_handle as zf:
        from core.ipa_analyzer import _find_app_bundle, _extract_entitlements
        app_path = _find_app_bundle(zf)
        if not app_path:
            return []
        ents = _extract_entitlements(app_path, zf)
        return [EntitlementInfo(**e) for e in ents]


@router.get("/{analysis_id}/ats")
async def get_ats(analysis_id: int, db: AsyncSession = Depends(get_db)):
    analysis = await db.get(Analysis, analysis_id)
    if not analysis or analysis.platform != "ios":
        raise HTTPException(404, "IPA analysis not found")
    return json.loads(analysis.ats_config_json or "{}")


@router.get("/{analysis_id}/strings")
async def get_strings(analysis_id: int, db: AsyncSession = Depends(get_db)):
    """Return binary string findings for this IPA analysis."""
    result = await db.execute(
        select(StaticFinding)
        .where(StaticFinding.analysis_id == analysis_id)
        .where(StaticFinding.category == "ios_binary")
    )
    findings = result.scalars().all()
    return [{"severity": f.severity, "title": f.title, "evidence": f.evidence} for f in findings]


def _open_ipa(analysis) -> zipfile.ZipFile:
    ipa_path = analysis.upload_path
    if not ipa_path or not Path(ipa_path).exists():
        raise HTTPException(404, "IPA file not found on disk")
    try:
        return zipfile.ZipFile(ipa_path, "r")
    except zipfile.BadZipFile:
        raise HTTPException(422, "IPA file is not a valid zip archive")


@router.get("/{analysis_id}/frameworks")
async def get_frameworks(analysis_id: int, db: AsyncSession = Depends(get_db)):
    """Detect embedded frameworks and dylibs in the IPA."""
    analysis = await db.get(Analysis, analysis_id)
    if not analysis or analysis.platform != "ios":
        raise HTTPException(404, "IPA analysis not found")

    from core.ipa_analyzer import _find_app_bundle, _detect_frameworks
    with _open_ipa(analysis) as zf:
        app_path = _find_app_bundle(zf)
        if not app_path:
            return []
        return _detect_frameworks(zf, app_path)


@router.get("/{analysis_id}/permissions")
async def get_permissions(analysis_id: int, db: AsyncSession = Depends(get_db)):
    """Return privacy usage description keys with risk levels."""
    analysis = await db.get(Analysis, analysis_id)
    if not analysis or analysis.platform != "ios":
        raise HTTPException(404, "IPA analysis not found")

    import plistlib
    from core.ipa_analyzer import _norm, _find_app_bundle, _parse_plist, _parse_permissions

    with _open_ipa(analysis) as zf:
        name_map = {_norm(n): n for n in zf.namelist()}
        app_path = _find_app_bundle(zf)
        if not app_path:
            return []
        plist_key = next(
            (k for k in name_map if k.startswith(app_path) and k.lower().endswith("info.plist") and k[len(app_path):].count("/") == 0),
            None,
        )
        if not plist_key:
            return []
        info_plist = _parse_plist(zf.read(name_map[plist_key]))
        return _parse_permissions(info_plist)


@router.get("/{analysis_id}/url-schemes")
async def get_url_schemes(analysis_id: int, db: AsyncSession = Depends(get_db)):
    """Return custom URL schemes declared in Info.plist."""
    analysis = await db.get(Analysis, analysis_id)
    if not analysis or analysis.platform != "ios":
        raise HTTPException(404, "IPA analysis not found")

    from core.ipa_analyzer import _norm, _find_app_bundle, _parse_plist, _parse_url_schemes

    with _open_ipa(analysis) as zf:
        name_map = {_norm(n): n for n in zf.namelist()}
        app_path = _find_app_bundle(zf)
        if not app_path:
            return []
        plist_key = next(
            (k for k in name_map if k.startswith(app_path) and k.lower().endswith("info.plist") and k[len(app_path):].count("/") == 0),
            None,
        )
        if not plist_key:
            return []
        info_plist = _parse_plist(zf.read(name_map[plist_key]))
        return _parse_url_schemes(info_plist)


@router.get("/{analysis_id}/summary")
async def get_summary(analysis_id: int, db: AsyncSession = Depends(get_db)):
    """Return overall security summary with risk score and checks."""
    analysis = await db.get(Analysis, analysis_id)
    if not analysis or analysis.platform != "ios":
        raise HTTPException(404, "IPA analysis not found")

    result = await db.execute(
        select(StaticFinding).where(StaticFinding.analysis_id == analysis_id)
    )
    findings = result.scalars().all()

    by_severity: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        if f.severity in by_severity:
            by_severity[f.severity] += 1

    risk_score = min(100, (
        by_severity["critical"] * 30 +
        by_severity["high"] * 15 +
        by_severity["medium"] * 5 +
        by_severity["low"] * 1
    ))

    ats = json.loads(analysis.ats_config_json or "{}")
    finding_titles = {f.title for f in findings}
    finding_categories = {f.category for f in findings}

    checks = [
        {
            "name": "ATS Enforced",
            "status": "fail" if ats.get("NSAllowsArbitraryLoads") else "pass",
            "severity": "high",
            "description": "NSAllowsArbitraryLoads is disabled — HTTPS enforced for all connections",
        },
        {
            "name": "Not Debuggable",
            "status": "fail" if any("debuggable" in t for t in finding_titles) else "pass",
            "severity": "high",
            "description": "get-task-allow entitlement is not set — binary cannot be attached to by debugger",
        },
        {
            "name": "No Embedded Private Keys",
            "status": "fail" if any("Private key" in t for t in finding_titles) else "pass",
            "severity": "critical",
            "description": "No private cryptographic keys found embedded in the binary",
        },
        {
            "name": "No Hardcoded Credentials",
            "status": "fail" if any(
                f.severity in ("high", "critical") and f.category == "ios_binary"
                and any(kw in f.title for kw in ("API key", "Password", "Token", "Credential", "AWS"))
                for f in findings
            ) else "pass",
            "severity": "high",
            "description": "No hardcoded secrets or API keys found in binary strings",
        },
        {
            "name": "No Weak Crypto",
            "status": "fail" if any("Weak cryptography" in t for t in finding_titles) else "pass",
            "severity": "medium",
            "description": "No references to weak algorithms (MD5, RC4, DES) in binary strings",
        },
        {
            "name": "Sandbox Enabled",
            "status": "fail" if any("sandbox disabled" in t.lower() for t in finding_titles) else "pass",
            "severity": "critical",
            "description": "App sandbox is not explicitly disabled via private entitlement",
        },
    ]

    return {
        "analysis_id": analysis_id,
        "bundle_id": analysis.bundle_id,
        "min_ios_version": analysis.min_ios_version,
        "platform": analysis.platform,
        "status": analysis.status,
        "findings_by_severity": by_severity,
        "risk_score": risk_score,
        "checks": checks,
    }
