"""
Orchestrates the full static analysis pipeline for an uploaded APK.
"""
import asyncio
import hashlib
import json
from pathlib import Path

import structlog

from config import settings
from core.apktool_wrapper import ApktoolWrapper
from core.jadx_wrapper import JadxWrapper
from core.manifest_parser import parse_manifest
from core.permission_analyzer import classify_permissions
from core.secret_scanner import scan_directory

logger = structlog.get_logger()


async def _sha256(path: Path) -> str:
    loop = asyncio.get_event_loop()

    def _compute():
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()

    return await loop.run_in_executor(None, _compute)


async def run_analysis(
    analysis_id: int,
    apk_path: Path,
    progress_queue: asyncio.Queue,
    db_session_factory,
) -> None:
    """
    Full pipeline. Runs as a background task.
    Updates the Analysis row in the DB as it progresses.
    Emits progress events onto progress_queue.
    """
    from database import AsyncSessionLocal
    from models.analysis import Analysis, StaticFinding

    async def _update_status(status: str, error: str | None = None, **kwargs):
        async with AsyncSessionLocal() as db:
            from sqlalchemy import select
            result = await db.execute(select(Analysis).where(Analysis.id == analysis_id))
            analysis = result.scalar_one_or_none()
            if analysis:
                analysis.status = status
                if error:
                    analysis.error_message = error
                for k, v in kwargs.items():
                    setattr(analysis, k, v)
                await db.commit()

    async def _emit(stage: str, pct: int, message: str):
        await progress_queue.put({"type": "progress", "stage": stage, "pct": pct, "message": message})
        logger.info("Analysis progress", analysis_id=analysis_id, stage=stage, pct=pct)

    try:
        await _emit("hashing", 2, "Computing APK hash...")
        sha256 = await _sha256(apk_path)

        decompile_dir = settings.decompile_dir / sha256 / "apktool"
        jadx_dir = settings.decompile_dir / sha256 / "jadx"

        # --- Decompile with apktool ---
        await _update_status("decompiling")
        await _emit("decompile", 5, "Decompiling APK with apktool...")

        apktool = ApktoolWrapper()
        if not decompile_dir.exists():
            result = await apktool.decompile(apk_path, decompile_dir, progress_queue)
            if not result.success:
                await _update_status("failed", error=f"apktool failed: {result.error}")
                await _emit("error", 0, f"apktool failed: {result.error}")
                return
        else:
            await _emit("decompile", 20, "Using cached apktool output")

        await _emit("decompile", 30, "apktool decompile complete")

        # --- Parse manifest ---
        await _emit("manifest", 32, "Parsing AndroidManifest.xml...")
        manifest_path = decompile_dir / "AndroidManifest.xml"
        manifest_data: dict = {}
        if manifest_path.exists():
            try:
                manifest_data = parse_manifest(manifest_path)
            except Exception as e:
                logger.warning("Manifest parse failed", error=str(e))

        pkg = manifest_data.get("package_name")
        await _update_status(
            "analyzing",
            package_name=pkg,
            version_name=manifest_data.get("version_name"),
            version_code=manifest_data.get("version_code"),
            min_sdk=manifest_data.get("min_sdk"),
            target_sdk=manifest_data.get("target_sdk"),
            decompile_path=str(decompile_dir),
        )
        await _emit("manifest", 35, f"Manifest parsed — package: {pkg}")

        # --- Decompile with jadx (Java source) ---
        jadx = JadxWrapper()
        if jadx.available():
            await _emit("jadx", 36, "Decompiling Java source with jadx...")
            if not jadx_dir.exists():
                jresult = await jadx.decompile(apk_path, jadx_dir, progress_queue)
                if jresult.success:
                    await _update_status("analyzing", jadx_path=str(jadx_dir))
                    await _emit("jadx", 55, "jadx decompile complete")
                else:
                    await _emit("jadx", 55, f"jadx partial or failed: {jresult.error}")
            else:
                await _update_status("analyzing", jadx_path=str(jadx_dir))
                await _emit("jadx", 55, "Using cached jadx output")
        else:
            await _emit("jadx", 55, "jadx not available — skipping Java decompile")

        # --- Build static findings ---
        findings: list[dict] = []

        # Manifest-level findings
        if manifest_data:
            if manifest_data.get("debuggable"):
                findings.append({
                    "category": "manifest_issue", "severity": "high",
                    "title": "Application is debuggable",
                    "description": "android:debuggable=true allows attaching a debugger to the app process.",
                    "file_path": "AndroidManifest.xml", "line_number": None,
                    "evidence": None, "rule_id": "manifest_debuggable",
                })
            if manifest_data.get("allow_backup"):
                findings.append({
                    "category": "manifest_issue", "severity": "medium",
                    "title": "Application backup enabled",
                    "description": "android:allowBackup=true allows ADB backup of app data without root.",
                    "file_path": "AndroidManifest.xml", "line_number": None,
                    "evidence": None, "rule_id": "manifest_allow_backup",
                })
            ct = manifest_data.get("uses_cleartext_traffic")
            if ct is True:
                findings.append({
                    "category": "insecure_config", "severity": "medium",
                    "title": "Cleartext traffic enabled",
                    "description": "android:usesCleartextTraffic=true permits unencrypted HTTP traffic.",
                    "file_path": "AndroidManifest.xml", "line_number": None,
                    "evidence": None, "rule_id": "manifest_cleartext",
                })

            # Exported components
            for comp in manifest_data.get("components", []):
                if comp["exported"] and not comp.get("permission"):
                    findings.append({
                        "category": "exported_component", "severity": "medium",
                        "title": f"Exported {comp['type']} without permission",
                        "description": f"{comp['name']} is exported and accessible to other apps without requiring a permission.",
                        "file_path": "AndroidManifest.xml", "line_number": None,
                        "evidence": json.dumps({"component": comp["name"], "type": comp["type"]}),
                        "rule_id": "exported_component_no_permission",
                    })

            # Dangerous permissions
            perms = classify_permissions(manifest_data.get("permissions", []))
            for p in perms:
                if p["risk"] in ("high", "critical"):
                    findings.append({
                        "category": "dangerous_permission", "severity": p["risk"],
                        "title": f"Dangerous permission: {p['short_name']}",
                        "description": p["description"],
                        "file_path": "AndroidManifest.xml", "line_number": None,
                        "evidence": json.dumps({"permission": p["name"]}),
                        "rule_id": f"perm_{p['short_name'].lower()}",
                    })

        await _emit("permissions", 58, f"Found {len(findings)} manifest findings")

        # --- Secret scan ---
        await _emit("secrets", 60, "Scanning for hardcoded secrets...")
        scan_base = jadx_dir if jadx_dir.exists() else decompile_dir
        secret_findings = await scan_directory(scan_base, progress_queue)
        for sf in secret_findings:
            findings.append({
                "category": "hardcoded_secret", "severity": sf.severity,
                "title": sf.title,
                "description": f"Pattern '{sf.rule_id}' matched in {sf.file_path}:{sf.line_number}",
                "file_path": sf.file_path,
                "line_number": sf.line_number,
                "evidence": json.dumps({"match": sf.match, "context": sf.context}),
                "rule_id": sf.rule_id,
            })
        await _emit("secrets", 90, f"Secret scan complete — {len(secret_findings)} potential secrets found")

        # --- Persist findings ---
        await _emit("saving", 92, "Saving findings to database...")
        async with AsyncSessionLocal() as db:
            for f in findings:
                db.add(StaticFinding(analysis_id=analysis_id, **f))
            await db.commit()

        await _update_status("complete")
        await _emit("complete", 100, f"Analysis complete — {len(findings)} total findings")

    except Exception as exc:
        logger.exception("Analysis pipeline error", analysis_id=analysis_id)
        await _update_status("failed", error=str(exc))
        await progress_queue.put({"type": "error", "message": str(exc)})
