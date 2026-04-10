from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from schemas.webview import WebViewScanResult, WebViewFile, WebViewFinding

router = APIRouter()

# In-memory cache: analysis_id -> list of file dicts
_cache: dict[int, list[dict]] = {}


@router.post("/scan/{analysis_id}", response_model=WebViewScanResult)
async def scan_webview(analysis_id: int, db: AsyncSession = Depends(get_db)):
    from models.analysis import Analysis
    analysis = await db.get(Analysis, analysis_id)
    if not analysis:
        raise HTTPException(404, "Analysis not found")
    if analysis.status != "complete":
        raise HTTPException(400, "Analysis must be complete before WebView scan")

    from core.webview_anaylzer import extract_webview_js
    files = extract_webview_js(analysis.decompile_path, analysis.jadx_path)
    _cache[analysis_id] = files

    # Also persist findings as StaticFindings
    from models.analysis import StaticFinding
    import json
    new_findings = []
    for file_data in files:
        for finding in file_data.get("findings", []):
            sf = StaticFinding(
                analysis_id=analysis_id,
                category="webview_js",
                severity=finding["severity"],
                title=finding["title"],
                description=f"WebView JS finding in {finding['file']}",
                file_path=file_data["path"],
                line_number=finding["line"] or None,
                evidence=json.dumps({"match": finding["evidence"]}),
                rule_id=finding["rule_id"],
            )
            new_findings.append(sf)
    db.add_all(new_findings)
    await db.commit()

    return _build_result(analysis_id, files)


@router.get("/{analysis_id}/files", response_model=WebViewScanResult)
async def get_files(analysis_id: int, db: AsyncSession = Depends(get_db)):
    if analysis_id not in _cache:
        from models.analysis import Analysis
        analysis = await db.get(Analysis, analysis_id)
        if not analysis:
            raise HTTPException(404, "Analysis not found")
        from core.webview_anaylzer import extract_webview_js
        files = extract_webview_js(analysis.decompile_path, analysis.jadx_path)
        _cache[analysis_id] = files

    return _build_result(analysis_id, _cache[analysis_id])


@router.get("/{analysis_id}/files/{index}/content")
async def get_file_content(analysis_id: int, index: int):
    files = _cache.get(analysis_id)
    if not files or index >= len(files):
        raise HTTPException(404, "File not found")
    return {"content": files[index]["content"]}


def _build_result(analysis_id: int, files: list[dict]) -> WebViewScanResult:
    file_out = []
    total_findings = 0
    for i, f in enumerate(files):
        findings = [WebViewFinding(**fi) for fi in f.get("findings", [])]
        total_findings += len(findings)
        file_out.append(WebViewFile(
            index=i,
            source=f["source"],
            path=f["path"],
            size_bytes=f["size_bytes"],
            findings=findings,
            bridge_methods=f.get("bridge_methods", []),
        ))
    return WebViewScanResult(
        analysis_id=analysis_id,
        files_found=len(files),
        findings_count=total_findings,
        files=file_out,
    )
