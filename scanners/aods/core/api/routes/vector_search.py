"""
AODS Vector Search API Routes
=============================

This module provides API endpoints for semantic similarity search across
vulnerability findings using the ChromaDB vector database.

Endpoints:
- POST /api/vector/findings/similar - Find similar findings
- GET  /api/vector/index/status - Get index status
- POST /api/vector/index/rebuild - Rebuild index (admin only)

Security:
- All endpoints require authentication
- RBAC enforced: users see only their own findings unless admin
- Secrets redacted in embeddings (never exposed via API)

Environment:
- AODS_VECTOR_DB_ENABLED=1 required to enable these endpoints
- Returns 503 if vector DB is disabled or unavailable
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, Field

from core.api.shared_state import REPO_ROOT, check_expensive_op_rate

# Logging with graceful fallback
try:
    from core.logging_config import get_logger

    logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging

    logger = stdlib_logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Router Definition
# ---------------------------------------------------------------------------

router = APIRouter(prefix="/vector", tags=["vector"])


# ---------------------------------------------------------------------------
# Request/Response Models
# ---------------------------------------------------------------------------


class FindingInput(BaseModel):
    """Input finding for similarity search."""

    title: Optional[str] = Field(None, max_length=500, description="Finding title")
    description: Optional[str] = Field(None, max_length=5000, description="Finding description")
    vulnerability_type: Optional[str] = Field(None, max_length=256, description="Vulnerability type")
    severity: Optional[str] = Field(None, max_length=32, description="Severity level")
    cwe_id: Optional[str] = Field(None, max_length=32, description="CWE identifier")
    evidence: Optional[Dict[str, Any]] = Field(None, description="Evidence dict")
    scan_id: Optional[str] = Field(None, max_length=256, description="Exclude findings from this scan")


class FindSimilarRequest(BaseModel):
    """Request body for finding similar findings."""

    finding: FindingInput = Field(..., description="Finding to search for similar matches")
    n_results: int = Field(10, ge=1, le=100, description="Maximum number of results")
    include_same_scan: bool = Field(False, description="Include findings from same scan")


class SimilarFindingResponse(BaseModel):
    """A similar finding result."""

    finding_id: str = Field(..., description="Finding identifier")
    scan_id: str = Field(..., description="Scan session ID")
    similarity_score: float = Field(..., description="Similarity score (0-1)")
    severity: Optional[str] = Field(None, description="Severity level")
    cwe_id: Optional[str] = Field(None, description="CWE identifier")
    title: Optional[str] = Field(None, description="Finding title (truncated)")
    vulnerability_type: Optional[str] = Field(None, description="Vulnerability type")


class FindSimilarResponse(BaseModel):
    """Response for similar findings search."""

    results: List[SimilarFindingResponse] = Field(default_factory=list)
    query_time_ms: float = Field(..., description="Query time in milliseconds")
    total_indexed: int = Field(..., description="Total findings in index")


class VectorIndexStatus(BaseModel):
    """Vector index status response."""

    enabled: bool = Field(..., description="Whether vector DB is enabled")
    available: bool = Field(..., description="Whether vector DB is operational")
    model: str = Field(..., description="Embedding model name")
    storage_path: str = Field(..., description="Storage path")
    collection_count: int = Field(..., description="Number of indexed findings")
    embedding_dimension: int = Field(0, description="Embedding vector dimension")
    cache_stats: Optional[Dict[str, int]] = Field(None, description="Embedding cache statistics")
    error: Optional[str] = Field(None, description="Error message if not available")


class RebuildIndexRequest(BaseModel):
    """Request to rebuild vector index."""

    reports_dir: str = Field("reports", max_length=2048, description="Directory containing report files")
    clear_existing: bool = Field(True, description="Clear existing index before rebuild")


class RebuildIndexResponse(BaseModel):
    """Response for index rebuild."""

    indexed: int = Field(..., description="Number of findings indexed")
    skipped_no_owner: int = Field(..., description="Skipped due to missing owner")
    skipped_pollution: int = Field(..., description="Skipped due to pollution filter")
    errors: int = Field(..., description="Number of errors")


# ---------------------------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------------------------


def _get_auth_helpers():
    """Import auth helpers."""
    from core.api.auth_helpers import _require_roles, _get_user_info

    return _require_roles, _get_user_info


def _check_vector_db_enabled() -> None:
    """Check if vector DB is enabled, raise 503 if not."""
    if os.environ.get("AODS_VECTOR_DB_ENABLED", "0") != "1":
        raise HTTPException(
            status_code=503, detail="Vector database is disabled. Set AODS_VECTOR_DB_ENABLED=1 to enable."
        )


def _get_index():
    """Get the semantic finding index, raise 503 if unavailable."""
    try:
        from core.vector_db import get_semantic_finding_index

        index = get_semantic_finding_index()
        if index is None or not index.is_available():
            raise HTTPException(
                status_code=503, detail="Vector database is not available. Check dependencies and configuration."
            )
        return index
    except ImportError:
        raise HTTPException(status_code=503, detail="Vector database module not available")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/findings/similar", response_model=FindSimilarResponse)
async def find_similar_findings(
    request: FindSimilarRequest,
    authorization: Optional[str] = Header(None),
):
    """
    Find findings similar to the provided finding.

    Uses semantic similarity search via embeddings. Results are filtered
    by ownership - non-admin users only see their own findings plus
    shared/public findings.

    Requires: analyst or admin role
    """
    _check_vector_db_enabled()

    _require_roles, _get_user_info = _get_auth_helpers()

    # Require analyst or admin role
    user_info = _require_roles(authorization, ["analyst", "admin"])

    # Get index
    index = _get_index()

    # Build finding dict from request
    finding_dict = {
        "title": request.finding.title,
        "description": request.finding.description,
        "vulnerability_type": request.finding.vulnerability_type,
        "severity": request.finding.severity,
        "cwe_id": request.finding.cwe_id,
        "evidence": request.finding.evidence or {},
    }

    # Add scan_id for exclusion if provided
    if request.finding.scan_id:
        finding_dict["_scan_id"] = request.finding.scan_id

    # Time the query
    import time

    start = time.perf_counter()

    # Execute search with ownership filtering
    raw_results = index.find_similar(
        finding=finding_dict,
        user_info=user_info,
        n_results=request.n_results,
        include_same_scan=request.include_same_scan,
    )

    elapsed_ms = (time.perf_counter() - start) * 1000

    # Transform results
    results = []
    for r in raw_results:
        metadata = r.get("metadata", {})
        results.append(
            SimilarFindingResponse(
                finding_id=r.get("id", ""),
                scan_id=metadata.get("scan_id", ""),
                similarity_score=r.get("similarity", 0.0),
                severity=metadata.get("severity"),
                cwe_id=metadata.get("cwe_id"),
                title=metadata.get("title"),
                vulnerability_type=metadata.get("vulnerability_type"),
            )
        )

    logger.info(
        "vector_search_completed",
        user=user_info.get("user", "unknown"),
        results=len(results),
        query_time_ms=round(elapsed_ms, 2),
    )

    return FindSimilarResponse(
        results=results,
        query_time_ms=round(elapsed_ms, 2),
        total_indexed=index.get_collection_count(),
    )


@router.get("/index/status", response_model=VectorIndexStatus)
async def get_index_status(
    authorization: Optional[str] = Header(None),
):
    """
    Get vector index status information.

    Returns information about whether the index is enabled, available,
    and statistics about indexed findings.

    Requires: viewer, analyst, or admin role
    """
    _require_roles, _ = _get_auth_helpers()

    # Any authenticated user can check status
    _require_roles(authorization, ["viewer", "analyst", "admin"])

    # Get status from vector_db module
    try:
        from core.vector_db import get_vector_db_status

        status = get_vector_db_status()

        return VectorIndexStatus(
            enabled=status.get("enabled", False),
            available=status.get("available", False),
            model=status.get("model", "unknown"),
            storage_path=status.get("storage_path", ""),
            collection_count=status.get("collection_count", 0),
            embedding_dimension=status.get("embedding_dimension", 0),
            cache_stats=status.get("embedding_cache"),
            error=status.get("error"),
        )
    except ImportError:
        return VectorIndexStatus(
            enabled=False,
            available=False,
            model="unknown",
            storage_path="",
            collection_count=0,
            error="Vector database module not installed",
        )


@router.post("/index/rebuild", response_model=RebuildIndexResponse)
async def rebuild_vector_index(
    request: RebuildIndexRequest,
    authorization: Optional[str] = Header(None),
):
    """
    Rebuild the vector index from existing report files.

    This is an admin-only operation that re-indexes all findings from
    saved reports. Reports without owner metadata are skipped.

    WARNING: This operation can take several minutes for large repositories.

    Requires: admin role only
    """
    _check_vector_db_enabled()

    _require_roles, _ = _get_auth_helpers()

    # Admin only
    user_info = _require_roles(authorization, ["admin"])
    check_expensive_op_rate("vector_rebuild", user_info.get("user", "unknown"))

    # Get index
    index = _get_index()

    # Validate reports_dir stays within repo root
    reports_path = Path(request.reports_dir).resolve()
    if not str(reports_path).startswith(str(REPO_ROOT.resolve())):
        raise HTTPException(status_code=403, detail="reports_dir outside repository")

    logger.info(
        "vector_index_rebuild_started",
        user=user_info.get("user", "unknown"),
        reports_dir=request.reports_dir,
    )

    # Execute rebuild
    try:
        stats = index.rebuild_from_reports(
            reports_dir=request.reports_dir,
            clear_existing=request.clear_existing,
        )

        if "error" in stats:
            raise HTTPException(status_code=400, detail=stats["error"])

        logger.info(
            "vector_index_rebuild_completed",
            user=user_info.get("user", "unknown"),
            indexed=stats.get("indexed", 0),
            skipped_no_owner=stats.get("skipped_no_owner", 0),
            skipped_pollution=stats.get("skipped_pollution", 0),
        )

        return RebuildIndexResponse(
            indexed=stats.get("indexed", 0),
            skipped_no_owner=stats.get("skipped_no_owner", 0),
            skipped_pollution=stats.get("skipped_pollution", 0),
            errors=stats.get("errors", 0),
        )

    except Exception as e:
        logger.error("vector_index_rebuild_failed", error=str(e))
        raise HTTPException(status_code=500, detail="Index rebuild failed")


@router.delete("/index/scan/{scan_id}")
async def delete_scan_from_index(
    scan_id: str,
    authorization: Optional[str] = Header(None),
):
    """
    Delete all indexed findings for a specific scan.

    Requires: admin role only
    """
    _check_vector_db_enabled()

    _require_roles, _ = _get_auth_helpers()

    # Admin only
    user_info = _require_roles(authorization, ["admin"])

    # Get index
    index = _get_index()

    deleted = index.delete_scan_findings(scan_id)

    logger.info(
        "vector_index_scan_deleted",
        user=user_info.get("user", "unknown"),
        scan_id=scan_id,
        deleted=deleted,
    )

    return {"deleted": deleted, "scan_id": scan_id}


# ---------------------------------------------------------------------------
# IoC Correlation Endpoints
# ---------------------------------------------------------------------------


def _get_correlator():
    """Get the IoC correlator, raise 503 if unavailable."""
    try:
        from core.ioc_correlator import get_ioc_correlator

        correlator = get_ioc_correlator()
        if not correlator.enabled:
            raise HTTPException(
                status_code=503,
                detail="IoC correlator is disabled. Set AODS_IOC_CORRELATOR_ENABLED=1 to enable.",
            )
        return correlator
    except ImportError:
        raise HTTPException(status_code=503, detail="IoC correlator module not available")


@router.get("/iocs/correlations")
async def get_ioc_correlations(
    value: str,
    authorization: Optional[str] = Header(None),
):
    """
    Find all APK scans that share a specific IoC value.

    Query parameter ``value`` is the IoC string to search for (e.g. a
    wallet address, C2 domain, or IP).

    Requires: analyst or admin role.
    """
    _require_roles, _ = _get_auth_helpers()
    _require_roles(authorization, ["analyst", "admin"])

    correlator = _get_correlator()
    results = correlator.find_correlations(value.strip()[:500])
    return {"ioc_value": value.strip()[:500], "matches": results, "count": len(results)}


@router.get("/iocs/scan/{scan_id}")
async def get_scan_ioc_correlations(
    scan_id: str,
    authorization: Optional[str] = Header(None),
):
    """
    Find all cross-APK IoC correlations for a given scan.

    Returns shared IoC values, correlated APK names, and detailed
    per-IoC correlation data.

    Requires: analyst or admin role.
    """
    _require_roles, _ = _get_auth_helpers()
    _require_roles(authorization, ["analyst", "admin"])

    correlator = _get_correlator()
    return correlator.find_scan_correlations(scan_id)


@router.get("/iocs/clusters")
async def get_ioc_clusters(
    min_apks: int = 2,
    authorization: Optional[str] = Header(None),
):
    """
    Find IoC values shared across multiple APKs (campaign detection).

    Returns clusters of APKs grouped by shared IoC values.  Only IoCs
    appearing in ``min_apks`` or more distinct scans are returned.

    Requires: analyst or admin role.
    """
    _require_roles, _ = _get_auth_helpers()
    _require_roles(authorization, ["analyst", "admin"])

    min_apks = max(2, min(min_apks, 100))

    correlator = _get_correlator()
    clusters = correlator.get_ioc_clusters(min_apks=min_apks)
    return {"clusters": clusters, "count": len(clusters), "min_apks": min_apks}


@router.get("/iocs/stats")
async def get_ioc_stats(
    authorization: Optional[str] = Header(None),
):
    """
    Get IoC correlation index statistics.

    Returns total IoCs, unique values, scan count, and type distribution.

    Requires: viewer, analyst, or admin role.
    """
    _require_roles, _ = _get_auth_helpers()
    _require_roles(authorization, ["viewer", "analyst", "admin"])

    correlator = _get_correlator()
    return correlator.get_stats()


@router.delete("/iocs/scan/{scan_id}")
async def delete_scan_iocs(
    scan_id: str,
    authorization: Optional[str] = Header(None),
):
    """
    Delete all IoCs for a specific scan from the correlation index.

    Requires: admin role only.
    """
    _require_roles, _ = _get_auth_helpers()
    _require_roles(authorization, ["admin"])

    correlator = _get_correlator()
    deleted = correlator.delete_scan_iocs(scan_id)
    return {"deleted": deleted, "scan_id": scan_id}
